use std::{
    collections::HashSet,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{Context, Result, bail, ensure};
use futures_util::StreamExt;
use netlink_packet_core::{NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
    nftables::{
        DataAttribute, ListAttribute, NfTablesMessage, SetElementAttribute, SetElementList,
        SetElementMessage,
    },
};
use netlink_proto::{ConnectionHandle, sys};
use rtnetlink::{
    Handle as RouteHandle, RouteMessageBuilder,
    packet_route::{
        link::LinkAttribute,
        route::{RouteAttribute, RouteMessage, RouteType},
    },
};

use crate::dns::{
    config::{DnsOutletGroupConfig, PolicyConfig},
    policy::Selection,
};

const PACKED_MARK_MASK: u32 = 0x00ff_ffff;

/// Linux policy source backed by exact nftables map lookups and FIB queries.
pub(super) struct NftWltPolicy {
    table: String,
    ipv4_map: String,
    ipv6_map: Option<String>,
    default_eligible_interfaces: HashSet<String>,
    mark_masks: Vec<u32>,
    ipv4_default_mark: u32,
    ipv6_default_mark: Option<u32>,
    nft: ConnectionHandle<NetfilterMessage>,
    route: RouteHandle,
}

impl NftWltPolicy {
    pub(super) fn new(
        config: &PolicyConfig,
        outlet_groups: &[DnsOutletGroupConfig],
    ) -> Result<Self> {
        let runtime = tokio::runtime::Handle::try_current()
            .context("constructing Linux DNS policy requires a Tokio runtime")?;

        let (nft_connection, nft, _) =
            netlink_proto::new_connection::<NetfilterMessage>(sys::protocols::NETLINK_NETFILTER)
                .context("failed to open NETLINK_NETFILTER socket")?;
        runtime.spawn(nft_connection);

        let (route_connection, route, _) =
            rtnetlink::new_connection().context("failed to open NETLINK_ROUTE socket")?;
        runtime.spawn(route_connection);

        Ok(Self {
            table: config.table.clone(),
            ipv4_map: config.ipv4_map.clone(),
            ipv6_map: config.ipv6_map.clone(),
            default_eligible_interfaces: config
                .default_eligible_interfaces
                .iter()
                .cloned()
                .collect(),
            mark_masks: outlet_groups.iter().map(|group| group.mask).collect(),
            ipv4_default_mark: config.ipv4_default_mark,
            ipv6_default_mark: config.ipv6_default_mark,
            nft,
            route,
        })
    }

    async fn lookup_mark(&self, client: IpAddr) -> Result<Option<u32>> {
        let (map, key): (&str, Vec<u8>) = match client {
            IpAddr::V4(address) => (&self.ipv4_map, address.octets().to_vec()),
            IpAddr::V6(address) => {
                let Some(map) = self.ipv6_map.as_deref() else {
                    return Ok(None);
                };
                (map, address.octets().to_vec())
            }
        };

        let request = exact_set_element_request(&self.table, map, key.clone());
        let mut responses = self
            .nft
            .request(request, sys::SocketAddr::new(0, 0))
            .context("failed to submit nftables element lookup")?;
        let response = responses
            .next()
            .await
            .context("nftables element lookup returned no response")?;

        match response.payload {
            NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewSetElement(message)),
                ..
            }) => decode_set_element(message, &key).map(Some),
            NetlinkPayload::Error(error) if error.to_io().kind() == ErrorKind::NotFound => Ok(None),
            NetlinkPayload::Error(error) => Err(error.to_io()).with_context(|| {
                format!("nftables element lookup failed for {}/{}", self.table, map)
            }),
            payload => bail!("unexpected nftables element lookup response: {payload:?}"),
        }
    }

    async fn route_is_default_eligible(&self, client: IpAddr) -> Result<bool> {
        if self.default_eligible_interfaces.is_empty() {
            return Ok(false);
        }

        let Some(route) = self.lookup_route(client).await? else {
            return Ok(false);
        };

        if matches!(
            route.header.kind,
            RouteType::BlackHole | RouteType::Unreachable | RouteType::Prohibit | RouteType::Throw
        ) {
            return Ok(false);
        }

        let mut output_interfaces = route.attributes.iter().filter_map(|attr| {
            if let RouteAttribute::Oif(index) = attr {
                Some(*index)
            } else {
                None
            }
        });
        let output_interface = output_interfaces
            .next()
            .context("FIB lookup response has no output interface")?;
        ensure!(
            output_interfaces.next().is_none(),
            "FIB lookup response has multiple output interfaces"
        );

        let name = self.interface_name(output_interface).await?;
        Ok(self.default_eligible_interfaces.contains(&name))
    }

    async fn lookup_route(&self, client: IpAddr) -> Result<Option<RouteMessage>> {
        let responses = self
            .route
            .route()
            .get(route_lookup_request(client))
            .execute();
        futures_util::pin_mut!(responses);
        let response = responses.next().await;

        match response {
            Some(Ok(route)) => Ok(Some(route)),
            Some(Err(error)) if is_no_route(&error) => Ok(None),
            Some(Err(error)) => Err(error).context("FIB lookup failed"),
            None => bail!("FIB lookup returned no response"),
        }
    }

    async fn interface_name(&self, index: u32) -> Result<String> {
        let links = self.route.link().get().match_index(index).execute();
        futures_util::pin_mut!(links);
        let link = links
            .next()
            .await
            .context("interface lookup returned no response")?
            .with_context(|| format!("failed to look up interface {index}"))?;

        let mut names = link.attributes.into_iter().filter_map(|attr| {
            if let LinkAttribute::IfName(name) = attr {
                Some(name)
            } else {
                None
            }
        });
        let name = names
            .next()
            .context("interface lookup response has no name")?;
        ensure!(
            names.next().is_none(),
            "interface lookup response has multiple names"
        );
        Ok(name)
    }

    pub(super) async fn snapshot(&self, client: IpAddr) -> Result<Selection> {
        let client = normalize_client(client);
        let mark = self.lookup_mark(client).await?;
        let map_mark = mark.unwrap_or_default();
        let configured_default = match client {
            IpAddr::V4(_) => Some(self.ipv4_default_mark),
            IpAddr::V6(_) => self.ipv6_default_mark,
        };
        let default_mark = if let Some(default_mark) = configured_default
            && needs_default(map_mark, default_mark, &self.mark_masks)
            && self.route_is_default_eligible(client).await?
        {
            default_mark
        } else {
            0
        };

        Ok(Selection {
            map_mark,
            default_mark,
        })
    }
}

fn exact_set_element_request(
    table: &str,
    set: &str,
    key: Vec<u8>,
) -> NetlinkMessage<NetfilterMessage> {
    let payload = NfTablesMessage::GetSetElement(SetElementMessage {
        attributes: vec![
            SetElementList::Table(table.to_owned()),
            SetElementList::Set(set.to_owned()),
            SetElementList::Elements(vec![ListAttribute::Element(vec![
                SetElementAttribute::Key(DataAttribute::Value(key)),
            ])]),
        ],
    });
    let mut message = NetlinkMessage::from(NetfilterMessage::new(
        NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
        payload,
    ));
    message.header.flags = NLM_F_REQUEST;
    message
}

fn route_lookup_request(client: IpAddr) -> RouteMessage {
    match client {
        IpAddr::V4(address) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(address, 32)
            .build(),
        IpAddr::V6(address) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(address, 128)
            .build(),
    }
}

fn decode_set_element(message: SetElementMessage, expected_key: &[u8]) -> Result<u32> {
    let mut elements = message.attributes.into_iter().flat_map(|attribute| {
        if let SetElementList::Elements(elements) = attribute {
            elements
        } else {
            Vec::new()
        }
    });
    let element = elements
        .next()
        .context("nftables element response contains no element")?;
    ensure!(
        elements.next().is_none(),
        "nftables element response contains multiple elements"
    );

    let ListAttribute::Element(attributes) = element else {
        bail!("nftables element response contains an invalid list item");
    };
    let mut keys = attributes.iter().filter_map(|attribute| {
        if let SetElementAttribute::Key(DataAttribute::Value(bytes)) = attribute {
            Some(bytes.as_slice())
        } else {
            None
        }
    });
    let key = keys
        .next()
        .context("nftables element response contains no key")?;
    ensure!(
        keys.next().is_none(),
        "nftables element response contains multiple keys"
    );
    ensure!(
        key == expected_key,
        "nftables element response key does not match the request"
    );

    let mut values = attributes.iter().filter_map(|attribute| {
        if let SetElementAttribute::Data(DataAttribute::Value(bytes)) = attribute {
            Some(bytes.as_slice())
        } else {
            None
        }
    });
    let value = values
        .next()
        .context("nftables map element response contains no value")?;
    ensure!(
        values.next().is_none(),
        "nftables map element response contains multiple values"
    );
    let value: [u8; 4] = value
        .try_into()
        .with_context(|| format!("nftables map value has {} bytes instead of 4", value.len()))?;
    let mark = u32::from_ne_bytes(value);
    ensure!(
        mark & !PACKED_MARK_MASK == 0,
        "nftables map value {mark:#010x} exceeds the 24-bit packed mark schema"
    );
    Ok(mark)
}

fn normalize_client(client: IpAddr) -> IpAddr {
    match client {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        client => client,
    }
}

fn needs_default(map_mark: u32, default_mark: u32, masks: &[u32]) -> bool {
    masks
        .iter()
        .any(|mask| map_mark & mask == 0 && default_mark & mask != 0)
}

fn is_no_route(error: &rtnetlink::Error) -> bool {
    let rtnetlink::Error::NetlinkError(error) = error else {
        return false;
    };
    matches!(
        error.to_io().kind(),
        ErrorKind::NotFound | ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_element_reply(key: Vec<u8>, value: Vec<u8>) -> SetElementMessage {
        SetElementMessage {
            attributes: vec![SetElementList::Elements(vec![ListAttribute::Element(
                vec![
                    SetElementAttribute::Key(DataAttribute::Value(key)),
                    SetElementAttribute::Data(DataAttribute::Value(value)),
                ],
            )])],
        }
    }

    #[test]
    fn constructs_exact_set_element_lookup_without_dump() {
        let key = Ipv4Addr::new(192, 0, 2, 7).octets().to_vec();
        let message = exact_set_element_request("home-router", "src2mark", key.clone());
        assert_eq!(message.header.flags, NLM_F_REQUEST);

        let NetlinkPayload::InnerMessage(NetfilterMessage {
            inner: NetfilterMessageInner::NfTables(NfTablesMessage::GetSetElement(message)),
            ..
        }) = message.payload
        else {
            panic!("expected NFT_MSG_GETSETELEM");
        };
        assert!(message.attributes.contains(&SetElementList::Elements(vec![
            ListAttribute::Element(vec![SetElementAttribute::Key(DataAttribute::Value(key))])
        ])));
    }

    #[test]
    fn constructs_exact_fib_lookup() {
        let address = Ipv4Addr::new(192, 0, 2, 7);
        let message = route_lookup_request(IpAddr::V4(address));
        assert_eq!(message.header.destination_prefix_length, 32);
        assert!(message.attributes.iter().any(|attribute| {
            matches!(
                attribute,
                RouteAttribute::Destination(
                    rtnetlink::packet_route::route::RouteAddress::Inet(value)
                ) if *value == address
            )
        }));
    }

    #[test]
    fn decodes_native_endian_24_bit_mark_without_layout_assumptions() {
        let key = vec![192, 0, 2, 7];
        let mark = decode_set_element(
            set_element_reply(key.clone(), 0x00ab_c123_u32.to_ne_bytes().into()),
            &key,
        )
        .unwrap();
        assert_eq!(mark, 0x00ab_c123);
    }

    #[test]
    fn rejects_mark_bits_outside_packed_24_bit_schema() {
        let key = vec![192, 0, 2, 7];
        let error = decode_set_element(
            set_element_reply(key.clone(), 0x01ab_c123_u32.to_ne_bytes().into()),
            &key,
        )
        .unwrap_err();
        assert!(error.to_string().contains("exceeds the 24-bit packed mark"));
    }

    #[test]
    fn rejects_mismatched_key() {
        assert!(
            decode_set_element(
                set_element_reply(vec![192, 0, 2, 8], 0x123_u32.to_ne_bytes().into()),
                &[192, 0, 2, 7],
            )
            .is_err()
        );
    }

    #[test]
    fn default_detection_uses_configured_masks() {
        let masks = [0xff00_0000, 0x0000_ff00];
        assert!(needs_default(0xab00_0000, 0x0000_1200, &masks));
        assert!(!needs_default(0xab00_3400, 0x0000_1200, &masks));
        assert!(!needs_default(0, 0, &masks));
    }

    #[test]
    fn normalizes_ipv4_mapped_ipv6() {
        let mapped = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(
            normalize_client(mapped),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))
        );
    }
}
