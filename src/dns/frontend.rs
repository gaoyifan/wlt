use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use futures_util::{StreamExt, stream::FuturesOrdered};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, Name, RData, Record, RecordType, rdata::opt::EdnsCode},
};
use ipnet::IpNet;
use prefix_trie::joint::JointPrefixMap;
use regex::Regex;

use super::{
    AddressFamily,
    cache::{CacheKey, DnsCache},
    config::{
        DnsConfig, DnsOutletGroupConfig, DnsServerConfig, LocalRouteConfig, UpstreamProtocol,
    },
    exchange::{ExchangePool, ExchangeTarget},
    metrics::DnsMetrics,
    routing::{DomainPins, RoutingTable},
};

#[cfg(not(target_os = "linux"))]
use super::policy::UnsupportedPlatformPolicy as PlatformPolicy;
#[cfg(target_os = "linux")]
use super::policy_linux::NftWltPolicy as PlatformPolicy;

struct DnsUpstream {
    name: String,
    config: DnsServerConfig,
}

struct OutletOverride {
    outlet: Regex,
    dns_server: usize,
}

struct OutletGroup {
    config: DnsOutletGroupConfig,
    classifier: AddressClassifier,
    dns_server: usize,
    overrides: Vec<OutletOverride>,
}

impl OutletGroup {
    fn dns_server_for(&self, selection: super::policy::Selection, family: AddressFamily) -> usize {
        let positioned_mark = selection.positioned_mark(self.config.mask);
        let Some(outlet) = self.config.outlet_name(positioned_mark, family) else {
            return self.dns_server;
        };
        self.overrides
            .iter()
            .find(|override_config| override_config.outlet.is_match(outlet))
            .map(|override_config| override_config.dns_server)
            .unwrap_or(self.dns_server)
    }
}

pub(super) struct DnsFrontend {
    policy: Arc<PlatformPolicy>,
    routing: RoutingTable,
    local_routes: HashMap<String, LocalRouteConfig>,
    domain_pins: DomainPins,
    dns_servers: Vec<DnsUpstream>,
    outlet_groups: Vec<OutletGroup>,
    default_outlet_group: usize,
    exchange: ExchangePool,
    cache: DnsCache,
    metrics: DnsMetrics,
    max_response_ttl: u32,
}

impl DnsFrontend {
    pub(super) fn new(config: &DnsConfig, policy: Arc<PlatformPolicy>) -> Result<Self> {
        let routing = RoutingTable::new(&config.local_routes)?;
        let domain_pins = DomainPins::from_outlet_groups(&config.outlet_groups)?;
        let default_outlet_group = config
            .outlet_groups
            .iter()
            .position(|group| group.default)
            .context("default outlet group missing after validation")?;
        let dns_servers = config
            .dns_servers
            .iter()
            .map(|(name, config)| DnsUpstream {
                name: name.clone(),
                config: config.clone(),
            })
            .collect::<Vec<_>>();
        let dns_server_indices = dns_servers
            .iter()
            .enumerate()
            .map(|(index, server)| (server.name.as_str(), index))
            .collect::<HashMap<_, _>>();
        let outlet_groups = config
            .outlet_groups
            .iter()
            .cloned()
            .map(|group| {
                let dns_server = dns_server_indices[&group.dns_server.as_str()];
                let overrides = group
                    .overrides
                    .iter()
                    .map(|override_config| {
                        Ok(OutletOverride {
                            outlet: Regex::new(&override_config.outlet_regex)?,
                            dns_server: dns_server_indices[&override_config.dns_server.as_str()],
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(OutletGroup {
                    classifier: AddressClassifier::from_files(&group.ip_files)?,
                    config: group,
                    dns_server,
                    overrides,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            policy,
            routing,
            local_routes: config
                .local_routes
                .iter()
                .cloned()
                .map(|route| (route.name.clone(), route))
                .collect(),
            domain_pins,
            dns_servers,
            outlet_groups,
            default_outlet_group,
            exchange: ExchangePool::new(
                config.server.max_tcp_connections as u64,
                Duration::from_secs(config.server.tcp_idle_timeout_seconds),
                config.server.max_doh_body,
            ),
            cache: DnsCache::new(config.cache.max_entries, config.cache.max_weight_bytes),
            metrics: DnsMetrics,
            max_response_ttl: config.server.max_response_ttl,
        })
    }

    pub(super) async fn handle(&self, peer: SocketAddr, request: Message) -> Message {
        let mut response = self.answer(peer, request).await;
        cap_response_ttls(&mut response, self.max_response_ttl);
        response
    }

    async fn answer(&self, peer: SocketAddr, mut request: Message) -> Message {
        let original_id = request.metadata.id;
        if request.metadata.message_type != MessageType::Query || request.queries.len() != 1 {
            return response_from_request(&request, ResponseCode::FormErr);
        }
        let query = request.queries[0].clone();
        if request.metadata.op_code != OpCode::Query || query.query_class() != DNSClass::IN {
            return response_from_request(&request, ResponseCode::NotImp);
        }

        if let Some(route_name) = self.routing.lookup(query.name()) {
            match self.answer_local(route_name, request.clone()).await {
                Ok(response) => return response,
                Err(error) => {
                    tracing::debug!(
                        %peer,
                        route = route_name,
                        %error,
                        "local DNS route missed; falling back to public DNS"
                    );
                }
            }
        }

        strip_ecs(&mut request);

        let selection = match self.policy.snapshot(peer.ip()).await {
            Ok(selection) => selection,
            Err(error) => {
                tracing::warn!(%peer, %error, "DNS policy lookup failed");
                return response_for(original_id, &query, ResponseCode::ServFail);
            }
        };
        request.metadata.id = 0;
        let normalized_request = match request.to_vec() {
            Ok(wire) => Arc::from(wire),
            Err(_) => return response_for(original_id, &query, ResponseCode::FormErr),
        };
        let key = CacheKey {
            normalized_request,
            peer_family: AddressFamily::from(peer.ip()),
            selection,
        };
        let loaded = self
            .cache
            .get_or_try_insert_with(key, async {
                let mut response = self
                    .answer_public(peer.ip(), &query, &request, selection)
                    .await?;
                strip_ecs(&mut response);
                response.metadata.id = 0;
                Ok(response)
            })
            .await;
        let (mut response, cache_hit) = match loaded {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(%peer, %error, "all eligible DNS upstreams failed");
                return response_for(original_id, &query, ResponseCode::ServFail);
            }
        };
        self.metrics.cache_lookup(cache_hit);
        self.metrics
            .cache_size(self.cache.entry_count(), self.cache.weighted_size());
        response.metadata.id = original_id;
        response
    }

    async fn answer_local(&self, route_name: &str, request: Message) -> Result<Message> {
        let route = self
            .local_routes
            .get(route_name)
            .expect("routing index must refer to an immutable local route");
        let timeout = Duration::from_millis(route.timeout_milliseconds);
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_error = None;
        for endpoint in &route.servers {
            let target = ExchangeTarget {
                endpoint: *endpoint,
                protocol: UpstreamProtocol::Udp,
                mark: 0,
                timeout,
                tls_name: None,
                http_path: Arc::from("/dns-query"),
            };
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, self.exchange.exchange(&target, request.clone()))
                .await
            {
                Ok(Ok(response)) if local_response_succeeded(&response) => {
                    return Ok(response);
                }
                Ok(Ok(response)) => {
                    last_error = Some(anyhow!(
                        "local DNS server returned {} with {} answers",
                        response.metadata.response_code,
                        response.answers.len()
                    ));
                }
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => last_error = Some(anyhow!("local DNS route timed out")),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("local route has no servers")))
    }

    async fn answer_public(
        &self,
        peer: IpAddr,
        query: &hickory_proto::op::Query,
        request: &Message,
        selection: super::policy::Selection,
    ) -> Result<Message> {
        if let Some(pin) = self.domain_pins.lookup(query.name()) {
            let group_index = self
                .outlet_groups
                .iter()
                .position(|group| group.config.title == pin)
                .expect("domain pin must refer to an immutable outlet group");
            return self
                .query_outlet_group(group_index, peer, request, selection)
                .await;
        }

        if !matches!(query.query_type(), RecordType::A | RecordType::AAAA) {
            return self
                .query_outlet_group(self.default_outlet_group, peer, request, selection)
                .await;
        }

        let mut pending = self
            .outlet_groups
            .iter()
            .enumerate()
            .map(|(index, _)| self.query_outlet_group(index, peer, request, selection))
            .collect::<FuturesOrdered<_>>()
            .enumerate();
        let mut default_result = None;
        while let Some((index, result)) = pending.next().await {
            if let Ok(response) = &result
                && self.outlet_groups[index]
                    .classifier
                    .matches_response(response)
            {
                let mut response = response.clone();
                reorder_matching(&mut response, &self.outlet_groups[index].classifier);
                return Ok(response);
            }
            if index == self.default_outlet_group {
                default_result = Some(result);
            }
        }
        default_result.expect("validated default index")
    }

    async fn query_outlet_group(
        &self,
        group_index: usize,
        peer: IpAddr,
        request: &Message,
        selection: super::policy::Selection,
    ) -> Result<Message> {
        let query_type = request
            .queries
            .first()
            .expect("validated public request must contain one query")
            .query_type();
        let preferred_family = preferred_upstream_family(query_type, peer);
        if !matches!(query_type, RecordType::A | RecordType::AAAA) {
            return self
                .query_outlet_group_via(group_index, peer, preferred_family, request, selection)
                .await;
        }
        let fallback_family = match preferred_family {
            AddressFamily::Ipv4 => AddressFamily::Ipv6,
            AddressFamily::Ipv6 => AddressFamily::Ipv4,
        };
        let mut attempts = [preferred_family, fallback_family]
            .into_iter()
            .map(|family| {
                self.query_outlet_group_via(group_index, peer, family, request, selection)
            })
            .collect::<FuturesOrdered<_>>();
        match attempts.next().await.expect("preferred family missing") {
            Ok(response) => Ok(response),
            Err(_) => attempts.next().await.expect("fallback family missing"),
        }
    }

    async fn query_outlet_group_via(
        &self,
        group_index: usize,
        peer: IpAddr,
        upstream_family: AddressFamily,
        request: &Message,
        selection: super::policy::Selection,
    ) -> Result<Message> {
        let group = &self.outlet_groups[group_index];
        let dns_server =
            &self.dns_servers[group.dns_server_for(selection, AddressFamily::from(peer))];
        let endpoints = match upstream_family {
            AddressFamily::Ipv4 => &dns_server.config.ipv4_endpoints,
            AddressFamily::Ipv6 => &dns_server.config.ipv6_endpoints,
        };
        if endpoints.is_empty() {
            return Err(anyhow!(
                "DNS server {} has no {upstream_family:?} endpoint",
                dns_server.name,
            ));
        }
        let protocol = dns_server.config.protocol;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut last_error = None;
        for endpoint in endpoints {
            let target = ExchangeTarget {
                endpoint: *endpoint,
                protocol,
                mark: selection.routing_mark(group.config.mask),
                timeout: Duration::from_secs(5),
                tls_name: dns_server.config.tls_name.as_deref().map(Arc::from),
                http_path: dns_server
                    .config
                    .http_path
                    .as_deref()
                    .map(Arc::from)
                    .unwrap_or_else(|| Arc::from("/dns-query")),
            };
            let started = Instant::now();
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                last_error = Some(anyhow!("public DNS upstream timed out"));
                break;
            }
            let response = match tokio::time::timeout(
                remaining,
                self.exchange.exchange(&target, request.clone()),
            )
            .await
            {
                Ok(response) => response,
                Err(_) => Err(anyhow!("public DNS upstream timed out")),
            };
            self.metrics.upstream_request(
                &dns_server.name,
                protocol_label(protocol),
                if response.is_ok() { "success" } else { "error" },
                started.elapsed(),
            );
            match response {
                Ok(response) => return Ok(response),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.expect("non-empty endpoint list must produce an outcome"))
    }
}

fn local_response_succeeded(response: &Message) -> bool {
    response.metadata.response_code == ResponseCode::NoError
}

fn preferred_upstream_family(query_type: RecordType, peer: IpAddr) -> AddressFamily {
    match query_type {
        RecordType::A => AddressFamily::Ipv4,
        RecordType::AAAA => AddressFamily::Ipv6,
        _ => AddressFamily::from(peer),
    }
}

fn protocol_label(protocol: UpstreamProtocol) -> &'static str {
    match protocol {
        UpstreamProtocol::Udp => "udp",
        UpstreamProtocol::Tcp => "tcp",
        UpstreamProtocol::Https => "doh",
    }
}

fn strip_ecs(message: &mut Message) {
    if let Some(edns) = message.edns.as_mut() {
        edns.options_mut().remove(EdnsCode::Subnet);
    }
}

fn cap_response_ttls(message: &mut Message, maximum: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(&mut message.authorities)
        .chain(&mut message.additionals)
    {
        record.ttl = record.ttl.min(maximum);
    }
}

fn response_from_request(request: &Message, code: ResponseCode) -> Message {
    request
        .queries
        .first()
        .map(|query| response_for(request.metadata.id, query, code))
        .unwrap_or_else(|| {
            let mut response = Message::new(
                request.metadata.id,
                MessageType::Response,
                request.metadata.op_code,
            );
            response.metadata.response_code = code;
            response
        })
}

fn response_for(id: u16, query: &hickory_proto::op::Query, code: ResponseCode) -> Message {
    let mut response = Message::new(id, MessageType::Response, OpCode::Query);
    response.add_query(query.clone());
    response.metadata.response_code = code;
    response
}

#[derive(Debug)]
struct AddressClassifier {
    prefixes: JointPrefixMap<IpNet, ()>,
}

impl AddressClassifier {
    fn from_files(paths: &[impl AsRef<Path>]) -> Result<Self> {
        let mut prefixes = JointPrefixMap::new();
        for path in paths {
            let path = path.as_ref();
            let contents = fs::read_to_string(path)
                .with_context(|| format!("failed to read IP classifier {}", path.display()))?;
            for (line_number, line) in contents.lines().enumerate() {
                let value = line.trim();
                if value.is_empty() || value.starts_with('#') {
                    continue;
                }
                let prefix: IpNet = value.parse().with_context(|| {
                    format!(
                        "invalid IP classifier {}:{}",
                        path.display(),
                        line_number + 1
                    )
                })?;
                prefixes.insert(prefix.trunc(), ());
            }
        }
        Ok(Self { prefixes })
    }

    #[cfg(test)]
    fn new(prefixes: &[&str]) -> Self {
        let mut map = JointPrefixMap::new();
        for prefix in prefixes {
            map.insert(prefix.parse::<IpNet>().unwrap(), ());
        }
        Self { prefixes: map }
    }

    fn matches(&self, address: IpAddr) -> bool {
        self.prefixes.get_lpm(&IpNet::from(address)).is_some()
    }

    fn matches_response(&self, response: &Message) -> bool {
        response
            .answers
            .iter()
            .any(|record| record_address(record).is_some_and(|address| self.matches(address)))
    }
}

fn record_address(record: &Record) -> Option<IpAddr> {
    match &record.data {
        RData::A(address) => Some(IpAddr::V4(address.0)),
        RData::AAAA(address) => Some(IpAddr::V6(address.0)),
        _ => None,
    }
}

fn reorder_matching(message: &mut Message, classifier: &AddressClassifier) {
    let mut groups: HashMap<(Name, RecordType, DNSClass), Vec<usize>> = HashMap::new();
    for (index, record) in message.answers.iter().enumerate() {
        if record_address(record).is_some() {
            groups
                .entry((record.name.clone(), record.record_type(), record.dns_class))
                .or_default()
                .push(index);
        }
    }
    for indices in groups.into_values() {
        let records: Vec<Record> = indices
            .iter()
            .map(|index| message.answers[*index].clone())
            .collect();
        let reordered = records
            .iter()
            .filter(|record| {
                record_address(record).is_some_and(|address| classifier.matches(address))
            })
            .chain(records.iter().filter(|record| {
                !record_address(record).is_some_and(|address| classifier.matches(address))
            }))
            .cloned();
        for (index, record) in indices.into_iter().zip(reordered) {
            message.answers[index] = record;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use hickory_proto::{
        op::Query,
        rr::{
            RData, Record,
            rdata::{A, AAAA},
        },
    };
    use indexmap::IndexMap;

    use super::*;

    #[test]
    fn classifier_accepts_both_families() {
        let classifier = AddressClassifier::new(&["10.0.0.0/8", "2001:db8::/32"]);
        assert!(classifier.matches("10.1.2.3".parse().unwrap()));
        assert!(classifier.matches("2001:db8::1".parse().unwrap()));
        assert!(!classifier.matches("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn local_response_accepts_positive_and_nodata_answers() {
        let name = Name::from_ascii("host.example.test.").unwrap();
        let mut answered = Message::response(1, OpCode::Query);
        answered.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        assert!(local_response_succeeded(&answered));

        let mut empty = Message::response(1, OpCode::Query);
        empty.add_query(Query::query(name, RecordType::AAAA));
        assert!(local_response_succeeded(&empty));

        let mut refused = answered;
        refused.metadata.response_code = ResponseCode::Refused;
        assert!(!local_response_succeeded(&refused));

        let mut nxdomain = Message::response(1, OpCode::Query);
        nxdomain.metadata.response_code = ResponseCode::NXDomain;
        assert!(!local_response_succeeded(&nxdomain));
    }

    #[test]
    fn address_queries_prefer_upstream_family_matching_record_type() {
        let peer_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let peer_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        assert_eq!(
            preferred_upstream_family(RecordType::A, peer_v4),
            AddressFamily::Ipv4
        );
        assert_eq!(
            preferred_upstream_family(RecordType::A, peer_v6),
            AddressFamily::Ipv4
        );
        assert_eq!(
            preferred_upstream_family(RecordType::AAAA, peer_v4),
            AddressFamily::Ipv6
        );
        assert_eq!(
            preferred_upstream_family(RecordType::AAAA, peer_v6),
            AddressFamily::Ipv6
        );
    }

    #[test]
    fn other_queries_keep_using_client_family() {
        assert_eq!(
            preferred_upstream_family(RecordType::TXT, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            AddressFamily::Ipv4
        );
        assert_eq!(
            preferred_upstream_family(RecordType::TXT, IpAddr::V6(Ipv6Addr::LOCALHOST)),
            AddressFamily::Ipv6
        );
    }

    #[test]
    fn outlet_overrides_match_selected_name_by_client_family_and_order() {
        let group = OutletGroup {
            config: DnsOutletGroupConfig {
                title: "Primary outlets".into(),
                mask: 0xff,
                dns_server: "cloudflare".into(),
                default: true,
                outlets: IndexMap::from([
                    ("Default".into(), 0),
                    ("CN Hangzhou | Aliyun".into(), 0x12),
                ]),
                outlets_v6: IndexMap::from([
                    ("Default".into(), 0),
                    ("US San Jose | Oracle".into(), 0x12),
                ]),
                _cn_last: false,
                domain_files: Vec::new(),
                ip_files: Vec::new(),
                overrides: Vec::new(),
            },
            classifier: AddressClassifier::new(&[]),
            dns_server: 0,
            overrides: vec![
                OutletOverride {
                    outlet: Regex::new("^CN ").unwrap(),
                    dns_server: 1,
                },
                OutletOverride {
                    outlet: Regex::new("Aliyun$").unwrap(),
                    dns_server: 2,
                },
            ],
        };
        let selected = super::super::policy::Selection {
            map_mark: 0x12,
            default_mark: 0,
        };
        assert_eq!(group.dns_server_for(selected, AddressFamily::Ipv4), 1);
        assert_eq!(group.dns_server_for(selected, AddressFamily::Ipv6), 0);

        let defaulted = super::super::policy::Selection {
            map_mark: 0,
            default_mark: 0x12,
        };
        assert_eq!(group.dns_server_for(defaulted, AddressFamily::Ipv4), 1);
    }

    #[test]
    fn response_ttl_limit_covers_every_record_section() {
        let name = Name::from_ascii("example.test.").unwrap();
        let record = |ttl| Record::from_rdata(name.clone(), ttl, RData::A(A(Ipv4Addr::LOCALHOST)));
        let mut response = Message::response(1, OpCode::Query);
        response.add_answer(record(300));
        response.add_authority(record(120));
        response.add_additional(record(30));

        cap_response_ttls(&mut response, 60);

        assert_eq!(response.answers[0].ttl, 60);
        assert_eq!(response.authorities[0].ttl, 60);
        assert_eq!(response.additionals[0].ttl, 30);
    }

    #[tokio::test]
    async fn response_ttl_limit_does_not_change_cached_ttl() {
        let name = Name::from_ascii("example.test.").unwrap();
        let mut response = Message::response(1, OpCode::Query);
        response.add_query(Query::query(name.clone(), RecordType::A));
        response.add_answer(Record::from_rdata(
            name,
            300,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        let key = CacheKey {
            normalized_request: Arc::from([0_u8, 0, 1, 0]),
            peer_family: AddressFamily::Ipv4,
            selection: super::super::policy::Selection {
                map_mark: 1,
                default_mark: 2,
            },
        };
        let cache = DnsCache::new(10, 10_000);
        let (mut client_response, cache_hit) = cache
            .get_or_try_insert_with(key.clone(), async { Ok(response) })
            .await
            .unwrap();
        assert!(!cache_hit);

        cap_response_ttls(&mut client_response, 60);
        let (cached_response, cache_hit) = cache
            .get_or_try_insert_with(key, async { panic!("cache entry was not reused") })
            .await
            .unwrap();

        assert_eq!(client_response.answers[0].ttl, 60);
        assert!(cache_hit);
        assert_eq!(cached_response.answers[0].ttl, 300);
    }

    #[test]
    fn reorder_is_stable_and_does_not_prune() {
        let name = Name::from_ascii("example.test.").unwrap();
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        for address in [[192, 0, 2, 1], [10, 0, 0, 1], [10, 0, 0, 2], [192, 0, 2, 2]] {
            message.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A(Ipv4Addr::from(address))),
            ));
        }
        message.add_answer(Record::from_rdata(
            name,
            60,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        ));
        reorder_matching(&mut message, &AddressClassifier::new(&["10.0.0.0/8"]));
        let addresses: Vec<_> = message.answers.iter().filter_map(record_address).collect();
        assert_eq!(addresses.len(), 5);
        assert_eq!(addresses[0], "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[1], "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[2], "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[3], "192.0.2.2".parse::<IpAddr>().unwrap());
    }
}
