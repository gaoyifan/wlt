//! Label-aware local routing and public-upstream domain pins.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use hickory_proto::rr::Name;
use ipnet::IpNet;
use prefix_trie::joint::JointPrefixMap;

use super::config::{DnsOutletGroupConfig, LocalRouteConfig};

/// Routes local names and reverse lookups to a named local route.
#[derive(Debug)]
pub(super) struct RoutingTable {
    domains: SuffixTable,
    unqualified: Option<String>,
    reverse: JointPrefixMap<IpNet, String>,
}

impl RoutingTable {
    pub(super) fn new(routes: &[LocalRouteConfig]) -> Result<Self> {
        let mut domains = SuffixTable::default();
        let mut unqualified = None;
        let mut reverse = JointPrefixMap::new();

        for route in routes {
            for domain in &route.domains {
                domains.insert(domain, &route.name).with_context(|| {
                    format!("invalid domain route {domain:?} in {}", route.name)
                })?;
            }
            if route.unqualified {
                if let Some(existing) = &unqualified {
                    bail!(
                        "local routes {} and {} both claim unqualified names",
                        existing,
                        route.name
                    );
                }
                unqualified = Some(route.name.clone());
            }
            for cidr in &route.reverse_cidrs {
                let cidr = cidr.trunc();
                if let Some(existing) = reverse.get(&cidr) {
                    if existing != &route.name {
                        bail!(
                            "local routes {} and {} both claim reverse CIDR {}",
                            existing,
                            route.name,
                            cidr
                        );
                    }
                } else {
                    reverse.insert(cidr, route.name.clone());
                }
            }
        }

        Ok(Self {
            domains,
            unqualified,
            reverse,
        })
    }

    /// Returns the selected local route name, or `None` for a public query.
    pub(super) fn lookup(&self, name: &Name) -> Option<&str> {
        match parse_ptr_name(name) {
            PtrName::Address(address) => return self.lookup_reverse(address),
            PtrName::Invalid => return None,
            PtrName::NotReverse => {}
        }

        if name.iter().count() == 1 {
            return self.unqualified.as_deref();
        }
        self.domains.lookup(name)
    }

    fn lookup_reverse(&self, address: IpAddr) -> Option<&str> {
        self.reverse
            .get_lpm(&IpNet::from(address))
            .map(|(_, route)| route.as_str())
    }
}

/// Longest-suffix pins loaded from public upstream `domain_files`.
#[derive(Debug)]
pub(super) struct DomainPins {
    domains: SuffixTable,
}

impl DomainPins {
    #[cfg(test)]
    fn new<I, D, U>(entries: I) -> Result<Self>
    where
        I: IntoIterator<Item = (D, U)>,
        D: AsRef<str>,
        U: AsRef<str>,
    {
        let mut domains = SuffixTable::default();
        for (domain, upstream) in entries {
            domains.insert(domain.as_ref(), upstream.as_ref())?;
        }
        Ok(Self { domains })
    }

    pub(super) fn from_outlet_groups(outlet_groups: &[DnsOutletGroupConfig]) -> Result<Self> {
        let mut domains = SuffixTable::default();
        for group in outlet_groups {
            for path in &group.domain_files {
                load_domain_file(&mut domains, path, &group.title)?;
            }
        }
        Ok(Self { domains })
    }

    pub(super) fn lookup(&self, name: &Name) -> Option<&str> {
        self.domains.lookup(name)
    }
}

#[derive(Debug, Default)]
struct SuffixTable {
    entries: HashMap<Name, String>,
}

impl SuffixTable {
    fn insert(&mut self, suffix: &str, target: &str) -> Result<()> {
        let suffix = parse_suffix(suffix)?;
        match self.entries.get(&suffix) {
            Some(existing) if existing != target => bail!(
                "domain suffix {} is claimed by both {} and {}",
                suffix,
                existing,
                target
            ),
            Some(_) => {}
            None => {
                self.entries.insert(suffix, target.to_owned());
            }
        }
        Ok(())
    }

    fn lookup(&self, name: &Name) -> Option<&str> {
        let name = canonical_name(name);
        let label_count = name.iter().count();
        (1..=label_count)
            .rev()
            .find_map(|labels| self.entries.get(&name.trim_to(labels)).map(String::as_str))
    }
}

fn parse_suffix(value: &str) -> Result<Name> {
    let value = value.trim();
    if value.is_empty() {
        bail!("domain suffix cannot be empty");
    }
    let mut name = Name::from_ascii(value)
        .with_context(|| format!("invalid domain suffix {value:?}"))?
        .to_lowercase();
    if name.is_root() || name.iter().any(|label| label == b"*") {
        bail!("domain suffix must contain only concrete labels: {value:?}");
    }
    name.set_fqdn(true);
    Ok(name)
}

fn canonical_name(name: &Name) -> Name {
    let mut name = name.to_lowercase();
    name.set_fqdn(true);
    name
}

fn load_domain_file(table: &mut SuffixTable, path: &Path, upstream: &str) -> Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read domain classifier {}", path.display()))?;
    for (line_number, line) in contents.lines().enumerate() {
        let domain = line.trim();
        if domain.is_empty() || domain.starts_with('#') {
            continue;
        }
        table.insert(domain, upstream).with_context(|| {
            format!(
                "invalid domain classifier {}:{}",
                path.display(),
                line_number + 1
            )
        })?;
    }
    Ok(())
}

enum PtrName {
    NotReverse,
    Invalid,
    Address(IpAddr),
}

fn parse_ptr_name(name: &Name) -> PtrName {
    let labels: Vec<&[u8]> = name.iter().collect();
    let ipv4 = if has_suffix(&labels, &[b"in-addr", b"arpa"]) {
        true
    } else if has_suffix(&labels, &[b"ip6", b"arpa"]) {
        false
    } else {
        return PtrName::NotReverse;
    };
    if labels.len() != if ipv4 { 6 } else { 34 }
        || ipv4
            && labels[..4]
                .iter()
                .any(|label| label.len() > 1 && label[0] == b'0')
    {
        return PtrName::Invalid;
    }

    let mut name = name.clone();
    name.set_fqdn(true);
    name.parse_arpa_name()
        .map(|network| PtrName::Address(network.addr()))
        .unwrap_or(PtrName::Invalid)
}

fn has_suffix(labels: &[&[u8]], suffix: &[&[u8]]) -> bool {
    labels.len() >= suffix.len()
        && labels[labels.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    fn route(
        name: &str,
        domains: &[&str],
        unqualified: bool,
        reverse_cidrs: &[&str],
    ) -> LocalRouteConfig {
        LocalRouteConfig {
            name: name.to_owned(),
            domains: domains.iter().map(|value| (*value).to_owned()).collect(),
            unqualified,
            reverse_cidrs: reverse_cidrs
                .iter()
                .map(|value| value.parse().unwrap())
                .collect(),
            servers: vec!["127.0.0.1:53".parse().unwrap()],
            timeout_milliseconds: 500,
        }
    }

    fn name(value: &str) -> Name {
        Name::from_ascii(value).unwrap()
    }

    #[test]
    fn local_domains_use_label_aware_longest_suffix() {
        let table = RoutingTable::new(&[
            route("parent", &["example.com"], false, &[]),
            route("child", &["corp.example.com"], false, &[]),
        ])
        .unwrap();
        assert_eq!(table.lookup(&name("host.corp.example.com.")), Some("child"));
        assert_eq!(table.lookup(&name("corp.example.com.")), Some("child"));
        assert_eq!(table.lookup(&name("host.example.com.")), Some("parent"));
        assert_eq!(
            table.lookup(&name("deep.host.example.com.")),
            Some("parent")
        );
        assert_eq!(table.lookup(&name("example.com.")), Some("parent"));
        assert_eq!(table.lookup(&name("badexample.com.")), None);
        assert_eq!(table.lookup(&name("HOST.CORP.EXAMPLE.COM.")), Some("child"));
    }

    #[test]
    fn unqualified_names_have_one_explicit_route() {
        let table = RoutingTable::new(&[route("lan", &[], true, &[])]).unwrap();
        assert_eq!(table.lookup(&name("printer")), Some("lan"));
        assert_eq!(table.lookup(&name("printer.example")), None);

        let error =
            RoutingTable::new(&[route("one", &[], true, &[]), route("two", &[], true, &[])])
                .unwrap_err()
                .to_string();
        assert!(error.contains("both claim unqualified"));
    }

    #[test]
    fn reverse_routes_use_cidr_longest_prefix_match() {
        let table = RoutingTable::new(&[
            route("wide", &[], false, &["10.0.0.0/8", "fd00::/8"]),
            route("narrow", &[], false, &["10.20.0.0/16", "fd12:3456::/32"]),
        ])
        .unwrap();
        assert_eq!(
            table.lookup(&name("4.3.20.10.in-addr.arpa.")),
            Some("narrow")
        );
        assert_eq!(table.lookup(&name("4.3.21.10.in-addr.arpa.")), Some("wide"));
        assert_eq!(
            table.lookup(&Name::from("fd12:3456::1".parse::<Ipv6Addr>().unwrap())),
            Some("narrow")
        );
    }

    #[test]
    fn malformed_reverse_names_never_fall_through_to_domain_routes() {
        let table = RoutingTable::new(&[route(
            "catch",
            &["in-addr.arpa", "ip6.arpa"],
            false,
            &["0.0.0.0/0", "::/0"],
        )])
        .unwrap();
        assert_eq!(table.lookup(&name("1.2.3.in-addr.arpa.")), None);
        assert_eq!(table.lookup(&name("001.2.3.4.in-addr.arpa.")), None);
        assert_eq!(table.lookup(&name("g.0.ip6.arpa.")), None);
    }

    #[test]
    fn equal_reverse_prefixes_cannot_have_different_routes() {
        let error = RoutingTable::new(&[
            route("one", &[], false, &["10.0.0.0/8"]),
            route("two", &[], false, &["10.1.2.3/8"]),
        ])
        .unwrap_err()
        .to_string();
        assert!(error.contains("both claim reverse CIDR"));
    }

    #[test]
    fn domain_pins_use_longest_suffix_and_reject_conflicts() {
        let pins =
            DomainPins::new([("example.com", "default"), ("video.example.com", "video")]).unwrap();
        assert_eq!(pins.lookup(&name("example.com")), Some("default"));
        assert_eq!(pins.lookup(&name("cdn.video.example.com")), Some("video"));
        assert_eq!(pins.lookup(&name("www.example.com")), Some("default"));
        assert_eq!(pins.lookup(&name("notexample.com")), None);

        let error = DomainPins::new([("example.com", "one"), ("EXAMPLE.COM.", "two")])
            .unwrap_err()
            .to_string();
        assert!(error.contains("claimed by both"));
    }

    #[test]
    fn loads_domain_files_with_source_context() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("domains.txt");
        std::fs::write(&path, "# comment\nexample.com\n\nvideo.example.com\n").unwrap();
        let group = DnsOutletGroupConfig {
            title: "public".into(),
            mask: 0xff00,
            dns_server: "resolver".into(),
            default: true,
            outlets: Default::default(),
            outlets_v6: Default::default(),
            _cn_last: false,
            domain_files: vec![path],
            ip_files: Vec::new(),
            overrides: Vec::new(),
        };
        let pins = DomainPins::from_outlet_groups(&[group]).unwrap();
        assert_eq!(pins.lookup(&name("www.example.com")), Some("public"));
    }
}
