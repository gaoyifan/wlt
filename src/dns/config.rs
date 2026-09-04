//! Strict configuration model for the DNS daemon.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use indexmap::IndexMap;
use ipnet::IpNet;
use nftables::types::NfFamily;
use regex::Regex;
use serde::Deserialize;

use crate::config_file::load_merged_toml;

use super::AddressFamily;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    pub(super) server: ServerConfig,
    pub(super) policy: PolicyConfig,
    #[serde(default)]
    pub(super) local_routes: Vec<LocalRouteConfig>,
    pub(super) dns_servers: IndexMap<String, DnsServerConfig>,
    pub(super) outlet_groups: Vec<DnsOutletGroupConfig>,
    #[serde(default)]
    pub(super) cache: CacheConfig,
    #[serde(default)]
    pub(super) metrics: MetricsConfig,
}

impl DnsConfig {
    pub fn parse(input: &str) -> Result<Self> {
        let config: Self = toml::from_str(input).context("failed to parse DNS configuration")?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &std::path::Path, config_dir: Option<&std::path::Path>) -> Result<Self> {
        let data = load_merged_toml(path, config_dir, Some("outlet_groups"))?;
        let config: Self =
            Self::deserialize(data).context("failed to validate merged DNS configuration")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        self.server.validate()?;
        self.policy.validate()?;
        self.cache.validate()?;
        ensure!(
            self.metrics.listen.port() != 0,
            "metrics.listen port must be nonzero"
        );

        let mut names = HashSet::new();
        let mut local_endpoints = HashSet::new();
        for route in &self.local_routes {
            route.validate()?;
            ensure!(
                names.insert(route.name.as_str()),
                "local route names must be unique: {}",
                route.name
            );
            local_endpoints.extend(route.servers.iter().copied());
        }

        let serves_ipv4 = self.server.listen.iter().any(SocketAddr::is_ipv4);
        let serves_ipv6 = self.server.listen.iter().any(SocketAddr::is_ipv6);
        let listeners: HashSet<_> = self.server.listen.iter().copied().collect();
        ensure!(!self.dns_servers.is_empty(), "dns_servers cannot be empty");
        for (name, server) in &self.dns_servers {
            server.validate(name)?;
            ensure!(
                !server.ipv4_endpoints.is_empty(),
                "DNS server {name} needs an IPv4 endpoint"
            );
            ensure!(
                !server.ipv6_endpoints.is_empty(),
                "DNS server {name} needs an IPv6 endpoint"
            );
            for endpoint in server.ipv4_endpoints.iter().chain(&server.ipv6_endpoints) {
                ensure!(
                    !listeners.contains(endpoint) && !local_endpoints.contains(endpoint),
                    "DNS server {name} endpoint {endpoint} overlaps a listener or local backend"
                );
            }
        }

        ensure!(
            !self.outlet_groups.is_empty(),
            "outlet_groups cannot be empty"
        );
        let mut defaults = 0;
        let mut titles = HashSet::new();
        for group in &self.outlet_groups {
            group.validate(&self.dns_servers, serves_ipv4, serves_ipv6)?;
            ensure!(
                titles.insert(group.title.as_str()),
                "outlet_groups titles must be unique: {}",
                group.title
            );
            ensure!(
                names.insert(group.title.as_str()),
                "local route and outlet group titles must be unique: {}",
                group.title
            );
            defaults += usize::from(group.default);
        }
        ensure!(defaults == 1, "exactly one outlet group must be default");
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerConfig {
    pub listen: Vec<SocketAddr>,
    pub max_response_ttl: u32,
    pub max_udp_payload: usize,
    pub max_dns_message: usize,
    pub max_doh_body: usize,
    pub max_tcp_connections: usize,
    pub max_tcp_connections_per_client: usize,
    pub max_inflight_queries: usize,
    pub tcp_idle_timeout_seconds: u64,
    pub shutdown_timeout_seconds: u64,
}

impl ServerConfig {
    fn validate(&self) -> Result<()> {
        ensure!(!self.listen.is_empty(), "server.listen cannot be empty");
        let mut listeners = HashSet::new();
        for listener in &self.listen {
            ensure!(listener.port() != 0, "server.listen ports must be nonzero");
            ensure!(
                listeners.insert(listener),
                "server.listen contains duplicate listener {listener}"
            );
        }
        ensure!(
            self.max_udp_payload >= 512,
            "server.max_udp_payload must be at least 512"
        );
        ensure!(
            self.max_dns_message >= 12,
            "server.max_dns_message must be at least 12"
        );
        ensure!(
            self.max_doh_body >= 12,
            "server.max_doh_body must be at least 12"
        );
        ensure!(
            self.max_udp_payload <= self.max_dns_message,
            "server.max_udp_payload cannot exceed server.max_dns_message"
        );
        ensure!(
            self.max_dns_message <= u16::MAX as usize,
            "server.max_dns_message cannot exceed 65535"
        );
        ensure!(
            self.max_doh_body <= self.max_dns_message,
            "server.max_doh_body cannot exceed server.max_dns_message"
        );
        ensure!(
            self.max_tcp_connections != 0,
            "server.max_tcp_connections must be nonzero"
        );
        ensure!(
            self.max_tcp_connections_per_client != 0,
            "server.max_tcp_connections_per_client must be nonzero"
        );
        ensure!(
            self.max_tcp_connections_per_client <= self.max_tcp_connections,
            "server.max_tcp_connections_per_client cannot exceed server.max_tcp_connections"
        );
        ensure!(
            self.max_inflight_queries != 0,
            "server.max_inflight_queries must be nonzero"
        );
        ensure!(
            self.tcp_idle_timeout_seconds != 0,
            "server.tcp_idle_timeout_seconds must be nonzero"
        );
        ensure!(
            self.shutdown_timeout_seconds != 0,
            "server.shutdown_timeout_seconds must be nonzero"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyConfig {
    #[serde(default = "default_nft_family")]
    pub family: NfFamily,
    pub table: String,
    pub ipv4_map: Option<String>,
    pub ipv6_map: Option<String>,
    #[serde(default)]
    pub default_eligible_interfaces: Vec<String>,
    pub ipv4_default_mark: Option<u32>,
    pub ipv6_default_mark: Option<u32>,
}

impl PolicyConfig {
    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.family, NfFamily::INet | NfFamily::IP | NfFamily::IP6),
            "policy.family must be inet, ip, or ip6"
        );
        ensure!(
            !self.table.trim().is_empty(),
            "policy.table cannot be empty"
        );
        ensure!(
            self.ipv4_map.is_some() == self.ipv4_default_mark.is_some(),
            "policy.ipv4_map and policy.ipv4_default_mark must be configured together"
        );
        ensure!(
            self.ipv6_map.is_some() == self.ipv6_default_mark.is_some(),
            "policy.ipv6_map and policy.ipv6_default_mark must be configured together"
        );
        if let Some(map) = &self.ipv4_map {
            ensure!(!map.trim().is_empty(), "policy.ipv4_map cannot be empty");
        }
        if let Some(map) = &self.ipv6_map {
            ensure!(!map.trim().is_empty(), "policy.ipv6_map cannot be empty");
        }
        if let (Some(ipv4_map), Some(ipv6_map)) = (&self.ipv4_map, &self.ipv6_map) {
            ensure!(
                ipv4_map != ipv6_map,
                "policy IPv4 and IPv6 map names must differ"
            );
        }
        match self.family {
            NfFamily::INet => ensure!(
                self.ipv4_map.is_some() || self.ipv6_map.is_some(),
                "inet policy needs at least one client map"
            ),
            NfFamily::IP => ensure!(
                self.ipv4_map.is_some() && self.ipv6_map.is_none(),
                "ip policy needs only the IPv4 client map"
            ),
            NfFamily::IP6 => ensure!(
                self.ipv4_map.is_none() && self.ipv6_map.is_some(),
                "ip6 policy needs only the IPv6 client map"
            ),
            _ => unreachable!("validated nftables family"),
        }
        let mut interfaces = HashSet::new();
        for interface in &self.default_eligible_interfaces {
            ensure!(
                !interface.trim().is_empty(),
                "policy.default_eligible_interfaces cannot contain an empty name"
            );
            ensure!(
                interfaces.insert(interface.as_str()),
                "policy.default_eligible_interfaces contains duplicate {interface}"
            );
        }
        Ok(())
    }
}

fn default_nft_family() -> NfFamily {
    NfFamily::INet
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalRouteConfig {
    pub name: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub unqualified: bool,
    #[serde(default)]
    pub reverse_cidrs: Vec<IpNet>,
    pub servers: Vec<SocketAddr>,
    pub timeout_milliseconds: u64,
}

impl LocalRouteConfig {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.trim().is_empty(),
            "local route name cannot be empty"
        );
        ensure!(
            self.unqualified || !self.domains.is_empty() || !self.reverse_cidrs.is_empty(),
            "local route {} has no routing predicate",
            self.name
        );
        ensure!(
            !self.servers.is_empty(),
            "local route {} has no servers",
            self.name
        );
        for server in &self.servers {
            ensure!(
                server.port() != 0,
                "local route {} has a server with port zero",
                self.name
            );
        }
        ensure!(
            self.timeout_milliseconds != 0,
            "local route {} timeout must be nonzero",
            self.name
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DnsServerConfig {
    pub protocol: UpstreamProtocol,
    #[serde(default)]
    pub ipv4_endpoints: Vec<SocketAddr>,
    #[serde(default)]
    pub ipv6_endpoints: Vec<SocketAddr>,
    pub tls_name: Option<String>,
    pub http_path: Option<String>,
}

impl DnsServerConfig {
    fn validate(&self, name: &str) -> Result<()> {
        ensure!(!name.trim().is_empty(), "DNS server name cannot be empty");
        let mut endpoints = HashSet::new();
        for endpoint in &self.ipv4_endpoints {
            ensure!(
                endpoint.is_ipv4(),
                "DNS server {name} has an IPv6 endpoint in ipv4_endpoints"
            );
            validate_endpoint(name, *endpoint, &mut endpoints)?;
        }
        for endpoint in &self.ipv6_endpoints {
            ensure!(
                endpoint.is_ipv6(),
                "DNS server {name} has an IPv4 endpoint in ipv6_endpoints"
            );
            validate_endpoint(name, *endpoint, &mut endpoints)?;
        }

        match self.protocol {
            UpstreamProtocol::Https => {
                let tls_name = self
                    .tls_name
                    .as_deref()
                    .filter(|name| !name.is_empty())
                    .with_context(|| format!("HTTPS DNS server {name} must specify tls_name"))?;
                validate_tls_name(tls_name)
                    .with_context(|| format!("invalid tls_name for DNS server {name}"))?;
                let path = self
                    .http_path
                    .as_deref()
                    .with_context(|| format!("HTTPS DNS server {name} must specify http_path"))?;
                ensure!(
                    path.starts_with('/') && !path.starts_with("//") && !path.contains(['?', '#']),
                    "HTTPS DNS server {name} http_path must be an absolute path without query or fragment"
                );
            }
            UpstreamProtocol::Udp | UpstreamProtocol::Tcp => {
                ensure!(
                    self.tls_name.is_none() && self.http_path.is_none(),
                    "non-HTTPS DNS server {name} cannot specify tls_name or http_path"
                );
            }
        }
        Ok(())
    }
}

fn validate_endpoint(
    server: &str,
    endpoint: SocketAddr,
    seen: &mut HashSet<SocketAddr>,
) -> Result<()> {
    ensure!(
        endpoint.port() != 0,
        "DNS server {server} has an endpoint with port zero"
    );
    ensure!(
        seen.insert(endpoint),
        "DNS server {server} contains duplicate endpoint {endpoint}"
    );
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DnsOutletGroupConfig {
    pub title: String,
    pub mask: u32,
    pub dns_server: String,
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub outlets: IndexMap<String, u32>,
    #[serde(default)]
    pub outlets_v6: IndexMap<String, u32>,
    /// Accepted so WLT and WLT-DNS can consume the same outlet fragments.
    #[serde(default, rename = "cn_last")]
    pub _cn_last: bool,
    #[serde(default)]
    pub domain_files: Vec<PathBuf>,
    #[serde(default)]
    pub ip_files: Vec<PathBuf>,
    #[serde(default)]
    pub overrides: Vec<DnsOverrideConfig>,
}

impl DnsOutletGroupConfig {
    fn validate(
        &self,
        dns_servers: &IndexMap<String, DnsServerConfig>,
        serves_ipv4: bool,
        serves_ipv6: bool,
    ) -> Result<()> {
        ensure!(
            !self.title.trim().is_empty(),
            "outlet group title cannot be empty"
        );
        ensure!(
            self.mask != 0,
            "outlet group {} mask must be nonzero",
            self.title
        );
        ensure!(
            dns_servers.contains_key(&self.dns_server),
            "outlet group {} references unknown DNS server {}",
            self.title,
            self.dns_server
        );
        ensure!(
            !serves_ipv4 || !self.outlets.is_empty(),
            "outlet group {} needs IPv4 outlets because an IPv4 listener is enabled",
            self.title
        );
        ensure!(
            !serves_ipv6 || !self.outlets_v6.is_empty(),
            "outlet group {} needs IPv6 outlets because an IPv6 listener is enabled",
            self.title
        );
        for override_config in &self.overrides {
            ensure!(
                dns_servers.contains_key(&override_config.dns_server),
                "outlet group {} override references unknown DNS server {}",
                self.title,
                override_config.dns_server
            );
            Regex::new(&override_config.outlet_regex).with_context(|| {
                format!(
                    "invalid outlet regex {:?} in outlet group {}",
                    override_config.outlet_regex, self.title
                )
            })?;
        }
        Ok(())
    }

    pub(super) fn outlets_for(&self, family: AddressFamily) -> &IndexMap<String, u32> {
        match family {
            AddressFamily::Ipv4 => &self.outlets,
            AddressFamily::Ipv6 => &self.outlets_v6,
        }
    }

    pub(super) fn outlet_name(&self, positioned_mark: u32, family: AddressFamily) -> Option<&str> {
        self.outlets_for(family)
            .iter()
            .find(|&(_, mark)| mark & self.mask == positioned_mark)
            .map(|(name, _)| name.as_str())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DnsOverrideConfig {
    pub outlet_regex: String,
    pub dns_server: String,
}

fn validate_tls_name(name: &str) -> Result<()> {
    ensure!(name.len() <= 253, "TLS name is too long");
    ensure!(!name.ends_with('.'), "TLS name must not end with a dot");
    ensure!(
        name.parse::<IpAddr>().is_err(),
        "TLS name must not be an IP address"
    );
    for label in name.split('.') {
        ensure!(
            !label.is_empty() && label.len() <= 63,
            "TLS name contains an invalid label"
        );
        ensure!(
            !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "TLS name contains an invalid label"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum UpstreamProtocol {
    Udp,
    Tcp,
    Https,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct CacheConfig {
    pub max_entries: u64,
    pub max_weight_bytes: u64,
    pub learned_view_min_ttl_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_weight_bytes: 64 * 1024 * 1024,
            learned_view_min_ttl_seconds: 600,
        }
    }
}

impl CacheConfig {
    fn validate(&self) -> Result<()> {
        ensure!(self.max_entries != 0, "cache.max_entries must be nonzero");
        ensure!(
            self.max_weight_bytes != 0,
            "cache.max_weight_bytes must be nonzero"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct MetricsConfig {
    pub listen: SocketAddr,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9421"
                .parse()
                .expect("static metrics address is valid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
[server]
listen = ["127.0.0.1:53", "[::1]:53"]
max_response_ttl = 60
max_udp_payload = 1232
max_dns_message = 65535
max_doh_body = 65535
max_tcp_connections = 512
max_tcp_connections_per_client = 64
max_inflight_queries = 2048
tcp_idle_timeout_seconds = 30
shutdown_timeout_seconds = 10

[policy]
family = "inet"
table = "wlt"
ipv4_map = "src2mark"
ipv6_map = "src2mark6"
default_eligible_interfaces = ["lan0"]
ipv4_default_mark = 0x0202
ipv6_default_mark = 0x0404

[[local_routes]]
name = "lan"
domains = ["home.arpa"]
unqualified = true
reverse_cidrs = ["10.0.0.0/8", "fd00::/8"]
servers = ["10.0.0.53:53"]
timeout_milliseconds = 800

[dns_servers.regional]
protocol = "udp"
ipv4_endpoints = ["223.5.5.5:53"]
ipv6_endpoints = ["[2400:3200::1]:53"]

[dns_servers.default]
protocol = "https"
ipv4_endpoints = ["1.1.1.1:443"]
ipv6_endpoints = ["[2606:4700:4700::1111]:443"]
tls_name = "cloudflare-dns.com"
http_path = "/dns-query"

[[outlet_groups]]
title = "regional"
mask = 0xff00
dns_server = "regional"
default = false
ip_files = ["regional-v4.txt", "regional-v6.txt"]
[outlet_groups.outlets]
"Default" = 0
"CN Hangzhou | Aliyun" = 0x1200
[outlet_groups.outlets_v6]
"Default" = 0
"CN Hangzhou | Aliyun" = 0x1200

[[outlet_groups]]
title = "default"
mask = 0xff
dns_server = "default"
default = true
[outlet_groups.outlets]
"Default" = 0
"CN Hangzhou | Aliyun" = 0x12
[outlet_groups.outlets_v6]
"Default" = 0
"CN Hangzhou | Aliyun" = 0x12

[[outlet_groups.overrides]]
outlet_regex = "^CN "
dns_server = "regional"
"#;

    #[test]
    fn parses_strict_config_and_applies_defaults() {
        let config = DnsConfig::parse(VALID).unwrap();
        assert_eq!(config.policy.family, NfFamily::INet);
        assert_eq!(config.cache.max_entries, 10_000);
        assert_eq!(config.cache.max_weight_bytes, 64 * 1024 * 1024);
        assert_eq!(config.cache.learned_view_min_ttl_seconds, 600);

        let custom = DnsConfig::parse(&format!(
            "{VALID}\n[cache]\nlearned_view_min_ttl_seconds = 42\n"
        ))
        .unwrap();
        assert_eq!(custom.cache.learned_view_min_ttl_seconds, 42);

        let existing = DnsConfig::parse(&format!(
            "{VALID}\n[cache]\nmax_entries = 20\nmax_weight_bytes = 4096\n"
        ))
        .unwrap();
        assert_eq!(existing.cache.learned_view_min_ttl_seconds, 600);
        assert_eq!(config.metrics.listen, "127.0.0.1:9421".parse().unwrap());
        assert_eq!(
            config.local_routes[0].reverse_cidrs[0],
            "10.0.0.0/8".parse::<IpNet>().unwrap()
        );
    }

    #[test]
    fn validates_policy_family_and_client_maps() {
        let defaulted = VALID.replace("family = \"inet\"\n", "");
        assert_eq!(
            DnsConfig::parse(&defaulted).unwrap().policy.family,
            NfFamily::INet
        );

        let ipv4 = VALID
            .replace("family = \"inet\"", "family = \"ip\"")
            .replace("ipv6_map = \"src2mark6\"\n", "")
            .replace("ipv6_default_mark = 0x0404\n", "");
        assert_eq!(DnsConfig::parse(&ipv4).unwrap().policy.family, NfFamily::IP);

        let ipv6 = VALID
            .replace("family = \"inet\"", "family = \"ip6\"")
            .replace("ipv4_map = \"src2mark\"\n", "")
            .replace("ipv4_default_mark = 0x0202\n", "");
        assert_eq!(
            DnsConfig::parse(&ipv6).unwrap().policy.family,
            NfFamily::IP6
        );

        let mixed = VALID.replace("family = \"inet\"", "family = \"ip\"");
        assert!(
            DnsConfig::parse(&mixed)
                .unwrap_err()
                .to_string()
                .contains("only the IPv4 client map")
        );

        let unsupported = VALID.replace("family = \"inet\"", "family = \"bridge\"");
        assert!(
            DnsConfig::parse(&unsupported)
                .unwrap_err()
                .to_string()
                .contains("must be inet, ip, or ip6")
        );
    }

    #[test]
    fn loads_shared_wlt_outlet_fragments_and_ignores_other_settings() {
        let directory = tempfile::tempdir().unwrap();
        let main = directory.path().join("wlt-dns.toml");
        let fragments = directory.path().join("config.d");
        std::fs::create_dir(&fragments).unwrap();
        std::fs::write(&main, VALID).unwrap();
        std::fs::write(
            fragments.join("10-outlets.toml"),
            r#"
time_limits = [1, 4, 24]

[[outlet_groups]]
title = "default"
cn_last = true
[outlet_groups.outlets]
"CN Shanghai | Telecom" = 0x13
[outlet_groups.outlets_v6]
"CN Shanghai | Telecom" = 0x13
"#,
        )
        .unwrap();

        let config = DnsConfig::load(&main, None).unwrap();
        let group = config
            .outlet_groups
            .iter()
            .find(|group| group.title == "default")
            .unwrap();
        assert_eq!(group.outlets["CN Shanghai | Telecom"], 0x13);
        assert_eq!(group.outlets_v6["CN Shanghai | Telecom"], 0x13);
    }

    #[test]
    fn rejects_unknown_fields() {
        let input = VALID.replace(
            "shutdown_timeout_seconds = 10",
            "shutdown_timeout_seconds = 10\nallowed_clients = [\"0.0.0.0/0\"]",
        );
        let error = DnsConfig::parse(&input).unwrap_err().to_string();
        assert!(error.contains("failed to parse DNS configuration"));
    }

    #[test]
    fn rejects_hostnames_as_endpoints() {
        let input = VALID.replace("223.5.5.5:53", "dns.example:53");
        assert!(DnsConfig::parse(&input).is_err());
    }

    #[test]
    fn rejects_zero_group_mask() {
        let input = VALID.replacen("mask = 0xff00", "mask = 0", 1);
        assert!(
            DnsConfig::parse(&input)
                .unwrap_err()
                .to_string()
                .contains("mask must be nonzero")
        );
    }

    #[test]
    fn rejects_duplicate_listeners() {
        let input = VALID.replace(
            "[\"127.0.0.1:53\", \"[::1]:53\"]",
            "[\"127.0.0.1:53\", \"127.0.0.1:53\"]",
        );
        assert!(
            DnsConfig::parse(&input)
                .unwrap_err()
                .to_string()
                .contains("duplicate listener")
        );
    }

    #[test]
    fn requires_exactly_one_default() {
        let no_default = VALID.replacen("default = true", "default = false", 1);
        assert!(
            DnsConfig::parse(&no_default)
                .unwrap_err()
                .to_string()
                .contains("exactly one")
        );

        let two_defaults = VALID.replacen("default = false", "default = true", 1);
        assert!(
            DnsConfig::parse(&two_defaults)
                .unwrap_err()
                .to_string()
                .contains("exactly one")
        );
    }

    #[test]
    fn validates_https_specific_fields() {
        let missing_tls = VALID.replace("tls_name = \"cloudflare-dns.com\"\n", "");
        assert!(
            DnsConfig::parse(&missing_tls)
                .unwrap_err()
                .to_string()
                .contains("tls_name")
        );

        let bad_path = VALID.replace("http_path = \"/dns-query\"", "http_path = \"dns-query\"");
        assert!(
            DnsConfig::parse(&bad_path)
                .unwrap_err()
                .to_string()
                .contains("http_path")
        );
    }

    #[test]
    fn validates_coherent_limits() {
        let input = VALID.replace("max_udp_payload = 1232", "max_udp_payload = 511");
        assert!(
            DnsConfig::parse(&input)
                .unwrap_err()
                .to_string()
                .contains("at least 512")
        );

        let input = VALID.replace(
            "max_tcp_connections_per_client = 64",
            "max_tcp_connections_per_client = 513",
        );
        assert!(
            DnsConfig::parse(&input)
                .unwrap_err()
                .to_string()
                .contains("per_client")
        );
    }

    #[test]
    fn ipv4_only_listener_still_requires_both_upstream_families() {
        let input = VALID
            .replace("[\"127.0.0.1:53\", \"[::1]:53\"]", "[\"127.0.0.1:53\"]")
            .replace("ipv6_endpoints = [\"[2400:3200::1]:53\"]\n", "");
        assert!(
            DnsConfig::parse(&input)
                .unwrap_err()
                .to_string()
                .contains("needs an IPv6 endpoint")
        );
    }

    #[test]
    fn rejects_public_endpoint_overlap() {
        let input = VALID.replace("223.5.5.5:53", "127.0.0.1:53");
        assert!(
            DnsConfig::parse(&input)
                .unwrap_err()
                .to_string()
                .contains("overlaps")
        );
    }

    #[test]
    fn validates_override_references_and_regexes() {
        let unknown = VALID.replace(
            "outlet_regex = \"^CN \"\ndns_server = \"regional\"",
            "outlet_regex = \"^CN \"\ndns_server = \"missing\"",
        );
        assert!(
            DnsConfig::parse(&unknown)
                .unwrap_err()
                .to_string()
                .contains("unknown DNS server missing")
        );

        let invalid = VALID.replace("outlet_regex = \"^CN \"", "outlet_regex = \"[\"");
        assert!(
            DnsConfig::parse(&invalid)
                .unwrap_err()
                .to_string()
                .contains("invalid outlet regex")
        );
    }
}
