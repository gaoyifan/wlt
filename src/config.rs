//! Configuration loading: `config.toml` plus `config.d/*.toml` fragments,
//! deep-merged in filename order before validation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use indexmap::IndexMap;
use nftables::types::NfFamily;
use serde::Deserialize;

use crate::config_file::load_merged_toml;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct WebConfig {
    /// Listen addresses; one listener is bound per address.
    #[serde(default = "default_web_listen")]
    pub listen: Vec<String>,
    pub https: Option<HttpsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HttpsConfig {
    pub listen: Vec<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SshConfig {
    #[serde(default = "default_ssh_listen")]
    pub listen: Vec<String>,
    #[serde(default = "default_ssh_host_key")]
    pub host_key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct PersistConfig {
    #[serde(default = "default_persist_path")]
    pub path: PathBuf,
    /// Snapshot interval in seconds.
    #[serde(default = "default_persist_interval")]
    pub interval: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct NftablesConfig {
    pub family: NfFamily,
    pub table: String,
    /// IPv4 client src -> mark map.
    pub map: String,
    /// IPv6 client src -> mark map (enables IPv6 selection).
    pub map_v6: Option<String>,
}

impl Default for NftablesConfig {
    fn default() -> Self {
        Self {
            family: NfFamily::INet,
            table: "wlt".into(),
            map: "src2mark".into(),
            map_v6: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct PortalHosts {
    pub v4_host: Option<String>,
    pub v6_host: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct PortalConfig {
    /// Split-horizon hostnames used by the dual-stack single-page UI: each one
    /// must resolve to a single address family so the browser reveals (and the
    /// backend registers) the client's address for that family.
    pub v4_host: Option<String>,
    pub v6_host: Option<String>,
    /// Per-page-host split-horizon API hosts. This lets the same WLT service be
    /// reachable through multiple vanity domains while keeping family-specific
    /// API requests on matching hostnames.
    #[serde(default)]
    pub hosts: IndexMap<String, PortalHosts>,
    /// Allow cross-origin API calls from this domain and its subdomains
    /// (the SPA on one split-horizon host fetches the sibling family's API).
    pub cors_domain: Option<String>,
    /// Additional CORS domains. Exact host matches and subdomains are allowed.
    #[serde(default)]
    pub cors_domains: Vec<String>,
}

impl PortalConfig {
    pub(crate) fn cors_domains(&self) -> Vec<String> {
        let mut domains = Vec::new();
        if let Some(domain) = self.cors_domain.as_deref()
            && !domain.is_empty()
        {
            domains.push(domain.to_owned());
        }
        for domain in &self.cors_domains {
            if !domain.is_empty() && !domains.contains(domain) {
                domains.push(domain.clone());
            }
        }
        domains
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OutletGroup {
    pub title: String,
    pub mask: u32,
    pub outlets: IndexMap<String, u32>,
    /// Parallel IPv6 outlet set. The same group title/mask serves both
    /// families; an IPv6 client is offered (and writes) `outlets_v6`.
    #[serde(default)]
    pub outlets_v6: IndexMap<String, u32>,
    /// When set, outlets whose name marks a CN-country exit (name starts with
    /// "CN ") are moved to the end of the displayed list, keeping their
    /// relative order. Only affects display order, not mark lookup.
    #[serde(default)]
    pub cn_last: bool,
}

impl OutletGroup {
    pub(crate) fn outlets_for(&self, family: u8) -> &IndexMap<String, u32> {
        if family == 6 {
            &self.outlets_v6
        } else {
            &self.outlets
        }
    }

    /// Name of this group's outlet whose mark matches `mark` under the mask.
    pub(crate) fn selection_for(&self, mark: u32, family: u8) -> Option<&str> {
        let masked = mark & self.mask;
        self.outlets_for(family)
            .iter()
            .find(|&(_, &value)| value & self.mask == masked)
            .map(|(name, _)| name.as_str())
    }

    pub(crate) fn display_outlets_for(&self, family: u8) -> Vec<(&str, u32)> {
        let outlets = self.outlets_for(family);
        let mut ordered: Vec<(&str, u32)> = Vec::with_capacity(outlets.len());
        let mut cn: Vec<(&str, u32)> = Vec::new();
        for (name, &mark) in outlets {
            if self.cn_last && name.starts_with("CN ") {
                cn.push((name, mark));
            } else {
                ordered.push((name, mark));
            }
        }
        ordered.extend(cn);
        ordered
    }
}

pub(crate) fn duration_label(hours: u32) -> String {
    if hours == 0 {
        "永久".into()
    } else {
        format!("{hours}小时")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AppConfig {
    pub web: Option<WebConfig>,
    pub ssh: Option<SshConfig>,
    pub persist: Option<PersistConfig>,
    #[serde(default)]
    pub nftables: NftablesConfig,
    #[serde(default)]
    pub portal: PortalConfig,
    pub outlet_groups: Vec<OutletGroup>,
    pub time_limits: Vec<u32>,
}

impl AppConfig {
    pub(crate) fn map_for(&self, family: u8) -> Option<&str> {
        if family == 6 {
            self.nftables.map_v6.as_deref()
        } else {
            Some(&self.nftables.map)
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.outlet_groups.is_empty(),
            "outlet_groups cannot be empty"
        );
        ensure!(!self.time_limits.is_empty(), "time_limits cannot be empty");
        let mut titles = std::collections::HashSet::new();
        for group in &self.outlet_groups {
            ensure!(
                titles.insert(&group.title),
                "outlet_groups titles must be unique: {}",
                group.title
            );
            ensure!(
                !group.outlets.is_empty(),
                "outlet_groups.outlets cannot be empty: {}",
                group.title
            );
        }
        Ok(())
    }
}

fn default_web_listen() -> Vec<String> {
    vec!["0.0.0.0:80".into()]
}

fn default_ssh_listen() -> Vec<String> {
    vec!["[::]:2222".into()]
}

fn default_ssh_host_key() -> PathBuf {
    "ssh_host_key".into()
}

fn default_persist_path() -> PathBuf {
    "/etc/nftables/wlt_src2mark.conf".into()
}

fn default_persist_interval() -> u64 {
    300
}

pub(crate) fn load_config(path: &Path, config_dir: Option<&Path>) -> Result<AppConfig> {
    let data = load_merged_toml(path, config_dir, None)?;
    let config: AppConfig =
        AppConfig::deserialize(data).context("Failed to validate merged config")?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_CONFIG: &str = r#"
time_limits = [1, 4, 8]

[web]
listen = ["0.0.0.0:80"]

[[outlet_groups]]
title = "国内出口"
mask = 0xFF00
[outlet_groups.outlets]
"默认" = 0x0
"中国电信" = 0x1200

[[outlet_groups]]
title = "海外出口"
mask = 0xFF
[outlet_groups.outlets]
"默认" = 0x0
"#;

    fn write(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn loads_main_config_without_config_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("config.toml");
        write(&main, BASE_CONFIG);

        let config = load_config(&main, None).unwrap();

        assert_eq!(config.web.as_ref().unwrap().listen, ["0.0.0.0:80"]);
        assert_eq!(config.outlet_groups[0].outlets["中国电信"], 0x1200);
    }

    #[test]
    fn loads_fragments_from_explicit_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("config.toml");
        let fragments = tmp.path().join("fragments");
        write(&main, BASE_CONFIG);
        write(
            &fragments.join("10-web.toml"),
            r#"
[web]
listen = ["127.0.0.1:8080"]
"#,
        );

        let config = load_config(&main, Some(&fragments)).unwrap();

        assert_eq!(config.web.as_ref().unwrap().listen, ["127.0.0.1:8080"]);
    }

    #[test]
    fn merges_toml_files_in_filename_order() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("config.toml");
        write(&main, BASE_CONFIG);
        write(
            &tmp.path().join("config.d/10-extra.toml"),
            r#"
[web]
listen = ["0.0.0.0:8080", "[::1]:8080"]

[[outlet_groups]]
title = "国内出口"
[outlet_groups.outlets]
"测试出口1" = 0xff00

[[outlet_groups]]
title = "新增分组"
mask = 0xF0000
[outlet_groups.outlets]
"新增出口" = 0x10000
"#,
        );
        write(
            &tmp.path().join("config.d/20-override.toml"),
            r#"
time_limits = [10, 24]

[[outlet_groups]]
title = "国内出口"
[outlet_groups.outlets]
"测试出口1" = 0xfe00
"测试出口2" = 0xfd00
"#,
        );

        let config = load_config(&main, None).unwrap();

        assert_eq!(
            config.web.as_ref().unwrap().listen,
            ["0.0.0.0:8080", "[::1]:8080"]
        );
        assert_eq!(config.time_limits, [10, 24]);
        let titles: Vec<&str> = config
            .outlet_groups
            .iter()
            .map(|g| g.title.as_str())
            .collect();
        assert_eq!(titles, ["国内出口", "海外出口", "新增分组"]);
        let domestic = &config.outlet_groups[0];
        assert_eq!(domestic.mask, 0xFF00);
        assert_eq!(domestic.outlets["中国电信"], 0x1200);
        assert_eq!(domestic.outlets["测试出口1"], 0xFE00);
        assert_eq!(domestic.outlets["测试出口2"], 0xFD00);
    }

    #[test]
    fn ignores_non_toml_files_and_subdirectories() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("config.toml");
        write(&main, BASE_CONFIG);
        write(&tmp.path().join("config.d/README.md"), "not toml");
        write(
            &tmp.path().join("config.d/nested/ignored.toml"),
            "this is not valid toml",
        );

        let config = load_config(&main, None).unwrap();

        assert_eq!(config.web.as_ref().unwrap().listen, ["0.0.0.0:80"]);
    }

    #[test]
    fn cn_last_moves_cn_outlets_to_the_end() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("config.toml");
        write(
            &main,
            r#"
time_limits = [1]

[[outlet_groups]]
title = "海外出口"
mask = 0xFF
cn_last = true
[outlet_groups.outlets]
"默认" = 0x0
"CN 合肥 | 中国电信" = 0x12
"JP 东京 | Cloudflare WARP" = 0x66
"CN 杭州 | 阿里云" = 0x40
"US 圣何塞 | Cloudflare WARP" = 0x67
"#,
        );

        let config = load_config(&main, None).unwrap();
        let group = &config.outlet_groups[0];

        let display: Vec<&str> = group
            .display_outlets_for(4)
            .iter()
            .map(|&(n, _)| n)
            .collect();
        assert_eq!(
            display,
            [
                "默认",
                "JP 东京 | Cloudflare WARP",
                "US 圣何塞 | Cloudflare WARP",
                "CN 合肥 | 中国电信",
                "CN 杭州 | 阿里云",
            ]
        );
        // Underlying outlets and mark lookups are untouched.
        assert_eq!(group.outlets["CN 合肥 | 中国电信"], 0x12);
        assert_eq!(group.outlets.get_index(1).unwrap().0, "CN 合肥 | 中国电信");
    }

    #[test]
    fn cn_last_defaults_off_and_preserves_order() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("config.toml");
        write(&main, BASE_CONFIG);

        let config = load_config(&main, None).unwrap();
        let overseas = &config.outlet_groups[1];

        assert!(!overseas.cn_last);
        let display: Vec<&str> = overseas
            .display_outlets_for(4)
            .iter()
            .map(|&(n, _)| n)
            .collect();
        let raw: Vec<&str> = overseas.outlets.keys().map(String::as_str).collect();
        assert_eq!(display, raw);
    }

    #[test]
    fn loads_portal_host_overrides_and_cors_domains() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("config.toml");
        write(
            &main,
            &format!(
                r#"{BASE_CONFIG}

[portal]
v4_host = "wlt-ipv4.example.net"
v6_host = "wlt-ipv6.example.net"
cors_domain = "example.net"
cors_domains = ["example.org", "example.net"]

[portal.hosts."wlt.example.org"]
v4_host = "wlt-ipv4.example.org"
v6_host = "wlt-ipv6.example.org"
"#
            ),
        );

        let config = load_config(&main, None).unwrap();

        assert_eq!(
            config.portal.hosts["wlt.example.org"].v4_host.as_deref(),
            Some("wlt-ipv4.example.org")
        );
        assert_eq!(
            config.portal.hosts["wlt.example.org"].v6_host.as_deref(),
            Some("wlt-ipv6.example.org")
        );
        assert_eq!(config.portal.cors_domains(), ["example.net", "example.org"]);
    }

    #[test]
    fn reports_the_invalid_fragment_filename() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("config.toml");
        write(&main, BASE_CONFIG);
        write(&tmp.path().join("config.d/10-invalid.toml"), "invalid = [");

        let err = format!("{:#}", load_config(&main, None).unwrap_err());
        assert!(
            err.contains("10-invalid.toml"),
            "error should name the fragment: {err}"
        );
    }
}
