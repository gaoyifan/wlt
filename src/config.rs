//! Configuration loading: `config.toml` plus `config.d/*.toml` fragments,
//! deep-merged in filename order before validation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use indexmap::IndexMap;
use nftables::types::NfFamily;
use serde::Deserialize;
use toml::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct WebConfig {
    /// Listen addresses; one listener is bound per address.
    #[serde(default = "default_web_listen")]
    pub listen: Vec<String>,
    pub https: Option<HttpsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpsConfig {
    pub listen: Vec<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SshConfig {
    #[serde(default = "default_ssh_listen")]
    pub listen: Vec<String>,
    #[serde(default = "default_ssh_host_key")]
    pub host_key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PersistConfig {
    #[serde(default = "default_persist_path")]
    pub path: PathBuf,
    /// Snapshot interval in seconds.
    #[serde(default = "default_persist_interval")]
    pub interval: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NftablesConfig {
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
pub struct PortalConfig {
    /// Split-horizon hostnames used by the dual-stack single-page UI: each one
    /// must resolve to a single address family so the browser reveals (and the
    /// backend registers) the client's address for that family.
    pub v4_host: Option<String>,
    pub v6_host: Option<String>,
    /// Allow cross-origin API calls from this domain and its subdomains
    /// (the SPA on one split-horizon host fetches the sibling family's API).
    pub cors_domain: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutletGroup {
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
    pub fn outlets_for(&self, family: u8) -> &IndexMap<String, u32> {
        if family == 6 {
            &self.outlets_v6
        } else {
            &self.outlets
        }
    }

    /// Name of this group's outlet whose mark matches `mark` under the mask.
    pub fn selection_for(&self, mark: u32, family: u8) -> Option<&str> {
        let masked = mark & self.mask;
        self.outlets_for(family)
            .iter()
            .find(|&(_, &value)| value & self.mask == masked)
            .map(|(name, _)| name.as_str())
    }

    pub fn display_outlets_for(&self, family: u8) -> Vec<(&str, u32)> {
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

pub fn duration_label(hours: u32) -> String {
    if hours == 0 {
        "永久".into()
    } else {
        format!("{hours}小时")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
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
    pub fn map_for(&self, family: u8) -> Option<&str> {
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

fn load_toml(path: &Path) -> Result<Value> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file {}", path.display()))?;
    let table: toml::Table = content
        .parse()
        .with_context(|| format!("Failed to parse config file {}", path.display()))?;
    Ok(Value::Table(table))
}

/// Merge `outlet_groups` arrays by group title; unmatched groups are appended.
fn merge_outlet_groups(base: Vec<Value>, other: Vec<Value>) -> Vec<Value> {
    let mut merged = base;
    for group in other {
        let title = group
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let existing = title.as_deref().and_then(|title| {
            merged
                .iter_mut()
                .find(|g| g.get("title").and_then(Value::as_str) == Some(title))
        });
        match existing {
            Some(slot) => merge_in_place(slot, group, None),
            None => merged.push(group),
        }
    }
    merged
}

/// `deep_merge` into an occupied slot without cloning the base value.
fn merge_in_place(slot: &mut Value, other: Value, key: Option<&str>) {
    let base = std::mem::replace(slot, Value::Boolean(false));
    *slot = deep_merge(base, other, key);
}

/// Recursive merge with Python-dict semantics: tables merge per key (keeping
/// the base key order), `outlet_groups` arrays merge by title, and any other
/// value (including plain arrays) is replaced by the override.
fn deep_merge(base: Value, other: Value, key: Option<&str>) -> Value {
    match (base, other) {
        (Value::Array(b), Value::Array(o)) if key == Some("outlet_groups") => {
            Value::Array(merge_outlet_groups(b, o))
        }
        (Value::Table(mut b), Value::Table(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(slot) => merge_in_place(slot, v, Some(&k)),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
            Value::Table(b)
        }
        (_, o) => o,
    }
}

pub fn load_config(path: &Path) -> Result<AppConfig> {
    if !path.is_file() {
        bail!("Failed to load config: {} not found", path.display());
    }
    let mut data = load_toml(path)?;

    let config_dir = path.parent().unwrap_or(Path::new(".")).join("config.d");
    if config_dir.exists() && !config_dir.is_dir() {
        bail!(
            "Failed to load config: {} is not a directory",
            config_dir.display()
        );
    }
    if config_dir.is_dir() {
        let mut fragments: Vec<PathBuf> = std::fs::read_dir(&config_dir)?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.is_file() && p.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        fragments.sort_by_key(|p| p.file_name().map(|n| n.to_owned()));
        for fragment in fragments {
            data = deep_merge(data, load_toml(&fragment)?, None);
        }
    }

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

        let config = load_config(&main).unwrap();

        assert_eq!(config.web.as_ref().unwrap().listen, ["0.0.0.0:80"]);
        assert_eq!(config.outlet_groups[0].outlets["中国电信"], 0x1200);
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

        let config = load_config(&main).unwrap();

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

        let config = load_config(&main).unwrap();

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

        let config = load_config(&main).unwrap();
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

        let config = load_config(&main).unwrap();
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
    fn reports_the_invalid_fragment_filename() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("config.toml");
        write(&main, BASE_CONFIG);
        write(&tmp.path().join("config.d/10-invalid.toml"), "invalid = [");

        let err = format!("{:#}", load_config(&main).unwrap_err());
        assert!(
            err.contains("10-invalid.toml"),
            "error should name the fragment: {err}"
        );
    }
}
