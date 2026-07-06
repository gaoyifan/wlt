//! Persist the nftables src2mark maps to a reloadable include file.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

use crate::config::{AppConfig, PersistConfig};
use crate::nft::{Nft, NftEntry};

fn map_names(cfg: &AppConfig) -> Vec<&str> {
    let mut names = vec![cfg.nftables.map.as_str()];
    if let Some(map_v6) = cfg.nftables.map_v6.as_deref()
        && !names.contains(&map_v6)
    {
        names.push(map_v6);
    }
    names
}

/// nftables reports timeout/expires in whole seconds; clamp to at least 1s so
/// the rendered element stays valid.
fn optional_seconds(value: Option<u32>) -> Option<u32> {
    value.map(|seconds| seconds.max(1))
}

fn sort_entries(mut entries: Vec<NftEntry>) -> Vec<NftEntry> {
    entries.sort_by(|a, b| {
        let (ka, kb) = (a.ip.parse::<IpAddr>().ok(), b.ip.parse::<IpAddr>().ok());
        ka.cmp(&kb).then_with(|| a.ip.cmp(&b.ip))
    });
    entries
}

pub fn render_snapshot(family: &str, table: &str, sections: &[(&str, Vec<NftEntry>)]) -> String {
    let mut lines = vec![
        "# Managed by wlt-persist. Manual changes will be overwritten.".to_owned(),
        "# Timeout counters resume from the saved remaining time after reload.".to_owned(),
    ];
    for (map_name, entries) in sections {
        if entries.is_empty() {
            continue;
        }
        lines.push(format!("add element {family} {table} {map_name} {{"));
        for (index, entry) in entries.iter().enumerate() {
            let mut options = String::new();
            if let Some(timeout) = optional_seconds(entry.timeout) {
                options.push_str(&format!(" timeout {timeout}s"));
            }
            if let Some(expires) = optional_seconds(entry.expires) {
                options.push_str(&format!(" expires {expires}s"));
            }
            let comma = if index + 1 < entries.len() { "," } else { "" };
            lines.push(format!(
                "    {}{} : {:#x}{}",
                entry.ip, options, entry.mark, comma
            ));
        }
        lines.push("}".to_owned());
    }
    lines.join("\n") + "\n"
}

/// Atomically replace `path` with `content` if it differs; fsyncs both the
/// file and its directory. Returns whether a write happened.
pub fn write_if_changed(path: &Path, content: &str) -> Result<bool> {
    if std::fs::read(path).is_ok_and(|existing| existing == content.as_bytes()) {
        return Ok(false);
    }

    let dir = path
        .parent()
        .context("snapshot path has no parent directory")?;
    std::fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("snapshot");
    let mut temp = tempfile::Builder::new()
        .prefix(&format!(".{file_name}."))
        .tempfile_in(dir)?;
    {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
        temp.write_all(content.as_bytes())?;
        temp.as_file().sync_all()?;
    }
    temp.persist(path).context("failed to replace snapshot")?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(true)
}

async fn save_snapshot(cfg: &AppConfig, nft: &Nft, path: &Path) -> Result<bool> {
    let mut sections = Vec::new();
    let mut total = 0;
    for map_name in map_names(cfg) {
        let entries = sort_entries(nft.list_entries(map_name).await?);
        total += entries.len();
        sections.push((map_name, entries));
    }
    let content = render_snapshot(nft.family_str(), nft.table(), &sections);
    let changed = write_if_changed(path, &content)?;
    if changed {
        tracing::info!("saved {total} src2mark entries to {}", path.display());
    } else {
        tracing::debug!("src2mark snapshot is unchanged");
    }
    Ok(changed)
}

async fn save_safely(cfg: &AppConfig, nft: &Nft, path: &Path) {
    if let Err(e) = save_snapshot(cfg, nft, path).await {
        tracing::error!("failed to save src2mark snapshot: {e:#}");
    }
}

pub async fn run(
    cfg: std::sync::Arc<AppConfig>,
    nft: Nft,
    persist: PersistConfig,
    shutdown: CancellationToken,
) -> Result<()> {
    let interval = Duration::from_secs(persist.interval);
    save_safely(&cfg, &nft, &persist.path).await;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(interval) => save_safely(&cfg, &nft, &persist.path).await,
        }
    }
    // Final snapshot so a clean shutdown loses nothing.
    save_safely(&cfg, &nft, &persist.path).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ip: &str, mark: u32, timeout: Option<u32>, expires: Option<u32>) -> NftEntry {
        NftEntry {
            ip: ip.into(),
            mark,
            timeout,
            expires,
        }
    }

    #[test]
    fn renders_permanent_and_timed_entries() {
        let sections = vec![(
            "src2mark",
            vec![
                entry("10.0.0.1", 0x1, None, None),
                entry("10.0.0.2", 0x1200, Some(3600), Some(0)),
            ],
        )];
        let text = render_snapshot("inet", "wlt", &sections);
        assert_eq!(
            text,
            "# Managed by wlt-persist. Manual changes will be overwritten.\n\
             # Timeout counters resume from the saved remaining time after reload.\n\
             add element inet wlt src2mark {\n\
             \x20   10.0.0.1 : 0x1,\n\
             \x20   10.0.0.2 timeout 3600s expires 1s : 0x1200\n\
             }\n"
        );
    }

    #[test]
    fn skips_empty_sections() {
        let sections = vec![
            ("src2mark", vec![]),
            ("src2mark6", vec![entry("fd00::1", 0x30, None, None)]),
        ];
        let text = render_snapshot("inet", "wlt", &sections);
        assert!(!text.contains("add element inet wlt src2mark {"));
        assert!(text.contains("add element inet wlt src2mark6 {\n    fd00::1 : 0x30\n}"));
    }

    #[test]
    fn sorts_entries_by_ip() {
        let entries = vec![
            entry("10.0.0.10", 1, None, None),
            entry("10.0.0.2", 2, None, None),
            entry("9.9.9.9", 3, None, None),
        ];
        let sorted = sort_entries(entries);
        let ips: Vec<&str> = sorted.iter().map(|e| e.ip.as_str()).collect();
        assert_eq!(ips, ["9.9.9.9", "10.0.0.2", "10.0.0.10"]);
    }

    #[test]
    fn write_if_changed_only_writes_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.conf");
        assert!(write_if_changed(&path, "hello\n").unwrap());
        assert!(!write_if_changed(&path, "hello\n").unwrap());
        assert!(write_if_changed(&path, "world\n").unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "world\n");
    }
}
