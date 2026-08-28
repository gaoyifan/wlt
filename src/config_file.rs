//! Loading and deep-merging a main TOML file with ordered config fragments.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use toml::Value;

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
                .find(|group| group.get("title").and_then(Value::as_str) == Some(title))
        });
        match existing {
            Some(slot) => merge_in_place(slot, group, None),
            None => merged.push(group),
        }
    }
    merged
}

fn merge_in_place(slot: &mut Value, other: Value, key: Option<&str>) {
    let base = std::mem::replace(slot, Value::Boolean(false));
    *slot = deep_merge(base, other, key);
}

/// Tables merge recursively, `outlet_groups` merge by title, and other values
/// (including ordinary arrays) are replaced by the later file.
fn deep_merge(base: Value, other: Value, key: Option<&str>) -> Value {
    match (base, other) {
        (Value::Array(base), Value::Array(other)) if key == Some("outlet_groups") => {
            Value::Array(merge_outlet_groups(base, other))
        }
        (Value::Table(mut base), Value::Table(other)) => {
            for (key, value) in other {
                match base.get_mut(&key) {
                    Some(slot) => merge_in_place(slot, value, Some(&key)),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
            Value::Table(base)
        }
        (_, other) => other,
    }
}

pub(crate) fn load_merged_toml(
    path: &Path,
    config_dir: Option<&Path>,
    fragment_key: Option<&str>,
) -> Result<Value> {
    if !path.is_file() {
        bail!("Failed to load config: {} not found", path.display());
    }
    let mut data = load_toml(path)?;

    let default_config_dir = path.parent().unwrap_or(Path::new(".")).join("config.d");
    let config_dir = config_dir.unwrap_or(&default_config_dir);
    if config_dir.exists() && !config_dir.is_dir() {
        bail!(
            "Failed to load config: {} is not a directory",
            config_dir.display()
        );
    }
    if config_dir.is_dir() {
        let mut fragments: Vec<PathBuf> = std::fs::read_dir(config_dir)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        fragments.sort_by_key(|path| path.file_name().map(|name| name.to_owned()));
        for fragment in fragments {
            let fragment = load_toml(&fragment)?;
            let fragment = match (fragment, fragment_key) {
                (Value::Table(mut table), Some(key)) => {
                    let mut selected = toml::Table::new();
                    if let Some(value) = table.remove(key) {
                        selected.insert(key.into(), value);
                    }
                    Value::Table(selected)
                }
                (fragment, _) => fragment,
            };
            data = deep_merge(data, fragment, None);
        }
    }

    Ok(data)
}
