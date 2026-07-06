//! Thin wrapper around the nftables JSON API (via the `nftables` crate) for
//! the `src ip -> mark` maps.

use std::borrow::Cow;
use std::net::IpAddr;

use anyhow::{Context, Result, anyhow};
use nftables::expr::{self, Expression, NamedExpression};
use nftables::helper::{self, DEFAULT_NFT};
use nftables::schema::{Element, NfCmd, NfListObject, NfObject, Nftables};
use nftables::types::NfFamily;

use crate::config::NftablesConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftEntry {
    pub ip: String,
    pub mark: u32,
    pub timeout: Option<u32>,
    pub expires: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Nft {
    family: NfFamily,
    table: String,
}

pub fn family_str(family: NfFamily) -> &'static str {
    match family {
        NfFamily::IP => "ip",
        NfFamily::IP6 => "ip6",
        NfFamily::INet => "inet",
        NfFamily::ARP => "arp",
        NfFamily::Bridge => "bridge",
        NfFamily::NetDev => "netdev",
    }
}

fn expr_to_ip(expr: &Expression) -> Option<String> {
    match expr {
        Expression::String(s) => Some(s.to_string()),
        // Interval maps may report entries as prefixes; a full-length prefix
        // is just the address itself.
        Expression::Named(NamedExpression::Prefix(p)) => {
            let addr = match p.addr.as_ref() {
                Expression::String(s) => s.to_string(),
                _ => return None,
            };
            let full = match addr.parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => p.len == 32,
                Ok(IpAddr::V6(_)) => p.len == 128,
                Err(_) => false,
            };
            Some(if full {
                addr
            } else {
                format!("{addr}/{}", p.len)
            })
        }
        _ => None,
    }
}

fn expr_to_mark(expr: &Expression) -> Option<u32> {
    match expr {
        Expression::Number(n) => Some(*n),
        Expression::String(s) => {
            let s = s.trim();
            match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => s.parse().ok(),
            }
        }
        _ => None,
    }
}

impl Nft {
    pub fn new(config: &NftablesConfig) -> Self {
        Self {
            family: config.family,
            table: config.table.clone(),
        }
    }

    pub fn family_str(&self) -> &'static str {
        family_str(self.family)
    }

    pub fn table(&self) -> &str {
        &self.table
    }

    /// All entries of the given map, in listing order.
    pub async fn list_entries(&self, map_name: &str) -> Result<Vec<NftEntry>> {
        let args = ["list", "map", self.family_str(), &self.table, map_name];
        let ruleset = helper::get_current_ruleset_with_args_async(DEFAULT_NFT, &args)
            .await
            .with_context(|| format!("nft list map {map_name} failed"))?;

        let map = ruleset
            .objects
            .iter()
            .find_map(|obj| match obj {
                NfObject::ListObject(NfListObject::Map(m)) => Some(m),
                _ => None,
            })
            .ok_or_else(|| anyhow!("nftables JSON does not contain map {map_name}"))?;

        let mut entries = Vec::new();
        for item in map.elem.as_deref().unwrap_or_default() {
            let Expression::List(pair) = item else {
                return Err(anyhow!("unexpected nftables map element: {item:?}"));
            };
            let [key, value] = pair.as_slice() else {
                return Err(anyhow!("unexpected nftables map element: {pair:?}"));
            };
            let (ip_expr, timeout, expires) = match key {
                Expression::Named(NamedExpression::Elem(elem)) => {
                    (elem.val.as_ref(), elem.timeout, elem.expires)
                }
                other => (other, None, None),
            };
            let ip = expr_to_ip(ip_expr)
                .ok_or_else(|| anyhow!("unexpected nftables map key: {ip_expr:?}"))?;
            let mark = expr_to_mark(value)
                .ok_or_else(|| anyhow!("unexpected nftables map value: {value:?}"))?;
            entries.push(NftEntry {
                ip,
                mark,
                timeout,
                expires,
            });
        }
        Ok(entries)
    }

    pub async fn get_entry(&self, ip: &str, map_name: &str) -> Result<Option<NftEntry>> {
        let entries = self.list_entries(map_name).await?;
        Ok(entries.into_iter().find(|entry| entry.ip == ip))
    }

    /// Apply a single `add`/`delete` command for one `ip : mark` pair.
    async fn apply_element(
        &self,
        cmd: fn(NfListObject<'static>) -> NfCmd<'static>,
        map_name: &str,
        key: Expression<'static>,
        mark: u32,
    ) -> Result<()> {
        let pair = Expression::List(vec![key, Expression::Number(mark)]);
        let ruleset = Nftables {
            objects: Cow::Owned(vec![NfObject::CmdObject(cmd(NfListObject::Element(
                Element {
                    family: self.family,
                    table: Cow::Owned(self.table.clone()),
                    name: Cow::Owned(map_name.to_owned()),
                    elem: Cow::Owned(vec![pair]),
                },
            )))]),
        };
        helper::apply_ruleset_async(&ruleset).await?;
        Ok(())
    }

    pub async fn add_element(&self, ip: &str, mark: u32, hours: u32, map_name: &str) -> Result<()> {
        let ip_expr = Expression::String(Cow::Owned(ip.to_owned()));
        let key = if hours > 0 {
            Expression::Named(NamedExpression::Elem(expr::Elem {
                val: Box::new(ip_expr),
                timeout: Some(hours * 3600),
                expires: None,
                comment: None,
                counter: None,
            }))
        } else {
            ip_expr
        };
        self.apply_element(NfCmd::Add, map_name, key, mark)
            .await
            .with_context(|| format!("nft add element {ip} to {map_name} failed"))
    }

    /// Remove the entry for `ip` if present; missing entries are a no-op.
    pub async fn delete_element(&self, ip: &str, map_name: &str) -> Result<()> {
        let Some(entry) = self.get_entry(ip, map_name).await? else {
            return Ok(());
        };
        let key = Expression::String(Cow::Owned(ip.to_owned()));
        self.apply_element(NfCmd::Delete, map_name, key, entry.mark)
            .await
            .with_context(|| format!("nft delete element {ip} from {map_name} failed"))
    }
}
