//! Shared per-client helpers used by both the web portal and the SSH TUI.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{Name, RData};

use crate::config::AppConfig;
use crate::nft::Nft;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AppConfig>,
    pub nft: Nft,
    pub resolver: Option<Arc<TokioResolver>>,
}

impl AppState {
    pub fn new(cfg: Arc<AppConfig>, nft: Nft) -> Self {
        let resolver = TokioResolver::builder_tokio()
            .and_then(|mut builder| {
                let opts = builder.options_mut();
                opts.timeout = Duration::from_secs(1);
                opts.attempts = 1;
                builder.build()
            })
            .map(Arc::new)
            .inspect_err(|e| tracing::warn!("DNS resolver unavailable: {e}"))
            .ok();
        Self { cfg, nft, resolver }
    }

    /// Reverse-DNS (PTR) lookup with a hard 1s timeout so a dead reverse zone
    /// never stalls the client.
    pub async fn resolve_hostname(&self, ip: IpAddr) -> Option<String> {
        let resolver = self.resolver.as_ref()?;
        let lookup = tokio::time::timeout(
            Duration::from_secs(1),
            resolver.reverse_lookup(Name::from(ip)),
        )
        .await
        .ok()?
        .ok()?;
        let name = lookup
            .answers()
            .iter()
            .find_map(|record| match &record.data {
                RData::PTR(ptr) => Some(ptr.to_string()),
                _ => None,
            })?;
        Some(name.trim_end_matches('.').to_owned())
    }
}

/// Unwrap IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) from dual-stack listeners.
pub fn normalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        v4 => v4,
    }
}

pub fn ip_family(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}
