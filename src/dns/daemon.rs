#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;
#[cfg(target_os = "linux")]
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio_util::sync::CancellationToken;

use super::config::DnsConfig;
#[cfg(target_os = "linux")]
use super::{frontend::DnsFrontend, metrics::DnsMetrics, server::DnsServer};

pub struct DnsDaemon;

impl DnsDaemon {
    pub async fn run(config: DnsConfig, shutdown: CancellationToken) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (config, shutdown);
            anyhow::bail!("wlt-dns requires Linux nftables support");
        }

        #[cfg(target_os = "linux")]
        {
            PrometheusBuilder::new()
                .with_http_listener(config.metrics.listen)
                .install()
                .context("start DNS Prometheus exporter")?;

            let policy = Arc::new(
                super::policy_linux::NftWltPolicy::new(&config.policy, &config.outlet_groups)
                    .context("initialize DNS policy source")?,
            );
            let frontend = Arc::new(DnsFrontend::new(&config, policy)?);
            DnsServer::new(config.server, frontend, DnsMetrics)
                .run(shutdown)
                .await
        }
    }
}
