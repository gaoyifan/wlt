mod cache;
mod config;
mod daemon;
mod exchange;
mod frontend;
mod metrics;
mod policy;
#[cfg(target_os = "linux")]
mod policy_linux;
mod routing;
mod server;

use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl From<IpAddr> for AddressFamily {
    fn from(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

pub use config::DnsConfig;
pub use daemon::DnsDaemon;
