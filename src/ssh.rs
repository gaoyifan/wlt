//! No-auth SSH TUI for network outlet selection.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Server as _, Session};
use russh::{Channel, ChannelId, Pty};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinSet;

use crate::app::{AppState, ip_family, normalize_ip};
use crate::config::{OutletGroup, SshConfig, duration_label};

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RST: &str = "\x1b[0m";
const KEYS: &str = "1234567890abcdefghijklmnopqrstuvwxyz";

fn load_or_generate_host_key(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        return russh::keys::load_secret_key(path, None)
            .with_context(|| format!("failed to load host key {}", path.display()));
    }
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .context("failed to generate host key")?;
    let pem = key.to_openssh(LineEnding::LF)?;
    std::fs::write(path, pem.as_bytes())
        .with_context(|| format!("failed to write host key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::info!("generated host key: {}", path.display());
    Ok(key)
}

struct WltServer {
    state: AppState,
}

impl russh::server::Server for WltServer {
    type Handler = WltHandler;

    fn new_client(&mut self, peer: Option<SocketAddr>) -> WltHandler {
        WltHandler {
            state: self.state.clone(),
            peer,
            channel: None,
        }
    }
}

struct WltHandler {
    state: AppState,
    peer: Option<SocketAddr>,
    channel: Option<Channel<Msg>>,
}

impl Handler for WltHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel = Some(channel);
        reply.accept().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel_id)?;
        if let Some(channel) = self.channel.take() {
            let state = self.state.clone();
            let peer = self.peer;
            let handle = session.handle();
            tokio::spawn(async move {
                let stream = channel.into_stream();
                if let Err(e) = run_tui(state, peer, stream).await {
                    tracing::debug!("ssh session ended: {e:#}");
                }
                let _ = handle.exit_status_request(channel_id, 0).await;
                let _ = handle.eof(channel_id).await;
                let _ = handle.close(channel_id).await;
            });
        }
        Ok(())
    }
}

async fn show<S: AsyncWrite + Unpin>(stream: &mut S, text: &str) -> std::io::Result<()> {
    stream
        .write_all(text.replace('\n', "\r\n").as_bytes())
        .await?;
    stream.flush().await
}

/// One keypress from the client (the pty is in raw mode), or None on EOF.
async fn key<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Option<char>> {
    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).await?;
    Ok(if n == 0 { None } else { Some(buf[0] as char) })
}

/// Show a keyed menu and wait for a valid pick; None on EOF or Ctrl-C.
async fn pick<S>(stream: &mut S, title: &str, items: &[&str]) -> std::io::Result<Option<usize>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let keys = &KEYS[..items.len().min(KEYS.len())];
    let opts: Vec<String> = keys
        .chars()
        .zip(items)
        .map(|(k, name)| format!("    {k}. {name}"))
        .collect();
    show(
        stream,
        &format!("  {BOLD}{title}{RST}\n{}\n\n  选择: ", opts.join("\n")),
    )
    .await?;
    loop {
        let Some(ch) = key(stream).await? else {
            return Ok(None);
        };
        if ch == '\x03' {
            return Ok(None);
        }
        let ch = ch.to_ascii_lowercase();
        if let Some(idx) = keys.find(ch) {
            show(stream, &format!("{ch}\n\n")).await?;
            return Ok(Some(idx));
        }
    }
}

async fn run_tui<S>(state: AppState, peer: Option<SocketAddr>, mut stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(peer) = peer else { return Ok(()) };
    let ip = normalize_ip(peer.ip());
    let family = ip_family(ip);
    let ip_str = ip.to_string();
    let hostname = state
        .resolve_hostname(ip)
        .await
        .unwrap_or_else(|| ip_str.clone());
    tracing::info!("connected: {ip} ({hostname}) IPv{family}");

    let Some(map_name) = state.cfg.map_for(family) else {
        show(
            &mut stream,
            &format!(
                "\x1b[2J\x1b[H\n  {BOLD}网络通{RST}\n\n  IP: {ip_str} ({hostname})\n\n  \
                 {DIM}本协议族（IPv{family}）暂未启用出口选择{RST}\n\n  按任意键退出 "
            ),
        )
        .await?;
        key(&mut stream).await?;
        return Ok(());
    };

    loop {
        let entry = state
            .nft
            .get_entry(&ip_str, map_name)
            .await
            .unwrap_or_else(|e| {
                tracing::error!("failed to fetch nftables entry for {ip}: {e:#}");
                None
            });
        let status = match &entry {
            Some(entry) => {
                let labels: Vec<&str> = state
                    .cfg
                    .outlet_groups
                    .iter()
                    .filter_map(|g| g.selection_for(entry.mark, family))
                    .collect();
                let outlet = if labels.is_empty() {
                    format!("{:#x}", entry.mark)
                } else {
                    labels.join(" + ")
                };
                let expires = match entry.expires {
                    None => "永久".into(),
                    Some(seconds) => format!("{seconds}秒"),
                };
                format!("  当前出口: {CYAN}{outlet}{RST}\n  剩余时间: {expires}")
            }
            None => format!("  当前出口: {DIM}默认{RST}"),
        };
        show(
            &mut stream,
            &format!(
                "\x1b[2J\x1b[H\n  {BOLD}网络通{RST}\n\n  IP: {ip_str} ({hostname})\n{status}\n\n  \
                 {BOLD}[1]{RST} 开通  {BOLD}[2]{RST} 重置  {BOLD}[q]{RST} 退出\n\n  请选择: "
            ),
        )
        .await?;

        let ch = key(&mut stream).await?;
        match ch {
            None | Some('q') | Some('Q') | Some('\x03') => break,
            Some('2') => {
                if let Err(e) = state.nft.delete_element(&ip_str, map_name).await {
                    tracing::error!("error deleting rule for {ip}: {e:#}");
                }
                show(&mut stream, &format!("\n\n  {GREEN}网络已重置{RST}\n")).await?;
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            Some('1') => {}
            _ => continue,
        }
        show(&mut stream, "\n\n").await?;

        let groups: Vec<_> = state
            .cfg
            .outlet_groups
            .iter()
            .filter(|g| !g.outlets_for(family).is_empty())
            .collect();
        let mut selections: Vec<(&OutletGroup, &str)> = Vec::new();
        for group in &groups {
            let names: Vec<&str> = group
                .display_outlets_for(family)
                .iter()
                .map(|&(n, _)| n)
                .collect();
            match pick(&mut stream, &group.title, &names).await? {
                Some(idx) => selections.push((group, names[idx])),
                None => break,
            }
        }
        if selections.len() != groups.len() {
            continue;
        }

        let labels: Vec<String> = state
            .cfg
            .time_limits
            .iter()
            .map(|&h| duration_label(h))
            .collect();
        let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        let Some(idx) = pick(&mut stream, "选择时限", &label_refs).await? else {
            continue;
        };
        let hours = state.cfg.time_limits[idx];

        let mut mark_value: u32 = 0;
        let mut names: Vec<&str> = Vec::new();
        for (group, name) in &selections {
            mark_value |= group.outlets_for(family)[*name] & group.mask;
            names.push(name);
        }
        if let Err(e) = state.nft.delete_element(&ip_str, map_name).await {
            tracing::error!("error deleting rule for {ip}: {e:#}");
        }
        match state
            .nft
            .add_element(&ip_str, mark_value, hours, map_name)
            .await
        {
            Ok(()) => {
                show(
                    &mut stream,
                    &format!(
                        "  {GREEN}已开通：{}，{}{RST}\n",
                        names.join(" + "),
                        duration_label(hours)
                    ),
                )
                .await?;
            }
            Err(e) => {
                tracing::error!("error adding rule for {ip}: {e:#}");
                show(&mut stream, &format!("  {RED}设置失败{RST}\n")).await?;
            }
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }
    Ok(())
}

pub async fn serve(state: AppState, cfg: SshConfig) -> Result<()> {
    let host_key = load_or_generate_host_key(&cfg.host_key)?;
    let config = Arc::new(russh::server::Config {
        keys: vec![host_key],
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(Duration::from_secs(3600)),
        nodelay: true,
        ..Default::default()
    });
    let mut listeners: JoinSet<Result<()>> = JoinSet::new();
    for listen in cfg.listen {
        let config = config.clone();
        let state = state.clone();
        listeners.spawn(async move {
            tracing::info!("ssh listening on {listen}");
            WltServer { state }
                .run_on_address(config, listen.as_str())
                .await
                .context("ssh server failed")
        });
    }
    // Listeners never exit on their own; treat the first return as fatal.
    match listeners.join_next().await {
        Some(result) => result.context("ssh listener panicked")?,
        None => Ok(()),
    }
}
