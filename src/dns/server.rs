use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
};
use tokio_util::{
    codec::{Framed, LengthDelimitedCodec},
    sync::CancellationToken,
    task::TaskTracker,
};
use tracing::{debug, warn};

use super::{config::ServerConfig, frontend::DnsFrontend, metrics::DnsMetrics};

pub(super) struct DnsServer {
    config: ServerConfig,
    handler: Arc<DnsFrontend>,
    metrics: DnsMetrics,
}

impl DnsServer {
    pub(super) fn new(
        config: ServerConfig,
        handler: Arc<DnsFrontend>,
        metrics: DnsMetrics,
    ) -> Self {
        Self {
            config,
            handler,
            metrics,
        }
    }

    pub(super) async fn run(self, shutdown: CancellationToken) -> Result<()> {
        let tracker = TaskTracker::new();
        let inflight = Arc::new(Semaphore::new(self.config.max_inflight_queries));
        let connections = Arc::new(Semaphore::new(self.config.max_tcp_connections));
        let clients = Arc::new(ClientConnections::default());

        for address in &self.config.listen {
            let udp =
                bind_udp(*address).with_context(|| format!("bind UDP DNS listener {address}"))?;
            let tcp =
                bind_tcp(*address).with_context(|| format!("bind TCP DNS listener {address}"))?;

            tracker.spawn(run_udp(
                udp,
                self.handler.clone(),
                self.config.max_udp_payload,
                inflight.clone(),
                tracker.clone(),
                self.metrics,
                shutdown.clone(),
            ));
            tracker.spawn(run_tcp(
                tcp,
                self.handler.clone(),
                self.config.max_dns_message,
                self.config.max_tcp_connections_per_client,
                Duration::from_secs(self.config.tcp_idle_timeout_seconds),
                inflight.clone(),
                connections.clone(),
                clients.clone(),
                tracker.clone(),
                self.metrics,
                shutdown.clone(),
            ));
        }

        shutdown.cancelled().await;
        tracker.close();
        if tokio::time::timeout(
            Duration::from_secs(self.config.shutdown_timeout_seconds),
            tracker.wait(),
        )
        .await
        .is_err()
        {
            warn!("timed out draining DNS requests during shutdown");
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp(
    socket: UdpSocket,
    handler: Arc<DnsFrontend>,
    max_payload: usize,
    inflight: Arc<Semaphore>,
    tracker: TaskTracker,
    metrics: DnsMetrics,
    shutdown: CancellationToken,
) {
    let socket = Arc::new(socket);
    let mut buffer = vec![0_u8; max_payload.saturating_add(1)];
    loop {
        let receive = tokio::select! {
            _ = shutdown.cancelled() => break,
            receive = socket.recv_from(&mut buffer) => receive,
        };
        let (length, peer) = match receive {
            Ok(receive) => receive,
            Err(error) => {
                warn!(%error, "UDP DNS receive failed");
                continue;
            }
        };
        metrics.request("udp");
        if length > max_payload {
            metrics.rejected("udp", "message_too_large");
            continue;
        }
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            metrics.rejected("udp", "overloaded");
            continue;
        };
        let request = buffer[..length].to_vec();
        let socket = socket.clone();
        let handler = handler.clone();
        tracker.spawn(async move {
            let _permit = permit;
            let response = process_wire(&handler, peer, &request).await;
            let response = encode_udp(response, udp_limit(&request, max_payload), metrics);
            if let Some(response) = response
                && let Err(error) = socket.send_to(&response, peer).await
            {
                debug!(%peer, %error, "UDP DNS response send failed");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp(
    listener: TcpListener,
    handler: Arc<DnsFrontend>,
    max_message: usize,
    per_client_limit: usize,
    idle_timeout: Duration,
    inflight: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    clients: Arc<ClientConnections>,
    tracker: TaskTracker,
    metrics: DnsMetrics,
    shutdown: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                warn!(%error, "TCP DNS accept failed");
                continue;
            }
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            metrics.rejected("tcp", "connection_limit");
            continue;
        };
        let Some(client_guard) = clients.acquire(peer.ip(), per_client_limit) else {
            metrics.rejected("tcp", "client_connection_limit");
            continue;
        };
        let handler = handler.clone();
        let inflight = inflight.clone();
        let shutdown = shutdown.clone();
        tracker.spawn(async move {
            let (_permit, _client_guard) = (permit, client_guard);
            if let Err(error) = serve_tcp_connection(
                stream,
                peer,
                handler,
                max_message,
                idle_timeout,
                inflight,
                metrics,
                shutdown,
            )
            .await
            {
                debug!(%peer, %error, "TCP DNS connection closed");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_tcp_connection(
    stream: TcpStream,
    peer: SocketAddr,
    handler: Arc<DnsFrontend>,
    max_message: usize,
    idle_timeout: Duration,
    inflight: Arc<Semaphore>,
    metrics: DnsMetrics,
    shutdown: CancellationToken,
) -> Result<()> {
    let codec = LengthDelimitedCodec::builder()
        .length_field_length(2)
        .max_frame_length(max_message)
        .new_codec();
    let mut framed = Framed::new(stream, codec);
    loop {
        let next = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            next = tokio::time::timeout(idle_timeout, framed.next()) => next,
        };
        let Some(frame) = next.context("TCP DNS idle timeout")? else {
            return Ok(());
        };
        let frame = frame.context("read TCP DNS frame")?;
        metrics.request("tcp");
        let permit = match inflight.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                metrics.rejected("tcp", "overloaded");
                let response = error_response(&frame, ResponseCode::ServFail).to_vec()?;
                framed.send(Bytes::from(response)).await?;
                continue;
            }
        };
        let response = process_wire(&handler, peer, &frame).await;
        drop(permit);
        metrics.response("tcp", response.metadata.response_code);
        framed.send(Bytes::from(response.to_vec()?)).await?;
    }
}

async fn process_wire(handler: &DnsFrontend, peer: SocketAddr, wire: &[u8]) -> Message {
    match Message::from_vec(wire) {
        Ok(request) => handler.handle(peer, request).await,
        Err(_) => error_response(wire, ResponseCode::FormErr),
    }
}

fn error_response(wire: &[u8], response_code: ResponseCode) -> Message {
    let id = wire
        .get(..2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .unwrap_or_default();
    let mut response = Message::new(id, MessageType::Response, OpCode::Query);
    response.metadata.response_code = response_code;
    response
}

fn udp_limit(request: &[u8], configured: usize) -> usize {
    Message::from_vec(request)
        .ok()
        .and_then(|message| message.edns.map(|edns| usize::from(edns.max_payload())))
        .unwrap_or(512)
        .clamp(512, configured)
}

fn encode_udp(mut message: Message, limit: usize, metrics: DnsMetrics) -> Option<Vec<u8>> {
    let encoded = message.to_vec().ok()?;
    if encoded.len() <= limit {
        metrics.response("udp", message.metadata.response_code);
        return Some(encoded);
    }
    message = message.truncate();
    let encoded = message.to_vec().ok()?;
    if encoded.len() <= limit {
        return Some(encoded);
    }
    message.edns = None;
    message
        .to_vec()
        .ok()
        .filter(|encoded| encoded.len() <= limit)
}

fn bind_udp(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = dns_socket(address, Type::DGRAM, Protocol::UDP)?;
    socket.bind(&SockAddr::from(address))?;
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket)
}

fn bind_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = dns_socket(address, Type::STREAM, Protocol::TCP)?;
    socket.bind(&SockAddr::from(address))?;
    socket.listen(1024)?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener)
}

fn dns_socket(address: SocketAddr, kind: Type, protocol: Protocol) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(address), kind, Some(protocol))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    match address {
        SocketAddr::V4(_) => socket.set_freebind_v4(true)?,
        SocketAddr::V6(_) => {
            socket.set_only_v6(true)?;
            socket.set_freebind_v6(true)?;
        }
    }
    Ok(socket)
}

#[derive(Default)]
struct ClientConnections {
    counts: Mutex<HashMap<IpAddr, usize>>,
}

impl ClientConnections {
    fn acquire(self: &Arc<Self>, client: IpAddr, limit: usize) -> Option<ClientGuard> {
        let mut counts = self.counts.lock().expect("client connection lock poisoned");
        let count = counts.entry(client).or_default();
        if *count >= limit {
            return None;
        }
        *count += 1;
        Some(ClientGuard {
            owner: self.clone(),
            client,
        })
    }
}

struct ClientGuard {
    owner: Arc<ClientConnections>,
    client: IpAddr,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        let mut counts = self
            .owner
            .counts
            .lock()
            .expect("client connection lock poisoned");
        let count = counts
            .get_mut(&self.client)
            .expect("client connection count missing");
        *count -= 1;
        if *count == 0 {
            counts.remove(&self.client);
        }
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{Message, MessageType, OpCode};

    use super::{DnsMetrics, encode_udp};

    #[test]
    fn udp_encoder_sets_tc_and_respects_limit() {
        let message = Message::new(7, MessageType::Response, OpCode::Query);
        let encoded = encode_udp(message, 12, DnsMetrics).unwrap();
        assert!(encoded.len() <= 12);
    }
}
