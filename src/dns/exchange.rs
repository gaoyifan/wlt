use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use bytes::Bytes;
use futures_util::StreamExt;
use hickory_net::{
    runtime::{RuntimeProvider, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd},
    tcp::TcpClientStream,
    udp::UdpClientStream,
    xfer::{DnsExchange, DnsHandle},
};
use hickory_proto::op::{DnsRequest, DnsRequestOptions, DnsResponse, Message};
use http::{Request, Uri, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use moka::future::Cache;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tower_service::Service;

use super::config::UpstreamProtocol;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct ExchangeTarget {
    pub endpoint: SocketAddr,
    pub protocol: UpstreamProtocol,
    pub mark: u32,
    pub timeout: Duration,
    pub tls_name: Option<Arc<str>>,
    pub http_path: Arc<str>,
}

type MarkedTcp = AsyncIoTokioAsStd<tokio::net::TcpStream>;

#[derive(Clone)]
enum PooledExchange {
    Tcp {
        handle: DnsExchange<MarkedRuntime>,
        _runtime: MarkedRuntime,
    },
    Https(Box<DohClient>),
}

pub(super) struct ExchangePool {
    clients: Cache<ExchangeTarget, PooledExchange>,
    max_doh_body: usize,
}

impl ExchangePool {
    pub(super) fn new(max_clients: u64, idle_timeout: Duration, max_doh_body: usize) -> Self {
        Self {
            clients: Cache::builder()
                .max_capacity(max_clients.max(1))
                .time_to_idle(idle_timeout)
                .build(),
            max_doh_body,
        }
    }

    pub(super) async fn exchange(
        &self,
        target: &ExchangeTarget,
        message: Message,
    ) -> Result<Message> {
        if target.protocol == UpstreamProtocol::Udp {
            return self.exchange_udp(target, message).await;
        }

        let result = self.exchange_once(target, message.clone()).await;
        if result.is_ok() {
            return result;
        }

        // A pooled TCP/TLS connection can have gone stale between checkout and use.
        self.clients.invalidate(target).await;
        self.exchange_once(target, message).await
    }

    async fn exchange_udp(&self, target: &ExchangeTarget, message: Message) -> Result<Message> {
        let runtime = MarkedRuntime::new(target.mark);
        let handle = UdpClientStream::builder(target.endpoint, runtime)
            .with_timeout(Some(target.timeout))
            .with_max_retries(1)
            .exchange();
        let original_request = message.clone();
        match send_hickory(handle, message).await {
            Ok(response) if !response.metadata.truncation => Ok(response),
            Ok(_) => self.exchange_tcp_fallback(target, original_request).await,
            Err(udp_error) => self
                .exchange_tcp_fallback(target, original_request)
                .await
                .with_context(|| {
                    format!("UDP exchange failed ({udp_error:#}); TCP fallback also failed")
                }),
        }
    }

    async fn exchange_tcp_fallback(
        &self,
        target: &ExchangeTarget,
        message: Message,
    ) -> Result<Message> {
        let mut tcp = target.clone();
        tcp.protocol = UpstreamProtocol::Tcp;
        Box::pin(self.exchange(&tcp, message)).await
    }

    async fn exchange_once(&self, target: &ExchangeTarget, message: Message) -> Result<Message> {
        let max_doh_body = self.max_doh_body;
        let client_target = target.clone();
        let client = self
            .clients
            .try_get_with(target.clone(), async move {
                create_client(&client_target, max_doh_body).await
            })
            .await
            .map_err(|error| anyhow!(error.to_string()))?;

        match client {
            PooledExchange::Tcp { handle, .. } => send_hickory(handle, message).await,
            PooledExchange::Https(client) => client.exchange(message, target.timeout).await,
        }
    }
}

async fn create_client(target: &ExchangeTarget, max_doh_body: usize) -> Result<PooledExchange> {
    let runtime = MarkedRuntime::new(target.mark);
    match target.protocol {
        UpstreamProtocol::Udp => unreachable!("UDP exchanges are not pooled"),
        UpstreamProtocol::Tcp => {
            let runtime_guard = runtime.clone();
            Ok(PooledExchange::Tcp {
                handle: TcpClientStream::<MarkedTcp>::exchange(
                    target.endpoint,
                    None,
                    target.timeout,
                    Some(32),
                    runtime,
                )
                .await?,
                _runtime: runtime_guard,
            })
        }
        UpstreamProtocol::Https => Ok(PooledExchange::Https(Box::new(DohClient::new(
            target,
            max_doh_body,
        )?))),
    }
}

async fn send_hickory(handle: DnsExchange<MarkedRuntime>, message: Message) -> Result<Message> {
    let mut responses = handle.send(DnsRequest::new(message, DnsRequestOptions::default()));
    Ok(responses
        .next()
        .await
        .ok_or_else(|| anyhow!("DNS upstream returned no response"))??
        .into_message())
}

#[derive(Clone)]
struct DohClient {
    client: Client<HttpsConnector<LiteralConnector>, Full<Bytes>>,
    uri: Uri,
    max_body: usize,
}

impl DohClient {
    fn new(target: &ExchangeTarget, max_body: usize) -> Result<Self> {
        let tls_name = target
            .tls_name
            .as_deref()
            .ok_or_else(|| anyhow!("HTTPS upstream is missing tls_name"))?;
        let uri: Uri = format!("https://{tls_name}{}", target.http_path)
            .parse()
            .context("invalid DoH URI")?;
        let connector = LiteralConnector {
            endpoint: target.endpoint,
            mark: target.mark,
        };
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .context("load native CA roots")?
            .https_only()
            .enable_http2()
            .wrap_connector(connector);
        let client = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build(https);
        Ok(Self {
            client,
            uri,
            max_body,
        })
    }

    async fn exchange(&self, message: Message, timeout: Duration) -> Result<Message> {
        tokio::time::timeout(timeout, async {
            let expected_id = message.metadata.id;
            let expected_queries = message.queries.clone();
            let body = message.to_vec().context("encode DNS request")?;
            let request = Request::post(self.uri.clone())
                .header(header::CONTENT_TYPE, "application/dns-message")
                .header(header::ACCEPT, "application/dns-message")
                .body(Full::new(Bytes::from(body)))?;
            let response = self.client.request(request).await?;
            if !response.status().is_success() {
                bail!("DoH upstream returned HTTP {}", response.status());
            }
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .map(str::trim);
            if !content_type
                .is_some_and(|value| value.eq_ignore_ascii_case("application/dns-message"))
            {
                bail!("DoH upstream returned an invalid content type");
            }
            if response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|length| length > self.max_body)
            {
                bail!("DoH response exceeds configured body limit");
            }
            let body = Limited::new(response.into_body(), self.max_body)
                .collect()
                .await
                .map_err(|error| anyhow!("read bounded DoH response: {error}"))?
                .to_bytes();
            let response = DnsResponse::from_buffer(body.to_vec())?.into_message();
            ensure!(
                response.metadata.message_type == hickory_proto::op::MessageType::Response,
                "DoH upstream returned a non-response DNS message"
            );
            ensure!(
                response.metadata.id == expected_id,
                "DoH upstream returned a mismatched DNS ID"
            );
            ensure!(
                response.queries == expected_queries,
                "DoH upstream returned a mismatched DNS question"
            );
            Ok(response)
        })
        .await
        .context("DoH exchange timed out")?
    }
}

#[derive(Clone)]
struct LiteralConnector {
    endpoint: SocketAddr,
    mark: u32,
}

impl Service<Uri> for LiteralConnector {
    type Response = TokioIo<tokio::net::TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let endpoint = self.endpoint;
        let mark = self.mark;
        Box::pin(async move {
            let stream = connect_marked(endpoint, None, mark).await?;
            Ok(TokioIo::new(stream))
        })
    }
}

#[derive(Clone)]
struct MarkedRuntime {
    mark: u32,
    handle: TokioHandle,
}

impl MarkedRuntime {
    fn new(mark: u32) -> Self {
        Self {
            mark,
            handle: TokioHandle::default(),
        }
    }
}

impl RuntimeProvider for MarkedRuntime {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = tokio::net::UdpSocket;
    type Tcp = MarkedTcp;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Tcp>> + Send>> {
        let mark = self.mark;
        Box::pin(async move {
            let connect = connect_marked(server_addr, bind_addr, mark);
            let stream = if let Some(timeout) = timeout {
                tokio::time::timeout(timeout, connect).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out")
                })??
            } else {
                connect.await?
            };
            Ok(AsyncIoTokioAsStd(stream))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Udp>> + Send>> {
        let mark = self.mark;
        Box::pin(async move {
            let domain = Domain::for_address(local_addr);
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_nonblocking(true)?;
            if mark != 0 {
                socket.set_mark(mark)?;
            }
            socket.bind(&SockAddr::from(local_addr))?;
            let socket: std::net::UdpSocket = socket.into();
            tokio::net::UdpSocket::from_std(socket)
        })
    }
}

async fn connect_marked(
    endpoint: SocketAddr,
    bind_addr: Option<SocketAddr>,
    mark: u32,
) -> io::Result<tokio::net::TcpStream> {
    let raw = Socket::new(
        Domain::for_address(endpoint),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    raw.set_nonblocking(true)?;
    if mark != 0 {
        raw.set_mark(mark)?;
    }
    let stream: std::net::TcpStream = raw.into();
    let socket = tokio::net::TcpSocket::from_std_stream(stream);
    if let Some(bind_addr) = bind_addr {
        socket.bind(bind_addr)?;
    }
    socket.set_nodelay(true)?;
    socket.connect(endpoint).await
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use hickory_proto::{
        op::{Message, MessageType, Query, ResponseCode},
        rr::{Name, RecordType},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    use super::{ExchangePool, ExchangeTarget, UpstreamProtocol};

    async fn reply_once_over_tcp(listener: TcpListener) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut wire = vec![0_u8; usize::from(length)];
        stream.read_exact(&mut wire).await.unwrap();
        let mut response = Message::from_vec(&wire).unwrap();
        response.metadata.message_type = MessageType::Response;
        let wire = response.to_vec().unwrap();
        stream
            .write_u16(u16::try_from(wire.len()).unwrap())
            .await
            .unwrap();
        stream.write_all(&wire).await.unwrap();
    }

    #[test]
    fn exchange_target_identity_includes_client_construction_state() {
        let base = ExchangeTarget {
            endpoint: "192.0.2.1:53".parse().unwrap(),
            protocol: UpstreamProtocol::Udp,
            mark: 1,
            timeout: Duration::from_secs(1),
            tls_name: None,
            http_path: Arc::from("/dns-query"),
        };
        let mut other = base.clone();
        other.mark = 2;
        assert_ne!(base, other);

        other.mark = base.mark;
        other.timeout = Duration::from_secs(2);
        assert_ne!(base, other);
    }

    #[tokio::test]
    async fn udp_exchange_reaches_literal_local_server() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
            let mut response = Message::from_vec(&buffer[..length]).unwrap();
            response.metadata.message_type = MessageType::Response;
            server
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });

        let mut request = Message::query();
        request.queries.push(Query::query(
            Name::from_ascii("local.test.").unwrap(),
            RecordType::A,
        ));
        let target = ExchangeTarget {
            endpoint,
            protocol: UpstreamProtocol::Udp,
            mark: 0,
            timeout: Duration::from_secs(1),
            tls_name: None,
            http_path: Arc::from("/dns-query"),
        };

        let pool = ExchangePool::new(1, Duration::from_secs(1), 4096);
        let response = pool.exchange(&target, request).await.unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(pool.clients.entry_count(), 0);
    }

    #[tokio::test]
    async fn malformed_udp_response_falls_back_to_tcp_on_same_endpoint() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(endpoint).await.unwrap();

        tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (_length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            udp.send_to(&[0_u8], peer).await.unwrap();
        });
        tokio::spawn(reply_once_over_tcp(tcp));

        let mut request = Message::query();
        request.queries.push(Query::query(
            Name::from_ascii("fallback.test.").unwrap(),
            RecordType::A,
        ));
        let target = ExchangeTarget {
            endpoint,
            protocol: UpstreamProtocol::Udp,
            mark: 0,
            timeout: Duration::from_secs(1),
            tls_name: None,
            http_path: Arc::from("/dns-query"),
        };

        let response = ExchangePool::new(2, Duration::from_secs(1), 4096)
            .exchange(&target, request)
            .await
            .unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn udp_receive_timeout_falls_back_to_tcp_on_same_endpoint() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(endpoint).await.unwrap();

        tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let _ = udp.recv_from(&mut buffer).await.unwrap();
        });
        tokio::spawn(reply_once_over_tcp(tcp));

        let mut request = Message::query();
        request.queries.push(Query::query(
            Name::from_ascii("timeout-fallback.test.").unwrap(),
            RecordType::A,
        ));
        let target = ExchangeTarget {
            endpoint,
            protocol: UpstreamProtocol::Udp,
            mark: 0,
            timeout: Duration::from_millis(50),
            tls_name: None,
            http_path: Arc::from("/dns-query"),
        };

        let response = ExchangePool::new(2, Duration::from_secs(1), 4096)
            .exchange(&target, request)
            .await
            .unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn dns_error_rcode_is_a_valid_udp_response_without_tcp_fallback() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            let mut response = Message::from_vec(&buffer[..length]).unwrap();
            response.metadata.message_type = MessageType::Response;
            response.metadata.response_code = ResponseCode::ServFail;
            udp.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });

        let mut request = Message::query();
        request.queries.push(Query::query(
            Name::from_ascii("rcode.test.").unwrap(),
            RecordType::A,
        ));
        let target = ExchangeTarget {
            endpoint,
            protocol: UpstreamProtocol::Udp,
            mark: 0,
            timeout: Duration::from_millis(200),
            tls_name: None,
            http_path: Arc::from("/dns-query"),
        };

        let response = ExchangePool::new(2, Duration::from_secs(1), 4096)
            .exchange(&target, request)
            .await
            .unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }
}
