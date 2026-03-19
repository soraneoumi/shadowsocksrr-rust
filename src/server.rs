use crate::config::AppConfig;
use crate::obfs::ObfsCodec;
use crate::obfs::tls12_ticket_auth::{FirstPacketError, TlsTicketAuth, TlsTicketAuthShared};
use crate::protocol::auth_akarin::{AuthAkarinCodec, AuthAkarinVariant};
use crate::protocol::auth_chain::{AuthChainCodec, AuthChainVariant};
use crate::protocol::{ProtocolCodec, ProtocolConfigRuntime};
use crate::state::SharedUserRegistry;
use anyhow::{Context, Result, anyhow};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::sync::Semaphore;
use tokio::time::{Duration, Instant as TokioInstant, timeout_at};
use tracing::{Instrument, debug, error, info, info_span, warn};

const FIXED_IV_HEADER: &[u8] = b"\x16\x03\x03";
const REQUIRE_CLIENT_IV_HEADER: bool = false;
const TCP_DNS_CACHE_TTL: Duration = Duration::from_secs(30);
const TCP_DNS_CACHE_MAX_ENTRIES: usize = 4096;
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TcpDnsCacheKey {
    host: String,
    port: u16,
}

#[derive(Clone, Copy, Debug)]
struct CachedTcpTarget {
    addr: SocketAddr,
    expires_at: Instant,
}

#[derive(Debug)]
struct ResolvedTcpTargetCache {
    ttl: Duration,
    max_entries: usize,
    entries: HashMap<TcpDnsCacheKey, CachedTcpTarget>,
    order: VecDeque<(Instant, TcpDnsCacheKey)>,
}

impl ResolvedTcpTargetCache {
    fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &TcpDnsCacheKey) -> Option<SocketAddr> {
        let now = Instant::now();
        self.sweep_expired(now);
        self.entries.get(key).map(|entry| entry.addr)
    }

    fn insert(&mut self, key: TcpDnsCacheKey, addr: SocketAddr) {
        let now = Instant::now();
        self.sweep_expired(now);

        let existed = self.entries.contains_key(&key);
        if existed {
            self.order.retain(|(_, queued_key)| queued_key != &key);
        } else {
            while self.entries.len() >= self.max_entries {
                let Some((expires_at, evicted_key)) = self.order.pop_front() else {
                    break;
                };
                let should_remove = self
                    .entries
                    .get(&evicted_key)
                    .is_some_and(|entry| entry.expires_at == expires_at);
                if should_remove {
                    self.entries.remove(&evicted_key);
                }
            }
        }

        let expires_at = now.checked_add(self.ttl).unwrap_or(now);
        self.entries
            .insert(key.clone(), CachedTcpTarget { addr, expires_at });
        self.order.push_back((expires_at, key));
    }

    fn sweep_expired(&mut self, now: Instant) {
        while let Some((expires_at, _)) = self.order.front() {
            if *expires_at >= now {
                break;
            }

            let (expires_at, key) = self.order.pop_front().expect("tcp dns cache entry");
            let should_remove = self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.expires_at == expires_at);
            if should_remove {
                self.entries.remove(&key);
            }
        }
    }
}

type TcpDnsCache = Arc<Mutex<ResolvedTcpTargetCache>>;

#[derive(Clone)]
struct IvHeaderMitigator {
    iv_header: Vec<u8>,
    require_client_header: bool,
    inbound_done: bool,
    inbound_buf: Vec<u8>,
}

impl IvHeaderMitigator {
    fn new(iv_header: Vec<u8>, require_client_header: bool) -> Self {
        Self {
            iv_header,
            require_client_header,
            inbound_done: false,
            inbound_buf: Vec::new(),
        }
    }

    fn process_inbound_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        if self.inbound_done || self.iv_header.is_empty() {
            self.inbound_done = true;
            out.clear();
            out.extend_from_slice(data);
            return Ok(true);
        }

        self.inbound_buf.extend_from_slice(data);
        if self.inbound_buf.len() < self.iv_header.len() {
            out.clear();
            return Ok(false);
        }

        out.clear();
        if self.inbound_buf.starts_with(&self.iv_header) {
            out.extend_from_slice(&self.inbound_buf[self.iv_header.len()..]);
        } else if self.require_client_header {
            return Err(anyhow!("fixed iv_header is required but missing"));
        } else {
            out.extend_from_slice(&self.inbound_buf);
        }
        self.inbound_buf.clear();
        self.inbound_done = true;
        Ok(true)
    }

    fn process_outbound_into(&mut self, data: &[u8], out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(&data);
    }
}

#[derive(Default)]
struct CodecBuffers {
    obfs_decoded: Vec<u8>,
    inbound_plain: Vec<u8>,
    protocol_plain: Vec<u8>,
    protocol_outbound: Vec<u8>,
    iv_outbound: Vec<u8>,
    obfs_outbound: Vec<u8>,
}

pub async fn run(config: AppConfig) -> Result<()> {
    config.validate()?;

    if config.server.cipher.to_lowercase() != "none" {
        return Err(anyhow!(
            "unsupported cipher `{}`: this simplified server only supports `none`",
            config.server.cipher
        ));
    }

    if config.server.udp_enabled {
        let tcp_cfg = config.clone();
        let udp_cfg = config.clone();
        tokio::try_join!(run_tcp(tcp_cfg), crate::udp_relay::run(udp_cfg))?;
        Ok(())
    } else {
        run_tcp(config).await
    }
}

async fn run_tcp(config: AppConfig) -> Result<()> {
    let listener = TcpListener::bind(&config.server.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.server.listen))?;

    let max_tcp_connections = config.server.max_tcp_connections.max(1);
    let connection_limiter = Arc::new(Semaphore::new(max_tcp_connections));
    let replay_capacity = config.server.replay_max_entries.max(1);
    let tls_shared = TlsTicketAuthShared::with_capacity(replay_capacity);
    let shared_registry = SharedUserRegistry::new(64);
    let tcp_dns_cache: TcpDnsCache = Arc::new(Mutex::new(ResolvedTcpTargetCache::new(
        TCP_DNS_CACHE_TTL,
        TCP_DNS_CACHE_MAX_ENTRIES,
    )));

    info!(listen = %config.server.listen, "ssrr simplified server listening");

    loop {
        let (socket, peer) = listener.accept().await?;
        let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let permit = match connection_limiter.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(
                    conn_id,
                    peer = %peer,
                    max_tcp_connections,
                    "tcp connection limit reached, dropping incoming connection"
                );
                continue;
            }
        };
        info!(conn_id, peer = %peer, "accepted tcp connection");
        if let Err(err) = socket.set_nodelay(true) {
            debug!(conn_id, peer = %peer, error = %err, "failed to set tcp nodelay");
        }
        let cfg = config.clone();
        let tls_shared_clone = tls_shared.clone();
        let registry = shared_registry.clone();
        let dns_cache = tcp_dns_cache.clone();
        let span = info_span!("tcp_conn", conn_id, peer = %peer);
        tokio::spawn(
            async move {
                let _permit = permit;
                let result = handle_connection(
                    socket,
                    peer.to_string(),
                    cfg,
                    tls_shared_clone,
                    registry,
                    dns_cache,
                )
                .await;
                if let Err(err) = result {
                    error!(error = %err, "connection terminated with error");
                }
            }
            .instrument(span),
        );
    }
}

fn build_codecs(
    config: &AppConfig,
    peer: &str,
    tls_shared: TlsTicketAuthShared,
    shared_registry: SharedUserRegistry,
) -> Result<(Box<dyn ObfsCodec>, Box<dyn ProtocolCodec>)> {
    let key = config.protocol.password.as_bytes().to_vec();
    let users = config.user_map_bytes();

    let protocol_runtime = ProtocolConfigRuntime {
        method: config.protocol.method.clone(),
        key: key.clone(),
        recv_iv: Vec::new(),
        protocol_param: config.protocol.protocol_param.clone(),
        users,
        overhead: config.protocol.overhead,
        tcp_mss: config.protocol.tcp_mss,
    };

    let obfs: Box<dyn ObfsCodec> = match config.obfs.method.as_str() {
        "tls1.2_ticket_auth" | "tls1.2_ticket_fastauth" => Box::new(TlsTicketAuth::new(
            &config.obfs.method,
            key.clone(),
            config.obfs.obfs_param.clone(),
            tls_shared,
        )),
        other => {
            return Err(anyhow!("unsupported obfs method: {other}"));
        }
    };

    let protocol: Box<dyn ProtocolCodec> =
        if let Some(v) = AuthChainVariant::from_method(&config.protocol.method) {
            Box::new(AuthChainCodec::new(v, protocol_runtime, shared_registry))
        } else if let Some(v) = AuthAkarinVariant::from_method(&config.protocol.method) {
            Box::new(AuthAkarinCodec::new(v, protocol_runtime, shared_registry))
        } else {
            return Err(anyhow!(
                "unsupported protocol method: {}",
                config.protocol.method
            ));
        };

    debug!(
        peer = %peer,
        obfs = %config.obfs.method,
        obfs_host = %config.obfs.host,
        protocol = %config.protocol.method,
        "codec stack initialized"
    );
    Ok((obfs, protocol))
}

async fn handle_connection(
    socket: TcpStream,
    peer: String,
    config: AppConfig,
    tls_shared: TlsTicketAuthShared,
    shared_registry: SharedUserRegistry,
    tcp_dns_cache: TcpDnsCache,
) -> Result<()> {
    let (mut obfs, mut protocol) = build_codecs(&config, &peer, tls_shared, shared_registry)?;
    let mut iv_mitigator =
        IvHeaderMitigator::new(FIXED_IV_HEADER.to_vec(), REQUIRE_CLIENT_IV_HEADER);
    let redirect_target = pick_redirect_target(&config);
    if let Some(target) = redirect_target.as_deref() {
        info!(redirect = %target, "redirect fallback is enabled for this listen port");
    }

    if let Some(mss) = detect_tcp_mss(&socket) {
        protocol.update_tcp_mss(mss);
        info!(tcp_mss = mss, "detected tcp maxseg from client socket");
    } else {
        debug!("tcp maxseg not available; protocol will use configured/default mss");
    }

    info!(peer = %peer, "connection established in dynamic target mode");
    let (client_r, client_w) = socket.into_split();
    let result = run_dynamic_proxy_loop(
        client_r,
        client_w,
        DynamicProxyLoopCtx {
            peer: &peer,
            read_buf_size: config.server.read_buffer_size,
            handshake_timeout: Duration::from_secs(config.server.handshake_timeout_secs.max(1)),
            obfs: obfs.as_mut(),
            protocol: protocol.as_mut(),
            iv_mitigator: &mut iv_mitigator,
            redirect_target: redirect_target.as_deref(),
            tcp_dns_cache: tcp_dns_cache.clone(),
        },
    )
    .await;
    protocol.dispose();
    result
}

struct DynamicProxyLoopCtx<'a> {
    peer: &'a str,
    read_buf_size: usize,
    handshake_timeout: Duration,
    obfs: &'a mut dyn ObfsCodec,
    protocol: &'a mut dyn ProtocolCodec,
    iv_mitigator: &'a mut IvHeaderMitigator,
    redirect_target: Option<&'a str>,
    tcp_dns_cache: TcpDnsCache,
}

async fn run_dynamic_proxy_loop(
    mut client_r: OwnedReadHalf,
    mut client_w: OwnedWriteHalf,
    ctx: DynamicProxyLoopCtx<'_>,
) -> Result<()> {
    let DynamicProxyLoopCtx {
        peer,
        read_buf_size,
        handshake_timeout,
        obfs,
        protocol,
        iv_mitigator,
        redirect_target,
        tcp_dns_cache,
    } = ctx;
    let mut client_buf = vec![0_u8; read_buf_size];
    let mut remote_buf = vec![0_u8; read_buf_size];
    let mut first_plain = Vec::new();
    let mut first_raw = Vec::new();
    let mut codec_buffers = CodecBuffers::default();
    let mut uplink_plain_bytes: u64 = 0;
    let mut downlink_plain_bytes: u64 = 0;
    let mut current_target: Option<String> = None;
    let handshake_deadline = TokioInstant::now() + handshake_timeout;

    let mut remote_r: Option<OwnedReadHalf> = None;
    let mut remote_w: Option<OwnedWriteHalf> = None;

    loop {
        if remote_r.is_none() {
            let n = match timeout_at(handshake_deadline, client_r.read(&mut client_buf)).await {
                Ok(res) => res?,
                Err(_) => {
                    debug!(
                        peer = %peer,
                        timeout_secs = handshake_timeout.as_secs(),
                        buffered_first_packet_bytes = first_raw.len(),
                        "timed out waiting for initial handshake bytes"
                    );
                    break;
                }
            };
            if n == 0 {
                break;
            }

            first_raw.extend_from_slice(&client_buf[..n]);
            let plain = match handle_client_packet(
                peer,
                &client_buf[..n],
                &mut client_w,
                obfs,
                protocol,
                iv_mitigator,
                &mut codec_buffers,
            )
            .await
            {
                Ok(v) => v,
                Err(err) => {
                    if let Some(first_packet_error) = err.downcast_ref::<FirstPacketError>() {
                        match first_packet_error {
                            FirstPacketError::PlainTlsClientHello => {
                                if let Some(target) = redirect_target
                                    .filter(|target| is_local_redirect_target(target))
                                {
                                    warn!(
                                        peer = %peer,
                                        redirect = %target,
                                        first_packet_hex = %hex_preview(&first_raw, 64),
                                        "plain TLS ClientHello detected on SSR port, switching to local redirect passthrough"
                                    );
                                    return run_redirect_passthrough(
                                        peer,
                                        client_r,
                                        client_w,
                                        target,
                                        &first_raw,
                                        read_buf_size,
                                    )
                                    .await;
                                }

                                warn!(
                                    peer = %peer,
                                    first_packet_hex = %hex_preview(&first_raw, 64),
                                    "plain TLS ClientHello detected on SSR port, returning TLS fatal alert"
                                );
                                send_tls_alert_and_close(
                                    &mut client_w,
                                    tls_record_version_or_default(&first_raw),
                                )
                                .await?;
                                return Ok(());
                            }
                            FirstPacketError::DropConnection => {
                                warn!(
                                    peer = %peer,
                                    first_packet_hex = %hex_preview(&first_raw, 64),
                                    "dropping invalid non-TLS first packet"
                                );
                                return Ok(());
                            }
                        }
                    }
                    if let Some(target) = redirect_target {
                        warn!(
                            peer = %peer,
                            redirect = %target,
                            error = %err,
                            first_packet_hex = %hex_preview(&first_raw, 64),
                            "protocol/obfs decode failed before target resolution, switching to redirect passthrough"
                        );
                        return run_redirect_passthrough(
                            peer,
                            client_r,
                            client_w,
                            target,
                            &first_raw,
                            read_buf_size,
                        )
                        .await;
                    }
                    return Err(err);
                }
            };

            if !plain {
                continue;
            }
            first_plain.extend_from_slice(&codec_buffers.protocol_plain);
            if first_plain.is_empty() {
                continue;
            }

            let parsed = match parse_ss_target_header(&first_plain) {
                Ok(v) => v,
                Err(err) => {
                    if let Some(target) = redirect_target {
                        warn!(
                            redirect = %target,
                            error = %err,
                            first_plain_hex = %hex_preview(&first_plain, 64),
                            "target header parse failed, switching to redirect passthrough"
                        );
                        return run_redirect_passthrough(
                            peer,
                            client_r,
                            client_w,
                            target,
                            &first_raw,
                            read_buf_size,
                        )
                        .await;
                    }
                    return Err(err);
                }
            };

            match parsed {
                Some((target_host, target_port, header_len)) => {
                    info!(target_host = %target_host, target_port, "tcp request parsed");
                    let target_addr = resolve_tcp_target(&target_host, target_port, &tcp_dns_cache)
                        .await
                        .with_context(|| {
                            format!("failed to resolve target {}:{}", target_host, target_port)
                        })?;
                    let remote = TcpStream::connect(target_addr)
                        .await
                        .with_context(|| format!("failed to connect target {}", target_addr))?;
                    if let Err(err) = remote.set_nodelay(true) {
                        debug!(
                            peer = %peer,
                            target = %target_addr,
                            error = %err,
                            "failed to set nodelay on target socket"
                        );
                    }

                    info!(peer = %peer, target = %target_addr, "dynamic target connected");
                    current_target = Some(target_addr.to_string());
                    let (r, w) = remote.into_split();
                    let mut w = BufWriter::with_capacity(read_buf_size.max(2048), w);
                    if first_plain.len() > header_len {
                        let payload = &first_plain[header_len..];
                        w.write_all(payload).await?;
                        w.flush().await?;
                        uplink_plain_bytes += payload.len() as u64;
                    }
                    remote_r = Some(r);
                    remote_w = Some(w.into_inner());
                }
                None => {
                    continue;
                }
            }
        } else {
            let (r, w) = match (&mut remote_r, &mut remote_w) {
                (Some(r), Some(w)) => (r, w),
                _ => break,
            };
            let mut remote_writer = BufWriter::with_capacity(read_buf_size.max(2048), w);
            let mut client_writer =
                BufWriter::with_capacity(read_buf_size.max(2048), &mut client_w);

            enum IoEvent {
                Client(usize),
                Remote(usize),
            }

            let event = tokio::select! {
                client_res = client_r.read(&mut client_buf) => IoEvent::Client(client_res?),
                remote_res = r.read(&mut remote_buf) => IoEvent::Remote(remote_res?),
            };

            match event {
                IoEvent::Client(n) => {
                    if n == 0 {
                        break;
                    }
                    if handle_client_packet(
                        peer,
                        &client_buf[..n],
                        &mut client_w,
                        obfs,
                        protocol,
                        iv_mitigator,
                        &mut codec_buffers,
                    )
                    .await?
                    {
                        if !codec_buffers.protocol_plain.is_empty() {
                            remote_writer
                                .write_all(&codec_buffers.protocol_plain)
                                .await?;
                            remote_writer.flush().await?;
                            uplink_plain_bytes += codec_buffers.protocol_plain.len() as u64;
                        }
                    }
                }
                IoEvent::Remote(n) => {
                    if n == 0 {
                        break;
                    }
                    downlink_plain_bytes += n as u64;
                    protocol.encode_to_client_into(
                        &remote_buf[..n],
                        &mut codec_buffers.protocol_outbound,
                    )?;
                    iv_mitigator.process_outbound_into(
                        &codec_buffers.protocol_outbound,
                        &mut codec_buffers.iv_outbound,
                    );
                    obfs.encode_to_client_into(
                        &codec_buffers.iv_outbound,
                        &mut codec_buffers.obfs_outbound,
                    )?;
                    if !codec_buffers.obfs_outbound.is_empty() {
                        client_writer
                            .write_all(&codec_buffers.obfs_outbound)
                            .await?;
                        client_writer.flush().await?;
                        protocol.on_encode_to_client_flushed(true)?;
                    }
                }
            }
        }
    }

    info!(
        target = %current_target.unwrap_or_else(|| "-".to_string()),
        uplink_plain_bytes,
        downlink_plain_bytes,
        "connection closed"
    );
    Ok(())
}

fn tls_record_version_or_default(first_packet: &[u8]) -> [u8; 2] {
    if first_packet.len() >= 3 && first_packet[0] == 0x16 && first_packet[1] == 0x03 {
        return [first_packet[1], first_packet[2]];
    }
    [0x03, 0x03]
}

fn build_tls_fatal_alert(record_version: [u8; 2]) -> [u8; 7] {
    [
        0x15,
        record_version[0],
        record_version[1],
        0x00,
        0x02,
        0x02,
        0x70,
    ]
}

async fn send_tls_alert_and_close(
    client_w: &mut OwnedWriteHalf,
    record_version: [u8; 2],
) -> Result<()> {
    client_w
        .write_all(&build_tls_fatal_alert(record_version))
        .await?;
    let _ = client_w.shutdown().await;
    Ok(())
}

async fn run_redirect_passthrough(
    peer: &str,
    mut client_r: OwnedReadHalf,
    mut client_w: OwnedWriteHalf,
    redirect_target: &str,
    initial_data: &[u8],
    read_buf_size: usize,
) -> Result<()> {
    info!(
        peer = %peer,
        redirect = %redirect_target,
        initial_bytes = initial_data.len(),
        "starting redirect passthrough"
    );
    let redirect = TcpStream::connect(redirect_target)
        .await
        .with_context(|| format!("failed to connect redirect target {}", redirect_target))?;
    if let Err(err) = redirect.set_nodelay(true) {
        debug!(peer = %peer, redirect = %redirect_target, error = %err, "failed to set nodelay on redirect socket");
    }
    let (mut redirect_r, mut redirect_w) = redirect.into_split();

    if !initial_data.is_empty() {
        redirect_w.write_all(initial_data).await?;
    }

    let mut client_buf = vec![0_u8; read_buf_size.max(2048)];
    let mut remote_buf = vec![0_u8; read_buf_size.max(2048)];
    let mut c2r_bytes: u64 = initial_data.len() as u64;
    let mut r2c_bytes: u64 = 0;

    loop {
        enum IoEvent {
            Client(usize),
            Redirect(usize),
        }

        let event = tokio::select! {
            client_res = client_r.read(&mut client_buf) => IoEvent::Client(client_res?),
            redirect_res = redirect_r.read(&mut remote_buf) => IoEvent::Redirect(redirect_res?),
        };

        match event {
            IoEvent::Client(n) => {
                if n == 0 {
                    break;
                }
                redirect_w.write_all(&client_buf[..n]).await?;
                c2r_bytes += n as u64;
            }
            IoEvent::Redirect(n) => {
                if n == 0 {
                    break;
                }
                client_w.write_all(&remote_buf[..n]).await?;
                r2c_bytes += n as u64;
            }
        }
    }

    info!(
        peer = %peer,
        redirect = %redirect_target,
        client_to_redirect_bytes = c2r_bytes,
        redirect_to_client_bytes = r2c_bytes,
        "redirect passthrough closed"
    );
    Ok(())
}

fn parse_ss_target_header(data: &[u8]) -> Result<Option<(String, u16, usize)>> {
    if data.is_empty() {
        return Ok(None);
    }
    let addr_type = data[0] & 0x07;
    match addr_type {
        1 => {
            if data.len() < 7 {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]).to_string();
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok(Some((ip, port, 7)))
        }
        3 => {
            if data.len() < 2 {
                return Ok(None);
            }
            let len = data[1] as usize;
            if data.len() < 4 + len {
                return Ok(None);
            }
            let host = String::from_utf8_lossy(&data[2..2 + len]).into_owned();
            let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
            Ok(Some((host, port, 4 + len)))
        }
        4 => {
            if data.len() < 19 {
                return Ok(None);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = Ipv6Addr::from(octets).to_string();
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok(Some((ip, port, 19)))
        }
        other => Err(anyhow!("unsupported target address type {}", other)),
    }
}

async fn resolve_tcp_target(host: &str, port: u16, dns_cache: &TcpDnsCache) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        debug!(target_host = %host, target_port = port, resolved = %addr, "target is already an IP address");
        return Ok(addr);
    }
    let key = TcpDnsCacheKey {
        host: host.to_string(),
        port,
    };
    if let Some(addr) = dns_cache.lock().get(&key) {
        return Ok(addr);
    }
    let mut addrs = lookup_host((host, port))
        .await
        .with_context(|| format!("dns resolve failed for {}:{}", host, port))?;
    let addr = addrs
        .next()
        .ok_or_else(|| anyhow!("dns returned no address for {}:{}", host, port))?;
    dns_cache.lock().insert(key, addr);
    debug!(target_host = %host, target_port = port, resolved = %addr, "dns resolved target");
    Ok(addr)
}

fn pick_redirect_target(config: &AppConfig) -> Option<String> {
    let listen_port = listen_port_from_addr(&config.server.listen)?;
    for rule in &config.server.redirect {
        if let Some(target) = parse_redirect_rule(rule, listen_port) {
            return Some(target);
        }
    }
    None
}

fn parse_redirect_rule(rule: &str, listen_port: u16) -> Option<String> {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some((left, right)) = trimmed.split_once('#') {
        let matcher = left.trim();
        if let Some(port_text) = matcher.strip_prefix(':') {
            if port_text.parse::<u16>().ok() == Some(listen_port) {
                return Some(right.trim().to_string());
            }
            return None;
        }
        if let Some((_, maybe_port)) = matcher.rsplit_once(':') {
            if maybe_port.parse::<u16>().ok() == Some(listen_port) {
                return Some(right.trim().to_string());
            }
        }
        return None;
    }

    Some(trimmed.to_string())
}

fn is_local_redirect_target(target: &str) -> bool {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return addr.ip().is_loopback();
    }

    let Some((host, port)) = split_host_port(target) else {
        return false;
    };
    if port.parse::<u16>().is_err() {
        return false;
    }

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn split_host_port(target: &str) -> Option<(&str, &str)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host, port));
    }
    target.rsplit_once(':')
}

fn listen_port_from_addr(listen: &str) -> Option<u16> {
    let (_, port) = listen.rsplit_once(':')?;
    port.parse::<u16>().ok()
}

#[cfg(unix)]
fn detect_tcp_mss(stream: &TcpStream) -> Option<u16> {
    let fd = stream.as_raw_fd();
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            (&mut val as *mut libc::c_int).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc == 0 && val > 0 {
        Some((val as u16).clamp(500, 1500))
    } else {
        None
    }
}

#[cfg(not(unix))]
fn detect_tcp_mss(_stream: &TcpStream) -> Option<u16> {
    None
}

async fn handle_client_packet(
    peer: &str,
    input: &[u8],
    client_w: &mut OwnedWriteHalf,
    obfs: &mut dyn ObfsCodec,
    protocol: &mut dyn ProtocolCodec,
    iv_mitigator: &mut IvHeaderMitigator,
    buffers: &mut CodecBuffers,
) -> Result<bool> {
    let (need_decrypt, obfs_sendback) =
        obfs.decode_from_client_into(input, &mut buffers.obfs_decoded)?;

    if obfs_sendback {
        obfs.encode_to_client_into(&[], &mut buffers.obfs_outbound)?;
        if !buffers.obfs_outbound.is_empty() {
            client_w.write_all(&buffers.obfs_outbound).await?;
            debug!(peer = %peer, bytes = buffers.obfs_outbound.len(), "sent obfs handshake response");
        }
    }

    if !need_decrypt {
        return Ok(false);
    }

    if !iv_mitigator.process_inbound_into(&buffers.obfs_decoded, &mut buffers.inbound_plain)? {
        return Ok(false);
    }

    let proto_sendback =
        protocol.decode_from_client_into(&buffers.inbound_plain, &mut buffers.protocol_plain)?;
    if proto_sendback {
        protocol.encode_to_client_into(&[], &mut buffers.protocol_outbound)?;
        iv_mitigator.process_outbound_into(&buffers.protocol_outbound, &mut buffers.iv_outbound);
        obfs.encode_to_client_into(&buffers.iv_outbound, &mut buffers.obfs_outbound)?;
        if !buffers.obfs_outbound.is_empty() {
            client_w.write_all(&buffers.obfs_outbound).await?;
            protocol.on_encode_to_client_flushed(true)?;
            debug!(peer = %peer, bytes = buffers.obfs_outbound.len(), "sent protocol sendback frame");
        }
    }

    Ok(!buffers.protocol_plain.is_empty())
}

fn hex_preview(data: &[u8], max_bytes: usize) -> String {
    if data.is_empty() {
        return "-".to_string();
    }
    let take = data.len().min(max_bytes);
    let mut out = hex::encode(&data[..take]);
    if data.len() > take {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        IvHeaderMitigator, build_codecs, build_tls_fatal_alert, is_local_redirect_target,
        parse_redirect_rule, parse_ss_target_header,
    };
    use crate::config::AppConfig;
    use crate::obfs::tls12_ticket_auth::TlsTicketAuthShared;
    use crate::state::SharedUserRegistry;
    use std::collections::HashMap;

    fn base_config() -> AppConfig {
        AppConfig {
            server: crate::config::ServerConfig {
                listen: "127.0.0.1:443".to_string(),
                redirect: Vec::new(),
                cipher: "none".to_string(),
                read_buffer_size: 2048,
                handshake_timeout_secs: 10,
                max_tcp_connections: 16,
                udp_enabled: false,
                udp_listen: None,
                udp_timeout_secs: 30,
                udp_max_associations: 16,
                replay_max_entries: 128,
            },
            logging: crate::config::LoggingConfig {
                level: "info".to_string(),
            },
            obfs: crate::config::ObfsConfig {
                method: "tls1.2_ticket_auth".to_string(),
                obfs_param: String::new(),
                host: String::new(),
            },
            protocol: crate::config::ProtocolConfig {
                method: "auth_akarin_spec_a".to_string(),
                password: "demo-pass".to_string(),
                protocol_param: "64".to_string(),
                tcp_mss: 1460,
                overhead: 4,
                users: HashMap::new(),
            },
        }
    }

    #[test]
    fn parses_port_specific_redirect_rule() {
        assert_eq!(
            parse_redirect_rule(":8443#127.0.0.1:443", 8443),
            Some("127.0.0.1:443".to_string())
        );
    }

    #[test]
    fn rejects_wildcard_redirect_rule() {
        assert_eq!(parse_redirect_rule("*#127.0.0.1:443", 8443), None);
    }

    #[test]
    fn detects_loopback_redirect_targets() {
        assert!(is_local_redirect_target("127.0.0.1:443"));
        assert!(is_local_redirect_target("[::1]:443"));
        assert!(is_local_redirect_target("localhost:443"));
        assert!(!is_local_redirect_target("example.com:443"));
    }

    #[test]
    fn parse_ss_target_header_supports_all_address_families() {
        let ipv4 = [1_u8, 127, 0, 0, 1, 0x01, 0xbb];
        let domain = [
            3_u8, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb,
        ];
        let mut ipv6 = vec![4_u8];
        ipv6.extend_from_slice(&[0_u8; 15]);
        ipv6.push(1);
        ipv6.extend_from_slice(&0x01bbu16.to_be_bytes());

        assert_eq!(
            parse_ss_target_header(&ipv4).expect("ipv4"),
            Some(("127.0.0.1".to_string(), 443, 7))
        );
        assert_eq!(
            parse_ss_target_header(&domain).expect("domain"),
            Some(("example.com".to_string(), 443, 15))
        );
        assert_eq!(
            parse_ss_target_header(&ipv6).expect("ipv6"),
            Some(("::1".to_string(), 443, 19))
        );
    }

    #[test]
    fn iv_header_mitigator_strips_optional_inbound_header() {
        let mut mitigator = IvHeaderMitigator::new(b"\x16\x03\x03".to_vec(), false);
        let mut out = Vec::new();

        assert!(
            !mitigator
                .process_inbound_into(b"\x16\x03", &mut out)
                .expect("partial header should buffer")
        );
        assert!(out.is_empty());
        assert!(
            mitigator
                .process_inbound_into(b"\x03payload", &mut out)
                .expect("full header should decode")
        );
        assert_eq!(out, b"payload");
    }

    #[test]
    fn iv_header_mitigator_leaves_outbound_untouched() {
        let mut mitigator = IvHeaderMitigator::new(b"\x16\x03\x03".to_vec(), false);
        let mut out = Vec::new();

        mitigator.process_outbound_into(b"first", &mut out);
        assert_eq!(out, b"first");

        mitigator.process_outbound_into(b"second", &mut out);
        assert_eq!(out, b"second");
    }

    #[test]
    fn build_tls_fatal_alert_uses_requested_record_version() {
        let alert = build_tls_fatal_alert([0x03, 0x01]);
        assert_eq!(alert, [0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x70]);
    }

    #[test]
    fn build_codecs_accepts_supported_protocol_stacks() {
        let variants = ["auth_chain_d", "auth_akarin_rand", "auth_akarin_spec_a"];

        for method in variants {
            let mut config = base_config();
            config.protocol.method = method.to_string();
            let result = build_codecs(
                &config,
                "peer",
                TlsTicketAuthShared::with_capacity(32),
                SharedUserRegistry::new(64),
            );
            assert!(result.is_ok(), "codec stack should support {method}");
        }
    }

    #[tokio::test]
    async fn server_run_rejects_unsupported_cipher() {
        let mut config = base_config();
        config.server.cipher = "aes-256-gcm".to_string();

        let err = super::run(config)
            .await
            .expect_err("unsupported cipher should fail before binding");
        assert!(
            err.to_string().contains("unsupported cipher"),
            "unexpected error: {err}"
        );
    }
}
