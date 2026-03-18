use crate::config::AppConfig;
use crate::protocol::ProtocolConfigRuntime;
use crate::protocol::udp::{UdpClientPacket, UdpProtocolCodec, UdpSendPlan, UdpSessionRef};
use anyhow::{Context, Result, anyhow};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::Notify;
use tokio::sync::futures::OwnedNotified;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum UdpFamily {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AssociationKey {
    client_addr: SocketAddr,
    family: UdpFamily,
    session: UdpSessionRef,
}

struct UdpAssociation {
    socket: Arc<UdpSocket>,
}

enum AssociationEntry {
    Ready(Arc<UdpAssociation>),
    Binding(Arc<Notify>),
}

type UdpAssociations = Arc<Mutex<HashMap<AssociationKey, AssociationEntry>>>;

const UDP_DNS_CACHE_TTL: Duration = Duration::from_secs(30);
const UDP_DNS_CACHE_MAX_ENTRIES: usize = 4096;
const UDP_INBOUND_QUEUE_CAPACITY: usize = 1024;

struct InboundPacketJob {
    client_addr: SocketAddr,
    packet: Vec<u8>,
}

struct OutboundPacketJob {
    client_addr: SocketAddr,
    plan: UdpSendPlan,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DnsCacheKey {
    host: String,
    port: u16,
}

#[derive(Clone, Copy, Debug)]
struct CachedTarget {
    addr: SocketAddr,
    expires_at: Instant,
}

#[derive(Debug)]
struct ResolvedTargetCache {
    ttl: Duration,
    max_entries: usize,
    entries: HashMap<DnsCacheKey, CachedTarget>,
    order: VecDeque<(Instant, DnsCacheKey)>,
}

impl ResolvedTargetCache {
    fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &DnsCacheKey) -> Option<SocketAddr> {
        let now = Instant::now();
        self.sweep_expired(now);
        self.entries.get(key).map(|entry| entry.addr)
    }

    fn insert(&mut self, key: DnsCacheKey, addr: SocketAddr) {
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
            .insert(key.clone(), CachedTarget { addr, expires_at });
        self.order.push_back((expires_at, key));
    }

    fn sweep_expired(&mut self, now: Instant) {
        while let Some((expires_at, _)) = self.order.front() {
            if *expires_at >= now {
                break;
            }

            let (expires_at, key) = self.order.pop_front().expect("dns cache entry");
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

type DnsCache = Arc<Mutex<ResolvedTargetCache>>;

enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

enum AssociationReservation {
    Wait(OwnedNotified),
    Create(Arc<Notify>),
}

pub async fn run(config: AppConfig) -> Result<()> {
    let protocol = Arc::new(build_udp_protocol(&config)?);
    let listen_addr = config.udp_listen_addr();
    let listen_socket = Arc::new(
        UdpSocket::bind(&listen_addr)
            .await
            .with_context(|| format!("failed to bind UDP {}", listen_addr))?,
    );

    let read_buf_size = config.server.read_buffer_size.max(2048);
    let timeout = Duration::from_secs(config.server.udp_timeout_secs.max(1));
    let max_associations = config.server.udp_max_associations.max(1);

    info!(
        udp_listen = %listen_addr,
        udp_timeout_secs = config.server.udp_timeout_secs,
        udp_max_associations = config.server.udp_max_associations,
        "udp relay listening"
    );

    let associations: UdpAssociations = Arc::new(Mutex::new(HashMap::new()));
    let dns_cache: DnsCache = Arc::new(Mutex::new(ResolvedTargetCache::new(
        UDP_DNS_CACHE_TTL,
        UDP_DNS_CACHE_MAX_ENTRIES,
    )));
    let inbound_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1);
    let mut outbound_senders = Vec::with_capacity(inbound_workers);
    for worker_id in 0..inbound_workers {
        let (tx, mut rx) = mpsc::channel::<OutboundPacketJob>(UDP_INBOUND_QUEUE_CAPACITY);
        outbound_senders.push(tx);

        let listen_socket = listen_socket.clone();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                let delivered = if let Err(err) = listen_socket
                    .send_to(job.plan.packet(), job.client_addr)
                    .await
                {
                    debug!(
                        worker_id,
                        client = %job.client_addr,
                        error = %err,
                        "udp sharded sender failed to send packet"
                    );
                    false
                } else {
                    true
                };
                job.plan.complete(delivered);
            }
        });
    }
    let outbound_senders = Arc::new(outbound_senders);
    let mut worker_senders = Vec::with_capacity(inbound_workers);
    for worker_id in 0..inbound_workers {
        let (tx, mut rx) = mpsc::channel::<InboundPacketJob>(UDP_INBOUND_QUEUE_CAPACITY);
        worker_senders.push(tx);

        let associations = associations.clone();
        let dns_cache = dns_cache.clone();
        let outbound_senders = outbound_senders.clone();
        let protocol = protocol.clone();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                let result = process_incoming_udp_packet(
                    job.client_addr,
                    &job.packet,
                    associations.clone(),
                    dns_cache.clone(),
                    outbound_senders.clone(),
                    protocol.clone(),
                    max_associations,
                    read_buf_size,
                    timeout,
                )
                .await;
                if let Err(err) = result {
                    warn!(
                        worker_id,
                        client = %job.client_addr,
                        error = %err,
                        "udp worker dropped packet due to processing error"
                    );
                }
            }
        });
    }
    let mut inbound_buf = vec![0_u8; read_buf_size];
    let mut next_worker = 0_usize;

    loop {
        let (n, client_addr) = listen_socket.recv_from(&mut inbound_buf).await?;
        if n == 0 {
            continue;
        }
        let packet = inbound_buf[..n].to_vec();
        let job = InboundPacketJob {
            client_addr,
            packet,
        };
        if let Err(err) = worker_senders[next_worker].send(job).await {
            warn!(
                client = %client_addr,
                error = %err,
                worker = next_worker,
                "udp worker queue closed, dropping packet"
            );
        }
        next_worker = (next_worker + 1) % inbound_workers;
    }
}

async fn process_incoming_udp_packet(
    client_addr: SocketAddr,
    packet: &[u8],
    associations: UdpAssociations,
    dns_cache: DnsCache,
    outbound_senders: Arc<Vec<mpsc::Sender<OutboundPacketJob>>>,
    protocol: Arc<UdpProtocolCodec>,
    max_associations: usize,
    read_buf_size: usize,
    timeout: Duration,
) -> Result<()> {
    let decoded = match protocol.decode_from_client(packet) {
        Ok(v) => v,
        Err(err) => {
            debug!(client = %client_addr, error = %err, "drop invalid udp client packet");
            return Ok(());
        }
    };

    let UdpClientPacket::Data {
        plain: decoded,
        session,
    } = decoded;

    let (target, header_len) = match parse_target_addr(&decoded) {
        Ok(v) => v,
        Err(err) => {
            debug!(client = %client_addr, error = %err, "drop udp packet with invalid target header");
            return Ok(());
        }
    };
    let payload = &decoded[header_len..];

    let target_addr = match resolve_target_addr(target, &dns_cache).await {
        Ok(addr) => addr,
        Err(err) => {
            debug!(client = %client_addr, error = %err, "failed to resolve udp target");
            return Ok(());
        }
    };
    debug!(
        client = %client_addr,
        target = %target_addr,
        payload_bytes = payload.len(),
        session = ?session,
        "udp request parsed and ready to relay"
    );
    let family = if target_addr.is_ipv6() {
        UdpFamily::V6
    } else {
        UdpFamily::V4
    };

    let key = AssociationKey {
        client_addr,
        family,
        session,
    };

    let association = match get_or_create_association(
        associations,
        key,
        max_associations,
        read_buf_size,
        timeout,
        outbound_senders,
        protocol,
    )
    .await
    {
        Ok(v) => v,
        Err(err) => {
            warn!(client = %client_addr, error = %err, "drop udp packet due to association limit or socket error");
            return Ok(());
        }
    };

    if let Err(err) = association.socket.send_to(payload, target_addr).await {
        warn!(client = %client_addr, target = %target_addr, error = %err, "udp forward send failed");
    }
    Ok(())
}

fn build_udp_protocol(config: &AppConfig) -> Result<UdpProtocolCodec> {
    let key = config.protocol.password.as_bytes().to_vec();
    let users = config.user_map_bytes();

    let runtime = ProtocolConfigRuntime {
        method: config.protocol.method.clone(),
        key,
        recv_iv: Vec::new(),
        protocol_param: config.protocol.protocol_param.clone(),
        users,
        overhead: config.protocol.overhead,
        tcp_mss: config.protocol.tcp_mss,
    };

    UdpProtocolCodec::new_with_replay_capacity(runtime, config.server.replay_max_entries)
}

async fn get_or_create_association(
    associations: UdpAssociations,
    key: AssociationKey,
    max_associations: usize,
    read_buf_size: usize,
    timeout: Duration,
    outbound_senders: Arc<Vec<mpsc::Sender<OutboundPacketJob>>>,
    protocol: Arc<UdpProtocolCodec>,
) -> Result<Arc<UdpAssociation>> {
    loop {
        let reservation = {
            let mut map = associations.lock();
            match map.get(&key) {
                Some(AssociationEntry::Ready(existing)) => return Ok(existing.clone()),
                Some(AssociationEntry::Binding(waiter)) => Some(AssociationReservation::Wait(
                    waiter.clone().notified_owned(),
                )),
                None => {
                    if map.len() >= max_associations {
                        return Err(anyhow!(
                            "udp association limit reached: {}",
                            max_associations
                        ));
                    }

                    let waiter = Arc::new(Notify::new());
                    map.insert(key, AssociationEntry::Binding(waiter.clone()));
                    Some(AssociationReservation::Create(waiter))
                }
            }
        };

        match reservation {
            Some(AssociationReservation::Wait(waiter)) => {
                waiter.await;
                continue;
            }
            Some(AssociationReservation::Create(waiter)) => {
                let bind_addr = match key.family {
                    UdpFamily::V4 => "0.0.0.0:0",
                    UdpFamily::V6 => "[::]:0",
                };
                let socket = match UdpSocket::bind(bind_addr)
                    .await
                    .with_context(|| format!("failed to bind udp association socket {}", bind_addr))
                {
                    Ok(socket) => Arc::new(socket),
                    Err(err) => {
                        let notify = {
                            let mut map = associations.lock();
                            let removed = map.remove(&key);
                            match removed {
                                Some(AssociationEntry::Binding(notify)) => Some(notify),
                                Some(entry @ AssociationEntry::Ready(_)) => {
                                    map.insert(key, entry);
                                    None
                                }
                                None => None,
                            }
                        };
                        if let Some(notify) = notify {
                            notify.notify_waiters();
                        }
                        return Err(err);
                    }
                };

                let association = Arc::new(UdpAssociation {
                    socket: socket.clone(),
                });

                let associations_len = {
                    let mut map = associations.lock();
                    map.insert(key, AssociationEntry::Ready(association.clone()));
                    map.len()
                };

                spawn_association_task(
                    associations.clone(),
                    key,
                    association.clone(),
                    read_buf_size,
                    timeout,
                    outbound_senders,
                    protocol,
                );

                waiter.notify_waiters();
                info!(
                    client = %key.client_addr,
                    family = ?key.family,
                    session = ?key.session,
                    associations = associations_len,
                    "udp association created"
                );
                return Ok(association);
            }
            None => {
                unreachable!("association lookup should resolve via ready entry or reservation")
            }
        }
    }
}

fn spawn_association_task(
    associations: UdpAssociations,
    key: AssociationKey,
    association: Arc<UdpAssociation>,
    read_buf_size: usize,
    timeout: Duration,
    outbound_senders: Arc<Vec<mpsc::Sender<OutboundPacketJob>>>,
    protocol: Arc<UdpProtocolCodec>,
) {
    tokio::spawn(async move {
        let mut recv_buf = vec![0_u8; read_buf_size.max(2048)];
        loop {
            let received =
                tokio::time::timeout(timeout, association.socket.recv_from(&mut recv_buf)).await;
            let (n, source_addr) = match received {
                Ok(Ok(v)) => v,
                Ok(Err(err)) => {
                    debug!(client = %key.client_addr, error = %err, "udp association recv failed");
                    break;
                }
                Err(_) => {
                    debug!(client = %key.client_addr, "udp association timeout, recycling socket");
                    break;
                }
            };
            if n == 0 {
                continue;
            }

            let plain_packet = pack_udp_response_packet(source_addr, &recv_buf[..n]);
            let encoded = match protocol.encode_to_client(&plain_packet, key.session) {
                Ok(v) => v,
                Err(err) => {
                    debug!(client = %key.client_addr, error = %err, "udp encode_to_client failed");
                    continue;
                }
            };
            debug!(
                client = %key.client_addr,
                source = %source_addr,
                encoded_bytes = encoded.packet().len(),
                "udp response encoded and ready for client"
            );
            dispatch_udp_response(key.client_addr, encoded, &outbound_senders).await;
        }

        let mut map = associations.lock();
        let should_remove = matches!(
            map.get(&key),
            Some(AssociationEntry::Ready(current)) if Arc::ptr_eq(current, &association)
        );
        if should_remove {
            map.remove(&key);
            info!(
                client = %key.client_addr,
                family = ?key.family,
                session = ?key.session,
                associations = map.len(),
                "udp association removed"
            );
        }
    });
}

async fn dispatch_udp_response(
    client_addr: SocketAddr,
    plan: UdpSendPlan,
    outbound_senders: &Arc<Vec<mpsc::Sender<OutboundPacketJob>>>,
) {
    let shard = udp_sender_shard(client_addr, outbound_senders.len());
    if let Err(err) = outbound_senders[shard]
        .send(OutboundPacketJob { client_addr, plan })
        .await
    {
        let job = err.0;
        debug!(
            client = %job.client_addr,
            shard,
            "udp sharded sender queue closed, dropping packet"
        );
        job.plan.complete(false);
    }
}

fn udp_sender_shard(client_addr: SocketAddr, shard_count: usize) -> usize {
    if shard_count <= 1 {
        return 0;
    }
    let hash = match client_addr.ip() {
        IpAddr::V4(ip) => u32::from_be_bytes(ip.octets()) as usize,
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            usize::from(octets[0])
                ^ usize::from(octets[5])
                ^ usize::from(octets[10])
                ^ usize::from(octets[15])
        }
    } ^ usize::from(client_addr.port());
    hash % shard_count
}

fn parse_target_addr(data: &[u8]) -> Result<(TargetAddr, usize)> {
    if data.is_empty() {
        return Err(anyhow!("empty udp payload"));
    }
    let addr_type = data[0] & 0x07;
    match addr_type {
        1 => {
            if data.len() < 7 {
                return Err(anyhow!("short ipv4 udp header"));
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 7))
        }
        3 => {
            if data.len() < 4 {
                return Err(anyhow!("short domain udp header"));
            }
            let len = data[1] as usize;
            if data.len() < 4 + len {
                return Err(anyhow!("domain udp header length mismatch"));
            }
            let host = String::from_utf8_lossy(&data[2..2 + len]).into_owned();
            let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
            Ok((TargetAddr::Domain(host, port), 4 + len))
        }
        4 => {
            if data.len() < 19 {
                return Err(anyhow!("short ipv6 udp header"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port)), 19))
        }
        other => Err(anyhow!("unsupported udp addr type {}", other)),
    }
}

async fn resolve_target_addr(target: TargetAddr, dns_cache: &DnsCache) -> Result<SocketAddr> {
    match target {
        TargetAddr::Ip(addr) => Ok(addr),
        TargetAddr::Domain(host, port) => {
            let key = DnsCacheKey { host, port };
            if let Some(addr) = dns_cache.lock().get(&key) {
                return Ok(addr);
            }

            let addr = {
                let mut addrs = lookup_host((key.host.as_str(), key.port))
                    .await
                    .with_context(|| format!("dns resolve failed for {}:{}", key.host, key.port))?;
                addrs.next().ok_or_else(|| {
                    anyhow!("dns returned no address for {}:{}", key.host, key.port)
                })?
            };
            dns_cache.lock().insert(key, addr);
            Ok(addr)
        }
    }
}

fn pack_udp_response_packet(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    match source {
        SocketAddr::V4(v4) => {
            let mut out = Vec::with_capacity(1 + 4 + 2 + payload.len());
            out.push(1);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
        SocketAddr::V6(v6) => {
            let mut out = Vec::with_capacity(1 + 16 + 2 + payload.len());
            out.push(4);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::thread;

    #[test]
    fn association_keys_are_scoped_by_session() {
        let client_addr: SocketAddr = "127.0.0.1:9000".parse().expect("client addr");

        let key_a = AssociationKey {
            client_addr,
            family: UdpFamily::V4,
            session: UdpSessionRef::LegacyUid(Some(1001)),
        };
        let key_b = AssociationKey {
            client_addr,
            family: UdpFamily::V4,
            session: UdpSessionRef::LegacyUid(Some(2002)),
        };
        let key_c = AssociationKey {
            client_addr,
            family: UdpFamily::V4,
            session: UdpSessionRef::LegacyUid(Some(1001)),
        };

        assert_ne!(
            key_a, key_b,
            "different sessions from the same client must map to different association keys"
        );
        assert_eq!(
            key_a, key_c,
            "the same client/session tuple should still hit the same association key"
        );

        let mut associations = HashMap::new();
        associations.insert(key_a, 1_u8);
        associations.insert(key_b, 2_u8);
        assert_eq!(
            associations.len(),
            2,
            "association table should hold one entry per client/family/session tuple"
        );
        assert_eq!(
            associations.get(&key_c),
            Some(&1_u8),
            "reusing the same client/session should resolve to the original association slot"
        );
    }

    #[test]
    fn resolved_target_cache_keeps_latest_entry_per_host() {
        let mut cache = ResolvedTargetCache::new(Duration::from_secs(30), 2);
        let key = DnsCacheKey {
            host: "example.com".to_string(),
            port: 53,
        };
        let first: SocketAddr = "1.1.1.1:53".parse().expect("first addr");
        let second: SocketAddr = "8.8.8.8:53".parse().expect("second addr");

        cache.insert(key.clone(), first);
        cache.insert(key.clone(), second);

        assert_eq!(
            cache.entries.len(),
            1,
            "cache should overwrite duplicate host entries"
        );
        assert_eq!(
            cache.order.len(),
            1,
            "updating the same host should not grow the expiry queue"
        );
        assert_eq!(cache.get(&key), Some(second));
    }

    #[test]
    fn resolved_target_cache_evicts_expired_entries() {
        let mut cache = ResolvedTargetCache::new(Duration::from_millis(5), 4);
        let key = DnsCacheKey {
            host: "expired.example".to_string(),
            port: 443,
        };
        let addr: SocketAddr = "203.0.113.10:443".parse().expect("cached addr");

        cache.insert(key.clone(), addr);
        thread::sleep(Duration::from_millis(10));

        assert_eq!(
            cache.get(&key),
            None,
            "expired DNS entries should be discarded"
        );
    }

    #[test]
    fn resolved_target_cache_update_does_not_evict_other_hosts_at_capacity() {
        let mut cache = ResolvedTargetCache::new(Duration::from_secs(30), 2);
        let hot_key = DnsCacheKey {
            host: "hot.example".to_string(),
            port: 53,
        };
        let cold_key = DnsCacheKey {
            host: "cold.example".to_string(),
            port: 53,
        };
        let hot_addr: SocketAddr = "1.1.1.1:53".parse().expect("hot addr");
        let updated_hot_addr: SocketAddr = "8.8.8.8:53".parse().expect("updated hot addr");
        let cold_addr: SocketAddr = "9.9.9.9:53".parse().expect("cold addr");

        cache.insert(hot_key.clone(), hot_addr);
        cache.insert(cold_key.clone(), cold_addr);
        cache.insert(hot_key.clone(), updated_hot_addr);

        assert_eq!(
            cache.entries.len(),
            2,
            "updating an existing host should keep cache size stable"
        );
        assert_eq!(
            cache.order.len(),
            2,
            "expiry queue should stay bounded by live entries"
        );
        assert_eq!(cache.get(&hot_key), Some(updated_hot_addr));
        assert_eq!(
            cache.get(&cold_key),
            Some(cold_addr),
            "updating one host should not evict unrelated cached hosts"
        );
    }

    #[test]
    fn udp_sender_shard_is_stable_per_client() {
        let client: SocketAddr = "127.0.0.1:9000".parse().expect("client");
        let first = udp_sender_shard(client, 8);
        let second = udp_sender_shard(client, 8);
        assert_eq!(first, second);
        assert!(first < 8);
    }

    #[test]
    fn udp_parse_target_addr_supports_all_address_families() {
        let ipv4 = [1_u8, 127, 0, 0, 1, 0x00, 0x35];
        let domain = [
            3_u8, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb,
        ];
        let mut ipv6 = vec![4_u8];
        ipv6.extend_from_slice(&[0_u8; 15]);
        ipv6.push(1);
        ipv6.extend_from_slice(&0x01bbu16.to_be_bytes());

        match parse_target_addr(&ipv4).expect("ipv4") {
            (TargetAddr::Ip(addr), 7) => assert_eq!(addr, "127.0.0.1:53".parse().unwrap()),
            _ => panic!("unexpected ipv4 parse result"),
        }
        match parse_target_addr(&domain).expect("domain") {
            (TargetAddr::Domain(host, port), 15) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("unexpected domain parse result"),
        }
        match parse_target_addr(&ipv6).expect("ipv6") {
            (TargetAddr::Ip(addr), 19) => assert_eq!(addr, "[::1]:443".parse().unwrap()),
            _ => panic!("unexpected ipv6 parse result"),
        }
    }

    #[test]
    fn pack_udp_response_packet_encodes_source_address_and_payload() {
        let ipv4_source: SocketAddr = "127.0.0.1:53".parse().expect("ipv4 source");
        let ipv6_source: SocketAddr = "[::1]:5353".parse().expect("ipv6 source");
        let payload = b"hello";

        let ipv4_packet = pack_udp_response_packet(ipv4_source, payload);
        let ipv6_packet = pack_udp_response_packet(ipv6_source, payload);

        match parse_target_addr(&ipv4_packet).expect("parse ipv4 response") {
            (TargetAddr::Ip(addr), 7) => {
                assert_eq!(addr, ipv4_source);
                assert_eq!(&ipv4_packet[7..], payload);
            }
            _ => panic!("unexpected ipv4 packet parse"),
        }
        match parse_target_addr(&ipv6_packet).expect("parse ipv6 response") {
            (TargetAddr::Ip(addr), 19) => {
                assert_eq!(addr, ipv6_source);
                assert_eq!(&ipv6_packet[19..], payload);
            }
            _ => panic!("unexpected ipv6 packet parse"),
        }
    }
}
