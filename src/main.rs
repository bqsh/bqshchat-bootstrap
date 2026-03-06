use anyhow::{anyhow, Result};
use futures::StreamExt;
use libp2p::{
    core::{
        muxing::StreamMuxerBox,
        transport::{upgrade::Version, Boxed, Transport},
    },
    gossipsub::{
        AllowAllSubscriptionFilter, Behaviour as GossipBehaviour, ConfigBuilder as GossipsubConfigBuilder,
        Event, IdentTopic, IdentityTransform, MessageAuthenticity, MessageId, PublishError, TopicHash,
        ValidationMode,
    },
    identity,
    noise::Config as NoiseConfig,
    swarm::{Config as SwarmConfig, Swarm, SwarmEvent},
    tcp::{tokio::Transport as TcpTransport, Config as TcpConfig},
    websocket,
    yamux::Config as YamuxConfig,
    Multiaddr, PeerId,
};
use libp2p_tokio_socks5::{Socks5Config, Socks5Transport};
use rand::thread_rng;
use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    time::{Duration, Instant},
};
use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System,
};
use tokio::io::{self, AsyncBufReadExt};
use tokio::time;
use tracing::{debug, error, info, warn};

const KIND_DATA: u8 = 1;
const KIND_ACK: u8 = 2;

const DEFAULT_COUNTS: &[usize] = &[1000];
const PAYLOAD_SIZES: &[usize] = &[32, 1024, 4096];

const IN_FLIGHT: usize = 1000;

const RUN_TIMEOUT: Duration = Duration::from_secs(120);
const DIAL_READY_TIMEOUT: Duration = Duration::from_secs(20);

const MAX_SEEN_IDS: usize = 1_000_000;
const MAX_RTT_SAMPLES: usize = 200_000;

const GOSSIPSUB_MAX_TRANSMIT_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Receiver,
    Sender,
}

fn parse_role(s: &str) -> Option<Role> {
    match s.trim().to_lowercase().as_str() {
        "recv" | "receiver" | "server" | "peer2" | "2" => Some(Role::Receiver),
        "send" | "sender" | "client" | "peer1" | "1" => Some(Role::Sender),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Stack {
    Tcp,
    Quic,
    WebSocket,
    WebRtcUdp,
    Tor,
    All,
}

fn parse_stack(s: &str) -> Option<Stack> {
    match s.trim().to_lowercase().as_str() {
        "tcp" => Some(Stack::Tcp),
        "quic" => Some(Stack::Quic),
        "ws" | "websocket" | "http" | "http2" => Some(Stack::WebSocket),
        "udp" | "webrtc" | "webrtc-udp" => Some(Stack::WebRtcUdp),
        "tor" => Some(Stack::Tor),
        "all" => Some(Stack::All),
        _ => None,
    }
}

fn stack_name(s: Stack) -> &'static str {
    match s {
        Stack::Tcp => "tcp",
        Stack::Quic => "quic",
        Stack::WebSocket => "ws",
        Stack::WebRtcUdp => "udp",
        Stack::Tor => "tor",
        Stack::All => "all",
    }
}

fn port_for_stack(base: u16, stack: Stack) -> u16 {
    match stack {
        Stack::Tcp | Stack::Tor => base,
        Stack::WebSocket => base.saturating_add(1),
        Stack::Quic => base.saturating_add(2),
        Stack::WebRtcUdp => base.saturating_add(3),
        Stack::All => base,
    }
}

#[derive(Clone)]
struct Metrics {
    outgoing_bytes: u64,
    incoming_bytes: u64,

    payload_bytes_sent: u64,
    payload_bytes_delivered: u64,

    data_sent: u64,
    data_delivered: u64,

    publish_failed: u64,

    pending: HashMap<u64, (Instant, usize)>,
    rtt_us: Vec<u64>,
    rtt_seen: u64,

    jitter_us: f64,
    prev_rtt_us: Option<u64>,

    next_id: u64,

    duplicates: u64,
    seen_data_ids: HashSet<(PeerId, u64)>,
}

impl Metrics {
    fn new() -> Self {
        Self {
            outgoing_bytes: 0,
            incoming_bytes: 0,

            payload_bytes_sent: 0,
            payload_bytes_delivered: 0,

            data_sent: 0,
            data_delivered: 0,

            publish_failed: 0,

            pending: HashMap::new(),
            rtt_us: Vec::new(),
            rtt_seen: 0,

            jitter_us: 0.0,
            prev_rtt_us: None,

            next_id: 1,

            duplicates: 0,
            seen_data_ids: HashSet::new(),
        }
    }

    fn reset_run(&mut self) {
        self.outgoing_bytes = 0;
        self.incoming_bytes = 0;

        self.payload_bytes_sent = 0;
        self.payload_bytes_delivered = 0;

        self.data_sent = 0;
        self.data_delivered = 0;

        self.publish_failed = 0;

        self.pending.clear();
        self.rtt_us.clear();
        self.rtt_seen = 0;

        self.jitter_us = 0.0;
        self.prev_rtt_us = None;

        self.duplicates = 0;
        self.seen_data_ids.clear();
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn note_outgoing(&mut self, bytes: usize) {
        self.outgoing_bytes = self.outgoing_bytes.saturating_add(bytes as u64);
    }

    fn note_incoming(&mut self, bytes: usize) {
        self.incoming_bytes = self.incoming_bytes.saturating_add(bytes as u64);
    }

    fn note_data_send(&mut self, id: u64, full_msg_bytes: usize, payload_bytes: usize) {
        self.data_sent = self.data_sent.saturating_add(1);
        self.note_outgoing(full_msg_bytes);
        self.payload_bytes_sent = self.payload_bytes_sent.saturating_add(payload_bytes as u64);
        self.pending.insert(id, (Instant::now(), payload_bytes));
    }

    fn note_publish_failed(&mut self) {
        self.publish_failed = self.publish_failed.saturating_add(1);
    }

    fn note_ack_send(&mut self, bytes: usize) {
        self.note_outgoing(bytes);
    }

    fn note_ack_received(&mut self, id: u64) {
        if let Some((sent_at, payload_bytes)) = self.pending.remove(&id) {
            let us = sent_at.elapsed().as_micros() as u64;

            if let Some(prev) = self.prev_rtt_us {
                let d = if us >= prev { us - prev } else { prev - us };
                self.jitter_us += (d as f64 - self.jitter_us) / 16.0;
            }
            self.prev_rtt_us = Some(us);

            self.rtt_seen = self.rtt_seen.saturating_add(1);
            if self.rtt_us.len() < MAX_RTT_SAMPLES {
                self.rtt_us.push(us);
            } else {
                let j = rand::random::<u64>() % self.rtt_seen.max(1);
                if (j as usize) < MAX_RTT_SAMPLES {
                    self.rtt_us[j as usize] = us;
                }
            }

            self.data_delivered = self.data_delivered.saturating_add(1);
            self.payload_bytes_delivered =
                self.payload_bytes_delivered.saturating_add(payload_bytes as u64);
        }
    }

    fn note_payload_delivered_receiver_side(&mut self, payload_bytes: usize) {
        self.payload_bytes_delivered =
            self.payload_bytes_delivered.saturating_add(payload_bytes as u64);
    }

    fn delivery_percent(&self) -> f64 {
        if self.data_sent == 0 {
            0.0
        } else {
            (self.data_delivered as f64 / self.data_sent as f64) * 100.0
        }
    }

    fn median_rtt_us(&self) -> Option<u64> {
        percentile_us(&self.rtt_us, 50.0)
    }

    fn p95_rtt_us(&self) -> Option<u64> {
        percentile_us(&self.rtt_us, 95.0)
    }

    fn p99_rtt_us(&self) -> Option<u64> {
        percentile_us(&self.rtt_us, 99.0)
    }

    fn overhead_ratio(&self) -> f64 {
        let good = self.payload_bytes_delivered.max(1) as f64;
        (self.outgoing_bytes as f64) / good
    }

    fn goodput_mbps(&self, elapsed: Duration) -> f64 {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        let bits = (self.payload_bytes_delivered as f64) * 8.0;
        (bits / secs) / 1_000_000.0
    }
}

fn percentile_us(v: &[u64], p: f64) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_unstable();
    let n = s.len();
    let idx = ((p / 100.0) * (n.saturating_sub(1) as f64)).round() as usize;
    Some(s[idx.min(n - 1)])
}

enum ParsedMsg<'a> {
    Data { id: u64, sender: PeerId, payload: &'a [u8] },
    Ack { id: u64, target: PeerId },
}

fn encode_data(id: u64, sender: &PeerId, payload: &[u8]) -> Vec<u8> {
    let sender_bytes = sender.to_bytes();
    let mut v = Vec::with_capacity(1 + 8 + 1 + sender_bytes.len() + payload.len());
    v.push(KIND_DATA);
    v.extend_from_slice(&id.to_be_bytes());
    v.push(sender_bytes.len() as u8);
    v.extend_from_slice(&sender_bytes);
    v.extend_from_slice(payload);
    v
}

fn encode_ack(id: u64, target: &PeerId) -> Vec<u8> {
    let target_bytes = target.to_bytes();
    let mut v = Vec::with_capacity(1 + 8 + 1 + target_bytes.len());
    v.push(KIND_ACK);
    v.extend_from_slice(&id.to_be_bytes());
    v.push(target_bytes.len() as u8);
    v.extend_from_slice(&target_bytes);
    v
}

fn decode_msg(bytes: &[u8]) -> Option<ParsedMsg<'_>> {
    if bytes.len() < 1 + 8 + 1 {
        return None;
    }
    let kind = bytes[0];

    let mut id_arr = [0u8; 8];
    id_arr.copy_from_slice(&bytes[1..9]);
    let id = u64::from_be_bytes(id_arr);

    let len = bytes[9] as usize;
    if bytes.len() < 10 + len {
        return None;
    }

    let peer_bytes = &bytes[10..10 + len];
    let peer = PeerId::from_bytes(peer_bytes).ok()?;

    match kind {
        KIND_DATA => {
            let payload = &bytes[10 + len..];
            Some(ParsedMsg::Data { id, sender: peer, payload })
        }
        KIND_ACK => Some(ParsedMsg::Ack { id, target: peer }),
        _ => None,
    }
}

fn make_message_id(data: &[u8]) -> MessageId {
    if let Some(pm) = decode_msg(data) {
        match pm {
            ParsedMsg::Data { id, sender, .. } => MessageId::from(format!("d:{}:{}", id, sender)),
            ParsedMsg::Ack { id, target } => MessageId::from(format!("a:{}:{}", id, target)),
        }
    } else {
        let mut h = DefaultHasher::new();
        data.hash(&mut h);
        MessageId::from(format!("raw:{:x}", h.finish()))
    }
}

fn make_gossipsub(
    id_keys: &identity::Keypair,
) -> Result<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>> {
    let cfg = GossipsubConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        .allow_self_origin(false)
        .flood_publish(true)
        .max_transmit_size(GOSSIPSUB_MAX_TRANSMIT_SIZE)
        .message_id_fn(|m| make_message_id(&m.data))
        .build()?;

    GossipBehaviour::<IdentityTransform, AllowAllSubscriptionFilter>::new(
        MessageAuthenticity::Signed(id_keys.clone()),
        cfg,
    )
    .map_err(|e| anyhow!(e))
}

fn build_transport_single(
    stack: Stack,
    id_keys: &identity::Keypair,
    onion_map: HashMap<Multiaddr, SocketAddr>,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
    match stack {
        Stack::Tcp => {
            let tcp = TcpTransport::new(TcpConfig::default());
            let noise = NoiseConfig::new(id_keys)?;
            Ok(tcp
                .upgrade(Version::V1)
                .authenticate(noise)
                .multiplex(YamuxConfig::default())
                .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
                .boxed())
        }

        Stack::WebSocket => {
            let tcp = TcpTransport::new(TcpConfig::default());
            let ws = websocket::Config::new(tcp);
            let noise = NoiseConfig::new(id_keys)?;
            Ok(ws
                .upgrade(Version::V1)
                .authenticate(noise)
                .multiplex(YamuxConfig::default())
                .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
                .boxed())
        }

        Stack::Quic => {
            let quic_cfg = libp2p::quic::Config::new(id_keys);
            let quic_transport = libp2p::quic::tokio::Transport::new(quic_cfg);
            Ok(quic_transport
                .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
                .boxed())
        }

        Stack::WebRtcUdp => {
            use libp2p_webrtc::tokio::{Certificate, Transport as WebRtcTransport};
            let cert = Certificate::generate(&mut thread_rng())?;
            let webrtc = WebRtcTransport::new(id_keys.clone(), cert);
            Ok(webrtc
                .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
                .boxed())
        }

        Stack::Tor => {
            let tcp = TcpTransport::new(TcpConfig::default());
            let socks_cfg = Socks5Config::default();
            let socks = Socks5Transport::new(socks_cfg, onion_map);
            let combined = tcp.or_transport(socks);

            let noise = NoiseConfig::new(id_keys)?;
            Ok(combined
                .upgrade(Version::V1)
                .authenticate(noise)
                .multiplex(YamuxConfig::default())
                .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
                .boxed())
        }

        Stack::All => Err(anyhow!("use build_transport_all()")),
    }
}

fn build_transport_all(id_keys: &identity::Keypair) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
    let tcp = build_transport_single(Stack::Tcp, id_keys, HashMap::new())?;
    let ws = build_transport_single(Stack::WebSocket, id_keys, HashMap::new())?;
    let quic = build_transport_single(Stack::Quic, id_keys, HashMap::new())?;
    let udp = build_transport_single(Stack::WebRtcUdp, id_keys, HashMap::new())?;

    let t = tcp.or_transport(ws).map(|either, _| either.into_inner());
    let t = t.or_transport(quic).map(|either, _| either.into_inner());
    let t = t.or_transport(udp).map(|either, _| either.into_inner());

    Ok(t.boxed())
}

fn listen_multiaddr(stack: Stack, base_port: u16) -> Result<Multiaddr> {
    let port = port_for_stack(base_port, stack);
    Ok(match stack {
        Stack::Tcp | Stack::Tor => format!("/ip4/0.0.0.0/tcp/{}", port).parse()?,
        Stack::WebSocket => format!("/ip4/0.0.0.0/tcp/{}/ws", port).parse()?,
        Stack::Quic => format!("/ip4/0.0.0.0/udp/{}/quic-v1", port).parse()?,
        Stack::WebRtcUdp => format!("/ip4/0.0.0.0/udp/{}/webrtc-direct", port).parse()?,
        Stack::All => return Err(anyhow!("use multiple listen_on for Stack::All")),
    })
}

fn dial_addr_for_stack(
    stack: Stack,
    ip: IpAddr,
    base_port: u16,
    peer: PeerId,
    webrtc_full: Option<Multiaddr>,
) -> Result<Multiaddr> {
    let port = port_for_stack(base_port, stack);

    let s = match stack {
        Stack::Tcp => format!("/ip4/{}/tcp/{}/p2p/{}", ip, port, peer),
        Stack::WebSocket => format!("/ip4/{}/tcp/{}/ws/p2p/{}", ip, port, peer),
        Stack::Quic => format!("/ip4/{}/udp/{}/quic-v1/p2p/{}", ip, port, peer),
        Stack::WebRtcUdp => {
            if let Some(ma) = webrtc_full {
                return Ok(ma);
            }
            return Err(anyhow!(
                "Для udp/webrtc нужен полный multiaddr с /certhash/.../p2p/... (скопируй из Peer2 логов)"
            ));
        }
        Stack::Tor => return Err(anyhow!("Tor dial requires onion multiaddr (пока не автоматизировали)")),
        Stack::All => return Err(anyhow!("use per-stack dial in all mode")),
    };

    Ok(s.parse()?)
}

#[derive(Default, Clone)]
struct ResourceStats {
    cpu_avg: f32,
    cpu_max: f32,
    mem_avg_mb: f64,
    mem_max_mb: f64,
}

struct ResourceMeter {
    sys: System,
    cpu_samples: Vec<f32>,
    mem_samples_kb: Vec<u64>,
}

impl ResourceMeter {
    fn new() -> Self {
        let refresh = RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything())
            .with_processes(ProcessRefreshKind::nothing().with_cpu().with_memory());

        let mut sys = System::new_with_specifics(refresh);
        sys.refresh_processes(ProcessesToUpdate::All, false);

        Self { sys, cpu_samples: Vec::new(), mem_samples_kb: Vec::new() }
    }

    fn sample(&mut self) {
        self.sys.refresh_processes(ProcessesToUpdate::All, false);
        if let Some(p) = self.sys.process(sysinfo::Pid::from_u32(std::process::id())) {
            self.cpu_samples.push(p.cpu_usage());
            self.mem_samples_kb.push(p.memory());
        }
    }

    fn summarize(&self) -> ResourceStats {
        let mut out = ResourceStats::default();

        if !self.cpu_samples.is_empty() {
            let sum: f32 = self.cpu_samples.iter().sum();
            out.cpu_avg = sum / (self.cpu_samples.len() as f32);
            out.cpu_max = self.cpu_samples.iter().cloned().fold(0.0, f32::max);
        }

        if !self.mem_samples_kb.is_empty() {
            let sum: u64 = self.mem_samples_kb.iter().sum();
            let avg_kb = sum as f64 / (self.mem_samples_kb.len() as f64);
            let max_kb = *self.mem_samples_kb.iter().max().unwrap_or(&0) as f64;
            out.mem_avg_mb = avg_kb / 1024.0;
            out.mem_max_mb = max_kb / 1024.0;
        }

        out
    }
}

#[derive(Clone)]
struct BenchRow {
    stack: Stack,
    payload: usize,

    requested: usize,
    sent: u64,
    delivered: u64,
    publish_failed: u64,

    dial_ms: u128,

    delivery_percent: f64,
    median_us: Option<u64>,
    p95_us: Option<u64>,
    p99_us: Option<u64>,
    jitter_us: f64,
    goodput_mbps: f64,
    overhead: f64,
    cpu_avg: f32,
    mem_avg: f64,
}

fn print_table(rows: &[BenchRow]) {
    println!();
    println!("-------------------------------------------------------------------------------------------------------------------------------------------------------------------");
    println!(
        "{:>6} | {:>7} | {:>8} | {:>7} | {:>7} | {:>7} | {:>7} | {:>8} | {:>9} | {:>9} | {:>9} | {:>8} | {:>9} | {:>9} | {:>7} | {:>7}",
        "stack", "payload", "req", "sent", "deliv", "fail", "dialms",
        "deliv%", "medianus", "p95us", "p99us", "jitter", "goodput", "overhead", "cpu", "mem"
    );
    println!("-------------------------------------------------------------------------------------------------------------------------------------------------------------------");

    for r in rows {
        println!(
            "{:>6} | {:>7} | {:>8} | {:>7} | {:>7} | {:>7} | {:>7} | {:>7.2}% | {:>9} | {:>9} | {:>9} | {:>7.1} | {:>8.3} | {:>8.3} | {:>6.2} | {:>6.2}",
            stack_name(r.stack),
            r.payload,
            r.requested,
            r.sent,
            r.delivered,
            r.publish_failed,
            r.dial_ms,
            r.delivery_percent,
            r.median_us.map(|x| x.to_string()).unwrap_or_else(|| "n/a".into()),
            r.p95_us.map(|x| x.to_string()).unwrap_or_else(|| "n/a".into()),
            r.p99_us.map(|x| x.to_string()).unwrap_or_else(|| "n/a".into()),
            r.jitter_us,
            r.goodput_mbps,
            r.overhead,
            r.cpu_avg,
            r.mem_avg,
        );
    }

    println!("-------------------------------------------------------------------------------------------------------------------------------------------------------------------");
    println!();
}

async fn handle_message(
    swarm: &mut Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: &IdentTopic,
    local_peer: PeerId,
    metrics: &mut Metrics,
    msg: &libp2p::gossipsub::Message,
) {
    metrics.note_incoming(msg.data.len());

    if let Some(parsed) = decode_msg(&msg.data) {
        match parsed {
            ParsedMsg::Data { id, sender, payload } => {
                if sender == local_peer {
                    return;
                }
                let key = (sender, id);

                let first_seen = if metrics.seen_data_ids.len() < MAX_SEEN_IDS {
                    metrics.seen_data_ids.insert(key)
                } else {
                    true
                };

                if !first_seen {
                    metrics.duplicates = metrics.duplicates.saturating_add(1);
                    tracing::debug!(%sender, id, "duplicate DATA -> drop (no ACK)");
                    return;
                }

                metrics.note_payload_delivered_receiver_side(payload.len());

                let ack = encode_ack(id, &sender);
                match swarm.behaviour_mut().publish(topic.clone(), ack.clone()) {
                    Ok(_) => {
                        metrics.note_ack_send(ack.len());
                    }
                    Err(PublishError::Duplicate) => {}
                    Err(e) => {
                        warn!(?e, ack_len = ack.len(), id, "receiver publish ACK failed");
                    }
                }
            }
            ParsedMsg::Ack { id, target } => {
                if target == local_peer {
                    metrics.note_ack_received(id);
                }
            }
        }
    }
}

async fn dial_wait_ready(
    swarm: &mut Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>,
    remote_addr: Multiaddr,
    remote_peer: PeerId,
    topic_hash: TopicHash,
    timeout: Duration,
    ) -> Result<Duration> {
    let t0 = Instant::now();

    swarm.behaviour_mut().add_explicit_peer(&remote_peer);

    if let Err(e) = swarm.dial(remote_addr) {
        warn!(?e, "dial warning");
    }

    let deadline = Instant::now() + timeout;
    let mut connected = false;
    let mut subscribed = false;

    loop {
        if connected && subscribed {
            return Ok(t0.elapsed());
        }

        if Instant::now() > deadline {
            return Err(anyhow!(
                "dial-ready timeout: connected={} subscribed={}",
                connected,
                subscribed
            ));
        }

        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == remote_peer => {
                connected = true;
                debug!(%peer_id, "dial-ready: ConnectionEstablished");
            }
            SwarmEvent::Behaviour(Event::Subscribed { peer_id, topic }) => {
                if peer_id == remote_peer && topic == topic_hash {
                    subscribed = true;
                    debug!(%peer_id, "dial-ready: Subscribed");
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                warn!(?peer_id, ?error, "outgoing connection error");
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                warn!(?error, "incoming connection error");
            }
            _ => {}
        }
    }
}

async fn run_bench_windowed(
    swarm: &mut Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: &IdentTopic,
    local_peer: PeerId,
    requested: usize,
    payload_size: usize,
    metrics: &mut Metrics,
) -> Result<(Duration, ResourceStats)> {
    metrics.reset_run();

    let payload = vec![b'x'; payload_size];
    let started = Instant::now();

    let mut sent_total: usize = 0;

    let mut meter = ResourceMeter::new();
    let mut tick = time::interval(Duration::from_secs(1));

    let mut warned_no_peers = false;

    loop {
        let mut burst = 0usize;

        while sent_total < requested && metrics.pending.len() < IN_FLIGHT && burst < 64 {
            if started.elapsed() > RUN_TIMEOUT {
                break;
            }

            let id = metrics.alloc_id();
            let msg = encode_data(id, &local_peer, &payload);

            match swarm.behaviour_mut().publish(topic.clone(), msg.clone()) {
                Ok(_) => {
                    metrics.note_data_send(id, msg.len(), payload.len());
                    sent_total += 1;
                    burst += 1;
                }
                Err(PublishError::NoPeersSubscribedToTopic) => {
                    metrics.note_publish_failed();
                    if !warned_no_peers {
                        warned_no_peers = true;
                        warn!("publish -> NoPeersSubscribedToTopic");
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(PublishError::Duplicate) => {
                    metrics.note_publish_failed();
                }
                Err(e) => {
                    metrics.note_publish_failed();
                    warn!(?e, payload = payload.len(), msg_len = msg.len(), "publish failed");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }

            tokio::task::yield_now().await;
        }

        if sent_total == requested && metrics.pending.is_empty() {
            break;
        }

        if started.elapsed() > RUN_TIMEOUT {
            warn!(
                requested,
                sent_total,
                data_sent = metrics.data_sent,
                delivered = metrics.data_delivered,
                pending = metrics.pending.len(),
                "RUN_TIMEOUT hit"
            );
            break;
        }

        tokio::select! {
            _ = tick.tick() => {
                meter.sample();
                debug!(
                    sent_total,
                    pending = metrics.pending.len(),
                    delivered = metrics.data_delivered,
                    failed = metrics.publish_failed,
                    "tick"
                );
            }
            ev = swarm.select_next_some() => {
                match ev {
                    SwarmEvent::Behaviour(Event::Message { message, .. }) => {
                        handle_message(swarm, topic, local_peer, metrics, &message).await;
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        debug!(%peer_id, ?endpoint, "bench: connection established");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        debug!(%peer_id, ?cause, "bench: connection closed");
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        warn!(?peer_id, ?error, "outgoing connection error");
                    }
                    SwarmEvent::IncomingConnectionError { error, .. } => {
                        warn!(?error, "incoming connection error");
                    }
                    _ => {}
                }
            }
        }
    }

    Ok((started.elapsed(), meter.summarize()))
}

async fn receiver_loop(
    mut swarm: Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: IdentTopic,
    local_peer: PeerId,
) -> Result<()> {
    info!("=== Peer2 / Receiver ===");
    info!(peer = %local_peer, "started");

    let mut metrics = Metrics::new();

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "listening");
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                info!(%peer_id, ?endpoint, "connection established");
                swarm.behaviour_mut().add_explicit_peer(&peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                warn!(%peer_id, ?cause, "connection closed");
                swarm.behaviour_mut().remove_explicit_peer(&peer_id);
            }
            SwarmEvent::Behaviour(Event::Subscribed { peer_id, topic }) => {
                info!(%peer_id, ?topic, "peer subscribed");
            }
            SwarmEvent::Behaviour(Event::Unsubscribed { peer_id, topic }) => {
                info!(%peer_id, ?topic, "peer unsubscribed");
            }
            SwarmEvent::Behaviour(Event::Message { message, .. }) => {
                handle_message(&mut swarm, &topic, local_peer, &mut metrics, &message).await;
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                warn!(?peer_id, ?error, "outgoing connection error");
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                warn!(?error, "incoming connection error");
            }
            _ => {}
        }
    }
}

async fn sender_run_stack(
    mut swarm: Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: IdentTopic,
    local_peer: PeerId,
    remote_peer: PeerId,
    dial_addr: Multiaddr,
    stack: Stack,
) -> Result<Vec<BenchRow>> {
    println!("Dial {} ...", dial_addr);

    let dial_time = dial_wait_ready(
        &mut swarm,
        dial_addr,
        remote_peer,
        topic.hash(),
        DIAL_READY_TIMEOUT,
    )
    .await?;

    println!("Connected + Subscribed. dial_ms={}", dial_time.as_millis());

    tokio::time::sleep(Duration::from_millis(1000)).await;

    let mut rows = Vec::new();
    let mut metrics = Metrics::new();

    for &payload_size in PAYLOAD_SIZES {
        println!("--- payload={} bytes ---", payload_size);

        for &requested in DEFAULT_COUNTS {
            let (elapsed, rs) =
                run_bench_windowed(&mut swarm, &topic, local_peer, requested, payload_size, &mut metrics)
                    .await?;

            let sent = metrics.data_sent;
            let delivered = metrics.data_delivered;
            let deliv_pct = metrics.delivery_percent();

            rows.push(BenchRow {
                stack,
                payload: payload_size,

                requested,
                sent,
                delivered,
                publish_failed: metrics.publish_failed,

                dial_ms: dial_time.as_millis(),

                delivery_percent: deliv_pct,
                median_us: metrics.median_rtt_us(),
                p95_us: metrics.p95_rtt_us(),
                p99_us: metrics.p99_rtt_us(),
                jitter_us: metrics.jitter_us,
                goodput_mbps: metrics.goodput_mbps(elapsed),
                overhead: metrics.overhead_ratio(),
                cpu_avg: rs.cpu_avg,
                mem_avg: rs.mem_avg_mb,
            });

            println!(
                "[{}] payload={}B req={} sent={} deliv={} ({:.2}%) fail={} pending={} median={:?}us p95={:?}us p99={:?}us goodput={:.3} Mbps overhead={:.3}",
                stack_name(stack),
                payload_size,
                requested,
                sent,
                delivered,
                deliv_pct,
                metrics.publish_failed,
                metrics.pending.len(),
                metrics.median_rtt_us(),
                metrics.p95_rtt_us(),
                metrics.p99_rtt_us(),
                metrics.goodput_mbps(elapsed),
                metrics.overhead_ratio(),
            );
        }
    }

    Ok(rows)
}

async fn sender_all_mode(
    remote_peer: PeerId,
    ip: IpAddr,
    base_port: u16,
    webrtc_full: Option<Multiaddr>,
) -> Result<()> {
    let order = [Stack::Tcp, Stack::WebSocket, Stack::Quic, Stack::WebRtcUdp];

    let mut all_rows = Vec::new();

    for st in order {
        if st == Stack::WebRtcUdp && webrtc_full.is_none() {
            println!("[udp] нет полного webrtc multiaddr с /certhash/... → пропуск");
            continue;
        }

        println!(
            "\n==================== RUN {} (port={}) ====================",
            stack_name(st),
            port_for_stack(base_port, st)
        );

        let id_keys = identity::Keypair::generate_ed25519();
        let local_peer = PeerId::from(id_keys.public());

        let transport = build_transport_single(st, &id_keys, HashMap::new())?;
        let behaviour = make_gossipsub(&id_keys)?;
        let swarm_config = SwarmConfig::with_tokio_executor();
        let mut swarm = Swarm::new(transport, behaviour, local_peer, swarm_config);

        if st == Stack::WebRtcUdp {
            swarm.listen_on("/ip4/0.0.0.0/udp/0/webrtc-direct".parse()?)?;
        }

        let topic = IdentTopic::new("forum/autos/board/general");
        swarm.behaviour_mut().subscribe(&topic)?;

        let dial_addr = dial_addr_for_stack(st, ip, base_port, remote_peer, webrtc_full.clone())?;
        let rows = sender_run_stack(swarm, topic, local_peer, remote_peer, dial_addr, st).await?;

        print_table(&rows);
        all_rows.extend(rows);
    }

    println!("=== SUMMARY ===");
    print_table(&all_rows);

    Ok(())
}

async fn sender_single_mode(
    transport: Boxed<(PeerId, StreamMuxerBox)>,
    id_keys: &identity::Keypair,
    local_peer: PeerId,
    remote_peer: PeerId,
    ip: IpAddr,
    base_port: u16,
    stack: Stack,
    webrtc_full: Option<Multiaddr>,
) -> Result<()> {
    let behaviour = make_gossipsub(id_keys)?;
    let swarm_config = SwarmConfig::with_tokio_executor();
    let mut swarm = Swarm::new(transport, behaviour, local_peer, swarm_config);

    if stack == Stack::WebRtcUdp {
        swarm.listen_on("/ip4/0.0.0.0/udp/0/webrtc-direct".parse()?)?;
    }

    let topic = IdentTopic::new("forum/autos/board/general");
    swarm.behaviour_mut().subscribe(&topic)?;

    let dial_addr = dial_addr_for_stack(stack, ip, base_port, remote_peer, webrtc_full)?;
    let rows = sender_run_stack(swarm, topic, local_peer, remote_peer, dial_addr, stack).await?;

    print_table(&rows);
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(true).compact().init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let mut stdin = io::BufReader::new(io::stdin()).lines();

    println!("role: receiver(peer2) | sender(peer1)");
    let role_in = read_line(&mut stdin).await?;
    let role = parse_role(&role_in).unwrap_or(Role::Receiver);

    println!("stack: tcp | quic | ws | udp | tor | all");
    let stack_in = read_line(&mut stdin).await?;
    let stack = parse_stack(&stack_in).unwrap_or(Stack::Tcp);

    println!("port (base, default 9000):");
    let port_in = read_line(&mut stdin).await?;
    let base_port: u16 = if port_in.trim().is_empty() {
        9000
    } else {
        port_in.trim().parse().unwrap_or(9000)
    };

    let mut onion_map: HashMap<Multiaddr, SocketAddr> = HashMap::new();
    if stack == Stack::Tor && role == Role::Receiver {
        println!("onion multiaddr (пример: /onion3/...:443):");
        let onion_in = read_line(&mut stdin).await?;
        if !onion_in.trim().is_empty() {
            let onion: Multiaddr = onion_in.trim().parse()?;
            let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, base_port));
            onion_map.insert(onion, local);
        }
    }

    let id_keys = identity::Keypair::generate_ed25519();
    let local_peer = PeerId::from(id_keys.public());

    match role {
        Role::Receiver => {
            let transport = match stack {
                Stack::All => build_transport_all(&id_keys)?,
                _ => build_transport_single(stack, &id_keys, onion_map)?,
            };

            let behaviour = make_gossipsub(&id_keys)?;
            let swarm_config = SwarmConfig::with_tokio_executor();
            let mut swarm = Swarm::new(transport, behaviour, local_peer, swarm_config);

            let topic = IdentTopic::new("forum/autos/board/general");
            swarm.behaviour_mut().subscribe(&topic)?;

            match stack {
                Stack::All => {
                    for st in [Stack::Tcp, Stack::WebSocket, Stack::Quic, Stack::WebRtcUdp] {
                        let la = listen_multiaddr(st, base_port)?;
                        swarm.listen_on(la)?;
                    }
                }
                _ => {
                    let la = listen_multiaddr(stack, base_port)?;
                    swarm.listen_on(la)?;
                }
            }

            receiver_loop(swarm, topic, local_peer).await
        }

        Role::Sender => {
            println!("remote peerId:");
            let peer_in = read_line(&mut stdin).await?;
            let remote_peer = PeerId::from_str(peer_in.trim())?;

            println!("remote ip (например 45.148.103.19):");
            let ip_in = read_line(&mut stdin).await?;
            let ip: IpAddr = ip_in.trim().parse()?;

            let mut webrtc_full: Option<Multiaddr> = None;
            if stack == Stack::WebRtcUdp || stack == Stack::All {
                println!("webrtc full multiaddr (/certhash/.../p2p/...) (если нет — пусто):");
                let w = read_line(&mut stdin).await?;
                if !w.trim().is_empty() {
                    webrtc_full = Some(w.trim().parse()?);
                }
            }

            println!("\n=== Peer1 / Sender ===");
            println!("Local PeerId: {}", local_peer);
            println!("Remote PeerId: {}", remote_peer);
            println!("stack = {:?}", stack);
            println!("base_port = {}", base_port);
            println!(
                "ports: tcp={} ws={} quic={} udp={}",
                port_for_stack(base_port, Stack::Tcp),
                port_for_stack(base_port, Stack::WebSocket),
                port_for_stack(base_port, Stack::Quic),
                port_for_stack(base_port, Stack::WebRtcUdp),
            );
            println!(
                "window(IN_FLIGHT) = {} | payloads={:?} | counts={:?}",
                IN_FLIGHT, PAYLOAD_SIZES, DEFAULT_COUNTS
            );
            println!("gossipsub.max_transmit_size = {} bytes\n", GOSSIPSUB_MAX_TRANSMIT_SIZE);

            if stack == Stack::All {
                return sender_all_mode(remote_peer, ip, base_port, webrtc_full).await;
            }

            let transport = build_transport_single(stack, &id_keys, HashMap::new())?;
            sender_single_mode(
                transport,
                &id_keys,
                local_peer,
                remote_peer,
                ip,
                base_port,
                stack,
                webrtc_full,
            )
            .await
        }
    }
}

async fn read_line(lines: &mut io::Lines<io::BufReader<tokio::io::Stdin>>) -> Result<String> {
    Ok(lines.next_line().await?.unwrap_or_default())
}
