use anyhow::{anyhow, Result};
use futures::StreamExt;
use libp2p::{
    core::{
        muxing::StreamMuxerBox,
        transport::{upgrade::Version, Boxed, Transport},
    },
    gossipsub::{
        AllowAllSubscriptionFilter, Behaviour as GossipBehaviour,
        ConfigBuilder as GossipsubConfigBuilder, Event, IdentTopic, IdentityTransform,
        MessageAuthenticity, ValidationMode,
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
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    time::{Duration, Instant},
};
use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System,
};
use tokio::io::{self, AsyncBufReadExt};
use tokio::time;
use tracing::info;
use tracing_subscriber::EnvFilter;

const KIND_DATA: u8 = 1;
const KIND_ACK: u8 = 2;

const DEFAULT_COUNTS: &[usize] = &[
    1, 10, 100, 1000, 10_000, 100_000, 1_000_000, 10_000_000,
];

const PAYLOAD_SIZE: usize = 32;

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

/// ✅ ВАЖНО: чтобы в all не было "Address in use"
/// tcp и ws оба используют TCP listener, поэтому им нужны разные порты.
/// quic/udp тоже вынесем на отдельные порты для чистоты эксперимента.
fn port_for(stack: Stack, base: u16) -> u16 {
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

    pending: HashMap<u64, Instant>,
    rtt_us: Vec<u64>,

    jitter_us: f64,
    prev_rtt_us: Option<u64>,

    next_id: u64,

    duplicates: u64,
    seen_data_ids: HashSet<u64>,
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

            pending: HashMap::new(),
            rtt_us: Vec::new(),

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

        self.pending.clear();
        self.rtt_us.clear();

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
        self.pending.insert(id, Instant::now());
    }

    fn note_ack_send(&mut self, bytes: usize) {
        self.note_outgoing(bytes);
    }

    fn note_ack_received(&mut self, id: u64) {
        if let Some(sent_at) = self.pending.remove(&id) {
            let us = sent_at.elapsed().as_micros() as u64;

            if let Some(prev) = self.prev_rtt_us {
                let d = if us >= prev { us - prev } else { prev - us };
                self.jitter_us += (d as f64 - self.jitter_us) / 16.0;
            }
            self.prev_rtt_us = Some(us);

            self.rtt_us.push(us);
            self.data_delivered = self.data_delivered.saturating_add(1);
        }
    }

    fn note_payload_delivered(&mut self, payload_bytes: usize) {
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
    Data {
        id: u64,
        sender: PeerId,
        payload: &'a [u8],
    },
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
            Some(ParsedMsg::Data {
                id,
                sender: peer,
                payload,
            })
        }
        KIND_ACK => Some(ParsedMsg::Ack { id, target: peer }),
        _ => None,
    }
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
    let quic = build_transport_single(Stack::Quic, id_keys, HashMap::new())?;
    let ws = build_transport_single(Stack::WebSocket, id_keys, HashMap::new())?;
    let udp = build_transport_single(Stack::WebRtcUdp, id_keys, HashMap::new())?;

    let t = tcp.or_transport(quic).map(|either, _| either.into_inner());
    let t = t.or_transport(ws).map(|either, _| either.into_inner());
    let t = t.or_transport(udp).map(|either, _| either.into_inner());

    Ok(t.boxed())
}

fn listen_multiaddr(stack: Stack, port: u16) -> Result<Multiaddr> {
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
    port: u16,
    peer: PeerId,
    webrtc_full: Option<Multiaddr>,
) -> Result<Multiaddr> {
    let s = match stack {
        Stack::Tcp => format!("/ip4/{}/tcp/{}/p2p/{}", ip, port, peer),
        Stack::WebSocket => format!("/ip4/{}/tcp/{}/ws/p2p/{}", ip, port, peer),
        Stack::Quic => format!("/ip4/{}/udp/{}/quic-v1/p2p/{}", ip, port, peer),
        Stack::WebRtcUdp => {
            if let Some(ma) = webrtc_full {
                return Ok(ma);
            }
            return Err(anyhow!(
                "Для udp/webrtc нужен полный multiaddr с /certhash/... (скопируй из Peer2 логов)"
            ));
        }
        Stack::Tor => return Err(anyhow!("Tor dial requires onion multiaddr")),
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

        Self {
            sys,
            cpu_samples: Vec::new(),
            mem_samples_kb: Vec::new(),
        }
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
    count: usize,
    delivery_percent: f64,
    median_us: Option<u64>,
    p95_us: Option<u64>,
    p99_us: Option<u64>,
    jitter_us: f64,
    outgoing_bytes: u64,
    incoming_bytes: u64,
    goodput_mbps: f64,
    overhead: f64,
    cpu_avg: f32,
    cpu_max: f32,
    mem_avg: f64,
    mem_max: f64,
}

fn print_table(rows: &[BenchRow]) {
    println!();
    println!("--------------------------------------------------------------------------------------------------------------");
    println!(
        "{:>6} | {:>10} | {:>8} | {:>9} | {:>9} | {:>9} | {:>8} | {:>10} | {:>10} | {:>9} | {:>9}",
        "stack", "count", "deliv%", "medianus", "p95us", "p99us", "jitter", "goodput", "overhead", "cpu_avg", "mem_avg"
    );
    println!("--------------------------------------------------------------------------------------------------------------");

    for r in rows {
        println!(
            "{:>6} | {:>10} | {:>7.2}% | {:>9} | {:>9} | {:>9} | {:>7.1} | {:>8.3} | {:>8.3} | {:>8.2} | {:>8.2}",
            stack_name(r.stack),
            r.count,
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

    println!("--------------------------------------------------------------------------------------------------------------");
    println!();
}

fn make_gossipsub(
    id_keys: &identity::Keypair,
) -> Result<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>> {
    let cfg = GossipsubConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        .build()?;

    GossipBehaviour::<IdentityTransform, AllowAllSubscriptionFilter>::new(
        MessageAuthenticity::Signed(id_keys.clone()),
        cfg,
    )
    .map_err(|e| anyhow!(e))
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

                if !metrics.seen_data_ids.insert(id) {
                    metrics.duplicates = metrics.duplicates.saturating_add(1);
                }

                metrics.note_payload_delivered(payload.len());

                let ack = encode_ack(id, &sender);
                if swarm.behaviour_mut().publish(topic.clone(), ack.clone()).is_ok() {
                    metrics.note_ack_send(ack.len());
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

async fn dial_wait_connected(
    swarm: &mut Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>,
    remote: Multiaddr,
    remote_peer: PeerId,
    timeout: Duration,
) -> Result<()> {
    swarm.dial(remote)?;

    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            return Err(anyhow!("dial timeout"));
        }

        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == remote_peer => {
                return Ok(())
            }
            _ => {}
        }
    }
}

async fn run_bench(
    swarm: &mut Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: &IdentTopic,
    local_peer: PeerId,
    count: usize,
    metrics: &mut Metrics,
) -> Result<(Duration, ResourceStats)> {
    metrics.reset_run();

    let payload = vec![b'x'; PAYLOAD_SIZE];

    for _ in 0..count {
        let id = metrics.alloc_id();
        let msg = encode_data(id, &local_peer, &payload);
        if swarm.behaviour_mut().publish(topic.clone(), msg.clone()).is_ok() {
            metrics.note_data_send(id, msg.len(), payload.len());
        }
    }

    let started = Instant::now();
    let timeout = Duration::from_secs(120);

    let mut meter = ResourceMeter::new();
    let mut tick = time::interval(Duration::from_secs(1));

    loop {
        if metrics.pending.is_empty() {
            break;
        }
        if started.elapsed() > timeout {
            break;
        }

        tokio::select! {
            _ = tick.tick() => {
                meter.sample();
            }
            ev = swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(Event::Message { message, .. }) = ev {
                    handle_message(swarm, topic, local_peer, metrics, &message).await;
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
    println!("=== Peer2 / Receiver ===");
    println!("PeerId: {}", local_peer);
    println!("Ждём DATA и отвечаем ACK автоматически.");
    println!("Для udp/webrtc копируй полный multiaddr с /certhash/... из Listening on");
    println!();

    let mut metrics = Metrics::new();

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("Listening on {}", address);
            }
            SwarmEvent::Behaviour(Event::Message { message, .. }) => {
                handle_message(&mut swarm, &topic, local_peer, &mut metrics, &message).await;
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                info!("ConnectionEstablished with {} via {:?}", peer_id, endpoint);
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                info!("ConnectionClosed with {} cause={:?}", peer_id, cause);
            }
            _ => {}
        }
    }
}

async fn sender_run_stack(
    swarm: &mut Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: &IdentTopic,
    local_peer: PeerId,
    remote_peer: PeerId,
    dial_addr: Multiaddr,
    stack: Stack,
) -> Result<Vec<BenchRow>> {
    println!("Dial {} ...", dial_addr);
    dial_wait_connected(swarm, dial_addr, remote_peer, Duration::from_secs(20)).await?;
    println!("Connected.");

    let mut rows = Vec::new();
    let mut metrics = Metrics::new();

    for &count in DEFAULT_COUNTS {
        let (elapsed, rs) = run_bench(swarm, topic, local_peer, count, &mut metrics).await?;

        rows.push(BenchRow {
            stack,
            count,
            delivery_percent: metrics.delivery_percent(),
            median_us: metrics.median_rtt_us(),
            p95_us: metrics.p95_rtt_us(),
            p99_us: metrics.p99_rtt_us(),
            jitter_us: metrics.jitter_us,
            outgoing_bytes: metrics.outgoing_bytes,
            incoming_bytes: metrics.incoming_bytes,
            goodput_mbps: metrics.goodput_mbps(elapsed),
            overhead: metrics.overhead_ratio(),
            cpu_avg: rs.cpu_avg,
            cpu_max: rs.cpu_max,
            mem_avg: rs.mem_avg_mb,
            mem_max: rs.mem_max_mb,
        });

        println!(
            "[{}] count={} delivery={:.2}% median={:?}us p95={:?}us p99={:?}us goodput={:.3} Mbps",
            stack_name(stack),
            count,
            metrics.delivery_percent(),
            metrics.median_rtt_us(),
            metrics.p95_rtt_us(),
            metrics.p99_rtt_us(),
            metrics.goodput_mbps(elapsed),
        );
    }

    Ok(rows)
}

async fn sender_loop(
    mut swarm: Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: IdentTopic,
    local_peer: PeerId,
    remote_peer: PeerId,
    ip: IpAddr,
    base_port: u16,
    stack: Stack,
    webrtc_full: Option<Multiaddr>,
) -> Result<()> {
    println!("=== Peer1 / Sender ===");
    println!("Local PeerId: {}", local_peer);
    println!("Remote PeerId: {}", remote_peer);
    println!("stack = {:?}", stack);
    println!("base_port = {}", base_port);
    if stack == Stack::All {
        println!(
            "all ports: tcp={} ws={} quic={} udp={}",
            port_for(Stack::Tcp, base_port),
            port_for(Stack::WebSocket, base_port),
            port_for(Stack::Quic, base_port),
            port_for(Stack::WebRtcUdp, base_port)
        );
    }
    println!();

    let order = match stack {
        Stack::All => vec![Stack::Tcp, Stack::WebSocket, Stack::Quic, Stack::WebRtcUdp],
        other => vec![other],
    };

    let mut all_rows = Vec::new();

    for st in order {
        if st == Stack::Tor {
            println!("[tor] пока пропускаем в all режиме");
            continue;
        }

        if st == Stack::WebRtcUdp && webrtc_full.is_none() {
            println!("[udp] нет полного webrtc multiaddr с /certhash/... → пропуск");
            continue;
        }

        let p = port_for(st, base_port);

        println!("--- RUN {} (port={}) ---", stack_name(st), p);

        let dial_addr = dial_addr_for_stack(
            st,
            ip,
            p,
            remote_peer,
            webrtc_full.clone(),
        )?;

        let rows =
            sender_run_stack(&mut swarm, &topic, local_peer, remote_peer, dial_addr, st).await?;
        print_table(&rows);
        all_rows.extend(rows);
    }

    println!("=== SUMMARY ===");
    print_table(&all_rows);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

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
    if stack == Stack::Tor {
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
                let p = port_for(st, base_port);
                let la = listen_multiaddr(st, p)?;
                swarm.listen_on(la)?;
            }
        }
        _ => {
            let la = listen_multiaddr(stack, base_port)?;
            swarm.listen_on(la)?;
        }
    }

    match role {
        Role::Receiver => receiver_loop(swarm, topic, local_peer).await,
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

            sender_loop(
                swarm,
                topic,
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
