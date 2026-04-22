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
use libp2p_webrtc::tokio::{Certificate, Transport as WebRtcTransport};
// Подтягиваем твой отдельный крейт!
use libp2p_tokio_socks5::{Socks5Config, Socks5Transport};

use rand::thread_rng;
use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fs::File,
    hash::{Hash, Hasher},
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System,
};
use tokio::io::AsyncBufReadExt;
use tokio::time;
use tracing::{debug, error, info, warn};

// --- КОНСТАНТЫ ---
const KIND_DATA: u8 = 1;
const KIND_ACK: u8 = 2;

const DEFAULT_COUNTS: &[usize] = &[100, 1000, 5000];
const PAYLOAD_SIZES: &[usize] = &[32, 1024, 4096];

const RUN_TIMEOUT: Duration = Duration::from_secs(120);
const DIAL_READY_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SEEN_IDS: usize = 1_000_000;
const MAX_RTT_SAMPLES: usize = 200_000;
const GOSSIPSUB_MAX_TRANSMIT_SIZE: usize = 64 * 1024;

// --- ПЕРЕЧИСЛЕНИЯ ---
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role { Receiver, Sender }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Stack { Tcp, Quic, WebSocket, WebRtcUdp, Tor, All }

fn parse_role(s: &str) -> Option<Role> {
    match s.trim().to_lowercase().as_str() {
        "recv" | "receiver" | "2" => Some(Role::Receiver),
        "send" | "sender" | "1" => Some(Role::Sender),
        _ => None,
    }
}

fn parse_stack(s: &str) -> Option<Stack> {
    match s.trim().to_lowercase().as_str() {
        "tcp" => Some(Stack::Tcp),
        "quic" => Some(Stack::Quic),
        "ws" | "websocket" => Some(Stack::WebSocket),
        "udp" | "webrtc" => Some(Stack::WebRtcUdp),
        "tor" => Some(Stack::Tor),
        "all" => Some(Stack::All),
        _ => None,
    }
}

fn stack_name(s: Stack) -> &'static str {
    match s {
        Stack::Tcp => "tcp", Stack::Quic => "quic", Stack::WebSocket => "ws",
        Stack::WebRtcUdp => "udp", Stack::Tor => "tor", Stack::All => "all",
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

// --- СТРУКТУРЫ МЕТРИК ---
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
            outgoing_bytes: 0, incoming_bytes: 0, payload_bytes_sent: 0,
            payload_bytes_delivered: 0, data_sent: 0, data_delivered: 0,
            publish_failed: 0, pending: HashMap::new(), rtt_us: Vec::new(),
            rtt_seen: 0, jitter_us: 0.0, prev_rtt_us: None, next_id: 1,
            duplicates: 0, seen_data_ids: HashSet::new(),
        }
    }

    fn reset_run(&mut self) {
        self.outgoing_bytes = 0; self.incoming_bytes = 0;
        self.payload_bytes_sent = 0; self.payload_bytes_delivered = 0;
        self.data_sent = 0; self.data_delivered = 0; self.publish_failed = 0;
        self.pending.clear(); self.rtt_us.clear(); self.rtt_seen = 0;
        self.jitter_us = 0.0; self.prev_rtt_us = None;
        self.duplicates = 0; self.seen_data_ids.clear();
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn note_outgoing(&mut self, bytes: usize) { self.outgoing_bytes = self.outgoing_bytes.saturating_add(bytes as u64); }
    fn note_incoming(&mut self, bytes: usize) { self.incoming_bytes = self.incoming_bytes.saturating_add(bytes as u64); }

    fn note_data_send(&mut self, id: u64, full_msg_bytes: usize, payload_bytes: usize) {
        self.data_sent = self.data_sent.saturating_add(1);
        self.note_outgoing(full_msg_bytes);
        self.payload_bytes_sent = self.payload_bytes_sent.saturating_add(payload_bytes as u64);
        self.pending.insert(id, (Instant::now(), payload_bytes));
    }

    fn note_publish_failed(&mut self) { self.publish_failed = self.publish_failed.saturating_add(1); }
    fn note_ack_send(&mut self, bytes: usize) { self.note_outgoing(bytes); }

    fn note_ack_received(&mut self, id: u64) {
        if let Some((sent_at, payload_bytes)) = self.pending.remove(&id) {
            let us = sent_at.elapsed().as_micros() as u64;
            if let Some(prev) = self.prev_rtt_us {
                let d = if us >= prev { us - prev } else { prev - us };
                self.jitter_us += (d as f64 - self.jitter_us) / 16.0;
            }
            self.prev_rtt_us = Some(us);
            self.rtt_seen = self.rtt_seen.saturating_add(1);
            if self.rtt_us.len() < MAX_RTT_SAMPLES { self.rtt_us.push(us); }
            self.data_delivered = self.data_delivered.saturating_add(1);
            self.payload_bytes_delivered = self.payload_bytes_delivered.saturating_add(payload_bytes as u64);
        }
    }

    fn note_payload_delivered_receiver_side(&mut self, payload_bytes: usize) {
        self.payload_bytes_delivered = self.payload_bytes_delivered.saturating_add(payload_bytes as u64);
    }

    fn delivery_percent(&self) -> f64 {
        if self.data_sent == 0 { 0.0 } else { (self.data_delivered as f64 / self.data_sent as f64) * 100.0 }
    }

    fn median_rtt_us(&self) -> Option<u64> { percentile_us(&self.rtt_us, 50.0) }
    fn p95_rtt_us(&self) -> Option<u64> { percentile_us(&self.rtt_us, 95.0) }
    fn p99_rtt_us(&self) -> Option<u64> { percentile_us(&self.rtt_us, 99.0) }

    fn overhead_ratio(&self) -> f64 {
        let good = self.payload_bytes_delivered.max(1) as f64;
        (self.outgoing_bytes as f64) / good
    }

    fn goodput_mbps(&self, elapsed: Duration) -> f64 {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 { return 0.0; }
        let bits = (self.payload_bytes_delivered as f64) * 8.0;
        (bits / secs) / 1_000_000.0
    }
}

fn percentile_us(v: &[u64], p: f64) -> Option<u64> {
    if v.is_empty() { return None; }
    let mut s = v.to_vec();
    s.sort_unstable();
    let n = s.len();
    let idx = ((p / 100.0) * (n.saturating_sub(1) as f64)).round() as usize;
    Some(s[idx.min(n - 1)])
}

#[derive(Default, Clone)]
struct ResourceStats { cpu_avg: f32, mem_avg_mb: f64 }

struct ResourceMeter {
    sys: System, cpu_samples: Vec<f32>, mem_samples_kb: Vec<u64>,
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
            out.cpu_avg = self.cpu_samples.iter().sum::<f32>() / (self.cpu_samples.len() as f32);
        }
        if !self.mem_samples_kb.is_empty() {
            let avg_kb = self.mem_samples_kb.iter().sum::<u64>() as f64 / (self.mem_samples_kb.len() as f64);
            out.mem_avg_mb = avg_kb / 1024.0;
        }
        out
    }
}

// --- КОДИРОВАНИЕ ПАКЕТОВ ---
enum ParsedMsg<'a> {
    Data { id: u64, sender: PeerId, payload: &'a [u8] },
    Ack { id: u64, target: PeerId },
}

fn encode_data(id: u64, sender: &PeerId, payload: &[u8]) -> Vec<u8> {
    let sb = sender.to_bytes();
    let mut v = Vec::with_capacity(10 + sb.len() + payload.len());
    v.push(KIND_DATA); v.extend_from_slice(&id.to_be_bytes());
    v.push(sb.len() as u8); v.extend_from_slice(&sb); v.extend_from_slice(payload);
    v
}

fn encode_ack(id: u64, target: &PeerId) -> Vec<u8> {
    let tb = target.to_bytes();
    let mut v = Vec::with_capacity(10 + tb.len());
    v.push(KIND_ACK); v.extend_from_slice(&id.to_be_bytes());
    v.push(tb.len() as u8); v.extend_from_slice(&tb);
    v
}

fn decode_msg(bytes: &[u8]) -> Option<ParsedMsg<'_>> {
    if bytes.len() < 10 { return None; }
    let id = u64::from_be_bytes(bytes[1..9].try_into().ok()?);
    let len = bytes[9] as usize;
    if bytes.len() < 10 + len { return None; }
    let peer = PeerId::from_bytes(&bytes[10..10 + len]).ok()?;

    match bytes[0] {
        KIND_DATA => Some(ParsedMsg::Data { id, sender: peer, payload: &bytes[10 + len..] }),
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

// --- ВЫВОД ТАБЛИЦ И CSV ---
#[derive(Clone)]
struct BenchRow {
    stack: Stack, payload: usize, requested: usize, sent: u64, delivered: u64,
    publish_failed: u64, dial_ms: u128, delivery_percent: f64, median_us: Option<u64>,
    p95_us: Option<u64>, p99_us: Option<u64>, jitter_us: f64, goodput_mbps: f64,
    overhead: f64, cpu_avg: f32, mem_avg: f64,
}

fn print_table(rows: &[BenchRow]) {
    println!("\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------");
    println!(
        "{:>6} | {:>7} | {:>8} | {:>7} | {:>7} | {:>7} | {:>7} | {:>8} | {:>9} | {:>9} | {:>9} | {:>8} | {:>9} | {:>9} | {:>7} | {:>7}",
        "stack", "payload", "req", "sent", "deliv", "fail", "dialms", "deliv%", "medianus", "p95us", "p99us", "jitter", "goodput", "overhead", "cpu", "mem"
    );
    println!("-------------------------------------------------------------------------------------------------------------------------------------------------------------------");
    for r in rows {
        println!(
            "{:>6} | {:>7} | {:>8} | {:>7} | {:>7} | {:>7} | {:>7} | {:>7.2}% | {:>9} | {:>9} | {:>9} | {:>7.1} | {:>8.3} | {:>8.3} | {:>6.2} | {:>6.2}",
            stack_name(r.stack), r.payload, r.requested, r.sent, r.delivered, r.publish_failed, r.dial_ms,
            r.delivery_percent, r.median_us.map(|x| x.to_string()).unwrap_or_else(|| "n/a".into()),
            r.p95_us.map(|x| x.to_string()).unwrap_or_else(|| "n/a".into()), r.p99_us.map(|x| x.to_string()).unwrap_or_else(|| "n/a".into()),
            r.jitter_us, r.goodput_mbps, r.overhead, r.cpu_avg, r.mem_avg,
        );
    }
    println!("-------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
}

fn export_to_csv(rows: &[BenchRow]) -> Result<()> {
    if rows.is_empty() { return Ok(()); }
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let fname = format!("results_{}.csv", ts);
    let mut file = File::create(&fname)?;
    
    writeln!(file, "stack,payload,requested,sent,delivered,publish_failed,dial_ms,delivery_percent,median_us,p95_us,p99_us,jitter_us,goodput_mbps,overhead,cpu_avg,mem_avg_mb")?;
    for r in rows {
        writeln!(file, "{},{},{},{},{},{},{},{:.2},{},{},{},{:.1},{:.3},{:.3},{:.2},{:.2}",
            stack_name(r.stack), r.payload, r.requested, r.sent, r.delivered, r.publish_failed, r.dial_ms,
            r.delivery_percent, r.median_us.unwrap_or(0), r.p95_us.unwrap_or(0), r.p99_us.unwrap_or(0),
            r.jitter_us, r.goodput_mbps, r.overhead, r.cpu_avg, r.mem_avg)?;
    }
    println!("✅ Данные бенчмарка успешно сохранены в: {}", fname);
    Ok(())
}

// --- ИНИЦИАЛИЗАЦИЯ LIBP2P ---
fn make_gossipsub(id_keys: &identity::Keypair) -> Result<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>> {
    let cfg = GossipsubConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        .allow_self_origin(false)
        .flood_publish(true)
        .max_transmit_size(GOSSIPSUB_MAX_TRANSMIT_SIZE)
        .message_id_fn(|m| make_message_id(&m.data))
        .build()?;
    GossipBehaviour::<IdentityTransform, AllowAllSubscriptionFilter>::new(MessageAuthenticity::Signed(id_keys.clone()), cfg).map_err(|e| anyhow!(e))
}

fn build_transport_single(stack: Stack, id_keys: &identity::Keypair, onion_map: HashMap<Multiaddr, SocketAddr>) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
    match stack {
        Stack::Tcp => {
            let tcp = TcpTransport::new(TcpConfig::default());
            let noise = NoiseConfig::new(id_keys)?;
            Ok(tcp.upgrade(Version::V1).authenticate(noise).multiplex(YamuxConfig::default()).map(|(p, m), _| (p, StreamMuxerBox::new(m))).boxed())
        }
        Stack::WebSocket => {
            let ws = websocket::Config::new(TcpTransport::new(TcpConfig::default()));
            let noise = NoiseConfig::new(id_keys)?;
            Ok(ws.upgrade(Version::V1).authenticate(noise).multiplex(YamuxConfig::default()).map(|(p, m), _| (p, StreamMuxerBox::new(m))).boxed())
        }
        Stack::Quic => {
            let quic = libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(id_keys));
            Ok(quic.map(|(p, c), _| (p, StreamMuxerBox::new(c))).boxed())
        }
        Stack::WebRtcUdp => {
            let cert = Certificate::generate(&mut thread_rng())?;
            let webrtc = WebRtcTransport::new(id_keys.clone(), cert);
            Ok(webrtc.map(|(p, c), _| (p, StreamMuxerBox::new(c))).boxed())
        }
        Stack::Tor => {
            let tcp = TcpTransport::new(TcpConfig::default());
            let socks = Socks5Transport::new(Socks5Config::default(), onion_map);
            let noise = NoiseConfig::new(id_keys)?;
            Ok(tcp.or_transport(socks).upgrade(Version::V1).authenticate(noise).multiplex(YamuxConfig::default()).map(|(p, m), _| (p, StreamMuxerBox::new(m))).boxed())
        }
        Stack::All => Err(anyhow!("use build_transport_all()")),
    }
}

fn build_transport_all(id_keys: &identity::Keypair) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
    let tcp = build_transport_single(Stack::Tcp, id_keys, HashMap::new())?;
    let ws = build_transport_single(Stack::WebSocket, id_keys, HashMap::new())?;
    let quic = build_transport_single(Stack::Quic, id_keys, HashMap::new())?;
    let udp = build_transport_single(Stack::WebRtcUdp, id_keys, HashMap::new())?;

    Ok(tcp.or_transport(ws).map(|e, _| e.into_inner())
          .or_transport(quic).map(|e, _| e.into_inner())
          .or_transport(udp).map(|e, _| e.into_inner()).boxed())
}

fn build_swarm(transport: Boxed<(PeerId, StreamMuxerBox)>, behaviour: GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>, local_peer: PeerId) -> Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>> {
    Swarm::new(transport, behaviour, local_peer, SwarmConfig::with_tokio_executor())
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

fn dial_addr_for_stack(stack: Stack, ip: IpAddr, base_port: u16, peer: PeerId, webrtc_full: Option<Multiaddr>, onion: Option<Multiaddr>) -> Result<Multiaddr> {
    let port = port_for_stack(base_port, stack);
    match stack {
        Stack::Tcp => Ok(format!("/ip4/{}/tcp/{}/p2p/{}", ip, port, peer).parse()?),
        Stack::WebSocket => Ok(format!("/ip4/{}/tcp/{}/ws/p2p/{}", ip, port, peer).parse()?),
        Stack::Quic => Ok(format!("/ip4/{}/udp/{}/quic-v1/p2p/{}", ip, port, peer).parse()?),
        Stack::WebRtcUdp => webrtc_full.ok_or_else(|| anyhow!("Need full multiaddr for webrtc")),
        Stack::Tor => onion.ok_or_else(|| anyhow!("Tor dial requires onion multiaddr")),
        Stack::All => Err(anyhow!("use per-stack dial in all mode")),
    }
}

// --- ЛОГИКА БЕНЧМАРКА ---
async fn handle_message(swarm: &mut Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>, topic: &IdentTopic, local_peer: PeerId, metrics: &mut Metrics, msg: &libp2p::gossipsub::Message) {
    metrics.note_incoming(msg.data.len());
    if let Some(parsed) = decode_msg(&msg.data) {
        match parsed {
            ParsedMsg::Data { id, sender, payload } => {
                if sender == local_peer || !metrics.seen_data_ids.insert((sender, id)) {
                    if sender != local_peer { metrics.duplicates = metrics.duplicates.saturating_add(1); }
                    return;
                }
                metrics.note_payload_delivered_receiver_side(payload.len());
                let ack = encode_ack(id, &sender);
                if let Ok(_) = swarm.behaviour_mut().publish(topic.clone(), ack.clone()) {
                    metrics.note_ack_send(ack.len());
                }
            }
            ParsedMsg::Ack { id, target } => {
                if target == local_peer { metrics.note_ack_received(id); }
            }
        }
    }
}

async fn dial_wait_ready(swarm: &mut Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>, addr: Multiaddr, peer: PeerId, th: TopicHash, timeout: Duration) -> Result<Duration> {
    let t0 = Instant::now();
    
    let _ = swarm.dial(addr);
    let deadline = Instant::now() + timeout;
    let (mut c, mut s) = (false, false);

    loop {
        if c && s { return Ok(t0.elapsed()); }
        if Instant::now() > deadline { return Err(anyhow!("dial timeout")); }
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer => c = true,
            SwarmEvent::Behaviour(Event::Subscribed { peer_id, topic }) if peer_id == peer && topic == th => s = true,
            _ => {}
        }
    }
}

async fn run_bench_windowed(swarm: &mut Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>, topic: &IdentTopic, local: PeerId, req: usize, size: usize, inflight: usize, metrics: &mut Metrics) -> Result<(Duration, ResourceStats)> {
    metrics.reset_run();
    let payload = vec![b'x'; size];
    let start = Instant::now();
    let mut sent = 0;
    let mut meter = ResourceMeter::new();
    let mut tick = time::interval(Duration::from_secs(1));

    loop {
        let mut burst = 0;
        while sent < req && metrics.pending.len() < inflight && burst < 64 {
            if start.elapsed() > RUN_TIMEOUT { break; }
            let id = metrics.alloc_id();
            let msg = encode_data(id, &local, &payload);
            if swarm.behaviour_mut().publish(topic.clone(), msg.clone()).is_ok() {
                metrics.note_data_send(id, msg.len(), size);
                sent += 1; burst += 1;
            } else {
                metrics.note_publish_failed();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            tokio::task::yield_now().await;
        }

        if (sent == req && metrics.pending.is_empty()) || start.elapsed() > RUN_TIMEOUT { break; }

        tokio::select! {
            _ = tick.tick() => meter.sample(),
            ev = swarm.select_next_some() => if let SwarmEvent::Behaviour(Event::Message { message, .. }) = ev {
                handle_message(swarm, topic, local, metrics, &message).await;
            }
        }
    }
    Ok((start.elapsed(), meter.summarize()))
}

async fn receiver_loop(mut swarm: Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>, topic: IdentTopic, local: PeerId) -> Result<()> {
    info!("=== Receiver [{}] ===", local);
    let mut m = Metrics::new();
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => info!("Listen: {}", address),
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected: {}", peer_id);
            }
            SwarmEvent::Behaviour(Event::Message { message, .. }) => handle_message(&mut swarm, &topic, local, &mut m, &message).await,
            _ => {}
        }
    }
}

async fn sender_run_stack(mut swarm: Swarm<GossipBehaviour<IdentityTransform, AllowAllSubscriptionFilter>>, topic: IdentTopic, local: PeerId, remote: PeerId, addr: Multiaddr, stack: Stack, inflight: usize) -> Result<Vec<BenchRow>> {
    println!("Dial {} ...", addr);
    let dial_time = dial_wait_ready(&mut swarm, addr, remote, topic.hash(), DIAL_READY_TIMEOUT).await?;
    println!("Ready. dial_ms={}", dial_time.as_millis());
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let mut rows = Vec::new();
    let mut m = Metrics::new();

    for &size in PAYLOAD_SIZES {
        for &req in DEFAULT_COUNTS {
            let (el, rs) = run_bench_windowed(&mut swarm, &topic, local, req, size, inflight, &mut m).await?;
            rows.push(BenchRow {
                stack, payload: size, requested: req, sent: m.data_sent, delivered: m.data_delivered,
                publish_failed: m.publish_failed, dial_ms: dial_time.as_millis(), delivery_percent: m.delivery_percent(),
                median_us: m.median_rtt_us(), p95_us: m.p95_rtt_us(), p99_us: m.p99_rtt_us(), jitter_us: m.jitter_us,
                goodput_mbps: m.goodput_mbps(el), overhead: m.overhead_ratio(), cpu_avg: rs.cpu_avg, mem_avg: rs.mem_avg_mb,
            });
            println!("[{}] {}B | {}/{} | {:?}us | {:.3} Mbps", stack_name(stack), size, m.data_delivered, req, m.median_rtt_us(), m.goodput_mbps(el));
        }
    }
    Ok(rows)
}

async fn sender_all_mode(remote_peer: PeerId, ip: IpAddr, base_port: u16, webrtc: Option<Multiaddr>, inflight: usize, onion: Option<Multiaddr>) -> Result<()> {
    let mut all_rows = Vec::new();
    for st in [Stack::Tcp, Stack::WebSocket, Stack::Quic, Stack::WebRtcUdp] {
        if st == Stack::WebRtcUdp && webrtc.is_none() { continue; }
        println!("\n=== RUN {} ===", stack_name(st));
        
        let id_keys = identity::Keypair::generate_ed25519();
        let local_peer = PeerId::from(id_keys.public());
        let mut swarm = build_swarm(build_transport_single(st, &id_keys, HashMap::new())?, make_gossipsub(&id_keys)?, local_peer);
        if st == Stack::WebRtcUdp { swarm.listen_on("/ip4/0.0.0.0/udp/0/webrtc-direct".parse()?)?; }
        
        let topic = IdentTopic::new("forum/autos/board/general");
        swarm.behaviour_mut().subscribe(&topic)?;
        
        let addr = dial_addr_for_stack(st, ip, base_port, remote_peer, webrtc.clone(), onion.clone())?;
        let rows = sender_run_stack(swarm, topic, local_peer, remote_peer, addr, st, inflight).await?;
        print_table(&rows);
        all_rows.extend(rows);
    }
    println!("=== SUMMARY ===");
    print_table(&all_rows);
    export_to_csv(&all_rows)?;
    Ok(())
}

async fn read_line(lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::io::Stdin>>) -> Result<String> {
    Ok(lines.next_line().await?.unwrap_or_default())
}

// --- MAIN ---
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    println!("1) Local Receiver (TCP, 9000)\n2) Local Sender (TCP, 9000)\n3) Tor Receiver\n4) Manual");
    let preset = read_line(&mut stdin).await?;

    let mut role = Role::Receiver;
    let mut stack = Stack::Tcp;
    let mut base_port = 9000;
    let mut peer_str = String::new();
    let mut ip_str = "127.0.0.1".to_string();
    let mut in_flight = 10000;

    match preset.trim() {
        "1" => {},
        "2" => { role = Role::Sender; println!("PeerId:"); peer_str = read_line(&mut stdin).await?; },
        "3" => { stack = Stack::Tor; },
        _ => {
            println!("Role (send/recv):"); role = parse_role(&read_line(&mut stdin).await?).unwrap_or(Role::Receiver);
            println!("Stack (tcp/quic/ws/udp/tor/all):"); stack = parse_stack(&read_line(&mut stdin).await?).unwrap_or(Stack::Tcp);
            println!("Port:"); let p = read_line(&mut stdin).await?; if !p.is_empty() { base_port = p.parse().unwrap_or(9000); }
        }
    }

    if role == Role::Sender {
        println!("Window (IN_FLIGHT, 10000):");
        let w = read_line(&mut stdin).await?; if !w.is_empty() { in_flight = w.parse().unwrap_or(10000); }
    }

    let mut onion_map = HashMap::new();
    let mut onion_sender = None;
    if stack == Stack::Tor {
        println!("Onion address:");
        let o = read_line(&mut stdin).await?;
        if role == Role::Receiver { onion_map.insert(o.parse()?, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, base_port))); }
        else { onion_sender = Some(o.parse()?); }
    }

    let keys = identity::Keypair::generate_ed25519();
    let local = PeerId::from(keys.public());

    match role {
        Role::Receiver => {
            let t = if stack == Stack::All { build_transport_all(&keys)? } else { build_transport_single(stack, &keys, onion_map)? };
            let mut swarm = build_swarm(t, make_gossipsub(&keys)?, local);
            let topic = IdentTopic::new("forum/autos/board/general");
            swarm.behaviour_mut().subscribe(&topic)?;
            
            if stack == Stack::All {
                for st in [Stack::Tcp, Stack::WebSocket, Stack::Quic, Stack::WebRtcUdp] { swarm.listen_on(listen_multiaddr(st, base_port)?)?; }
            } else { swarm.listen_on(listen_multiaddr(stack, base_port)?)?; }
            
            receiver_loop(swarm, topic, local).await?;
        }
        Role::Sender => {
            if peer_str.is_empty() { println!("PeerId:"); peer_str = read_line(&mut stdin).await?; }
            if ip_str == "127.0.0.1" && preset.trim() != "2" { println!("IP:"); ip_str = read_line(&mut stdin).await?; }
            
            let mut webrtc = None;
            if stack == Stack::WebRtcUdp || stack == Stack::All {
                println!("WebRTC multiaddr (optional):");
                let w = read_line(&mut stdin).await?; if !w.is_empty() { webrtc = Some(w.parse()?); }
            }

            if stack == Stack::All { return sender_all_mode(PeerId::from_str(&peer_str)?, ip_str.parse()?, base_port, webrtc, in_flight, onion_sender).await; }

            let mut swarm = build_swarm(build_transport_single(stack, &keys, HashMap::new())?, make_gossipsub(&keys)?, local);
            if stack == Stack::WebRtcUdp { swarm.listen_on("/ip4/0.0.0.0/udp/0/webrtc-direct".parse()?)?; }
            
            let topic = IdentTopic::new("forum/autos/board/general");
            swarm.behaviour_mut().subscribe(&topic)?;
            let addr = dial_addr_for_stack(stack, ip_str.parse()?, base_port, PeerId::from_str(&peer_str)?, webrtc, onion_sender)?;
            
            let rows = sender_run_stack(swarm, topic, local, PeerId::from_str(&peer_str)?, addr, stack, in_flight).await?;
            print_table(&rows);
            export_to_csv(&rows)?;
        }
    }
    Ok(())
}
