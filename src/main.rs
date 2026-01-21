use anyhow::Result;
use futures::prelude::*;
use libp2p::{
    core::{
        muxing::StreamMuxerBox,
        transport::{upgrade::Version, Boxed, Transport},
    },
    gossipsub::{
        AllowAllSubscriptionFilter, Behaviour as GossipBehaviour, ConfigBuilder as GossipsubConfigBuilder,
        Event, IdentTopic, IdentityTransform, MessageAuthenticity, ValidationMode,
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
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::io::{self, AsyncBufReadExt};
use tokio::time;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

const KIND_DATA: u8 = 1;
const KIND_ACK: u8 = 2;

#[derive(Clone)]
struct Metrics {
    started_at: Instant,
    first_send_at: Option<Instant>,
    outgoing_bytes: u64,
    incoming_bytes: u64,
    data_sent: u64,
    data_delivered: u64,
    pending: HashMap<u64, Instant>,
    rtt_us: Vec<u64>,
    jitter_us: f64,
    prev_rtt_us: Option<u64>,
    next_id: u64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            first_send_at: None,
            outgoing_bytes: 0,
            incoming_bytes: 0,
            data_sent: 0,
            data_delivered: 0,
            pending: HashMap::new(),
            rtt_us: Vec::new(),
            jitter_us: 0.0,
            prev_rtt_us: None,
            next_id: 1,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
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

    fn note_data_send(&mut self, id: u64, bytes: usize) {
        if self.first_send_at.is_none() {
            self.first_send_at = Some(Instant::now());
        }
        self.data_sent = self.data_sent.saturating_add(1);
        self.note_outgoing(bytes);
        self.pending.insert(id, Instant::now());
    }

    fn note_ack_send(&mut self, bytes: usize) {
        self.note_outgoing(bytes);
    }

    fn note_ack_received(&mut self, id: u64) {
        if let Some(sent_at) = self.pending.remove(&id) {
            let rtt = sent_at.elapsed();
            let us = rtt.as_micros() as u64;

            if let Some(prev) = self.prev_rtt_us {
                let d = if us >= prev { us - prev } else { prev - us };
                self.jitter_us += (d as f64 - self.jitter_us) / 16.0;
            }
            self.prev_rtt_us = Some(us);

            self.rtt_us.push(us);
            self.data_delivered = self.data_delivered.saturating_add(1);
        }
    }

    fn startup_ms(&self) -> Option<u128> {
        self.first_send_at
            .map(|t| t.duration_since(self.started_at).as_millis())
    }

    fn median_rtt_us(&self) -> Option<u64> {
        if self.rtt_us.is_empty() {
            return None;
        }
        let mut v = self.rtt_us.clone();
        v.sort_unstable();
        let n = v.len();
        if n % 2 == 1 {
            Some(v[n / 2])
        } else {
            let a = v[n / 2 - 1] as u128;
            let b = v[n / 2] as u128;
            Some(((a + b) / 2) as u64)
        }
    }

    fn delivery_percent(&self) -> f64 {
        if self.data_sent == 0 {
            0.0
        } else {
            (self.data_delivered as f64 / self.data_sent as f64) * 100.0
        }
    }

    fn print(&self) {
        let startup = self.startup_ms();
        let median = self.median_rtt_us();
        println!("--- stats ---");
        match startup {
            Some(ms) => println!("startup_to_first_send_ms: {}", ms),
            None => println!("startup_to_first_send_ms: n/a"),
        }
        match median {
            Some(us) => println!("median_rtt_us: {}", us),
            None => println!("median_rtt_us: n/a"),
        }
        println!("jitter_us: {:.2}", self.jitter_us);
        println!("outgoing_bytes: {}", self.outgoing_bytes);
        println!("incoming_bytes: {}", self.incoming_bytes);
        println!(
            "sent_delivered: {} / {} ({:.2}%)",
            self.data_delivered,
            self.data_sent,
            self.delivery_percent()
        );
        println!("pending_unacked: {}", self.pending.len());
    }
}

enum ParsedMsg<'a> {
    Data { id: u64, sender: PeerId, payload: &'a [u8] },
    Ack { id: u64, target: PeerId },
}

fn encode_data(id: u64, sender: &PeerId, text: &[u8]) -> Vec<u8> {
    let sender_bytes = sender.to_bytes();
    let mut v = Vec::with_capacity(1 + 8 + 1 + sender_bytes.len() + text.len());
    v.push(KIND_DATA);
    v.extend_from_slice(&id.to_be_bytes());
    v.push(sender_bytes.len() as u8);
    v.extend_from_slice(&sender_bytes);
    v.extend_from_slice(text);
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

#[derive(Clone, Copy, Debug)]
enum Stack {
    Tcp,
    Tor,
    Quic,
    WebSocket,
    WebRtcUdp,
}

fn parse_stack(s: &str) -> Option<Stack> {
    match s.trim().to_lowercase().as_str() {
        "tcp" => Some(Stack::Tcp),
        "tor" => Some(Stack::Tor),
        "quic" => Some(Stack::Quic),
        "ws" | "websocket" | "http" | "http2" => Some(Stack::WebSocket),
        "udp" | "webrtc" | "webrtc-udp" => Some(Stack::WebRtcUdp),
        _ => None,
    }
}

fn build_transport(
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
    }
}

fn listen_multiaddr(stack: Stack, port: u16) -> Result<Multiaddr> {
    Ok(match stack {
        Stack::Tcp | Stack::Tor => format!("/ip4/0.0.0.0/tcp/{}", port).parse()?,
        Stack::WebSocket => format!("/ip4/0.0.0.0/tcp/{}/ws", port).parse()?,
        Stack::Quic => format!("/ip4/0.0.0.0/udp/{}/quic-v1", port).parse()?,
        Stack::WebRtcUdp => format!("/ip4/0.0.0.0/udp/{}/webrtc-direct", port).parse()?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    println!("=== gossipsub client (multi-transport) ===");
    println!("Stacks: tcp | tor | quic | websocket(ws/http/http2) | udp(webrtc)");
    println!("Введите stack:");

    let mut stdin = io::BufReader::new(io::stdin()).lines();
    let stack_input = read_line(&mut stdin).await?;
    let stack = parse_stack(&stack_input).unwrap_or(Stack::Tcp);
    println!("stack = {:?}", stack);

    println!("Введите onion адрес (нужно только для tor, иначе можно пусто):");
    let onion_input = read_line(&mut stdin).await?;
    let onion_ma: Option<Multiaddr> = if onion_input.trim().is_empty() {
        None
    } else {
        Some(onion_input.trim().parse::<Multiaddr>()?)
    };

    println!("Введите peer id (опционально):");
    let peerid_input = read_line(&mut stdin).await?;
    let remote_peer: Option<PeerId> = if peerid_input.trim().is_empty() {
        None
    } else {
        Some(PeerId::from_str(peerid_input.trim())?)
    };

    println!("Введите локальный порт приложения (по умолчанию 9000):");
    let port_input = read_line(&mut stdin).await?;
    let app_port: u16 = if port_input.trim().is_empty() {
        9000
    } else {
        port_input.trim().parse().unwrap_or(9000)
    };

    let mut onion_map: HashMap<Multiaddr, SocketAddr> = HashMap::new();
    if let Some(ref ma) = onion_ma {
        let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, app_port));
        onion_map.insert(ma.clone(), local);
        info!("Добавлен mapping: {:?} -> {}", ma, local);
    }

    let id_keys = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(id_keys.public());
    info!("Local PeerId: {}", local_peer_id);

    let transport = build_transport(stack, &id_keys, onion_map)?;

    let gossipsub_cfg = GossipsubConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        .build()?;

    let gossip_behaviour = GossipBehaviour::<IdentityTransform, AllowAllSubscriptionFilter>::new(
        MessageAuthenticity::Signed(id_keys.clone()),
        gossipsub_cfg,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    let topic = IdentTopic::new("forum/autos/board/general");

    let swarm_config = SwarmConfig::with_tokio_executor();
    let mut swarm = Swarm::new(transport, gossip_behaviour, local_peer_id, swarm_config);

    let listen_addr = listen_multiaddr(stack, app_port)?;
    swarm.listen_on(listen_addr.clone())?;
    info!("Listening on {}", listen_addr);

    let mut peers_to_dial: Vec<Multiaddr> = Vec::new();
    if let Some(mut ma) = onion_ma.clone() {
        if let Some(pid) = remote_peer {
            use libp2p::multiaddr::Protocol;
            ma.push(Protocol::P2p(pid.into()));
        }
        peers_to_dial.push(ma);
    }

    if let Ok(peers_env) = std::env::var("PEER_MULTIADDRS") {
        for s in peers_env.split(',') {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            if let Ok(ma) = s.parse::<Multiaddr>() {
                peers_to_dial.push(ma);
            } else {
                eprintln!("Bad multiaddr in PEER_MULTIADDRS '{}'", s);
            }
        }
    }

    for arg in std::env::args().skip(1) {
        let a = arg.trim();
        if a.is_empty() {
            continue;
        }
        if let Ok(ma) = a.parse::<Multiaddr>() {
            peers_to_dial.push(ma);
        } else {
            eprintln!("Bad multiaddr CLI arg '{}'", a);
        }
    }

    if let Err(e) = swarm.behaviour_mut().subscribe(&topic) {
        warn!("Failed to subscribe to topic: {:?}", e);
    }

    println!("Ready. Commands: dial <multiaddr>, peers, stats, reset_stats, quit, <text to publish>");

    let mut stdin_lines = io::BufReader::new(io::stdin()).lines();
    let mut pending_initial_peers = peers_to_dial;

    let mut metrics = Metrics::new();
    let mut ticker = time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                metrics.print();
            }

            line = stdin_lines.next_line() => {
                if let Ok(Some(text)) = line {
                    let text = text.trim();
                    if text.is_empty() { continue; }

                    if text == "quit" {
                        println!("Exiting...");
                        break;
                    }

                    if text == "peers" {
                        println!("Connected peers:");
                        for p in swarm.connected_peers() {
                            println!("  {}", p);
                        }
                        continue;
                    }

                    if text == "stats" {
                        metrics.print();
                        continue;
                    }

                    if text == "reset_stats" {
                        metrics.reset();
                        println!("stats reset");
                        continue;
                    }

                    if text.starts_with("dial ") {
                        let addr_str = text[5..].trim();
                        match addr_str.parse::<Multiaddr>() {
                            Ok(ma) => {
                                match swarm.dial(ma.clone()) {
                                    Ok(_) => println!("Dialing {}", ma),
                                    Err(e) => eprintln!("Dial error {}: {:?}", ma, e),
                                }
                            }
                            Err(e) => eprintln!("Bad multiaddr '{}': {:?}", addr_str, e),
                        }
                        continue;
                    }

                    let id = metrics.alloc_id();
                    let payload = encode_data(id, &local_peer_id, text.as_bytes());
                    match swarm.behaviour_mut().publish(topic.clone(), payload.clone()) {
                        Ok(_) => {
                            metrics.note_data_send(id, payload.len());
                        }
                        Err(e) => {
                            eprintln!("Publish error: {:?}", e);
                        }
                    }
                }
            }

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on {:?}", address);
                        if !pending_initial_peers.is_empty() {
                            for ma in pending_initial_peers.drain(..) {
                                match swarm.dial(ma.clone()) {
                                    Ok(_) => info!("Dialing initial peer {}", ma),
                                    Err(e) => warn!("Dial error {}: {:?}", ma, e),
                                }
                            }
                        }
                    }

                    SwarmEvent::Behaviour(ev) => {
                        match ev {
                            Event::Message { propagation_source, message_id: _, message } => {
                                metrics.note_incoming(message.data.len());

                                if let Some(parsed) = decode_msg(&message.data) {
                                    match parsed {
                                        ParsedMsg::Data { id, sender, payload } => {
                                            if sender != local_peer_id {
                                                let text = String::from_utf8_lossy(payload);
                                                println!("<<< {}: {}", sender, text);

                                                let ack = encode_ack(id, &sender);
                                                if swarm.behaviour_mut().publish(topic.clone(), ack.clone()).is_ok() {
                                                    metrics.note_ack_send(ack.len());
                                                }
                                            } else {
                                                debug!("Self DATA observed via propagation_source={}", propagation_source);
                                            }
                                        }
                                        ParsedMsg::Ack { id, target } => {
                                            if target == local_peer_id {
                                                metrics.note_ack_received(id);
                                            }
                                        }
                                    }
                                } else {
                                    let text = String::from_utf8_lossy(&message.data);
                                    println!("<<< {}: {}", propagation_source, text);
                                }
                            }

                            Event::Subscribed { peer_id, topic } => {
                                println!("Peer {} subscribed to {:?}", peer_id, topic);
                            }

                            Event::Unsubscribed { peer_id, topic } => {
                                println!("Peer {} unsubscribed to {:?}", peer_id, topic);
                            }

                            other => {
                                debug!("Other gossipsub event: {:?}", other);
                            }
                        }
                    }

                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        info!("ConnectionEstablished with {} via {:?}", peer_id, endpoint);
                    }

                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        info!("ConnectionClosed with {} cause={:?}", peer_id, cause);
                    }

                    other => debug!("SwarmEvent: {:?}", other),
                }
            }
        }
    }

    Ok(())
}

async fn read_line(lines: &mut io::Lines<io::BufReader<tokio::io::Stdin>>) -> Result<String> {
    if let Some(line) = lines.next_line().await? {
        Ok(line)
    } else {
        Ok(String::new())
    }
}
