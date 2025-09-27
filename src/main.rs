// gossipsub_with_tor_and_menu.rs
// Переработанный gossipsub-клиент с поддержкой Tor (SOCKS5) и интерактивным меню.
// Использует API, который ты указал в последних сообщениях (Behaviour, ConfigBuilder, Event, Noise::Config и т.д.).

use anyhow::Result;
use futures::prelude::*;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed as TransportBoxed, upgrade},
    gossipsub::{Behaviour as Gossipbehaviour, ConfigBuilder as GossipsubConfigBuilder, Event, IdentTopic, MessageAuthenticity, MessageId, ValidationMode},
    identity,
    noise::Config as NoiseConfig,
    swarm::{Config as SwarmConfig, Swarm, SwarmEvent},
    tcp::{Config as TcpConfig, tokio::Transport as TcpTransport},
    yamux::Config as YamuxConfig,
    Multiaddr, PeerId,
};

// Трейт Transport нужен для метода or_transport()
use libp2p::core::transport::{Transport, upgrade::Version};

use libp2p_tokio_socks5::{Socks5Config, Socks5Transport};
use std::{collections::HashMap, error::Error, net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4}, str::FromStr};
use tokio::io::{self, AsyncBufReadExt};
use tracing::{info, warn, debug};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Инициализация логов
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    println!("=== gossipsub client (Tor/SOCKS5 support) ===");

    // Интерактивное меню: спросим onion и (опционально) peer id
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    println!("Введите onion адрес");
    let onion_input = read_line(&mut stdin).await?;
    let onion_ma: Option<Multiaddr> = if onion_input.trim().is_empty() {
        None
    } else {
        Some(onion_input.trim().parse::<Multiaddr>()?)
    };

    println!("Введите peer id (PeerId) соответствующий onion (опционально, можно оставить пустым):");
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

    // onion -> local mapping для Socks5Transport
    let mut onion_map: HashMap<Multiaddr, SocketAddr> = HashMap::new();
    if let Some(ref ma) = onion_ma {
        let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, app_port));
        onion_map.insert(ma.clone(), local);
        info!("Добавлен mapping: {:?} -> {}", ma, local);
    }

    // Ключи и PeerId
    let id_keys = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(id_keys.public());
    info!("Local PeerId: {}", local_peer_id);

    // --- Транспорт ---
    // TCP транспорт
    let tcp_transport = TcpTransport::new(TcpConfig::default());

    // SOCKS5 (Tor) транспорт
    info!("Создаём Socks5Transport (Tor)...");
    let socks_cfg = Socks5Config::default();
    let socks5transport = Socks5Transport::new(socks_cfg, onion_map);
    info!("Socks5Transport created.");

    // Комбинируем транспорты: tcp OR socks
    let combined = tcp_transport.or_transport(socks5transport);

    // Настраиваем noise + yamux поверх комбинированного транспорта
    let noise_cfg = NoiseConfig::new(&id_keys).expect("Cannot create config");
    let transport = combined
        .upgrade(Version::V1)
        .authenticate(noise_cfg)
        .multiplex(YamuxConfig::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();

    // --- Gossipsub Behaviour ---
    let gossipsub_cfg = GossipsubConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        .build()
        .expect("gossipsub config");

    let gossipbehaviour: Gossipbehaviour = Gossipbehaviour::new(MessageAuthenticity::Signed(id_keys.clone()), gossipsub_cfg)
        .expect("failed to create gossipsub behaviour");

    let topic = IdentTopic::new("forum/autos/board/general");

    // Swarm config с tokio executor
    let swarm_config = SwarmConfig::with_tokio_executor();

    // Создаём Swarm
    let mut swarm = Swarm::new(transport, gossipbehaviour, local_peer_id, swarm_config);

    // Слушаем локально на tcp 0.0.0.0:app_port
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", app_port).parse()?;
    swarm.listen_on(listen_addr.clone())?;
    info!("Listening on {}", listen_addr);

    // Соберём peers to dial из введённых значений (если есть onion)
    let mut peers_to_dial: Vec<Multiaddr> = Vec::new();
    if let Some(mut ma) = onion_ma.clone() {
        if let Some(pid) = remote_peer {
            use libp2p::multiaddr::Protocol;
            ma.push(Protocol::P2p(pid.into()));
        }
        peers_to_dial.push(ma);
    }

    // Попробуем взять дополнительно peers из env/args (как у тебя было)
    if let Ok(peers_env) = std::env::var("PEER_MULTIADDRS") {
        for s in peers_env.split(',') {
            let s = s.trim();
            if s.is_empty() { continue; }
            match s.parse::<Multiaddr>() {
                Ok(ma) => peers_to_dial.push(ma),
                Err(e) => eprintln!("Bad multiaddr in PEER_MULTIADDRS '{}': {:?}", s, e),
            }
        }
    }
    for arg in std::env::args().skip(1) {
        let a = arg.trim();
        if a.is_empty() { continue; }
        match a.parse::<Multiaddr>() {
            Ok(ma) => peers_to_dial.push(ma),
            Err(e) => eprintln!("Bad multiaddr CLI arg '{}': {:?}", a, e),
        }
    }

    if !peers_to_dial.is_empty() {
        info!("Will attempt to dial peers from env/args/onion: {:?}", peers_to_dial);
    }

    // Подписываемся на топик
    if let Err(e) = swarm.behaviour_mut().subscribe(&topic) {
        warn!("Failed to subscribe to topic: {:?}", e);
    }

    println!("Ready. Commands: dial <multiaddr>, peers, quit, <text to publish>");

    let mut stdin_lines = io::BufReader::new(io::stdin()).lines();
    let mut pending_initial_peers = peers_to_dial;

    loop {
        tokio::select! {
            line = stdin_lines.next_line() => {
                if let Ok(Some(text)) = line {
                    let text = text.trim();
                    if text.is_empty() { continue; }

                    if text == "quit" { println!("Exiting..."); break; }

                    if text == "peers" {
                        println!("Known peers:");
                        for p in swarm.behaviour().all_peers() {
                            println!("  {}", p.0);
                        }
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

                    // Publish message
                    let behaviour = swarm.behaviour_mut();
                    let _msgid = behaviour.publish(topic.clone(), text.as_bytes()).unwrap_or_else(|e| {
                        eprintln!("Publish error: {:?}", e);
                        MessageId::from(vec![])
                    });

                }
            }

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on {:?}", address);
                        // Dial initial peers once listen is up
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
                                let text = String::from_utf8_lossy(&message.data);
                                println!("<<< {}: {}", propagation_source, text);
                            }
                            Event::Subscribed { peer_id, topic } => {
                                println!("Peer {} subscribed to {:?}", peer_id, topic);
                            }
                            Event::Unsubscribed { peer_id, topic } => {
                                println!("Peer {} unsubscribed from {:?}", peer_id, topic);
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

async fn read_line(lines: &mut io::Lines<io::BufReader<tokio::io::Stdin>>) -> Result<String, Box<dyn Error>> {
    if let Some(line) = lines.next_line().await? {
        Ok(line)
    } else {
        Ok(String::new())
    }
}
