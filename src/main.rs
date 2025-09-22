use anyhow::Result;
use futures::prelude::*;
use libp2p::{
    Multiaddr, PeerId, Swarm,
    gossipsub::{
        Behaviour as Gossipbehaviour, Config as GossipsubConfig, MessageAuthenticity, Topic,
        TopicHash, IdentTopic, ConfigBuilder as GossipsubConfigBuilder
    },
    identity,
    noise::Config as NoiseConfig,
    swarm::{SwarmEvent, Config as SwarmConfig, },
    tcp::{Config as TcpConfig, tokio::Transport as TcpTransport},
    yamux::Config as YamuxConfig,
};

use libp2p::core::transport::{Transport as TransportTrait, upgrade};

use std::{env, error::Error};
use std::time::Duration;
use libp2p::gossipsub::{Event, MessageId, ValidationMode};
use tokio::io::{self, AsyncBufReadExt};

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let id_keys = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(id_keys.public());
    println!("Bootstrap PeerId: {}", local_peer_id);

    let tcp_transport = TcpTransport::new(TcpConfig::default());
    let noise_config = NoiseConfig::new(&id_keys).unwrap();
    let yamux_config = YamuxConfig::default();

    let transport = tcp_transport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(yamux_config)
        .boxed();

    // Gossipsub (bootstrap tuned)
    let gossipsub_cfg = GossipsubConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        .flood_publish(true)
        .do_px() // enable PX on bootstrap
        .prune_peers(32)
        .prune_backoff(Duration::from_secs(60))
        .gossip_factor(0.33)
        .opportunistic_graft_ticks(30)
        .opportunistic_graft_peers(4)
        .build()
        .unwrap();

    let gossipbehaviour: Gossipbehaviour = match Gossipbehaviour::new(MessageAuthenticity::Signed(id_keys), gossipsub_cfg) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("gossipsub init error: {:?}", e);
            return Err(e.into());
        }
    };

    let topic = IdentTopic::new("forum/autos/board/general");
    let swarm_config = SwarmConfig::with_tokio_executor();
    let mut swarm = Swarm::new(transport, gossipbehaviour, local_peer_id, swarm_config);

    // Listen on 0.0.0.0:APP_PORT
    let app_port: u16 = env::var("APP_PORT")
        .unwrap_or_else(|_| "9000".into())
        .parse()
        .unwrap_or(9000);
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", app_port).parse()?;
    swarm.listen_on(listen_addr)?;

    let mut peers_to_dial: Vec<Multiaddr> = Vec::new();
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
        println!("Will attempt to dial peers from env/args: {:?}", peers_to_dial);
    }

    let mut pending_initial_peers = peers_to_dial;

    // stdin loop
    let mut stdin = io::BufReader::new(io::stdin()).lines();
    println!("Ready. Type messages to publish to gossipsub topic 'forum/autos/board/general'.");
    println!("Commands:");
    println!("  dial <multiaddr>   — attempt to dial a peer");
    println!("  peers              — print known peers from behaviour");
    println!("  <any text>         — publish text to topic");

    // subscribe
    let res = swarm.behaviour_mut().subscribe(&topic);
    if res.is_err() {
        println!("Failed to subscribe to topic 'forum/autos/board/general'.");
    }

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                if let Ok(Some(text)) = line {
                    let text = text.trim();
                    if text.is_empty() { continue; }

                    if text == "peers" {
                        println!("Known peers (via gossipsub behaviour):");
                        for p in swarm.behaviour().all_peers() {
                            println!("  {}", p.0);
                        }
                        continue;
                    }

                    if text.starts_with("dial ") {
                        let addr_str = text["dial ".len()..].trim();
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

                    // publish
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
                        println!("Listening on {:?}", address);
                        // Dial initial peers once listen is up
                        if !pending_initial_peers.is_empty() {
                            for ma in pending_initial_peers.drain(..) {
                                match swarm.dial(ma.clone()) {
                                    Ok(_) => println!("Dialing initial peer {}", ma),
                                    Err(e) => eprintln!("Dial error {}: {:?}", ma, e),
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
                                println!("Other gossipsub event: {:?}", other);
                            }
                        }
                    }

                    other => {
                        println!("SwarmEvent: {:?}", other);
                    }
                }
            }
        }
    }

    // never reached
    // Ok(())
}
