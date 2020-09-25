use std::error::Error;
use mio::net::{ TcpStream, UdpSocket};
use mio::{Events, Interest, Poll, Token};
use std::io::{Read, Write};
use hex;
use rand::{thread_rng, Rng};
use keccak_hash::keccak;
use secp256k1::{SecretKey, PublicKey, Message, RecoveryId, Signature, sign, recover};
use rlp::{Rlp, RlpStream};
use std::collections::VecDeque;
use std::net::{ SocketAddr };
use tokio::net::{ TcpListener, UdpSocket as TokioUdp};
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver, self};
use tokio::time::{delay_for, Duration};
use std::cell::Cell;
use crate::message::{self, PeerInfo};


fn print_message_type(message_type: u8) {
    match message_type {
        0x01 => {
            println!("ping message");
        },

        0x02 => {
            println!("pong message");
        },

        0x03 => {
            println!("find neighbours message");
        },

        0x04 => {
            println!("neighbours message");
        },

        _ => {
            println!("unknow message");
        },
    }
}

struct NodePoint {
    version: u8,
    pubkey: PublicKey,
}

pub struct Peer {
    addr: SocketAddr,
    local_addr: SocketAddr,
    private_key: SecretKey,
    version: Cell<u8>,
    tx: Option<UnboundedSender<Vec<u8>>>,
}

impl Peer {
    pub fn new(addr: SocketAddr, private_key: SecretKey) -> Self {
        let local_udp_addr: SocketAddr = "192.168.31.125:30309".parse().unwrap();

        Self {
            addr,
            local_addr: local_udp_addr,
            private_key,
            version: Cell::new(0),
            tx: None,
        }
    }

    pub fn on_packet(&self, message_type: u8, rlp: Rlp, read_buf: &[u8], pubkey: PublicKey) -> Result<(), Box<dyn Error>> {
        let local_addr = &self.local_addr;
        let tx = self.tx.as_ref().unwrap();

        if message_type == 0x01 {
            // got a ping message
            let version: u8 = rlp.val_at(0)?;
            let from_peer = PeerInfo::decode_rlp(&rlp.at(1)?)?;
            let to_peer = PeerInfo::decode_rlp(&rlp.at(2)?)?;
            println!("from_peer = {:?}, to_peer = {:?}", from_peer, to_peer);
            let timestamp: u64 = rlp.val_at(3)?;
            println!("version = {:?}, timestamp = {:?}", version, timestamp);

            // send pong message
            let from = PeerInfo::from_sock_addr(&local_addr);
            let bytes = message::encode_pong(&from, &read_buf[0..32].to_vec(), &timestamp, &self.private_key);
            println!("pong bytes is {:?}", bytes.len());

            self.version.set(version);
            tx.send(bytes);

        } else if message_type == 0x02 {
            // got a pong message
            let from_peer = PeerInfo::decode_rlp(&rlp.at(0)?)?;
            let hash_bytes = rlp.at(1)?.data()?;
            let timestamp: u64 = rlp.val_at(2)?;
            println!("got a pong message {:?} {:?}", from_peer, timestamp);

            // start send findneighbours packet
            let bytes = message::encode_find_node(&self.private_key);
            println!("find node bytes is {:?}", bytes.len());

            tx.send(bytes);

        } else if message_type == 0x03 {
            println!("got a find node message");
        } else if message_type == 0x04 {
            let version = self.version.get();

            println!("got a node message, self.version is {:?}", version);

            let list: Vec<PeerInfo> = rlp.list_at(0)?;
            let timestamp: u64 = rlp.val_at(1)?;
            println!("list is {:?}, total is {:?}", list, timestamp);
        }

        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let upd_server_addr = &self.addr;
        let private_key = &self.private_key;
        let local_udp_addr = &self.local_addr;

        let mut socket = TokioUdp::bind(local_udp_addr).await?;
        socket.connect(&upd_server_addr).await?;

        let (mut reader, mut writer) = socket.split();

        const MAX_DATAGRAM_SIZE: usize = 65_507;

        let peer = PeerInfo::from_sock_addr(&upd_server_addr);
        let local_peer = PeerInfo::from_sock_addr(&local_udp_addr);

        let (mut tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

        self.tx = Some(tx.clone());

        tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                let size = writer.send(&buf).await.unwrap();
                println!("send {:?} bytes of {:?} bytes", size, buf.len());
            }
        });

        let local_peer1 = local_peer.clone();
        let peer1 = peer.clone();
        let private_key1 = self.private_key.clone();

        tokio::spawn(async move {
            loop {
                let ping = message::encode_ping(&local_peer1, &peer1, &private_key1);
                tx.send(ping);
                delay_for(Duration::from_millis(5_000)).await;
            }
        });

        loop {
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            let size = reader.recv(&mut buf).await?;

            if size > 0 {
                let read_buf = &buf[..size];
                let hash_signed = keccak(&read_buf[32..]);
                let signed = &read_buf[(32 + 65)..];
                let message_type = signed[0];

                let recover_id = RecoveryId::parse(read_buf[32 + 64]).expect("can not get recover id");
                let signature = Signature::parse_slice(&read_buf[32..(32 + 64)]).expect("can not get signature");
                let hash = keccak(signed);
                let pubkey = recover(&Message::parse_slice(&hash).unwrap(), &signature, &recover_id).expect("can not recover pubkey");

                println!("pubkey is {:?}", hex::encode(&pubkey.serialize().to_vec()));
                let rlp = Rlp::new(&signed[1..]);

                match self.on_packet(message_type, rlp, read_buf, pubkey) {
                    Err(err) => {
                        println!("on packet error: {:?}", err);
                    },
                    _ => {}
                }
            }
            println!("recv {:?} bytes", size);
        }
    }
}
