use std::error::Error;
use std::io::{Read, Write};
use hex;
use byteorder::{LittleEndian, BigEndian, WriteBytesExt};
use rand::{thread_rng, Rng};
use keccak_hash::{keccak, write_keccak};
use secp256k1::{SecretKey, PublicKey, Message, RecoveryId, Signature};
use rlp::{Rlp, RlpStream};
use std::collections::VecDeque;
use std::net::{ SocketAddr };
use tokio::net::{ TcpStream, TcpListener};
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver, self};
use tokio::time::{delay_for, Duration};
use tokio::io::{self, split, ReadHalf, WriteHalf, AsyncReadExt, AsyncWriteExt};
use parity_crypto::publickey::{Generator, KeyPair, Public, Random, recover, Secret, sign, ecdh, ecies};
use parity_crypto::aes::{AesCtr256, AesEcb256};
use ethereum_types::{H128, H256, H512};
use std::future::Future;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::cell::{Cell, RefCell};
use std::cmp::PartialEq;
use bytes::{Buf, BufMut};
use tiny_keccak::{Keccak, Hasher};
use crate::message::{self, PeerInfo};
use parity_bytes::Bytes;

// Auth, Ack, Header, Body
#[derive(Clone, Copy, PartialEq)]
enum NodeState {
    Auth,
    Ack,
    Header,
    Body,
    Closed,
}

type Tx = UnboundedSender<Vec<u8>>;
type Rx = UnboundedReceiver<Vec<u8>>;

pub struct  Node {
    addr: SocketAddr,
    pubkey: Public,
    ecdhe: KeyPair,
    key: KeyPair,
    nonce: H256,
    secret: Secret,
    state: Cell<NodeState>,
    tx: Option<Tx>,
    id: Public,
    remote_ephemeral_public_key: RefCell<Public>,
    remote_nonce: RefCell<H256>,
    encoder: RefCell<Option<AesCtr256>>,
	decoder: RefCell<Option<AesCtr256>>,
    auth_cipher: Vec<u8>,
    ack_cipher: Vec<u8>,
    mac_encoder_key: Secret,
	/// MAC for egress data
	egress_mac: Keccak,
	/// MAC for ingress data
	ingress_mac: Keccak,
}

const NULL_IV : [u8; 16] = [0;16];
const ENCRYPTED_HEADER_LEN: usize = 32;
const RECEIVE_PAYLOAD: Duration = Duration::from_secs(30);
pub const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1; // 16Mb

/// Network responses should try not to go over this limit.
/// This should be lower than MAX_PAYLOAD_SIZE
pub const PAYLOAD_SOFT_LIMIT: usize = (1 << 22) - 1; // 4Mb
const HEADER_LEN: usize = 16;

const PACKET_HELLO: u8 = 0x80;
const PACKET_DISCONNECT: u8 = 0x01;
const PACKET_PING: u8 = 0x02;
const PACKET_PONG: u8 = 0x03;
const PACKET_GET_PEERS: u8 = 0x04;
const PACKET_PEERS: u8 = 0x05;
const PACKET_USER: u8 = 0x10;
const PACKET_LAST: u8 = 0x7f;

impl Node {
    pub fn new(addr: SocketAddr, pubkey: Public, secret: Secret, id: PublicKey) -> Self {
        let mut arr = [0u8; 32];
        thread_rng().fill(&mut arr[..]);
        let nonce = H256::from_slice(&arr);

        Self {
            ecdhe: Random.generate(),
            key: Random.generate(),
            addr,
            pubkey,
            nonce,
            secret,
            state: Cell::new(NodeState::Auth),
            tx: None,
            id: Public::from_slice(&id.serialize().to_vec()[1..]),
            remote_ephemeral_public_key: RefCell::new(Public::default()),
            remote_nonce: RefCell::new(H256::zero()),
            encoder: RefCell::new(None),
            decoder: RefCell::new(None),
            auth_cipher: vec![],
            ack_cipher: vec![],

            mac_encoder_key: Secret::from(nonce),
        	/// MAC for egress data
        	egress_mac: Keccak::v256(),
        	/// MAC for ingress data
        	ingress_mac: Keccak::v256(),
        }
    }

    fn encode_frame(message_code: u64, data: &[u8]) {
        let ptype = rlp::encode(&message_code);
        let mut header_buf = [0u8; 16];
        let fsize = (ptype.len() + data.len()) as u32;

        // fsize must < maxUint24 frame size
        header_buf[0] = (fsize >> 16) as u8;
        header_buf[1] = (fsize >> 8) as u8;
        header_buf[2] = (fsize) as u8;

        // extend header data = [0, 0]  rlp.encode([0, 0]) which is [0xc2, 0x80, 0x80];
        header_buf[3] = 0xC2;
        header_buf[4] = 0x80;
        header_buf[5] = 0x80;

        // 0xC2, 0x80, 0x80

        // write header

        // message.extend_from_slice(data);

    }

    /// Update MAC after reading or writing any data.
	fn update_mac(mac: &mut Keccak, mac_encoder_key: &Secret, seed: &[u8]) -> Result<(), Box<dyn Error>> {
		let mut prev = H128::default();
		mac.clone().finalize(prev.as_bytes_mut());
		let mut enc = H128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());
		let mac_encoder = AesEcb256::new(mac_encoder_key.as_bytes())?;
		mac_encoder.encrypt(enc.as_bytes_mut())?;

		enc = enc ^ if seed.is_empty() { prev } else { H128::from_slice(seed) };
		mac.update(enc.as_bytes());
		Ok(())
	}

    /// Send a packet
	pub fn encode_packet(&mut self, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
		let mut header = RlpStream::new();
		let len = payload.len();
		if len > MAX_PAYLOAD_SIZE {
			return Err("Error::OversizedPacket".into());
		}

		header.append_raw(&[(len >> 16) as u8, (len >> 8) as u8, len as u8], 1);
		header.append_raw(&[0xc2u8, 0x80u8, 0x80u8], 1);
		let padding = (16 - (len % 16)) % 16;

		let mut packet = vec![0u8; 16 + 16 + len + padding + 16];
		let mut header = header.out();
		header.resize(HEADER_LEN, 0u8);
		&mut packet[..HEADER_LEN].copy_from_slice(&mut header);
		self.encoder.borrow_mut().as_mut().unwrap().encrypt(&mut packet[..HEADER_LEN])?;
		Self::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &packet[..HEADER_LEN])?;
		self.egress_mac.clone().finalize(&mut packet[HEADER_LEN..32]);
		&mut packet[32..32 + len].copy_from_slice(payload);
		self.encoder.borrow_mut().as_mut().unwrap().encrypt(&mut packet[32..32 + len])?;
		if padding != 0 {
			self.encoder.borrow_mut().as_mut().unwrap().encrypt(&mut packet[(32 + len)..(32 + len + padding)])?;
		}
		self.egress_mac.update(&packet[32..(32 + len + padding)]);
		Self::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &[0u8; 0])?;
		self.egress_mac.clone().finalize(&mut packet[(32 + len + padding)..]);
		// self.connection.send(io, packet);

		Ok(packet)
	}

    /// Decrypt and authenticate an incoming packet header. Prepare for receiving payload.
	fn read_header(&mut self, mut header: Bytes) -> Result<(usize), Box<dyn Error>> {
		if header.len() != ENCRYPTED_HEADER_LEN {
			return Err("Error::Auth".into());
		}
		Self::update_mac(&mut self.ingress_mac, &self.mac_encoder_key, &header[0..16])?;
		let mac = &header[16..];
		let mut expected = H256::zero();
		self.ingress_mac.clone().finalize(expected.as_bytes_mut());
		if mac != &expected[0..16] {
			return Err("Error::Auth".into());
		}

		self.decoder.borrow_mut().as_mut().unwrap().decrypt(&mut header[..16])?;

		let length = ((((header[0] as u32) << 8) + (header[1] as u32)) << 8) + (header[2] as u32);
		let header_rlp = Rlp::new(&header[3..6]);
		let protocol_id = header_rlp.val_at::<u16>(0)?;

		// self.payload_len = length as usize;
		// self.protocol_id = protocol_id;
		// self.read_state = EncryptedConnectionState::Payload;

		let padding = (16 - (length % 16)) % 16;
		let full_length = length + padding + 16;

        println!("expect to read {:?} bytes", full_length);
		// self.connection.expect(full_length as usize);
		Ok(full_length as usize)
	}

	/// Decrypt and authenticate packet payload.
	fn read_payload(&mut self, mut payload: Bytes, payload_len: usize) -> Result<(), Box<dyn Error>> {
		let padding = (16 - (payload_len  % 16)) % 16;
		let full_length = payload_len + padding + 16;
		if payload.len() != full_length {
			return Err("Error::Auth".into());
		}
		self.ingress_mac.update(&payload[0..payload.len() - 16]);
		Self::update_mac(&mut self.ingress_mac, &self.mac_encoder_key, &[0u8; 0])?;

		let mac = &payload[(payload.len() - 16)..];
		let mut expected = H128::default();
		self.ingress_mac.clone().finalize(expected.as_bytes_mut());
		if mac != &expected[..] {
			return Err("Error::Auth".into());
		}
		self.decoder.borrow_mut().as_mut().unwrap().decrypt(&mut payload[..payload_len + padding])?;
		payload.truncate(payload_len);
		// Ok(Packet {
		// 	protocol: self.protocol_id,
		// 	data: payload
		// })
        Ok(())
	}

    async fn send_hello(&mut self, writer: &mut WriteHalf<TcpStream>) -> Result<(), Box<dyn Error>> {
        // let mut rlp = RlpStream::new_list(5);
        // let client_id = "learning block chain and rust/rust";
        // rlp.append(&(4 as u8));
        // rlp.append(&client_id);
        // rlp.begin_list(2);
        // rlp.append(&message::Capabilitiy{
        //     name: "eth".into(),
        //     version: 62,
        // });
        //
        // rlp.append(&message::Capabilitiy{
        //     name: "eth".into(),
        //     version: 63,
        // });
        // let port: u8 = 0;
        //
        // rlp.append(&port);
        // rlp.append(&self.key.public().as_bytes());
        //
        // let bytes = rlp.drain();
        //
        // let mut bs = [0u8; std::mem::size_of::<u32>()];
        // bs.as_mut().write_u32::<BigEndian>(bytes.len() as u32).expect("unable to write");
        // let mut buf: Vec<u8> = Vec::new();
        // buf.extend_from_slice(&bs[1..]);
        //
        // let mut rlp = RlpStream::new_list(2);
        // rlp.append(&port);
        // rlp.append(&port);
        //
        // buf.extend_from_slice(&rlp.drain());

        let protocol_version :u32 = 4;
        let port: u32 = 0;
        let client_version = "learning block chain and rust/rust";
        let capabilities: Vec<message::CapabilityInfo> = vec![
            message::CapabilityInfo {
                protocol: [65, 74, 68],
                version: 62,
            },

            message::CapabilityInfo {
                protocol: [65, 74, 68],
                version: 63,
            },
        ];

        let mut rlp = RlpStream::new();
		rlp.append_raw(&[PACKET_HELLO as u8], 0);
		rlp.begin_list(5)
			.append(&protocol_version)
			.append(&client_version)
			.append_list(&capabilities)
			.append(&port)
			.append(&self.key.public().as_bytes());

        match writer.write(&self.encode_packet(&rlp.drain()).unwrap()).await {
            Ok(size) => {
                println!("send hello ok with {:?} bytes", size);
            },
            Err(err) => {
                println!("send hello error {:?}", err);
            }
        };

        Ok(())
    }

    async fn send_auth(&mut self, writer: &mut WriteHalf<TcpStream>) -> Result<(), Box<dyn Error>> {
        let mut data = [0u8; /*Signature::SIZE*/ 65 + /*H256::SIZE*/ 32 + /*Public::SIZE*/ 64 + /*H256::SIZE*/ 32 + 1]; //TODO: use associated constants
    	let len = data.len();

        data[len - 1] = 0x0;
        let (sig, rest) = data.split_at_mut(65);
        let (hepubk, rest) = rest.split_at_mut(32);
        let (pubk, rest) = rest.split_at_mut(64);
        let (nonce, _) = rest.split_at_mut(32);

        // E(remote-pubk, S(ecdhe-random, ecdh-shared-secret^nonce) || H(ecdhe-random-pubk) || pubk || nonce || 0x0)
        let shared = *ecdh::agree(&self.key.secret(), &self.pubkey)?;
        sig.copy_from_slice(&*sign(self.ecdhe.secret(), &(shared ^ self.nonce))?);
        write_keccak(self.ecdhe.public(), hepubk);
        pubk.copy_from_slice(self.key.public().as_bytes());
        nonce.copy_from_slice(self.nonce.as_bytes());
    	let message = ecies::encrypt(&self.pubkey, &[], &data)?;

        match writer.write(&message).await {
            Ok(size) => {
                println!("write {:?} bytes of {:?}", size, message.len());
                self.auth_cipher = message;
            },
            Err(err) => {
                println!("send auth write error {:?}", err);
            }
        }

        // self.tx.as_ref().unwrap().send(message);
        //
        // {
        //     let shared = *ecdh::agree(&self.secret, &self.pubkey)?;
        //     let sig = *sign(self.ecdhe.secret(), &(shared ^ self.nonce))?;
        //     let version = [0x04];
        //     let mut rlp = RlpStream::new_list(4);
        //     rlp.append(&sig.to_vec());
        //     rlp.append(&self.pubkey);
        //     rlp.append(&self.nonce);
        //     rlp.append(&version.to_vec());
        //     let mut auth_data: Vec<u8> = rlp.drain();
        //
        //     let mut arr = [0u8; 200];
        //     thread_rng().fill(&mut arr[..]);
        //
        //     auth_data.extend_from_slice(&arr);
        //     let shared_data = auth_data.len() + 113;
        //
        //     let mut bs = [0u8; std::mem::size_of::<u16>()];
        //     bs.as_mut().write_u16::<BigEndian>(shared_data as u16).expect("unable to write");
        //     let message = ecies::encrypt(&self.pubkey, &bs, &auth_data)?;
        //     writer.write(&message).await?;
        // }
        Ok(())
    }

    async fn read(&mut self, stream: &mut ReadHalf<TcpStream>) {
        let mut buf = vec![0u8; 1024];
        match stream.read(&mut buf).await {
            Ok(size) => {
                if size == 0 {
                    // println!("server socket closed");
                    self.state.set(NodeState::Closed);
                    return;
                }

                let buf = &buf[..size];

                // parse header first
                // let mut header: Bytes = &buf[..32].to_vec();
                let payload_size = self.read_header(buf[..32].to_vec()).unwrap();
                let left_size = payload_size - (buf.len() - 32);

                // we don't have to read payload
                if left_size == 0 {

                }

                let mut payload_buf: Vec<u8> = Vec::with_capacity(left_size);
                match stream.read_exact(&mut payload_buf).await {
                    Ok(size) => {
                        println!("read left_size {:?} bytes of {:?}", size, left_size);
                    },
                    Err(err) => {
                        println!("read error {:?}", err);
                    }
                };

                println!("{:?}", buf[0]);
                println!("read {:?} bytes", size);
            },
            Err(err) => {
                println!("read error {:?}", err);
            }
        }
    }

    fn handle_header(&self, buf: &[u8]) {
        let header = &buf[..16];
        let mac = &buf[16..32];
    }

    async fn write(&self, rx: &mut Rx, stream: &mut WriteHalf<TcpStream>) {
        if let Some(buf) = rx.recv().await {
            let size = stream.write(&buf).await.unwrap();
            println!("send {:?} bytes of {:?} bytes", size, buf.len());
        }
    }

    async fn read_auth_ack(&mut self, stream: &mut ReadHalf<TcpStream>) -> Result<(), Box<dyn Error>> {
        let mut buf = vec![0u8; 1024];
        match stream.read(&mut buf).await {
            Ok(size) => {
                if size == 0 {
                    // println!("server socket closed");
                    self.state.set(NodeState::Closed);
                    return Err("socket closed".into());
                }

                println!("read auth ack got {:?} bytes", size);
                let buf = &buf[..size];

                let message = ecies::decrypt(&self.key.secret(), &[], buf).expect("handle_ack decrypt error");

                self.ack_cipher = buf.to_vec();

                let mut pub_key = Vec::new();
                pub_key.push(0x04);
                pub_key.extend_from_slice(&message[..64]);

                let remote_ephemeral_public_key = H512::from_slice(&message[..64]);
                let remote_nonce = H256::from_slice(&message[64..96]);
                // *self.remote_ephemeral_public_key.borrow_mut() = remote_ephemeral_public_key;
                // *self.remote_nonce.borrow_mut() = H256::from_slice(&message[64..96]);

                // set up encoder and decorder
                let shared = *ecdh::agree(&self.ecdhe.secret(), &remote_ephemeral_public_key).unwrap();
                let mut nonce_material = H512::default();
                (&mut nonce_material[0..32]).copy_from_slice(remote_nonce.as_bytes());
			    (&mut nonce_material[32..64]).copy_from_slice(self.nonce.as_bytes());

                let mut key_material = H512::default();
        		(&mut key_material[0..32]).copy_from_slice(shared.as_bytes());
        		write_keccak(&nonce_material, &mut key_material[32..64]);
        		let key_material_keccak = keccak(&key_material);
        		(&mut key_material[32..64]).copy_from_slice(&key_material_keccak);
        		let key_material_keccak = keccak(&key_material);
        		(&mut key_material[32..64]).copy_from_slice(&key_material_keccak);

        		// Using a 0 IV with CTR is fine as long as the same IV is never reused with the same key.
        		// This is the case here: ecdh creates a new secret which will be the symmetric key used
        		// only for this session the 0 IV is only use once with this secret, so we are in the case
        		// of same IV use for different key.
        		let encoder = AesCtr256::new(&key_material[32..64], &NULL_IV)?;
        		let decoder = AesCtr256::new(&key_material[32..64], &NULL_IV)?;
                let key_material_keccak = keccak(&key_material);

        		(&mut key_material[32..64]).copy_from_slice(&key_material_keccak);
        		let mac_encoder_key: Secret = Secret::copy_from_slice(&key_material[32..64]).expect("can create Secret from 32 bytes; qed");

        		let mut egress_mac = Keccak::v256();
        		let mut mac_material = H256::from_slice(&key_material[32..64]) ^ remote_nonce;
        		egress_mac.update(mac_material.as_bytes());
        		egress_mac.update(&self.auth_cipher);

        		let mut ingress_mac = Keccak::v256();
        		mac_material = H256::from_slice(&key_material[32..64]) ^ self.nonce;
        		ingress_mac.update(mac_material.as_bytes());
        		ingress_mac.update(&self.ack_cipher);

                self.mac_encoder_key = mac_encoder_key;
                self.ingress_mac = ingress_mac;
                self.egress_mac = egress_mac;

                *self.encoder.borrow_mut() = Some(encoder);
                *self.decoder.borrow_mut() = Some(decoder);

                // const sharedSecret = keccak256(this._ephemeralSharedSecret, hNonce);
            },
            Err(err) => {
                println!("read error {:?}", err);
            }
        }

        Ok(())
    }

    pub async fn connect(&mut self) -> Result<(), Box<dyn Error>> {

        let stream = TcpStream::connect(self.addr.clone()).await?;
        let (mut reader, mut writer) = split(stream);
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

        self.tx = Some(tx);

        // send auth
        self.send_auth(&mut writer).await?;
        println!("send auth ok");

        // read auth-ack
        self.read_auth_ack(&mut reader).await?;
        println!("read auth ack ok");

        // send first hello world encrypted message
        self.send_hello(&mut writer).await?;

        loop {
            match self.state.get() {
                NodeState::Closed => {
                    println!("socket is closed");
                    break;
                },

                NodeState::Auth => {

                    self.state.set(NodeState::Ack);
                },

                _ => {

                }
            };

            self.read(&mut reader).await;

            // we don't have to call tokio::spawn in this way

            // tokio::select! {
            //     _ = self.write(&mut rx, &mut writer) => {
            //         println!("write");
            //     },
            //
            //     _ = self.read(&mut reader) => {
            //         println!("read");
            //     }
            // }
        }


        Ok(())
    }
}
