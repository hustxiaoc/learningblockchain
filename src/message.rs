use byteorder::{LittleEndian, BigEndian, WriteBytesExt};
use std::mem;
use std::net::{IpAddr, Ipv6Addr, Ipv4Addr, SocketAddr};
use rlp::{Rlp, RlpStream, Decodable, DecoderError};
use std::time::{ SystemTime, Duration, UNIX_EPOCH};
use keccak_hash::keccak;
use secp256k1::{SecretKey, PublicKey, Message, sign};
use std::error::Error;
use std::slice;

const EXPIRY_TIME: Duration = Duration::from_secs(20);

#[derive(Debug, Clone)]
pub struct PeerInfo {
    ip: IpAddr,
    udp_port: u16,
    tcp_port: u16,
}

impl Decodable for PeerInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Self::decode_rlp(rlp).map_err(|err| {
            println!("{:?}", err);
            DecoderError::Custom("rlp decode peer error")
        })
    }
}

pub type RlpItem = Vec<u8>;
pub type RlpList = Vec<RlpItem>;

impl PeerInfo {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            ip: ip,
            tcp_port: port,
            udp_port: port,
        }
    }

    pub fn from_sock_addr(addr: &SocketAddr) -> Self {
        Self {
            ip: addr.ip(),
            tcp_port: addr.port(),
            udp_port: addr.port(),
        }
    }

    pub fn encode_rlp(&self, rlp: &mut RlpStream) {
        rlp.begin_list(3);
        rlp.append(&self.get_ip_bytes());
        rlp.append(&int_u16_2buttfer(self.udp_port).to_vec());
        rlp.append(&int_u16_2buttfer(self.tcp_port).to_vec());
    }

    pub fn decode_rlp(r: &Rlp) -> Result<Self, Box<dyn Error>> {
        let addr_bytes = r.at(0)?.data()?;
        let udp_port:u16 = r.val_at(1)?;
        let tcp_port:u16 = r.val_at(2)?;

        let addr = match addr_bytes.len() {
            4 => {
                // IpAddr::V4(addr_bytes.into())
                IpAddr::V4(Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]))
            },

            16 => {
                // IpAddr::V6(addr_bytes.into())
                unsafe {
                    let o: *const u16 = addr_bytes.as_ptr() as *const u16;
                    let o = slice::from_raw_parts(o, 8);
                    IpAddr::V6(Ipv6Addr::new(
                        o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]
                    ))
                }
            },

            _ => {
                return Err("decode error".into());
            }
        };

        Ok(Self {
            ip: addr,
            tcp_port,
            udp_port,
        })
    }

    pub fn get_ip_bytes(&self) -> Vec<u8> {
        match self.ip {
            IpAddr::V4(ipv4) => {
                ipv4.octets().to_vec()
            },
            IpAddr::V6(ipv6) => {
                ipv6.octets().to_vec()
            },
        }
    }
}

fn int_u16_2buttfer(number: u16) -> [u8; 2] {
    let mut bs = [0u8; mem::size_of::<u16>()];
    bs.as_mut().write_u16::<BigEndian>(number).expect("unable to write");
    bs
}

fn int_u32_2buttfer(number: u32) -> [u8; 4] {
    let mut bs = [0u8; mem::size_of::<u32>()];
    bs.as_mut().write_u32::<BigEndian>(number).expect("unable to write");
    bs
}

pub fn encode_ping(from: &PeerInfo, to: &PeerInfo, secret: &SecretKey) -> Vec<u8>  {
    let version: u8 = 0x04;
    let message_type = 0x01; // ping

    let mut rlp = RlpStream::new_list(4);
    rlp.append(&version);
    from.encode_rlp(&mut rlp);
    to.encode_rlp(&mut rlp);

    let expiry = SystemTime::now() + EXPIRY_TIME;
    let timestamp = expiry.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as u32;
    rlp.append(&timestamp);

    let payload = rlp.drain();

    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(message_type);
    bytes.extend_from_slice(&payload);

    let sighash = keccak(&bytes);

    let (signature, cecoveryId) = match sign(&Message::parse_slice(&sighash).unwrap(), secret) {
        Ok(s) => s,
        Err(e) => {
            panic!("sign error {:?}", e);
        }
    };

    let mut hashdata: Vec<u8> = Vec::new();
    hashdata.extend_from_slice(&signature.serialize());
    hashdata.push(cecoveryId.serialize());
    hashdata.extend_from_slice(&bytes);
    let hash = keccak(&hashdata);

    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&hash);
    bytes.extend_from_slice(&hashdata);

    bytes
}

pub fn encode_pong(from: &PeerInfo, hashbuf: &Vec<u8>, timestamp: &u64, secret: &SecretKey) -> Vec<u8> {
    let message_type = 0x02; // ping

    let mut response = RlpStream::new_list(3);
    from.encode_rlp(&mut response);
    response.append(hashbuf);
    response.append(timestamp);
    let payload = response.drain();


    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(message_type);
    bytes.extend_from_slice(&payload);

    let sighash = keccak(&bytes);

    let (signature, cecoveryId) = match sign(&Message::parse_slice(&sighash).unwrap(), secret) {
        Ok(s) => s,
        Err(e) => {
            panic!("sign error {:?}", e);
        }
    };

    let mut hashdata: Vec<u8> = Vec::new();
    hashdata.extend_from_slice(&signature.serialize());
    hashdata.push(cecoveryId.serialize());
    hashdata.extend_from_slice(&bytes);
    let hash = keccak(&hashdata);

    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&hash);
    bytes.extend_from_slice(&hashdata);

    bytes
}

pub fn encode_find_node(secret: &SecretKey) -> Vec<u8> {
    let pubkey = PublicKey::from_secret_key(&secret);
    let id = &pubkey.serialize().to_vec()[1..];

    let message_type = 0x03; // find node

    let mut response = RlpStream::new_list(2);
    response.append(&id);
    let expiry = SystemTime::now() + EXPIRY_TIME;
    let timestamp = expiry.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as u32;
    response.append(&timestamp);

    let payload = response.drain();


    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(message_type);
    bytes.extend_from_slice(&payload);

    let sighash = keccak(&bytes);

    let (signature, cecoveryId) = match sign(&Message::parse_slice(&sighash).unwrap(), secret) {
        Ok(s) => s,
        Err(e) => {
            panic!("sign error {:?}", e);
        }
    };

    let mut hashdata: Vec<u8> = Vec::new();
    hashdata.extend_from_slice(&signature.serialize());
    hashdata.push(cecoveryId.serialize());
    hashdata.extend_from_slice(&bytes);
    let hash = keccak(&hashdata);

    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&hash);
    bytes.extend_from_slice(&hashdata);

    bytes
}
