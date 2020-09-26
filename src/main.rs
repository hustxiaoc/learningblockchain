use std::error::Error;
use std::io::{Read, Write};
use hex;
use rand::{thread_rng, Rng};
use keccak_hash::{keccak, write_keccak};
use secp256k1::{SecretKey, PublicKey, Message, RecoveryId, Signature};
use rlp::{Rlp, RlpStream};
use std::collections::VecDeque;
use std::net::{ SocketAddr };
use tokio::net::{ TcpStream, TcpListener};
use tokio::sync::mpsc;
use tokio::time::{delay_for, Duration};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use parity_crypto::publickey::{Generator, KeyPair, Public, Random, recover, Secret, sign, ecdh, ecies};
use ethereum_types::{H256, H512};

mod peer;
mod message;
mod dht;
mod node;

use node::Node;
use dht::DHT;
use peer::Peer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arr = [0u8; 32];
    thread_rng().fill(&mut arr[..]);

    let pk = hex::decode("ee5495585eff78f2fcf95bab21ef1a598c54d1e3c672e23b3bb97a4fc7490660").unwrap();
    let private_key = SecretKey::parse_slice(&pk).unwrap();
    let public_key = PublicKey::from_secret_key(&private_key);
    // let id = &public_key.serialize().to_vec()[1..];

    let secret = Secret::from(H256::from_slice(&pk));

    let remote_pubkey = hex::decode("041f17e484e66c988e46e23007d343b3702f91018c5c2337591521444d8d97e43bb8942d0846c48d7feb0b98cd3fd34eb0be925369d131b58fb5332774297b4ae3").unwrap();

    let my_id = H512::from_slice(&remote_pubkey[1..]);

    // let node_addr: SocketAddr = "35.180.217.147:30304".parse()?;
    let addr: SocketAddr = "192.168.88.120:30303".parse()?;

    // let dht = DHT::new();

    // tokio::spawn(async move {
    //     let mut node = Peer::new(addr, private_key);
    //
    //     node.run().await;
    // });

    let mut node = Node::new(addr, my_id, secret, public_key);
    node.connect().await?;




    println!("Hello, world!");

    Ok(())
}
