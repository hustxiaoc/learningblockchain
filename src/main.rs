use std::error::Error;
use mio::{Events, Interest, Poll, Token};
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

    let remote_pubkey = hex::decode("041f17e484e66c988e46e23007d343b3702f91018c5c2337591521444d8d97e43bb8942d0846c48d7feb0b98cd3fd34eb0be925369d131b58fb5332774297b4ae3").unwrap();

    let private_key = SecretKey::parse_slice(&arr[0..arr.len()]).unwrap();
    let pubkey = PublicKey::from_secret_key(&private_key);
    let id = &pubkey.serialize().to_vec()[1..];
    let secret = private_key.serialize();
    let my_secret = Secret::import_key(&private_key.serialize()).unwrap();
    let ecdhe = Random.generate();

    let my_id = H512::from_slice(&remote_pubkey[1..]);

    let my_nonce = H256::from_slice(&arr);

    let node_addr: SocketAddr = "35.180.217.147:30304".parse()?;
    let addr: SocketAddr = "192.168.31.248:30303".parse()?;

    let mut node = Node::new(addr, my_id);
    node.connect().await?;


    // let dht = DHT::new();

    // let mut node = Peer::new(addr, private_key);
    //
    // node.run().await;

    println!("Hello, world!");

    Ok(())
}
