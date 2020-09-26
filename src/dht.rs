use std::error::Error;
// use mio::net::{ TcpStream, UdpSocket};
// use mio::{Events, Interest, Poll, Token};
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
use std::default::Default;

#[derive(Default)]
pub struct DHT {
    nodes: Vec<PeerInfo>
}

impl DHT {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn bootstrap(&self, peer: PeerInfo) {

    }
}
