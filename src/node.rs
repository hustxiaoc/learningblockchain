#![feature(non_exhaustive)]
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
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver, self};
use tokio::time::{delay_for, Duration};
use tokio::io::{self, split, ReadHalf, WriteHalf, AsyncReadExt, AsyncWriteExt};
use parity_crypto::publickey::{Generator, KeyPair, Public, Random, recover, Secret, sign, ecdh, ecies};
use ethereum_types::{H256, H512};
use std::future::Future;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::cell::Cell;
use crate::message::{self, PeerInfo};

// Auth, Ack, Header, Body
#[derive(Clone, Copy)]
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
    nonce: H256,
    secret: Secret,
    state: Cell<NodeState>,
    tx: Option<Tx>,
    inner: Option<Inner>,
}

struct  Inner {
    rx: Rx,
    reader: ReadHalf<TcpStream>
}
//
// impl Future for Inner {
//     type Output = Vec<u8>;
//
//     fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         println!("call polling");
//
//         match self.rx.poll_recv(cx) {
//             Poll::Ready(x) => {
//                 println!("x = {:?}", x);
//                 return Poll::Ready(x.unwrap());
//             },
//             _ => {
//
//             }
//         };
//
//         let mut buf = [u8; 1024];
//         match self.reader.poll_read(ctx, &mut buf) {
//             Poll::Ready(size) => {
//                 println!("read {:?} bytes", size);
//                 return Poll::Ready(&buf[..size]);
//             },
//             _ => {
//
//             }
//         };
//
//         Poll::Pending
//     }
// }

impl Node {
    pub fn new(addr: SocketAddr, pubkey: Public) -> Self {
        let mut arr = [0u8; 32];
        thread_rng().fill(&mut arr[..]);
        let nonce = H256::from_slice(&arr);

        Self {
            ecdhe: Random.generate(),
            addr,
            pubkey,
            nonce,
            secret: Secret::from(nonce),
            state: Cell::new(NodeState::Auth),
            tx: None,
            inner: None,
        }
    }

    fn send_auth(&self) -> Result<(), Box<dyn Error>> {
        let mut data = [0u8; /*Signature::SIZE*/ 65 + /*H256::SIZE*/ 32 + /*Public::SIZE*/ 64 + /*H256::SIZE*/ 32 + 1]; //TODO: use associated constants
    	let len = data.len();

        data[len - 1] = 0x0;
        let (sig, rest) = data.split_at_mut(65);
        let (hepubk, rest) = rest.split_at_mut(32);
        let (pubk, rest) = rest.split_at_mut(64);
        let (nonce, _) = rest.split_at_mut(32);

        // E(remote-pubk, S(ecdhe-random, ecdh-shared-secret^nonce) || H(ecdhe-random-pubk) || pubk || nonce || 0x0)
        let shared = *ecdh::agree(&self.secret, &self.pubkey)?;
        sig.copy_from_slice(&*sign(self.ecdhe.secret(), &(shared ^ self.nonce))?);
        write_keccak(self.ecdhe.public(), hepubk);
        pubk.copy_from_slice(self.pubkey.as_bytes());
        nonce.copy_from_slice(self.nonce.as_bytes());
    	let message = ecies::encrypt(&self.pubkey, &[], &data)?;

        self.tx.as_ref().unwrap().send(message);
        Ok(())
    }

    async fn read(&self, stream: &mut ReadHalf<TcpStream>) {
        let mut buf = vec![0u8; 1024];
        match stream.read(&mut buf).await {
            Ok(size) => {
                if size == 0 {
                    // println!("server socket closed");
                    self.state.set(NodeState::Closed);
                    return;
                }

                if buf[0] == 4 {
                    // decode ack
                    // let message = ecies::decrypt(&self.secret, &[], &buf[0..size]).expect("decrypt error");
                    // println!("message decrypted {:?}", message);
                }


                println!("{:?}", buf[0]);
                println!("read {:?} bytes", size);
            },
            Err(err) => {

            }
        }
    }

    async fn write(&self, rx: &mut Rx, stream: &mut WriteHalf<TcpStream>) {
        if let Some(buf) = rx.recv().await {
            let size = stream.write(&buf).await.unwrap();
            println!("send {:?} bytes of {:?} bytes", size, buf.len());
        }
    }

    pub async fn connect(&mut self) -> Result<(), Box<dyn Error>> {

        let mut stream = TcpStream::connect(self.addr.clone()).await?;
        let (mut reader, mut writer) = split(stream);
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // tokio::spawn(async move {
        //     while let Some(buf) = rx.recv().await {
        //         let size = writer.write(&buf).await.unwrap();
        //         println!("send {:?} bytes of {:?} bytes", size, buf.len());
        //     }
        // });

        self.tx = Some(tx);
        // let inner = Inner {
        //     rx,
        //     reader,
        // };

        self.send_auth();

        // loop {
        //     let buf = inner.await;
        //     println!("{:?}", buf);
        // }

        // tokio::select! {
        //     _ =
        // }

        loop {
            match self.state.get() {
                NodeState::Closed => {
                    println!("socket is closed");
                    break;
                },
                _ => {

                }
            };

            tokio::select! {
                _ = self.read(&mut reader) => {
                    println!("read");
                },

                _ = self.write(&mut rx, &mut writer) => {
                    println!("write");
                }
            }
        }


        Ok(())
    }
}
