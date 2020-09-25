use std::error::Error;
use mio::net::{ TcpListener, TcpStream, UdpSocket};
use mio::{Events, Interest, Poll, Token};
use std::io::{Read, Write};
use hex;
use rand::{thread_rng, Rng};
use keccak_hash::keccak;
use secp256k1::{SecretKey, PublicKey, Message, RecoveryId, Signature, sign, recover};
use rlp::{Rlp, RlpStream};
use std::collections::VecDeque;

mod message;

use message::PeerInfo;

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
fn main() -> Result<(), Box<dyn Error>> {
    let mut arr = [0u8; 32];
    thread_rng().fill(&mut arr[..]);

    // let data = vec![0x83, b'c', b'a', b't'];
    // let aa: String = rlp::decode(&data).unwrap();
    // println!("aa = {:?}", aa);

    // let pk = hex::decode("ee5495585eff78f2fcf95bab21ef1a598c54d1e3c672e23b3bb97a4fc7490660").unwrap();
    let private_key = SecretKey::parse_slice(&arr[0..arr.len()]).unwrap();
    // let private_key = SecretKey::parse_slice(&pk).unwrap();
    let pubkey = PublicKey::from_secret_key(&private_key);
    let id = &pubkey.serialize().to_vec()[1..];

    println!("id is {:?}", hex::encode(&id));

    const CLIENT: Token = Token(0);
    const SENDER: Token = Token(0);

    let udp_server_ip = "35.180.217.147";
    let udp_server_port = "30304";

    let upd_server_addr = "35.180.217.147:30304";

    let local_udp_addr = "192.168.31.125:30309";
    let mut udp_socket = UdpSocket::bind(local_udp_addr.parse()?)?;
    // let local_addr = udp_socket.local_addr()?;
    //
    // println!("local_addr = {:?}", local_addr);

    println!("private_key is {:?}", private_key);
    let mut poll = Poll::new()?;

    let mut events = Events::with_capacity(1024);

    let addr = "192.168.31.248:30303".parse()?;

    let peer = PeerInfo::from_sock_addr(&upd_server_addr.parse()?);
    let local_peer = PeerInfo::from_sock_addr(&local_udp_addr.parse()?);

    let mut sent_ping = false;
    // message::encode_ping(&peer, &peer, &private_key);
    // println!("peer ip {:?}", peer.encode());
    // let addr = "127.0.0.1:9000".parse()?;

    let mut send_queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut client = TcpStream::connect(addr)?;

    let mut status_sent = false;

    poll.registry().register(&mut client, CLIENT, Interest::READABLE | Interest::WRITABLE)?;
    poll.registry().register(&mut udp_socket, SENDER, Interest::READABLE | Interest::WRITABLE)?;

    let mut received_data = Vec::with_capacity(4096);

    send_queue.push_back(message::encode_ping(&local_peer, &peer, &private_key));

    loop {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            match event.token() {
                SENDER => {
                    println!("udp socket is active");

                    if event.is_writable() {
                        'inner: loop {
                            if let Some(buf) = send_queue.pop_front() {
                                match udp_socket.send_to(&buf, upd_server_addr.parse()?) {
                                    Ok(size) => {
                                        println!("sent {:?} bytes(total {:?})", size, buf.len());

                                        // we have some buf remain for next time
                                        if size < buf.len() {
                                            if size == 0 {
                                                send_queue.push_front(buf);
                                            }
                                            break 'inner;
                                        }

                                    },
                                    Err(e) => {
                                        println!("send error {:?}", e);
                                        break 'inner;
                                    }
                                }
                            } else {
                                println!("no data to send, reregister for next writable event");

                                break 'inner;
                            }
                        }
                    }

                    if event.is_readable() {
                        'read: loop {
                            let mut buf = [0; 1024];
                            match udp_socket.recv_from(&mut buf) {
                                Ok((size, addr)) => {
                                    println!("read {:?} bytes from {:?}", size, addr);
                                    if (size > 0) {
                                        let read_buf = &buf[..size];
                                        let hash_signed = keccak(&read_buf[32..]);
                                        println!("hash_signed = {:?}", hash_signed);
                                        println!("check_sum = {:?}", hex::encode(&read_buf[0..32]));

                                        // if hash_signed.as_bytes() != &read_buf[0..32] {
                                        //     // return Box::new(Err("bad protocol"));
                                        //     break;
                                        // }

                                        let signed = &read_buf[(32 + 65)..];
                                        let message_type = signed[0];
                                        print_message_type(message_type);

                                        println!("message_type is {:?}", message_type);
                                        let recover_id = RecoveryId::parse(read_buf[32 + 64]).expect("can not get recover id");
                                        println!("recover_id = {:?}", recover_id);
                                        let signature = Signature::parse_slice(&read_buf[32..(32 + 64)]).expect("can not get signature");
                                        let hash = keccak(signed);
                                        let pubkey = recover(&Message::parse_slice(&hash).unwrap(), &signature, &recover_id).expect("can not recover pubkey");
                                        println!("pubkey is {:?}", hex::encode(&pubkey.serialize_compressed().to_vec()));

                                        let rlp = Rlp::new(&signed[1..]);

                                        if message_type == 0x01 {
                                            // got a ping message
                                            let version: u8 = rlp.val_at(0)?;
                                            let from_peer = PeerInfo::decode_rlp(&rlp.at(1)?)?;
                                            let to_peer = PeerInfo::decode_rlp(&rlp.at(2)?)?;
                                            println!("from_peer = {:?}, to_peer = {:?}", from_peer, to_peer);
                                            let timestamp: u64 = rlp.val_at(3)?;
                                            println!("version = {:?}, timestamp = {:?}", version, timestamp);

                                            // send pong message
                                            let from = PeerInfo::from_sock_addr(&addr);
                                            let bytes = message::encode_pong(&from, &read_buf[0..32].to_vec(), &timestamp, &private_key);
                                            println!("pong bytes is {:?}", bytes.len());

                                            send_queue.push_back(bytes);
                                            // send_queue


                                        } else if message_type == 0x02 {
                                            // got a pong message
                                            let from_peer = PeerInfo::decode_rlp(&rlp.at(0)?)?;
                                            let hash_bytes = rlp.at(1)?.data()?;
                                            let timestamp: u64 = rlp.val_at(2)?;
                                            println!("got a pong message {:?} {:?}", from_peer, timestamp);

                                            // start send findneighbours packet
                                            let bytes = message::encode_find_node(&private_key);
                                            println!("find node bytes is {:?}", bytes.len());

                                            send_queue.push_back(bytes);

                                        } else if message_type == 0x03 {
                                            println!("got a find node message");
                                        } else if message_type == 0x04 {
                                            println!("got a node message");
                                        }

                                        poll.registry().reregister(&mut udp_socket, event.token(), Interest::WRITABLE)?;


                                        // we have read all data
                                        if (size < buf.len()) {
                                            println!("no more data read");
                                            break 'read;
                                        }
                                    } else {
                                        println!("no data read");
                                        break 'read;
                                    }
                                },
                                Err(e) => {
                                    println!("read error {:?}", e);
                                    break 'read;
                                }
                            }
                        }
                    }
                },

                CLIENT => {
                    if event.is_readable() {
                        println!("client socket is readable");
                        // read buf
                        let mut buf = [0; 1024];
                        match client.read(&mut buf) {
                            Ok(n) => {
                                if (n > 0) {
                                    received_data.extend_from_slice(&buf[..n]);
                                    println!("read data: {:?}", String::from_utf8_lossy(&received_data));
                                }
                                println!("read {:?} bytes", n);
                            },
                            Err(err) => {
                                println!("read data error {:?}", err);
                            }
                        }
                    }

                    if event.is_writable() {
                        // send auth info
                        let auth = "0196045fa704aa5f5a85f36c6b399b08d823083228d63c4346f382f78a18b684f3a4e64a671de498abf20cba88dd8f3f0a11443bed18248895b981e0c842e9e4fafe387cf9ad619ba89fe7dbfa6f504725bb673a804f3526df31c68a69caf9bc7a9eed62fe73dffdeae5e21f55e2a1ec28e17ad5f98bd0a61759fe25f8f96665278197413d86ab84ea2f3adbf70634b49d13b4b55037e23f393ddc2ae46e63d4c3d1b67945bcf22d03183a1b1ff3b9b74cf3d83a8093489b508759c5042ca0d7de29aa6eb024800868594f848f646f1488c7bbf2a598d411a7333db52168f53e04e28b260e218233e9641232304625ba67cbaa7b6a3703161235ab41758d466701beac1a08e5edc612e42cb7235d43cbdd51ff7bb3cbe4720dfa165f084dafce2c84795eb619016647c9aef4d6d9b31e1a4b1e3b18e856a025ab99275b8b860816259ddf86cdc20c22e0f6f70445258113fade6d38814cb88d8c0693a64880088563cb02ff15236bca24720aaaa9da219c0f2fa71f8a4b1e34793a330b31ccfbdcbaf0026c881d5761b198be428feb93b170afe95174722f";

                        let buf = hex::decode(auth).unwrap();

                        if !status_sent {
                            status_sent = true;
                            match client.write_all(&buf) {
                                Ok(_) => {
                                    println!("write ok");
                                },
                                Err(err) => {
                                    println!("read data error {:?}", err);
                                }
                            }
                        }

                        println!("client socket is writable");
                    }

                    println!("client event token {:?}", event.token());
                },

                _ => {

                }
            }
        }
    }
    println!("Hello, world!");
}
