//! Peer connections over the version 1 transport (chapter 14 section 14.1): one reader thread and
//! one writer thread per peer. Readers answer `ping` themselves (so a busy validation loop never
//! delays a `pong`) and forward every other message to the node's event channel.

use consensus::p2p::{checksum_ok, decode_message_header, encode_message};
use crossbeam_channel::{Receiver, Sender};
use std::io::{BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub enum NetEvent {
    Connected { peer: usize, sender: Sender<Vec<u8>> },
    Message { peer: usize, command: String, payload: Vec<u8> },
    Disconnected { peer: usize, reason: String },
}

/// Connects to `address` in a background thread. Events are sent to `events`.
pub fn connect(peer: usize, address: String, magic: [u8; 4], events: Sender<NetEvent>) {
    std::thread::Builder::new()
        .name(format!("peer-{peer}"))
        .spawn(move || {
            let reason = match run_peer(peer, &address, magic, &events) {
                Ok(()) => "closed".to_string(),
                Err(error) => error.to_string(),
            };
            let _ = events.send(NetEvent::Disconnected { peer, reason });
        })
        .expect("spawn peer thread");
}

fn run_peer(peer: usize, address: &str, magic: [u8; 4], events: &Sender<NetEvent>) -> std::io::Result<()> {
    let socket = address
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "address did not resolve"))?;
    let stream = TcpStream::connect_timeout(&socket, Duration::from_secs(10))?;
    stream.set_nodelay(true)?;
    let write_stream = stream.try_clone()?;
    let (sender, outgoing): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = crossbeam_channel::unbounded();
    std::thread::Builder::new()
        .name(format!("peer-{peer}-writer"))
        .spawn(move || {
            let mut stream = write_stream;
            for frame in outgoing {
                // An empty frame asks the writer to close the connection.
                if frame.is_empty() || stream.write_all(&frame).is_err() {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    break;
                }
            }
        })
        .expect("spawn writer thread");
    if events.send(NetEvent::Connected { peer, sender: sender.clone() }).is_err() {
        return Ok(());
    }
    let mut reader = BufReader::with_capacity(4 << 20, stream);
    let mut header = [0u8; 24];
    loop {
        reader.read_exact(&mut header)?;
        let parsed = decode_message_header(&header, magic).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut payload = vec![0u8; parsed.length];
        reader.read_exact(&mut payload)?;
        if !checksum_ok(&parsed, &payload) {
            // Bitcoin Core drops messages with a wrong checksum.
            continue;
        }
        if parsed.command == "ping" {
            let _ = sender.send(encode_message(magic, "pong", &payload));
            continue;
        }
        if events.send(NetEvent::Message { peer, command: parsed.command, payload }).is_err() {
            return Ok(());
        }
    }
}
