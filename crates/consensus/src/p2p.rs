//! Chapter 14: peer-to-peer message formats (version 1 transport).

use crate::hashes::sha256d;
use crate::serialize::*;
use crate::tx::{read_block_header, BlockHeader};
use crate::util::Hash256;

/// Core: `MAX_PROTOCOL_MESSAGE_LENGTH`.
pub const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 4_000_000;

/// One decoded message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub command: String,
    pub payload: Vec<u8>,
}

/// Frames a message. Core: `V1Transport`.
pub fn encode_message(magic: [u8; 4], command: &str, payload: &[u8]) -> Vec<u8> {
    assert!(command.len() <= 12);
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&magic);
    let mut name = [0u8; 12];
    name[..command.len()].copy_from_slice(command.as_bytes());
    out.extend_from_slice(&name);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&sha256d(payload)[..4]);
    out.extend_from_slice(payload);
    out
}

/// A parsed 24-byte message header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    pub command: String,
    pub length: usize,
    pub checksum: [u8; 4],
}

/// Parses and checks a message header: wrong magic or an oversized payload is an error.
pub fn decode_message_header(header: &[u8; 24], magic: [u8; 4]) -> Result<MessageHeader, &'static str> {
    if header[..4] != magic {
        return Err("wrong network magic");
    }
    let name_end = header[4..16].iter().position(|&b| b == 0).unwrap_or(12);
    let command = String::from_utf8_lossy(&header[4..4 + name_end]).to_string();
    let length = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    if length > MAX_PROTOCOL_MESSAGE_LENGTH {
        return Err("message too large");
    }
    Ok(MessageHeader { command, length, checksum: [header[20], header[21], header[22], header[23]] })
}

/// True if `payload` matches the header's checksum.
pub fn checksum_ok(header: &MessageHeader, payload: &[u8]) -> bool {
    sha256d(payload)[..4] == header.checksum
}

/// Reads one message. Errors on the wrong magic, an oversized payload, or a bad checksum.
pub fn read_message(stream: &mut dyn std::io::Read, magic: [u8; 4]) -> std::io::Result<Message> {
    use std::io::{Error, ErrorKind};
    let mut header = [0u8; 24];
    stream.read_exact(&mut header)?;
    let parsed = decode_message_header(&header, magic).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    let mut payload = vec![0u8; parsed.length];
    stream.read_exact(&mut payload)?;
    if !checksum_ok(&parsed, &payload) {
        return Err(Error::new(ErrorKind::InvalidData, "bad checksum"));
    }
    Ok(Message { command: parsed.command, payload })
}

pub const PROTOCOL_VERSION: i32 = 70016;
/// Core: `MIN_PEER_PROTO_VERSION`.
pub const MIN_PEER_PROTO_VERSION: i32 = 31800;
pub const NODE_NETWORK: u64 = 1;
pub const NODE_WITNESS: u64 = 1 << 3;
pub const NODE_NETWORK_LIMITED: u64 = 1 << 10;

/// The fields of a `version` message that a node acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionMessage {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub nonce: u64,
    pub user_agent: Vec<u8>,
    pub start_height: i32,
    pub relay: bool,
}

pub fn encode_version(message: &VersionMessage) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&message.version.to_le_bytes());
    out.extend_from_slice(&message.services.to_le_bytes());
    out.extend_from_slice(&message.timestamp.to_le_bytes());
    out.extend_from_slice(&[0u8; 26]); // receiver: services, address, port
    out.extend_from_slice(&[0u8; 26]); // sender
    out.extend_from_slice(&message.nonce.to_le_bytes());
    write_var_bytes(&mut out, &message.user_agent);
    out.extend_from_slice(&message.start_height.to_le_bytes());
    out.push(message.relay as u8);
    out
}

/// Decodes a `version` payload the way Bitcoin Core does.
pub fn decode_version(payload: &[u8]) -> Result<VersionMessage, DecodeError> {
    let mut reader = Reader::new(payload);
    let version = reader.read_i32()?;
    let services = reader.read_u64()?;
    let timestamp = reader.read_i64()?;
    reader.read_bytes(26)?;
    let mut message = VersionMessage { version, services, timestamp, nonce: 1, user_agent: Vec::new(), start_height: -1, relay: true };
    if reader.remaining() > 0 {
        reader.read_bytes(26)?;
        message.nonce = reader.read_u64()?;
    }
    if reader.remaining() > 0 {
        message.user_agent = reader.read_var_bytes()?;
    }
    if reader.remaining() > 0 {
        message.start_height = reader.read_i32()?;
    }
    if reader.remaining() > 0 {
        message.relay = reader.read_u8()? != 0;
    }
    Ok(message)
}

/// Core: `MAX_HEADERS_RESULTS`.
pub const MAX_HEADERS_RESULTS: usize = 2000;
/// Core: `MAX_LOCATOR_SZ`.
pub const MAX_LOCATOR_SZ: usize = 101;

pub fn encode_getheaders(locator: &[Hash256], stop: &Hash256) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(PROTOCOL_VERSION as u32).to_le_bytes());
    write_compact_size(&mut out, locator.len() as u64);
    for hash in locator {
        out.extend_from_slice(hash);
    }
    out.extend_from_slice(stop);
    out
}

pub fn decode_getheaders(payload: &[u8]) -> Result<(Vec<Hash256>, Hash256), DecodeError> {
    let mut reader = Reader::new(payload);
    reader.read_u32()?;
    let count = reader.read_compact_size()?;
    let mut locator = Vec::new();
    for _ in 0..count {
        locator.push(reader.read_hash()?);
    }
    Ok((locator, reader.read_hash()?))
}

pub fn encode_headers(headers: &[BlockHeader]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + headers.len() * 81);
    write_compact_size(&mut out, headers.len() as u64);
    for header in headers {
        out.extend_from_slice(&header.serialize());
        out.push(0);
    }
    out
}

pub fn decode_headers(payload: &[u8]) -> Result<Vec<BlockHeader>, DecodeError> {
    let mut reader = Reader::new(payload);
    let count = reader.read_compact_size()? as usize;
    if count > MAX_HEADERS_RESULTS {
        return Err(DecodeError("too many headers"));
    }
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        headers.push(read_block_header(&mut reader)?);
        reader.read_compact_size()?;
    }
    Ok(headers)
}

pub const MSG_TX: u32 = 1;
pub const MSG_BLOCK: u32 = 2;
pub const MSG_WITNESS_FLAG: u32 = 1 << 30;
pub const MSG_WITNESS_BLOCK: u32 = MSG_BLOCK | MSG_WITNESS_FLAG;
/// Core: `MAX_BLOCKS_IN_TRANSIT_PER_PEER`.
pub const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 16;

pub fn encode_inv(items: &[(u32, Hash256)]) -> Vec<u8> {
    let mut out = Vec::new();
    write_compact_size(&mut out, items.len() as u64);
    for (kind, hash) in items {
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(hash);
    }
    out
}

pub fn decode_inv(payload: &[u8]) -> Result<Vec<(u32, Hash256)>, DecodeError> {
    let mut reader = Reader::new(payload);
    let count = reader.read_compact_size()?;
    let mut items = Vec::new();
    for _ in 0..count {
        items.push((reader.read_u32()?, reader.read_hash()?));
    }
    Ok(items)
}
