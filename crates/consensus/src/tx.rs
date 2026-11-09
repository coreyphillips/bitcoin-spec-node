//! Chapter 03 sections 3.2 to 3.4: transactions, headers and blocks, their encodings and ids.
//!
//! The reference computes ids and sizes by re-serializing. Decoding here also records, for every
//! transaction, its txid, wtxid and sizes computed from the received bytes. That is equivalent:
//! a successfully decoded transaction re-serializes to exactly the bytes it was decoded from
//! (CompactSize encodings are canonical, and the witness encoding is used if and only if the
//! decoded transaction has witness data), so hashing the original slices hashes the same bytes.

use crate::hashes::{sha256d, Sha256Writer};
use crate::serialize::*;
use crate::util::{Hash256, ZERO_HASH};

/// A reference to a transaction output. Ordered by raw txid bytes, then index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: Hash256,
    pub vout: u32,
}

impl OutPoint {
    /// The outpoint of a coinbase input. Core: `COutPoint::SetNull`.
    pub fn null() -> OutPoint {
        OutPoint { txid: ZERO_HASH, vout: 0xffff_ffff }
    }

    /// Core: `COutPoint::IsNull`.
    pub fn is_null(&self) -> bool {
        self.txid == ZERO_HASH && self.vout == 0xffff_ffff
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    /// The witness stack. Empty when the input has no witness.
    pub witness: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Unsigned (chapter 01): 0xffffffff compares greater than 2.
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

/// Core: `WITNESS_SCALE_FACTOR`.
pub const WITNESS_SCALE_FACTOR: usize = 4;

impl Transaction {
    /// True if any input has a non-empty witness stack. Core: `CTransaction::HasWitness`.
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|input| !input.witness.is_empty())
    }

    /// Serializes the transaction. Core: `SerializeTransaction`.
    pub fn serialize(&self, include_witness: bool) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize_into(&mut out, include_witness);
        out
    }

    pub fn serialize_into(&self, out: &mut Vec<u8>, include_witness: bool) {
        out.extend_from_slice(&self.version.to_le_bytes());
        let extended = include_witness && self.has_witness();
        if extended {
            out.push(0x00);
            out.push(0x01);
        }
        write_compact_size(out, self.inputs.len() as u64);
        for input in &self.inputs {
            out.extend_from_slice(&input.prevout.txid);
            out.extend_from_slice(&input.prevout.vout.to_le_bytes());
            write_var_bytes(out, &input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_compact_size(out, self.outputs.len() as u64);
        for output in &self.outputs {
            serialize_txout(out, output);
        }
        if extended {
            for input in &self.inputs {
                write_compact_size(out, input.witness.len() as u64);
                for item in &input.witness {
                    write_var_bytes(out, item);
                }
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
    }

    pub fn txid(&self) -> Hash256 {
        sha256d(&self.serialize(false))
    }

    pub fn wtxid(&self) -> Hash256 {
        sha256d(&self.serialize(true))
    }

    pub fn stripped_size(&self) -> usize {
        self.serialize(false).len()
    }

    pub fn total_size(&self) -> usize {
        self.serialize(true).len()
    }

    /// Core: `GetTransactionWeight`.
    pub fn weight(&self) -> usize {
        self.stripped_size() * (WITNESS_SCALE_FACTOR - 1) + self.total_size()
    }

    /// Ids and sizes computed by re-serializing (the reference definition).
    pub fn info(&self) -> TxInfo {
        TxInfo { txid: self.txid(), wtxid: self.wtxid(), stripped_size: self.stripped_size(), total_size: self.total_size() }
    }
}

/// Core: `CTxOut` serialization.
pub fn serialize_txout(out: &mut Vec<u8>, output: &TxOut) {
    out.extend_from_slice(&output.value.to_le_bytes());
    write_var_bytes(out, &output.script_pubkey);
}

/// Ids and sizes of a transaction (chapter 03 section 3.2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxInfo {
    pub txid: Hash256,
    pub wtxid: Hash256,
    pub stripped_size: usize,
    pub total_size: usize,
}

impl TxInfo {
    pub fn weight(&self) -> usize {
        self.stripped_size * (WITNESS_SCALE_FACTOR - 1) + self.total_size
    }
}

fn read_txin(reader: &mut Reader) -> Result<TxIn, DecodeError> {
    let txid = reader.read_hash()?;
    let vout = reader.read_u32()?;
    let script_sig = reader.read_var_bytes()?;
    let sequence = reader.read_u32()?;
    Ok(TxIn { prevout: OutPoint { txid, vout }, script_sig, sequence, witness: Vec::new() })
}

fn read_txins(reader: &mut Reader) -> Result<Vec<TxIn>, DecodeError> {
    let count = reader.read_compact_size()?;
    // Bound the preallocation by what the remaining bytes could hold (41 bytes per input).
    let mut inputs = Vec::with_capacity((count as usize).min(reader.remaining() / 41));
    for _ in 0..count {
        inputs.push(read_txin(reader)?);
    }
    Ok(inputs)
}

pub fn read_txout(reader: &mut Reader) -> Result<TxOut, DecodeError> {
    let value = reader.read_i64()?;
    let script_pubkey = reader.read_var_bytes()?;
    Ok(TxOut { value, script_pubkey })
}

fn read_txouts(reader: &mut Reader) -> Result<Vec<TxOut>, DecodeError> {
    let count = reader.read_compact_size()?;
    let mut outputs = Vec::with_capacity((count as usize).min(reader.remaining() / 9));
    for _ in 0..count {
        outputs.push(read_txout(reader)?);
    }
    Ok(outputs)
}

fn read_witness_stack(reader: &mut Reader) -> Result<Vec<Vec<u8>>, DecodeError> {
    let count = reader.read_compact_size()?;
    let mut stack = Vec::with_capacity((count as usize).min(reader.remaining()));
    for _ in 0..count {
        stack.push(reader.read_var_bytes()?);
    }
    Ok(stack)
}

/// Decodes one transaction with witness data allowed and computes its ids and sizes from the
/// bytes read. Core: `UnserializeTransaction` with `TX_WITH_WITNESS`.
pub fn read_transaction_info(reader: &mut Reader) -> Result<(Transaction, TxInfo), DecodeError> {
    let start = reader.position();
    let version = reader.read_u32()?;
    let mut flags = 0u8;
    let mut inputs = read_txins(reader)?;
    let mut outputs = Vec::new();
    // Start of the input count in the legacy encoding (after the marker and flag, if any).
    let mut legacy_body_start = start + 4;
    if inputs.is_empty() {
        flags = reader.read_u8()?;
        if flags != 0 {
            legacy_body_start = reader.position();
            inputs = read_txins(reader)?;
            outputs = read_txouts(reader)?;
        }
    } else {
        outputs = read_txouts(reader)?;
    }
    let witness_start = reader.position();
    let mut has_witness_encoding = false;
    if flags & 1 != 0 {
        flags ^= 1;
        for input in inputs.iter_mut() {
            input.witness = read_witness_stack(reader)?;
        }
        if !inputs.iter().any(|input| !input.witness.is_empty()) {
            return Err(DecodeError("Superfluous witness record"));
        }
        has_witness_encoding = true;
    }
    if flags != 0 {
        return Err(DecodeError("Unknown transaction optional data"));
    }
    let witness_end = reader.position();
    let lock_time = reader.read_u32()?;
    let end = reader.position();
    let bytes = reader.data();
    let raw = &bytes[start..end];
    let wtxid = sha256d(raw);
    let info = if has_witness_encoding {
        let mut writer = Sha256Writer::new();
        writer.write(&bytes[start..start + 4]);
        writer.write(&bytes[legacy_body_start..witness_start]);
        writer.write(&bytes[witness_end..end]);
        let stripped_size = 4 + (witness_start - legacy_body_start) + 4;
        TxInfo { txid: writer.finish_double(), wtxid, stripped_size, total_size: end - start }
    } else {
        TxInfo { txid: wtxid, wtxid, stripped_size: end - start, total_size: end - start }
    };
    Ok((Transaction { version, inputs, outputs, lock_time }, info))
}

/// Decodes one transaction with witness data allowed. Core: `UnserializeTransaction`.
pub fn read_transaction(reader: &mut Reader) -> Result<Transaction, DecodeError> {
    read_transaction_info(reader).map(|(tx, _)| tx)
}

/// Decodes a transaction that must occupy `bytes` exactly.
pub fn deserialize_transaction(bytes: &[u8]) -> Result<Transaction, DecodeError> {
    deserialize_transaction_info(bytes).map(|(tx, _)| tx)
}

/// Decodes a transaction that must occupy `bytes` exactly, with its ids and sizes.
pub fn deserialize_transaction_info(bytes: &[u8]) -> Result<(Transaction, TxInfo), DecodeError> {
    let mut reader = Reader::new(bytes);
    let tx = read_transaction_info(&mut reader)?;
    if reader.remaining() != 0 {
        return Err(DecodeError("trailing data"));
    }
    Ok(tx)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block: Hash256,
    pub merkle_root: Hash256,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    pub fn serialize(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_block);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Core: `CBlockHeader::GetHash`.
    pub fn hash(&self) -> Hash256 {
        sha256d(&self.serialize())
    }

    pub fn deserialize(bytes: &[u8; 80]) -> BlockHeader {
        read_block_header(&mut Reader::new(bytes)).expect("80 bytes")
    }
}

pub fn read_block_header(reader: &mut Reader) -> Result<BlockHeader, DecodeError> {
    Ok(BlockHeader {
        version: reader.read_i32()?,
        prev_block: reader.read_hash()?,
        merkle_root: reader.read_hash()?,
        time: reader.read_u32()?,
        bits: reader.read_u32()?,
        nonce: reader.read_u32()?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Serializes the block. Core: `CBlock` serialization.
    pub fn serialize(&self, include_witness: bool) -> Vec<u8> {
        let mut out = self.header.serialize().to_vec();
        write_compact_size(&mut out, self.transactions.len() as u64);
        for tx in &self.transactions {
            tx.serialize_into(&mut out, include_witness);
        }
        out
    }

    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }
}

/// A block with the ids and sizes of its transactions (computed once, at decoding).
#[derive(Clone, Debug)]
pub struct BlockData {
    pub block: Block,
    pub hash: Hash256,
    pub tx_info: Vec<TxInfo>,
    /// Length of the block serialized without witness data.
    pub stripped_size: usize,
    /// Length of the block serialized with witness data (trailing bytes excluded).
    pub total_size: usize,
    /// Merkle root of the txids and the mutation flag, once computed (a pure cache).
    pub merkle: std::sync::OnceLock<(Hash256, bool)>,
    /// Witness merkle root, once computed (a pure cache).
    pub witness_merkle: std::sync::OnceLock<Hash256>,
    /// Legacy signature operation count of each transaction, once computed (a pure cache).
    pub legacy_sigops: std::sync::OnceLock<Vec<u64>>,
}

impl BlockData {
    /// Builds the cached data for a block constructed in memory.
    pub fn from_block(block: Block) -> BlockData {
        let tx_info: Vec<TxInfo> = block.transactions.iter().map(|tx| tx.info()).collect();
        BlockData::assemble(block, tx_info)
    }

    fn assemble(block: Block, tx_info: Vec<TxInfo>) -> BlockData {
        let count_len = compact_size_len(block.transactions.len() as u64);
        let stripped_size = 80 + count_len + tx_info.iter().map(|info| info.stripped_size).sum::<usize>();
        let total_size = 80 + count_len + tx_info.iter().map(|info| info.total_size).sum::<usize>();
        let hash = block.header.hash();
        BlockData { block, hash, tx_info, stripped_size, total_size, merkle: std::sync::OnceLock::new(), witness_merkle: std::sync::OnceLock::new(), legacy_sigops: std::sync::OnceLock::new() }
    }

    /// Core: `GetBlockWeight`.
    pub fn weight(&self) -> usize {
        self.stripped_size * (WITNESS_SCALE_FACTOR - 1) + self.total_size
    }

    pub fn txid(&self, index: usize) -> &Hash256 {
        &self.tx_info[index].txid
    }
}

/// Decodes a block. Bytes after the last transaction are not part of the block and are ignored.
pub fn deserialize_block(bytes: &[u8]) -> Result<Block, DecodeError> {
    deserialize_block_data(bytes).map(|data| data.block)
}

/// Decodes a block with the ids and sizes of its transactions.
pub fn deserialize_block_data(bytes: &[u8]) -> Result<BlockData, DecodeError> {
    let mut reader = Reader::new(bytes);
    let header = read_block_header(&mut reader)?;
    let count = reader.read_compact_size()?;
    let capacity = (count as usize).min(reader.remaining() / 10);
    let mut transactions = Vec::with_capacity(capacity);
    let mut tx_info = Vec::with_capacity(capacity);
    for _ in 0..count {
        let (tx, info) = read_transaction_info(&mut reader)?;
        transactions.push(tx);
        tx_info.push(info);
    }
    Ok(BlockData::assemble(Block { header, transactions }, tx_info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    #[test]
    fn empty_transaction_quirk() {
        let bytes = hex_decode("01000000000000000000").unwrap();
        let (tx, info) = deserialize_transaction_info(&bytes).unwrap();
        assert!(tx.inputs.is_empty() && tx.outputs.is_empty());
        assert_eq!(info, tx.info());
    }

    #[test]
    fn info_matches_reserialization_for_witness_tx() {
        let tx = Transaction {
            version: 2,
            inputs: vec![
                TxIn { prevout: OutPoint { txid: [7u8; 32], vout: 3 }, script_sig: vec![1, 2, 3], sequence: 5, witness: vec![vec![], vec![9; 80]] },
                TxIn { prevout: OutPoint { txid: [8u8; 32], vout: 1 }, script_sig: vec![], sequence: 0xffff_ffff, witness: vec![] },
            ],
            outputs: vec![TxOut { value: 12345, script_pubkey: vec![0x51] }],
            lock_time: 99,
        };
        let bytes = tx.serialize(true);
        let (decoded, info) = deserialize_transaction_info(&bytes).unwrap();
        assert_eq!(decoded, tx);
        assert_eq!(info, tx.info());
        let legacy = tx.serialize(false);
        let (decoded, info) = deserialize_transaction_info(&legacy).unwrap();
        assert_eq!(info, decoded.info());
    }
}
