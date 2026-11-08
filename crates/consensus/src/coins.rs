//! The UTXO set: coin serialization, a write-back coin cache over a pluggable key-value backend,
//! and the chapter 15 fingerprint. The harness uses an in-memory backend and the node a RocksDB
//! one; both go through the same cache, so the harness exercises the node's UTXO code.

use crate::hashes::Sha256Writer;
use crate::serialize::{write_var_bytes, DecodeError, Reader};
use crate::tx::{OutPoint, TxOut};
use crate::tx_rules::Coin;
use crate::util::Hash256;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hasher};

// ---------------------------------------------------------------------------------------------
// Serialization (internal storage format, lossless).

/// Appends an unsigned LEB128 integer.
pub fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub fn read_varint(reader: &mut Reader) -> Result<u64, DecodeError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = reader.read_u8()?;
        if shift > 63 {
            return Err(DecodeError("varint too long"));
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// Database key of an outpoint: raw txid then the index big-endian, so that the byte order of
/// keys is the chapter 15 order (txid raw bytes, then index numerically).
pub fn outpoint_key(outpoint: &OutPoint) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(&outpoint.txid);
    key[32..].copy_from_slice(&outpoint.vout.to_be_bytes());
    key
}

pub fn outpoint_from_key(key: &[u8]) -> Option<OutPoint> {
    if key.len() != 36 {
        return None;
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&key[..32]);
    Some(OutPoint { txid, vout: u32::from_be_bytes([key[32], key[33], key[34], key[35]]) })
}

fn write_script_compact(out: &mut Vec<u8>, script: &[u8]) {
    match script.len() {
        25 if script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac => {
            out.push(0);
            out.extend_from_slice(&script[3..23]);
        }
        23 if script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 => {
            out.push(1);
            out.extend_from_slice(&script[2..22]);
        }
        22 if script[0] == 0x00 && script[1] == 0x14 => {
            out.push(2);
            out.extend_from_slice(&script[2..22]);
        }
        34 if script[0] == 0x00 && script[1] == 0x20 => {
            out.push(3);
            out.extend_from_slice(&script[2..34]);
        }
        34 if script[0] == 0x51 && script[1] == 0x20 => {
            out.push(4);
            out.extend_from_slice(&script[2..34]);
        }
        35 if script[0] == 0x21 && script[34] == 0xac => {
            out.push(5);
            out.extend_from_slice(&script[1..34]);
        }
        67 if script[0] == 0x41 && script[66] == 0xac => {
            out.push(6);
            out.extend_from_slice(&script[1..66]);
        }
        _ => {
            out.push(7);
            write_var_bytes(out, script);
        }
    }
}

fn read_script_compact(reader: &mut Reader) -> Result<Vec<u8>, DecodeError> {
    let kind = reader.read_u8()?;
    let script = match kind {
        0 => {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(reader.read_bytes(20)?);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        }
        1 => {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(reader.read_bytes(20)?);
            s.push(0x87);
            s
        }
        2 => {
            let mut s = vec![0x00, 0x14];
            s.extend_from_slice(reader.read_bytes(20)?);
            s
        }
        3 => {
            let mut s = vec![0x00, 0x20];
            s.extend_from_slice(reader.read_bytes(32)?);
            s
        }
        4 => {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(reader.read_bytes(32)?);
            s
        }
        5 => {
            let mut s = vec![0x21];
            s.extend_from_slice(reader.read_bytes(33)?);
            s.push(0xac);
            s
        }
        6 => {
            let mut s = vec![0x41];
            s.extend_from_slice(reader.read_bytes(65)?);
            s.push(0xac);
            s
        }
        7 => reader.read_var_bytes()?,
        _ => return Err(DecodeError("bad script kind")),
    };
    Ok(script)
}

/// Serializes a coin: varint(height * 2 + coinbase), varint(value bits), compact script.
pub fn write_coin(out: &mut Vec<u8>, coin: &Coin) {
    write_varint(out, ((coin.height as u32 as u64) << 1) | coin.is_coinbase as u64);
    write_varint(out, coin.output.value as u64);
    write_script_compact(out, &coin.output.script_pubkey);
}

pub fn read_coin(reader: &mut Reader) -> Result<Coin, DecodeError> {
    let code = read_varint(reader)?;
    let value = read_varint(reader)? as i64;
    let script_pubkey = read_script_compact(reader)?;
    Ok(Coin { output: TxOut { value, script_pubkey }, height: (code >> 1) as u32 as i32, is_coinbase: code & 1 == 1 })
}

pub fn encode_coin(coin: &Coin) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    write_coin(&mut out, coin);
    out
}

pub fn decode_coin(bytes: &[u8]) -> Result<Coin, DecodeError> {
    let mut reader = Reader::new(bytes);
    let coin = read_coin(&mut reader)?;
    if reader.remaining() != 0 {
        return Err(DecodeError("trailing coin bytes"));
    }
    Ok(coin)
}

// ---------------------------------------------------------------------------------------------
// Backend interface.

/// A persistent (or in-memory) set of coins, keyed by outpoint, iterable in key order.
pub trait CoinDb: Send + Sync {
    fn get(&self, outpoint: &OutPoint) -> Option<Coin>;

    /// Looks up many outpoints; implementations may do this in parallel.
    fn get_many(&self, outpoints: &[OutPoint]) -> Vec<Option<Coin>> {
        outpoints.iter().map(|op| self.get(op)).collect()
    }

    /// Atomically applies `changes` (sorted by outpoint; `None` deletes) and records `best` as the
    /// block whose UTXO set the database now holds.
    fn write(&mut self, changes: &[(OutPoint, Option<Coin>)], best: &Hash256) -> std::io::Result<()>;

    /// The block whose UTXO set the database holds, if any was recorded.
    fn best_block(&self) -> Option<Hash256>;

    /// Visits every coin in key order (txid raw bytes, then index).
    fn for_each_sorted(&self, visit: &mut dyn FnMut(&OutPoint, &Coin)) -> std::io::Result<()>;
}

/// In-memory backend (the harness).
#[derive(Default)]
pub struct MemoryCoinDb {
    pub coins: BTreeMap<OutPoint, Coin>,
    pub best: Option<Hash256>,
}

impl CoinDb for MemoryCoinDb {
    fn get(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coins.get(outpoint).cloned()
    }

    fn write(&mut self, changes: &[(OutPoint, Option<Coin>)], best: &Hash256) -> std::io::Result<()> {
        for (outpoint, coin) in changes {
            match coin {
                Some(coin) => {
                    self.coins.insert(*outpoint, coin.clone());
                }
                None => {
                    self.coins.remove(outpoint);
                }
            }
        }
        self.best = Some(*best);
        Ok(())
    }

    fn best_block(&self) -> Option<Hash256> {
        self.best
    }

    fn for_each_sorted(&self, visit: &mut dyn FnMut(&OutPoint, &Coin)) -> std::io::Result<()> {
        for (outpoint, coin) in &self.coins {
            visit(outpoint, coin);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// The cache.

/// Hasher for outpoints: txids are uniformly distributed hash outputs, so a keyed mix of their
/// first eight bytes and the index is enough (the random key keeps bucket positions unknown to
/// anyone grinding txids).
#[derive(Clone, Copy)]
pub struct OutPointHashBuilder {
    key: u64,
}

impl OutPointHashBuilder {
    pub fn new() -> OutPointHashBuilder {
        let random = std::collections::hash_map::RandomState::new();
        let mut hasher = random.build_hasher();
        hasher.write_u64(0x5bd1_e995);
        OutPointHashBuilder { key: hasher.finish() | 1 }
    }
}

impl Default for OutPointHashBuilder {
    fn default() -> Self {
        OutPointHashBuilder::new()
    }
}

pub struct OutPointHasher {
    state: u64,
    key: u64,
}

impl Hasher for OutPointHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if bytes.len() >= 8 {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[..8]);
            self.state ^= u64::from_le_bytes(word);
            if bytes.len() >= 16 {
                word.copy_from_slice(&bytes[8..16]);
                self.state = self.state.rotate_left(29) ^ u64::from_le_bytes(word);
            }
        } else {
            for &b in bytes {
                self.state = self.state.rotate_left(8) ^ b as u64;
            }
        }
    }

    #[inline]
    fn write_u32(&mut self, value: u32) {
        self.state ^= (value as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }

    #[inline]
    fn write_usize(&mut self, _length_prefix: usize) {}

    #[inline]
    fn finish(&self) -> u64 {
        let mut x = self.state ^ self.key;
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        x ^ (x >> 33)
    }
}

impl BuildHasher for OutPointHashBuilder {
    type Hasher = OutPointHasher;
    #[inline]
    fn build_hasher(&self) -> OutPointHasher {
        OutPointHasher { state: 0, key: self.key }
    }
}

pub type OutPointMap<V> = HashMap<OutPoint, V, OutPointHashBuilder>;

pub fn new_outpoint_map<V>() -> OutPointMap<V> {
    HashMap::with_hasher(OutPointHashBuilder::new())
}

/// One cached outpoint. `coin` is `None` for a spent coin whose deletion is not yet written.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub coin: Option<Coin>,
    /// Differs from the backend.
    pub dirty: bool,
    /// The backend certainly does not hold this outpoint (so spending it needs no write).
    pub fresh: bool,
}

/// Approximate heap and table cost of one entry, for memory accounting.
const ENTRY_OVERHEAD: usize = 120;

fn entry_cost(entry: &CacheEntry) -> usize {
    ENTRY_OVERHEAD + entry.coin.as_ref().map_or(0, |coin| coin.output.script_pubkey.capacity())
}

/// Write-back cache of coins over a backend. Lookups that miss go to the backend (never
/// "assumed absent": Appendix B.4); changes are written back by `flush`.
pub struct CoinsCache {
    map: OutPointMap<CacheEntry>,
    db: Box<dyn CoinDb>,
    usage: usize,
    /// The block whose UTXO set the cache (plus backend) represents.
    pub best_block: Hash256,
}

impl CoinsCache {
    pub fn new(db: Box<dyn CoinDb>, best_block: Hash256) -> CoinsCache {
        CoinsCache { map: new_outpoint_map(), db, usage: 0, best_block }
    }

    pub fn db(&self) -> &dyn CoinDb {
        self.db.as_ref()
    }

    pub fn db_mut(&mut self) -> &mut dyn CoinDb {
        self.db.as_mut()
    }

    /// Approximate memory used by cached entries, in bytes.
    pub fn usage(&self) -> usize {
        self.usage
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Looks a coin up, caching what the backend returns.
    pub fn get(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        if let Some(entry) = self.map.get(outpoint) {
            return entry.coin.clone();
        }
        let coin = self.db.get(outpoint)?;
        let entry = CacheEntry { coin: Some(coin.clone()), dirty: false, fresh: false };
        self.usage += entry_cost(&entry);
        self.map.insert(*outpoint, entry);
        Some(coin)
    }

    /// True if the outpoint is cached (as a coin or as a pending deletion).
    pub fn is_cached(&self, outpoint: &OutPoint) -> bool {
        self.map.contains_key(outpoint)
    }

    /// Loads the given outpoints from the backend (in one batched, possibly parallel lookup) if
    /// they are not cached. Purely a performance measure: results are identical without it.
    pub fn prefetch(&mut self, outpoints: &[OutPoint]) {
        let missing: Vec<OutPoint> = outpoints.iter().filter(|op| !self.map.contains_key(op)).copied().collect();
        if missing.is_empty() {
            return;
        }
        let found = self.db.get_many(&missing);
        for (outpoint, coin) in missing.into_iter().zip(found) {
            if let Some(coin) = coin {
                let entry = CacheEntry { coin: Some(coin), dirty: false, fresh: false };
                self.usage += entry_cost(&entry);
                self.map.entry(outpoint).or_insert(entry);
            }
        }
    }

    /// Records a coin. `fresh_hint` asserts that the backend cannot hold this outpoint.
    pub fn put(&mut self, outpoint: OutPoint, coin: Coin, fresh_hint: bool) {
        match self.map.get_mut(&outpoint) {
            Some(entry) => {
                self.usage -= entry_cost(entry);
                entry.coin = Some(coin);
                entry.dirty = true;
                self.usage += entry_cost(entry);
            }
            None => {
                let entry = CacheEntry { coin: Some(coin), dirty: true, fresh: fresh_hint };
                self.usage += entry_cost(&entry);
                self.map.insert(outpoint, entry);
            }
        }
    }

    /// Removes a coin.
    pub fn delete(&mut self, outpoint: &OutPoint) {
        match self.map.get_mut(outpoint) {
            Some(entry) => {
                if entry.fresh {
                    let entry = self.map.remove(outpoint).unwrap();
                    self.usage -= entry_cost(&entry);
                } else {
                    self.usage -= entry_cost(entry);
                    entry.coin = None;
                    entry.dirty = true;
                    self.usage += entry_cost(entry);
                }
            }
            None => {
                let entry = CacheEntry { coin: None, dirty: true, fresh: false };
                self.usage += entry_cost(&entry);
                self.map.insert(*outpoint, entry);
            }
        }
    }

    /// Number of entries that differ from the backend.
    pub fn dirty_count(&self) -> usize {
        self.map.values().filter(|entry| entry.dirty).count()
    }

    /// Writes every pending change to the backend atomically, recording `best_block`. Afterwards
    /// the cache keeps the coins it held (now clean) when `keep` is true, or is emptied.
    pub fn flush(&mut self, keep: bool) -> std::io::Result<usize> {
        let mut changes: Vec<(OutPoint, Option<Coin>)> = Vec::new();
        for (outpoint, entry) in self.map.iter() {
            if entry.dirty {
                changes.push((*outpoint, entry.coin.clone()));
            }
        }
        changes.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        self.db.write(&changes, &self.best_block)?;
        let written = changes.len();
        drop(changes);
        if keep {
            let mut usage = 0;
            self.map.retain(|_, entry| {
                if entry.coin.is_none() {
                    return false;
                }
                entry.dirty = false;
                entry.fresh = false;
                usage += entry_cost(entry);
                true
            });
            self.usage = usage;
        } else {
            self.map = new_outpoint_map();
            self.usage = 0;
        }
        Ok(written)
    }

    /// Drops clean entries for which `evict` returns true (no write needed).
    pub fn evict_clean(&mut self, mut evict: impl FnMut(&Coin) -> bool) {
        let mut usage = 0;
        self.map.retain(|_, entry| {
            let drop_it = !entry.dirty && entry.coin.as_ref().is_some_and(&mut evict);
            if !drop_it {
                usage += entry_cost(entry);
            }
            !drop_it
        });
        self.usage = usage;
    }

    /// Height histogram of clean cached coins (for eviction policies).
    pub fn clean_heights(&self) -> Vec<i32> {
        self.map.values().filter(|e| !e.dirty).filter_map(|e| e.coin.as_ref().map(|c| c.height)).collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Chapter 15: the UTXO set fingerprint.

/// Streams coins (in key order) into Bitcoin Core's `hash_serialized_3`. Core: `TxOutSer`,
/// `ApplyHash`, `ComputeUTXOStats` with `HASH_SERIALIZED`.
pub struct UtxoHasher {
    writer: Sha256Writer,
    buffer: Vec<u8>,
    count: u64,
}

impl Default for UtxoHasher {
    fn default() -> Self {
        UtxoHasher::new()
    }
}

impl UtxoHasher {
    pub fn new() -> UtxoHasher {
        UtxoHasher { writer: Sha256Writer::new(), buffer: Vec::with_capacity(1 << 20), count: 0 }
    }

    pub fn add(&mut self, outpoint: &OutPoint, coin: &Coin) {
        self.buffer.extend_from_slice(&outpoint.txid);
        self.buffer.extend_from_slice(&outpoint.vout.to_le_bytes());
        let code = ((coin.height as u32) << 1) | coin.is_coinbase as u32;
        self.buffer.extend_from_slice(&code.to_le_bytes());
        self.buffer.extend_from_slice(&coin.output.value.to_le_bytes());
        write_var_bytes(&mut self.buffer, &coin.output.script_pubkey);
        self.count += 1;
        if self.buffer.len() >= (1 << 20) - 20_000 {
            self.writer.write(&self.buffer);
            self.buffer.clear();
        }
    }

    /// Returns (hash_serialized_3 in raw order, number of coins).
    pub fn finish(mut self) -> (Hash256, u64) {
        self.writer.write(&self.buffer);
        (self.writer.finish_double(), self.count)
    }
}

/// The fingerprint of everything a backend holds.
pub fn utxo_hash_of_db(db: &dyn CoinDb) -> std::io::Result<(Hash256, u64)> {
    let mut hasher = UtxoHasher::new();
    db.for_each_sorted(&mut |outpoint, coin| hasher.add(outpoint, coin))?;
    Ok(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coin_round_trip() {
        let scripts: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x6a],
            {
                let mut s = vec![0x76, 0xa9, 0x14];
                s.extend_from_slice(&[7; 20]);
                s.extend_from_slice(&[0x88, 0xac]);
                s
            },
            {
                let mut s = vec![0xa9, 0x14];
                s.extend_from_slice(&[9; 20]);
                s.push(0x87);
                s
            },
            {
                let mut s = vec![0x51, 0x20];
                s.extend_from_slice(&[3; 32]);
                s
            },
            {
                let mut s = vec![0x21];
                s.extend_from_slice(&[2; 33]);
                s.push(0xac);
                s
            },
            vec![0x41; 67],
            vec![1; 300],
        ];
        for script in scripts {
            for (height, cb, value) in [(0, false, 0i64), (1, true, 5_000_000_000), (899_999, false, 2_100_000_000_000_000)] {
                let coin = Coin { output: TxOut { value, script_pubkey: script.clone() }, height, is_coinbase: cb };
                assert_eq!(decode_coin(&encode_coin(&coin)).unwrap(), coin);
            }
        }
    }

    #[test]
    fn key_order_is_fingerprint_order() {
        let a = OutPoint { txid: [1; 32], vout: 256 };
        let b = OutPoint { txid: [1; 32], vout: 2 };
        assert!(b < a);
        assert!(outpoint_key(&b) < outpoint_key(&a));
        assert_eq!(outpoint_from_key(&outpoint_key(&a)), Some(a));
    }
}
