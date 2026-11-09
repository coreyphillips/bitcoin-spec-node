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


/// A borrowed view of a coin (used to stream coins to a backend without copying scripts).
#[derive(Clone, Copy, Debug)]
pub struct CoinRef<'a> {
    pub value: i64,
    pub height: i32,
    pub is_coinbase: bool,
    pub script: &'a [u8],
}

impl CoinRef<'_> {
    pub fn to_coin(&self) -> Coin {
        Coin { output: TxOut { value: self.value, script_pubkey: self.script.to_vec() }, height: self.height, is_coinbase: self.is_coinbase }
    }

    pub fn of(coin: &Coin) -> CoinRef<'_> {
        CoinRef { value: coin.output.value, height: coin.height, is_coinbase: coin.is_coinbase, script: &coin.output.script_pubkey }
    }
}

/// Serializes a coin view exactly as `write_coin` serializes the coin.
pub fn write_coin_ref(out: &mut Vec<u8>, coin: &CoinRef) {
    write_varint(out, ((coin.height as u32 as u64) << 1) | coin.is_coinbase as u64);
    write_varint(out, coin.value as u64);
    write_script_compact(out, coin.script);
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

    /// Atomically applies `changes` (in ascending outpoint order; `None` deletes) and records
    /// `best` as the block whose UTXO set the database now holds.
    fn write(&mut self, changes: &mut dyn Iterator<Item = (OutPoint, Option<CoinRef<'_>>)>, best: &Hash256) -> std::io::Result<()>;

    /// Like `write`, for changes produced in `parts` key ranges: `produce(p, sink)` feeds the
    /// changes of range `p` to `sink` in ascending order, and every key of range `p` sorts before
    /// every key of range `p + 1`. Implementations may produce and write the ranges in parallel;
    /// the result must still be applied atomically.
    fn write_parts(&mut self, parts: usize, produce: &(dyn Fn(usize, &mut dyn FnMut(OutPoint, Option<CoinRef<'_>>)) + Sync), best: &Hash256) -> std::io::Result<()> {
        let mut owned: Vec<(OutPoint, Option<Coin>)> = Vec::new();
        for part in 0..parts {
            produce(part, &mut |outpoint, coin| owned.push((outpoint, coin.map(|c| c.to_coin()))));
        }
        let mut iter = owned.iter().map(|(outpoint, coin)| (*outpoint, coin.as_ref().map(CoinRef::of)));
        self.write(&mut iter, best)
    }

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

    fn write(&mut self, changes: &mut dyn Iterator<Item = (OutPoint, Option<CoinRef<'_>>)>, best: &Hash256) -> std::io::Result<()> {
        let mut last: Option<OutPoint> = None;
        for (outpoint, coin) in changes {
            assert!(last.is_none_or(|l| l < outpoint), "changes must be in ascending order");
            last = Some(outpoint);
            match coin {
                Some(coin) => {
                    self.coins.insert(outpoint, coin.to_coin());
                }
                None => {
                    self.coins.remove(&outpoint);
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
/// first sixteen bytes and the index is enough (the random key keeps bucket positions unknown to
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

/// The slot holds a coin (otherwise it records a spent coin whose deletion is not written yet,
/// or, when clean, an outpoint the backend is known not to hold).
const PRESENT: u8 = 1;
/// The slot differs from the backend.
const DIRTY: u8 = 2;
/// The backend certainly does not hold this outpoint (so spending it needs no write).
const FRESH: u8 = 4;
/// Scripts up to this length are stored inside the slot; longer ones in a side table.
const INLINE_SCRIPT: usize = 35;
const SCRIPT_IN_SIDE_TABLE: u8 = 0xff;

/// One cached outpoint, in a fixed 52 bytes (no heap allocation for common scripts).
#[derive(Clone, Copy)]
#[repr(C)]
struct Slot {
    value: [u32; 2],
    code: u32,
    flags: u8,
    script_len: u8,
    script: [u8; INLINE_SCRIPT],
}

impl Slot {
    fn empty(flags: u8) -> Slot {
        Slot { value: [0, 0], code: 0, flags, script_len: 0, script: [0; INLINE_SCRIPT] }
    }

    fn present(&self) -> bool {
        self.flags & PRESENT != 0
    }

    fn value(&self) -> i64 {
        (self.value[0] as u64 | ((self.value[1] as u64) << 32)) as i64
    }

    fn height(&self) -> i32 {
        (self.code >> 1) as i32
    }

    fn is_coinbase(&self) -> bool {
        self.code & 1 == 1
    }
}

/// Write-back cache of coins over a backend, in a hash table sized once (so it never reallocates
/// while full of coins). Lookups that miss go to the backend (never "assumed absent": Appendix
/// B.4); changes are written back by `flush`, which then empties the cache.
pub struct CoinsCache {
    map: OutPointMap<Slot>,
    /// Scripts longer than `INLINE_SCRIPT` bytes of present slots.
    side: OutPointMap<Box<[u8]>>,
    side_bytes: usize,
    db: Box<dyn CoinDb>,
    /// Entries the table was sized for.
    capacity: usize,
    /// The block whose UTXO set the cache (plus backend) represents.
    pub best_block: Hash256,
}

/// Bytes one table bucket costs (key, slot and control byte).
pub const BUCKET_BYTES: usize = std::mem::size_of::<(OutPoint, Slot)>() + 1;

impl CoinsCache {
    /// A cache whose table holds `capacity` entries without reallocating.
    pub fn new(db: Box<dyn CoinDb>, best_block: Hash256, capacity: usize) -> CoinsCache {
        CoinsCache {
            map: HashMap::with_capacity_and_hasher(capacity, OutPointHashBuilder::new()),
            side: new_outpoint_map(),
            side_bytes: 0,
            db,
            capacity,
            best_block,
        }
    }

    /// The largest capacity whose table fits in `bytes` (tables have a power-of-two number of
    /// buckets, at most 7/8 of them used).
    pub fn capacity_for_bytes(bytes: usize) -> usize {
        let mut buckets = 1usize << 4;
        while (buckets * 2) * BUCKET_BYTES <= bytes {
            buckets *= 2;
        }
        buckets / 8 * 7
    }

    pub fn db(&self) -> &dyn CoinDb {
        self.db.as_ref()
    }

    pub fn db_mut(&mut self) -> &mut dyn CoinDb {
        self.db.as_mut()
    }

    /// Memory used by the table and the side table, in bytes (approximate).
    pub fn usage(&self) -> usize {
        self.map.capacity().max(self.map.len()) * 8 / 7 * BUCKET_BYTES + self.side_bytes + self.side.capacity() * 48
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// True when the table is close to needing to grow (a flush empties it).
    pub fn needs_flush(&self, margin: usize) -> bool {
        let headroom = self.map.capacity().saturating_sub(self.map.len());
        headroom < margin.min(self.capacity / 4).max(1) || self.side_bytes > self.capacity * 8
    }

    fn slot_coin(&self, outpoint: &OutPoint, slot: &Slot) -> Option<Coin> {
        if !slot.present() {
            return None;
        }
        let script_pubkey = if slot.script_len == SCRIPT_IN_SIDE_TABLE {
            self.side.get(outpoint).expect("side-table script").to_vec()
        } else {
            slot.script[..slot.script_len as usize].to_vec()
        };
        Some(Coin { output: TxOut { value: slot.value(), script_pubkey }, height: slot.height(), is_coinbase: slot.is_coinbase() })
    }

    /// Fills `slot` with `coin`, keeping long scripts in the side table.
    fn store_coin(&mut self, outpoint: &OutPoint, slot: &mut Slot, coin: Coin) {
        let value = coin.output.value as u64;
        slot.value = [value as u32, (value >> 32) as u32];
        slot.code = ((coin.height as u32) << 1) | coin.is_coinbase as u32;
        let script = coin.output.script_pubkey;
        if script.len() <= INLINE_SCRIPT {
            slot.script_len = script.len() as u8;
            slot.script[..script.len()].copy_from_slice(&script);
            if let Some(old) = self.side.remove(outpoint) {
                self.side_bytes -= old.len();
            }
        } else {
            slot.script_len = SCRIPT_IN_SIDE_TABLE;
            self.side_bytes += script.len();
            if let Some(old) = self.side.insert(*outpoint, script.into_boxed_slice()) {
                self.side_bytes -= old.len();
            }
        }
    }

    fn drop_side(&mut self, outpoint: &OutPoint, slot: &Slot) {
        if slot.present() && slot.script_len == SCRIPT_IN_SIDE_TABLE {
            if let Some(old) = self.side.remove(outpoint) {
                self.side_bytes -= old.len();
            }
        }
    }

    /// Looks a coin up, caching what the backend returns.
    pub fn get(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        if let Some(slot) = self.map.get(outpoint) {
            return self.slot_coin(outpoint, slot);
        }
        let coin = self.db.get(outpoint)?;
        let mut slot = Slot::empty(PRESENT);
        self.store_coin(outpoint, &mut slot, coin.clone());
        self.map.insert(*outpoint, slot);
        Some(coin)
    }

    /// True if the outpoint is cached (as a coin, a pending deletion or a known absence).
    pub fn is_cached(&self, outpoint: &OutPoint) -> bool {
        self.map.contains_key(outpoint)
    }

    /// Loads the given outpoints from the backend (in one batched, possibly parallel lookup) if
    /// they are not cached. Purely a performance measure: results are identical without it.
    pub fn prefetch(&mut self, outpoints: &[OutPoint]) {
        let mut missing: Vec<OutPoint> = outpoints.iter().filter(|op| !self.map.contains_key(op)).copied().collect();
        if missing.is_empty() {
            return;
        }
        missing.sort_unstable();
        missing.dedup();
        let found = self.db.get_many(&missing);
        for (outpoint, coin) in missing.into_iter().zip(found) {
            // An absent outpoint is cached as a clean, fresh, empty slot: the backend does not
            // hold it, and the backend only changes in `flush`, which empties the cache.
            let mut slot = Slot::empty(0);
            match coin {
                Some(coin) => {
                    slot.flags = PRESENT;
                    self.store_coin(&outpoint, &mut slot, coin);
                }
                None => slot.flags = FRESH,
            }
            self.map.insert(outpoint, slot);
        }
    }

    /// Records a coin. `fresh_hint` asserts that the backend cannot hold this outpoint.
    pub fn put(&mut self, outpoint: OutPoint, coin: Coin, fresh_hint: bool) {
        let mut slot = match self.map.get(&outpoint) {
            Some(existing) => {
                let mut slot = *existing;
                slot.flags = (existing.flags & FRESH) | PRESENT | DIRTY;
                slot
            }
            None => Slot::empty(PRESENT | DIRTY | if fresh_hint { FRESH } else { 0 }),
        };
        self.store_coin(&outpoint, &mut slot, coin);
        self.map.insert(outpoint, slot);
    }

    /// Removes a coin.
    pub fn delete(&mut self, outpoint: &OutPoint) {
        match self.map.get(outpoint).copied() {
            Some(slot) => {
                self.drop_side(outpoint, &slot);
                if slot.flags & FRESH != 0 {
                    self.map.remove(outpoint);
                } else {
                    self.map.insert(*outpoint, Slot::empty(DIRTY));
                }
            }
            None => {
                self.map.insert(*outpoint, Slot::empty(DIRTY));
            }
        }
    }

    /// Number of entries that differ from the backend.
    pub fn dirty_count(&self) -> usize {
        self.map.values().filter(|slot| slot.flags & DIRTY != 0).count()
    }

    /// Writes every pending change to the backend atomically, recording `best_block`, then
    /// empties the cache. The changes are split into key ranges (by the first byte of the txid)
    /// that the backend may sort and write in parallel.
    pub fn flush(&mut self) -> std::io::Result<usize> {
        const PARTS: usize = 16;
        let mut parts: Vec<Vec<(&OutPoint, &Slot)>> = (0..PARTS).map(|_| Vec::new()).collect();
        for (outpoint, slot) in self.map.iter() {
            if slot.flags & DIRTY != 0 {
                parts[outpoint.txid[0] as usize * PARTS / 256].push((outpoint, slot));
            }
        }
        let written: usize = parts.iter().map(|part| part.len()).sum();
        let parts: Vec<std::sync::Mutex<Vec<(&OutPoint, &Slot)>>> = parts.into_iter().map(std::sync::Mutex::new).collect();
        let side = &self.side;
        let produce = |part: usize, sink: &mut dyn FnMut(OutPoint, Option<CoinRef<'_>>)| {
            let mut entries = std::mem::take(&mut *parts[part].lock().unwrap());
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            for (outpoint, slot) in entries {
                let coin = if slot.present() {
                    let script: &[u8] = if slot.script_len == SCRIPT_IN_SIDE_TABLE { side.get(outpoint).expect("side-table script") } else { &slot.script[..slot.script_len as usize] };
                    Some(CoinRef { value: slot.value(), height: slot.height(), is_coinbase: slot.is_coinbase(), script })
                } else {
                    None
                };
                sink(*outpoint, coin);
            }
        };
        self.db.write_parts(PARTS, &produce, &self.best_block)?;
        drop(parts);
        self.map.clear();
        self.side.clear();
        self.side.shrink_to_fit();
        self.side_bytes = 0;
        Ok(written)
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

    fn coin(script: Vec<u8>, height: i32) -> Coin {
        Coin { output: TxOut { value: 1234, script_pubkey: script }, height, is_coinbase: height % 2 == 0 }
    }

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
                let mut via_ref = Vec::new();
                write_coin_ref(&mut via_ref, &CoinRef::of(&coin));
                assert_eq!(via_ref, encode_coin(&coin));
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

    /// The cache over a backend behaves exactly like a plain map of coins, whatever the order of
    /// puts, deletes, lookups, prefetches and flushes.
    #[test]
    fn cache_matches_plain_map() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut cache = CoinsCache::new(Box::<MemoryCoinDb>::default(), [0; 32], 64);
        let mut model: BTreeMap<OutPoint, Coin> = BTreeMap::new();
        for step in 0..200_000 {
            let outpoint = OutPoint { txid: [(next() % 40) as u8; 32], vout: (next() % 3) as u32 };
            match next() % 10 {
                0..=3 => {
                    let script = if next() % 5 == 0 { vec![0xab; 50 + (next() % 20) as usize] } else { vec![0x51; (next() % 36) as usize] };
                    let c = coin(script, (next() % 1000) as i32);
                    // The fresh hint may only be given when the backend cannot hold the outpoint.
                    let fresh = !model.contains_key(&outpoint) && !cache.is_cached(&outpoint) && cache.db().get(&outpoint).is_none() && next() % 2 == 0;
                    cache.put(outpoint, c.clone(), fresh);
                    model.insert(outpoint, c);
                }
                4..=5 => {
                    if model.remove(&outpoint).is_some() {
                        cache.delete(&outpoint);
                    }
                }
                6..=7 => assert_eq!(cache.get(&outpoint), model.get(&outpoint).cloned(), "step {step}"),
                8 => cache.prefetch(&[outpoint, OutPoint { txid: [(next() % 40) as u8; 32], vout: 1 }]),
                _ => {
                    if next() % 20 == 0 {
                        cache.flush().unwrap();
                        let mut from_db = BTreeMap::new();
                        cache.db().for_each_sorted(&mut |op, c| {
                            from_db.insert(*op, c.clone());
                        }).unwrap();
                        assert_eq!(from_db, model, "step {step}");
                    }
                }
            }
        }
    }
}
