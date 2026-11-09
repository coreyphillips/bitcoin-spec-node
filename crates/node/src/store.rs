//! Persistent storage for the node: a `ChainStore` over RocksDB (coins and the block index) and
//! flat files (block and undo data).
//!
//! Crash safety: the coin database is only ever changed by `flush`, which writes all pending
//! changes plus the hash of the block they correspond to as one sorted SST file and ingests it
//! (an atomic operation). Before that, every block and undo file and every block index record
//! the flush could depend on has been written. A process killed at any moment therefore restarts
//! from the last flushed block, with an index that contains it; blocks after it are downloaded
//! and connected again.

use consensus::chain::{BlockEntry, BlockTree, BlockUndo, ChainStore, EntryId};
use consensus::coins::{decode_coin, outpoint_from_key, outpoint_key, read_coin, read_varint, write_coin, write_coin_ref, write_varint, CoinDb, CoinRef, CoinsCache, UtxoHasher};
use consensus::hashes::sha256d;
use consensus::serialize::Reader;
use consensus::tx::{deserialize_block_data, BlockData, BlockHeader, OutPoint};
use consensus::tx_rules::Coin;
use consensus::util::{hash_to_display, Hash256};
use crossbeam_channel::{Receiver, Sender};
use rayon::prelude::*;
use rocksdb::{BlockBasedOptions, Cache, ColumnFamilyDescriptor, IngestExternalFileOptions, Options, SstFileWriter, WriteBatch, WriteOptions, DB};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const CF_COINS: &str = "coins";
pub const CF_INDEX: &str = "index";
/// Key of the "best block" record inside the coins column family. It sorts after every 36-byte
/// outpoint key, so the coins and the record they belong to are written by one ingestion.
pub const BEST_BLOCK_KEY: [u8; 37] = [0xff; 37];

fn to_io(error: rocksdb::Error) -> io::Error {
    io::Error::other(error.to_string())
}

/// Options of the coins column family (also used to write the SST files that are ingested).
fn coins_options(cache: &Cache) -> Options {
    let mut table = BlockBasedOptions::default();
    table.set_block_cache(cache);
    table.set_bloom_filter(10.0, false);
    table.set_cache_index_and_filter_blocks(true);
    table.set_block_size(16 * 1024);
    let mut options = Options::default();
    options.set_block_based_table_factory(&table);
    options.set_compression_type(rocksdb::DBCompressionType::None);
    options.set_target_file_size_base(128 << 20);
    options.set_level_compaction_dynamic_level_bytes(true);
    options
}

/// The node's RocksDB database.
pub struct Database {
    pub db: Arc<DB>,
    pub coins_options: Options,
    pub dir: PathBuf,
}

impl Database {
    pub fn open(dir: &Path, cache_bytes: usize) -> io::Result<Database> {
        std::fs::create_dir_all(dir)?;
        let cache = Cache::new_lru_cache(cache_bytes);
        let mut db_options = Options::default();
        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);
        db_options.set_max_background_jobs(6);
        db_options.set_max_open_files(2000);
        db_options.set_keep_log_file_num(4);
        let coins = coins_options(&cache);
        let mut index_options = Options::default();
        let mut index_table = BlockBasedOptions::default();
        index_table.set_block_cache(&cache);
        index_options.set_block_based_table_factory(&index_table);
        let cfs = vec![ColumnFamilyDescriptor::new(CF_COINS, coins_options(&cache)), ColumnFamilyDescriptor::new(CF_INDEX, index_options)];
        let db = DB::open_cf_descriptors(&db_options, dir, cfs).map_err(to_io)?;
        Ok(Database { db: Arc::new(db), coins_options: coins, dir: dir.to_path_buf() })
    }

    pub fn get_meta(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        self.db.get(key.as_bytes()).map_err(to_io)
    }

    pub fn put_meta(&self, key: &str, value: &[u8]) -> io::Result<()> {
        let mut options = WriteOptions::default();
        options.set_sync(true);
        self.db.put_opt(key.as_bytes(), value, &options).map_err(to_io)
    }
}

/// The coin backend in RocksDB.
pub struct RocksCoinDb {
    db: Arc<DB>,
    options: Options,
    sst_dir: PathBuf,
    sequence: u64,
}

impl RocksCoinDb {
    pub fn new(database: &Database) -> io::Result<RocksCoinDb> {
        let sst_dir = database.dir.join("ingest");
        std::fs::create_dir_all(&sst_dir)?;
        // Leftovers of an interrupted flush were never ingested; they are garbage.
        for entry in std::fs::read_dir(&sst_dir)? {
            let _ = std::fs::remove_file(entry?.path());
        }
        Ok(RocksCoinDb { db: database.db.clone(), options: database.coins_options.clone(), sst_dir, sequence: 0 })
    }
}

impl CoinDb for RocksCoinDb {
    fn get(&self, outpoint: &OutPoint) -> Option<Coin> {
        let cf = self.db.cf_handle(CF_COINS).expect("coins column family");
        let value = self.db.get_pinned_cf(&cf, outpoint_key(outpoint)).expect("coin database read failed")?;
        Some(decode_coin(&value).expect("corrupt coin record"))
    }

    fn get_many(&self, outpoints: &[OutPoint]) -> Vec<Option<Coin>> {
        if outpoints.len() < 64 {
            return outpoints.iter().map(|op| self.get(op)).collect();
        }
        outpoints.par_iter().with_min_len(16).map(|op| self.get(op)).collect()
    }

    fn write(&mut self, changes: &mut dyn Iterator<Item = (OutPoint, Option<CoinRef<'_>>)>, best: &Hash256) -> io::Result<()> {
        self.sequence += 1;
        let path = self.sst_dir.join(format!("flush-{}-{}.sst", std::process::id(), self.sequence));
        let mut writer = SstFileWriter::create(&self.options);
        writer.open(&path).map_err(to_io)?;
        let mut buffer = Vec::with_capacity(128);
        for (outpoint, coin) in changes {
            let key = outpoint_key(&outpoint);
            match coin {
                Some(coin) => {
                    buffer.clear();
                    write_coin_ref(&mut buffer, &coin);
                    writer.put(key, &buffer).map_err(to_io)?;
                }
                None => writer.delete(key).map_err(to_io)?,
            }
        }
        writer.put(BEST_BLOCK_KEY, best).map_err(to_io)?;
        writer.finish().map_err(to_io)?;
        drop(writer);
        let mut ingest = IngestExternalFileOptions::default();
        ingest.set_move_files(true);
        let cf = self.db.cf_handle(CF_COINS).expect("coins column family");
        self.db.ingest_external_file_cf_opts(&cf, &ingest, vec![&path]).map_err(to_io)?;
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    fn best_block(&self) -> Option<Hash256> {
        let cf = self.db.cf_handle(CF_COINS).expect("coins column family");
        let value = self.db.get_pinned_cf(&cf, BEST_BLOCK_KEY).expect("coin database read failed")?;
        value.as_ref().try_into().ok()
    }

    fn for_each_sorted(&self, visit: &mut dyn FnMut(&OutPoint, &Coin)) -> io::Result<()> {
        let cf = self.db.cf_handle(CF_COINS).expect("coins column family");
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_first();
        while iter.valid() {
            let key = iter.key().unwrap();
            if key.len() == 36 {
                let outpoint = outpoint_from_key(key).unwrap();
                let coin = decode_coin(iter.value().unwrap()).map_err(|e| io::Error::other(e.0))?;
                visit(&outpoint, &coin);
            }
            iter.next();
        }
        iter.status().map_err(to_io)
    }
}

/// Computes the chapter 15 fingerprint of the coin database as it is when this is called. The
/// iterator is created before `created` is signalled; it sees that point-in-time state even if
/// later flushes change the database.
pub fn utxo_hash_of_database(db: &DB, created: Option<Sender<()>>) -> io::Result<(Hash256, u64, Option<Hash256>)> {
    let cf = db.cf_handle(CF_COINS).expect("coins column family");
    let mut iter = db.raw_iterator_cf(&cf);
    iter.seek_to_first();
    if let Some(created) = created {
        let _ = created.send(());
    }
    let mut hasher = UtxoHasher::new();
    let mut best = None;
    let mut reader_buffer;
    while iter.valid() {
        let key = iter.key().unwrap();
        if key.len() == 36 {
            let outpoint = outpoint_from_key(key).unwrap();
            reader_buffer = iter.value().unwrap();
            let coin = read_coin(&mut Reader::new(reader_buffer)).map_err(|e| io::Error::other(e.0))?;
            hasher.add(&outpoint, &coin);
        } else if key == BEST_BLOCK_KEY {
            best = iter.value().and_then(|v| v.try_into().ok());
        }
        iter.next();
    }
    iter.status().map_err(to_io)?;
    let (hash, count) = hasher.finish();
    Ok((hash, count, best))
}

// ---------------------------------------------------------------------------------------------
// Block index records.

const FLAG_HAS_DATA: u8 = 1;
const FLAG_HAS_UNDO: u8 = 2;
const FLAG_FAILED: u8 = 4;
const FLAG_CONNECTED_ONCE: u8 = 8;

/// A persisted block index entry: header, height, header order and flags. Chain work, median
/// time past, parent and skip pointers are recomputed when the index is loaded.
#[derive(Clone, Debug)]
pub struct IndexRecord {
    pub hash: Hash256,
    pub header: BlockHeader,
    pub height: i32,
    pub header_order: u64,
    pub flags: u8,
}

impl IndexRecord {
    pub fn from_entry(entry: &BlockEntry) -> IndexRecord {
        let mut flags = 0;
        if entry.has_data {
            flags |= FLAG_HAS_DATA;
        }
        if entry.has_undo {
            flags |= FLAG_HAS_UNDO;
        }
        if entry.failed {
            flags |= FLAG_FAILED;
        }
        if entry.connected_once {
            flags |= FLAG_CONNECTED_ONCE;
        }
        IndexRecord { hash: entry.hash, header: entry.header, height: entry.height, header_order: entry.header_order, flags }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(93);
        out.extend_from_slice(&self.header.serialize());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.header_order.to_le_bytes());
        out.push(self.flags);
        out
    }

    pub fn decode(hash: &[u8], value: &[u8]) -> Option<IndexRecord> {
        if hash.len() != 32 || value.len() != 93 {
            return None;
        }
        let header = BlockHeader::deserialize(value[..80].try_into().unwrap());
        Some(IndexRecord {
            hash: hash.try_into().unwrap(),
            header,
            height: i32::from_le_bytes(value[80..84].try_into().unwrap()),
            header_order: u64::from_le_bytes(value[84..92].try_into().unwrap()),
            flags: value[92],
        })
    }

    pub fn has_data(&self) -> bool {
        self.flags & FLAG_HAS_DATA != 0
    }
    pub fn has_undo(&self) -> bool {
        self.flags & FLAG_HAS_UNDO != 0
    }
    pub fn failed(&self) -> bool {
        self.flags & FLAG_FAILED != 0
    }
    pub fn connected_once(&self) -> bool {
        self.flags & FLAG_CONNECTED_ONCE != 0
    }
}

pub fn load_index(database: &Database) -> io::Result<Vec<IndexRecord>> {
    let cf = database.db.cf_handle(CF_INDEX).expect("index column family");
    let mut iter = database.db.raw_iterator_cf(&cf);
    iter.seek_to_first();
    let mut records = Vec::new();
    while iter.valid() {
        let record = IndexRecord::decode(iter.key().unwrap(), iter.value().unwrap()).ok_or_else(|| io::Error::other("corrupt block index record"))?;
        records.push(record);
        iter.next();
    }
    iter.status().map_err(to_io)?;
    Ok(records)
}

// ---------------------------------------------------------------------------------------------
// Block and undo files.

pub fn encode_undo(undo: &BlockUndo) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + undo.iter().map(|tx| tx.len() * 40).sum::<usize>());
    write_varint(&mut out, undo.len() as u64);
    for tx in undo {
        write_varint(&mut out, tx.len() as u64);
        for coin in tx {
            write_coin(&mut out, coin);
        }
    }
    let checksum = sha256d(&out);
    out.extend_from_slice(&checksum[..4]);
    out
}

pub fn decode_undo(bytes: &[u8]) -> Option<BlockUndo> {
    if bytes.len() < 5 {
        return None;
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 4);
    if sha256d(body)[..4] != *checksum {
        return None;
    }
    let mut reader = Reader::new(body);
    let count = read_varint(&mut reader).ok()?;
    let mut undo = Vec::with_capacity(count.min(1 << 20) as usize);
    for _ in 0..count {
        let coins = read_varint(&mut reader).ok()?;
        let mut tx = Vec::with_capacity(coins.min(1 << 20) as usize);
        for _ in 0..coins {
            tx.push(read_coin(&mut reader).ok()?);
        }
        undo.push(tx);
    }
    if reader.remaining() != 0 {
        return None;
    }
    Some(undo)
}

enum WriteJob {
    Block(PathBuf, Arc<BlockData>),
    Undo(PathBuf, BlockUndo),
    Remove(Vec<PathBuf>),
    Barrier(Sender<()>),
}

fn write_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path)
}

fn writer_loop(jobs: Receiver<WriteJob>) {
    for job in jobs {
        let result = match job {
            WriteJob::Block(path, block) => write_file(&path, &block.block.serialize(true)),
            WriteJob::Undo(path, undo) => write_file(&path, &encode_undo(&undo)),
            WriteJob::Remove(paths) => {
                for path in paths {
                    let _ = std::fs::remove_file(path);
                }
                Ok(())
            }
            WriteJob::Barrier(done) => {
                let _ = done.send(());
                Ok(())
            }
        };
        if let Err(error) = result {
            eprintln!("fatal: cannot write block data: {error}");
            std::process::exit(1);
        }
    }
}

/// A flush is made before the coin table has fewer free slots than this (more than any block
/// can add), so that the table never has to grow.
const FLUSH_MARGIN: usize = 1_000_000;

/// Settings and callbacks the store applies when blocks are connected.
pub struct Hooks {
    /// Stop chain activation (and the node) when this block becomes the tip.
    pub stop_at: Option<Hash256>,
    /// Heights at which to print the UTXO set fingerprint.
    pub utxo_hash_heights: Vec<i32>,
    /// Flush the coin cache when it uses more than this many bytes.
    pub cache_limit: usize,
    /// Minimum interval between progress lines.
    pub progress_interval: std::time::Duration,
    /// Flush at least this often.
    pub flush_interval: std::time::Duration,
}

/// The node's `ChainStore`.
pub struct DiskStore {
    pub database: Database,
    coins: CoinsCache,
    blocks_dir: PathBuf,
    recent: HashMap<Hash256, Arc<BlockData>>,
    recent_order: VecDeque<Hash256>,
    pending_index: HashMap<Hash256, Vec<u8>>,
    writer: Sender<WriteJob>,
    pub hooks: Hooks,
    last_progress: std::time::Instant,
    last_flush: std::time::Instant,
    pub stop_reached: bool,
    /// Background UTXO fingerprint computations in progress.
    pub hash_threads: Vec<std::thread::JoinHandle<()>>,
    pub connected_count: u64,
}

impl DiskStore {
    pub fn open(datadir: &Path, rocks_cache: usize, hooks: Hooks) -> io::Result<DiskStore> {
        let database = Database::open(&datadir.join("chainstate"), rocks_cache)?;
        let blocks_dir = datadir.join("blocks");
        std::fs::create_dir_all(&blocks_dir)?;
        let coin_db = RocksCoinDb::new(&database)?;
        let best = coin_db.best_block().unwrap_or([0u8; 32]);
        let capacity = CoinsCache::capacity_for_bytes(hooks.cache_limit);
        let coins = CoinsCache::new(Box::new(coin_db), best, capacity);
        eprintln!("coin cache: room for {} coins ({} MiB table)", capacity, (capacity * 8 / 7 * consensus::coins::BUCKET_BYTES) >> 20);
        let (sender, receiver) = crossbeam_channel::bounded(256);
        std::thread::Builder::new().name("block-writer".into()).spawn(move || writer_loop(receiver))?;
        Ok(DiskStore {
            database,
            coins,
            blocks_dir,
            recent: HashMap::new(),
            recent_order: VecDeque::new(),
            pending_index: HashMap::new(),
            writer: sender,
            hooks,
            last_progress: std::time::Instant::now() - std::time::Duration::from_secs(3600),
            last_flush: std::time::Instant::now(),
            stop_reached: false,
            hash_threads: Vec::new(),
            connected_count: 0,
        })
    }

    /// The block the coin database holds (all zeros for a new database).
    pub fn coins_best_block(&self) -> Hash256 {
        self.coins.db().best_block().unwrap_or([0u8; 32])
    }

    fn block_path(&self, hash: &Hash256) -> PathBuf {
        self.blocks_dir.join(format!("{}.blk", hash_to_display(hash)))
    }

    fn undo_path(&self, hash: &Hash256) -> PathBuf {
        self.blocks_dir.join(format!("{}.rev", hash_to_display(hash)))
    }

    pub fn block_file_exists(&self, hash: &Hash256) -> bool {
        self.block_path(hash).exists()
    }

    pub fn undo_file_exists(&self, hash: &Hash256) -> bool {
        self.undo_path(hash).exists()
    }

    /// Waits until every queued file write is done.
    pub fn writer_barrier(&self) {
        let (done, wait) = crossbeam_channel::bounded(1);
        self.writer.send(WriteJob::Barrier(done)).expect("writer thread");
        let _ = wait.recv();
    }

    /// Writes the block index records queued so far.
    pub fn write_index(&mut self, sync: bool) -> io::Result<()> {
        if self.pending_index.is_empty() {
            return Ok(());
        }
        let cf = self.database.db.cf_handle(CF_INDEX).expect("index column family");
        let mut batch = WriteBatch::default();
        for (hash, record) in self.pending_index.drain() {
            batch.put_cf(&cf, hash, record);
        }
        let mut options = WriteOptions::default();
        options.set_sync(sync);
        self.database.db.write_opt(batch, &options).map_err(to_io)
    }

    /// Makes everything durable: block and undo files, the block index, then the coins.
    pub fn flush(&mut self) -> io::Result<()> {
        let started = std::time::Instant::now();
        self.writer_barrier();
        self.write_index(true)?;
        let entries = self.coins.len();
        let written = self.coins.flush()?;
        self.last_flush = std::time::Instant::now();
        eprintln!("flush: {written} changes from {entries} cached coins written in {:.1}s", started.elapsed().as_secs_f64());
        Ok(())
    }

    /// Computes the fingerprint of the coin database in the background and prints the
    /// `utxo_hash` event; returns once the database view has been pinned.
    fn spawn_utxo_hash(&mut self, height: i32, tip: Hash256) {
        let db = self.database.db.clone();
        let (created, wait) = crossbeam_channel::bounded(1);
        let handle = std::thread::Builder::new()
            .name(format!("utxo-hash-{height}"))
            .spawn(move || {
                let started = std::time::Instant::now();
                match utxo_hash_of_database(&db, Some(created)) {
                    Ok((hash, count, best)) => {
                        if best != Some(tip) {
                            eprintln!("warning: utxo hash at height {height}: database best block does not match the tip");
                        }
                        crate::emit(&format!(
                            "{{\"event\":\"utxo_hash\",\"height\":{},\"hash_serialized_3\":\"{}\",\"txouts\":{}}}",
                            height,
                            hash_to_display(&hash),
                            count
                        ));
                        eprintln!("utxo hash at height {height} computed in {:.1}s", started.elapsed().as_secs_f64());
                    }
                    Err(error) => eprintln!("error: utxo hash at height {height} failed: {error}"),
                }
            })
            .expect("spawn hasher");
        let _ = wait.recv();
        self.hash_threads.push(handle);
    }

    pub fn coins_usage(&self) -> usize {
        self.coins.usage()
    }

    pub fn coins_entries(&self) -> usize {
        self.coins.len()
    }

    /// Removes blocks from the in-memory set once the file exists (or is queued).
    fn trim_recent(&mut self) {
        while self.recent_order.len() > 64 {
            if let Some(hash) = self.recent_order.pop_front() {
                self.recent.remove(&hash);
            }
        }
    }
}

impl ChainStore for DiskStore {
    fn coins(&mut self) -> &mut CoinsCache {
        &mut self.coins
    }

    fn put_block(&mut self, entry: &BlockEntry, block: Arc<BlockData>) {
        let path = self.block_path(&entry.hash);
        self.writer.send(WriteJob::Block(path, block.clone())).expect("writer thread");
        if self.recent.insert(entry.hash, block).is_none() {
            self.recent_order.push_back(entry.hash);
        }
        self.trim_recent();
    }

    fn get_block(&mut self, entry: &BlockEntry) -> Option<Arc<BlockData>> {
        if let Some(block) = self.recent.get(&entry.hash) {
            return Some(block.clone());
        }
        self.writer_barrier();
        let bytes = std::fs::read(self.block_path(&entry.hash)).ok()?;
        let data = deserialize_block_data(&bytes).ok()?;
        if data.hash != entry.hash {
            return None;
        }
        Some(Arc::new(data))
    }

    fn put_undo(&mut self, entry: &BlockEntry, _block: &Arc<BlockData>, undo: BlockUndo) {
        let path = self.undo_path(&entry.hash);
        self.writer.send(WriteJob::Undo(path, undo)).expect("writer thread");
    }

    fn get_undo(&mut self, entry: &BlockEntry) -> Option<BlockUndo> {
        self.writer_barrier();
        let bytes = std::fs::read(self.undo_path(&entry.hash)).ok()?;
        decode_undo(&bytes)
    }

    fn entry_changed(&mut self, _id: EntryId, entry: &BlockEntry) {
        self.pending_index.insert(entry.hash, IndexRecord::from_entry(entry).encode());
    }

    fn connected(&mut self, tree: &BlockTree, id: EntryId) -> bool {
        let entry = tree.get(id);
        self.connected_count += 1;
        let now = std::time::Instant::now();
        let is_stop = self.hooks.stop_at == Some(entry.hash);
        if is_stop || now.duration_since(self.last_progress) >= self.hooks.progress_interval {
            self.last_progress = now;
            crate::emit(&format!("{{\"event\":\"tip\",\"tip\":\"{}\",\"height\":{}}}", hash_to_display(&entry.hash), entry.height));
        }
        if self.hooks.utxo_hash_heights.contains(&entry.height) {
            crate::emit(&format!("{{\"event\":\"tip\",\"tip\":\"{}\",\"height\":{}}}", hash_to_display(&entry.hash), entry.height));
            if let Err(error) = self.flush() {
                eprintln!("fatal: flush failed: {error}");
                std::process::exit(1);
            }
            self.spawn_utxo_hash(entry.height, entry.hash);
        } else if self.coins.needs_flush(FLUSH_MARGIN) || self.last_flush.elapsed() > self.hooks.flush_interval {
            if let Err(error) = self.flush() {
                eprintln!("fatal: flush failed: {error}");
                std::process::exit(1);
            }
        }
        if is_stop {
            self.stop_reached = true;
            return false;
        }
        true
    }

    fn remove_data(&mut self, entry: &BlockEntry) {
        self.recent.remove(&entry.hash);
        let paths = vec![self.block_path(&entry.hash), self.undo_path(&entry.hash)];
        self.writer.send(WriteJob::Remove(paths)).expect("writer thread");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::tx::TxOut;

    #[test]
    fn undo_round_trip() {
        let coin = Coin { output: TxOut { value: 5, script_pubkey: vec![0x51] }, height: 7, is_coinbase: false };
        let undo = vec![vec![coin.clone(), coin.clone()], vec![], vec![coin]];
        let bytes = encode_undo(&undo);
        assert_eq!(decode_undo(&bytes), Some(undo));
        let mut corrupt = bytes.clone();
        corrupt[1] ^= 1;
        assert_eq!(decode_undo(&corrupt), None);
    }
}
