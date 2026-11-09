//! `bitcoin-spec-node run`: the persistent full node.
//!
//! One thread owns the chain state (chapter 11) and handles every peer message in arrival order;
//! block payloads are decoded (and their transactions hashed) in parallel before they reach it.
//! The blocks of one batch of messages are stored first and connected by one chain activation, in
//! which the script checks of a block run in parallel with the UTXO work of the next. Headers are
//! synchronized first (chapter 14 section 14.3); blocks are requested along the best header chain,
//! oldest first, with at most `max_in_flight` per peer, and requests are refilled by the peer reader
//! threads as blocks arrive (`downloads.rs`), so downloading continues while blocks are connected.

use crate::downloads::{DownloadState, Downloads};
use crate::net::{connect, NetEvent};
use crate::store::{load_index, utxo_hash_of_database, DiskStore, Hooks, IndexRecord};
use consensus::block_rules::{block_witness_merkle_root, check_block, is_block_mutated};
use consensus::chain::{headers_message_acceptable, p2p_block_work_acceptable, BlockEntry, BlockOutcome, BlockTree, ChainState, EntryId, HeaderError, HeadersRejection};
use consensus::p2p::*;
use consensus::params::{Network, NetworkOptions, NetworkParams};
use consensus::pow::{block_proof, median_time_past, MEDIAN_TIME_SPAN};
use consensus::tx::{deserialize_block_data, BlockData, BlockHeader};
use consensus::uint::U256;
use consensus::util::{hash_to_display, FailureKind, Hash256, ZERO_HASH};
use crossbeam_channel::{Receiver, Sender};
use rayon::prelude::*;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct NodeConfig {
    pub network: Network,
    pub datadir: PathBuf,
    pub connect: Vec<String>,
    pub stop_at: Option<Hash256>,
    pub utxo_hash_at: Vec<i32>,
    /// Coin cache limit in MiB.
    pub dbcache_mb: usize,
    /// Blocks per peer in flight.
    pub max_in_flight: usize,
    /// Keep block and undo data for at least this many blocks below the tip.
    pub prune_depth: i32,
    /// Network parameter overrides (non-mainnet only; PROTOCOL.md 4.8 and 5).
    pub options: NetworkOptions,
    /// With a stop block: give up (exit with an error) after this long without progress.
    pub idle_timeout: Duration,
    /// Without `--connect`: how many peers found through the DNS seeds to keep connected.
    pub max_peers: usize,
}

/// DNS seeds (chapter 14 section 14.6) and the network's default port.
fn dns_seeds(network: Network) -> &'static [&'static str] {
    match network {
        Network::Main => &[
            "dnsseed.bluematt.me",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.net",
            "seed.bitcoin.sprovoost.nl",
            "dnsseed.emzy.de",
            "seed.bitcoin.wiz.biz",
            "seed.mainnet.achownodes.xyz",
        ],
        Network::Testnet3 => &["testnet-seed.bitcoin.jonasschnelli.ch", "seed.tbtc.petertodd.net", "testnet-seed.bluematt.me", "seed.testnet.achownodes.xyz"],
        Network::Testnet4 => &["seed.testnet4.bitcoin.sprovoost.nl", "seed.testnet4.wiz.biz"],
        Network::Signet => &["seed.signet.bitcoin.sprovoost.nl", "seed.signet.achownodes.xyz"],
        Network::Regtest => &[],
    }
}

/// Resolves the DNS seeds into a shuffled list of `address:port` strings.
fn resolve_seeds(network: Network, port: u16) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let mut addresses: Vec<String> = Vec::new();
    for seed in dns_seeds(network) {
        match (*seed, port).to_socket_addrs() {
            Ok(found) => addresses.extend(found.map(|a| a.to_string())),
            Err(error) => eprintln!("DNS seed {seed}: {error}"),
        }
    }
    addresses.sort();
    addresses.dedup();
    // Shuffle (Fisher-Yates with a clock-seeded generator).
    let mut state = random_u64() | 1;
    for i in (1..addresses.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        addresses.swap(i, (state % (i as u64 + 1)) as usize);
    }
    addresses
}

/// Blocks are not requested further than this above the active tip.
const MAX_AHEAD: i32 = 1024;
/// At most this many blocks are requested or received and not yet processed.
const MAX_BUFFERED: usize = 256;
/// At most this many messages are handled before chain activation runs.
const MAX_BATCH: usize = 512;
/// A block requested this long ago without an answer is requested again (Bitcoin Core never sends
/// `notfound` for blocks; chapter 14 section 14.4).
const BLOCK_TIMEOUT: Duration = Duration::from_secs(64);

pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// How often performance statistics go to standard error (`BSN_STATS_SECS`, default 10).
fn stats_interval() -> Duration {
    static SECONDS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    Duration::from_secs(*SECONDS.get_or_init(|| std::env::var("BSN_STATS_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(10)))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn random_u64() -> u64 {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(unix_now() as u64);
    hasher.finish()
}

/// Core: `LocatorEntries` (chapter 14 section 14.3).
pub fn block_locator(tree: &BlockTree, from: EntryId) -> Vec<Hash256> {
    let mut have = Vec::new();
    let mut step = 1;
    let mut entry = Some(from);
    while let Some(id) = entry {
        let current = tree.get(id);
        have.push(current.hash);
        if current.height == 0 {
            break;
        }
        let height = (current.height - step).max(0);
        entry = tree.ancestor(id, height);
        if have.len() > 10 {
            step *= 2;
        }
    }
    have
}

/// The answer to `getheaders`, or `None` for no answer at all (chapter 14 section 14.3): an empty
/// locator asks for the stop block's header only; otherwise the first locator hash that is on the
/// active chain (or descends from the active tip) is the fork point, unknown and side-branch hashes
/// are skipped, and genesis is used if none qualifies.
pub fn answer_getheaders(tree: &BlockTree, locator: &[Hash256], stop: &Hash256) -> Option<Vec<BlockHeader>> {
    if locator.is_empty() {
        let id = tree.lookup(stop)?;
        if !tree.is_active(id) {
            return None;
        }
        return Some(vec![tree.get(id).header]);
    }
    let tip = tree.tip();
    let tip_height = tree.get(tip).height;
    let mut fork_height = 0;
    for hash in locator {
        if let Some(id) = tree.lookup(hash) {
            if tree.is_active(id) {
                fork_height = tree.get(id).height;
                break;
            }
            if tree.ancestor(id, tip_height) == Some(tip) {
                fork_height = tip_height;
                break;
            }
        }
    }
    let mut headers = Vec::new();
    for height in fork_height + 1..=tip_height {
        let entry = tree.get(tree.active[height as usize]);
        headers.push(entry.header);
        if headers.len() >= MAX_HEADERS_RESULTS || entry.hash == *stop {
            break;
        }
    }
    Some(headers)
}

/// Loads the chain state from the data directory (or starts a new one).
fn load_chain(params: NetworkParams, store: DiskStore) -> Result<ChainState<DiskStore>, String> {
    let records = load_index(&store.database).map_err(|e| e.to_string())?;
    let coins_best = store.coins_best_block();
    if records.is_empty() {
        if coins_best != ZERO_HASH {
            return Err("the coin database has a best block but the block index is empty".into());
        }
        let genesis = params.consensus.genesis_hash;
        let mut chain = ChainState::new(params, store);
        consensus::chain::ChainStore::coins(&mut chain.store).best_block = genesis;
        chain.store.flush().map_err(|e| e.to_string())?;
        return Ok(chain);
    }
    let mut records = records;
    records.sort_by(|a, b| a.height.cmp(&b.height).then(a.header_order.cmp(&b.header_order)));
    let mut position: HashMap<Hash256, usize> = HashMap::with_capacity(records.len());
    let mut entries: Vec<BlockEntry> = Vec::with_capacity(records.len());
    let mut proofs: HashMap<u32, U256> = HashMap::new();
    for record in records.into_iter() {
        let IndexRecord { hash, header, height, header_order, .. } = record;
        let parent = if height == 0 {
            if hash != params.consensus.genesis_hash {
                return Err("block index has a height-0 entry that is not the genesis block".into());
            }
            None
        } else {
            match position.get(&header.prev_block) {
                Some(&p) => Some(p),
                None => {
                    eprintln!("warning: block index entry {} has no parent; ignored", hash_to_display(&hash));
                    continue;
                }
            }
        };
        let proof = *proofs.entry(header.bits).or_insert_with(|| block_proof(header.bits));
        let chain_work = parent.map_or(U256::ZERO, |p| entries[p].chain_work).wrapping_add(proof);
        let mut times = Vec::with_capacity(MEDIAN_TIME_SPAN);
        times.push(header.time as i64);
        let mut cursor = parent;
        while times.len() < MEDIAN_TIME_SPAN {
            match cursor {
                Some(p) => {
                    times.push(entries[p].header.time as i64);
                    cursor = entries[p].parent.map(|id| id as usize);
                }
                None => break,
            }
        }
        let has_data = record.has_data() && (height == 0 || store.block_file_exists(&hash));
        let has_undo = record.has_undo() && (height == 0 || store.undo_file_exists(&hash));
        position.insert(hash, entries.len());
        entries.push(BlockEntry {
            hash,
            header,
            height,
            parent: parent.map(|p| p as EntryId),
            skip: None,
            chain_work,
            median_time_past: median_time_past(&times),
            has_data,
            has_undo,
            sequence_id: 0,
            failed: record.failed(),
            connected_once: record.connected_once(),
            header_order,
        });
    }
    let active_tip = if coins_best == ZERO_HASH { params.consensus.genesis_hash } else { coins_best };
    ChainState::restore(params, store, entries, active_tip)
}

struct Peer {
    address: String,
    sender: Sender<Vec<u8>>,
    handshake_done: bool,
    headers_requested: Option<Instant>,
    services: u64,
    start_height: i32,
}

pub struct Node {
    config: NodeConfig,
    magic: [u8; 4],
    chain: ChainState<DiskStore>,
    events: Receiver<NetEvent>,
    event_sender: Sender<NetEvent>,
    peers: HashMap<usize, Peer>,
    next_peer_id: usize,
    reconnect_at: Vec<(Instant, String)>,
    downloads: Downloads,
    our_nonce: u64,
    pruned_to: i32,
    last_stats: Instant,
    stats_blocks: u64,
    stats_txs: u64,
    /// Last time the best header or the active tip changed (or a block or headers arrived).
    last_progress: Instant,
    progress_marker: (EntryId, EntryId),
    /// The wanted list was computed for this (best header, tip), at this time.
    wanted_marker: Option<(EntryId, EntryId)>,
    last_wanted: Instant,
    /// Set when the stop block can no longer be reached.
    fatal: Option<String>,
    /// Addresses from the DNS seeds not tried yet (discovery mode, without `--connect`).
    candidates: Vec<String>,
    last_resolve: Option<Instant>,
    /// A peer that holds the next needed block longer than this is stalling.
    stall_timeout: Duration,
    last_stall: Instant,
    /// The tip and since when it is the tip; when the last waiting diagnostic was printed.
    tip_since: (EntryId, Instant),
    last_wait_report: Instant,
}

/// Initial and maximum stall timeouts (Bitcoin Core: `BLOCK_STALLING_TIMEOUT_DEFAULT`, `_MAX`).
const STALL_TIMEOUT_MIN: Duration = Duration::from_secs(2);
const STALL_TIMEOUT_MAX: Duration = Duration::from_secs(64);

impl Node {
    pub fn new(config: NodeConfig) -> Result<Node, String> {
        let params = consensus::params::try_network_params(config.network, &config.options).map_err(|e| format!("invalid network options: {e}"))?;
        let magic = params.magic;
        let hooks = Hooks {
            stop_at: config.stop_at,
            utxo_hash_heights: config.utxo_hash_at.clone(),
            cache_limit: config.dbcache_mb << 20,
            progress_interval: Duration::from_millis(if config.network == Network::Regtest { 0 } else { 1000 }),
            flush_interval: Duration::from_secs(3600),
        };
        let rocks_cache = (config.dbcache_mb << 20) / 16 + (64 << 20);
        let store = DiskStore::open(&config.datadir, rocks_cache, hooks).map_err(|e| format!("cannot open data directory: {e}"))?;
        let identity = format!("{} {:?}", config.network.name(), config.options);
        if let Some(stored) = store.database.get_meta("network").map_err(|e| e.to_string())? {
            if stored != identity.as_bytes() {
                return Err(format!("data directory belongs to another network or options: {}", String::from_utf8_lossy(&stored)));
            }
        } else {
            store.database.put_meta("network", identity.as_bytes()).map_err(|e| e.to_string())?;
        }
        let chain = load_chain(params, store)?;
        let (event_sender, events) = crossbeam_channel::unbounded();
        let tip = chain.tip();
        eprintln!(
            "loaded chain: tip {} at height {}, best header at height {}, {} block index entries",
            hash_to_display(&tip.hash),
            tip.height,
            chain.best_header().height,
            chain.tree.entries.len()
        );
        let downloads = DownloadState::new(magic, config.max_in_flight, MAX_BUFFERED);
        Ok(Node {
            magic,
            pruned_to: 1,
            config,
            chain,
            events,
            event_sender,
            peers: HashMap::new(),
            next_peer_id: 1,
            reconnect_at: Vec::new(),
            downloads,
            our_nonce: random_u64(),
            last_stats: Instant::now(),
            stats_blocks: 0,
            stats_txs: 0,
            last_progress: Instant::now(),
            progress_marker: (0, 0),
            wanted_marker: None,
            last_wanted: Instant::now(),
            fatal: None,
            candidates: Vec::new(),
            last_resolve: None,
            stall_timeout: STALL_TIMEOUT_MIN,
            last_stall: Instant::now(),
            tip_since: (0, Instant::now()),
            last_wait_report: Instant::now(),
        })
    }

    /// Without `--connect`, peers come from the DNS seeds.
    fn discovery(&self) -> bool {
        self.config.connect.is_empty()
    }

    /// Keeps `max_peers` connections in discovery mode.
    fn discover_peers(&mut self) {
        if !self.discovery() {
            return;
        }
        while self.peers.len() < self.config.max_peers {
            if self.candidates.is_empty() {
                if self.last_resolve.is_some_and(|at| at.elapsed() < Duration::from_secs(60)) {
                    return;
                }
                self.last_resolve = Some(Instant::now());
                self.candidates = resolve_seeds(self.config.network, self.chain.params.default_port);
                eprintln!("DNS seeds gave {} addresses", self.candidates.len());
                if self.candidates.is_empty() {
                    return;
                }
            }
            let address = self.candidates.pop().unwrap();
            if self.peers.values().any(|p| p.address == address) {
                continue;
            }
            self.connect_peer(address);
        }
    }

    fn send(&self, peer: usize, command: &str, payload: &[u8]) {
        if let Some(p) = self.peers.get(&peer) {
            let _ = p.sender.send(encode_message(self.magic, command, payload));
        }
    }

    fn connect_peer(&mut self, address: String) {
        let id = self.next_peer_id;
        self.next_peer_id += 1;
        eprintln!("connecting to {address} (peer {id})");
        connect(id, address.clone(), self.magic, self.event_sender.clone(), self.downloads.clone());
        self.peers.insert(id, Peer { address, sender: crossbeam_channel::unbounded().0, handshake_done: false, headers_requested: None, services: 0, start_height: 0 });
    }

    fn request_headers(&mut self, peer: usize, from: EntryId) {
        let locator = block_locator(&self.chain.tree, from);
        self.send(peer, "getheaders", &encode_getheaders(&locator, &ZERO_HASH));
        if let Some(p) = self.peers.get_mut(&peer) {
            p.headers_requested = Some(Instant::now());
        }
    }

    /// True once the tip is the stop block; the node then finishes.
    fn stop_reached(&self) -> bool {
        self.chain.store.stop_reached || self.config.stop_at == Some(self.chain.tip().hash)
    }

    pub fn run(mut self) -> Result<(), String> {
        // Blocks stored before a restart (above the last flushed tip) are connected now, as Core's
        // startup `ActivateBestChain` does; nothing else would trigger their activation.
        self.activate();
        if self.fatal.is_some() {
            return self.fail();
        }
        if self.stop_reached() {
            return self.finish();
        }
        for address in self.config.connect.clone() {
            self.connect_peer(address);
        }
        self.discover_peers();
        loop {
            if SHUTDOWN.load(Ordering::SeqCst) {
                eprintln!("shutting down");
                self.chain.store.flush().map_err(|e| e.to_string())?;
                for handle in self.chain.store.hash_threads.drain(..) {
                    let _ = handle.join();
                }
                return Ok(());
            }
            let mut batch = Vec::new();
            match self.events.recv_timeout(Duration::from_millis(200)) {
                Ok(event) => batch.push(event),
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return Err("event channel closed".into()),
            }
            let mut block_bytes = 0usize;
            while batch.len() < MAX_BATCH && block_bytes < (256 << 20) {
                match self.events.try_recv() {
                    Ok(event) => {
                        if let NetEvent::Message { command, payload, .. } = &event {
                            if command == "block" {
                                block_bytes += payload.len();
                            }
                        }
                        batch.push(event);
                    }
                    Err(_) => break,
                }
            }
            // Decode blocks in parallel, keeping arrival order, together with the work that needs
            // nothing but the block: merkle roots and the context-free checks (`check_block`).
            let consensus = &self.chain.params.consensus;
            let decoded: Vec<Option<(BlockData, Result<(), consensus::util::Failure>)>> = batch
                .par_iter()
                .map(|event| match event {
                    NetEvent::Message { command, payload, .. } if command == "block" => deserialize_block_data(payload).ok().map(|data| {
                        let checked = check_block(&data, consensus);
                        block_witness_merkle_root(&data);
                        (data, checked)
                    }),
                    _ => None,
                })
                .collect();
            // Store the blocks (and handle every other message) in arrival order, then activate
            // once for the whole batch.
            let mut stored = false;
            for (event, block) in batch.into_iter().zip(decoded) {
                match event {
                    NetEvent::Message { peer, command, requested, .. } if command == "block" => {
                        match block {
                            Some((data, checked)) => {
                                self.handle_block(peer, data, checked, requested);
                                stored = true;
                            }
                            None => eprintln!("peer {peer}: block message does not decode"),
                        }
                        self.downloads.lock().unwrap().processed();
                    }
                    other => self.handle_event(other),
                }
                if self.fatal.is_some() {
                    return self.fail();
                }
            }
            if stored {
                self.activate();
            }
            if self.stop_reached() {
                return self.finish();
            }
            if self.fatal.is_some() {
                return self.fail();
            }
            self.maintain();
            if self.fatal.is_some() {
                return self.fail();
            }
        }
    }

    /// Chain activation for the blocks stored so far (chapter 11 section 11.7).
    fn activate(&mut self) {
        let failures = self.chain.activate_best_chain();
        for (id, failure) in failures {
            let hash = self.chain.tree.get(id).hash;
            eprintln!("block {} failed to connect: {}", hash_to_display(&hash), failure.reason);
            // A peer sent a block that fails validation: with a stop block, give up (PROTOCOL.md
            // section 5); otherwise keep following the best valid chain.
            if self.config.stop_at.is_some() && !self.stop_reached() {
                self.fatal = Some(format!("peer sent an invalid block {}: {}", hash_to_display(&hash), failure.reason));
            }
        }
        self.refresh_wanted();
    }

    fn handle_event(&mut self, event: NetEvent) {
        match event {
            NetEvent::Connected { peer, sender } => {
                let Some(p) = self.peers.get_mut(&peer) else { return };
                p.sender = sender.clone();
                self.downloads.lock().unwrap().add_peer(peer, sender);
                let version = VersionMessage {
                    version: PROTOCOL_VERSION,
                    services: NODE_WITNESS,
                    timestamp: unix_now(),
                    nonce: self.our_nonce,
                    user_agent: format!("/bitcoin-spec-node:{}/", env!("CARGO_PKG_VERSION")).into_bytes(),
                    start_height: self.chain.tip().height,
                    relay: false,
                };
                self.send(peer, "version", &encode_version(&version));
            }
            NetEvent::Disconnected { peer, reason } => {
                self.downloads.lock().unwrap().remove_peer(peer);
                if let Some(p) = self.peers.remove(&peer) {
                    eprintln!("peer {peer} ({}) disconnected: {reason}", p.address);
                    if !self.discovery() {
                        self.reconnect_at.push((Instant::now() + Duration::from_secs(5), p.address));
                    }
                }
            }
            NetEvent::Message { peer, command, payload, .. } => self.handle_message(peer, &command, &payload),
        }
    }

    fn handle_message(&mut self, peer: usize, command: &str, payload: &[u8]) {
        match command {
            "version" => {
                let Ok(theirs) = decode_version(payload) else {
                    self.disconnect(peer, "bad version message");
                    return;
                };
                if theirs.version < MIN_PEER_PROTO_VERSION {
                    self.disconnect(peer, "peer version too old");
                    return;
                }
                if theirs.nonce == self.our_nonce {
                    self.disconnect(peer, "connected to self");
                    return;
                }
                eprintln!("peer {peer}: version {} {} height {} services {:#x}", theirs.version, String::from_utf8_lossy(&theirs.user_agent), theirs.start_height, theirs.services);
                // Blocks with witnesses from the whole history need NODE_NETWORK and NODE_WITNESS;
                // peers found through the seeds without them are of no use for synchronizing.
                if self.discovery() && (theirs.services & NODE_NETWORK == 0 || theirs.services & NODE_WITNESS == 0) {
                    self.disconnect(peer, "peer does not serve the full block history with witnesses");
                    return;
                }
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.services = theirs.services;
                    p.start_height = theirs.start_height;
                }
                self.send(peer, "verack", &[]);
            }
            "verack" => {
                let mut start_height = 0;
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.handshake_done = true;
                    start_height = p.start_height;
                }
                self.send(peer, "sendheaders", &[]);
                let best = self.chain.best_header;
                self.request_headers(peer, best);
                // Headers first: blocks are requested from a peer once its header chain is known
                // (block requests would otherwise delay its answers to `getheaders`).
                if self.chain.best_header().height >= start_height {
                    self.downloads.lock().unwrap().set_ready(peer, start_height);
                }
            }
            "getheaders" => {
                if let Ok((locator, stop)) = decode_getheaders(payload) {
                    if locator.len() <= MAX_LOCATOR_SZ {
                        if let Some(headers) = answer_getheaders(&self.chain.tree, &locator, &stop) {
                            self.send(peer, "headers", &encode_headers(&headers));
                        }
                    }
                }
            }
            "headers" => self.handle_headers(peer, payload),
            "inv" => {
                if let Ok(items) = decode_inv(payload) {
                    let mut unknown = false;
                    for (kind, hash) in &items {
                        if *kind & !MSG_WITNESS_FLAG != MSG_BLOCK {
                            continue;
                        }
                        match self.chain.tree.lookup(hash) {
                            Some(id) => {
                                let height = self.chain.tree.get(id).height;
                                self.downloads.lock().unwrap().peer_has_height(peer, height);
                            }
                            None => unknown = true,
                        }
                    }
                    if unknown {
                        let best = self.chain.best_header;
                        self.request_headers(peer, best);
                    }
                }
            }
            _ => {}
        }
    }

    fn disconnect(&mut self, peer: usize, reason: &str) {
        eprintln!("disconnecting peer {peer}: {reason}");
        if let Some(p) = self.peers.get(&peer) {
            // An empty frame makes the writer thread close the connection.
            let _ = p.sender.send(Vec::new());
        }
        self.peers.remove(&peer);
        self.downloads.lock().unwrap().remove_peer(peer);
    }

    fn handle_headers(&mut self, peer: usize, payload: &[u8]) {
        if let Some(p) = self.peers.get_mut(&peer) {
            p.headers_requested = None;
        }
        let headers = match decode_headers(payload) {
            Ok(headers) => headers,
            Err(_) => {
                self.disconnect(peer, "malformed headers message");
                return;
            }
        };
        if headers.is_empty() {
            let start_height = self.peers.get(&peer).map_or(0, |p| p.start_height);
            self.downloads.lock().unwrap().set_ready(peer, start_height);
            return;
        }
        self.last_progress = Instant::now();
        match headers_message_acceptable(&self.chain, &headers) {
            Err(HeadersRejection::UnknownParent) => {
                let best = self.chain.best_header;
                self.request_headers(peer, best);
                return;
            }
            Err(reason) => {
                eprintln!("peer {peer}: headers message dropped ({reason:?})");
                return;
            }
            Ok(()) => {}
        }
        let now = unix_now();
        if let Err((index, error)) = self.chain.process_headers(&headers, now) {
            match error {
                HeaderError::Orphan => eprintln!("peer {peer}: header {index} is an orphan"),
                HeaderError::Failed(failure) => eprintln!("peer {peer}: header {} rejected: {}", hash_to_display(&headers[index].hash()), failure.reason),
            }
        }
        if let Err(error) = self.chain.store.write_index(false) {
            eprintln!("warning: cannot write the block index: {error}");
        }
        if let Some(last) = self.chain.tree.lookup(&headers.last().unwrap().hash()) {
            let height = self.chain.tree.get(last).height;
            self.downloads.lock().unwrap().peer_has_height(peer, height);
        }
        if headers.len() == MAX_HEADERS_RESULTS {
            if let Some(last) = self.chain.tree.lookup(&headers.last().unwrap().hash()) {
                self.request_headers(peer, last);
            }
        } else {
            let best = self.chain.best_header();
            eprintln!("headers synchronized with peer {peer}: best header {} at height {}", hash_to_display(&best.hash), best.height);
            let start_height = self.peers.get(&peer).map_or(0, |p| p.start_height);
            self.downloads.lock().unwrap().set_ready(peer, start_height);
        }
        self.refresh_wanted();
    }

    /// Stores a block received from a peer (chapter 14 section 14.4, then chapter 11 section 11.6
    /// steps 1 to 6; activation runs once per batch).
    fn handle_block(&mut self, peer: usize, data: BlockData, checked: Result<(), consensus::util::Failure>, requested: bool) {
        self.last_progress = Instant::now();
        if let Some(parent) = self.chain.tree.lookup(&data.block.header.prev_block) {
            let segwit_active = self.chain.tree.get(parent).height + 1 >= self.chain.params.consensus.segwit_height;
            if is_block_mutated(&data, segwit_active) {
                eprintln!("peer {peer}: block {} is mutated; dropped", hash_to_display(&data.hash));
                return;
            }
        }
        if !p2p_block_work_acceptable(&self.chain, &data.block.header, &data.hash) {
            eprintln!("peer {peer}: block {} has too little chain work; dropped", hash_to_display(&data.hash));
            return;
        }
        let hash = data.hash;
        let txs = data.block.transactions.len() as u64;
        match self.chain.store_checked_block(Arc::new(data), checked, unix_now(), requested) {
            BlockOutcome::Rejected(failure) => {
                eprintln!("block {} rejected: {} ({:?})", hash_to_display(&hash), failure.reason, failure.kind);
                if failure.kind == FailureKind::Invalid && self.config.stop_at.is_some() && !self.stop_reached() {
                    self.fatal = Some(format!("peer sent an invalid block {}: {}", hash_to_display(&hash), failure.reason));
                }
            }
            BlockOutcome::Orphan => eprintln!("block {} is an orphan", hash_to_display(&hash)),
            _ => {
                self.stats_blocks += 1;
                self.stats_txs += txs;
            }
        }
    }

    /// The missing blocks along the best header chain, oldest first (chapter 14 section 14.4).
    fn refresh_wanted(&mut self) {
        let best = self.chain.best_header;
        let tip = self.chain.tree.tip();
        if self.wanted_marker == Some((best, tip)) && self.last_wanted.elapsed() < Duration::from_secs(5) {
            return;
        }
        self.wanted_marker = Some((best, tip));
        self.last_wanted = Instant::now();
        let tree = &self.chain.tree;
        let tip_height = tree.get(tip).height;
        let best_height = tree.get(best).height;
        let mut wanted: Vec<(Hash256, i32)> = Vec::new();
        let fork = tree.find_fork(best);
        if fork != best {
            let mut limit_height = best_height.min(tip_height + MAX_AHEAD);
            if let Some(stop) = self.config.stop_at {
                if let Some(stop_id) = tree.lookup(&stop) {
                    let stop_height = tree.get(stop_id).height;
                    if stop_height <= best_height && tree.ancestor(best, stop_height) == Some(stop_id) {
                        limit_height = limit_height.min(stop_height);
                    }
                }
            }
            let start = tree.get(fork).height.min(tip_height) + 1;
            if start <= limit_height {
                let mut id = tree.ancestor(best, limit_height).unwrap();
                loop {
                    let entry = tree.get(id);
                    if entry.height < start {
                        break;
                    }
                    if !entry.has_data && !entry.failed {
                        wanted.push((entry.hash, entry.height));
                    }
                    match entry.parent {
                        Some(parent) => id = parent,
                        None => break,
                    }
                }
                wanted.reverse();
            }
        }
        self.downloads.lock().unwrap().set_wanted(wanted);
    }

    /// Re-requests stalled blocks, reconnects, prunes, watches progress and reports.
    fn maintain(&mut self) {
        let now = Instant::now();
        let due: Vec<String> = self.reconnect_at.iter().filter(|(when, _)| *when <= now).map(|(_, a)| a.clone()).collect();
        self.reconnect_at.retain(|(when, _)| *when > now);
        for address in due {
            self.connect_peer(address);
        }
        self.discover_peers();
        let expired = self.downloads.lock().unwrap().expire(BLOCK_TIMEOUT);
        if expired > 0 {
            eprintln!("{expired} block requests timed out; requesting them again");
        }
        // A peer holding up the next block while others could deliver it is stalling: drop it
        // (discovery mode, where it is replaced) or ask someone else (Bitcoin Core: stalling).
        let oldest = self.downloads.lock().unwrap().oldest_needed();
        if let Some((staller, waited, height)) = oldest {
            let alternatives = self.downloads.lock().unwrap().alternatives(staller, height);
            // With discovery a stalling peer is replaced even when no other peer is ready.
            if (alternatives > 0 || self.discovery()) && height == self.chain.tip().height + 1 && waited > self.stall_timeout {
                eprintln!("peer {staller} stalls block {height} ({} s); stall timeout now {} s", waited.as_secs(), (self.stall_timeout * 2).min(STALL_TIMEOUT_MAX).as_secs());
                self.stall_timeout = (self.stall_timeout * 2).min(STALL_TIMEOUT_MAX);
                self.last_stall = Instant::now();
                if self.discovery() {
                    self.disconnect(staller, "stalling");
                } else {
                    // A peer given with --connect stays, but its requests go to the others and it
                    // is avoided for a while.
                    let taken = self.downloads.lock().unwrap().penalize(staller);
                    eprintln!("peer {staller}: {taken} block requests moved to other peers");
                }
            }
        }
        if self.last_stall.elapsed() > Duration::from_secs(60) && self.stall_timeout > STALL_TIMEOUT_MIN {
            self.stall_timeout /= 2;
            self.last_stall = Instant::now();
        }
        // Headers requests that went unanswered.
        let silent: Vec<usize> = self.peers.iter().filter(|(_, p)| p.headers_requested.is_some_and(|at| at.elapsed() > Duration::from_secs(120))).map(|(id, _)| *id).collect();
        for peer in silent {
            let best = self.chain.best_header;
            self.request_headers(peer, best);
        }
        self.refresh_wanted();
        // Diagnostics: say what the next block is waiting for when the tip has not moved for a
        // while although the header chain goes further.
        let tip = self.chain.tree.tip();
        if tip != self.tip_since.0 {
            self.tip_since = (tip, Instant::now());
        }
        if self.tip_since.1.elapsed() > Duration::from_secs(10) && self.last_wait_report.elapsed() > Duration::from_secs(10) {
            let tree = &self.chain.tree;
            let next_height = tree.get(tip).height + 1;
            if let Some(next) = tree.ancestor(self.chain.best_header, next_height) {
                let entry = tree.get(next);
                let state = self.downloads.lock().unwrap().describe(&entry.hash);
                eprintln!(
                    "waiting for block {} {} for {} s: data {}, failed {}; {state}; stall timeout {} s",
                    next_height,
                    hash_to_display(&entry.hash),
                    self.tip_since.1.elapsed().as_secs(),
                    entry.has_data,
                    entry.failed,
                    self.stall_timeout.as_secs()
                );
                self.last_wait_report = Instant::now();
            }
        }
        // Progress, and giving up on an unreachable stop block.
        let marker = (self.chain.best_header, self.chain.tree.tip());
        if marker != self.progress_marker {
            self.progress_marker = marker;
            self.last_progress = Instant::now();
        }
        if self.config.stop_at.is_some() && self.last_progress.elapsed() > self.config.idle_timeout {
            self.fatal = Some(format!("no progress towards the stop block for {} s", self.config.idle_timeout.as_secs()));
        }
        // Pruning.
        let keep_from = self.chain.tip().height - self.config.prune_depth;
        if keep_from > self.pruned_to + 64 {
            self.chain.prune_active(self.pruned_to, keep_from);
            self.pruned_to = keep_from;
        }
        if self.last_stats.elapsed() >= stats_interval() {
            let seconds = self.last_stats.elapsed().as_secs_f64();
            let tip = self.chain.tip();
            let (phases, inputs) = consensus::chain::timing::take();
            let (in_flight, buffered) = {
                let downloads = self.downloads.lock().unwrap();
                (downloads.in_flight_count(), downloads.buffered())
            };
            eprintln!(
                "height {} ({} headers): {:.1} blocks/s, {:.0} tx/s, {:.0} coins/s; in flight {}, buffered {}; cache {} MiB, {} entries; ms checks {} prefetch {} serial {} scripts {} wait {} apply {}",
                tip.height,
                self.chain.best_header().height,
                self.stats_blocks as f64 / seconds,
                self.stats_txs as f64 / seconds,
                inputs as f64 / seconds,
                in_flight,
                buffered,
                self.chain.store.coins_usage() >> 20,
                self.chain.store.coins_entries(),
                phases[0],
                phases[1],
                phases[2],
                phases[3],
                phases[4],
                phases[5]
            );
            self.last_stats = Instant::now();
            self.stats_blocks = 0;
            self.stats_txs = 0;
        }
    }

    /// The stop block cannot be reached: make everything durable, report, and exit non-zero.
    fn fail(mut self) -> Result<(), String> {
        let message = self.fatal.take().unwrap_or_default();
        let _ = self.chain.store.flush();
        let tip = self.chain.tip();
        crate::emit(&format!(
            "{{\"event\":\"error\",\"message\":{},\"tip\":\"{}\",\"height\":{}}}",
            serde_json::Value::String(message.clone()),
            hash_to_display(&tip.hash),
            tip.height
        ));
        Err(message)
    }

    /// The tip reached the stop block: make everything durable and report.
    fn finish(mut self) -> Result<(), String> {
        let tip = self.chain.tip().clone();
        self.chain.store.flush().map_err(|e| e.to_string())?;
        for handle in self.chain.store.hash_threads.drain(..) {
            let _ = handle.join();
        }
        let (hash, _count, best) = utxo_hash_of_database(&self.chain.store.database.db, None).map_err(|e| e.to_string())?;
        if best.is_some() && best != Some(tip.hash) {
            return Err("coin database does not match the tip after the final flush".into());
        }
        crate::emit(&format!(
            "{{\"event\":\"stopped\",\"tip\":\"{}\",\"height\":{},\"hash_serialized_3\":\"{}\"}}",
            hash_to_display(&tip.hash),
            tip.height,
            hash_to_display(&hash)
        ));
        Ok(())
    }
}
