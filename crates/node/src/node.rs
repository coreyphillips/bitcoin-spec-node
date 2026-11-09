//! `bitcoin-spec-node run`: the persistent full node.
//!
//! One thread owns the chain state (chapter 11) and handles every peer message in arrival order;
//! block payloads are decoded (and their transactions hashed) in parallel before they reach it,
//! and script checks run in parallel inside `connect_block`. Headers are synchronized first
//! (chapter 14 section 14.3), then blocks are requested along the best header chain, oldest
//! first, with a bounded number in flight per peer.

use crate::net::{connect, NetEvent};
use crate::store::{load_index, utxo_hash_of_database, DiskStore, Hooks, IndexRecord};
use consensus::block_rules::is_block_mutated;
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
}

/// Blocks are not requested further than this above the active tip.
const MAX_AHEAD: i32 = 1024;
/// A block requested this long ago without an answer is requested again (Bitcoin Core never sends
/// `notfound` for blocks; chapter 14 section 14.4).
const BLOCK_TIMEOUT: Duration = Duration::from_secs(64);

pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

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
    in_flight: usize,
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
    in_flight: HashMap<Hash256, (usize, Instant)>,
    our_nonce: u64,
    pruned_to: i32,
    last_stats: Instant,
    stats_blocks: u64,
    stats_txs: u64,
    /// Last time the best header or the active tip changed (or a block or headers arrived).
    last_progress: Instant,
    progress_marker: (EntryId, EntryId),
    /// Set when the stop block can no longer be reached.
    fatal: Option<String>,
}

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
            in_flight: HashMap::new(),
            our_nonce: random_u64(),
            last_stats: Instant::now(),
            stats_blocks: 0,
            stats_txs: 0,
            last_progress: Instant::now(),
            progress_marker: (0, 0),
            fatal: None,
        })
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
        connect(id, address.clone(), self.magic, self.event_sender.clone());
        self.peers.insert(id, Peer { address, sender: crossbeam_channel::unbounded().0, handshake_done: false, headers_requested: None, in_flight: 0 });
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
        if self.stop_reached() {
            return self.finish();
        }
        for address in self.config.connect.clone() {
            self.connect_peer(address);
        }
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
            while batch.len() < 256 && block_bytes < (256 << 20) {
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
            // Decode blocks in parallel, keeping arrival order.
            let decoded: Vec<Option<BlockData>> = batch
                .par_iter()
                .map(|event| match event {
                    NetEvent::Message { command, payload, .. } if command == "block" => deserialize_block_data(payload).ok(),
                    _ => None,
                })
                .collect();
            for (event, block) in batch.into_iter().zip(decoded) {
                self.handle_event(event, block);
                if self.stop_reached() {
                    return self.finish();
                }
                if self.fatal.is_some() {
                    return self.fail();
                }
            }
            self.maintain();
            if self.stop_reached() {
                return self.finish();
            }
            if self.fatal.is_some() {
                return self.fail();
            }
        }
    }

    fn handle_event(&mut self, event: NetEvent, block: Option<BlockData>) {
        match event {
            NetEvent::Connected { peer, sender } => {
                let Some(p) = self.peers.get_mut(&peer) else { return };
                p.sender = sender;
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
                if let Some(p) = self.peers.remove(&peer) {
                    eprintln!("peer {peer} ({}) disconnected: {reason}", p.address);
                    self.in_flight.retain(|_, (owner, _)| *owner != peer);
                    self.reconnect_at.push((Instant::now() + Duration::from_secs(5), p.address));
                }
            }
            NetEvent::Message { peer, command, payload } => self.handle_message(peer, &command, &payload, block),
        }
    }

    fn handle_message(&mut self, peer: usize, command: &str, payload: &[u8], block: Option<BlockData>) {
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
                eprintln!("peer {peer}: version {} {} height {}", theirs.version, String::from_utf8_lossy(&theirs.user_agent), theirs.start_height);
                self.send(peer, "verack", &[]);
            }
            "verack" => {
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.handshake_done = true;
                }
                self.send(peer, "sendheaders", &[]);
                let best = self.chain.best_header;
                self.request_headers(peer, best);
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
                    let unknown = items.iter().any(|(kind, hash)| *kind & !MSG_WITNESS_FLAG == MSG_BLOCK && self.chain.tree.lookup(hash).is_none());
                    if unknown {
                        let best = self.chain.best_header;
                        self.request_headers(peer, best);
                    }
                }
            }
            "block" => {
                match block {
                    Some(data) => self.handle_block(peer, data),
                    None => eprintln!("peer {peer}: block message does not decode"),
                }
                // Keep the download pipeline full while blocks are being connected.
                self.schedule_downloads();
            }
            "notfound" => {
                if let Ok(items) = decode_inv(payload) {
                    for (_, hash) in items {
                        if self.in_flight.remove(&hash).is_some() {
                            if let Some(p) = self.peers.get_mut(&peer) {
                                p.in_flight = p.in_flight.saturating_sub(1);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn disconnect(&mut self, peer: usize, reason: &str) {
        eprintln!("disconnecting peer {peer}: {reason}");
        if let Some(p) = self.peers.get(&peer) {
            // Dropping the sender ends the writer thread, which shuts the socket down.
            let _ = p.sender.send(Vec::new());
        }
        self.peers.remove(&peer);
        self.in_flight.retain(|_, (owner, _)| *owner != peer);
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
        if headers.len() == MAX_HEADERS_RESULTS {
            if let Some(last) = self.chain.tree.lookup(&headers.last().unwrap().hash()) {
                self.request_headers(peer, last);
            }
        } else {
            let best = self.chain.best_header();
            eprintln!("headers synchronized with peer {peer}: best header {} at height {}", hash_to_display(&best.hash), best.height);
        }
    }

    fn handle_block(&mut self, peer: usize, data: BlockData) {
        let requested = match self.in_flight.remove(&data.hash) {
            Some((owner, _)) => {
                if let Some(p) = self.peers.get_mut(&owner) {
                    p.in_flight = p.in_flight.saturating_sub(1);
                }
                true
            }
            None => false,
        };
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
        let outcome = self.chain.process_block(Arc::new(data), unix_now(), requested);
        match outcome {
            BlockOutcome::Rejected(failure) => {
                eprintln!("block {} rejected: {} ({:?})", hash_to_display(&hash), failure.reason, failure.kind);
                // The peer sent a block that fails validation: with a stop block, give up (PROTOCOL.md
                // section 5); otherwise keep following the best valid chain.
                if failure.kind == FailureKind::Invalid && self.config.stop_at.is_some() && self.config.stop_at != Some(self.chain.tip().hash) {
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

    /// Requests blocks, re-requests stalled ones, reconnects, prunes and reports.
    fn maintain(&mut self) {
        let now = Instant::now();
        let due: Vec<String> = self.reconnect_at.iter().filter(|(when, _)| *when <= now).map(|(_, a)| a.clone()).collect();
        self.reconnect_at.retain(|(when, _)| *when > now);
        for address in due {
            self.connect_peer(address);
        }
        // Stalled requests.
        let stalled: Vec<Hash256> = self.in_flight.iter().filter(|(_, (_, at))| at.elapsed() > BLOCK_TIMEOUT).map(|(h, _)| *h).collect();
        for hash in stalled {
            if let Some((owner, _)) = self.in_flight.remove(&hash) {
                if let Some(p) = self.peers.get_mut(&owner) {
                    p.in_flight = p.in_flight.saturating_sub(1);
                }
                eprintln!("block {} timed out; requesting it again", hash_to_display(&hash));
            }
        }
        // Headers requests that went unanswered.
        let silent: Vec<usize> = self.peers.iter().filter(|(_, p)| p.headers_requested.is_some_and(|at| at.elapsed() > Duration::from_secs(120))).map(|(id, _)| *id).collect();
        for peer in silent {
            let best = self.chain.best_header;
            self.request_headers(peer, best);
        }
        self.schedule_downloads();
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
        if self.last_stats.elapsed() >= Duration::from_secs(10) {
            let seconds = self.last_stats.elapsed().as_secs_f64();
            let tip = self.chain.tip();
            let (phases, inputs) = consensus::chain::timing::take();
            eprintln!(
                "height {} ({} headers): {:.1} blocks/s, {:.0} tx/s, {:.0} inputs/s; in flight {}; cache {} MiB, {} entries; ms checks {} prefetch {} serial {} scripts {} wait {} apply {}",
                tip.height,
                self.chain.best_header().height,
                self.stats_blocks as f64 / seconds,
                self.stats_txs as f64 / seconds,
                inputs as f64 / seconds,
                self.in_flight.len(),
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

    /// Requests missing blocks along the best header chain, oldest first (chapter 14 section 14.4).
    fn schedule_downloads(&mut self) {
        let ready: Vec<usize> = self.peers.iter().filter(|(_, p)| p.handshake_done && p.in_flight < self.config.max_in_flight).map(|(id, _)| *id).collect();
        if ready.is_empty() {
            return;
        }
        let best = self.chain.best_header;
        let tree = &self.chain.tree;
        let tip_height = self.chain.tip().height;
        let best_height = tree.get(best).height;
        if best_height <= tip_height && tree.find_fork(best) == best {
            return;
        }
        let mut limit_height = best_height.min(tip_height + MAX_AHEAD);
        if let Some(stop) = self.config.stop_at {
            if let Some(stop_id) = tree.lookup(&stop) {
                let stop_height = tree.get(stop_id).height;
                if stop_height <= best_height && tree.ancestor(best, stop_height) == Some(stop_id) {
                    limit_height = limit_height.min(stop_height);
                }
            }
        }
        let fork_height = tree.get(tree.find_fork(best)).height;
        let start = fork_height.min(tip_height) + 1;
        let mut capacity: Vec<(usize, usize)> = ready.iter().map(|id| (*id, self.config.max_in_flight - self.peers[id].in_flight)).collect();
        let total_capacity: usize = capacity.iter().map(|(_, c)| c).sum();
        let mut wanted: Vec<Hash256> = Vec::new();
        if start <= limit_height {
            let mut id = tree.ancestor(best, limit_height).unwrap();
            // Walk down from the limit to `start`, then reverse (oldest first).
            let mut candidates = Vec::new();
            loop {
                let entry = tree.get(id);
                if entry.height < start {
                    break;
                }
                candidates.push(id);
                match entry.parent {
                    Some(parent) => id = parent,
                    None => break,
                }
            }
            candidates.reverse();
            for id in candidates {
                if wanted.len() >= total_capacity {
                    break;
                }
                let entry = tree.get(id);
                if !entry.has_data && !entry.failed && !self.in_flight.contains_key(&entry.hash) {
                    wanted.push(entry.hash);
                }
            }
        }
        let mut per_peer: HashMap<usize, Vec<(u32, Hash256)>> = HashMap::new();
        let mut slot = 0;
        for hash in wanted {
            while capacity[slot % capacity.len()].1 == 0 {
                slot += 1;
            }
            let index = slot % capacity.len();
            capacity[index].1 -= 1;
            let peer = capacity[index].0;
            per_peer.entry(peer).or_default().push((MSG_WITNESS_BLOCK, hash));
            self.in_flight.insert(hash, (peer, Instant::now()));
            slot += 1;
        }
        for (peer, items) in per_peer {
            if let Some(p) = self.peers.get_mut(&peer) {
                p.in_flight += items.len();
            }
            self.send(peer, "getdata", &encode_inv(&items));
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
