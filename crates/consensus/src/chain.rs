//! Chapter 11: chain state and chain selection, plus chapter 10 section 10.8 (connecting a block).
//!
//! This is the reference algorithm (`process_block`, `accept_header`, `activate_best_chain`,
//! `invalidate_block`, ...) restructured for a production node: block tree entries live in an
//! arena with skip pointers for fast ancestor lookup, block data and undo data are kept by a
//! `ChainStore` (in memory for the harness, on disk for the node), the UTXO set is a write-back
//! cache over a backend, and script checks of a block run in parallel. The observable behaviour
//! (chain selected after every block, UTXO set, what is remembered about failures) is the
//! reference's.

use crate::block_rules::*;
use crate::coins::{new_outpoint_map, CoinsCache, OutPointMap};
use crate::interpreter::ScriptError;
use crate::params::NetworkParams;
use crate::pow::{block_proof, median_time_past, MEDIAN_TIME_SPAN};
use crate::script::is_unspendable;
use crate::sighash::PrecomputedTx;
use crate::tx::{BlockData, BlockHeader, OutPoint, Transaction, TxOut};
use crate::tx_rules::*;
use crate::uint::U256;
use crate::util::*;
use crate::verify::verify_input;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Index of an entry in the block tree arena.
pub type EntryId = u32;

/// Cumulative time spent in the phases of block processing (for performance reports only).
pub mod timing {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub static CHECKS_NS: AtomicU64 = AtomicU64::new(0);
    pub static PREFETCH_NS: AtomicU64 = AtomicU64::new(0);
    pub static SERIAL_NS: AtomicU64 = AtomicU64::new(0);
    pub static SCRIPTS_NS: AtomicU64 = AtomicU64::new(0);
    pub static APPLY_NS: AtomicU64 = AtomicU64::new(0);
    pub static WAIT_NS: AtomicU64 = AtomicU64::new(0);
    pub static INPUTS: AtomicU64 = AtomicU64::new(0);

    pub fn add(counter: &AtomicU64, since: std::time::Instant) {
        counter.fetch_add(since.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    /// (checks, prefetch, serial, scripts, wait, apply) in milliseconds, and inputs; resets the
    /// counters. `scripts` is the wall time of the (overlapping) script verifications, `wait` the time
    /// the chain thread waited for them.
    pub fn take() -> ([u64; 6], u64) {
        let ms = |c: &AtomicU64| c.swap(0, Ordering::Relaxed) / 1_000_000;
        ([ms(&CHECKS_NS), ms(&PREFETCH_NS), ms(&SERIAL_NS), ms(&SCRIPTS_NS), ms(&WAIT_NS), ms(&APPLY_NS)], INPUTS.swap(0, Ordering::Relaxed))
    }
}

/// Core: `CBlockIndex`.
#[derive(Clone, Debug)]
pub struct BlockEntry {
    pub hash: Hash256,
    pub header: BlockHeader,
    pub height: i32,
    pub parent: Option<EntryId>,
    /// Ancestor pointer for O(log n) ancestor lookup (Core: `pskip`).
    pub skip: Option<EntryId>,
    pub chain_work: U256,
    /// Median time past of this block (chapter 09).
    pub median_time_past: i64,
    /// The block's data has been received and accepted (reference: `block.is_some()`).
    pub has_data: bool,
    /// Undo data exists (reference: `undo.is_some()`).
    pub has_undo: bool,
    /// Sequence number assigned when the block became linked; 0 while unlinked.
    pub sequence_id: u64,
    /// The block, or an ancestor, is invalid.
    pub failed: bool,
    /// The block has been connected successfully at least once.
    pub connected_once: bool,
    /// Order in which the header was accepted, for reporting the best header.
    pub header_order: u64,
}

fn invert_lowest_one(n: i32) -> i32 {
    n & (n - 1)
}

/// Height of the skip pointer target for a block at `height`.
fn skip_height(height: i32) -> i32 {
    if height < 2 {
        return 0;
    }
    if height & 1 == 1 {
        invert_lowest_one(invert_lowest_one(height - 1)) + 1
    } else {
        invert_lowest_one(height)
    }
}

/// The block tree: every accepted header, plus the active chain.
#[derive(Clone, Debug, Default)]
pub struct BlockTree {
    pub entries: Vec<BlockEntry>,
    pub index: HashMap<Hash256, EntryId>,
    /// `active[h]` is the active block at height h.
    pub active: Vec<EntryId>,
}

impl BlockTree {
    #[inline]
    pub fn get(&self, id: EntryId) -> &BlockEntry {
        &self.entries[id as usize]
    }

    #[inline]
    pub fn get_mut(&mut self, id: EntryId) -> &mut BlockEntry {
        &mut self.entries[id as usize]
    }

    pub fn lookup(&self, hash: &Hash256) -> Option<EntryId> {
        self.index.get(hash).copied()
    }

    #[inline]
    pub fn is_active(&self, id: EntryId) -> bool {
        let height = self.entries[id as usize].height as usize;
        height < self.active.len() && self.active[height] == id
    }

    pub fn tip(&self) -> EntryId {
        *self.active.last().expect("chain has genesis")
    }

    /// The ancestor of `id` at `height` (the block itself at its own height). Core: `GetAncestor`.
    pub fn ancestor(&self, id: EntryId, height: i32) -> Option<EntryId> {
        let entry = self.get(id);
        if height < 0 || height > entry.height {
            return None;
        }
        let mut walk = id;
        let mut walk_height = entry.height;
        while walk_height > height {
            if self.is_active(walk) {
                return Some(self.active[height as usize]);
            }
            let current = self.get(walk);
            let skip_h = skip_height(walk_height);
            let skip_prev = skip_height(walk_height - 1);
            match current.skip {
                Some(skip) if skip_h == height || (skip_h > height && !(skip_prev < skip_h - 2 && skip_prev >= height)) => {
                    walk = skip;
                    walk_height = skip_h;
                }
                _ => {
                    walk = current.parent.expect("non-genesis block has a parent");
                    walk_height -= 1;
                }
            }
        }
        Some(walk)
    }

    /// Adds an entry, computing its skip pointer.
    pub fn insert(&mut self, mut entry: BlockEntry) -> EntryId {
        let id = self.entries.len() as EntryId;
        entry.skip = entry.parent.and_then(|parent| self.ancestor(parent, skip_height(entry.height)));
        self.index.insert(entry.hash, id);
        self.entries.push(entry);
        id
    }

    /// The last block of the active chain that is an ancestor of (or is) `id`. Core: `CChain::FindFork`.
    pub fn find_fork(&self, id: EntryId) -> EntryId {
        let entry = self.get(id);
        let start = if entry.height as usize >= self.active.len() { self.ancestor(id, self.active.len() as i32 - 1).unwrap() } else { id };
        let mut walk = start;
        while !self.is_active(walk) {
            walk = self.get(walk).parent.unwrap();
        }
        walk
    }

    /// Header of the ancestor of `id` at `height`; the caller knows it exists.
    pub fn ancestor_header(&self, id: EntryId, height: i32) -> BlockHeader {
        self.get(self.ancestor(id, height).expect("ancestor exists")).header
    }
}

/// Undo data of one block: for each non-coinbase transaction, the coins its inputs spent.
pub type BlockUndo = Vec<Vec<Coin>>;

/// What happened to a block given to `process_block`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockOutcome {
    /// Stored; valid so far.
    Accepted,
    /// Unrequested and with too little work (or too far ahead): only the header was kept.
    AcceptedHeaderOnly,
    /// The block's data was already known.
    Duplicate,
    /// The parent is unknown; the block was discarded.
    Orphan,
    /// Rejected; the failure says whether anything was recorded.
    Rejected(Failure),
}

/// Why a header was not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderError {
    Orphan,
    Failed(Failure),
}

/// Where block data, undo data and coins live, and hooks for persistence and progress.
pub trait ChainStore {
    fn coins(&mut self) -> &mut CoinsCache;
    /// Stores the data of an accepted block.
    fn put_block(&mut self, entry: &BlockEntry, block: Arc<BlockData>);
    fn get_block(&mut self, entry: &BlockEntry) -> Option<Arc<BlockData>>;
    /// Stores undo data after the block was connected.
    fn put_undo(&mut self, entry: &BlockEntry, block: &Arc<BlockData>, undo: BlockUndo);
    fn get_undo(&mut self, entry: &BlockEntry) -> Option<BlockUndo>;
    /// An entry was added or one of its flags changed (for persistence).
    fn entry_changed(&mut self, _id: EntryId, _entry: &BlockEntry) {}
    /// A block was connected and is now the tip. Returning false stops chain activation.
    fn connected(&mut self, _tree: &BlockTree, _id: EntryId) -> bool {
        true
    }
    /// The tip was disconnected.
    fn disconnected(&mut self, _tree: &BlockTree, _id: EntryId) {}
    /// Discards the stored data and undo data of a block (pruning).
    fn remove_data(&mut self, _entry: &BlockEntry) {}
}

/// Core: `MIN_BLOCKS_TO_KEEP`.
pub const MIN_BLOCKS_TO_KEEP: i32 = 288;

pub struct ChainState<S: ChainStore> {
    pub params: NetworkParams,
    pub tree: BlockTree,
    pub store: S,
    /// Linked, not known invalid blocks that are at least as good as the tip.
    pub candidates: HashSet<EntryId>,
    /// Blocks with data whose parent's data has not arrived, keyed by parent.
    pub unlinked: HashMap<EntryId, Vec<EntryId>>,
    pub next_sequence_id: u64,
    pub next_header_order: u64,
    /// The most-work header not known invalid; the first accepted wins ties.
    pub best_header: EntryId,
    /// Set when a store hook stopped activation.
    pub halted: bool,
    /// Bitcoin Core's minimum chain work (peer-to-peer policy, not consensus): unrequested blocks
    /// with less chain work are reduced to their header (section 11.6 step 4), and it floors the
    /// anti-denial-of-service work threshold of chapter 14. Zero, the regtest default, unless set.
    pub minimum_chain_work: U256,
    /// Blocks whose scripts may be verified while later blocks of the same path are prepared
    /// (1 connects strictly one block at a time). Commits always happen in order, so the result is
    /// the same for any depth.
    pub pipeline_depth: usize,
}

/// Default `pipeline_depth`.
pub const DEFAULT_PIPELINE_DEPTH: usize = 4;

impl<S: ChainStore> ChainState<S> {
    /// A chain with only the genesis block.
    pub fn new(params: NetworkParams, mut store: S) -> ChainState<S> {
        let genesis = BlockData::from_block(params.genesis.clone());
        let entry = BlockEntry {
            hash: genesis.hash,
            header: genesis.block.header,
            height: 0,
            parent: None,
            skip: None,
            chain_work: block_proof(genesis.block.header.bits),
            median_time_past: genesis.block.header.time as i64,
            has_data: true,
            has_undo: true,
            sequence_id: 1,
            failed: false,
            connected_once: true,
            header_order: 0,
        };
        let mut tree = BlockTree::default();
        let id = tree.insert(entry);
        tree.active.push(id);
        let genesis = Arc::new(genesis);
        store.put_block(tree.get(id), genesis.clone());
        store.put_undo(tree.get(id), &genesis, Vec::new());
        store.entry_changed(id, tree.get(id));
        let mut candidates = HashSet::new();
        candidates.insert(id);
        ChainState {
            params,
            tree,
            store,
            candidates,
            unlinked: HashMap::new(),
            next_sequence_id: 2,
            next_header_order: 1,
            best_header: id,
            halted: false,
            minimum_chain_work: U256::ZERO,
            pipeline_depth: DEFAULT_PIPELINE_DEPTH,
        }
    }

    /// Rebuilds a chain state from persisted entries (parents before children) and the active tip.
    /// Blocks are linked in the order given; candidates are recomputed. Used by the node at startup.
    pub fn restore(params: NetworkParams, store: S, entries: Vec<BlockEntry>, active_tip: Hash256) -> Result<ChainState<S>, String> {
        let mut tree = BlockTree::default();
        for entry in entries {
            tree.insert(entry);
        }
        let tip = tree.lookup(&active_tip).ok_or("active tip is not in the block index")?;
        let tip_height = tree.get(tip).height;
        let mut active = vec![0 as EntryId; tip_height as usize + 1];
        let mut walk = Some(tip);
        while let Some(id) = walk {
            active[tree.get(id).height as usize] = id;
            walk = tree.get(id).parent;
        }
        if tree.get(active[0]).hash != params.consensus.genesis_hash {
            return Err("active chain does not start at genesis".into());
        }
        tree.active = active;
        // Sequence ids: the active chain first (so it wins ties), then everything else with data
        // whose ancestors all have data, in index order.
        let mut next_sequence_id = 1u64;
        for &id in &tree.active.clone() {
            tree.get_mut(id).sequence_id = next_sequence_id;
            next_sequence_id += 1;
        }
        for index in 0..tree.entries.len() {
            let id = index as EntryId;
            if tree.is_active(id) {
                continue;
            }
            let entry = tree.get(id);
            let linked = entry.has_data && entry.parent.is_some_and(|p| tree.get(p).sequence_id != 0);
            let sequence = if linked {
                next_sequence_id += 1;
                next_sequence_id - 1
            } else {
                0
            };
            tree.get_mut(id).sequence_id = sequence;
        }
        let next_header_order = tree.entries.iter().map(|entry| entry.header_order + 1).max().unwrap_or(1);
        let mut state = ChainState {
            params,
            tree,
            store,
            candidates: HashSet::new(),
            unlinked: HashMap::new(),
            next_sequence_id,
            next_header_order,
            best_header: 0,
            halted: false,
            minimum_chain_work: U256::ZERO,
            pipeline_depth: DEFAULT_PIPELINE_DEPTH,
        };
        state.recalculate_best_header();
        let tip = state.tree.tip();
        state.candidates.insert(tip);
        for index in 0..state.tree.entries.len() {
            let id = index as EntryId;
            let entry = state.tree.get(id);
            if entry.has_data && !entry.failed && entry.sequence_id != 0 && !state.is_worse(id, tip) {
                state.candidates.insert(id);
            }
        }
        // Blocks with data waiting for a parent's data.
        for index in 0..state.tree.entries.len() {
            let id = index as EntryId;
            let entry = state.tree.get(id);
            if entry.has_data && entry.sequence_id == 0 {
                if let Some(parent) = entry.parent {
                    if !state.tree.get(parent).failed {
                        state.unlinked.entry(parent).or_default().push(id);
                    }
                }
            }
        }
        Ok(state)
    }

    pub fn tip(&self) -> &BlockEntry {
        self.tree.get(self.tree.tip())
    }

    pub fn best_header(&self) -> &BlockEntry {
        self.tree.get(self.best_header)
    }

    /// Core: `CBlockIndexWorkComparator`, as "a is worse than b".
    fn is_worse(&self, a: EntryId, b: EntryId) -> bool {
        let (a, b) = (self.tree.get(a), self.tree.get(b));
        if a.chain_work != b.chain_work {
            return a.chain_work < b.chain_work;
        }
        a.sequence_id > b.sequence_id
    }

    // -----------------------------------------------------------------------------------------
    // Headers (section 11.5).

    /// Core: `ChainstateManager::AcceptBlockHeader`.
    pub fn accept_header(&mut self, header: &BlockHeader, now: i64) -> Result<EntryId, HeaderError> {
        self.accept_header_hashed(header, &header.hash(), now)
    }

    fn accept_header_hashed(&mut self, header: &BlockHeader, hash: &Hash256, now: i64) -> Result<EntryId, HeaderError> {
        if *hash == self.params.consensus.genesis_hash {
            return Ok(self.tree.active[0]);
        }
        if let Some(id) = self.tree.lookup(hash) {
            if self.tree.get(id).failed {
                return Err(HeaderError::Failed(invalid("duplicate-invalid")));
            }
            return Ok(id);
        }
        check_block_header(header, hash, &self.params.consensus).map_err(HeaderError::Failed)?;
        let parent_id = match self.tree.lookup(&header.prev_block) {
            Some(id) => id,
            None => return Err(HeaderError::Orphan),
        };
        let parent = self.tree.get(parent_id);
        if parent.failed {
            return Err(HeaderError::Failed(invalid("bad-prevblk")));
        }
        {
            let tree = &self.tree;
            let parent_info = ParentInfo { height: parent.height, header: &parent.header, median_time_past: parent.median_time_past };
            let ancestor = |h: i32| tree.ancestor_header(parent_id, h);
            contextual_check_block_header(header, &parent_info, &ancestor, &self.params.consensus, now).map_err(HeaderError::Failed)?;
        }

        let mut times = Vec::with_capacity(MEDIAN_TIME_SPAN);
        times.push(header.time as i64);
        let mut cursor = Some(parent_id);
        while times.len() < MEDIAN_TIME_SPAN {
            match cursor {
                Some(id) => {
                    let entry = self.tree.get(id);
                    times.push(entry.header.time as i64);
                    cursor = entry.parent;
                }
                None => break,
            }
        }
        let parent = self.tree.get(parent_id);
        let entry = BlockEntry {
            hash: *hash,
            header: *header,
            height: parent.height + 1,
            parent: Some(parent_id),
            skip: None,
            chain_work: parent.chain_work.wrapping_add(block_proof(header.bits)),
            median_time_past: median_time_past(&times),
            has_data: false,
            has_undo: false,
            sequence_id: 0,
            failed: false,
            connected_once: false,
            header_order: self.next_header_order,
        };
        self.next_header_order += 1;
        let more_work = entry.chain_work > self.tree.get(self.best_header).chain_work;
        let id = self.tree.insert(entry);
        if more_work {
            self.best_header = id;
        }
        self.store.entry_changed(id, self.tree.get(id));
        Ok(id)
    }

    /// Processes headers in order, stopping at the first one not accepted.
    /// Core: `ChainstateManager::ProcessNewBlockHeaders`.
    pub fn process_headers(&mut self, headers: &[BlockHeader], now: i64) -> Result<(), (usize, HeaderError)> {
        for (index, header) in headers.iter().enumerate() {
            self.accept_header(header, now).map_err(|e| (index, e))?;
        }
        Ok(())
    }

    /// Recomputes the best header after blocks were marked invalid: the most work, then the active
    /// tip, then the first accepted. Core: `RecalculateBestHeader`.
    fn recalculate_best_header(&mut self) {
        let tip = self.tree.tip();
        let mut best: Option<EntryId> = None;
        for (index, entry) in self.tree.entries.iter().enumerate() {
            if entry.failed {
                continue;
            }
            let id = index as EntryId;
            best = match best {
                None => Some(id),
                Some(current) => {
                    let current_entry = self.tree.get(current);
                    let ordering = entry
                        .chain_work
                        .cmp(&current_entry.chain_work)
                        .then((id == tip).cmp(&(current == tip)))
                        .then(current_entry.header_order.cmp(&entry.header_order));
                    if ordering == std::cmp::Ordering::Greater {
                        Some(id)
                    } else {
                        Some(current)
                    }
                }
            };
        }
        self.best_header = best.expect("genesis is never invalid");
    }

    // -----------------------------------------------------------------------------------------
    // Blocks (section 11.6).

    /// Core: `ChainstateManager::ProcessNewBlock`. `requested` is false only for blocks a peer sent
    /// without being asked; block submission by an operator counts as requested.
    pub fn process_block(&mut self, block: Arc<BlockData>, now: i64, requested: bool) -> BlockOutcome {
        let id = block.hash;
        match self.store_block(block, now, requested) {
            BlockOutcome::Accepted => {
                let id = self.tree.lookup(&id).expect("stored");
                // A failure of this very block is reported; a failure of an ancestor leaves `Accepted`.
                match self.activate_best_chain().into_iter().find(|(failed, _)| *failed == id) {
                    Some((_, failure)) => BlockOutcome::Rejected(failure),
                    None => BlockOutcome::Accepted,
                }
            }
            BlockOutcome::Duplicate => {
                self.activate_best_chain();
                BlockOutcome::Duplicate
            }
            BlockOutcome::AcceptedHeaderOnly => {
                self.activate_best_chain();
                BlockOutcome::AcceptedHeaderOnly
            }
            other => other,
        }
    }

    /// Steps 1 to 6 of `process_block` (everything except chain activation). A node that receives
    /// several blocks at once may store them all and activate once: the chain then selected is the
    /// same, and connecting several blocks in one activation lets their script checks overlap.
    pub fn store_block(&mut self, block: Arc<BlockData>, now: i64, requested: bool) -> BlockOutcome {
        let started = std::time::Instant::now();
        let checked = check_block(&block, &self.params.consensus);
        timing::add(&timing::CHECKS_NS, started);
        if let Err(failure) = checked {
            return BlockOutcome::Rejected(failure);
        }
        let id = match self.accept_header_hashed(&block.block.header, &block.hash, now) {
            Ok(id) => id,
            Err(HeaderError::Orphan) => return BlockOutcome::Orphan,
            Err(HeaderError::Failed(failure)) => return BlockOutcome::Rejected(failure),
        };
        if self.tree.get(id).has_data {
            return BlockOutcome::Duplicate;
        }
        if !requested {
            let entry = self.tree.get(id);
            let tip = self.tip();
            if entry.chain_work < tip.chain_work || entry.height > tip.height + MIN_BLOCKS_TO_KEEP || entry.chain_work < self.minimum_chain_work {
                return BlockOutcome::AcceptedHeaderOnly;
            }
        }
        let result = {
            let entry = self.tree.get(id);
            match entry.parent {
                Some(parent_id) => {
                    let parent = self.tree.get(parent_id);
                    let info = ParentInfo { height: parent.height, header: &parent.header, median_time_past: parent.median_time_past };
                    contextual_check_block(&block, Some(&info), &self.params.consensus)
                }
                None => contextual_check_block(&block, None, &self.params.consensus),
            }
        };
        if let Err(failure) = result {
            if failure.kind != FailureKind::Mutated {
                self.mark_invalid(id);
            }
            return BlockOutcome::Rejected(failure);
        }
        self.tree.get_mut(id).has_data = true;
        self.store.put_block(self.tree.get(id), block);
        self.store.entry_changed(id, self.tree.get(id));
        self.link(id);
        BlockOutcome::Accepted
    }

    /// Assigns sequence numbers to `id` and any waiting descendants, or queues it until its parent
    /// is linked. Core: `ChainstateManager::ReceivedBlockTransactions`.
    fn link(&mut self, id: EntryId) {
        let parent = self.tree.get(id).parent;
        let parent_linked = parent.is_none_or(|p| self.tree.get(p).sequence_id != 0);
        if !parent_linked {
            let parent = parent.unwrap();
            if !self.tree.get(parent).failed {
                self.unlinked.entry(parent).or_default().push(id);
            }
            return;
        }
        let mut queue = VecDeque::new();
        queue.push_back(id);
        while let Some(current) = queue.pop_front() {
            self.tree.get_mut(current).sequence_id = self.next_sequence_id;
            self.next_sequence_id += 1;
            let tip = self.tree.tip();
            if !self.is_worse(current, tip) {
                self.candidates.insert(current);
            }
            if let Some(children) = self.unlinked.remove(&current) {
                queue.extend(children);
            }
        }
    }

    /// Marks a block and all its known descendants invalid. Core: `InvalidBlockFound`,
    /// `InvalidChainFound`, `SetBlockFailureFlags`.
    fn mark_invalid(&mut self, id: EntryId) {
        let height = self.tree.get(id).height;
        let mut descendants = Vec::new();
        for index in 0..self.tree.entries.len() {
            let other = index as EntryId;
            if self.tree.get(other).height >= height && self.tree.ancestor(other, height) == Some(id) {
                descendants.push(other);
            }
        }
        for descendant in descendants {
            if !self.tree.get(descendant).failed {
                self.tree.get_mut(descendant).failed = true;
                self.store.entry_changed(descendant, self.tree.get(descendant));
            }
        }
        self.candidates.remove(&id);
        if self.tree.get(self.best_header).failed {
            self.recalculate_best_header();
        }
    }

    // -----------------------------------------------------------------------------------------
    // Chain activation (section 11.7).

    /// Core: `Chainstate::FindMostWorkChain`.
    fn find_most_work_chain(&mut self) -> Option<EntryId> {
        loop {
            let mut best: Option<EntryId> = None;
            for &candidate in &self.candidates {
                best = match best {
                    None => Some(candidate),
                    Some(current) if self.is_worse(current, candidate) => Some(candidate),
                    keep => keep,
                };
            }
            let best = best?;
            let mut test = best;
            let mut bad_path = false;
            loop {
                if self.tree.is_active(test) {
                    break;
                }
                let entry = self.tree.get(test);
                if entry.failed || !entry.has_data {
                    let mut failed = best;
                    while failed != test {
                        self.candidates.remove(&failed);
                        failed = self.tree.get(failed).parent.unwrap();
                    }
                    self.candidates.remove(&test);
                    bad_path = true;
                    break;
                }
                test = entry.parent.expect("non-active block has a parent");
            }
            if !bad_path {
                return Some(best);
            }
        }
    }

    /// Core: `Chainstate::PruneBlockIndexCandidates`.
    fn prune_candidates(&mut self) {
        let tip = self.tree.tip();
        let worse: Vec<EntryId> = self.candidates.iter().filter(|&&c| self.is_worse(c, tip)).copied().collect();
        for candidate in worse {
            self.candidates.remove(&candidate);
        }
    }

    /// The second half of Core's `Chainstate::ConnectTip`: a block whose checks all passed becomes
    /// the tip.
    fn commit(&mut self, pending: PendingBlock) {
        let started = std::time::Instant::now();
        let PendingBlock { id, block, changes, undo, .. } = pending;
        let coins = self.store.coins();
        changes.apply(coins);
        coins.best_block = block.hash;
        timing::add(&timing::APPLY_NS, started);
        let entry = self.tree.get_mut(id);
        entry.has_undo = true;
        entry.connected_once = true;
        self.tree.active.push(id);
        self.store.put_undo(self.tree.get(id), &block, undo);
        self.store.entry_changed(id, self.tree.get(id));
    }

    /// Connects `path` (children of the tip, in order). Core: `ActivateBestChainStep`, `ConnectTip`.
    /// Up to `pipeline_depth` blocks are in progress at once: block k's scripts are verified while
    /// block k+1's transactions are applied to a view that includes block k's (uncommitted) changes.
    /// Blocks are committed strictly in order, and a failure is acted on only once every earlier
    /// block has committed, so the outcome is exactly that of connecting one block at a time.
    /// Returns false if a store hook stopped activation.
    fn connect_path(&mut self, path: &[EntryId], failures: &mut Vec<(EntryId, Failure)>) -> bool {
        let depth = self.pipeline_depth.max(1);
        let mut pending: VecDeque<PendingBlock> = VecDeque::new();
        let mut next = 0usize;
        let mut prepare_failure: Option<(EntryId, Failure)> = None;
        loop {
            while prepare_failure.is_none() && next < path.len() && pending.len() < depth {
                let id = path[next];
                next += 1;
                let block = self.store.get_block(self.tree.get(id)).expect("candidate has data");
                let overlays: Vec<&BlockChanges> = pending.iter().map(|p| &p.changes).collect();
                match prepare_block(&block, id, &self.tree, self.store.coins(), &overlays, &self.params) {
                    Ok(prepared) => pending.push_back(PendingBlock::start(id, block, prepared)),
                    Err(failure) => prepare_failure = Some((id, failure)),
                }
            }
            let Some(oldest) = pending.pop_front() else {
                if let Some((id, failure)) = prepare_failure.take() {
                    self.mark_invalid(id);
                    failures.push((id, failure));
                }
                return true;
            };
            match oldest.wait() {
                (oldest, None) => {
                    let id = oldest.id;
                    self.commit(oldest);
                    self.prune_candidates();
                    if !self.store.connected(&self.tree, id) {
                        self.halted = true;
                        return false;
                    }
                }
                (oldest, Some(error)) => {
                    // Later blocks descend from this one; their work is discarded.
                    pending.clear();
                    self.mark_invalid(oldest.id);
                    failures.push((oldest.id, invalid(&format!("block-script-verify-flag-failed ({})", error.message()))));
                    return true;
                }
            }
        }
    }

    /// Core: `Chainstate::DisconnectTip`, `DisconnectBlock`.
    fn disconnect_tip(&mut self) {
        let id = self.tree.active.pop().expect("never disconnect genesis");
        assert!(!self.tree.active.is_empty(), "never disconnect genesis");
        let entry = self.tree.get(id).clone();
        let block = self.store.get_block(&entry).expect("a block to disconnect must have data (pruned too deep?)");
        let undo = self.store.get_undo(&entry).expect("a block to disconnect must have undo data (pruned too deep?)");
        let coins = self.store.coins();
        for (index, tx) in block.block.transactions.iter().enumerate().rev() {
            let txid = block.tx_info[index].txid;
            for (vout, output) in tx.outputs.iter().enumerate() {
                if !is_unspendable(&output.script_pubkey) {
                    coins.delete(&OutPoint { txid, vout: vout as u32 });
                }
            }
            if index > 0 {
                for (input, coin) in tx.inputs.iter().zip(undo[index - 1].iter()).rev() {
                    coins.put(input.prevout, coin.clone(), false);
                }
            }
        }
        coins.best_block = entry.header.prev_block;
        self.store.disconnected(&self.tree, id);
    }

    /// Core: `Chainstate::ActivateBestChain`. Returns the blocks that failed to connect, with their
    /// failures.
    pub fn activate_best_chain(&mut self) -> Vec<(EntryId, Failure)> {
        let mut failures = Vec::new();
        loop {
            if self.halted {
                return failures;
            }
            let best = match self.find_most_work_chain() {
                Some(best) => best,
                None => return failures,
            };
            if best == self.tree.tip() {
                return failures;
            }
            let fork = self.tree.find_fork(best);
            while self.tree.tip() != fork {
                self.disconnect_tip();
            }
            let fork_height = self.tree.get(fork).height;
            let best_height = self.tree.get(best).height;
            let path: Vec<EntryId> = (fork_height + 1..=best_height).map(|h| self.tree.ancestor(best, h).unwrap()).collect();
            if !self.connect_path(&path, &mut failures) {
                return failures;
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Operator invalidation (section 11.9) and reporting (section 11.10).

    /// Core: `Chainstate::InvalidateBlock` and `ActivateBestChain`.
    pub fn invalidate_block(&mut self, hash: &Hash256) {
        if *hash == self.params.consensus.genesis_hash {
            return;
        }
        let id = match self.tree.lookup(hash) {
            Some(id) => id,
            None => return,
        };
        while self.tree.is_active(id) {
            let disconnected = self.tree.tip();
            self.disconnect_tip();
            self.tree.get_mut(disconnected).failed = true;
            self.store.entry_changed(disconnected, self.tree.get(disconnected));
            self.candidates.remove(&disconnected);
        }
        self.mark_invalid(id);
        let tip = self.tree.tip();
        self.candidates.insert(tip);
        let eligible: Vec<EntryId> = (0..self.tree.entries.len() as EntryId)
            .filter(|&e| {
                let entry = self.tree.get(e);
                entry.has_data && !entry.failed && entry.sequence_id != 0
            })
            .filter(|&e| !self.is_worse(e, tip))
            .collect();
        self.candidates.extend(eligible);
        self.activate_best_chain();
    }

    /// Returns (hash, height, status) for every chain tip.
    pub fn chain_tips(&self) -> Vec<(Hash256, i32, &'static str)> {
        let mut has_inactive_child = HashSet::new();
        for (index, entry) in self.tree.entries.iter().enumerate() {
            if !self.tree.is_active(index as EntryId) {
                if let Some(parent) = entry.parent {
                    has_inactive_child.insert(parent);
                }
            }
        }
        let tip = self.tree.tip();
        let mut tips = Vec::new();
        for (index, entry) in self.tree.entries.iter().enumerate() {
            let id = index as EntryId;
            let active = self.tree.is_active(id);
            let is_tip = if active { id == tip } else { !has_inactive_child.contains(&id) };
            if !is_tip {
                continue;
            }
            let status = if active {
                "active"
            } else if entry.failed {
                "invalid"
            } else if entry.sequence_id == 0 {
                "headers-only"
            } else if entry.connected_once {
                "valid-fork"
            } else {
                "valid-headers"
            };
            tips.push((entry.hash, entry.height, status));
        }
        tips.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        tips
    }

    /// Prunes the block and undo data of the active blocks at heights `from..to` (a node may do
    /// this after connecting them; a reorganization can then not go below `to`).
    pub fn prune_active(&mut self, from: i32, to: i32) {
        let to = to.min(self.tree.active.len() as i32);
        for height in from.max(1)..to {
            let id = self.tree.active[height as usize];
            let entry = self.tree.get(id);
            if entry.has_data || entry.has_undo {
                self.store.remove_data(entry);
                let entry = self.tree.get_mut(id);
                entry.has_data = false;
                entry.has_undo = false;
                self.store.entry_changed(id, self.tree.get(id));
            }
        }
    }

    /// Chapter 15 fingerprint of the active chain's UTXO set (flushes the cache first).
    pub fn utxo_hash(&mut self) -> std::io::Result<(Hash256, u64)> {
        let coins = self.store.coins();
        coins.flush()?;
        crate::coins::utxo_hash_of_db(coins.db())
    }
}

/// Core: `PeerManagerImpl::GetAntiDoSWorkThreshold` (chapter 14 section 14.4): the tip's work minus
/// 144 blocks of work at the tip's difficulty, but at least the minimum chain work.
pub fn anti_dos_work_threshold<S: ChainStore>(state: &ChainState<S>) -> U256 {
    let tip = state.tip();
    let buffer = block_proof(tip.header.bits).wrapping_mul(U256::from_u64(144));
    let near_tip = if buffer > tip.chain_work { U256::ZERO } else { tip.chain_work.wrapping_sub(buffer) };
    std::cmp::max(near_tip, state.minimum_chain_work)
}

/// Whether a block that arrived in a `block` message may be processed (chapter 14 section 14.4).
/// Core: the `BLOCK` case of `ProcessMessage` (`min_pow_checked`) and `AcceptBlockHeader`.
pub fn p2p_block_work_acceptable<S: ChainStore>(state: &ChainState<S>, header: &BlockHeader, hash: &Hash256) -> bool {
    if state.tree.lookup(hash).is_some() {
        return true;
    }
    match state.tree.lookup(&header.prev_block) {
        // An orphan; `process_block` discards it.
        None => true,
        Some(parent) => state.tree.get(parent).chain_work.wrapping_add(block_proof(header.bits)) >= anti_dos_work_threshold(state),
    }
}

/// Why `headers_message_acceptable` drops a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadersRejection {
    /// A header fails its own proof of work (misbehaviour).
    BadProofOfWork,
    /// The headers do not form a continuous chain (misbehaviour).
    NonContinuous,
    /// The first header's parent is unknown (Core asks for headers again).
    UnknownParent,
    /// The chain's claimed work is below the anti-denial-of-service threshold.
    LowWork,
}

/// Core: the message-level checks of `PeerManagerImpl::ProcessHeadersMessage`, `CheckHeadersPoW`,
/// `TryLowWorkHeadersSync`, `IsAncestorOfBestHeaderOrTip` (chapter 14 section 14.3).
pub fn headers_message_acceptable<S: ChainStore>(state: &ChainState<S>, headers: &[BlockHeader]) -> Result<(), HeadersRejection> {
    if headers.is_empty() {
        return Ok(());
    }
    let pow_limit = state.params.consensus.pow_limit;
    let hashes: Vec<Hash256> = headers.iter().map(|header| header.hash()).collect();
    if headers.iter().zip(&hashes).any(|(header, hash)| !crate::pow::check_proof_of_work(hash, header.bits, pow_limit)) {
        return Err(HeadersRejection::BadProofOfWork);
    }
    if headers.windows(2).zip(hashes.iter()).any(|(pair, first_hash)| pair[1].prev_block != *first_hash) {
        return Err(HeadersRejection::NonContinuous);
    }
    let parent = match state.tree.lookup(&headers[0].prev_block) {
        Some(parent) => parent,
        None => return Err(HeadersRejection::UnknownParent),
    };
    let last = *hashes.last().expect("not empty");
    let last_already_on_best = state.tree.lookup(&last).is_some_and(|id| {
        let height = state.tree.get(id).height;
        state.tree.ancestor(state.best_header, height) == Some(id) || state.tree.is_active(id)
    });
    if last_already_on_best {
        return Ok(());
    }
    let claimed_work = headers.iter().fold(state.tree.get(parent).chain_work, |work, header| work.wrapping_add(block_proof(header.bits)));
    if claimed_work < anti_dos_work_threshold(state) {
        return Err(HeadersRejection::LowWork);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Connecting a block (chapter 10 section 10.8).

/// The changes a block makes to the UTXO set, kept apart from the cache until the block is
/// known to be valid (reference: the `UtxoView` changes).
pub struct BlockChanges {
    /// Outputs created by the block: the coin (`None` once spent later in the same block) and
    /// whether the outpoint already held an unspent coin before the block (a BIP30 exception).
    created: OutPointMap<(Option<Coin>, bool)>,
    /// Coins that existed before the block and that it spent.
    spent: OutPointMap<()>,
}

impl BlockChanges {
    fn new() -> BlockChanges {
        BlockChanges { created: new_outpoint_map(), spent: new_outpoint_map() }
    }

    /// The coin at `outpoint` after this block's changes so far, if they say anything about it.
    fn lookup(&self, outpoint: &OutPoint) -> Option<Option<Coin>> {
        if let Some((coin, _)) = self.created.get(outpoint) {
            return Some(coin.clone());
        }
        if self.spent.contains_key(outpoint) {
            return Some(None);
        }
        None
    }

    /// The coin at `outpoint` as seen by the block so far: its own changes, then those of the
    /// earlier uncommitted blocks (newest first), then the cache.
    fn get(&self, coins: &mut CoinsCache, earlier: &[&BlockChanges], outpoint: &OutPoint) -> Option<Coin> {
        if let Some(found) = self.lookup(outpoint) {
            return found;
        }
        for overlay in earlier.iter().rev() {
            if let Some(found) = overlay.lookup(outpoint) {
                return found;
            }
        }
        coins.get(outpoint)
    }

    /// Spends a coin that `get` returned.
    fn spend(&mut self, outpoint: &OutPoint) {
        if let Some((coin, _)) = self.created.get_mut(outpoint) {
            *coin = None;
        } else {
            self.spent.insert(*outpoint, ());
        }
    }

    /// Writes the changes into the cache.
    pub fn apply(self, coins: &mut CoinsCache) {
        for outpoint in self.spent.keys() {
            coins.delete(outpoint);
        }
        for (outpoint, (coin, overwrote)) in self.created {
            match coin {
                Some(coin) => {
                    let fresh = !coin.is_coinbase && !overwrote && !self.spent.contains_key(&outpoint);
                    coins.put(outpoint, coin, fresh);
                }
                None => {
                    if overwrote {
                        coins.delete(&outpoint);
                    }
                }
            }
        }
    }
}

/// Script check data of one transaction.
struct TxScriptData {
    spent_outputs: Vec<TxOut>,
    precomputed: PrecomputedTx,
}

/// A block prepared for connection: its UTXO changes, undo data, and what its script checks need.
pub struct PreparedBlock {
    changes: BlockChanges,
    undo: BlockUndo,
    script_data: Vec<Option<TxScriptData>>,
    flags: u32,
}

/// A block whose scripts are being verified in the background.
struct PendingBlock {
    id: EntryId,
    block: Arc<BlockData>,
    changes: BlockChanges,
    undo: BlockUndo,
    scripts: std::sync::mpsc::Receiver<Option<ScriptError>>,
}

impl PendingBlock {
    fn start(id: EntryId, block: Arc<BlockData>, prepared: PreparedBlock) -> PendingBlock {
        let PreparedBlock { changes, undo, script_data, flags } = prepared;
        let (sender, receiver) = std::sync::mpsc::channel();
        let job_block = block.clone();
        rayon::spawn(move || {
            let started = std::time::Instant::now();
            let result = verify_block_scripts(&job_block.block.transactions, &script_data, flags);
            timing::add(&timing::SCRIPTS_NS, started);
            let _ = sender.send(result);
        });
        PendingBlock { id, block, changes, undo, scripts: receiver }
    }

    /// Waits for the script checks; returns the first failing input's error, if any.
    fn wait(self) -> (PendingBlock, Option<ScriptError>) {
        let started = std::time::Instant::now();
        let result = self.scripts.recv().expect("script verification task");
        timing::add(&timing::WAIT_NS, started);
        (self, result)
    }
}

/// Connects `block` (entry `id`, whose parent is the active tip) to the UTXO set in `coins`.
/// On success returns the changes to apply and the undo data. Core: `ConnectBlock`.
pub fn connect_block(block: &BlockData, id: EntryId, tree: &BlockTree, coins: &mut CoinsCache, params: &NetworkParams) -> Result<(BlockChanges, BlockUndo), Failure> {
    let prepared = prepare_block(block, id, tree, coins, &[], params)?;
    if let Some(error) = verify_block_scripts(&block.block.transactions, &prepared.script_data, prepared.flags) {
        return Err(invalid(&format!("block-script-verify-flag-failed ({})", error.message())));
    }
    Ok((prepared.changes, prepared.undo))
}

/// Everything `ConnectBlock` checks except the scripts (chapter 10 section 10.8 steps 1 to 4),
/// against the UTXO set in `coins` as modified by `earlier` (uncommitted blocks between the active
/// tip and this block's parent, oldest first).
pub fn prepare_block(block: &BlockData, id: EntryId, tree: &BlockTree, coins: &mut CoinsCache, earlier: &[&BlockChanges], params: &NetworkParams) -> Result<PreparedBlock, Failure> {
    let consensus = &params.consensus;
    let entry = tree.get(id);
    let mut changes = BlockChanges::new();
    let flags = block_script_flags(&entry.hash, entry.height, consensus);
    if entry.hash == consensus.genesis_hash {
        return Ok(PreparedBlock { changes, undo: Vec::new(), script_data: Vec::new(), flags });
    }
    let height = entry.height;
    let parent_id = entry.parent.expect("non-genesis block has a parent");
    let parent = tree.get(parent_id);
    let transactions = &block.block.transactions;

    // BIP30.
    let mut enforce_bip30 = !is_bip30_repeat(height, &entry.hash);
    if let Some(bip34_block) = tree.ancestor(parent_id, consensus.bip34_height) {
        if tree.get(bip34_block).hash == consensus.bip34_hash {
            enforce_bip30 = false;
        }
    }
    let check_bip30 = enforce_bip30 || height >= BIP34_IMPLIES_BIP30_LIMIT;

    // Load every coin the block can touch in one batched lookup (a cache warm-up only).
    let started = std::time::Instant::now();
    {
        let mut wanted: Vec<OutPoint> = Vec::new();
        for tx in transactions.iter().skip(1) {
            wanted.extend(tx.inputs.iter().map(|input| input.prevout));
        }
        if check_bip30 {
            for (tx, info) in transactions.iter().zip(&block.tx_info) {
                wanted.extend((0..tx.outputs.len() as u32).map(|vout| OutPoint { txid: info.txid, vout }));
            }
        }
        coins.prefetch(&wanted);
        timing::INPUTS.fetch_add(wanted.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }
    timing::add(&timing::PREFETCH_NS, started);
    let started = std::time::Instant::now();

    if check_bip30 {
        for (tx, info) in transactions.iter().zip(&block.tx_info) {
            for vout in 0..tx.outputs.len() as u32 {
                if changes.get(coins, earlier, &OutPoint { txid: info.txid, vout }).is_some() {
                    return Err(invalid("bad-txns-BIP30"));
                }
            }
        }
    }

    let enforce_bip68 = height >= consensus.csv_height;
    let mtp_at = |h: i32| tree.get(tree.ancestor(id, h).expect("ancestor exists")).median_time_past;

    let mut fees: i64 = 0;
    let mut sigops_cost: i64 = 0;
    let mut undo: BlockUndo = Vec::with_capacity(transactions.len().saturating_sub(1));
    let mut script_data: Vec<Option<TxScriptData>> = Vec::with_capacity(transactions.len());

    for (tx_index, tx) in transactions.iter().enumerate() {
        let is_coinbase = tx.is_coinbase();
        let spent: Vec<Coin> = if is_coinbase {
            Vec::new()
        } else {
            let found: Vec<Option<Coin>> = tx.inputs.iter().map(|input| changes.get(coins, earlier, &input.prevout)).collect();
            let fee = check_tx_inputs(tx, &found, height).map_err(invalid)?;
            fees += fee;
            if !money_range(fees) {
                return Err(invalid("bad-txns-accumulated-fee-outofrange"));
            }
            let spent: Vec<Coin> = found.into_iter().map(|coin| coin.unwrap()).collect();
            let coin_heights: Vec<i32> = spent.iter().map(|coin| coin.height).collect();
            let lock = calculate_sequence_locks(tx, enforce_bip68, &coin_heights, &mtp_at);
            if !evaluate_sequence_locks(height, parent.median_time_past, lock) {
                return Err(invalid("bad-txns-nonfinal"));
            }
            spent
        };
        let spent_refs: Vec<&TxOut> = spent.iter().map(|coin| &coin.output).collect();
        sigops_cost += transaction_sig_op_cost(tx, &spent_refs, flags);
        if sigops_cost > MAX_BLOCK_SIGOPS_COST {
            return Err(invalid("bad-blk-sigops"));
        }
        if is_coinbase {
            script_data.push(None);
        } else {
            let spent_outputs: Vec<TxOut> = spent.iter().map(|coin| coin.output.clone()).collect();
            let precomputed = PrecomputedTx::new(tx, &spent_outputs);
            script_data.push(Some(TxScriptData { spent_outputs, precomputed }));
            for input in &tx.inputs {
                changes.spend(&input.prevout);
            }
            undo.push(spent);
        }
        // Add the outputs (Core: `AddCoins`).
        let txid = block.tx_info[tx_index].txid;
        for (vout, output) in tx.outputs.iter().enumerate() {
            if is_unspendable(&output.script_pubkey) {
                continue;
            }
            let outpoint = OutPoint { txid, vout: vout as u32 };
            // Only a coinbase can repeat an earlier txid while that one is unspent (BIP30
            // exceptions); for anything else BIP30 (or BIP34) rules the overwrite out.
            let overwrote = if is_coinbase { changes.get(coins, earlier, &outpoint).is_some() } else { false };
            let coin = Coin { output: output.clone(), height, is_coinbase };
            match changes.created.get_mut(&outpoint) {
                Some(existing) => {
                    existing.0 = Some(coin);
                    existing.1 |= overwrote;
                }
                None => {
                    changes.created.insert(outpoint, (Some(coin), overwrote));
                }
            }
        }
    }

    let block_reward = fees + block_subsidy(height, consensus);
    if transactions[0].value_out() > block_reward {
        return Err(invalid("bad-cb-amount"));
    }
    timing::add(&timing::SERIAL_NS, started);
    Ok(PreparedBlock { changes, undo, script_data, flags })
}

/// Runs every input's script check in parallel and returns the error of the first failing input
/// in block order (the reference runs them in order and stops at the first failure).
fn verify_block_scripts(transactions: &[Transaction], script_data: &[Option<TxScriptData>], flags: u32) -> Option<ScriptError> {
    let jobs: Vec<(u32, u32)> = script_data
        .iter()
        .enumerate()
        .filter_map(|(tx_index, data)| data.as_ref().map(|_| tx_index))
        .flat_map(|tx_index| (0..transactions[tx_index].inputs.len() as u32).map(move |input| (tx_index as u32, input)))
        .collect();
    let check = |&(tx_index, input_index): &(u32, u32)| -> Option<ScriptError> {
        let tx = &transactions[tx_index as usize];
        let data = script_data[tx_index as usize].as_ref().unwrap();
        verify_input(tx, input_index as usize, &data.spent_outputs, &data.precomputed, flags).err()
    };
    if jobs.len() < 16 {
        return jobs.iter().find_map(check);
    }
    jobs.par_iter().with_min_len(4).find_map_first(check)
}

// ---------------------------------------------------------------------------------------------
// An in-memory store (the harness, and tests).

/// Coin cache size of the in-memory store. Deliberately small, so that the harness also
/// exercises flushing and reading coins back from the backend.
pub const MEMORY_STORE_CACHE_ENTRIES: usize = 448;

/// Keeps block data, undo data and the coin backend in memory.
pub struct MemoryStore {
    pub coins: CoinsCache,
    pub blocks: HashMap<Hash256, Arc<BlockData>>,
    pub undo: HashMap<Hash256, BlockUndo>,
}

impl MemoryStore {
    pub fn new(genesis_hash: Hash256) -> MemoryStore {
        MemoryStore {
            coins: CoinsCache::new(Box::<crate::coins::MemoryCoinDb>::default(), genesis_hash, MEMORY_STORE_CACHE_ENTRIES),
            blocks: HashMap::new(),
            undo: HashMap::new(),
        }
    }
}

impl ChainStore for MemoryStore {
    fn coins(&mut self) -> &mut CoinsCache {
        &mut self.coins
    }

    fn put_block(&mut self, entry: &BlockEntry, block: Arc<BlockData>) {
        self.blocks.insert(entry.hash, block);
    }

    fn get_block(&mut self, entry: &BlockEntry) -> Option<Arc<BlockData>> {
        self.blocks.get(&entry.hash).cloned()
    }

    fn put_undo(&mut self, entry: &BlockEntry, _block: &Arc<BlockData>, undo: BlockUndo) {
        self.undo.insert(entry.hash, undo);
    }

    fn get_undo(&mut self, entry: &BlockEntry) -> Option<BlockUndo> {
        self.undo.get(&entry.hash).cloned()
    }

    fn connected(&mut self, _tree: &BlockTree, _id: EntryId) -> bool {
        if self.coins.needs_flush(MEMORY_STORE_CACHE_ENTRIES / 4) {
            self.coins.flush().expect("in-memory flush");
        }
        true
    }
}
