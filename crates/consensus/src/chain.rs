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
}

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
        let mut best_header = 0;
        let mut next_header_order = 0;
        for (index, entry) in tree.entries.iter().enumerate() {
            next_header_order = next_header_order.max(entry.header_order + 1);
            if entry.failed {
                continue;
            }
            let best = tree.get(best_header);
            if entry.chain_work > best.chain_work || (entry.chain_work == best.chain_work && entry.header_order < best.header_order) {
                best_header = index as EntryId;
            }
        }
        let mut state = ChainState {
            params,
            tree,
            store,
            candidates: HashSet::new(),
            unlinked: HashMap::new(),
            next_sequence_id,
            next_header_order,
            best_header,
            halted: false,
        };
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

    /// Recomputes the best header after blocks were marked invalid. Core: `RecalculateBestHeader`.
    fn recalculate_best_header(&mut self) {
        let mut best: Option<EntryId> = None;
        for (index, entry) in self.tree.entries.iter().enumerate() {
            if entry.failed {
                continue;
            }
            best = match best {
                None => Some(index as EntryId),
                Some(current) => {
                    let current_entry = self.tree.get(current);
                    if entry.chain_work > current_entry.chain_work || (entry.chain_work == current_entry.chain_work && entry.header_order < current_entry.header_order) {
                        Some(index as EntryId)
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
        if let Err(failure) = check_block(&block, &self.params.consensus) {
            return BlockOutcome::Rejected(failure);
        }
        let id = match self.accept_header_hashed(&block.block.header, &block.hash, now) {
            Ok(id) => id,
            Err(HeaderError::Orphan) => return BlockOutcome::Orphan,
            Err(HeaderError::Failed(failure)) => return BlockOutcome::Rejected(failure),
        };
        if self.tree.get(id).has_data {
            self.activate_best_chain();
            return BlockOutcome::Duplicate;
        }
        if !requested {
            let entry = self.tree.get(id);
            let tip = self.tip();
            if entry.chain_work < tip.chain_work || entry.height > tip.height + MIN_BLOCKS_TO_KEEP {
                self.activate_best_chain();
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
        self.activate_best_chain();
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

    /// Core: `Chainstate::ConnectTip`.
    fn connect_tip(&mut self, id: EntryId) -> Result<(), Failure> {
        let block = self.store.get_block(self.tree.get(id)).expect("candidate has data");
        let (changes, undo) = connect_block(&block, id, &self.tree, self.store.coins(), &self.params)?;
        let coins = self.store.coins();
        changes.apply(coins);
        coins.best_block = block.hash;
        let entry = self.tree.get_mut(id);
        entry.has_undo = true;
        entry.connected_once = true;
        self.tree.active.push(id);
        self.store.put_undo(self.tree.get(id), &block, undo);
        self.store.entry_changed(id, self.tree.get(id));
        Ok(())
    }

    /// Core: `Chainstate::DisconnectTip`, `DisconnectBlock`.
    fn disconnect_tip(&mut self) {
        let id = self.tree.active.pop().expect("never disconnect genesis");
        assert!(!self.tree.active.is_empty(), "never disconnect genesis");
        let entry = self.tree.get(id).clone();
        let block = self.store.get_block(&entry).expect("disconnected block has data");
        let undo = self.store.get_undo(&entry).expect("disconnected block has undo data");
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

    /// Core: `Chainstate::ActivateBestChain`.
    pub fn activate_best_chain(&mut self) {
        loop {
            if self.halted {
                return;
            }
            let best = match self.find_most_work_chain() {
                Some(best) => best,
                None => return,
            };
            if best == self.tree.tip() {
                return;
            }
            let fork = self.tree.find_fork(best);
            while self.tree.tip() != fork {
                self.disconnect_tip();
            }
            let fork_height = self.tree.get(fork).height;
            let best_height = self.tree.get(best).height;
            let path: Vec<EntryId> = (fork_height + 1..=best_height).map(|h| self.tree.ancestor(best, h).unwrap()).collect();
            for id in path {
                match self.connect_tip(id) {
                    Ok(()) => {
                        self.prune_candidates();
                        if !self.store.connected(&self.tree, id) {
                            self.halted = true;
                            return;
                        }
                    }
                    Err(_) => {
                        self.mark_invalid(id);
                        break;
                    }
                }
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

    /// Chapter 15 fingerprint of the active chain's UTXO set (flushes the cache first).
    pub fn utxo_hash(&mut self) -> std::io::Result<(Hash256, u64)> {
        let coins = self.store.coins();
        coins.flush(true)?;
        crate::coins::utxo_hash_of_db(coins.db())
    }
}

/// Core: the message-level checks of `PeerManagerImpl::ProcessHeadersMessage`. Returns `Ok` if the
/// message is processed at all, else the index of the offending header and why.
pub fn headers_message_acceptable<S: ChainStore>(state: &ChainState<S>, headers: &[BlockHeader]) -> Result<(), (usize, &'static str)> {
    if headers.is_empty() {
        return Ok(());
    }
    let pow_limit = state.params.consensus.pow_limit;
    if let Some(index) = headers.iter().position(|header| !crate::pow::check_proof_of_work(&header.hash(), header.bits, pow_limit)) {
        return Err((index, "high-hash"));
    }
    if let Some(index) = headers.windows(2).position(|pair| pair[1].prev_block != pair[0].hash()) {
        return Err((index + 1, "bad-headers-noncontinuous"));
    }
    if state.tree.lookup(&headers[0].prev_block).is_none() {
        return Err((0, "prev-blk-not-found"));
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

    /// The coin at `outpoint` as seen by the block so far.
    fn get(&self, coins: &mut CoinsCache, outpoint: &OutPoint) -> Option<Coin> {
        if let Some((coin, _)) = self.created.get(outpoint) {
            return coin.clone();
        }
        if self.spent.contains_key(outpoint) {
            return None;
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

/// Connects `block` (entry `id`, whose parent is the active tip) to the UTXO set in `coins`.
/// On success returns the changes to apply and the undo data. Core: `ConnectBlock`.
pub fn connect_block(block: &BlockData, id: EntryId, tree: &BlockTree, coins: &mut CoinsCache, params: &NetworkParams) -> Result<(BlockChanges, BlockUndo), Failure> {
    let consensus = &params.consensus;
    let entry = tree.get(id);
    let mut changes = BlockChanges::new();
    if entry.hash == consensus.genesis_hash {
        return Ok((changes, Vec::new()));
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
    }

    if check_bip30 {
        for (tx, info) in transactions.iter().zip(&block.tx_info) {
            for vout in 0..tx.outputs.len() as u32 {
                if coins.get(&OutPoint { txid: info.txid, vout }).is_some() {
                    return Err(invalid("bad-txns-BIP30"));
                }
            }
        }
    }

    let enforce_bip68 = height >= consensus.csv_height;
    let flags = block_script_flags(&entry.hash, height, consensus);
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
            let found: Vec<Option<Coin>> = tx.inputs.iter().map(|input| changes.get(coins, &input.prevout)).collect();
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
            let overwrote = if is_coinbase { changes.get(coins, &outpoint).is_some() } else { false };
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

    if let Some(error) = verify_block_scripts(transactions, &script_data, flags) {
        return Err(invalid(&format!("block-script-verify-flag-failed ({})", error.message())));
    }
    Ok((changes, undo))
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

/// Keeps block data, undo data and the coin backend in memory.
pub struct MemoryStore {
    pub coins: CoinsCache,
    pub blocks: HashMap<Hash256, Arc<BlockData>>,
    pub undo: HashMap<Hash256, BlockUndo>,
}

impl MemoryStore {
    pub fn new(genesis_hash: Hash256) -> MemoryStore {
        MemoryStore {
            coins: CoinsCache::new(Box::<crate::coins::MemoryCoinDb>::default(), genesis_hash),
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
}
