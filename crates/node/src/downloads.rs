//! Block download bookkeeping shared by the chain thread and the peer reader threads.
//!
//! The chain thread decides which blocks are wanted (the missing blocks along the best header
//! chain, oldest first; chapter 14 section 14.4) and puts them in `queue`. Requests go out from
//! whichever thread frees a slot: a peer's reader thread as soon as a block arrives, or the chain
//! thread after it processed blocks or learned headers. So downloading continues while the chain
//! thread is busy connecting blocks.

use consensus::p2p::{encode_inv, encode_message, MSG_WITNESS_BLOCK};
use consensus::util::Hash256;
use crossbeam_channel::Sender;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct PeerSlot {
    pub sender: Sender<Vec<u8>>,
    /// Handshake complete and the peer serves historical blocks: requests may be sent.
    pub ready: bool,
    pub in_flight: usize,
    /// Height of the best block the peer is known to have.
    pub height: i32,
}

pub struct DownloadState {
    magic: [u8; 4],
    /// Blocks to request (hash and height), oldest first.
    queue: VecDeque<(Hash256, i32)>,
    queued: HashSet<Hash256>,
    /// Requested blocks: peer, time of the request and height.
    pub in_flight: HashMap<Hash256, (usize, Instant, i32)>,
    peers: HashMap<usize, PeerSlot>,
    /// Blocks received and not yet processed by the chain thread.
    buffered: usize,
    max_per_peer: usize,
    max_buffered: usize,
    next_peer: usize,
}

pub type Downloads = Arc<Mutex<DownloadState>>;

impl DownloadState {
    pub fn new(magic: [u8; 4], max_per_peer: usize, max_buffered: usize) -> Downloads {
        Arc::new(Mutex::new(DownloadState {
            magic,
            queue: VecDeque::new(),
            queued: HashSet::new(),
            in_flight: HashMap::new(),
            peers: HashMap::new(),
            buffered: 0,
            max_per_peer,
            max_buffered,
            next_peer: 0,
        }))
    }

    pub fn add_peer(&mut self, peer: usize, sender: Sender<Vec<u8>>) {
        self.peers.insert(peer, PeerSlot { sender, ready: false, in_flight: 0, height: 0 });
    }

    pub fn set_ready(&mut self, peer: usize, height: i32) {
        if let Some(slot) = self.peers.get_mut(&peer) {
            slot.ready = true;
            slot.height = slot.height.max(height);
        }
        self.fill();
    }

    /// The peer has (at least) the block at `height`.
    pub fn peer_has_height(&mut self, peer: usize, height: i32) {
        if let Some(slot) = self.peers.get_mut(&peer) {
            if height > slot.height {
                slot.height = height;
                self.fill();
            }
        }
    }

    pub fn ready_peers(&self) -> usize {
        self.peers.values().filter(|slot| slot.ready).count()
    }

    /// Forgets a peer; its outstanding requests go back to the front of the queue.
    pub fn remove_peer(&mut self, peer: usize) {
        self.peers.remove(&peer);
        let mut lost: Vec<(Hash256, i32)> = self.in_flight.iter().filter(|(_, (owner, _, _))| *owner == peer).map(|(h, (_, _, height))| (*h, *height)).collect();
        lost.sort_by_key(|(_, height)| *height);
        for (hash, height) in lost.into_iter().rev() {
            self.in_flight.remove(&hash);
            if self.queued.insert(hash) {
                self.queue.push_front((hash, height));
            }
        }
        self.fill();
    }

    /// Replaces the wanted list (oldest first). Blocks already in flight stay in flight.
    pub fn set_wanted(&mut self, wanted: Vec<(Hash256, i32)>) {
        self.queue.clear();
        self.queued.clear();
        for (hash, height) in wanted {
            if !self.in_flight.contains_key(&hash) && self.queued.insert(hash) {
                self.queue.push_back((hash, height));
            }
        }
        self.fill();
    }

    /// A block arrived from a peer; returns whether it had been requested.
    pub fn received(&mut self, hash: &Hash256) -> bool {
        self.buffered += 1;
        let requested = match self.in_flight.remove(hash) {
            Some((owner, _, _)) => {
                if let Some(slot) = self.peers.get_mut(&owner) {
                    slot.in_flight = slot.in_flight.saturating_sub(1);
                }
                true
            }
            None => false,
        };
        self.fill();
        requested
    }

    /// The chain thread finished with a received block.
    pub fn processed(&mut self) {
        self.buffered = self.buffered.saturating_sub(1);
    }

    /// Requests that went unanswered for `timeout` are requested again (Bitcoin Core never sends
    /// `notfound` for blocks).
    pub fn expire(&mut self, timeout: Duration) -> usize {
        let mut expired: Vec<(Hash256, usize, i32)> = self.in_flight.iter().filter(|(_, (_, at, _))| at.elapsed() > timeout).map(|(h, (p, _, height))| (*h, *p, *height)).collect();
        expired.sort_by_key(|(_, _, height)| std::cmp::Reverse(*height));
        for (hash, owner, height) in &expired {
            self.in_flight.remove(hash);
            if let Some(slot) = self.peers.get_mut(owner) {
                slot.in_flight = slot.in_flight.saturating_sub(1);
            }
            if self.queued.insert(*hash) {
                self.queue.push_front((*hash, *height));
            }
        }
        if !expired.is_empty() {
            self.fill();
        }
        expired.len()
    }

    /// The in-flight request for the lowest block, if any: (peer, how long ago, height).
    pub fn oldest_needed(&self) -> Option<(usize, Duration, i32)> {
        self.in_flight.values().min_by_key(|(_, _, height)| *height).map(|(peer, at, height)| (*peer, at.elapsed(), *height))
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// Sends requests, oldest block first, to ready peers that have the block and a free slot,
    /// while the buffer limit allows.
    pub fn fill(&mut self) {
        let mut per_peer: HashMap<usize, Vec<(u32, Hash256)>> = HashMap::new();
        loop {
            if self.buffered + self.in_flight.len() >= self.max_buffered {
                break;
            }
            let Some(&(hash, height)) = self.queue.front() else { break };
            if self.in_flight.contains_key(&hash) {
                self.queue.pop_front();
                self.queued.remove(&hash);
                continue;
            }
            let mut ids: Vec<usize> = self.peers.iter().filter(|(_, s)| s.ready && s.in_flight < self.max_per_peer && s.height >= height).map(|(id, _)| *id).collect();
            if ids.is_empty() {
                break;
            }
            ids.sort_unstable();
            let peer = ids[self.next_peer % ids.len()];
            self.next_peer = self.next_peer.wrapping_add(1);
            self.queue.pop_front();
            self.queued.remove(&hash);
            self.in_flight.insert(hash, (peer, Instant::now(), height));
            self.peers.get_mut(&peer).unwrap().in_flight += 1;
            per_peer.entry(peer).or_default().push((MSG_WITNESS_BLOCK, hash));
        }
        for (peer, items) in per_peer {
            if let Some(slot) = self.peers.get(&peer) {
                let _ = slot.sender.send(encode_message(self.magic, "getdata", &encode_inv(&items)));
            }
        }
    }
}
