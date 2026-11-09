# bitcoin-spec-node

A Bitcoin full node in Rust, written only from the specification package in `spec-package/`
(the Bitcoin consensus specification, version `v32.1-1`, pinned to Bitcoin Core v32.1). It
validates every block and every script (no assume-valid), keeps its state on disk across restarts
and crashes, and reports the UTXO set fingerprint (`hash_serialized_3`) that Bitcoin Core's
`gettxoutsetinfo` reports, so that its state can be compared with Bitcoin Core's at any height.

This repository is also an experiment: can a specification alone produce a node that agrees with
Bitcoin Core on every block? `EXPERIMENT_LOG.md` records how it went (timeline, first-run results
of every conformance suite, bugs and their causes) and `SPEC_FEEDBACK.md` lists every place where
the specification was unclear, incomplete or wrong.

## Status

- Every suite of the package's conformance runner passes: script tests, transaction tests, sighash,
  BIP340/BIP341 vectors and the script assets (all 64 flag combinations, identical error
  identifiers), the custom edge cases, the 20-file block corpus (all normative checks, chain tips
  and UTXO set hashes), live header chains of mainnet, testnet3 and testnet4, and the interop suite
  next to Bitcoin Core v32.1 (20 of 20 chains match).
- Regtest scenarios against Bitcoin Core match after syncs, reorganizations (150-step storm), ten
  SIGKILLs during a sync and damaged block files.
- A full testnet4 sync from public peers to 150,000 (run by the experiment owner) reproduced
  Bitcoin Core's three published UTXO set fingerprints.

## Layout

| Path | Contents |
|---|---|
| `crates/consensus` | The consensus library: one module per specification chapter (02 to 15), the chain state of chapter 11 (generic over storage), the UTXO cache and the chapter 15 fingerprint |
| `crates/node` | The `bitcoin-spec-node` binary: `harness` (conformance protocol) and `run` (the node: RocksDB, block files, peer-to-peer) |
| `tools/replay` | `bsn-replay`, an independent replayer for the block corpus (`spec-package/conformance/CORPUS.md`) |
| `tools/txgen` | `bsn-txgen`, builds regtest blocks full of signed transactions and submits them to Bitcoin Core |
| `tools/regtest.py` | Regtest interoperability scenarios against Bitcoin Core (sync with an output contract check, follow, reorganize, storm, kill and restart, benchmark) |
| `tools/corrupt_test.py` | Kills a syncing node, damages its newest block files, restarts it and compares with Bitcoin Core |
| `tools/stall_test.py` | Syncs from Bitcoin Core and from a fake peer that never answers block requests |
| `tools/check_custom.py` | Checks a harness against `spec-package/conformance/vectors/custom/*.jsonl` |
| `spec-package/` | The specification package (read-only, not part of this repository's history; see below) |

`spec-package/` is a copy of [github.com/coreyphillips/bitcoin-consensus-spec](https://github.com/coreyphillips/bitcoin-consensus-spec):
its `spec/` and `conformance/` directories (the chapters, the protocol and corpus documents, the
runner, the vectors and the block corpus) plus the top-level `Cargo.toml`, `Cargo.lock`,
`README.md` and `LICENSE`, without `reference/` (the specification's own implementation, which the
experiment did not use) and without the corpus recorder (`conformance/recorder/`; the
`conformance/oracle-core/` harness is not included either). To rebuild it, clone that repository at
the tag the experiment used, copy those files and directories into `spec-package/`, remove the
excluded ones, and build the runner with `cargo build --release` inside `spec-package/`.

## Building

Requirements: a Rust toolchain (tested with 1.99), a C/C++ compiler and libclang (RocksDB is
compiled from source; on macOS the Command Line Tools provide both, and `.cargo/config.toml` points
bindgen at them).

```sh
cargo build --release
cargo test --release
```

The binaries are in `target/release/`: `bitcoin-spec-node`, `bsn-replay`, `bsn-txgen`.

## Running a node

```sh
target/release/bitcoin-spec-node run --network <main|testnet3|testnet4|signet|regtest> \
    --datadir <dir> [--connect <host:port> ...] [--max-peers <n>] \
    [--stop-at <block hash>] [--utxo-hash-at <h1,h2,...>] [--options '<json>'] \
    [--dbcache <MiB>] [--max-in-flight <n>] [--prune-depth <n>] [--idle-timeout <seconds>]
```

- With `--connect`, the node connects only to those peers (version 1 transport). Without it
  (not on regtest), it finds peers through the network's DNS seeds (specification chapter 14.6)
  and keeps `--max-peers` (default 8) of them, dropping peers that do not serve the whole block
  history with witnesses (`NODE_NETWORK` and `NODE_WITNESS`) and peers that stall the next block.
- It synchronizes headers first, then downloads and validates every block along the best header
  chain (no assume-valid: every script is checked), and keeps following new blocks and
  reorganizations.
- Standard output carries only JSON event lines; everything else goes to standard error:
  - `{"event":"tip","tip":<hash>,"height":<n>}` progress (at most one line per connected block:
    the stop block and `--utxo-hash-at` heights always, other blocks at most once a second, except
    on regtest where every block is reported);
  - `{"event":"utxo_hash","height":H,"hash_serialized_3":<hash>,"txouts":N}` when the tip reaches
    a height listed in `--utxo-hash-at` (the coin cache is flushed, and the database is hashed in
    the background from a pinned view, while the synchronization continues);
  - `{"event":"stopped","tip":<hash>,"height":<n>,"hash_serialized_3":<hash>}` when the tip
    reaches `--stop-at`, after which the node exits with status 0;
  - `{"event":"error","message":...,"tip":...,"height":...}` and a non-zero exit when the
    `--stop-at` block cannot be reached (a peer sends an invalid block, or nothing progresses for
    `--idle-timeout` seconds, default 300).
- `--dbcache` sizes the coin cache (default 12000 MiB on mainnet, 1000 MiB elsewhere). The cache
  table is allocated once and flushed before it would have to grow; the whole process stays
  within roughly 1.3 times this value.
- Block and undo data are kept for the last `--prune-depth` blocks (default 2100, at least 2016).
- `--options` takes the network options of `spec-package/conformance/PROTOCOL.md` section 4.8
  (`{"testactivationheight":{"segwit":120},"test":["bip94"],"signetchallenge":"..."}`; not on
  mainnet).
- The node may be killed at any moment; it restarts from the last flushed state and downloads what
  it is missing. `SIGINT`/`SIGTERM` flush and exit cleanly. `BSN_STATS_SECS=<n>` sets how often
  performance statistics go to standard error (default 10).

A full mainnet synchronization from a local Bitcoin Core node, reporting the fingerprints that
Bitcoin Core publishes (specification chapter 15):

```sh
target/release/bitcoin-spec-node run --network main --datadir /path/to/datadir \
    --connect 127.0.0.1:8333 --utxo-hash-at 840000,880000,910000,935000,965000
```

A testnet4 synchronization from public peers, stopping at the last chapter 15 checkpoint:

```sh
target/release/bitcoin-spec-node run --network testnet4 --datadir /path/to/datadir \
    --utxo-hash-at 90000,120000,150000 \
    --stop-at 0000000000d9877342754dea8ec1eb24631517d38e3443c370465ee53a8b7434
```

## How it works

- **Consensus** (`crates/consensus`): the specification's normative code, chapter by chapter,
  with the production substitutions chapter 02 and Appendix B allow (libsecp256k1 behind the
  Bitcoin wrapping rules, hardware SHA-256) and caches that are invisible by construction
  (transaction ids and merkle roots computed once while decoding, lazily computed signature hash
  midstates).
- **Chain state** (`chain.rs`): chapter 11's algorithm over an arena of block entries with skip
  pointers. Activation connects a path with up to four blocks in progress: block k's scripts are
  verified on all cores while block k+1's transactions are applied to a view that includes block
  k's uncommitted changes; commits happen strictly in order and a failure is acted on only after
  every earlier block committed, so the result is that of connecting one block at a time.
- **UTXO set** (`coins.rs`, `store.rs`): a write-back cache (fixed 88-byte slots, scripts up to 35
  bytes inline) over RocksDB, keyed by txid then index big-endian so that iteration order is the
  chapter 15 fingerprint order. A flush writes the dirty coins of 16 key ranges as SST files in
  parallel and ingests them, with the best-block record, in one atomic `IngestExternalFile` call,
  after the block index and the block and undo files it depends on are durable.
- **Node** (`node.rs`, `net.rs`, `downloads.rs`): one thread owns the chain state and handles
  messages in arrival order; blocks are decoded and checked context-free in parallel, stored as a
  batch and connected by one activation; peer reader threads answer pings and refill block requests
  (16 in flight per peer, `MSG_WITNESS_BLOCK`) as blocks arrive.

Measured on an Apple M5 Pro (6 performance and 12 efficiency cores): a regtest chain of 902 blocks
with 1.96 million transactions synced from Bitcoin Core in 10.5 s (186,000 transactions per
second); public testnet4 heights 0 to 35,703 in 100 s; public mainnet headers plus heights 0 to
76,937 in 170 s. Details in `EXPERIMENT_LOG.md` (M4).

## The conformance harness

```sh
target/release/bitcoin-spec-node harness
```

speaks the JSON-lines protocol of `spec-package/conformance/PROTOCOL.md` on standard input and
output (every operation, including the chain operations, which run the node's own chain-state code
on an in-memory store). With the package's runner:

```sh
cd spec-package
./target/release/bcs-conformance --impl "../target/release/bitcoin-spec-node harness"
./target/release/bcs-conformance interop --impl "../target/release/bitcoin-spec-node harness" \
    --bitcoind ~/bcs-data/bin/bitcoin-32.1/bin/bitcoind --port-range 30000-30999 \
    --node "../target/release/bitcoin-spec-node run --network {network} --datadir {datadir} --connect {peer} --stop-at {stop_at} --options {options}"
```

## Testing against Bitcoin Core

`tools/regtest.py` runs Bitcoin Core v32.1 (`~/bcs-data/bin/bitcoin-32.1/bin`) as a black box on
regtest (ports 30700-30799, data under `test-data/regtest/`) and compares the node's tip and
`hash_serialized_3` with `gettxoutsetinfo`:

```sh
python3 -I tools/regtest.py sync blocks=300 txs=300   # chain built by bsn-txgen, synced from genesis
python3 -I tools/regtest.py reorg                     # follow new blocks, two reorganizations
python3 -I tools/regtest.py restart kills=10          # SIGKILL at random moments during a sync
python3 -I tools/regtest.py storm steps=150           # reorganizations of depth 1 to 8, then a restart
python3 -I tools/regtest.py bench                     # time a sync of a large chain (built once)
python3 -I tools/corrupt_test.py                      # kill, damage the newest block files, restart
python3 -I tools/stall_test.py                        # a second peer that never sends blocks
```
