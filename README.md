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

## Layout

| Path | Contents |
|---|---|
| `crates/consensus` | The consensus library: one module per specification chapter (02 to 15), the chain state of chapter 11 (generic over storage), the UTXO cache and the chapter 15 fingerprint |
| `crates/node` | The `bitcoin-spec-node` binary: `harness` (conformance protocol) and `run` (the node: RocksDB, block files, peer-to-peer) |
| `tools/replay` | `bsn-replay`, an independent replayer for the block corpus (`spec-package/conformance/CORPUS.md`) |
| `tools/txgen` | `bsn-txgen`, builds regtest blocks full of signed transactions and submits them to Bitcoin Core |
| `tools/regtest.py` | Regtest interoperability scenarios against Bitcoin Core (sync, follow, reorganize, kill and restart) |
| `tools/check_custom.py` | Checks a harness against `spec-package/conformance/vectors/custom/*.jsonl` |
| `spec-package/` | The specification package (provided separately, read-only, not part of this repository) |

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
    --datadir <dir> --connect <host:port> [--connect <host:port> ...] \
    [--stop-at <block hash>] [--utxo-hash-at <h1,h2,...>] [--options '<json>'] \
    [--dbcache <MiB>] [--max-in-flight <n>] [--prune-depth <n>] [--idle-timeout <seconds>]
```

- The node connects only to the `--connect` peers (version 1 transport), synchronizes headers,
  then downloads and validates blocks along the best header chain, and keeps following new blocks
  and reorganizations.
- Standard output carries only JSON event lines; everything else goes to standard error:
  - `{"event":"tip","tip":<hash>,"height":<n>}` progress (at most once a second, except on
    regtest where every block is reported);
  - `{"event":"utxo_hash","height":H,"hash_serialized_3":<hash>,"txouts":N}` when the tip reaches
    a height listed in `--utxo-hash-at` (computed in the background from a consistent snapshot);
  - `{"event":"stopped","tip":<hash>,"height":<n>,"hash_serialized_3":<hash>}` when the tip
    reaches `--stop-at`, after which the node exits with status 0;
  - `{"event":"error","message":...,"tip":...,"height":...}` and a non-zero exit when the
    `--stop-at` block cannot be reached (a peer sends an invalid block, or nothing progresses for
    `--idle-timeout` seconds, default 300).
- `--dbcache` sizes the coin cache (default 12000 MiB on mainnet, 1000 MiB elsewhere). The cache
  table is allocated once and flushed (atomically, as one ingested RocksDB file) before it would
  have to grow; the whole process stays within roughly 1.3 times this value.
- Block and undo data are kept for the last `--prune-depth` blocks (default 2100, at least 2016).
- `--options` takes the network options of `spec-package/conformance/PROTOCOL.md` section 4.8
  (`{"testactivationheight":{"segwit":120},"test":["bip94"],"signetchallenge":"..."}`; not on
  mainnet).
- The node may be killed at any moment; it restarts from the last flushed state and downloads what
  it is missing. `SIGINT`/`SIGTERM` flush and exit cleanly.

A full mainnet synchronization from a local Bitcoin Core node, reporting the fingerprints that
Bitcoin Core publishes (specification chapter 15):

```sh
target/release/bitcoin-spec-node run --network main --datadir /path/to/datadir \
    --connect 127.0.0.1:8333 --utxo-hash-at 840000,880000,910000,935000,965000
```

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
```
