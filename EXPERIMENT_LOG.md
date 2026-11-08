# Experiment log: bitcoin-spec-node

A Bitcoin full node written in Rust from the specification package in `spec-package/`
(specification version `v32.1-1`, pinned to Bitcoin Core v32.1). This log records the timeline,
the first-run conformance results of each milestone (verbatim), and every bug found, with its
root cause and whether the specification was at fault.

## Timeline

### M0: reading (2026-11-08)

Read, in order: `spec/00` to `spec/15`, appendices A, B and C, then `conformance/PROTOCOL.md`,
`conformance/README.md` and `conformance/CORPUS.md`. Also listed the runner's suites
(`bcs-conformance suites`): `script-tests`, `tx-valid`, `tx-invalid`, `sighash`, `bip341`,
`bip340`, `script-assets` are implemented; `corpus`, `headers-live` and `interop` report
"not implemented yet" in the runner build that was provided. `conformance/vectors/blocks/` is
empty (the block corpus is still being recorded).

Plan taken from the reading:

- Consensus library (`crates/consensus`): a module per chapter, translating the normative Rust
  blocks, with libsecp256k1 (the `secp256k1` crate) behind the wrapping rules of 2.8 to 2.11 and
  hardware SHA-256 (`sha2` with the `asm` feature) instead of the reference's own primitives.
- Chain state (chapter 11) written once, generic over a storage backend, so that the harness
  (in-memory backend) and the node (RocksDB plus block files) run the same code.
- Node (`crates/node`, binary `bitcoin-spec-node`): `harness` (PROTOCOL.md) and `run`.

### M1: consensus library and harness (2026-11-08)

Wrote `crates/consensus` chapter by chapter from the normative code (chapters 01 to 15), keeping
the reference's function names and order of checks, with these production substitutions:

- hashes from `sha2` (hardware SHA-256), `ripemd`, `sha1`; tagged hashes start from a cached
  midstate;
- signatures through libsecp256k1 (`secp256k1` crate 0.31): `parse_pubkey` checks the first byte
  and exact length before `secp256k1_ec_pubkey_parse`; the lax DER parser is the reference's code
  in Rust (no strict DER parser anywhere); S is normalized before `secp256k1_ecdsa_verify`;
  `taproot_tweak_check` uses `secp256k1_xonly_pubkey_tweak_add_check`;
- txid, wtxid and sizes are computed while decoding, from the received byte slices (identical to
  re-serializing, because a decoded transaction re-serializes to the bytes it came from);
- BIP143/BIP341 per-transaction hashes are computed lazily (`OnceLock`), `FindAndDelete` returns
  the script borrowed when nothing matches (checked against the reference function by a
  200,000-case randomized differential test).

`bitcoin-spec-node harness` implements every PROTOCOL.md operation (the chain operations already
use the shared chain-state code, see M2).

First run of the conformance suite, before any fix (`bcs-conformance --impl
"target/release/bitcoin-spec-node harness"`, derived mode), verbatim:

```text
harness: bitcoin-spec-node 0.1.0 (spec v32.1-1), ops: info, script_verify, tx_check, sighash_legacy, sighash_taproot, taproot_commitment_verify, schnorr_verify, chain_reset, chain_process_block, chain_process_headers, chain_invalidate, chain_tip, chain_tips, utxo_hash
mode: derived (all 64 consensus flag combinations)  vectors: conformance/vectors  derived: conformance/vectors/derived

suite          mode         cases    passed   failed   level2  l2-checked  unsupp.     time
script-tests   derived      79168     79168        0        0       79168        0     1.9s
tx-valid       derived      11385     11385        0        0       11264        0     0.6s
tx-invalid     derived       7197      7197        0        0        7113        0     0.4s
sighash        -             1000      1000        0        0           0        0     0.0s
bip341         -               26        26        0        0           7        0     0.0s
bip340         -               19        19        0        0           0        0     0.0s
script-assets  derived     239168    239168        0        0      239168        0    26.4s

RESULT: PASS
```

Every suite passed at level 1 and at level 2 (identical error identifiers) on the first run. The
raw mode (`--raw`) also passes (log in `test-data/logs/m1-raw-run.txt`, not committed).

Custom edge cases (`conformance/vectors/custom/edge-cases.jsonl`, added to the package during M1;
the runner's `custom` suite was not built yet, so they were checked with
`tools/check_custom.py`), first run, verbatim:

```text
ok     p2sh-p2wsh canonical push
ok     p2sh-p2wsh extra leading push
ok     p2sh-p2wsh pushdata1 encoding
ok     p2sh-p2wsh pushdata2 encoding
ok     p2sh-p2wsh trailing OP_NOP after push
ok     p2sh-p2wsh without WITNESS flag
ok     native p2wsh with scriptSig OP_0
ok     native p2wsh empty scriptSig
ok     p2sh-wrapped v1 32-byte program with junk witness
ok     native v1 33-byte program with junk witness
ok     pay-to-anchor with witness item
ok     v0 program of 21 bytes
ok     v0 all-zero 32-byte program
ok     canonical transaction
ok     ten-byte empty transaction
ok     non-canonical input count (fd 01 00)
ok     non-canonical script length (fd 01 00)
ok     witness flag with only empty witnesses
ok     unknown flag 0x02
ok     trailing byte
ok     output count above MAX_SIZE
custom: 21 cases, 21 passed level 1, 0 failed, 0 level 2 mismatches
```

### M2: chain state and the block corpus (2026-11-08)

Chapter 11 is implemented once (`crates/consensus/src/chain.rs`) as `ChainState<S: ChainStore>`:
the reference algorithm with the block tree in an arena (skip pointers for O(log n) ancestor
lookup), block and undo data behind a `ChainStore` trait, the UTXO set as a write-back cache
(`coins.rs`) over a backend (`MemoryCoinDb` for the harness, RocksDB for the node), per-block
changes kept in an overlay until the block is valid (the reference's `UtxoView`), and script checks
run in parallel with the failure of the first failing input (in block order) reported.

The block corpus (`conformance/vectors/blocks/`, 16 files) arrived during M1. The runner's
`corpus` suite was not built yet, so it was replayed with `tools/replay` (`bsn-replay`), a small
independent replayer that maps events to PROTOCOL.md requests exactly as CORPUS.md section 4 says
(with the restart shortcut; also run with `--no-shortcut`, same result). First run, verbatim:

```text
scenario                              events blocks    level0 failed  non-norm      level1      level2  errors    time
feature_bip68_sequence.node0             481    446     31/31      0       0/0       31/31       29/29       0    0.1s
feature_bip68_sequence.node1             460    445     13/13      0       0/0       13/13       13/13       0    0.0s
feature_block.node0                      478    229   128/128      0       0/0     104/104       40/40       0    0.1s
feature_cltv.node0                       130    117     11/11      0       0/0       11/11         5/5       0    0.0s
feature_csv_activation.node0             832    555   139/139      0       0/0       82/82       33/33       0    0.0s
feature_dersig.node0                     112    104       6/6      0       0/0         6/6         4/4       0    0.0s
feature_nulldummy.node0                  117    107       8/8      0       0/0         8/8         6/6       0    0.0s
feature_segwit.node0                     185    171     12/12      0       0/0       12/12       12/12       0    0.0s
feature_segwit.node1                     185    171     12/12      0       0/0       12/12       12/12       0    0.0s
feature_segwit.node2                     185    171     12/12      0       0/0       12/12       12/12       0    0.0s
feature_taproot.node0                   8188   4142 4044/4044      0       0/0     108/108   1467/1467       0    1.2s
mining_basic.node0                      1008    582   375/375      0       0/0     375/375     328/328       0    0.0s
mining_basic.node1                       506    336       3/3      0       1/1         4/4         4/4       0    0.0s
p2p_invalid_block.node0                  127    108     10/10      0       0/0       10/10         5/5       0    0.0s
p2p_segwit.node0                         421    307   106/106      0       0/0     106/106       67/67       0    0.3s
p2p_segwit.node1                         328    284     41/41      0       0/0       41/41       41/41       0    0.1s
TOTAL level 0: 4951/4951 normative checks pass; level 1: 935/935; level 2: 2078/2078
RESULT: PASS (level 0)
```

All 4,951 normative checks pass (level 0), and so do every chain tips check (level 1, 935) and
every UTXO set hash (level 2, 2,078), on the first run.
