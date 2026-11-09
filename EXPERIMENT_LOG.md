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

### After errata 1 (2026-11-08)

The experiment owner applied three independent reviews to the specification and synced a new
package: chapter 11 (activation failures reported, best-header recalculation, minimum chain work),
chapter 14 (rewritten after a live audit: framing, handshake, misbehaviour, `answer_getheaders`,
no `notfound` for blocks, anti-DoS work checks), prose fixes in 01, 04, 05, 07, 10, 12, 15, A, B,
C, PROTOCOL.md (`via`/`requested` are MUST, outcome definitions, `{options}` placeholder, error
exit for the live node), a re-recorded corpus with two new scenarios, and a runner that now
implements `custom`, `corpus`, `headers-live` and `interop`.

First run of the new runner's default suites with the build made before the errata (no code
changed yet), verbatim:

```text
harness: bitcoin-spec-node 0.1.0 (spec v32.1-1), ops: info, script_verify, tx_check, sighash_legacy, sighash_taproot, taproot_commitment_verify, schnorr_verify, chain_reset, chain_process_block, chain_process_headers, chain_invalidate, chain_tip, chain_tips, utxo_hash
mode: derived (all 64 consensus flag combinations)  vectors: conformance/vectors  derived: conformance/vectors/derived

suite          mode         cases    passed   failed   level2  l2-checked  unsupp.     time
script-tests   derived      79168     79168        0        0       79168        0     2.9s
tx-valid       derived      11385     11385        0        0       11264        0     0.4s
tx-invalid     derived       7197      7197        0        0        7113        0     0.2s
sighash        -             1000      1000        0        0           0        0     0.0s
bip341         -               26        26        0        0           7        0     0.0s
bip340         -               19        19        0        0           0        0     0.0s
script-assets  derived     239168    239168        0        0      239168        0    13.4s
custom         -               21        21        0        0          20        0     0.0s
corpus         -             5114      5114        0        0        2138        0     8.7s

corpus file                                   checks  L0 normat.    L0 other   L1 tips   L2 utxo errors     time
feature_bip68_sequence.node0                      31       31/31         0/0     31/31     29/29      0     0.0s
feature_bip68_sequence.node1                      13       13/13         0/0     13/13     13/13      0     0.0s
feature_block.node0                              128     128/128         0/0   104/104     40/40      0     0.1s
feature_block_reorg.node0                        133     133/133         0/0   104/104     43/43      0     6.4s
feature_cltv.node0                                11       11/11         0/0     11/11       5/5      0     0.0s
feature_csv_activation.node0                     139     139/139         0/0     82/82     33/33      0     0.0s
feature_dersig.node0                               6         6/6         0/0       6/6       4/4      0     0.0s
feature_nulldummy.node0                            8         8/8         0/0       8/8       6/6      0     0.0s
feature_segwit.node0                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_segwit.node1                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_segwit.node2                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_spec_pitfalls.node0                       30       30/30         0/0     30/30     17/17      0     0.0s
feature_taproot.node0                           4044   4044/4044         0/0   108/108 1467/1467      0     1.6s
mining_basic.node0                               375     375/375         0/0   375/375   328/328      0     0.2s
mining_basic.node1                                 4         3/3         1/1       4/4       4/4      0     0.0s
p2p_invalid_block.node0                           10       10/10         0/0     10/10       5/5      0     0.0s
p2p_segwit.node0                                 106     106/106         0/0   106/106     67/67      0     0.1s
p2p_segwit.node1                                  41       41/41         0/0     41/41     41/41      0     0.1s
total (18 files, 16769 events)                  5115   5114/5114         1/1 1069/1069 2138/2138
restarts: 33 (0 skipped by the shortcut, 10781 events re-delivered); harness outcomes (diagnostic): block:accepted 10778, block:duplicate 2, block:invalid 69, block:mutated 25, block:temporary 3, headers:accepted 699, headers:invalid 7, invalidate:ok 20

RESULT: PASS
```

Everything already passed. The errata that needed code changes anyway (they change behaviour the
default suites only report as diagnostics, or behaviour of the live node):

- 11.6/11.7: `activate_best_chain` now returns the blocks that failed to connect, and
  `process_block` returns `Rejected` when activation finds that very block invalid (the harness then
  answers `invalid` instead of `accepted`; the diagnostic outcome counts above changed from 69 to
  2,881 `invalid` blocks, almost all from `feature_taproot` and `feature_block_reorg`).
- 11.5: `recalculate_best_header` prefers the active tip among equal-work headers (also used when
  the node restores its chain at startup).
- 11.3/11.6: `minimum_chain_work` (zero unless set) in the unrequested-block rule.
- 14.3: `headers_message_acceptable` gained the low-work rule (`anti_dos_work_threshold`); the
  harness answers a dropped message with `invalid` / `headers-message-rejected` and no index.
- 14.4: `p2p_block_work_acceptable` is applied to `via: p2p` blocks in the harness
  (`too-little-chainwork`) and to every block the node receives.
- 14.3: the node's `answer_getheaders` follows the new rules (empty locator, side-branch and
  unknown hashes skipped, a locator hash descending from the tip, possibly no reply at all).
- 14.4 and PROTOCOL.md section 5: block requests time out after 64 s (Core never sends
  `notfound` for blocks); `run` accepts `--options <json>`, and with `--stop-at` exits non-zero
  with an `{"event":"error",...}` line when a peer sends an invalid block or nothing progresses
  for `--idle-timeout` seconds (default 300).
- 07: `verify_script` asserts that `WITNESS` implies `P2SH`, as the reference now does.

Rerun after those changes, verbatim:

```text
harness: bitcoin-spec-node 0.1.0 (spec v32.1-1), ops: info, script_verify, tx_check, sighash_legacy, sighash_taproot, taproot_commitment_verify, schnorr_verify, chain_reset, chain_process_block, chain_process_headers, chain_invalidate, chain_tip, chain_tips, utxo_hash
mode: derived (all 64 consensus flag combinations)  vectors: conformance/vectors  derived: conformance/vectors/derived

suite          mode         cases    passed   failed   level2  l2-checked  unsupp.     time
script-tests   derived      79168     79168        0        0       79168        0     3.0s
tx-valid       derived      11385     11385        0        0       11264        0     0.5s
tx-invalid     derived       7197      7197        0        0        7113        0     0.3s
sighash        -             1000      1000        0        0           0        0     0.0s
bip341         -               26        26        0        0           7        0     0.0s
bip340         -               19        19        0        0           0        0     0.0s
script-assets  derived     239168    239168        0        0      239168        0    15.9s
custom         -               21        21        0        0          20        0     0.0s
corpus         -             5114      5114        0        0        2138        0     9.6s

corpus file                                   checks  L0 normat.    L0 other   L1 tips   L2 utxo errors     time
feature_bip68_sequence.node0                      31       31/31         0/0     31/31     29/29      0     0.0s
feature_bip68_sequence.node1                      13       13/13         0/0     13/13     13/13      0     0.0s
feature_block.node0                              128     128/128         0/0   104/104     40/40      0     0.1s
feature_block_reorg.node0                        133     133/133         0/0   104/104     43/43      0     6.7s
feature_cltv.node0                                11       11/11         0/0     11/11       5/5      0     0.0s
feature_csv_activation.node0                     139     139/139         0/0     82/82     33/33      0     0.0s
feature_dersig.node0                               6         6/6         0/0       6/6       4/4      0     0.0s
feature_nulldummy.node0                            8         8/8         0/0       8/8       6/6      0     0.0s
feature_segwit.node0                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_segwit.node1                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_segwit.node2                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_spec_pitfalls.node0                       30       30/30         0/0     30/30     17/17      0     0.0s
feature_taproot.node0                           4044   4044/4044         0/0   108/108 1467/1467      0     1.9s
mining_basic.node0                               375     375/375         0/0   375/375   328/328      0     0.5s
mining_basic.node1                                 4         3/3         1/1       4/4       4/4      0     0.0s
p2p_invalid_block.node0                           10       10/10         0/0     10/10       5/5      0     0.0s
p2p_segwit.node0                                 106     106/106         0/0   106/106     67/67      0     0.1s
p2p_segwit.node1                                  41       41/41         0/0     41/41     41/41      0     0.1s
total (18 files, 16769 events)                  5115   5114/5114         1/1 1069/1069 2138/2138
restarts: 33 (0 skipped by the shortcut, 10781 events re-delivered); harness outcomes (diagnostic): block:accepted 7966, block:duplicate 2, block:invalid 2881, block:mutated 25, block:temporary 3, headers:accepted 699, headers:invalid 7, invalidate:ok 20

RESULT: PASS
```

And with `--fail-on-level2` (exit status 0), last lines verbatim:

```text
restarts: 33 (0 skipped by the shortcut, 10781 events re-delivered); harness outcomes (diagnostic): block:accepted 7966, block:duplicate 2, block:invalid 2881, block:mutated 25, block:temporary 3, headers:accepted 699, headers:invalid 7, invalidate:ok 20

RESULT: PASS
```

#### Corpus rerun with `feature_spec_pitfalls` part g

Part g of `feature_spec_pitfalls.node0` (recorded against Core v32.1; it exercises the anti-DoS
work checks of 14.3/14.4: an unsolicited deep-fork block dropped with `too-little-chainwork`,
shallower ones kept header-only, a low-work headers message ignored, the same headers with one
more stored) landed after the runs above. Corpus suite rerun with the post-errata build, verbatim
(`--fail-on-level2` also exits 0):

```text
harness: bitcoin-spec-node 0.1.0 (spec v32.1-1), ops: info, script_verify, tx_check, sighash_legacy, sighash_taproot, taproot_commitment_verify, schnorr_verify, chain_reset, chain_process_block, chain_process_headers, chain_invalidate, chain_tip, chain_tips, utxo_hash

suite          mode         cases    passed   failed   level2  l2-checked  unsupp.     time
corpus         -             5121      5121        0        0        2139        0     9.8s

corpus file                                   checks  L0 normat.    L0 other   L1 tips   L2 utxo errors     time
feature_bip68_sequence.node0                      31       31/31         0/0     31/31     29/29      0     0.0s
feature_bip68_sequence.node1                      13       13/13         0/0     13/13     13/13      0     0.0s
feature_block.node0                              128     128/128         0/0   104/104     40/40      0     0.1s
feature_block_reorg.node0                        133     133/133         0/0   104/104     43/43      0     6.8s
feature_cltv.node0                                11       11/11         0/0     11/11       5/5      0     0.0s
feature_csv_activation.node0                     139     139/139         0/0     82/82     33/33      0     0.0s
feature_dersig.node0                               6         6/6         0/0       6/6       4/4      0     0.0s
feature_nulldummy.node0                            8         8/8         0/0       8/8       6/6      0     0.0s
feature_segwit.node0                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_segwit.node1                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_segwit.node2                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_spec_pitfalls.node0                       37       37/37         0/0     37/37     18/18      0     0.0s
feature_taproot.node0                           4044   4044/4044         0/0   108/108 1467/1467      0     2.0s
mining_basic.node0                               375     375/375         0/0   375/375   328/328      0     0.5s
mining_basic.node1                                 4         3/3         1/1       4/4       4/4      0     0.0s
p2p_invalid_block.node0                           10       10/10         0/0     10/10       5/5      0     0.0s
p2p_segwit.node0                                 106     106/106         0/0   106/106     67/67      0     0.1s
p2p_segwit.node1                                  41       41/41         0/0     41/41     41/41      0     0.1s
total (18 files, 16832 events)                  5122   5121/5121         1/1 1076/1076 2139/2139
restarts: 33 (0 skipped by the shortcut, 10781 events re-delivered); harness outcomes (diagnostic): block:accepted 8018, block:duplicate 2, block:invalid 2882, block:mutated 25, block:temporary 3, headers:accepted 701, headers:invalid 8, invalidate:ok 20

RESULT: PASS
```

For comparison, the same file against the build from before errata 1 (commit `e6e2de7`) passes
level 0 but not level 1, because that build stored headers Core drops; verbatim:

```text
harness: bitcoin-spec-node 0.1.0 (spec v32.1-1), ops: info, script_verify, tx_check, sighash_legacy, sighash_taproot, taproot_commitment_verify, schnorr_verify, chain_reset, chain_process_block, chain_process_headers, chain_invalidate, chain_tip, chain_tips, utxo_hash
LEVEL1   [corpus] feature_spec_pitfalls.node0 check 32 (event 262, line 264, send_blocks_and_test): chain tips differ (9 expected, 10 got); missing [], unexpected [("601ae10ece3e78890a598a6812154ec75e93cf0a389d1706a504623a6e974b66", 55, "headers-only")]
LEVEL1   [corpus] feature_spec_pitfalls.node0 check 33 (event 264, line 266, send_blocks_and_test): chain tips differ (10 expected, 11 got); missing [], unexpected [("601ae10ece3e78890a598a6812154ec75e93cf0a389d1706a504623a6e974b66", 55, "headers-only")]
LEVEL1   [corpus] feature_spec_pitfalls.node0 check 34 (event 266, line 268, send_blocks_and_test): chain tips differ (11 expected, 12 got); missing [], unexpected [("601ae10ece3e78890a598a6812154ec75e93cf0a389d1706a504623a6e974b66", 55, "headers-only")]
LEVEL1   [corpus] feature_spec_pitfalls.node0 check 35 (event 268, line 270, sync_with_ping): chain tips differ (11 expected, 13 got); missing [], unexpected [("4f915cf4e0a55af8028ace7c9a74180816743fbb3883c6d1428d52816038fea1", 55, "headers-only"), ("601ae10ece3e78890a598a6812154ec75e93cf0a389d1706a504623a6e974b66", 55, "headers-only")]
LEVEL1   [corpus] feature_spec_pitfalls.node0 check 36 (event 270, line 272, sync_with_ping): chain tips differ (12 expected, 13 got); missing [], unexpected [("601ae10ece3e78890a598a6812154ec75e93cf0a389d1706a504623a6e974b66", 55, "headers-only")]
LEVEL1   [corpus] feature_spec_pitfalls.node0 check 37 (event 272, line 274, sync_with_ping): chain tips differ (13 expected, 14 got); missing [], unexpected [("601ae10ece3e78890a598a6812154ec75e93cf0a389d1706a504623a6e974b66", 55, "headers-only")]

suite          mode         cases    passed   failed   level2  l2-checked  unsupp.     time
corpus         -               37        37        0        0          18        0     0.0s

corpus file                                   checks  L0 normat.    L0 other   L1 tips   L2 utxo errors     time
feature_spec_pitfalls.node0                       37       37/37         0/0     31/37     18/18      0     0.0s
total (1 files, 273 events)                       37       37/37         0/0     31/37     18/18
restarts: 0 (0 skipped by the shortcut, 0 events re-delivered); harness outcomes (diagnostic): block:accepted 210, block:invalid 5, block:mutated 1, headers:accepted 19
non-normative level 0 checks and level 1 (chain tips) are reported only; they never fail the run

RESULT: PASS
```

So the chapter 14 anti-DoS checks were invisible to the tip (level 0) in this scenario but are
visible in `getchaintips` (level 1).

### M3: the live node on regtest against Bitcoin Core (2026-11-08)

`bitcoin-spec-node run` (crates/node): one thread owns the chain state and handles peer messages
in arrival order; block payloads are decoded in parallel before they reach it; headers first, then
blocks along the best header chain (16 in flight per peer), `MSG_WITNESS_BLOCK` requests, ping
answered by the reader thread. Persistence: RocksDB (coins, block index) plus one file per block and
per undo record; the coin cache is flushed as one sorted SST file ingested atomically together with
the best-block record, after the block index and the block/undo files it depends on are durable.

Own regtest scenarios (`tools/regtest.py`, Bitcoin Core v32.1 as a black box on ports 30700-30799,
chains built by `tools/txgen`, which signs P2PKH, P2WPKH, P2SH-P2WPKH, P2WSH and P2TR spends with
its own keys and submits blocks with `submitblock`):

- `sync`: 513 blocks with about 90,000 transactions, synced from genesis in 0.9 s; tip and
  `hash_serialized_3` match Core's `gettxoutsetinfo`.
- `reorg`: the node follows new blocks, then Core invalidates 6 blocks and builds a longer fork
  (node reorganizes), then a second switch; both final states match Core.
- `restart`: 1,602 blocks with about 225,000 transactions, the node killed with SIGKILL ten times
  (four of them mid-sync, at heights 573, 760, 1,343 and 1,475) with a 4 MiB coin cache (so it
  flushes every few blocks), then restarted with `--stop-at`; tip and hash match.

First run of the package's `interop` suite (bitcoind v32.1 as a black-box peer without noban,
`--port-range 30000-30999`, node command `bitcoin-spec-node run --network {network} --datadir
{datadir} --connect {peer} --stop-at {stop_at} --options {options}`), before any fix,
verbatim:

```text
interop: generate-300 (1 of 19)
interop: feature_bip68_sequence.node0 (2 of 19)
interop: feature_bip68_sequence.node1 (3 of 19)
interop: feature_block.node0 (4 of 19)
interop: feature_block_reorg.node0 (5 of 19)
interop: feature_cltv.node0 (6 of 19)
interop: feature_csv_activation.node0 (7 of 19)
interop: feature_dersig.node0 (8 of 19)
interop: feature_nulldummy.node0 (9 of 19)
interop: feature_segwit.node0 (10 of 19)
interop: feature_segwit.node1 (11 of 19)
interop: feature_segwit.node2 (12 of 19)
interop: feature_spec_pitfalls.node0 (13 of 19)
interop: feature_taproot.node0 (14 of 19)
interop: mining_basic.node0 (15 of 19)
interop: mining_basic.node1 (16 of 19)
interop: p2p_invalid_block.node0 (17 of 19)
interop: p2p_segwit.node0 (18 of 19)
interop: p2p_segwit.node1 (19 of 19)

suite          mode         cases    passed   failed   level2  l2-checked  unsupp.     time
interop        -               18        18        0        0           0        0   385.8s

rows without a check in this mode (stated rules, counted):
  interop: 1 x scenario's final chain has blocks dated more than 2 hours after the current time (a live node uses its real clock)

interop chain                                 height   result     time  detail
generate-300                                     300    match     0.9s  tip 1b0f12349312197e
feature_bip68_sequence.node0                     431    match    25.9s  tip 7cf1dee5a139466e
feature_bip68_sequence.node1                     431    match    25.9s  tip 7cf1dee5a139466e
feature_block.node0                              134    match     8.8s  tip 11b168bdbe7f2738
feature_block_reorg.node0                       1224    match    77.5s  tip 79365b55bdbfa159
feature_cltv.node0                               111    match     7.3s  tip 487ab404b9130a94
feature_csv_activation.node0                     437    match    26.1s  tip 361301b2b2936959
feature_dersig.node0                             102    match     6.8s  tip 423b43404f22f8c2
feature_nulldummy.node0                          105    match     6.8s  tip 455727112aee5098
feature_segwit.node0                             171    match    10.7s  tip 1d06323b25f95532
feature_segwit.node1                             171    match    10.8s  tip 1d06323b25f95532
feature_segwit.node2                             171    match    10.7s  tip 1d06323b25f95532
feature_spec_pitfalls.node0                      200    match    12.6s  tip 56b13b712aebeddf
feature_taproot.node0                           1565    match    91.4s  tip 035363b53e65c94b
mining_basic.node0                                 - excluded           
mining_basic.node1                               367    match    22.3s  tip 00b59fd834cd2e7e
p2p_invalid_block.node0                          103    match     7.0s  tip 6476b5ef577af9e7
p2p_segwit.node0                                 268    match    16.7s  tip 025e52c52008615b
p2p_segwit.node1                                 268    match    16.5s  tip 025e52c52008615b

RESULT: PASS
```

All 18 chains match (tip, height, `hash_serialized_3`) and bitcoind logged no `Misbehaving` line;
`mining_basic.node0` is excluded by the runner's stated rule (blocks dated in the future).

#### Corpus with 20 files (2026-11-08)

`feature_spec_pitfalls.node1` (bip34@2, dersig@300, cltv@300: negative and version-1 blocks
rejected with `bad-version` at height 11, version 0x80000000 valid at height 1) and
`feature_spec_pitfalls.node2` (`-test=bip94`: blocks 601 s and 1,200 s before their parent rejected
with `time-timewarp-attack` at a period start, exactly 600 s accepted) were added, and node0 was
re-recorded. Corpus suite, first run on them (build with batched activation and pipelined script
checks, see M4), verbatim:

```text
harness: bitcoin-spec-node 0.1.0 (spec v32.1-1), ops: info, script_verify, tx_check, sighash_legacy, sighash_taproot, taproot_commitment_verify, schnorr_verify, chain_reset, chain_process_block, chain_process_headers, chain_invalidate, chain_tip, chain_tips, utxo_hash

suite          mode         cases    passed   failed   level2  l2-checked  unsupp.     time
corpus         -             5275      5275        0        0        2288        0    11.4s

corpus file                                   checks  L0 normat.    L0 other   L1 tips   L2 utxo errors     time
feature_bip68_sequence.node0                      31       31/31         0/0     31/31     29/29      0     0.0s
feature_bip68_sequence.node1                      13       13/13         0/0     13/13     13/13      0     0.0s
feature_block.node0                              128     128/128         0/0   104/104     40/40      0     0.2s
feature_block_reorg.node0                        133     133/133         0/0   104/104     43/43      0     8.0s
feature_cltv.node0                                11       11/11         0/0     11/11       5/5      0     0.0s
feature_csv_activation.node0                     139     139/139         0/0     82/82     33/33      0     0.1s
feature_dersig.node0                               6         6/6         0/0       6/6       4/4      0     0.0s
feature_nulldummy.node0                            8         8/8         0/0       8/8       6/6      0     0.0s
feature_segwit.node0                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_segwit.node1                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_segwit.node2                              12       12/12         0/0     12/12     12/12      0     0.0s
feature_spec_pitfalls.node0                       37       37/37         0/0     37/37     18/18      0     0.0s
feature_spec_pitfalls.node1                        7         7/7         0/0       7/7       4/4      0     0.0s
feature_spec_pitfalls.node2                      147     147/147         0/0   147/147   145/145      0     0.0s
feature_taproot.node0                           4044   4044/4044         0/0   108/108 1467/1467      0     2.1s
mining_basic.node0                               375     375/375         0/0   375/375   328/328      0     0.5s
mining_basic.node1                                 4         3/3         1/1       4/4       4/4      0     0.0s
p2p_invalid_block.node0                           10       10/10         0/0     10/10       5/5      0     0.0s
p2p_segwit.node0                                 106     106/106         0/0   106/106     67/67      0     0.2s
p2p_segwit.node1                                  41       41/41         0/0     41/41     41/41      0     0.1s
total (20 files, 17150 events)                  5276   5275/5275         1/1 1230/1230 2288/2288
restarts: 33 (0 skipped by the shortcut, 10781 events re-delivered); harness outcomes (diagnostic): block:accepted 8173, block:duplicate 2, block:invalid 2887, block:mutated 25, block:temporary 3, headers:accepted 703, headers:invalid 8, invalidate:ok 20

RESULT: PASS
```

### Live header chains (2026-11-08)

`bcs-conformance headers-live` against public peers (the runner downloads the header chain itself
and feeds it to the harness): testnet4 from `seed.testnet4.bitcoin.sprovoost.nl`, 159,961 headers
in 80 messages, all accepted (minimum-difficulty blocks, BIP94); mainnet from
`seed.bitcoin.sprovoost.nl`, verbatim:

```text
harness: bitcoin-spec-node 0.1.0 (spec v32.1-1), ops: info, script_verify, tx_check, sighash_legacy, sighash_taproot, taproot_commitment_verify, schnorr_verify, chain_reset, chain_process_block, chain_process_headers, chain_invalidate, chain_tip, chain_tips, utxo_hash
headers-live: connected to 162.245.185.13:8333 (/Satoshi:29.0.0/, protocol 70016, start height 975114)
headers-live: 162.245.185.13:8333: Connection reset by peer (os error 54); reconnecting
headers-live: connected to 103.228.171.171:8333 (/Satoshi:27.0.0/, protocol 70016, start height 975114)
headers-live: height 100000 after 50 messages, 13 s
headers-live: height 200000 after 100 messages, 26 s
headers-live: height 300000 after 150 messages, 39 s
headers-live: height 400000 after 200 messages, 47 s
headers-live: height 500000 after 250 messages, 56 s
headers-live: height 600000 after 300 messages, 63 s
headers-live: height 700000 after 350 messages, 69 s
headers-live: height 800000 after 400 messages, 77 s
headers-live: height 900000 after 450 messages, 90 s

suite          mode         cases    passed   failed   level2  l2-checked  unsupp.     time
headers-live   -              490       490        0        0           0        0    95.2s

headers-live: network main, peer 103.228.171.171:8333 (/Satoshi:27.0.0/, protocol 70016, start height 975114)
headers-live: 975114 headers in 488 messages, last header 00000000000000000000d64b1a1927a736eecf5524496bfc60eadd2d1ba2464e at height 975114, chainwork 000000000000000000000000000000000000000156dae733b668a04d89e38b8b, 95 s

RESULT: PASS
```

### Public network (2026-11-08)

Peer discovery from the chapter 14.6 DNS seeds when no `--connect` is given (8 peers; peers that do
not advertise `NODE_NETWORK` and `NODE_WITNESS` are dropped), block requests only to peers known to
have the block, Core-style stall handling (a peer holding up the next block for 2 s, doubling to
64 s, is replaced). A short testnet4 run from public peers (not a full sync; the full testnet4 and
mainnet syncs are the experiment owner's holdout runs): headers to 159,961 in seconds, blocks
validated to height 35,703 in 100 s with 8 peers, no block rejected; then a restart (resumed from
the flushed state at 35,829), a SIGKILL at 47,219 and another restart, which resumed from 35,829
again (the last flush), as designed.

#### Interop with 20 corpus files (2026-11-08)

Interop rerun with the 20-file corpus and the build of commit `7ddd347` (batched activation,
pipelined script checks, download refills from reader threads, DNS-seed discovery), verbatim
(progress lines omitted):

```text

suite          mode         cases    passed   failed   level2  l2-checked  unsupp.     time
interop        -               20        20        0        0           0        0   399.4s

rows without a check in this mode (stated rules, counted):
  interop: 1 x scenario's final chain has blocks dated more than 2 hours after the current time (a live node uses its real clock)

interop chain                                 height   result     time  detail
generate-300                                     300    match     0.9s  tip 7f6d7ac889e85289
feature_bip68_sequence.node0                     431    match    25.8s  tip 7cf1dee5a139466e
feature_bip68_sequence.node1                     431    match    25.3s  tip 7cf1dee5a139466e
feature_block.node0                              134    match     8.9s  tip 11b168bdbe7f2738
feature_block_reorg.node0                       1224    match    81.2s  tip 79365b55bdbfa159
feature_cltv.node0                               111    match     7.2s  tip 487ab404b9130a94
feature_csv_activation.node0                     437    match    26.0s  tip 361301b2b2936959
feature_dersig.node0                             102    match     6.7s  tip 423b43404f22f8c2
feature_nulldummy.node0                          105    match     7.0s  tip 455727112aee5098
feature_segwit.node0                             171    match    10.8s  tip 1d06323b25f95532
feature_segwit.node1                             171    match    10.7s  tip 1d06323b25f95532
feature_segwit.node2                             171    match    10.8s  tip 1d06323b25f95532
feature_spec_pitfalls.node0                      200    match    12.4s  tip 0d5e6e814ffe90bc
feature_spec_pitfalls.node1                       11    match     1.5s  tip 00618f4c750252cd
feature_spec_pitfalls.node2                      144    match     9.0s  tip 46202bbab91a3e22
feature_taproot.node0                           1565    match    92.0s  tip 035363b53e65c94b
mining_basic.node0                                 - excluded           
mining_basic.node1                               367    match    22.1s  tip 00b59fd834cd2e7e
p2p_invalid_block.node0                          103    match     6.8s  tip 6476b5ef577af9e7
p2p_segwit.node0                                 268    match    16.6s  tip 025e52c52008615b
p2p_segwit.node1                                 268    match    16.4s  tip 025e52c52008615b

RESULT: PASS
```


### More live checks (2026-11-08)

- `headers-live` on testnet3 (runner suite, public peer found through a DNS seed; the first peer
  closed the connection and the runner reconnected to another), verbatim summary:

  ```text
  suite          mode         cases    passed   failed   level2  l2-checked  unsupp.     time
  headers-live   -             2654      2654        0        0           0        0   272.6s

  headers-live: network testnet3, peer 44.238.21.47:18333 (/btcwire:0.5.0/btcd:0.27.0/, protocol 70016, start height 5303811)
  headers-live: 5303811 headers in 2652 messages, last header 0000000000c9ba9e2ea180982b2cb788947ebff0c705591cbb189bb754a168a5 at height 5303811, chainwork 00000000000000000000000000000000000000000000180efd396d2e6e92a0e5, 273 s

  RESULT: PASS
  ```

- Reorganization storm against Bitcoin Core (`tools/regtest.py storm`): Core builds a chain with
  wallet and `bsn-txgen` activity, then repeatedly invalidates a recent block (depth 1 to 8), adds
  wallet transactions and mines a longer branch, sometimes reconsidering an old branch; the node
  must be at Core's tip after every step, and after a restart its UTXO set must match
  `gettxoutsetinfo`. 25 steps (seed 13): match. 150 steps (seed 7; 105 reorganizations: depth 1 x
  11, 2 x 24, 3 x 11, 4 x 15, 5 x 14, 6 x 11, 7 x 11, 8 x 8; 45 reconsiders): match at height 581.
  The first attempt failed in the test itself: Core refused a mined block identical to the one it
  had just invalidated (same coinbase script, same transactions), so each step now mines to a
  coinbase script of its own.
- Damaged block files after a kill (`tools/corrupt_test.py`): see bug 3 below; match after the fix.

### M4: performance and memory (2026-11-08)

Measurements on the Apple M5 Pro (6 performance + 12 efficiency cores, 64 GB), all with the
conformance suites and the kill/restart scenario passing after each change. Numbers marked
"idle" were taken before the experiment owner's holdout runs started; later ones ran next to them
(load average 25 to 38) and are slower.

| What | Result |
|---|---|
| libsecp256k1 through the chapter 02 wrappers (`bsn-txgen --bench-sigs`) | 20 us per ECDSA or Schnorr verification on one core; 621,000 per second on 18 threads |
| Bitcoin Core v32.1 serving its blocks over P2P, 16 in flight (`bsn-txgen --bench-download`) | 2,152 blocks/s, 1.8 GB/s on regtest (not a bottleneck) |
| Regtest chain of 902 blocks, 1.96 million transactions (about 4 million inputs) built by `bsn-txgen`, synced from Core (`regtest.py bench`), first node version | 13.8 s, 65 blocks/s, 141,000 tx/s; 6.6 cores busy on average (idle) |
| same, after batched activation (one activation per message batch, pipelined script checks) and download refills from the reader threads | 10.5 s, 86 blocks/s, 187,000 tx/s (idle) |
| same, under the holdout load | 18 to 31 s |
| Coin flush (`bitcoin-spec-node bench-flush`): 20 million new coins, then 10 million deletions, into RocksDB as parallel SST files ingested atomically | 2.0 s and 0.9 s; fingerprint of 10 million coins 4.4 s (under load) |
| Public testnet4, 8 DNS-seed peers | heights 0 to 35,703 in 100 s (about 360 blocks/s) |
| Public mainnet, DNS-seed peers (short test only) | first try: heights 0 to 31,810 in about 6 minutes; header download from public peers that were also serving our block requests was the limit (576,000 headers after 5.5 minutes) |
| same, after making the node request blocks from a peer only once that peer's headers are synchronized (headers first) | all 975,116 headers, then heights 0 to 76,937, in 170 s; about 1,050 blocks/s on the early chain (under load) |
| Coin prefetch (`bench-flush`, 10 million coins read back from RocksDB on a 16-thread read pool): one `get` per coin against batched `MultiGet` in chunks of 256 sorted keys, alternating runs | single gets 8.3, 4.7, 9.5, 8.2 s; `MultiGet` 5.8, 5.9, 4.4, 3.4 s (kept) |
| Peak memory, regtest benchmark (`--dbcache 1000`) | 1.9 GB resident |

What the profile (`sample`) showed and what changed because of it:

1. With one activation per received block (the reference's order), every activation saw one block,
   so the script pipeline never filled, and downloads paused while blocks were connected; only 6.6
   of 18 cores were busy. The node now stores all blocks of a message batch and activates once
   (the chain selected is the same; see the design note below), connects the path with up to four
   blocks in progress (block k's scripts verify while block k+1's transactions are applied to a
   view that includes block k's uncommitted changes; commits are strictly in order and a failure is
   acted on only after every earlier block committed), and the peer reader threads refill block
   requests as blocks arrive.
2. The chain thread then became the limit (on regtest mostly the BIP30 lookups that regtest
   enforces for every output). Context-free block checks and merkle roots moved into the parallel
   decode step, the spent outputs for script checks are built inside the parallel script job, and
   per-transaction legacy sigop counts are computed once.
3. Small blocks (fewer than 8 inputs) are now checked inline: handing them to the thread pool cost
   about 80 us each, which dominated the early mainnet chain.
4. The coin cache is a hash table sized once from `--dbcache` (88-byte slots with scripts up to 35
   bytes inline, longer scripts in a side table), flushed and emptied before it would have to grow,
   so it never reallocates (a resize of a 12 GB table would need 24 GB at once). The flush splits
   the dirty entries into 16 key ranges that are sorted and written to separate SST files in
   parallel and ingested with one atomic `IngestExternalFile` call.

Design note on batched activation: chapter 11 requires that the selected chain equals the
reference's after every block processed. Storing a batch of blocks and activating once selects the
same chain (candidates are kept and compared exactly as in the reference); it can differ only in
what is remembered about descendants of a block that fails to connect within the same batch (they
are stored and then marked invalid, instead of being refused as children of an invalid block), and
in which unrequested blocks are reduced to headers, neither of which changes the active chain. The
harness keeps the reference's order (one activation per block), so the corpus checks the exact
semantics.

Estimate for mainnet from the local Core node (single peer, `--dbcache 12000`): late blocks are
bounded by script verification (about 7,000 inputs per block at 22 us of CPU each, 9 ms per block
on 17 threads) and by the chain thread's serial UTXO work (about 10 ms per block), so 60 to 100
blocks per second; 12 GB coin cache (117 million coins) flushed in about 10 to 15 s each time it
fills. Total memory stays around 14 GB.

## Bugs found

Every bug found so far, with its root cause and whether the specification was at fault. (The
first runs of every conformance suite passed, so these are all bugs of the node around the
consensus code, found by my own tests.)

1. **`find_and_delete` rewrite lost bytes before the first match** (M1, found before the first
   conformance run by the randomized differential test against the reference function). My
   borrowing version copied only from the current operation instead of the start of the script
   when the first match was found. Not a specification problem.
2. **Restart could stall forever** (M4, found by the SIGKILL scenario of `tools/regtest.py` after
   the switch to batched activation). After a restart, blocks that had been stored on disk above
   the last flushed tip were linked and were candidates, but chain activation only ran when a new
   block arrived; when every remaining block up to the stop block was already stored, nothing
   arrived and the node waited until `--idle-timeout`. Fixed by activating once at startup (as
   Core's startup `ActivateBestChain` does). Not a specification problem; the spec's 11.12 says a
   production node must behave as if every block went through `process_block`, which activates.
   The build of commit `7ddd347` (used for the testnet4 holdout run) has this bug; it can only
   show after a restart.
3. **Unreadable stored blocks stalled the node or would have crashed it** (M4, found by a
   fault-injection test, `tools/corrupt_test.py`: kill a syncing node, truncate its 40 newest
   block files as a system crash could, restart). The first version panicked when a candidate's
   data could not be read; the second marked only that block as "not received", but its stored
   descendants were linked already and had left the candidate set, so they were neither connected
   nor downloaded again, and the node stalled. Fixed by forgetting the data of the block and of all
   its stored descendants (unlinked, removed from candidates), so they are downloaded again and
   linked anew when they arrive; the wanted list is also refreshed every 5 s. Not a specification
   problem: the reference never loses data it stored.
