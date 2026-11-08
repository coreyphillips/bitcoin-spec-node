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
