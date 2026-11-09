# Specification feedback

Every place where the specification (`spec-package/`, version `v32.1-1`) was unclear, incomplete
or wrong while building `bitcoin-spec-node`. Each entry gives the chapter and section, what was
unclear, what was assumed, and how a test confirmed or refuted the assumption. Entries are added
as they are found; the status line of each entry is updated when a test settles it.

## Noted while reading (M0)

### F1. PROTOCOL.md 4.9 / spec 03 section 3.4: result for an undecodable block

Spec 3.4 says a block that cannot be decoded is "handled like a `Mutated` failure", and
PROTOCOL.md 4.9 lists `mutated` with an optional `reason`, but no reason identifier is given for a
decode failure (Bitcoin Core's `submitblock` says "Block decode failed"; over P2P the message is
just dropped). Assumed: `{"result":"mutated","reason":"block-decode"}`.
Status: settled by errata 1: PROTOCOL.md 4.9 now says undecodable bytes give `mutated` with an
implementation-defined reason.

### F2. PROTOCOL.md 4.10: result when a whole `headers` message is dropped

Spec 14.3 `headers_message_acceptable` and CORPUS.md section 5 rule 4 say Core processes nothing
when a header fails proof of work, the headers are not continuous, or the first parent is unknown.
PROTOCOL.md 4.10 does not say which `result`/`reason`/`index` to report then. Assumed: unknown first
parent gives `orphan` with index 0; a proof-of-work failure gives `invalid`/`high-hash` with the
index of the first failing header; a discontinuity gives `invalid`/`bad-headers-noncontinuous`
with the index of the first header that does not connect. These are diagnostics only.
Update (package update during M1): PROTOCOL.md 4.10 now documents `via` on
`chain_process_headers` and says the whole message is dropped unless it passes
`headers_message_acceptable`, but still not which `result` to report for a dropped message. The
assumption above is kept; the corpus replay does not depend on it (per-event results are
diagnostics). Status: open (diagnostic only).

### F3. PROTOCOL.md 4.9: `duplicate` versus a previously rejected block

PROTOCOL.md defines `duplicate` as "the block's full data was already known before this request
(whether valid or invalid)", but in the reference `process_block` a block whose header was marked
invalid by an earlier contextual failure is rejected by `accept_header` with `duplicate-invalid`
(its data was never stored). Assumed: report what the reference returns (`invalid`,
`duplicate-invalid`), since per-block results are diagnostics.
Status: settled by the package update during M1: PROTOCOL.md 4.9 now names `duplicate-invalid` as
the reason for a block already known to be invalid, which is what the harness reports.

## Found while implementing M1 and M2

### F4. CORPUS.md section 7 contradicts the updated PROTOCOL.md 4.10

CORPUS.md section 7 still says "`PROTOCOL.md` 4.10 `chain_process_headers` does not list a `via`
field", while the updated PROTOCOL.md 4.10 does list it (with the message-level checks for `p2p`).
Harmless (the harness reads `via` either way), but one of the two documents is stale.
Status: fixed by errata 1 (the stale note is gone).

### F5. Chapter 11: candidate set after a tip moves, and the old tip after a failed reorganization

The reference keeps the old tip in `candidates` during a reorganization (nothing removes it when it
is disconnected, and `prune_candidates` only removes entries worse than the *new* tip), which is
what lets "the node return to its previous chain" (11.7, Appendix A item 69) after a failed
connection. The prose of 11.7 does not say this; it is only visible in the code. Implementations
that rebuild candidates differently (for example "only blocks with more work than the tip") would
not return to the old chain. Assumed and implemented exactly as the code does; the corpus
(`feature_block`, `p2p_invalid_block`) passes with it.
Status: confirmed by the corpus replay (level 0 and level 1 all pass); errata 1 added this
explanation to the prose of 11.7.

## Found after errata 1

### F6. Chapter 11/12/14: per-network minimum chain work values are not given

`ChainState.minimum_chain_work` (11.3) and `anti_dos_work_threshold` (14.4) use Bitcoin Core's
`nMinimumChainWork`, but chapter 12 lists no value for any network; the reference starts at zero
("the regtest default"). For a live node on mainnet the value only matters for unrequested blocks
and for low-work header chains from untrusted peers. Assumed: zero on every network (the node
connects only to peers it is told to use). A node that wants Core's behaviour against hostile
peers would need the values. Status: open (no test depends on it).

### F7. Chapter 14 section 14.4 / PROTOCOL.md 4.9: reason for a block dropped by the work check

14.4 says Core reports `too-little-chainwork` "only after the context-free block checks and the
header checks have passed", while PROTOCOL.md 4.9 just lists `invalid` / `too-little-chainwork`.
The reference API has no side-effect-free way to run the contextual header checks for a block that
must not be stored. Assumed: the harness reports the `check_block` failure if there is one, else
`too-little-chainwork`. Diagnostic only. Status: open.

### F8. Chapter 11 section 11.12: activation after loading persisted state (suggestion)

The restart bug of `EXPERIMENT_LOG.md` (bug 2) was mine, not the specification's: 11.12 says a
production node must behave as if every block went through `process_block`, which always ends with
chain activation, and CORPUS.md 2.6 says "the active chain is selected again at startup". But the
reference keeps everything in memory, so nothing in its code shows the restart path, and a node
that restructures activation (here: one activation per batch of received blocks) can miss that
blocks persisted above the last flushed tip need an activation of their own. A one-line note in
11.12 ("after loading persisted state, run `activate_best_chain` before waiting for new data; Core:
`ActivateBestChain` at the end of `LoadChainTip`/init") would have prevented it.
Status: suggestion only; not a defect.
