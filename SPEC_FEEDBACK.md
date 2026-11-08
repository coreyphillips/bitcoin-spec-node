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
Status: open (no corpus file exercises it yet).

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
Status: open (documentation only).

### F5. Chapter 11: candidate set after a tip moves, and the old tip after a failed reorganization

The reference keeps the old tip in `candidates` during a reorganization (nothing removes it when it
is disconnected, and `prune_candidates` only removes entries worse than the *new* tip), which is
what lets "the node return to its previous chain" (11.7, Appendix A item 69) after a failed
connection. The prose of 11.7 does not say this; it is only visible in the code. Implementations
that rebuild candidates differently (for example "only blocks with more work than the tip") would
not return to the old chain. Assumed and implemented exactly as the code does; the corpus
(`feature_block`, `p2p_invalid_block`) passes with it.
Status: confirmed by the corpus replay (level 0 and level 1 all pass).
