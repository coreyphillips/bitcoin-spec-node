//! Chapter 10: block rules (subsidy, merkle trees, witness commitment, header and body checks,
//! script flags, BIP30). Connecting a block to the UTXO set lives in `chain.rs`, next to the
//! coin cache it works on.

use crate::hashes::sha256d;
use crate::interpreter::*;
use crate::params::ConsensusParams;
use crate::pow::*;
use crate::script::{push_int, OP_RETURN};
use crate::signet::check_signet_block_solution;
use crate::tx::{BlockData, BlockHeader, WITNESS_SCALE_FACTOR};
use crate::tx_rules::*;
use crate::util::*;

/// Core: `GetBlockSubsidy`.
pub fn block_subsidy(height: i32, params: &ConsensusParams) -> i64 {
    let halvings = height / params.subsidy_halving_interval;
    if halvings >= 64 {
        return 0;
    }
    (50 * COIN) >> halvings
}

/// Returns (root, mutated). Core: `ComputeMerkleRoot`.
pub fn compute_merkle_root(mut hashes: Vec<Hash256>) -> (Hash256, bool) {
    let mut mutated = false;
    while hashes.len() > 1 {
        let mut pos = 0;
        while pos + 1 < hashes.len() {
            if hashes[pos] == hashes[pos + 1] {
                mutated = true;
            }
            pos += 2;
        }
        if hashes.len() % 2 == 1 {
            hashes.push(*hashes.last().unwrap());
        }
        let mut data = [0u8; 64];
        for i in 0..hashes.len() / 2 {
            data[..32].copy_from_slice(&hashes[2 * i]);
            data[32..].copy_from_slice(&hashes[2 * i + 1]);
            hashes[i] = sha256d(&data);
        }
        hashes.truncate(hashes.len() / 2);
    }
    match hashes.first() {
        Some(root) => (*root, mutated),
        None => (ZERO_HASH, mutated),
    }
}

/// Core: `BlockMerkleRoot`.
pub fn block_merkle_root(block: &BlockData) -> (Hash256, bool) {
    compute_merkle_root(block.tx_info.iter().map(|info| info.txid).collect())
}

/// Core: `BlockWitnessMerkleRoot`.
pub fn block_witness_merkle_root(block: &BlockData) -> Hash256 {
    let mut leaves = Vec::with_capacity(block.tx_info.len());
    leaves.push(ZERO_HASH);
    for info in block.tx_info.iter().skip(1) {
        leaves.push(info.wtxid);
    }
    compute_merkle_root(leaves).0
}

/// Core: `MINIMUM_WITNESS_COMMITMENT`.
pub const MINIMUM_WITNESS_COMMITMENT: usize = 38;

/// Index of the commitment output in the coinbase, if any. Core: `GetWitnessCommitmentIndex`.
pub fn witness_commitment_index(block: &BlockData) -> Option<usize> {
    let coinbase = block.block.transactions.first()?;
    let mut position = None;
    for (index, output) in coinbase.outputs.iter().enumerate() {
        let script = &output.script_pubkey;
        if script.len() >= MINIMUM_WITNESS_COMMITMENT && script[..6] == [OP_RETURN, 0x24, 0xaa, 0x21, 0xa9, 0xed] {
            position = Some(index);
        }
    }
    position
}

/// Core: `CheckWitnessMalleation`.
pub fn check_witness_malleation(block: &BlockData, expect_witness_commitment: bool) -> Result<(), Failure> {
    if expect_witness_commitment {
        if let Some(position) = witness_commitment_index(block) {
            let stack = &block.block.transactions[0].inputs[0].witness;
            if stack.len() != 1 || stack[0].len() != 32 {
                return Err(mutated("bad-witness-nonce-size"));
            }
            let mut data = block_witness_merkle_root(block).to_vec();
            data.extend_from_slice(&stack[0]);
            let commitment = sha256d(&data);
            if commitment[..] != block.block.transactions[0].outputs[position].script_pubkey[6..38] {
                return Err(mutated("bad-witness-merkle-match"));
            }
            return Ok(());
        }
    }
    if block.block.transactions.iter().any(|tx| tx.has_witness()) {
        return Err(mutated("unexpected-witness"));
    }
    Ok(())
}

/// Core: `MAX_FUTURE_BLOCK_TIME`.
pub const MAX_FUTURE_BLOCK_TIME: i64 = 2 * 60 * 60;

/// Core: `CheckBlockHeader`.
pub fn check_block_header(header: &BlockHeader, hash: &Hash256, params: &ConsensusParams) -> Result<(), Failure> {
    if !check_proof_of_work(hash, header.bits, params.pow_limit) {
        return Err(invalid("high-hash"));
    }
    Ok(())
}

/// What the contextual checks need to know about the parent of a header.
pub struct ParentInfo<'a> {
    pub height: i32,
    pub header: &'a BlockHeader,
    pub median_time_past: i64,
}

/// Core: `ContextualCheckBlockHeader`. `ancestor(h)` returns the parent's ancestor header at height h.
pub fn contextual_check_block_header(
    header: &BlockHeader,
    parent: &ParentInfo,
    ancestor: &dyn Fn(i32) -> BlockHeader,
    params: &ConsensusParams,
    now: i64,
) -> Result<(), Failure> {
    let height = parent.height + 1;
    if header.bits != next_work_required(params, parent.height, parent.header, ancestor, header.time) {
        return Err(invalid("bad-diffbits"));
    }
    if header.time as i64 <= parent.median_time_past {
        return Err(invalid("time-too-old"));
    }
    if params.enforce_bip94 && height as i64 % params.difficulty_adjustment_interval() == 0 && (header.time as i64) < parent.header.time as i64 - MAX_TIMEWARP {
        return Err(invalid("time-timewarp-attack"));
    }
    if header.time as i64 > now + MAX_FUTURE_BLOCK_TIME {
        return Err(temporary("time-too-new"));
    }
    if (header.version < 2 && height >= params.bip34_height) || (header.version < 3 && height >= params.bip66_height) || (header.version < 4 && height >= params.bip65_height) {
        return Err(invalid(&format!("bad-version(0x{:08x})", header.version as u32)));
    }
    Ok(())
}

/// Core: `CheckBlock`.
pub fn check_block(block: &BlockData, params: &ConsensusParams) -> Result<(), Failure> {
    check_block_header(&block.block.header, &block.hash, params)?;
    if params.signet_challenge.is_some() && !check_signet_block_solution(block, params) {
        return Err(invalid("bad-signet-blksig"));
    }
    let (root, is_mutated) = block_merkle_root(block);
    if root != block.block.header.merkle_root {
        return Err(mutated("bad-txnmrklroot"));
    }
    if is_mutated {
        return Err(mutated("bad-txns-duplicate"));
    }
    let transactions = &block.block.transactions;
    if transactions.is_empty() || transactions.len() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || block.stripped_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT {
        return Err(invalid("bad-blk-length"));
    }
    if !transactions[0].is_coinbase() {
        return Err(invalid("bad-cb-missing"));
    }
    if transactions.iter().skip(1).any(|tx| tx.is_coinbase()) {
        return Err(invalid("bad-cb-multiple"));
    }
    for (tx, info) in transactions.iter().zip(&block.tx_info) {
        check_transaction_sized(tx, info.stripped_size).map_err(invalid)?;
    }
    let sigops: u64 = transactions.iter().map(legacy_sig_op_count).sum();
    if sigops as i64 * WITNESS_SCALE_FACTOR as i64 > MAX_BLOCK_SIGOPS_COST {
        return Err(invalid("bad-blk-sigops"));
    }
    Ok(())
}

/// Core: `ContextualCheckBlock`. `parent` is `None` only for the genesis block.
pub fn contextual_check_block(block: &BlockData, parent: Option<&ParentInfo>, params: &ConsensusParams) -> Result<(), Failure> {
    let height = parent.map_or(0, |p| p.height + 1);
    let lock_time_cutoff = match parent {
        Some(p) if height >= params.csv_height => p.median_time_past,
        _ => block.block.header.time as i64,
    };
    for tx in &block.block.transactions {
        if !is_final_tx(tx, height, lock_time_cutoff) {
            return Err(invalid("bad-txns-nonfinal"));
        }
    }
    if height >= params.bip34_height {
        let expect = push_int(height as i64);
        let script_sig = &block.block.transactions[0].inputs[0].script_sig;
        if script_sig.len() < expect.len() || script_sig[..expect.len()] != expect[..] {
            return Err(invalid("bad-cb-height"));
        }
    }
    check_witness_malleation(block, height >= params.segwit_height)?;
    if block.weight() > MAX_BLOCK_WEIGHT {
        return Err(invalid("bad-blk-weight"));
    }
    Ok(())
}

/// Core: `GetBlockScriptFlags`.
pub fn block_script_flags(hash: &Hash256, height: i32, params: &ConsensusParams) -> ScriptFlags {
    let mut flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT;
    if let Some((_, exception)) = params.script_flag_exceptions.iter().find(|(h, _)| h == hash) {
        flags = *exception;
    }
    if height >= params.bip66_height {
        flags |= VERIFY_DERSIG;
    }
    if height >= params.bip65_height {
        flags |= VERIFY_CHECKLOCKTIMEVERIFY;
    }
    if height >= params.csv_height {
        flags |= VERIFY_CHECKSEQUENCEVERIFY;
    }
    if height >= params.segwit_height {
        flags |= VERIFY_NULLDUMMY;
    }
    flags
}

/// Core: `IsBIP30Repeat`.
pub fn is_bip30_repeat(height: i32, hash: &Hash256) -> bool {
    (height == 91842 && hash_to_display(hash) == "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")
        || (height == 91880 && hash_to_display(hash) == "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
}

/// Core: `BIP34_IMPLIES_BIP30_LIMIT`.
pub const BIP34_IMPLIES_BIP30_LIMIT: i32 = 1_983_702;

/// Core: `IsBlockMutated` (chapter 11 section 11.11).
pub fn is_block_mutated(block: &BlockData, check_witness_root: bool) -> bool {
    let (root, tree_mutated) = block_merkle_root(block);
    if root != block.block.header.merkle_root || tree_mutated {
        return true;
    }
    let transactions = &block.block.transactions;
    if transactions.is_empty() || !transactions[0].is_coinbase() {
        return block.tx_info.iter().any(|info| info.stripped_size == 64);
    }
    check_witness_malleation(block, check_witness_root).is_err()
}
