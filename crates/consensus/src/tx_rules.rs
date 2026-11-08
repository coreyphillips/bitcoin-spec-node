//! Chapter 08: transaction rules.

use crate::interpreter::{ScriptFlags, SEQUENCE_FINAL, SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG, VERIFY_P2SH, VERIFY_WITNESS};
use crate::script::*;
use crate::tx::{OutPoint, Transaction, TxOut, WITNESS_SCALE_FACTOR};
use crate::util::{money_range, MAX_MONEY};
use crate::verify::{WITNESS_V0_KEYHASH_SIZE, WITNESS_V0_SCRIPTHASH_SIZE};

/// Coinbase outputs can be spent only this many blocks later. Core: `COINBASE_MATURITY`.
pub const COINBASE_MATURITY: i32 = 100;
/// Core: `MAX_BLOCK_WEIGHT`.
pub const MAX_BLOCK_WEIGHT: usize = 4_000_000;
/// Core: `MAX_BLOCK_SIGOPS_COST`.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Core: `CTxIn::SEQUENCE_LOCKTIME_GRANULARITY`.
pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;

impl Transaction {
    /// Core: `CTransaction::IsCoinBase`.
    #[inline]
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prevout.is_null()
    }

    /// Sum of output values. Only meaningful after `check_transaction`, which bounds it.
    pub fn value_out(&self) -> i64 {
        self.outputs.iter().map(|output| output.value).sum()
    }
}

/// Core: `CheckTransaction`.
pub fn check_transaction(tx: &Transaction) -> Result<(), &'static str> {
    check_transaction_sized(tx, tx.stripped_size())
}

/// `check_transaction` with the stripped size already known.
pub fn check_transaction_sized(tx: &Transaction, stripped_size: usize) -> Result<(), &'static str> {
    if tx.inputs.is_empty() {
        return Err("bad-txns-vin-empty");
    }
    if tx.outputs.is_empty() {
        return Err("bad-txns-vout-empty");
    }
    if stripped_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT {
        return Err("bad-txns-oversize");
    }
    let mut value_out: i64 = 0;
    for output in &tx.outputs {
        if output.value < 0 {
            return Err("bad-txns-vout-negative");
        }
        if output.value > MAX_MONEY {
            return Err("bad-txns-vout-toolarge");
        }
        value_out += output.value;
        if !money_range(value_out) {
            return Err("bad-txns-txouttotal-toolarge");
        }
    }
    if tx.inputs.len() <= 16 {
        // Small transactions: pairwise comparison, no allocation.
        for (i, input) in tx.inputs.iter().enumerate() {
            if tx.inputs[..i].iter().any(|other| other.prevout == input.prevout) {
                return Err("bad-txns-inputs-duplicate");
            }
        }
    } else {
        let mut seen: std::collections::HashSet<OutPoint> = std::collections::HashSet::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            if !seen.insert(input.prevout) {
                return Err("bad-txns-inputs-duplicate");
            }
        }
    }
    if tx.is_coinbase() {
        let length = tx.inputs[0].script_sig.len();
        if !(2..=100).contains(&length) {
            return Err("bad-cb-length");
        }
    } else if tx.inputs.iter().any(|input| input.prevout.is_null()) {
        return Err("bad-txns-prevout-null");
    }
    Ok(())
}

/// Core: `IsFinalTx`.
pub fn is_final_tx(tx: &Transaction, block_height: i32, block_time: i64) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    let lock_time = tx.lock_time as i64;
    let cutoff = if lock_time < LOCKTIME_THRESHOLD as i64 { block_height as i64 } else { block_time };
    if lock_time < cutoff {
        return true;
    }
    tx.inputs.iter().all(|input| input.sequence == SEQUENCE_FINAL)
}

/// An unspent output with its creation height and coinbase flag. Core: `Coin`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub output: TxOut,
    /// Height of the block containing the creating transaction.
    pub height: i32,
    pub is_coinbase: bool,
}

/// Returns (minimum height, minimum time), both "last invalid" values, -1 meaning no constraint.
/// Core: `CalculateSequenceLocks`.
pub fn calculate_sequence_locks(tx: &Transaction, enforce_bip68: bool, coin_heights: &[i32], mtp_at: &dyn Fn(i32) -> i64) -> (i32, i64) {
    assert!(coin_heights.len() == tx.inputs.len());
    let mut min_height: i32 = -1;
    let mut min_time: i64 = -1;
    if !(tx.version >= 2 && enforce_bip68) {
        return (min_height, min_time);
    }
    for (input, &coin_height) in tx.inputs.iter().zip(coin_heights) {
        if input.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            continue;
        }
        let value = input.sequence & SEQUENCE_LOCKTIME_MASK;
        if input.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
            let coin_time = mtp_at((coin_height - 1).max(0));
            min_time = min_time.max(coin_time + ((value << SEQUENCE_LOCKTIME_GRANULARITY) as i64) - 1);
        } else {
            min_height = min_height.max(coin_height + value as i32 - 1);
        }
    }
    (min_height, min_time)
}

/// Core: `EvaluateSequenceLocks`.
pub fn evaluate_sequence_locks(block_height: i32, prev_mtp: i64, lock: (i32, i64)) -> bool {
    !(lock.0 >= block_height || lock.1 >= prev_mtp)
}

/// `coins[i]` is the coin spent by input i, or `None` if it does not exist. Returns the fee.
/// Core: `Consensus::CheckTxInputs`.
pub fn check_tx_inputs(tx: &Transaction, coins: &[Option<Coin>], spend_height: i32) -> Result<i64, &'static str> {
    if coins.iter().any(|coin| coin.is_none()) {
        return Err("bad-txns-inputs-missingorspent");
    }
    let mut value_in: i64 = 0;
    for coin in coins.iter().flatten() {
        if coin.is_coinbase && spend_height - coin.height < COINBASE_MATURITY {
            return Err("bad-txns-premature-spend-of-coinbase");
        }
        // Both addends are checked before the next addition, so this cannot overflow.
        if !money_range(coin.output.value) {
            return Err("bad-txns-inputvalues-outofrange");
        }
        value_in += coin.output.value;
        if !money_range(value_in) {
            return Err("bad-txns-inputvalues-outofrange");
        }
    }
    let value_out = tx.value_out();
    if value_in < value_out {
        return Err("bad-txns-in-belowout");
    }
    let fee = value_in - value_out;
    if !money_range(fee) {
        return Err("bad-txns-fee-outofrange");
    }
    Ok(fee)
}

/// Core: `GetLegacySigOpCount`.
pub fn legacy_sig_op_count(tx: &Transaction) -> u64 {
    let inputs: u64 = tx.inputs.iter().map(|input| sig_op_count(&input.script_sig, false)).sum();
    let outputs: u64 = tx.outputs.iter().map(|output| sig_op_count(&output.script_pubkey, false)).sum();
    inputs + outputs
}

/// Core: `GetP2SHSigOpCount`. `spent[i]` is the output spent by input i.
pub fn p2sh_sig_op_count_tx(tx: &Transaction, spent: &[&TxOut]) -> u64 {
    if tx.is_coinbase() {
        return 0;
    }
    let mut count = 0;
    for (input, output) in tx.inputs.iter().zip(spent) {
        if is_p2sh(&output.script_pubkey) {
            count += p2sh_sig_op_count(&output.script_pubkey, &input.script_sig);
        }
    }
    count
}

/// Core: `WitnessSigOps`.
fn witness_sig_ops(version: u8, program: &[u8], witness: &[Vec<u8>]) -> u64 {
    if version == 0 {
        if program.len() == WITNESS_V0_KEYHASH_SIZE {
            return 1;
        }
        if program.len() == WITNESS_V0_SCRIPTHASH_SIZE && !witness.is_empty() {
            return sig_op_count(&witness[witness.len() - 1], true);
        }
    }
    0
}

/// Core: `CountWitnessSigOps`.
pub fn witness_sig_op_count(script_sig: &[u8], script_pubkey: &[u8], witness: &[Vec<u8>], flags: ScriptFlags) -> u64 {
    if flags & VERIFY_WITNESS == 0 {
        return 0;
    }
    if let Some((version, program)) = witness_program(script_pubkey) {
        return witness_sig_ops(version, program, witness);
    }
    if is_p2sh(script_pubkey) && is_push_only(script_sig) {
        let mut pos = 0;
        let mut last_data: &[u8] = &[];
        while pos < script_sig.len() {
            // Cannot fail: the script is push-only, so it parses completely.
            last_data = get_op(script_sig, &mut pos).unwrap().data;
        }
        if let Some((version, program)) = witness_program(last_data) {
            return witness_sig_ops(version, program, witness);
        }
    }
    0
}

/// Core: `GetTransactionSigOpCost`. `spent[i]` is the output spent by input i (unused for a
/// coinbase). `legacy_count` is `legacy_sig_op_count(tx)`.
pub fn transaction_sig_op_cost_with_legacy(tx: &Transaction, spent: &[&TxOut], flags: ScriptFlags, legacy_count: u64) -> i64 {
    let mut cost = legacy_count as i64 * WITNESS_SCALE_FACTOR as i64;
    if tx.is_coinbase() {
        return cost;
    }
    if flags & VERIFY_P2SH != 0 {
        cost += p2sh_sig_op_count_tx(tx, spent) as i64 * WITNESS_SCALE_FACTOR as i64;
    }
    for (input, output) in tx.inputs.iter().zip(spent) {
        cost += witness_sig_op_count(&input.script_sig, &output.script_pubkey, &input.witness, flags) as i64;
    }
    cost
}

/// Core: `GetTransactionSigOpCost`.
pub fn transaction_sig_op_cost(tx: &Transaction, spent: &[&TxOut], flags: ScriptFlags) -> i64 {
    transaction_sig_op_cost_with_legacy(tx, spent, flags, legacy_sig_op_count(tx))
}
