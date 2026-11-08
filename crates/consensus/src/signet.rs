//! Chapter 13: signet block solutions.

use crate::block_rules::{compute_merkle_root, witness_commitment_index};
use crate::interpreter::{VERIFY_DERSIG, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_WITNESS};
use crate::params::ConsensusParams;
use crate::script::{get_op, push_data, OP_0, OP_RETURN};
use crate::serialize::{DecodeError, Reader};
use crate::sighash::PrecomputedTx;
use crate::tx::{BlockData, OutPoint, Transaction, TxIn, TxOut};
use crate::verify::verify_input;

/// Core: `SIGNET_HEADER`.
pub const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// Returns (rebuilt script, solution) if a solution push is found. Core: `FetchAndClearCommitmentSection`.
fn fetch_and_clear_commitment_section(script: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut replacement = Vec::new();
    let mut solution = None;
    let mut pos = 0;
    while let Some(op) = get_op(script, &mut pos) {
        if !op.data.is_empty() {
            if solution.is_none() && op.data.len() > SIGNET_HEADER.len() && op.data[..4] == SIGNET_HEADER {
                solution = Some(op.data[4..].to_vec());
                replacement.extend_from_slice(&push_data(&SIGNET_HEADER));
            } else {
                replacement.extend_from_slice(&push_data(op.data));
            }
        } else {
            replacement.push(op.opcode);
        }
    }
    solution.map(|s| (replacement, s))
}

/// Core: `CheckSignetBlockSolution`, `SignetTxs::Create`.
pub fn check_signet_block_solution(block: &BlockData, params: &ConsensusParams) -> bool {
    if block.hash == params.genesis_hash {
        return true;
    }
    let challenge = params.signet_challenge.as_ref().expect("signet parameters");
    if block.block.transactions.is_empty() {
        return false;
    }
    let commitment_index = match witness_commitment_index(block) {
        Some(index) => index,
        None => return false,
    };
    let mut modified_coinbase = block.block.transactions[0].clone();
    let mut script_sig = Vec::new();
    let mut witness = Vec::new();
    if let Some((replacement, solution)) = fetch_and_clear_commitment_section(&modified_coinbase.outputs[commitment_index].script_pubkey) {
        modified_coinbase.outputs[commitment_index].script_pubkey = replacement;
        let mut reader = Reader::new(&solution);
        let parsed = (|| -> Result<(Vec<u8>, Vec<Vec<u8>>), DecodeError> {
            let script_sig = reader.read_var_bytes()?;
            let count = reader.read_compact_size()?;
            let mut stack = Vec::new();
            for _ in 0..count {
                stack.push(reader.read_var_bytes()?);
            }
            Ok((script_sig, stack))
        })();
        match parsed {
            Ok((s, w)) if reader.remaining() == 0 => {
                script_sig = s;
                witness = w;
            }
            _ => return false,
        }
    }
    let mut leaves = vec![modified_coinbase.txid()];
    for info in block.tx_info.iter().skip(1) {
        leaves.push(info.txid);
    }
    let signet_merkle_root = compute_merkle_root(leaves).0;
    let header = &block.block.header;
    let mut block_data = Vec::with_capacity(72);
    block_data.extend_from_slice(&header.version.to_le_bytes());
    block_data.extend_from_slice(&header.prev_block);
    block_data.extend_from_slice(&signet_merkle_root);
    block_data.extend_from_slice(&header.time.to_le_bytes());

    let mut to_spend_script_sig = vec![OP_0];
    to_spend_script_sig.extend_from_slice(&push_data(&block_data));
    let to_spend = Transaction {
        version: 0,
        inputs: vec![TxIn { prevout: OutPoint::null(), script_sig: to_spend_script_sig, sequence: 0, witness: Vec::new() }],
        outputs: vec![TxOut { value: 0, script_pubkey: challenge.clone() }],
        lock_time: 0,
    };
    let to_sign = Transaction {
        version: 0,
        inputs: vec![TxIn { prevout: OutPoint { txid: to_spend.txid(), vout: 0 }, script_sig, sequence: 0, witness }],
        outputs: vec![TxOut { value: 0, script_pubkey: vec![OP_RETURN] }],
        lock_time: 0,
    };
    let spent = vec![to_spend.outputs[0].clone()];
    let precomputed = PrecomputedTx::new(&to_sign, &spent);
    let flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_DERSIG | VERIFY_NULLDUMMY;
    verify_input(&to_sign, 0, &spent, &precomputed, flags).is_ok()
}
