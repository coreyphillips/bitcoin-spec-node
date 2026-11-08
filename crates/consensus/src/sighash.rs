//! Chapter 06: signature hashes (legacy, BIP143, BIP341).

use crate::hashes::{sha256, sha256d, tagged_writer, Sha256Writer};
use crate::interpreter::{ExecData, SigVersion};
use crate::script::{get_op, OP_CODESEPARATOR};
use crate::serialize::{write_compact_size, write_var_bytes};
use crate::tx::{serialize_txout, Transaction, TxOut};
use crate::util::{Hash256, ZERO_HASH};
use std::borrow::Cow;
use std::sync::OnceLock;

pub const SIGHASH_DEFAULT: u8 = 0x00;
pub const SIGHASH_ALL: i32 = 1;
pub const SIGHASH_NONE: i32 = 2;
pub const SIGHASH_SINGLE: i32 = 3;
pub const SIGHASH_ANYONECANPAY: i32 = 0x80;

/// Removes every operation-aligned occurrence of `pattern` from `script`. Core: `FindAndDelete`.
/// Returns the script unchanged (borrowed) when nothing was removed.
pub fn find_and_delete<'a>(script: &'a [u8], pattern: &[u8]) -> Cow<'a, [u8]> {
    if pattern.is_empty() {
        return Cow::Borrowed(script);
    }
    let mut result = Vec::new();
    let mut found = false;
    let mut pc = 0usize; // current position
    let mut pc2 = 0usize; // start of bytes not yet copied
    loop {
        if found {
            result.extend_from_slice(&script[pc2..pc]);
        }
        while script.len() - pc >= pattern.len() && &script[pc..pc + pattern.len()] == pattern {
            if !found {
                // First match: everything before it is kept (nothing was removed before it).
                result.reserve(script.len());
                result.extend_from_slice(&script[..pc]);
                found = true;
            }
            pc += pattern.len();
        }
        pc2 = pc;
        if get_op(script, &mut pc).is_none() {
            break;
        }
    }
    if found {
        result.extend_from_slice(&script[pc2..]);
        Cow::Owned(result)
    } else {
        Cow::Borrowed(script)
    }
}

/// Core: `CTransactionSignatureSerializer::SerializeScriptCode`.
fn serialize_script_code_legacy(out: &mut Vec<u8>, script_code: &[u8]) {
    let mut it = 0usize;
    let mut separators = 0usize;
    while let Some(op) = get_op(script_code, &mut it) {
        if op.opcode == OP_CODESEPARATOR {
            separators += 1;
        }
    }
    write_compact_size(out, (script_code.len() - separators) as u64);
    let mut it = 0usize;
    let mut begin = 0usize;
    while let Some(op) = get_op(script_code, &mut it) {
        if op.opcode == OP_CODESEPARATOR {
            out.extend_from_slice(&script_code[begin..it - 1]);
            begin = it;
        }
    }
    if begin != script_code.len() {
        out.extend_from_slice(&script_code[begin..it]);
    }
}

fn legacy_sighash(script_code: &[u8], tx: &Transaction, n_in: usize, hash_type: i32) -> Hash256 {
    let base_type = hash_type & 0x1f;
    if base_type == SIGHASH_SINGLE && n_in >= tx.outputs.len() {
        let mut one = [0u8; 32];
        one[0] = 1;
        return one;
    }
    let anyone_can_pay = hash_type & SIGHASH_ANYONECANPAY != 0;
    let hash_single = base_type == SIGHASH_SINGLE;
    let hash_none = base_type == SIGHASH_NONE;

    let mut data = Vec::with_capacity(64 + script_code.len() + 41 * tx.inputs.len() + 34 * tx.outputs.len());
    data.extend_from_slice(&tx.version.to_le_bytes());
    let input_count = if anyone_can_pay { 1 } else { tx.inputs.len() };
    write_compact_size(&mut data, input_count as u64);
    for position in 0..input_count {
        let index = if anyone_can_pay { n_in } else { position };
        let input = &tx.inputs[index];
        data.extend_from_slice(&input.prevout.txid);
        data.extend_from_slice(&input.prevout.vout.to_le_bytes());
        if index != n_in {
            write_compact_size(&mut data, 0);
        } else {
            serialize_script_code_legacy(&mut data, script_code);
        }
        if index != n_in && (hash_single || hash_none) {
            data.extend_from_slice(&0i32.to_le_bytes());
        } else {
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }
    }
    let output_count = if hash_none {
        0
    } else if hash_single {
        n_in + 1
    } else {
        tx.outputs.len()
    };
    write_compact_size(&mut data, output_count as u64);
    for index in 0..output_count {
        if hash_single && index != n_in {
            serialize_txout(&mut data, &TxOut { value: -1, script_pubkey: Vec::new() });
        } else {
            serialize_txout(&mut data, &tx.outputs[index]);
        }
    }
    data.extend_from_slice(&tx.lock_time.to_le_bytes());
    data.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&data)
}

/// Per-transaction hashes for BIP143 and BIP341, computed on first use (a pure cache: each
/// value is exactly what `PrecomputedTransactionData` would hold). Core: `PrecomputedTransactionData`.
#[derive(Debug, Default)]
pub struct PrecomputedTx {
    /// SHA256 of all outpoints, of all sequences, of all serialized outputs.
    common: OnceLock<[Hash256; 3]>,
    /// SHA256 of all spent amounts and of all spent scriptPubKeys (BIP341).
    spent: OnceLock<[Hash256; 2]>,
    /// The BIP143 (double SHA-256) versions of `common`.
    bip143: OnceLock<[Hash256; 3]>,
}

impl PrecomputedTx {
    /// Creates the cache. Nothing is hashed until a signature check needs it.
    pub fn new(_tx: &Transaction, _spent_outputs: &[TxOut]) -> PrecomputedTx {
        PrecomputedTx::default()
    }

    fn common(&self, tx: &Transaction) -> &[Hash256; 3] {
        self.common.get_or_init(|| {
            let mut prevouts = Sha256Writer::new();
            let mut sequences = Sha256Writer::new();
            for input in &tx.inputs {
                prevouts.write(&input.prevout.txid);
                prevouts.write(&input.prevout.vout.to_le_bytes());
                sequences.write(&input.sequence.to_le_bytes());
            }
            let mut outputs = Vec::new();
            for output in &tx.outputs {
                serialize_txout(&mut outputs, output);
            }
            [prevouts.finish(), sequences.finish(), sha256(&outputs)]
        })
    }

    fn spent(&self, spent_outputs: &[TxOut]) -> &[Hash256; 2] {
        self.spent.get_or_init(|| {
            let mut amounts = Sha256Writer::new();
            let mut scripts = Vec::new();
            for spent in spent_outputs {
                amounts.write(&spent.value.to_le_bytes());
                write_var_bytes(&mut scripts, &spent.script_pubkey);
            }
            [amounts.finish(), sha256(&scripts)]
        })
    }

    fn bip143(&self, tx: &Transaction) -> &[Hash256; 3] {
        self.bip143.get_or_init(|| {
            let common = self.common(tx);
            [sha256(&common[0]), sha256(&common[1]), sha256(&common[2])]
        })
    }
}

fn bip143_sighash(script_code: &[u8], tx: &Transaction, n_in: usize, hash_type: i32, amount: i64, pre: &PrecomputedTx) -> Hash256 {
    let base_type = hash_type & 0x1f;
    let anyone_can_pay = hash_type & SIGHASH_ANYONECANPAY != 0;
    let mut hash_prevouts = ZERO_HASH;
    let mut hash_sequence = ZERO_HASH;
    let mut hash_outputs = ZERO_HASH;
    if !anyone_can_pay {
        hash_prevouts = pre.bip143(tx)[0];
    }
    if !anyone_can_pay && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        hash_sequence = pre.bip143(tx)[1];
    }
    if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        hash_outputs = pre.bip143(tx)[2];
    } else if base_type == SIGHASH_SINGLE && n_in < tx.outputs.len() {
        let mut output = Vec::new();
        serialize_txout(&mut output, &tx.outputs[n_in]);
        hash_outputs = sha256d(&output);
    }
    let input = &tx.inputs[n_in];
    let mut data = Vec::with_capacity(160 + script_code.len());
    data.extend_from_slice(&tx.version.to_le_bytes());
    data.extend_from_slice(&hash_prevouts);
    data.extend_from_slice(&hash_sequence);
    data.extend_from_slice(&input.prevout.txid);
    data.extend_from_slice(&input.prevout.vout.to_le_bytes());
    write_var_bytes(&mut data, script_code);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&input.sequence.to_le_bytes());
    data.extend_from_slice(&hash_outputs);
    data.extend_from_slice(&tx.lock_time.to_le_bytes());
    data.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&data)
}

/// The ECDSA signature hash for `Base` and `WitnessV0`. Core: `SignatureHash`.
pub fn signature_hash(script_code: &[u8], tx: &Transaction, n_in: usize, hash_type: i32, amount: i64, sigversion: SigVersion, pre: &PrecomputedTx) -> Hash256 {
    assert!(n_in < tx.inputs.len());
    match sigversion {
        SigVersion::WitnessV0 => bip143_sighash(script_code, tx, n_in, hash_type, amount, pre),
        _ => legacy_sighash(script_code, tx, n_in, hash_type),
    }
}

/// BIP341/BIP342 signature hash. Returns `None` for an invalid hash type or a SIGHASH_SINGLE
/// without a matching output. Core: `SignatureHashSchnorr`.
pub fn signature_hash_schnorr(
    execdata: &ExecData,
    tx: &Transaction,
    in_pos: usize,
    hash_type: u8,
    sigversion: SigVersion,
    spent_outputs: &[TxOut],
    pre: &PrecomputedTx,
) -> Option<Hash256> {
    let ext_flag: u8 = match sigversion {
        SigVersion::Taproot => 0,
        SigVersion::Tapscript => 1,
        _ => panic!("signature_hash_schnorr requires a taproot sigversion"),
    };
    assert!(in_pos < tx.inputs.len());
    assert!(spent_outputs.len() == tx.inputs.len());
    let output_type = if hash_type == SIGHASH_DEFAULT { SIGHASH_ALL as u8 } else { hash_type & 0x03 };
    let input_type = hash_type & 0x80;
    if !(hash_type <= 0x03 || (0x81..=0x83).contains(&hash_type)) {
        return None;
    }
    if output_type == SIGHASH_SINGLE as u8 && in_pos >= tx.outputs.len() {
        return None;
    }
    let mut msg = tagged_writer("TapSighash");
    msg.write(&[0x00]); // epoch
    msg.write(&[hash_type]);
    msg.write(&tx.version.to_le_bytes());
    msg.write(&tx.lock_time.to_le_bytes());
    if input_type != SIGHASH_ANYONECANPAY as u8 {
        let common = pre.common(tx);
        let spent = pre.spent(spent_outputs);
        msg.write(&common[0]);
        msg.write(&spent[0]);
        msg.write(&spent[1]);
        msg.write(&common[1]);
    }
    if output_type == SIGHASH_ALL as u8 {
        msg.write(&pre.common(tx)[2]);
    }
    let have_annex = execdata.annex_hash.is_some();
    msg.write(&[(ext_flag << 1) + have_annex as u8]);
    if input_type == SIGHASH_ANYONECANPAY as u8 {
        let input = &tx.inputs[in_pos];
        let mut data = Vec::with_capacity(80 + spent_outputs[in_pos].script_pubkey.len());
        data.extend_from_slice(&input.prevout.txid);
        data.extend_from_slice(&input.prevout.vout.to_le_bytes());
        serialize_txout(&mut data, &spent_outputs[in_pos]);
        data.extend_from_slice(&input.sequence.to_le_bytes());
        msg.write(&data);
    } else {
        msg.write(&(in_pos as u32).to_le_bytes());
    }
    if let Some(annex_hash) = execdata.annex_hash {
        msg.write(&annex_hash);
    }
    if output_type == SIGHASH_SINGLE as u8 {
        let mut output = Vec::new();
        serialize_txout(&mut output, &tx.outputs[in_pos]);
        msg.write(&sha256(&output));
    }
    if sigversion == SigVersion::Tapscript {
        msg.write(&execdata.tapleaf_hash.expect("tapleaf hash is set for tapscript"));
        msg.write(&[0x00]); // key_version
        msg.write(&execdata.codeseparator_pos.to_le_bytes());
    }
    Some(msg.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference `FindAndDelete`, for comparison with the borrowing version above.
    fn reference_find_and_delete(script: &[u8], pattern: &[u8]) -> Vec<u8> {
        if pattern.is_empty() {
            return script.to_vec();
        }
        let mut result = Vec::with_capacity(script.len());
        let mut found = false;
        let mut pc = 0usize;
        let mut pc2 = 0usize;
        loop {
            result.extend_from_slice(&script[pc2..pc]);
            while script.len() - pc >= pattern.len() && &script[pc..pc + pattern.len()] == pattern {
                pc += pattern.len();
                found = true;
            }
            pc2 = pc;
            if get_op(script, &mut pc).is_none() {
                break;
            }
        }
        if found {
            result.extend_from_slice(&script[pc2..]);
            result
        } else {
            script.to_vec()
        }
    }

    #[test]
    fn find_and_delete_matches_reference() {
        // Deterministic pseudo-random scripts over a small alphabet so that matches are common.
        let mut seed = 0x1234_5678u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet = [0x00u8, 0x01, 0x02, 0x4c, 0x4d, 0x51, 0xab, 0xac, 0x03];
        for _ in 0..200_000 {
            let len = (next() % 12) as usize;
            let script: Vec<u8> = (0..len).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect();
            let plen = (next() % 4) as usize;
            let pattern: Vec<u8> = (0..plen).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect();
            assert_eq!(find_and_delete(&script, &pattern).into_owned(), reference_find_and_delete(&script, &pattern), "{script:?} {pattern:?}");
        }
    }
}
