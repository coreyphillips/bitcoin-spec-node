//! Chapter 07: script verification (`verify_script`, witness programs, taproot).

use crate::hashes::{sha256, tagged_writer};
use crate::interpreter::*;
use crate::script::*;
use crate::serialize::{compact_size_len, write_var_bytes};
use crate::sighash::PrecomputedTx;
use crate::tx::{Transaction, TxOut};
use crate::util::Hash256;

/// Core: `VerifyScript`.
pub fn verify_script(script_sig: &[u8], script_pubkey: &[u8], witness: &[Vec<u8>], flags: ScriptFlags, checker: &TxChecker) -> Result<(), ScriptError> {
    assert!((flags & VERIFY_WITNESS) == 0 || (flags & VERIFY_P2SH) != 0, "WITNESS requires P2SH");
    let mut had_witness = false;
    let mut stack: Vec<Vec<u8>> = Vec::new();

    eval_script(&mut stack, script_sig, flags, checker, SigVersion::Base, &mut ExecData::default())?;
    let stack_copy = if flags & VERIFY_P2SH != 0 && is_p2sh(script_pubkey) { Some(stack.clone()) } else { None };
    eval_script(&mut stack, script_pubkey, flags, checker, SigVersion::Base, &mut ExecData::default())?;
    if stack.is_empty() || !cast_to_bool(&stack[stack.len() - 1]) {
        return Err(ScriptError::EvalFalse);
    }

    if flags & VERIFY_WITNESS != 0 {
        if let Some((version, program)) = witness_program(script_pubkey) {
            had_witness = true;
            if !script_sig.is_empty() {
                return Err(ScriptError::WitnessMalleated);
            }
            verify_witness_program(witness, version, program, flags, checker, false)?;
        }
    }

    if flags & VERIFY_P2SH != 0 && is_p2sh(script_pubkey) {
        if !is_push_only(script_sig) {
            return Err(ScriptError::SigPushOnly);
        }
        let mut stack = stack_copy.expect("copied for P2SH");
        // Non-empty: otherwise the P2SH script would have failed above.
        let redeem_script = stack.pop().expect("P2SH stack is not empty");
        eval_script(&mut stack, &redeem_script, flags, checker, SigVersion::Base, &mut ExecData::default())?;
        if stack.is_empty() || !cast_to_bool(&stack[stack.len() - 1]) {
            return Err(ScriptError::EvalFalse);
        }
        if flags & VERIFY_WITNESS != 0 {
            if let Some((version, program)) = witness_program(&redeem_script) {
                had_witness = true;
                if script_sig != push_data(&redeem_script).as_slice() {
                    return Err(ScriptError::WitnessMalleatedP2sh);
                }
                verify_witness_program(witness, version, program, flags, checker, true)?;
            }
        }
    }

    if flags & VERIFY_WITNESS != 0 && !had_witness && !witness.is_empty() {
        return Err(ScriptError::WitnessUnexpected);
    }
    Ok(())
}

/// Core: `ExecuteWitnessScript`.
fn execute_witness_script(
    initial_stack: &[Vec<u8>],
    script: &[u8],
    flags: ScriptFlags,
    sigversion: SigVersion,
    checker: &TxChecker,
    execdata: &mut ExecData,
) -> Result<(), ScriptError> {
    if sigversion == SigVersion::Tapscript {
        let mut pos = 0;
        while pos < script.len() {
            match get_op(script, &mut pos) {
                None => return Err(ScriptError::BadOpcode),
                Some(op) if is_op_success(op.opcode) => return Ok(()),
                Some(_) => {}
            }
        }
        if initial_stack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
    }
    if initial_stack.iter().any(|item| item.len() > MAX_SCRIPT_ELEMENT_SIZE) {
        return Err(ScriptError::PushSize);
    }
    let mut stack = initial_stack.to_vec();
    eval_script(&mut stack, script, flags, checker, sigversion, execdata)?;
    if stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }
    if !cast_to_bool(&stack[0]) {
        return Err(ScriptError::EvalFalse);
    }
    Ok(())
}

/// Core: `WITNESS_V0_SCRIPTHASH_SIZE`, `WITNESS_V0_KEYHASH_SIZE`, `WITNESS_V1_TAPROOT_SIZE`.
pub const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;
pub const WITNESS_V0_KEYHASH_SIZE: usize = 20;
pub const WITNESS_V1_TAPROOT_SIZE: usize = 32;
/// Core: `ANNEX_TAG`.
pub const ANNEX_TAG: u8 = 0x50;
/// Core: `TAPROOT_LEAF_MASK`, `TAPROOT_LEAF_TAPSCRIPT`.
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
/// Core: `TAPROOT_CONTROL_BASE_SIZE`, `TAPROOT_CONTROL_NODE_SIZE`, `TAPROOT_CONTROL_MAX_NODE_COUNT`.
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
pub const TAPROOT_CONTROL_MAX_SIZE: usize = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

/// Core: `ComputeTapleafHash`.
pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> Hash256 {
    let mut writer = tagged_writer("TapLeaf");
    let mut data = Vec::with_capacity(script.len() + 10);
    data.push(leaf_version);
    write_var_bytes(&mut data, script);
    writer.write(&data);
    writer.finish()
}

/// Core: `ComputeTapbranchHash`.
pub fn tapbranch_hash(a: &[u8], b: &[u8]) -> Hash256 {
    let mut writer = tagged_writer("TapBranch");
    if a < b {
        writer.write(a);
        writer.write(b);
    } else {
        writer.write(b);
        writer.write(a);
    }
    writer.finish()
}

/// Core: `ComputeTaprootMerkleRoot`. The control block size has been checked by the caller.
pub fn taproot_merkle_root(control: &[u8], leaf_hash: &Hash256) -> Hash256 {
    let path_len = (control.len() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    let mut k = *leaf_hash;
    for i in 0..path_len {
        let start = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i;
        k = tapbranch_hash(&k, &control[start..start + TAPROOT_CONTROL_NODE_SIZE]);
    }
    k
}

/// Core: `VerifyTaprootCommitment`.
pub fn verify_taproot_commitment(control: &[u8], program: &[u8], leaf_hash: &Hash256) -> bool {
    let internal_key = &control[1..TAPROOT_CONTROL_BASE_SIZE];
    let merkle_root = taproot_merkle_root(control, leaf_hash);
    crate::crypto::taproot_tweak_check(&program[..32], control[0] & 1 == 1, internal_key, &merkle_root)
}

/// True if the control block length is valid.
pub fn control_block_size_valid(control: &[u8]) -> bool {
    control.len() >= TAPROOT_CONTROL_BASE_SIZE
        && control.len() <= TAPROOT_CONTROL_MAX_SIZE
        && (control.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE == 0
}

/// Serialized size of a witness stack: CompactSize count, then each item as var_bytes.
pub fn witness_serialized_size(witness: &[Vec<u8>]) -> usize {
    let mut size = compact_size_len(witness.len() as u64);
    for item in witness {
        size += compact_size_len(item.len() as u64) + item.len();
    }
    size
}

/// Core: `VerifyWitnessProgram`.
fn verify_witness_program(witness: &[Vec<u8>], version: u8, program: &[u8], flags: ScriptFlags, checker: &TxChecker, is_p2sh: bool) -> Result<(), ScriptError> {
    let mut execdata = ExecData::default();
    if version == 0 {
        if program.len() == WITNESS_V0_SCRIPTHASH_SIZE {
            if witness.is_empty() {
                return Err(ScriptError::WitnessProgramWitnessEmpty);
            }
            let (script, stack) = witness.split_last().unwrap();
            if sha256(script)[..] != program[..] {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            execute_witness_script(stack, script, flags, SigVersion::WitnessV0, checker, &mut execdata)
        } else if program.len() == WITNESS_V0_KEYHASH_SIZE {
            if witness.len() != 2 {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            let mut script = Vec::with_capacity(25);
            script.push(OP_DUP);
            script.push(OP_HASH160);
            append_push_data(&mut script, program);
            script.push(OP_EQUALVERIFY);
            script.push(OP_CHECKSIG);
            execute_witness_script(witness, &script, flags, SigVersion::WitnessV0, checker, &mut execdata)
        } else {
            Err(ScriptError::WitnessProgramWrongLength)
        }
    } else if version == 1 && program.len() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh {
        if flags & VERIFY_TAPROOT == 0 {
            return Ok(());
        }
        if witness.is_empty() {
            return Err(ScriptError::WitnessProgramWitnessEmpty);
        }
        let mut stack: &[Vec<u8>] = witness;
        if stack.len() >= 2 {
            let last = &stack[stack.len() - 1];
            if !last.is_empty() && last[0] == ANNEX_TAG {
                let mut serialized = Vec::with_capacity(last.len() + 9);
                write_var_bytes(&mut serialized, last);
                execdata.annex_hash = Some(sha256(&serialized));
                stack = &stack[..stack.len() - 1];
            }
        }
        if stack.len() == 1 {
            // Key path spending.
            return checker.check_schnorr_signature(&stack[0], program, SigVersion::Taproot, &execdata);
        }
        // Script path spending.
        let control = &stack[stack.len() - 1];
        let script = &stack[stack.len() - 2];
        let stack = &stack[..stack.len() - 2];
        if !control_block_size_valid(control) {
            return Err(ScriptError::TaprootWrongControlSize);
        }
        let leaf_version = control[0] & TAPROOT_LEAF_MASK;
        let leaf_hash = tapleaf_hash(leaf_version, script);
        if !verify_taproot_commitment(control, program, &leaf_hash) {
            return Err(ScriptError::WitnessProgramMismatch);
        }
        execdata.tapleaf_hash = Some(leaf_hash);
        if leaf_version == TAPROOT_LEAF_TAPSCRIPT {
            execdata.validation_weight_left = witness_serialized_size(witness) as i64 + VALIDATION_WEIGHT_OFFSET;
            return execute_witness_script(stack, script, flags, SigVersion::Tapscript, checker, &mut execdata);
        }
        // Unknown leaf version: reserved for future soft forks.
        Ok(())
    } else {
        // Pay-to-anchor, unknown witness versions and program lengths, and P2SH-wrapped version 1
        // programs are reserved for future soft forks and succeed.
        Ok(())
    }
}

/// Verifies input `index` of `tx`, which spends `spent_outputs[index]`.
pub fn verify_input(tx: &Transaction, index: usize, spent_outputs: &[TxOut], precomputed: &PrecomputedTx, flags: ScriptFlags) -> Result<(), ScriptError> {
    let checker = TxChecker { tx, input_index: index, amount: spent_outputs[index].value, spent_outputs, precomputed };
    let input = &tx.inputs[index];
    verify_script(&input.script_sig, &spent_outputs[index].script_pubkey, &input.witness, flags, &checker)
}
