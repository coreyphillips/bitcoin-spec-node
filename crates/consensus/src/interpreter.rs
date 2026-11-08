//! Chapter 05: script execution (`eval_script`).

use crate::crypto::{parse_der_lax, parse_pubkey};
use crate::hashes::{hash160, ripemd160, sha1, sha256, sha256d};
use crate::script::*;
use crate::sighash::{find_and_delete, signature_hash, signature_hash_schnorr, PrecomputedTx};
use crate::tx::{Transaction, TxOut};
use crate::util::Hash256;
use secp256k1::{ecdsa, Message, SECP256K1};

/// A set of script verification flags (Core: `script_verify_flags`).
pub type ScriptFlags = u32;

/// BIP16 pay-to-script-hash.
pub const VERIFY_P2SH: ScriptFlags = 1 << 0;
/// BIP66 strict DER signature encoding.
pub const VERIFY_DERSIG: ScriptFlags = 1 << 2;
/// BIP147 the CHECKMULTISIG dummy element must be empty.
pub const VERIFY_NULLDUMMY: ScriptFlags = 1 << 4;
/// BIP65 OP_CHECKLOCKTIMEVERIFY.
pub const VERIFY_CHECKLOCKTIMEVERIFY: ScriptFlags = 1 << 9;
/// BIP112 OP_CHECKSEQUENCEVERIFY.
pub const VERIFY_CHECKSEQUENCEVERIFY: ScriptFlags = 1 << 10;
/// BIP141/BIP143 segregated witness.
pub const VERIFY_WITNESS: ScriptFlags = 1 << 11;
/// BIP341/BIP342 taproot and tapscript.
pub const VERIFY_TAPROOT: ScriptFlags = 1 << 17;

/// All consensus flags.
pub const CONSENSUS_FLAGS: ScriptFlags =
    VERIFY_P2SH | VERIFY_DERSIG | VERIFY_NULLDUMMY | VERIFY_CHECKLOCKTIMEVERIFY | VERIFY_CHECKSEQUENCEVERIFY | VERIFY_WITNESS | VERIFY_TAPROOT;

/// Name of each consensus flag as used by Bitcoin Core's test data and the conformance protocol.
pub const FLAG_NAMES: [(&str, ScriptFlags); 7] = [
    ("P2SH", VERIFY_P2SH),
    ("DERSIG", VERIFY_DERSIG),
    ("NULLDUMMY", VERIFY_NULLDUMMY),
    ("CHECKLOCKTIMEVERIFY", VERIFY_CHECKLOCKTIMEVERIFY),
    ("CHECKSEQUENCEVERIFY", VERIFY_CHECKSEQUENCEVERIFY),
    ("WITNESS", VERIFY_WITNESS),
    ("TAPROOT", VERIFY_TAPROOT),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigVersion {
    Base,
    WitnessV0,
    Taproot,
    Tapscript,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptError {
    UnknownError,
    EvalFalse,
    OpReturn,
    ScriptNum,
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    NegativeLocktime,
    UnsatisfiedLocktime,
    SigDer,
    SigPushOnly,
    SigNullDummy,
    CleanStack,
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2sh,
    WitnessUnexpected,
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckmultisig,
    TapscriptMinimalif,
    TapscriptEmptyPubkey,
}

impl ScriptError {
    /// Identifier used by Bitcoin Core's test data and by the conformance protocol.
    pub fn name(&self) -> &'static str {
        match self {
            ScriptError::UnknownError => "UNKNOWN_ERROR",
            ScriptError::EvalFalse => "EVAL_FALSE",
            ScriptError::OpReturn => "OP_RETURN",
            ScriptError::ScriptNum => "SCRIPTNUM",
            ScriptError::ScriptSize => "SCRIPT_SIZE",
            ScriptError::PushSize => "PUSH_SIZE",
            ScriptError::OpCount => "OP_COUNT",
            ScriptError::StackSize => "STACK_SIZE",
            ScriptError::SigCount => "SIG_COUNT",
            ScriptError::PubkeyCount => "PUBKEY_COUNT",
            ScriptError::Verify => "VERIFY",
            ScriptError::EqualVerify => "EQUALVERIFY",
            ScriptError::CheckMultisigVerify => "CHECKMULTISIGVERIFY",
            ScriptError::CheckSigVerify => "CHECKSIGVERIFY",
            ScriptError::NumEqualVerify => "NUMEQUALVERIFY",
            ScriptError::BadOpcode => "BAD_OPCODE",
            ScriptError::DisabledOpcode => "DISABLED_OPCODE",
            ScriptError::InvalidStackOperation => "INVALID_STACK_OPERATION",
            ScriptError::InvalidAltstackOperation => "INVALID_ALTSTACK_OPERATION",
            ScriptError::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            ScriptError::NegativeLocktime => "NEGATIVE_LOCKTIME",
            ScriptError::UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
            ScriptError::SigDer => "SIG_DER",
            ScriptError::SigPushOnly => "SIG_PUSHONLY",
            ScriptError::SigNullDummy => "SIG_NULLDUMMY",
            ScriptError::CleanStack => "CLEANSTACK",
            ScriptError::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            ScriptError::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            ScriptError::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            ScriptError::WitnessMalleated => "WITNESS_MALLEATED",
            ScriptError::WitnessMalleatedP2sh => "WITNESS_MALLEATED_P2SH",
            ScriptError::WitnessUnexpected => "WITNESS_UNEXPECTED",
            ScriptError::SchnorrSigSize => "SCHNORR_SIG_SIZE",
            ScriptError::SchnorrSigHashtype => "SCHNORR_SIG_HASHTYPE",
            ScriptError::SchnorrSig => "SCHNORR_SIG",
            ScriptError::TaprootWrongControlSize => "TAPROOT_WRONG_CONTROL_SIZE",
            ScriptError::TapscriptValidationWeight => "TAPSCRIPT_VALIDATION_WEIGHT",
            ScriptError::TapscriptCheckmultisig => "TAPSCRIPT_CHECKMULTISIG",
            ScriptError::TapscriptMinimalif => "TAPSCRIPT_MINIMALIF",
            ScriptError::TapscriptEmptyPubkey => "TAPSCRIPT_EMPTY_PUBKEY",
        }
    }

    /// Bitcoin Core's description (`ScriptErrorString`), used inside block reject reasons.
    pub fn message(&self) -> &'static str {
        match self {
            ScriptError::UnknownError => "unknown error",
            ScriptError::EvalFalse => "Script evaluated without error but finished with a false/empty top stack element",
            ScriptError::OpReturn => "OP_RETURN was encountered",
            ScriptError::ScriptNum => "Script number overflowed or is non-minimally encoded",
            ScriptError::ScriptSize => "Script is too big",
            ScriptError::PushSize => "Push value size limit exceeded",
            ScriptError::OpCount => "Operation limit exceeded",
            ScriptError::StackSize => "Stack size limit exceeded",
            ScriptError::SigCount => "Signature count negative or greater than pubkey count",
            ScriptError::PubkeyCount => "Pubkey count negative or limit exceeded",
            ScriptError::Verify => "Script failed an OP_VERIFY operation",
            ScriptError::EqualVerify => "Script failed an OP_EQUALVERIFY operation",
            ScriptError::CheckMultisigVerify => "Script failed an OP_CHECKMULTISIGVERIFY operation",
            ScriptError::CheckSigVerify => "Script failed an OP_CHECKSIGVERIFY operation",
            ScriptError::NumEqualVerify => "Script failed an OP_NUMEQUALVERIFY operation",
            ScriptError::BadOpcode => "Opcode missing or not understood",
            ScriptError::DisabledOpcode => "Attempted to use a disabled opcode",
            ScriptError::InvalidStackOperation => "Operation not valid with the current stack size",
            ScriptError::InvalidAltstackOperation => "Operation not valid with the current altstack size",
            ScriptError::UnbalancedConditional => "Invalid OP_IF construction",
            ScriptError::NegativeLocktime => "Negative locktime",
            ScriptError::UnsatisfiedLocktime => "Locktime requirement not satisfied",
            ScriptError::SigDer => "Non-canonical DER signature",
            ScriptError::SigPushOnly => "Only push operators allowed in signatures",
            ScriptError::SigNullDummy => "Dummy CHECKMULTISIG argument must be zero",
            ScriptError::CleanStack => "Stack size must be exactly one after execution",
            ScriptError::WitnessProgramWrongLength => "Witness program has incorrect length",
            ScriptError::WitnessProgramWitnessEmpty => "Witness program was passed an empty witness",
            ScriptError::WitnessProgramMismatch => "Witness program hash mismatch",
            ScriptError::WitnessMalleated => "Witness requires empty scriptSig",
            ScriptError::WitnessMalleatedP2sh => "Witness requires only-redeemscript scriptSig",
            ScriptError::WitnessUnexpected => "Witness provided for non-witness script",
            ScriptError::SchnorrSigSize => "Invalid Schnorr signature size",
            ScriptError::SchnorrSigHashtype => "Invalid Schnorr signature hash type",
            ScriptError::SchnorrSig => "Invalid Schnorr signature",
            ScriptError::TaprootWrongControlSize => "Invalid Taproot control block size",
            ScriptError::TapscriptValidationWeight => "Too much signature validation relative to witness weight",
            ScriptError::TapscriptCheckmultisig => "OP_CHECKMULTISIG(VERIFY) is not available in tapscript",
            ScriptError::TapscriptMinimalif => "OP_IF/NOTIF argument must be minimal in tapscript",
            ScriptError::TapscriptEmptyPubkey => "Empty public key in tapscript",
        }
    }
}

/// Script number decoding failures abort execution with `SCRIPTNUM`.
#[inline]
fn script_num(bytes: &[u8], max_size: usize) -> Result<i64, ScriptError> {
    decode_script_num(bytes, false, max_size).map_err(|_| ScriptError::ScriptNum)
}

/// The transaction context of a script execution (chapter 05 section 5.3).
pub struct TxChecker<'a> {
    pub tx: &'a Transaction,
    pub input_index: usize,
    /// Value of the output being spent by this input.
    pub amount: i64,
    /// The outputs spent by every input of `tx`, in input order.
    pub spent_outputs: &'a [TxOut],
    pub precomputed: &'a PrecomputedTx,
}

/// Per-input taproot execution state. Core: `ScriptExecutionData`.
#[derive(Clone, Debug, Default)]
pub struct ExecData {
    /// SHA256 of the serialized annex, if the witness has one.
    pub annex_hash: Option<Hash256>,
    /// Tapleaf hash of the executing tapscript.
    pub tapleaf_hash: Option<Hash256>,
    /// Opcode position of the last executed OP_CODESEPARATOR, or 0xffffffff.
    pub codeseparator_pos: u32,
    /// Remaining tapscript validation weight budget.
    pub validation_weight_left: i64,
}

/// Core: `CTxIn::SEQUENCE_FINAL`.
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;
/// Core: `CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG`.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
/// Core: `CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG`.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
/// Core: `CTxIn::SEQUENCE_LOCKTIME_MASK`.
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

impl<'a> TxChecker<'a> {
    /// Core: `GenericTransactionSignatureChecker::CheckLockTime`.
    pub fn check_lock_time(&self, lock_time: i64) -> bool {
        let tx_lock_time = self.tx.lock_time as i64;
        let threshold = LOCKTIME_THRESHOLD as i64;
        if !((tx_lock_time < threshold && lock_time < threshold) || (tx_lock_time >= threshold && lock_time >= threshold)) {
            return false;
        }
        if lock_time > tx_lock_time {
            return false;
        }
        if self.tx.inputs[self.input_index].sequence == SEQUENCE_FINAL {
            return false;
        }
        true
    }

    /// Core: `GenericTransactionSignatureChecker::CheckSequence`.
    pub fn check_sequence(&self, sequence: i64) -> bool {
        let tx_sequence = self.tx.inputs[self.input_index].sequence as i64;
        if self.tx.version < 2 {
            return false;
        }
        if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG as i64 != 0 {
            return false;
        }
        let mask = (SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK) as i64;
        let tx_masked = tx_sequence & mask;
        let operand_masked = sequence & mask;
        let type_flag = SEQUENCE_LOCKTIME_TYPE_FLAG as i64;
        if !((tx_masked < type_flag && operand_masked < type_flag) || (tx_masked >= type_flag && operand_masked >= type_flag)) {
            return false;
        }
        operand_masked <= tx_masked
    }

    /// Core: `GenericTransactionSignatureChecker::CheckECDSASignature`.
    pub fn check_ecdsa_signature(&self, sig: &[u8], pubkey: &[u8], script_code: &[u8], sigversion: SigVersion) -> bool {
        let key = match parse_pubkey(pubkey) {
            Some(key) => key,
            None => return false,
        };
        if sig.is_empty() {
            return false;
        }
        let hash_type = sig[sig.len() - 1] as i32;
        let der = &sig[..sig.len() - 1];
        if sigversion == SigVersion::WitnessV0 && self.amount < 0 {
            return false;
        }
        // Parse the signature before hashing; a parse failure is a false result either way.
        let compact = match parse_der_lax(der) {
            Some(compact) => compact,
            None => return false,
        };
        if compact[0..32].iter().all(|&b| b == 0) || compact[32..64].iter().all(|&b| b == 0) {
            return false;
        }
        let mut signature = match ecdsa::Signature::from_compact(&compact) {
            Ok(signature) => signature,
            Err(_) => return false,
        };
        signature.normalize_s();
        let sighash = signature_hash(script_code, self.tx, self.input_index, hash_type, self.amount, sigversion, self.precomputed);
        SECP256K1.verify_ecdsa(Message::from_digest(sighash), &signature, &key).is_ok()
    }

    /// Core: `GenericTransactionSignatureChecker::CheckSchnorrSignature`.
    pub fn check_schnorr_signature(&self, sig: &[u8], pubkey: &[u8], sigversion: SigVersion, execdata: &ExecData) -> Result<(), ScriptError> {
        assert!(pubkey.len() == 32);
        if sig.len() != 64 && sig.len() != 65 {
            return Err(ScriptError::SchnorrSigSize);
        }
        let mut hash_type = 0u8;
        let mut sig = sig;
        if sig.len() == 65 {
            hash_type = sig[64];
            sig = &sig[..64];
            if hash_type == 0 {
                return Err(ScriptError::SchnorrSigHashtype);
            }
        }
        let sighash = match signature_hash_schnorr(execdata, self.tx, self.input_index, hash_type, sigversion, self.spent_outputs, self.precomputed) {
            Some(hash) => hash,
            None => return Err(ScriptError::SchnorrSigHashtype),
        };
        if !crate::crypto::schnorr_verify(pubkey, &sighash, sig) {
            return Err(ScriptError::SchnorrSig);
        }
        Ok(())
    }
}

/// BIP66 strict DER encoding, including the trailing hash type byte. Core: `IsValidSignatureEncoding`.
pub fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }
    if sig[0] != 0x30 {
        return false;
    }
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }
    let len_r = sig[3] as usize;
    if 5 + len_r >= sig.len() {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != sig.len() {
        return false;
    }
    if sig[2] != 0x02 || len_r == 0 || sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 || len_s == 0 || sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }
    true
}

/// Core: `EvalChecksigPreTapscript` (with policy flags omitted).
fn eval_checksig_pre_tapscript(
    sig: &[u8],
    pubkey: &[u8],
    script_code_start: &[u8],
    flags: ScriptFlags,
    checker: &TxChecker,
    sigversion: SigVersion,
) -> Result<bool, ScriptError> {
    if sigversion == SigVersion::Base {
        let script_code = find_and_delete(script_code_start, &push_data(sig));
        if flags & VERIFY_DERSIG != 0 && !sig.is_empty() && !is_valid_signature_encoding(sig) {
            return Err(ScriptError::SigDer);
        }
        return Ok(checker.check_ecdsa_signature(sig, pubkey, &script_code, sigversion));
    }
    if flags & VERIFY_DERSIG != 0 && !sig.is_empty() && !is_valid_signature_encoding(sig) {
        return Err(ScriptError::SigDer);
    }
    Ok(checker.check_ecdsa_signature(sig, pubkey, script_code_start, sigversion))
}

/// Core: `VALIDATION_WEIGHT_PER_SIGOP_PASSED`.
pub const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;
/// Core: `VALIDATION_WEIGHT_OFFSET`.
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Core: `EvalChecksigTapscript` (with policy flags omitted).
fn eval_checksig_tapscript(sig: &[u8], pubkey: &[u8], execdata: &mut ExecData, checker: &TxChecker) -> Result<bool, ScriptError> {
    let success = !sig.is_empty();
    if success {
        execdata.validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
        if execdata.validation_weight_left < 0 {
            return Err(ScriptError::TapscriptValidationWeight);
        }
    }
    if pubkey.is_empty() {
        return Err(ScriptError::TapscriptEmptyPubkey);
    } else if pubkey.len() == 32 && success {
        checker.check_schnorr_signature(sig, pubkey, SigVersion::Tapscript, execdata)?;
    }
    Ok(success)
}

/// O(1) record of nested IF branches. Core: `ConditionStack`.
struct ConditionStack {
    size: usize,
    first_false: Option<usize>,
}

impl ConditionStack {
    fn new() -> ConditionStack {
        ConditionStack { size: 0, first_false: None }
    }
    fn is_empty(&self) -> bool {
        self.size == 0
    }
    fn all_true(&self) -> bool {
        self.first_false.is_none()
    }
    fn push(&mut self, value: bool) {
        if self.first_false.is_none() && !value {
            self.first_false = Some(self.size);
        }
        self.size += 1;
    }
    fn pop(&mut self) {
        self.size -= 1;
        if self.first_false == Some(self.size) {
            self.first_false = None;
        }
    }
    fn toggle_top(&mut self) {
        match self.first_false {
            None => self.first_false = Some(self.size - 1),
            Some(position) if position == self.size - 1 => self.first_false = None,
            Some(_) => {}
        }
    }
}

fn is_disabled_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        OP_CAT | OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR | OP_2MUL | OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT
    )
}

/// The element `depth` places from the top (1 is the top). The caller has checked the stack size.
#[inline]
fn top(stack: &[Vec<u8>], depth: usize) -> &Vec<u8> {
    &stack[stack.len() - depth]
}

#[inline]
fn bool_element(value: bool) -> Vec<u8> {
    if value {
        vec![1]
    } else {
        Vec::new()
    }
}

/// Executes `script` on `stack`. Core: `EvalScript`.
pub fn eval_script(
    stack: &mut Vec<Vec<u8>>,
    script: &[u8],
    flags: ScriptFlags,
    checker: &TxChecker,
    sigversion: SigVersion,
    execdata: &mut ExecData,
) -> Result<(), ScriptError> {
    assert!(sigversion != SigVersion::Taproot);
    let legacy_limits = sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0;
    if legacy_limits && script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }
    let mut pos = 0usize;
    let mut code_start = 0usize;
    let mut exec_stack = ConditionStack::new();
    let mut altstack: Vec<Vec<u8>> = Vec::new();
    let mut op_count = 0usize;
    let mut opcode_pos: u32 = 0;
    execdata.codeseparator_pos = 0xffff_ffff;

    while pos < script.len() {
        let executing = exec_stack.all_true();
        let op = match get_op(script, &mut pos) {
            Some(op) => op,
            None => return Err(ScriptError::BadOpcode),
        };
        let opcode = op.opcode;
        if op.data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
        if legacy_limits && opcode > OP_16 {
            op_count += 1;
            if op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptError::OpCount);
            }
        }
        if is_disabled_opcode(opcode) {
            return Err(ScriptError::DisabledOpcode);
        }

        if executing && opcode <= OP_PUSHDATA4 {
            stack.push(op.data.to_vec());
        } else if executing || (OP_IF <= opcode && opcode <= OP_ENDIF) {
            match opcode {
                OP_1NEGATE | OP_1..=OP_16 => {
                    let value = opcode as i64 - (OP_1 as i64 - 1);
                    stack.push(encode_script_num(value));
                }

                OP_NOP => {}

                OP_CHECKLOCKTIMEVERIFY => {
                    if flags & VERIFY_CHECKLOCKTIMEVERIFY != 0 {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let lock_time = script_num(top(stack, 1), 5)?;
                        if lock_time < 0 {
                            return Err(ScriptError::NegativeLocktime);
                        }
                        if !checker.check_lock_time(lock_time) {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                    }
                }

                OP_CHECKSEQUENCEVERIFY => {
                    if flags & VERIFY_CHECKSEQUENCEVERIFY != 0 {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let sequence = script_num(top(stack, 1), 5)?;
                        if sequence < 0 {
                            return Err(ScriptError::NegativeLocktime);
                        }
                        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG as i64 == 0 && !checker.check_sequence(sequence) {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                    }
                }

                OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {}

                OP_IF | OP_NOTIF => {
                    let mut value = false;
                    if executing {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let element = top(stack, 1);
                        if sigversion == SigVersion::Tapscript && (element.len() > 1 || (element.len() == 1 && element[0] != 1)) {
                            return Err(ScriptError::TapscriptMinimalif);
                        }
                        value = cast_to_bool(element);
                        if opcode == OP_NOTIF {
                            value = !value;
                        }
                        stack.pop();
                    }
                    exec_stack.push(value);
                }

                OP_ELSE => {
                    if exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    exec_stack.toggle_top();
                }

                OP_ENDIF => {
                    if exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    exec_stack.pop();
                }

                OP_VERIFY => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    if cast_to_bool(top(stack, 1)) {
                        stack.pop();
                    } else {
                        return Err(ScriptError::Verify);
                    }
                }

                OP_RETURN => return Err(ScriptError::OpReturn),

                OP_TOALTSTACK => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    altstack.push(stack.pop().unwrap());
                }

                OP_FROMALTSTACK => {
                    if altstack.is_empty() {
                        return Err(ScriptError::InvalidAltstackOperation);
                    }
                    stack.push(altstack.pop().unwrap());
                }

                OP_2DROP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    stack.pop();
                    stack.pop();
                }

                OP_2DUP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let a = top(stack, 2).clone();
                    let b = top(stack, 1).clone();
                    stack.push(a);
                    stack.push(b);
                }

                OP_3DUP => {
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let a = top(stack, 3).clone();
                    let b = top(stack, 2).clone();
                    let c = top(stack, 1).clone();
                    stack.push(a);
                    stack.push(b);
                    stack.push(c);
                }

                OP_2OVER => {
                    if stack.len() < 4 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let a = top(stack, 4).clone();
                    let b = top(stack, 3).clone();
                    stack.push(a);
                    stack.push(b);
                }

                OP_2ROT => {
                    if stack.len() < 6 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    let a = stack[len - 6].clone();
                    let b = stack[len - 5].clone();
                    stack.drain(len - 6..len - 4);
                    stack.push(a);
                    stack.push(b);
                }

                OP_2SWAP => {
                    if stack.len() < 4 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.swap(len - 4, len - 2);
                    stack.swap(len - 3, len - 1);
                }

                OP_IFDUP => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let element = top(stack, 1).clone();
                    if cast_to_bool(&element) {
                        stack.push(element);
                    }
                }

                OP_DEPTH => {
                    let depth = stack.len() as i64;
                    stack.push(encode_script_num(depth));
                }

                OP_DROP => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    stack.pop();
                }

                OP_DUP => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let element = top(stack, 1).clone();
                    stack.push(element);
                }

                OP_NIP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.remove(len - 2);
                }

                OP_OVER => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let element = top(stack, 2).clone();
                    stack.push(element);
                }

                OP_PICK | OP_ROLL => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = script_num(top(stack, 1), DEFAULT_MAX_NUM_SIZE)?;
                    stack.pop();
                    if n < 0 || n >= stack.len() as i64 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let index = stack.len() - 1 - n as usize;
                    let element = if opcode == OP_ROLL { stack.remove(index) } else { stack[index].clone() };
                    stack.push(element);
                }

                OP_ROT => {
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.swap(len - 3, len - 2);
                    stack.swap(len - 2, len - 1);
                }

                OP_SWAP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.swap(len - 2, len - 1);
                }

                OP_TUCK => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let element = top(stack, 1).clone();
                    let len = stack.len();
                    stack.insert(len - 2, element);
                }

                OP_SIZE => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let size = top(stack, 1).len() as i64;
                    stack.push(encode_script_num(size));
                }

                OP_EQUAL | OP_EQUALVERIFY => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let equal = top(stack, 2) == top(stack, 1);
                    stack.pop();
                    stack.pop();
                    stack.push(bool_element(equal));
                    if opcode == OP_EQUALVERIFY {
                        if equal {
                            stack.pop();
                        } else {
                            return Err(ScriptError::EqualVerify);
                        }
                    }
                }

                OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = script_num(top(stack, 1), DEFAULT_MAX_NUM_SIZE)?;
                    let result = match opcode {
                        OP_1ADD => n + 1,
                        OP_1SUB => n - 1,
                        OP_NEGATE => -n,
                        OP_ABS => n.abs(),
                        OP_NOT => (n == 0) as i64,
                        _ => (n != 0) as i64,
                    };
                    stack.pop();
                    stack.push(encode_script_num(result));
                }

                OP_ADD | OP_SUB | OP_BOOLAND | OP_BOOLOR | OP_NUMEQUAL | OP_NUMEQUALVERIFY | OP_NUMNOTEQUAL | OP_LESSTHAN | OP_GREATERTHAN
                | OP_LESSTHANOREQUAL | OP_GREATERTHANOREQUAL | OP_MIN | OP_MAX => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let a = script_num(top(stack, 2), DEFAULT_MAX_NUM_SIZE)?;
                    let b = script_num(top(stack, 1), DEFAULT_MAX_NUM_SIZE)?;
                    let result = match opcode {
                        OP_ADD => a + b,
                        OP_SUB => a - b,
                        OP_BOOLAND => (a != 0 && b != 0) as i64,
                        OP_BOOLOR => (a != 0 || b != 0) as i64,
                        OP_NUMEQUAL | OP_NUMEQUALVERIFY => (a == b) as i64,
                        OP_NUMNOTEQUAL => (a != b) as i64,
                        OP_LESSTHAN => (a < b) as i64,
                        OP_GREATERTHAN => (a > b) as i64,
                        OP_LESSTHANOREQUAL => (a <= b) as i64,
                        OP_GREATERTHANOREQUAL => (a >= b) as i64,
                        OP_MIN => a.min(b),
                        _ => a.max(b),
                    };
                    stack.pop();
                    stack.pop();
                    stack.push(encode_script_num(result));
                    if opcode == OP_NUMEQUALVERIFY {
                        if cast_to_bool(top(stack, 1)) {
                            stack.pop();
                        } else {
                            return Err(ScriptError::NumEqualVerify);
                        }
                    }
                }

                OP_WITHIN => {
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let x = script_num(top(stack, 3), DEFAULT_MAX_NUM_SIZE)?;
                    let min = script_num(top(stack, 2), DEFAULT_MAX_NUM_SIZE)?;
                    let max = script_num(top(stack, 1), DEFAULT_MAX_NUM_SIZE)?;
                    let within = min <= x && x < max;
                    stack.pop();
                    stack.pop();
                    stack.pop();
                    stack.push(bool_element(within));
                }

                OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let element = stack.pop().unwrap();
                    let digest = match opcode {
                        OP_RIPEMD160 => ripemd160(&element).to_vec(),
                        OP_SHA1 => sha1(&element).to_vec(),
                        OP_SHA256 => sha256(&element).to_vec(),
                        OP_HASH160 => hash160(&element).to_vec(),
                        _ => sha256d(&element).to_vec(),
                    };
                    stack.push(digest);
                }

                OP_CODESEPARATOR => {
                    code_start = pos;
                    execdata.codeseparator_pos = opcode_pos;
                }

                OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let success = {
                        let sig = top(stack, 2);
                        let pubkey = top(stack, 1);
                        if sigversion == SigVersion::Tapscript {
                            eval_checksig_tapscript(sig, pubkey, execdata, checker)?
                        } else {
                            eval_checksig_pre_tapscript(sig, pubkey, &script[code_start..], flags, checker, sigversion)?
                        }
                    };
                    stack.pop();
                    stack.pop();
                    stack.push(bool_element(success));
                    if opcode == OP_CHECKSIGVERIFY {
                        if success {
                            stack.pop();
                        } else {
                            return Err(ScriptError::CheckSigVerify);
                        }
                    }
                }

                OP_CHECKSIGADD => {
                    if sigversion != SigVersion::Tapscript {
                        return Err(ScriptError::BadOpcode);
                    }
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = script_num(top(stack, 2), DEFAULT_MAX_NUM_SIZE)?;
                    let success = {
                        let sig = top(stack, 3);
                        let pubkey = top(stack, 1);
                        eval_checksig_tapscript(sig, pubkey, execdata, checker)?
                    };
                    stack.pop();
                    stack.pop();
                    stack.pop();
                    stack.push(encode_script_num(n + success as i64));
                }

                OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                    if sigversion == SigVersion::Tapscript {
                        return Err(ScriptError::TapscriptCheckmultisig);
                    }
                    // `i` counts elements from the top, as in Bitcoin Core.
                    let mut i = 1usize;
                    if stack.len() < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let mut keys_count = script_num(top(stack, i), DEFAULT_MAX_NUM_SIZE)?;
                    if !(0..=MAX_PUBKEYS_PER_MULTISIG).contains(&keys_count) {
                        return Err(ScriptError::PubkeyCount);
                    }
                    op_count += keys_count as usize;
                    if op_count > MAX_OPS_PER_SCRIPT {
                        return Err(ScriptError::OpCount);
                    }
                    i += 1;
                    let mut ikey = i;
                    i += keys_count as usize;
                    if stack.len() < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let mut sigs_count = script_num(top(stack, i), DEFAULT_MAX_NUM_SIZE)?;
                    if sigs_count < 0 || sigs_count > keys_count {
                        return Err(ScriptError::SigCount);
                    }
                    i += 1;
                    let mut isig = i;
                    i += sigs_count as usize;
                    // The extra element counted here is the dummy.
                    if stack.len() < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }

                    let mut script_code = std::borrow::Cow::Borrowed(&script[code_start..]);
                    if sigversion == SigVersion::Base {
                        for k in 0..sigs_count as usize {
                            let sig = top(stack, isig + k);
                            let removed = find_and_delete(&script_code, &push_data(sig));
                            if let std::borrow::Cow::Owned(owned) = removed {
                                script_code = std::borrow::Cow::Owned(owned);
                            }
                        }
                    }

                    let mut success = true;
                    while success && sigs_count > 0 {
                        let sig = top(stack, isig);
                        let pubkey = top(stack, ikey);
                        if flags & VERIFY_DERSIG != 0 && !sig.is_empty() && !is_valid_signature_encoding(sig) {
                            return Err(ScriptError::SigDer);
                        }
                        if checker.check_ecdsa_signature(sig, pubkey, &script_code, sigversion) {
                            isig += 1;
                            sigs_count -= 1;
                        }
                        ikey += 1;
                        keys_count -= 1;
                        if sigs_count > keys_count {
                            success = false;
                        }
                    }

                    // Pop everything except the dummy.
                    for _ in 1..i {
                        stack.pop();
                    }
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    if flags & VERIFY_NULLDUMMY != 0 && !top(stack, 1).is_empty() {
                        return Err(ScriptError::SigNullDummy);
                    }
                    stack.pop();
                    stack.push(bool_element(success));
                    if opcode == OP_CHECKMULTISIGVERIFY {
                        if success {
                            stack.pop();
                        } else {
                            return Err(ScriptError::CheckMultisigVerify);
                        }
                    }
                }

                _ => return Err(ScriptError::BadOpcode),
            }
        }

        if stack.len() + altstack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        opcode_pos += 1;
    }

    if !exec_stack.is_empty() {
        return Err(ScriptError::UnbalancedConditional);
    }
    Ok(())
}
