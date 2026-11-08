//! Chapter 04: script encoding, numbers, templates and signature operation counting.

pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_RESERVED: u8 = 0x50;
pub const OP_1: u8 = 0x51;
pub const OP_16: u8 = 0x60;
pub const OP_NOP: u8 = 0x61;
pub const OP_VER: u8 = 0x62;
pub const OP_IF: u8 = 0x63;
pub const OP_NOTIF: u8 = 0x64;
pub const OP_VERIF: u8 = 0x65;
pub const OP_VERNOTIF: u8 = 0x66;
pub const OP_ELSE: u8 = 0x67;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_VERIFY: u8 = 0x69;
pub const OP_RETURN: u8 = 0x6a;
pub const OP_TOALTSTACK: u8 = 0x6b;
pub const OP_FROMALTSTACK: u8 = 0x6c;
pub const OP_2DROP: u8 = 0x6d;
pub const OP_2DUP: u8 = 0x6e;
pub const OP_3DUP: u8 = 0x6f;
pub const OP_2OVER: u8 = 0x70;
pub const OP_2ROT: u8 = 0x71;
pub const OP_2SWAP: u8 = 0x72;
pub const OP_IFDUP: u8 = 0x73;
pub const OP_DEPTH: u8 = 0x74;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_NIP: u8 = 0x77;
pub const OP_OVER: u8 = 0x78;
pub const OP_PICK: u8 = 0x79;
pub const OP_ROLL: u8 = 0x7a;
pub const OP_ROT: u8 = 0x7b;
pub const OP_SWAP: u8 = 0x7c;
pub const OP_TUCK: u8 = 0x7d;
pub const OP_CAT: u8 = 0x7e;
pub const OP_SUBSTR: u8 = 0x7f;
pub const OP_LEFT: u8 = 0x80;
pub const OP_RIGHT: u8 = 0x81;
pub const OP_SIZE: u8 = 0x82;
pub const OP_INVERT: u8 = 0x83;
pub const OP_AND: u8 = 0x84;
pub const OP_OR: u8 = 0x85;
pub const OP_XOR: u8 = 0x86;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_RESERVED1: u8 = 0x89;
pub const OP_RESERVED2: u8 = 0x8a;
pub const OP_1ADD: u8 = 0x8b;
pub const OP_1SUB: u8 = 0x8c;
pub const OP_2MUL: u8 = 0x8d;
pub const OP_2DIV: u8 = 0x8e;
pub const OP_NEGATE: u8 = 0x8f;
pub const OP_ABS: u8 = 0x90;
pub const OP_NOT: u8 = 0x91;
pub const OP_0NOTEQUAL: u8 = 0x92;
pub const OP_ADD: u8 = 0x93;
pub const OP_SUB: u8 = 0x94;
pub const OP_MUL: u8 = 0x95;
pub const OP_DIV: u8 = 0x96;
pub const OP_MOD: u8 = 0x97;
pub const OP_LSHIFT: u8 = 0x98;
pub const OP_RSHIFT: u8 = 0x99;
pub const OP_BOOLAND: u8 = 0x9a;
pub const OP_BOOLOR: u8 = 0x9b;
pub const OP_NUMEQUAL: u8 = 0x9c;
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
pub const OP_NUMNOTEQUAL: u8 = 0x9e;
pub const OP_LESSTHAN: u8 = 0x9f;
pub const OP_GREATERTHAN: u8 = 0xa0;
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
pub const OP_MIN: u8 = 0xa3;
pub const OP_MAX: u8 = 0xa4;
pub const OP_WITHIN: u8 = 0xa5;
pub const OP_RIPEMD160: u8 = 0xa6;
pub const OP_SHA1: u8 = 0xa7;
pub const OP_SHA256: u8 = 0xa8;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_HASH256: u8 = 0xaa;
pub const OP_CODESEPARATOR: u8 = 0xab;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CHECKMULTISIG: u8 = 0xae;
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
pub const OP_NOP1: u8 = 0xb0;
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
pub const OP_NOP4: u8 = 0xb3;
pub const OP_NOP5: u8 = 0xb4;
pub const OP_NOP6: u8 = 0xb5;
pub const OP_NOP7: u8 = 0xb6;
pub const OP_NOP8: u8 = 0xb7;
pub const OP_NOP9: u8 = 0xb8;
pub const OP_NOP10: u8 = 0xb9;
/// Only defined in tapscript (BIP342).
pub const OP_CHECKSIGADD: u8 = 0xba;
pub const OP_INVALIDOPCODE: u8 = 0xff;

/// Largest data push, and largest stack element. Core: `MAX_SCRIPT_ELEMENT_SIZE`.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// Core: `MAX_OPS_PER_SCRIPT`.
pub const MAX_OPS_PER_SCRIPT: usize = 201;
/// Core: `MAX_PUBKEYS_PER_MULTISIG`.
pub const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;
/// Core: `MAX_SCRIPT_SIZE`.
pub const MAX_SCRIPT_SIZE: usize = 10_000;
/// Core: `MAX_STACK_SIZE`.
pub const MAX_STACK_SIZE: usize = 1000;
/// Core: `LOCKTIME_THRESHOLD`.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// One parsed operation: the opcode, and for pushes the pushed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptOp<'a> {
    pub opcode: u8,
    pub data: &'a [u8],
}

/// Reads the operation at `*pos`. Returns `None` if the script is malformed at this point; the
/// position has then still advanced past the bytes read. Core: `GetScriptOp`.
#[inline]
pub fn get_op<'a>(script: &'a [u8], pos: &mut usize) -> Option<ScriptOp<'a>> {
    if *pos >= script.len() {
        return None;
    }
    let opcode = script[*pos];
    *pos += 1;
    if opcode > OP_PUSHDATA4 {
        return Some(ScriptOp { opcode, data: &[] });
    }
    let size = if opcode < OP_PUSHDATA1 {
        opcode as usize
    } else if opcode == OP_PUSHDATA1 {
        if script.len() - *pos < 1 {
            return None;
        }
        let size = script[*pos] as usize;
        *pos += 1;
        size
    } else if opcode == OP_PUSHDATA2 {
        if script.len() - *pos < 2 {
            return None;
        }
        let size = u16::from_le_bytes([script[*pos], script[*pos + 1]]) as usize;
        *pos += 2;
        size
    } else {
        if script.len() - *pos < 4 {
            return None;
        }
        let size = u32::from_le_bytes([script[*pos], script[*pos + 1], script[*pos + 2], script[*pos + 3]]) as usize;
        *pos += 4;
        size
    };
    if script.len() - *pos < size {
        return None;
    }
    let data = &script[*pos..*pos + size];
    *pos += size;
    Some(ScriptOp { opcode, data })
}

/// `CScript() << data`.
pub fn push_data(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5);
    append_push_data(&mut out, data);
    out
}

/// Appends `CScript() << data` to `out`.
pub fn append_push_data(out: &mut Vec<u8>, data: &[u8]) {
    let size = data.len();
    if size < OP_PUSHDATA1 as usize {
        out.push(size as u8);
    } else if size <= 0xff {
        out.push(OP_PUSHDATA1);
        out.push(size as u8);
    } else if size <= 0xffff {
        out.push(OP_PUSHDATA2);
        out.extend_from_slice(&(size as u16).to_le_bytes());
    } else {
        out.push(OP_PUSHDATA4);
        out.extend_from_slice(&(size as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// `CScript() << n` for an integer.
pub fn push_int(n: i64) -> Vec<u8> {
    if n == -1 || (1..=16).contains(&n) {
        vec![(n + (OP_1 as i64 - 1)) as u8]
    } else if n == 0 {
        vec![OP_0]
    } else {
        push_data(&encode_script_num(n))
    }
}

/// `OP_1`..`OP_16` to 1..16 and `OP_0` to 0. Core: `CScript::DecodeOP_N`.
pub fn decode_op_n(opcode: u8) -> i64 {
    if opcode == OP_0 {
        0
    } else {
        assert!((OP_1..=OP_16).contains(&opcode));
        (opcode - (OP_1 - 1)) as i64
    }
}

/// Default largest script number input, in bytes. Core: `CScriptNum::nDefaultMaxNumSize`.
pub const DEFAULT_MAX_NUM_SIZE: usize = 4;

/// Why a script number could not be decoded. Core: `scriptnum_error`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptNumError {
    Overflow,
    NonMinimal,
}

/// Decodes a script number. Core: `CScriptNum::CScriptNum(const std::vector<unsigned char>&, bool, size_t)`.
pub fn decode_script_num(bytes: &[u8], require_minimal: bool, max_size: usize) -> Result<i64, ScriptNumError> {
    if bytes.len() > max_size {
        return Err(ScriptNumError::Overflow);
    }
    if require_minimal && !bytes.is_empty() {
        let last = bytes[bytes.len() - 1];
        if last & 0x7f == 0 && (bytes.len() <= 1 || bytes[bytes.len() - 2] & 0x80 == 0) {
            return Err(ScriptNumError::NonMinimal);
        }
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut result: i64 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }
    let last = bytes[bytes.len() - 1];
    if last & 0x80 != 0 {
        let mask = !(0x80i64 << (8 * (bytes.len() - 1)));
        return Ok(-(result & mask));
    }
    Ok(result)
}

/// Encodes a script number minimally. Core: `CScriptNum::serialize`.
pub fn encode_script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut out = Vec::with_capacity(9);
    while magnitude != 0 {
        out.push((magnitude & 0xff) as u8);
        magnitude >>= 8;
    }
    let last = out.len() - 1;
    if out[last] & 0x80 != 0 {
        out.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        out[last] |= 0x80;
    }
    out
}

/// Core: `CastToBool`.
#[inline]
pub fn cast_to_bool(element: &[u8]) -> bool {
    for (i, &byte) in element.iter().enumerate() {
        if byte != 0 {
            // Negative zero is false.
            return !(i == element.len() - 1 && byte == 0x80);
        }
    }
    false
}

/// Core: `CScript::IsPayToScriptHash`.
#[inline]
pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == OP_HASH160 && script[1] == 0x14 && script[22] == OP_EQUAL
}

/// Returns (version, program) for a witness program. Core: `CScript::IsWitnessProgram`.
#[inline]
pub fn witness_program(script: &[u8]) -> Option<(u8, &[u8])> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }
    if script[0] != OP_0 && (script[0] < OP_1 || script[0] > OP_16) {
        return None;
    }
    if script[1] as usize + 2 == script.len() {
        return Some((decode_op_n(script[0]) as u8, &script[2..]));
    }
    None
}

/// Core: `CScript::IsPayToAnchor(int, const std::vector<unsigned char>&)`.
pub fn is_pay_to_anchor(version: u8, program: &[u8]) -> bool {
    version == 1 && program == [0x4e, 0x73]
}

/// Core: `CScript::IsUnspendable`.
#[inline]
pub fn is_unspendable(script: &[u8]) -> bool {
    (!script.is_empty() && script[0] == OP_RETURN) || script.len() > MAX_SCRIPT_SIZE
}

/// Core: `CScript::IsPushOnly`.
pub fn is_push_only(script: &[u8]) -> bool {
    let mut pos = 0;
    while pos < script.len() {
        match get_op(script, &mut pos) {
            Some(op) if op.opcode <= OP_16 => {}
            _ => return false,
        }
    }
    true
}

/// Core: `IsOpSuccess`.
pub fn is_op_success(opcode: u8) -> bool {
    opcode == 80
        || opcode == 98
        || (126..=129).contains(&opcode)
        || (131..=134).contains(&opcode)
        || (137..=138).contains(&opcode)
        || (141..=142).contains(&opcode)
        || (149..=153).contains(&opcode)
        || (187..=254).contains(&opcode)
}

/// Core: `CScript::GetSigOpCount(bool)`.
pub fn sig_op_count(script: &[u8], accurate: bool) -> u64 {
    let mut count = 0u64;
    let mut pos = 0;
    let mut last_opcode = OP_INVALIDOPCODE;
    while pos < script.len() {
        let op = match get_op(script, &mut pos) {
            Some(op) => op,
            None => break,
        };
        if op.opcode == OP_CHECKSIG || op.opcode == OP_CHECKSIGVERIFY {
            count += 1;
        } else if op.opcode == OP_CHECKMULTISIG || op.opcode == OP_CHECKMULTISIGVERIFY {
            if accurate && (OP_1..=OP_16).contains(&last_opcode) {
                count += decode_op_n(last_opcode) as u64;
            } else {
                count += MAX_PUBKEYS_PER_MULTISIG as u64;
            }
        }
        last_opcode = op.opcode;
    }
    count
}

/// Sigops of a P2SH redeem script given the spending script_sig; for any other script_pubkey,
/// its own accurate count. Core: `CScript::GetSigOpCount(const CScript& scriptSig)`.
pub fn p2sh_sig_op_count(script_pubkey: &[u8], script_sig: &[u8]) -> u64 {
    if !is_p2sh(script_pubkey) {
        return sig_op_count(script_pubkey, true);
    }
    let mut pos = 0;
    let mut last_data: &[u8] = &[];
    while pos < script_sig.len() {
        let op = match get_op(script_sig, &mut pos) {
            Some(op) => op,
            None => return 0,
        };
        if op.opcode > OP_16 {
            return 0;
        }
        last_data = op.data;
    }
    sig_op_count(last_data, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex_decode, hex_encode};

    #[test]
    fn script_numbers() {
        for (value, bytes) in [(0i64, ""), (1, "01"), (-1, "81"), (127, "7f"), (128, "8000"), (-128, "8080"), (255, "ff00"), (-255, "ff80")] {
            assert_eq!(hex_encode(&encode_script_num(value)), bytes);
            assert_eq!(decode_script_num(&hex_decode(bytes).unwrap(), true, 4), Ok(value));
        }
        assert_eq!(decode_script_num(&[0x01, 0x00], false, 4), Ok(1));
        assert_eq!(decode_script_num(&[0x01, 0x00], true, 4), Err(ScriptNumError::NonMinimal));
        assert_eq!(decode_script_num(&[0, 0, 0, 0, 1], false, 4), Err(ScriptNumError::Overflow));
        assert_eq!(decode_script_num(&[0x80], false, 4), Ok(0));
        assert!(!cast_to_bool(&[0x00, 0x80]));
        assert!(cast_to_bool(&[0x80, 0x00]));
    }

    #[test]
    fn pushes() {
        assert_eq!(push_data(&[]), vec![0x00]);
        assert_eq!(push_int(16), vec![OP_16]);
        assert_eq!(push_int(17), vec![0x01, 0x11]);
        assert_eq!(push_int(-2), vec![0x01, 0x82]);
        assert_eq!(push_data(&[0xaa; 76])[..2], [OP_PUSHDATA1, 76]);
    }
}
