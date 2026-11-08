//! Chapter 02 sections 2.8 to 2.11: signature verification with Bitcoin's wrapping rules, on top
//! of libsecp256k1 (through the `secp256k1` crate) exactly as section 2.11 maps them:
//!
//! | spec                  | libsecp256k1 |
//! |-----------------------|--------------|
//! | `parse_pubkey`        | first byte and exact length checked here, then `secp256k1_ec_pubkey_parse` |
//! | `parse_der_lax`       | implemented here from the reference (never a strict DER parser) |
//! | `ecdsa_verify`        | `secp256k1_ecdsa_signature_normalize`, then `secp256k1_ecdsa_verify` |
//! | `schnorr_verify`      | `secp256k1_xonly_pubkey_parse`, then `secp256k1_schnorrsig_verify` |
//! | `taproot_tweak_check` | `secp256k1_xonly_pubkey_parse`, then `secp256k1_xonly_pubkey_tweak_add_check` |

use crate::hashes::tagged_writer;
use crate::util::Hash256;
use secp256k1::{ecdsa, schnorr, Message, Parity, PublicKey, Scalar, XOnlyPublicKey, SECP256K1};

/// Parses a public key exactly as Bitcoin Core does (`CPubKey::GetLen`, `CPubKey::Set`, then
/// `secp256k1_ec_pubkey_parse`, which accepts hybrid keys whose parity byte matches).
pub fn parse_pubkey(bytes: &[u8]) -> Option<PublicKey> {
    let expected_length = match bytes.first()? {
        0x02 | 0x03 => 33,
        0x04 | 0x06 | 0x07 => 65,
        _ => return None,
    };
    if bytes.len() != expected_length {
        return None;
    }
    PublicKey::from_slice(bytes).ok()
}

/// True if `n` (32 bytes, big-endian) is below the group order.
fn below_group_order(value: &[u8]) -> bool {
    const CURVE_N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc,
        0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ];
    value < &CURVE_N[..]
}

/// Lenient DER parsing (Core: `ecdsa_signature_parse_der_lax`). `None` means the parse failed;
/// otherwise the 64-byte compact `r || s`, which is all zeros for a signature that parsed but
/// cannot verify (a component longer than 32 bytes or not below the group order).
pub fn parse_der_lax(input: &[u8]) -> Option<[u8; 64]> {
    let len = input.len();
    let mut pos = 0usize;

    // Sequence tag and (ignored) sequence length.
    if pos == len || input[pos] != 0x30 {
        return None;
    }
    pos += 1;
    if pos == len {
        return None;
    }
    let mut lenbyte = input[pos] as usize;
    pos += 1;
    if lenbyte & 0x80 != 0 {
        lenbyte -= 0x80;
        if lenbyte > len - pos {
            return None;
        }
        pos += lenbyte;
    }

    // Reads an INTEGER header and returns (start, length) of its content.
    fn integer(input: &[u8], pos: &mut usize) -> Option<(usize, usize)> {
        let len = input.len();
        if *pos == len || input[*pos] != 0x02 {
            return None;
        }
        *pos += 1;
        if *pos == len {
            return None;
        }
        let mut lenbyte = input[*pos] as usize;
        *pos += 1;
        let content_length;
        if lenbyte & 0x80 != 0 {
            lenbyte -= 0x80;
            if lenbyte > len - *pos {
                return None;
            }
            while lenbyte > 0 && input[*pos] == 0 {
                *pos += 1;
                lenbyte -= 1;
            }
            if lenbyte >= 4 {
                return None;
            }
            let mut value = 0usize;
            while lenbyte > 0 {
                value = (value << 8) + input[*pos] as usize;
                *pos += 1;
                lenbyte -= 1;
            }
            content_length = value;
        } else {
            content_length = lenbyte;
        }
        if content_length > len - *pos {
            return None;
        }
        Some((*pos, content_length))
    }

    let (mut r_pos, mut r_len) = integer(input, &mut pos)?;
    pos += r_len;
    let (mut s_pos, mut s_len) = integer(input, &mut pos)?;

    let mut compact = [0u8; 64];
    let mut overflow = false;
    while r_len > 0 && input[r_pos] == 0 {
        r_len -= 1;
        r_pos += 1;
    }
    if r_len > 32 {
        overflow = true;
    } else {
        compact[32 - r_len..32].copy_from_slice(&input[r_pos..r_pos + r_len]);
    }
    while s_len > 0 && input[s_pos] == 0 {
        s_len -= 1;
        s_pos += 1;
    }
    if s_len > 32 {
        overflow = true;
    } else {
        compact[64 - s_len..64].copy_from_slice(&input[s_pos..s_pos + s_len]);
    }
    if overflow || !below_group_order(&compact[0..32]) || !below_group_order(&compact[32..64]) {
        return Some([0u8; 64]);
    }
    Some(compact)
}

/// ECDSA verification with Bitcoin's wrapping rules. `signature` excludes the hash type byte.
/// Core: `CPubKey::Verify`.
pub fn ecdsa_verify(pubkey: &[u8], signature: &[u8], message: &Hash256) -> bool {
    let key = match parse_pubkey(pubkey) {
        Some(key) => key,
        None => return false,
    };
    let compact = match parse_der_lax(signature) {
        Some(compact) => compact,
        None => return false,
    };
    // r or s zero never verifies (this includes the (0, 0) result of an overflowing component).
    if compact[0..32].iter().all(|&b| b == 0) || compact[32..64].iter().all(|&b| b == 0) {
        return false;
    }
    let mut sig = match ecdsa::Signature::from_compact(&compact) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    sig.normalize_s();
    SECP256K1.verify_ecdsa(Message::from_digest(*message), &sig, &key).is_ok()
}

/// BIP340 verification of a message of any length. Returns false for malformed inputs.
pub fn schnorr_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if pubkey.len() != 32 || signature.len() != 64 {
        return false;
    }
    let key = match XOnlyPublicKey::from_byte_array(pubkey.try_into().unwrap()) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let sig = schnorr::Signature::from_byte_array(signature.try_into().unwrap());
    SECP256K1.verify_schnorr(&sig, message, &key).is_ok()
}

/// True if `bytes` is a valid x-only public key. Core: `XOnlyPublicKey::IsFullyValid`.
pub fn xonly_pubkey_valid(bytes: &[u8]) -> bool {
    match <[u8; 32]>::try_from(bytes) {
        Ok(array) => XOnlyPublicKey::from_byte_array(array).is_ok(),
        Err(_) => false,
    }
}

/// Core: `XOnlyPublicKey::CheckTapTweak`. The output key is compared as bytes: a key that does
/// not parse as an x-only key can never equal the x-coordinate of a computed point, so rejecting it
/// up front gives the same result as libsecp256k1's byte comparison.
pub fn taproot_tweak_check(output_key: &[u8], parity_odd: bool, internal_key: &[u8], merkle_root: &Hash256) -> bool {
    if internal_key.len() != 32 || output_key.len() != 32 {
        return false;
    }
    let internal = match XOnlyPublicKey::from_byte_array(internal_key.try_into().unwrap()) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let mut writer = tagged_writer("TapTweak");
    writer.write(internal_key);
    writer.write(merkle_root);
    let tweak = match Scalar::from_be_bytes(writer.finish()) {
        Ok(tweak) => tweak,
        Err(_) => return false,
    };
    let output = match XOnlyPublicKey::from_byte_array(output_key.try_into().unwrap()) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let parity = if parity_odd { Parity::Odd } else { Parity::Even };
    internal.tweak_add_check(SECP256K1, &output, parity, tweak)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    #[test]
    fn hybrid_keys_parse_with_matching_parity() {
        // Generator point, uncompressed (y is even).
        let g = hex_decode("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap();
        assert!(parse_pubkey(&g).is_some());
        let mut hybrid_even = g.clone();
        hybrid_even[0] = 0x06;
        assert!(parse_pubkey(&hybrid_even).is_some());
        let mut hybrid_odd = g.clone();
        hybrid_odd[0] = 0x07;
        assert!(parse_pubkey(&hybrid_odd).is_none());
        let mut wrong_length = g.clone();
        wrong_length[0] = 0x02;
        assert!(parse_pubkey(&wrong_length).is_none());
        assert!(parse_pubkey(&[]).is_none());
    }

    #[test]
    fn lax_der_overflow_parses_as_zero() {
        // R of 33 non-zero bytes: parses, but as (0, 0).
        let mut sig = vec![0x30, 0x45, 0x02, 0x21];
        sig.extend_from_slice(&[0x01; 33]);
        sig.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert_eq!(parse_der_lax(&sig), Some([0u8; 64]));
        assert_eq!(parse_der_lax(&[0x30]), None);
    }
}
