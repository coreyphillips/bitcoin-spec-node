//! Chapter 01: conventions (hex, hash display order, failure kinds, money range).

/// Lowercase hexadecimal encoding of a byte string.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes hexadecimal text (either case). Returns `None` for odd length or a non-hex character.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// A 32-byte hash in raw order.
pub type Hash256 = [u8; 32];

/// The all-zero hash.
pub const ZERO_HASH: Hash256 = [0u8; 32];

/// Display order (Bitcoin Core's `uint256::GetHex`): reversed bytes, lowercase hex.
pub fn hash_to_display(hash: &Hash256) -> String {
    let mut reversed = *hash;
    reversed.reverse();
    hex_encode(&reversed)
}

/// Parses a display-order hash back to raw order.
pub fn hash_from_display(text: &str) -> Option<Hash256> {
    let bytes = hex_decode(text)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    for i in 0..32 {
        hash[i] = bytes[31 - i];
    }
    Some(hash)
}

/// What a node may remember about a failed block or header (chapter 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// Breaks a consensus rule. The hash, and every descendant, is invalid forever.
    Invalid,
    /// The body does not match the header's commitments. Nothing about the hash may be recorded.
    Mutated,
    /// Rejected only because of the current time. Nothing may be recorded.
    Temporary,
}

/// A validation failure: what kind it is, and Bitcoin Core's identifier for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub kind: FailureKind,
    pub reason: String,
}

pub fn invalid(reason: &str) -> Failure {
    Failure { kind: FailureKind::Invalid, reason: reason.to_string() }
}

pub fn mutated(reason: &str) -> Failure {
    Failure { kind: FailureKind::Mutated, reason: reason.to_string() }
}

pub fn temporary(reason: &str) -> Failure {
    Failure { kind: FailureKind::Temporary, reason: reason.to_string() }
}

/// Number of satoshis in one bitcoin.
pub const COIN: i64 = 100_000_000;

/// Upper bound for any single amount and for any sum of amounts. Core: `MAX_MONEY`.
pub const MAX_MONEY: i64 = 21_000_000 * COIN;

/// Core: `MoneyRange`.
pub fn money_range(value: i64) -> bool {
    (0..=MAX_MONEY).contains(&value)
}
