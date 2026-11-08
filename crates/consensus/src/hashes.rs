//! Chapter 02 sections 2.1 to 2.4: hash functions.
//!
//! The specification's reference implements SHA-256, SHA-1 and RIPEMD-160 itself; any correct
//! implementation may be used (chapter 02 introduction, Appendix B.3). This module uses the
//! RustCrypto crates (hardware SHA-256 on aarch64) and keeps the reference's function names.

use crate::util::Hash256;
use sha2::Digest;
use std::sync::OnceLock;

/// SHA-256 (FIPS 180-4).
#[inline]
pub fn sha256(data: &[u8]) -> Hash256 {
    sha2::Sha256::digest(data).into()
}

/// SHA-256 applied twice. Core: `Hash` / `CHash256`.
#[inline]
pub fn sha256d(data: &[u8]) -> Hash256 {
    sha256(&sha256(data))
}

/// SHA-1 (FIPS 180-4). Used only by `OP_SHA1`.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    sha1::Sha1::digest(data).into()
}

/// RIPEMD-160.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    ripemd::Ripemd160::digest(data).into()
}

/// RIPEMD-160 of SHA-256. Core: `Hash160`.
#[inline]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

/// Incremental SHA-256 used to hash data that is spread over several slices.
#[derive(Clone, Default)]
pub struct Sha256Writer(sha2::Sha256);

impl Sha256Writer {
    pub fn new() -> Sha256Writer {
        Sha256Writer(sha2::Sha256::new())
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Single SHA-256 of everything written.
    pub fn finish(self) -> Hash256 {
        self.0.finalize().into()
    }

    /// SHA-256 applied twice to everything written.
    pub fn finish_double(self) -> Hash256 {
        sha256(&self.finish())
    }
}

/// The tags used by consensus. Their prefixes `SHA256(tag) || SHA256(tag)` fill exactly one
/// SHA-256 block, so the state after absorbing them is cached.
const KNOWN_TAGS: [&str; 5] = ["TapLeaf", "TapBranch", "TapTweak", "TapSighash", "BIP0340/challenge"];

fn tag_states() -> &'static [sha2::Sha256; 5] {
    static STATES: OnceLock<[sha2::Sha256; 5]> = OnceLock::new();
    STATES.get_or_init(|| {
        KNOWN_TAGS.map(|tag| {
            let tag_hash = sha256(tag.as_bytes());
            let mut state = sha2::Sha256::new();
            state.update(tag_hash);
            state.update(tag_hash);
            state
        })
    })
}

/// A SHA-256 state primed with the prefix of a tagged hash.
pub fn tagged_writer(tag: &str) -> Sha256Writer {
    if let Some(position) = KNOWN_TAGS.iter().position(|known| *known == tag) {
        return Sha256Writer(tag_states()[position].clone());
    }
    let tag_hash = sha256(tag.as_bytes());
    let mut state = sha2::Sha256::new();
    state.update(tag_hash);
    state.update(tag_hash);
    Sha256Writer(state)
}

/// BIP340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || data)`. Core: `TaggedHash`.
pub fn tagged_hash(tag: &str, data: &[u8]) -> Hash256 {
    let mut writer = tagged_writer(tag);
    writer.write(data);
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_encode;

    #[test]
    fn hash_known_answers() {
        assert_eq!(hex_encode(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex_encode(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex_encode(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(hex_encode(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex_encode(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex_encode(&ripemd160(b"")), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        assert_eq!(hex_encode(&ripemd160(b"abc")), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        assert_eq!(hex_encode(&ripemd160(b"message digest")), "5d0689ef49d2fae572b881b123a85ffa21595f36");
        assert_eq!(
            hex_encode(&ripemd160(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
        );
    }

    #[test]
    fn tagged_hash_matches_definition() {
        for tag in KNOWN_TAGS.iter().copied().chain(["other tag"]) {
            let tag_hash = sha256(tag.as_bytes());
            let mut data = tag_hash.to_vec();
            data.extend_from_slice(&tag_hash);
            data.extend_from_slice(b"payload");
            assert_eq!(tagged_hash(tag, b"payload"), sha256(&data));
        }
    }
}
