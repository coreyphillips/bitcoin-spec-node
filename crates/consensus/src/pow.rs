//! Chapter 09: proof of work, chain work, median time past, difficulty adjustment.

use crate::params::ConsensusParams;
use crate::tx::BlockHeader;
use crate::uint::U256;
use crate::util::Hash256;

/// Decodes compact bits. Returns (value, negative, overflow). Core: `arith_uint256::SetCompact`.
pub fn compact_to_target(bits: u32) -> (U256, bool, bool) {
    let size = bits >> 24;
    let mut word = bits & 0x007f_ffff;
    let value = if size <= 3 {
        word >>= 8 * (3 - size);
        U256::from_u64(word as u64)
    } else {
        U256::from_u64(word as u64).shl(8 * (size - 3))
    };
    let negative = word != 0 && bits & 0x0080_0000 != 0;
    let overflow = word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    (value, negative, overflow)
}

/// Encodes a target in canonical compact form. Core: `arith_uint256::GetCompact`.
pub fn target_to_compact(target: U256) -> u32 {
    let mut size = target.bits().div_ceil(8);
    let mut compact: u32 = if size <= 3 { (target.low_u64() << (8 * (3 - size))) as u32 } else { target.shr(8 * (size - 3)).low_u64() as u32 };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    compact | (size << 24)
}

/// Core: `DeriveTarget`.
pub fn derive_target(bits: u32, pow_limit: U256) -> Option<U256> {
    let (target, negative, overflow) = compact_to_target(bits);
    if negative || target.is_zero() || overflow || target > pow_limit {
        return None;
    }
    Some(target)
}

/// Core: `CheckProofOfWorkImpl`.
pub fn check_proof_of_work(hash: &Hash256, bits: u32, pow_limit: U256) -> bool {
    match derive_target(bits, pow_limit) {
        Some(target) => U256::from_le_bytes(hash) <= target,
        None => false,
    }
}

/// Core: `GetBitsProof`.
pub fn block_proof(bits: u32) -> U256 {
    let (target, negative, overflow) = compact_to_target(bits);
    if negative || overflow || target.is_zero() {
        return U256::ZERO;
    }
    let (quotient, _) = target.not().div_rem(target.wrapping_add(U256::ONE));
    quotient.wrapping_add(U256::ONE)
}

/// Number of blocks in the median time past window. Core: `CBlockIndex::nMedianTimeSpan`.
pub const MEDIAN_TIME_SPAN: usize = 11;

/// `times` are the timestamps of a block and its predecessors, newest first (at most 11 used).
pub fn median_time_past(times: &[i64]) -> i64 {
    let mut window: Vec<i64> = times.iter().take(MEDIAN_TIME_SPAN).copied().collect();
    window.sort();
    window[window.len() / 2]
}

/// Core: `GetNextWorkRequired`. `ancestor(height)` returns the header of the parent's ancestor at
/// that height; `new_block_time` is the timestamp of the block being checked.
pub fn next_work_required(params: &ConsensusParams, parent_height: i32, parent: &BlockHeader, ancestor: &dyn Fn(i32) -> BlockHeader, new_block_time: u32) -> u32 {
    let pow_limit_bits = target_to_compact(params.pow_limit);
    let interval = params.difficulty_adjustment_interval();
    let height = parent_height as i64 + 1;
    if height % interval != 0 {
        if params.pow_allow_min_difficulty_blocks {
            if new_block_time as i64 > parent.time as i64 + params.pow_target_spacing * 2 {
                return pow_limit_bits;
            }
            let mut index_height = parent_height;
            let mut header = *parent;
            while index_height > 0 && index_height as i64 % interval != 0 && header.bits == pow_limit_bits {
                index_height -= 1;
                header = ancestor(index_height);
            }
            return header.bits;
        }
        return parent.bits;
    }
    let first_height = parent_height - (interval as i32 - 1);
    assert!(first_height >= 0);
    let first = ancestor(first_height);
    calculate_next_work_required(params, parent, &first)
}

/// Core: `CalculateNextWorkRequired`.
pub fn calculate_next_work_required(params: &ConsensusParams, last: &BlockHeader, first: &BlockHeader) -> u32 {
    if params.pow_no_retargeting {
        return last.bits;
    }
    let mut actual_timespan = last.time as i64 - first.time as i64;
    if actual_timespan < params.pow_target_timespan / 4 {
        actual_timespan = params.pow_target_timespan / 4;
    }
    if actual_timespan > params.pow_target_timespan * 4 {
        actual_timespan = params.pow_target_timespan * 4;
    }
    let base_bits = if params.enforce_bip94 { first.bits } else { last.bits };
    let (base, _, _) = compact_to_target(base_bits);
    let mut new_target = base.wrapping_mul(U256::from_u64(actual_timespan as u64));
    new_target = new_target.div_rem(U256::from_u64(params.pow_target_timespan as u64)).0;
    if new_target > params.pow_limit {
        new_target = params.pow_limit;
    }
    target_to_compact(new_target)
}

/// Core: `MAX_TIMEWARP`.
pub const MAX_TIMEWARP: i64 = 600;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_encode;

    #[test]
    fn compact_round_trips() {
        let (target, negative, overflow) = compact_to_target(0x1d00ffff);
        assert!(!negative && !overflow);
        assert_eq!(hex_encode(&target.to_be_bytes()), "00000000ffff0000000000000000000000000000000000000000000000000000");
        assert_eq!(target_to_compact(target), 0x1d00ffff);
        assert_eq!(compact_to_target(0x01003456).0, U256::ZERO);
        assert_eq!(compact_to_target(0x01123456).0, U256::from_u64(0x12));
        assert!(compact_to_target(0x04923456).1);
        assert!(compact_to_target(0xff123456).2);
        assert_eq!(target_to_compact(U256::from_u64(0x80)), 0x02008000);
        assert_eq!(block_proof(0x1d00ffff), U256::from_u64(0x0100010001));
    }
}
