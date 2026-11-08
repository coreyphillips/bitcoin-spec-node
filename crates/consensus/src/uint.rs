//! Chapter 02 section 2.5: 256-bit unsigned integers (used by proof of work and chain work).

/// Unsigned 256-bit integer, limbs least significant first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct U256(pub [u64; 4]);

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                ordering => return ordering,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    pub fn from_u64(value: u64) -> U256 {
        U256([value, 0, 0, 0])
    }

    /// Reads 32 bytes, most significant first.
    pub fn from_be_bytes(bytes: &[u8]) -> U256 {
        assert_eq!(bytes.len(), 32);
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[24 - 8 * i..32 - 8 * i]);
            *limb = u64::from_be_bytes(chunk);
        }
        U256(limbs)
    }

    /// Writes 32 bytes, most significant first.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[24 - 8 * i..32 - 8 * i].copy_from_slice(&self.0[i].to_be_bytes());
        }
        out
    }

    /// Reads 32 bytes, least significant first. Core: `UintToArith256`.
    pub fn from_le_bytes(bytes: &[u8]) -> U256 {
        assert_eq!(bytes.len(), 32);
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[8 * i..8 * i + 8]);
            *limb = u64::from_le_bytes(chunk);
        }
        U256(limbs)
    }

    /// Writes 32 bytes, least significant first. Core: `ArithToUint256`.
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut out = self.to_be_bytes();
        out.reverse();
        out
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Bit `index` (0 is the least significant bit).
    pub fn bit(&self, index: usize) -> bool {
        (self.0[index / 64] >> (index % 64)) & 1 == 1
    }

    /// Number of significant bits.
    pub fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    pub fn low_u64(&self) -> u64 {
        self.0[0]
    }

    pub fn overflowing_add(self, other: U256) -> (U256, bool) {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = self.0[i] as u128 + other.0[i] as u128 + carry;
            out[i] = sum as u64;
            carry = sum >> 64;
        }
        (U256(out), carry != 0)
    }

    pub fn overflowing_sub(self, other: U256) -> (U256, bool) {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (d1, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (d2, b2) = d1.overflowing_sub(borrow as u64);
            out[i] = d2;
            borrow = b1 || b2;
        }
        (U256(out), borrow)
    }

    /// Addition modulo 2^256.
    pub fn wrapping_add(self, other: U256) -> U256 {
        self.overflowing_add(other).0
    }

    /// Subtraction modulo 2^256.
    pub fn wrapping_sub(self, other: U256) -> U256 {
        self.overflowing_sub(other).0
    }

    /// Bitwise complement (Core: `arith_uint256::operator~`).
    pub fn not(self) -> U256 {
        U256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    /// Left shift; bits shifted past bit 255 are discarded. Shifts of 256 or more give zero.
    pub fn shl(self, shift: u32) -> U256 {
        if shift >= 256 {
            return U256::ZERO;
        }
        let limbs = (shift / 64) as usize;
        let bits = shift % 64;
        let mut out = [0u64; 4];
        for i in (limbs..4).rev() {
            out[i] = self.0[i - limbs] << bits;
            if bits > 0 && i > limbs {
                out[i] |= self.0[i - limbs - 1] >> (64 - bits);
            }
        }
        U256(out)
    }

    /// Right shift. Shifts of 256 or more give zero.
    pub fn shr(self, shift: u32) -> U256 {
        if shift >= 256 {
            return U256::ZERO;
        }
        let limbs = (shift / 64) as usize;
        let bits = shift % 64;
        let mut out = [0u64; 4];
        for i in 0..4 - limbs {
            out[i] = self.0[i + limbs] >> bits;
            if bits > 0 && i + limbs + 1 < 4 {
                out[i] |= self.0[i + limbs + 1] << (64 - bits);
            }
        }
        U256(out)
    }

    /// Full 512-bit product, limbs least significant first.
    pub fn mul_wide(self, other: U256) -> [u64; 8] {
        let mut out = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let product = self.0[i] as u128 * other.0[j] as u128 + out[i + j] as u128 + carry;
                out[i + j] = product as u64;
                carry = product >> 64;
            }
            out[i + 4] = carry as u64;
        }
        out
    }

    /// Product modulo 2^256 (Core: `arith_uint256::operator*=`).
    pub fn wrapping_mul(self, other: U256) -> U256 {
        let wide = self.mul_wide(other);
        U256([wide[0], wide[1], wide[2], wide[3]])
    }

    /// Quotient and remainder. The divisor must not be zero.
    pub fn div_rem(self, divisor: U256) -> (U256, U256) {
        assert!(!divisor.is_zero(), "division by zero");
        let mut quotient = U256::ZERO;
        let mut remainder = U256::ZERO;
        for i in (0..256).rev() {
            let carry = remainder.bit(255);
            remainder = remainder.shl(1);
            if self.bit(i) {
                remainder.0[0] |= 1;
            }
            if carry || remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                quotient.0[i / 64] |= 1u64 << (i % 64);
            }
        }
        (quotient, remainder)
    }
}
