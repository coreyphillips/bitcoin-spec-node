//! Chapter 03 section 3.1: primitive encodings.

use crate::util::Hash256;

/// Core: `MAX_SIZE`. Upper bound on any CompactSize used as a length or count.
pub const MAX_SIZE: u64 = 0x0200_0000;

/// A deserialization failure. The message matches Bitcoin Core's exception text where one exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

/// A cursor over a byte string.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    /// Bytes consumed so far.
    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The whole underlying byte string.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    #[inline]
    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        if count > self.remaining() {
            return Err(DecodeError("end of data"));
        }
        let slice = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    #[inline]
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_bytes(1)?[0])
    }

    #[inline]
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    #[inline]
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    pub fn read_i32(&mut self) -> Result<i32, DecodeError> {
        Ok(self.read_u32()? as i32)
    }

    #[inline]
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.read_bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    #[inline]
    pub fn read_i64(&mut self) -> Result<i64, DecodeError> {
        Ok(self.read_u64()? as i64)
    }

    #[inline]
    pub fn read_hash(&mut self) -> Result<Hash256, DecodeError> {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(self.read_bytes(32)?);
        Ok(hash)
    }

    /// CompactSize without the MAX_SIZE limit. Core: `ReadCompactSize(is, false)`.
    pub fn read_compact_size_unchecked(&mut self) -> Result<u64, DecodeError> {
        let first = self.read_u8()?;
        let value = match first {
            0xfd => {
                let v = self.read_u16()? as u64;
                if v < 0xfd {
                    return Err(DecodeError("non-canonical ReadCompactSize()"));
                }
                v
            }
            0xfe => {
                let v = self.read_u32()? as u64;
                if v < 0x1_0000 {
                    return Err(DecodeError("non-canonical ReadCompactSize()"));
                }
                v
            }
            0xff => {
                let v = self.read_u64()?;
                if v < 0x1_0000_0000 {
                    return Err(DecodeError("non-canonical ReadCompactSize()"));
                }
                v
            }
            small => small as u64,
        };
        Ok(value)
    }

    /// CompactSize used as a length or count. Core: `ReadCompactSize(is, true)`.
    #[inline]
    pub fn read_compact_size(&mut self) -> Result<u64, DecodeError> {
        let value = self.read_compact_size_unchecked()?;
        if value > MAX_SIZE {
            return Err(DecodeError("ReadCompactSize(): size too large"));
        }
        Ok(value)
    }

    /// A byte vector: CompactSize length, then the bytes.
    #[inline]
    pub fn read_var_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let length = self.read_compact_size()? as usize;
        Ok(self.read_bytes(length)?.to_vec())
    }
}

/// Appends a CompactSize. Core: `WriteCompactSize`.
pub fn write_compact_size(out: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Number of bytes `write_compact_size` produces for `value`.
pub fn compact_size_len(value: u64) -> usize {
    if value < 0xfd {
        1
    } else if value <= 0xffff {
        3
    } else if value <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// Appends a byte vector (CompactSize length, then the bytes).
pub fn write_var_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_canonical() {
        for (bytes, expected) in [(&[0xfcu8][..], Some(0xfc)), (&[0xfd, 0xfd, 0x00][..], Some(0xfd)), (&[0xfd, 0xfc, 0x00][..], None)] {
            let mut reader = Reader::new(bytes);
            assert_eq!(reader.read_compact_size().ok(), expected);
        }
        let mut too_large = vec![0xfe];
        too_large.extend_from_slice(&0x0200_0001u32.to_le_bytes());
        assert!(Reader::new(&too_large).read_compact_size().is_err());
    }
}
