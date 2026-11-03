//! Big-endian cursor and slice helpers.
//!
//! Every Ghidra database structure is big-endian (`java.io.DataInput` order). Java's
//! `DataBuffer` accessors throw `ArrayIndexOutOfBoundsException` on a bad offset; here every
//! accessor returns [`BytesError::OutOfBounds`] instead, and nothing ever panics.

use std::fmt;

/// Error returned when a read or write falls outside the backing slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytesError {
    /// `len` bytes at `offset` do not fit in a slice of `available` bytes.
    OutOfBounds {
        /// Requested start offset.
        offset: usize,
        /// Requested length.
        len: usize,
        /// Length of the slice.
        available: usize,
    },
}

impl fmt::Display for BytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds {
                offset,
                len,
                available,
            } => write!(
                f,
                "{len} bytes at offset {offset} exceed buffer of {available} bytes"
            ),
        }
    }
}

impl std::error::Error for BytesError {}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, BytesError>;

fn range(buf_len: usize, offset: usize, len: usize) -> Result<std::ops::Range<usize>> {
    offset
        .checked_add(len)
        .filter(|&end| end <= buf_len)
        .map(|end| offset..end)
        .ok_or(BytesError::OutOfBounds {
            offset,
            len,
            available: buf_len,
        })
}

/// Borrow `len` bytes of `buf` starting at `offset`.
pub fn slice(buf: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    Ok(&buf[range(buf.len(), offset, len)?])
}

fn array<const N: usize>(buf: &[u8], offset: usize) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    out.copy_from_slice(slice(buf, offset, N)?);
    Ok(out)
}

/// Read a byte.
pub fn get_u8(buf: &[u8], offset: usize) -> Result<u8> {
    Ok(array::<1>(buf, offset)?[0])
}

/// Read a signed byte.
pub fn get_i8(buf: &[u8], offset: usize) -> Result<i8> {
    Ok(i8::from_be_bytes(array(buf, offset)?))
}

/// Read a big-endian `i16`.
pub fn get_i16(buf: &[u8], offset: usize) -> Result<i16> {
    Ok(i16::from_be_bytes(array(buf, offset)?))
}

/// Read a big-endian `i32`.
pub fn get_i32(buf: &[u8], offset: usize) -> Result<i32> {
    Ok(i32::from_be_bytes(array(buf, offset)?))
}

/// Read a big-endian `i64`.
pub fn get_i64(buf: &[u8], offset: usize) -> Result<i64> {
    Ok(i64::from_be_bytes(array(buf, offset)?))
}

/// Write a byte.
pub fn put_u8(buf: &mut [u8], offset: usize, v: u8) -> Result<()> {
    put_bytes(buf, offset, &[v])
}

/// Write a big-endian `i16`.
pub fn put_i16(buf: &mut [u8], offset: usize, v: i16) -> Result<()> {
    put_bytes(buf, offset, &v.to_be_bytes())
}

/// Write a big-endian `i32`.
pub fn put_i32(buf: &mut [u8], offset: usize, v: i32) -> Result<()> {
    put_bytes(buf, offset, &v.to_be_bytes())
}

/// Write a big-endian `i64`.
pub fn put_i64(buf: &mut [u8], offset: usize, v: i64) -> Result<()> {
    put_bytes(buf, offset, &v.to_be_bytes())
}

/// Copy `src` into `buf` at `offset`.
pub fn put_bytes(buf: &mut [u8], offset: usize, src: &[u8]) -> Result<()> {
    let r = range(buf.len(), offset, src.len())?;
    buf[r].copy_from_slice(src);
    Ok(())
}

/// Sequential big-endian reader over a byte slice (`DataInputStream` equivalent).
#[derive(Debug, Clone)]
pub struct BeCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BeCursor<'a> {
    /// Start a cursor at offset 0.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Current offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes left to read.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Read a byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        let v = get_u8(self.buf, self.pos)?;
        self.pos += 1;
        Ok(v)
    }

    /// Read a big-endian `i16`.
    pub fn read_i16(&mut self) -> Result<i16> {
        let v = get_i16(self.buf, self.pos)?;
        self.pos += 2;
        Ok(v)
    }

    /// Read a big-endian `i32`.
    pub fn read_i32(&mut self) -> Result<i32> {
        let v = get_i32(self.buf, self.pos)?;
        self.pos += 4;
        Ok(v)
    }

    /// Read a big-endian `i64`.
    pub fn read_i64(&mut self) -> Result<i64> {
        let v = get_i64(self.buf, self.pos)?;
        self.pos += 8;
        Ok(v)
    }

    /// Borrow the next `len` bytes.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let v = slice(self.buf, self.pos, len)?;
        self.pos += len;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_big_endian() {
        let b = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        assert_eq!(get_i16(&b, 0), Ok(0x1234));
        assert_eq!(get_i32(&b, 0), Ok(0x1234_5678));
        assert_eq!(get_i64(&b, 0), Ok(0x1234_5678_9abc_def0));
        assert_eq!(get_i8(&[0xff], 0), Ok(-1));
    }

    #[test]
    fn writes_round_trip() {
        let mut b = [0u8; 8];
        put_i64(&mut b, 0, -2).unwrap();
        assert_eq!(get_i64(&b, 0), Ok(-2));
        put_i32(&mut b, 4, i32::MIN).unwrap();
        assert_eq!(&b[4..], &[0x80, 0, 0, 0]);
        put_i16(&mut b, 0, 0x0102).unwrap();
        put_u8(&mut b, 2, 9).unwrap();
        assert_eq!(&b[..3], &[1, 2, 9]);
    }

    #[test]
    fn out_of_bounds_is_an_error_not_a_panic() {
        let b = [0u8; 4];
        assert!(get_i32(&b, 1).is_err());
        assert!(get_i32(&b, usize::MAX).is_err());
        assert!(put_i64(&mut [0u8; 4], 0, 1).is_err());
        assert!(slice(&b, 5, 0).is_err());
        assert_eq!(slice(&b, 4, 0), Ok(&[][..]));
    }

    #[test]
    fn cursor_advances_and_stops() {
        let b = [0, 0, 0, 7, 0, 5, 1];
        let mut c = BeCursor::new(&b);
        assert_eq!(c.read_i32(), Ok(7));
        assert_eq!(c.read_i16(), Ok(5));
        assert_eq!(c.remaining(), 1);
        assert!(c.read_i32().is_err());
        assert_eq!(c.position(), 6);
        assert_eq!(c.read_u8(), Ok(1));
        assert_eq!(c.read_bytes(0), Ok(&[][..]));
    }
}
