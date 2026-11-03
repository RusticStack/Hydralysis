# ghidra-fmt-bytes porting notes

Source: `java.io.DataInput` / `DataOutput` order as used by `db.buffers.DataBuffer`
(`getInt`, `getLong`, `putInt`, ...). All values are big-endian.

| Java | Rust |
| --- | --- |
| `DataBuffer.getByte/getShort/getInt/getLong` | `get_u8/get_i8/get_i16/get_i32/get_i64` |
| `DataBuffer.put*` | `put_u8/put_i16/put_i32/put_i64/put_bytes` |
| `DataInputStream` over a byte array | `BeCursor` |
| `ArrayIndexOutOfBoundsException` | `BytesError::OutOfBounds` (never a panic) |

Tests: unit tests in `src/lib.rs`. The Java accessors have no direct test of their own.
