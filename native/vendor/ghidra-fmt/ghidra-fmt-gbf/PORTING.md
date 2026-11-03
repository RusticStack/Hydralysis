# ghidra-fmt-gbf porting notes

Source: `db.buffers.LocalBufferFile`, `DataBuffer` (storage part), `BufferFile` constants.
Test source: `db.buffers.LocalBufferFileTest`.

## Mapping

| Java | Rust |
| --- | --- |
| `new LocalBufferFile(file, readOnly)` | `BufferFile::open` |
| `new LocalBufferFile(file, bufferSize)` | `BufferFile::create(path, buffer_size, file_id)` (file id is a parameter; Java uses `Random`) |
| `new LocalBufferFile(bufferSize, prefix, ext)` | `BufferFile::create_temp` (deleted on close/drop, never flushed) |
| `get(DataBuffer, index)` / `put` | `BufferStore::get_buffer` / `BufferFile::put` |
| `getParameter/setParameter/clearParameters/getParameterNames` | same names, snake_case |
| `getFreeIndexes/setFreeIndexes` | `free_indexes` / `set_free_indexes` (sorted ascending) |
| `close()` (flush + commit) | `close(self)`; `flush()` is also public. Nothing is committed without it, as in Java |
| `LocalBufferFile.getDataBuffer(BufferFileBlock)` | `data_buffer_from_block` |
| `BufferMgr` allocation (needed by ChainedBuffer) | `BufferStoreMut` + `MemoryBufferStore` |

## Test mapping

| Java (`LocalBufferFileTest`) | Rust (`src/tests.rs`) |
| --- | --- |
| `testTempFile` | `test_temp_file` |
| `testFileSave` | `test_file_save` |
| `testFileModify` | `test_file_modify` |
| `doWriteReadTest`, `doReadTest1/2` | helpers of the same names |

Extra tests: header byte layout and padding, negative headers (magic, version, block size,
length not a multiple of block size, truncated), free list pointing at a used block, read-only
put, parameter name limit, the `getDataBuffer` flag quirk, and the fixture `db.1.gbf`
(95 buffers, buffer id equals index).

## Behaviours kept from Java on purpose

* `get` treats any block whose flag byte has bit 0 set as empty (`flags & 1`), while
  `getDataBuffer` (block streams) compares `flags == 1`. Both are kept.
* An empty buffer read through `get` has id -1; the 4 bytes on disk are the next free index.
* The free list head is the largest free index; each free block points at the next smaller one.
* The parameter-table size check in `writeHeader` compares against the buffer size, not the block size.
* `put` of an empty buffer writes only the 5-byte prefix; `flush` pads the file to a block multiple.
* Block size is `buffer_size + 5` and is NOT rounded to 512 here (`testFileSave` uses 1024, so
  1029). The 512-multiple rounding lives in `BufferMgr`/`DBHandle`, which is not ported.
* A parameter table that spills past block 0 is read from the following blocks, as in Java.

## In-memory store

`MemoryBufferStore` follows `BufferMgr`/`IndexProvider`: freed indexes go on a stack and the next
`create_buffer` takes the most recently freed one. A freed buffer keeps its bytes in Java's cache
and the reallocated buffer is NOT cleared, so the store hands the old bytes back (a never used
index is zero filled). This is needed for byte-identical results of the B-tree write path.
`save_to_file` writes the store the way `BufferMgr.saveAs` does.

## Deliberate differences

* Parameters are written in name order (Java: `Hashtable` iteration order, unspecified). Files
  that were read keep header order in `parameter_names()`. A byte-for-byte match with a
  Java-written file therefore only holds for files with at most one parameter.
* A free list that loops returns `CorruptFile` instead of hanging.
* `get_buffer(index)` uses one range check (`index >= count`); Java tests `index > count` and
  fails the read with EOF for `index == count`; both are errors.
* `put` of a non-empty buffer without payload is an error (Java: NullPointerException).

## Not ported

Block streams (`InputBlockStream`/`OutputBlockStream`), `copyFile`/`clone`, `poke`/`peek`
(use `put`/`get_buffer` on an opened file), `truncate`, `flushAhead`, `copyBuffersFrom`,
`BufferMgr` (cache, checkpoints, undo), `VersionFile`, `RecoveryFile`, `ChangeMapFile`,
`LocalManagedBufferFile`, `SharedPages`, `.ps` pre-save files and `cleanupOldPreSaveFiles`.
