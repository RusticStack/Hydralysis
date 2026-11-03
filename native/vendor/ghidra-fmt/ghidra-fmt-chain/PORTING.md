# ghidra-fmt-chain porting notes

Source: `db.ChainedBuffer`, `db.DBParms`. Test source: `db.AbstractChainedBufferTest`, run as
`ChainedBufferTest`, `ObfuscatedChaninedBufferTest` and `ObfuscatedSourcedChaninedBufferTest`.

## Design

Java keeps a `BufferMgr` reference inside the object. Here `ChainedBuffer` is plain state and
every call is handed the store (`&impl BufferStore` to read, `&mut impl BufferStoreMut` to
write), so there are no lifetimes and no interior locking. `ByteSource` is the "uninitialized
data source" (a `Buffer` in Java). `DbParms` is read, created and updated through the same traits.

## Test mapping (each runs for the three Java variants)

`testCreateChainedBuffer`, `testReadOnlyChainedBuffer`, `testFillChainedBuffer`,
`testSmallFillChainedBuffer`, `testChainedBufferOverflow`, `testBigChainedBuffer`,
`testPutAndGet`, `testSetByte` + `testGetByte` (`test_set_and_get_byte`),
`testSetInt/GetInt`, `testSetLong/GetLong`, `testSetShort/GetShort`
(`test_set_and_get_{int,long,short}`, with offsets chosen around the 255-byte node payload),
`testGetId`, `testDelete` (also checks that no buffer leaks), `testSplit`, `testAppend`,
`testSetSize`. Java `random.nextBytes` (seed 1) is replaced by an LCG; the tests compare against
the bytes written, so the exact values do not matter. `mgr.getLockCount()` has no analogue.

Extra tests: stored byte layout (data node and index node, XOR bit), corrupt index chain,
zero and negative size, `DbParms` create/set/read and rejection of a bad node type or version,
fixture `db.1.gbf` DBParms (3 parms, master root 1, database id).

## Behaviours kept from Java on purpose

* The XOR mask is 128 bytes, indexed by the offset inside one data node (not the whole buffer).
* Length field: bit 31 = obfuscated, low 31 bits = size.
* Never-written data nodes have id -1; reads give zeros or the data source (never XOR'd).
* A newly allocated data node with a partial fill is cleared first, so the tail past `size`
  is raw 0 (not the XOR mask).
* `delete` frees every index node including the first (the Java comment says "except the first").
* `shrink_to_single_buffer` with `preserve_data` and an unwritten first data node copies nothing,
  so the former index bytes (0xff) stay visible as data.
* `append` does not check that both buffers agree on obfuscation (the doc comment says it does).
* Buffer ids are allocated in the same order as Java (the new first data node before the index
  nodes when growing a single node), which matters when whole files are compared.

## Deliberate differences

* The `getInt/getLong/getShort` fast paths are folded into the generic byte path; results are equal.
* `fill(InputStream)` is not ported; `fill(start, end, byte)` is.
* Corrupt input returns `ChainError` (`CorruptIndex`, `Bytes`, ...) instead of an assert or an
  array index exception.

## Not ported

`DBParms.poke` (in-place patch of a closed file; use `BufferFile::put` of buffer 0),
`ChainedBuffer.fill(InputStream)`.
