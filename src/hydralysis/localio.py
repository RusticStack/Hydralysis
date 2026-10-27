"""Bounded Windows native shared reads with native error preservation.

The native reader requests ordinary read access and shares read/write/delete.
It never retries a denied open or changes permissions. Native error codes and
filenames remain attached to exceptions, including genuine access denials. The
public reader closes its handle before returning bytes; it does not guarantee
that a filesystem permits concurrent replacement while a handle remains open.
"""

from __future__ import annotations

import ctypes
import os
import sys
from contextlib import contextmanager
from functools import lru_cache

DEFAULT_MAX_BYTES = 32 * 1024 * 1024


@lru_cache(maxsize=1)
def _kernel():
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
    kernel.GetFileSizeEx.restype = wintypes.BOOL
    kernel.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                               ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    kernel.ReadFile.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


def _native_error(filename: str) -> OSError:
    error = ctypes.WinError(ctypes.get_last_error())
    error.filename = filename
    return error


@contextmanager
def _shared_handle(filename: str):
    kernel = _kernel()
    # GENERIC_READ; FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    # OPEN_EXISTING; FILE_ATTRIBUTE_NORMAL. No access/security setting changes.
    handle = kernel.CreateFileW(filename, 0x80000000, 7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise _native_error(filename)
    try:
        yield kernel, handle
    finally:
        if not kernel.CloseHandle(handle):
            error = _native_error(filename)
            active = sys.exc_info()[1]
            if active is None:
                raise error
            active.add_note("Native shared-read CloseHandle also failed: %s" % error)


def _read_handle(kernel, handle, filename: str, max_bytes: int) -> bytes:
    from ctypes import wintypes

    size = ctypes.c_longlong()
    if not kernel.GetFileSizeEx(handle, ctypes.byref(size)):
        raise _native_error(filename)
    if size.value > max_bytes:
        raise ValueError("metadata exceeds %d-byte read budget: %s" % (max_bytes, filename))
    result = bytearray()
    while len(result) <= max_bytes:
        capacity = min(65536, max_bytes + 1 - len(result))
        buffer = ctypes.create_string_buffer(capacity)
        count = wintypes.DWORD()
        if not kernel.ReadFile(handle, buffer, capacity, ctypes.byref(count), None):
            raise _native_error(filename)
        if count.value == 0:
            break
        result.extend(buffer.raw[:count.value])
    if len(result) > max_bytes:
        raise ValueError("metadata exceeds %d-byte read budget: %s" % (max_bytes, filename))
    return bytes(result)


def read_bytes(path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= DEFAULT_MAX_BYTES:
        raise ValueError("metadata read budget must be 1..%d bytes" % DEFAULT_MAX_BYTES)
    filename = os.fsdecode(os.fspath(path))
    if "\x00" in filename:
        raise ValueError("metadata filename contains a null character")
    if os.name == "nt":
        with _shared_handle(filename) as (kernel, handle):
            return _read_handle(kernel, handle, filename, max_bytes)
    with open(filename, "rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("metadata exceeds %d-byte read budget: %s" % (max_bytes, filename))
    return data


def read_text(path, *, encoding: str = "utf-8", max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    return read_bytes(path, max_bytes=max_bytes).decode(encoding, errors="strict")
