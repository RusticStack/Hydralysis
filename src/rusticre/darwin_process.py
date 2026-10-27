"""Darwin process creation time and executable path through Apple's libproc.

The structures and flavors follow Apple's public XNU headers:
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
"""

import ctypes
import errno
import os


class _BsdInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "reserved"
    )] + [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid")
    ] + [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]


def _library():
    return ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)


def _failure(operation: str) -> OSError:
    number = ctypes.get_errno() or errno.ESRCH
    return OSError(number, "%s: %s" % (operation, os.strerror(number)))


def created_ms(pid: int) -> int:
    if pid <= 0:
        raise ValueError("process id must be positive")
    lib = _library()
    lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    lib.proc_pidinfo.restype = ctypes.c_int
    info = _BsdInfo()
    length = lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))  # PROC_PIDTBSDINFO
    if length != ctypes.sizeof(info):
        raise _failure("cannot read Darwin process identity")
    if info.pid != pid or info.status == 5 or not info.start_sec or info.start_usec >= 1000000:
        raise OSError(errno.ESRCH, "Darwin process identity is absent, stale or invalid")
    return info.start_sec * 1000 + info.start_usec // 1000


def process_path(pid: int) -> str:
    if pid <= 0:
        raise ValueError("process id must be positive")
    lib = _library()
    lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    lib.proc_pidpath.restype = ctypes.c_int
    path = ctypes.create_string_buffer(4096)  # PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN)
    length = lib.proc_pidpath(pid, path, len(path))
    if length <= 0 or length >= len(path) or not path.value:
        raise _failure("cannot read Darwin process path")
    return os.fsdecode(path.value)
