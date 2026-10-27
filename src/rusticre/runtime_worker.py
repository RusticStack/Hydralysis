"""Optional isolated Frida worker. No REA or other MCP dependency."""

from __future__ import annotations

import collections
import hashlib
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

from rusticre.runtime_ipc import serve as ipc_serve
from rusticre.localio import read_text as local_read_text


CONTEXT_HELPER = r"""
function captureContext(context) {
 const names={ia32:['eip','esp','ebp','eax','ebx','ecx','edx','esi','edi'],
  x64:['rip','rsp','rbp','rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15'],
  arm:['pc','sp','lr','r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12'],
  arm64:['pc','sp','fp','lr',...Array.from({length:29},(_,i)=>'x'+i)]};
 const result={};for(const name of ['pc','sp',...(names[Process.arch]||[])]){
  const value=context[name];if(value!==undefined)result[name]=value.toString();
 }return result;
}
"""

MEMORY_HELPER = r"""
function readExact(address,size) {
 const buffer=address.readVolatile(size);
 if(buffer===null||buffer.byteLength!==size)throw new Error('live memory read was incomplete; target mapping may have changed');
 return Array.from(new Uint8Array(buffer));
}
"""

CONTROL = CONTEXT_HELPER + MEMORY_HELPER + r"""
rpc.exports = {
  info(selected) { const same=p=>Process.platform==='windows'?p.toLowerCase():p;
    const matches=selected?Process.enumerateModules().filter(m=>same(m.path)===same(selected)):[];
    const main=matches.length===1?matches[0]:Process.mainModule;
    return {pid:Process.id,arch:Process.arch,pointer_size:Process.pointerSize,selected_module_found:matches.length===1,
    main:{name:main.name,path:main.path,base:main.base.toString(),size:main.size}}; },
  modules(limit) { const all=Process.enumerateModules(); return {total:all.length,truncated:all.length>limit,
    modules:all.slice(0,limit).map(m=>({name:m.name,path:m.path,base:m.base.toString(),size:m.size}))}; },
  threads(limit) { const all=Process.enumerateThreads(); return {total:all.length,truncated:all.length>limit,
    threads:all.slice(0,limit).map(t=>({id:t.id,state:t.state,context:captureContext(t.context)}))}; },
  module(name) { const matches=Process.enumerateModules().filter(m=>m.path===name||m.name===name);
    if(matches.length!==1)throw new Error('module must match exactly one loaded path/name');
    const m=matches[0];return {name:m.name,path:m.path,base:m.base.toString(),size:m.size}; },
  locate(address) { const p=ptr(address),r=Process.findRangeByAddress(p),m=Process.findModuleByAddress(p);
    return {range:r?{base:r.base.toString(),size:r.size,protection:r.protection}:null,
      module:m?{name:m.name,path:m.path,base:m.base.toString(),size:m.size}:null}; },
  read(address,size) { const p=ptr(address),r=Process.findRangeByAddress(p);
    if(!r||r.protection.indexOf('r')<0||p.add(size).compare(p)<0||p.add(size).compare(r.base.add(r.size))>0)throw new Error('read exceeds readable memory range');
    return readExact(p,size); }
};
"""


def _write(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def _read(path: Path) -> dict:
    try:
        return json.loads(local_read_text(path))
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise RuntimeError("runtime mailbox read failed: errno=%s winerror=%s path=%s: %s"
                           % (exc.errno, getattr(exc, "winerror", None), path, exc)) from exc


def _ready_record(worker: dict, observation: dict) -> dict:
    # Worker and target are different processes. Never let the target's pid
    # replace the worker identity used for admission and timeout cleanup.
    return {"ok": True, **observation, **worker}


def _created_ms(pid: int) -> int:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            raise OSError(ctypes.get_last_error(), "cannot query selected process identity")
        try:
            values = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *[ctypes.byref(value) for value in values]):
                raise OSError(ctypes.get_last_error(), "cannot read selected process creation time")
            ticks = (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
            return ticks // 10000 - 11644473600000
        finally:
            kernel.CloseHandle(handle)
    if sys.platform == "darwin":
        from rusticre.darwin_process import created_ms
        return created_ms(pid)
    stat = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
    boot = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))
    return int((boot + int(stat[19]) / os.sysconf("SC_CLK_TCK")) * 1000)


def _process_path(pid: int) -> str:
    if sys.platform == "darwin":
        from rusticre.darwin_process import process_path
        return process_path(pid)
    if os.name != "nt":
        return str(Path("/proc/%d/exe" % pid).resolve())
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "cannot inspect selected process path")
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "cannot inspect selected process path")
        return buffer.value
    finally:
        kernel.CloseHandle(handle)


def target_environment(overrides: dict) -> dict:
    """The caller's environment, not this worker's private TEMP/PYTHONPATH, plus overrides."""
    env = dict(os.environ)
    restore = json.loads(env.pop("RUSTICRE_TARGET_ENV_RESTORE", "{}") or "{}")
    for key, value in restore.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    env.update(overrides)
    return env


def _same_path(a: str, b: str) -> bool:
    return os.path.normcase(str(Path(a).resolve())) == os.path.normcase(str(Path(b).resolve()))


def decode_detour(data: bytes, address: int) -> dict | None:
    """The jump a hooking library writes over a function's first bytes, if it is one."""
    if len(data) >= 5 and data[0] == 0xE9:
        return {"kind": "jmp rel32", "length": 5, "target": address + 5 + int.from_bytes(data[1:5], "little", signed=True)}
    if len(data) >= 14 and data[:6] == bytes.fromhex("ff2500000000"):
        return {"kind": "jmp [rip+0] abs64", "length": 14, "target": int.from_bytes(data[6:14], "little")}
    if len(data) >= 12 and data[:2] == bytes.fromhex("48b8") and data[10:12] == bytes.fromhex("ffe0"):
        return {"kind": "mov rax, imm64; jmp rax", "length": 12, "target": int.from_bytes(data[2:10], "little")}
    if len(data) >= 13 and data[:2] == bytes.fromhex("49bb") and data[10:13] == bytes.fromhex("41ffe3"):
        return {"kind": "mov r11, imm64; jmp r11", "length": 13, "target": int.from_bytes(data[2:10], "little")}
    return None


_IMAGES: dict = {}


def _image(path: str):
    """A parsed module file, kept while the file is unchanged (a game exe is tens of MB)."""
    from rusticre.pe import Image
    stat = Path(path).stat()
    key = (str(path), stat.st_size, stat.st_mtime_ns)
    if key not in _IMAGES:
        _IMAGES.clear()
        _IMAGES[key] = Image(Path(path))
    return _IMAGES[key]


def file_bytes(path: str, rva: int, size: int, load_base: int | None = None) -> bytes:
    """What the module's file on disk holds at an RVA: the original, whatever is patched live.
    With load_base, as the loader leaves it there (base relocations applied)."""
    image = _image(path)
    return image.read_rva(rva, size) if load_base is None else image.loaded_bytes(rva, size, load_base)


# Bytes a probe overwrites at its site (a 5-byte jump, rounded up to whole instructions).
PROBE_SPAN = 8


def _relocated(module: dict, rva: int, expected: list, actual: list) -> bool:
    """expect is the file's bytes and the live ones differ only by the loader's base relocations."""
    try:
        return list(file_bytes(module["path"], rva, len(expected))) == expected \
            and actual == list(file_bytes(module["path"], rva, len(expected), int(module["base"], 16)))
    except Exception:  # a module file that cannot be decoded gives no evidence
        return False


def _call_in_span(path: str, rva: int) -> str | None:
    """A call instruction inside the bytes a probe would overwrite, or None.

    The instrumentation relocates an overwritten call into its trampoline, so the callee
    returns into it; in testing (Frida 17.24.3, a probe over a call in a loop) such a probe
    could not be released again. Probe the call's target or the instruction after it.
    """
    try:
        image = _image(path)
        decoder = image._decoder()
        code = image.read_rva(rva, PROBE_SPAN + 15)
    except Exception:  # a module file that cannot be decoded gives no evidence either way
        return None
    for instruction in decoder.disasm(code, rva):
        if instruction.address >= rva + 5:
            break
        if instruction.mnemonic.startswith("call"):
            return "%s %s at rva %#x" % (instruction.mnemonic, instruction.op_str, instruction.address)
    return None


def _inside_function(path: str, rva: int) -> bool:
    """True when the module's pdata shows rva inside a function, not at its start (x64 only)."""
    try:
        bounds = _image(path)._bounds(rva)
    except Exception:  # not a PE we can read: no pdata evidence
        return False
    return bounds is not None and bounds[0] != rva


def _expect(text: str) -> list[int]:
    words = str(text).split()
    if not 5 <= len(words) <= 64 or any(not re.fullmatch("[0-9A-Fa-f]{2}", word) for word in words):
        raise ValueError("runtime probe requires 5..64 exact expected bytes; wildcards cannot validate a live hook")
    return [int(word, 16) for word in words]


def _probe_source(module: dict, rva: int, expected: list[int], hook_id: str, limit: int, pause: bool,
                  captures: list | None = None, sample: dict | None = None, convention: str = "native",
                  instruction: bool = False) -> str:
    parameters = json.dumps({"module": module["path"], "base": module["base"], "rva": rva,
                             "expect": expected, "id": hook_id, "limit": limit, "pause": pause,
                             "captures": [{"arg": c["arg"], "reg": c.get("reg"), "deref": c["deref"], "size": c["size"],
                                           "value_only": c["value_only"], "ptr": c["as"] == "pointer"} for c in (captures or [])],
                             "sample": sample, "convention": convention, "instruction": instruction})
    return CONTEXT_HELPER + MEMORY_HELPER + r"""const p=PARAMETERS;
const all=Process.enumerateModules().filter(m=>m.path===p.module);
if(all.length!==1||all[0].base.toString()!==p.base)throw new Error('module mapping changed before probe installation');
const site=all[0].base.add(p.rva);
const got=readExact(site,p.expect.length);
if(got.some((b,i)=>b!==p.expect[i]))throw new Error('PROLOGUE MISMATCH; probe refused');
let hits=0;
// Bounded copies of what arguments point to; every read is checked against a readable range.
function readable(q,n){const r=Process.findRangeByAddress(q);return r!==null&&r.protection.indexOf('r')>=0&&q.add(n).compare(r.base.add(r.size))<=0;}
// Argument i under the probe's calling convention. Native: what Frida reads for this ABI (x64
// registers then stack; ia32 stack slots). 32-bit thiscall: `this` in ecx, the rest on the stack;
// fastcall: ecx, edx, then the stack.
if(p.convention!=='native'&&Process.arch!=='ia32')throw new Error('convention '+p.convention+' is for 32-bit x86 targets');
function argAt(context,args,i){
  if(p.convention==='thiscall')return i===0?context.ecx:args[i-1];
  if(p.convention==='fastcall')return i===0?context.ecx:i===1?context.edx:args[i-2];
  return args[i];}
function captureArgs(args,context){return p.captures.map(c=>{try{
  if(c.reg!==null&&context[c.reg]===undefined)return {error:'no register '+c.reg+' on '+Process.arch};
  let q=c.reg!==null?context[c.reg]:argAt(context,args,c.arg);
  // A vector register (x64 xmm0..xmm15) is its bytes: a float argument is the low 4 or 8.
  if(q instanceof ArrayBuffer)return {pointer:null,hex:Array.from(new Uint8Array(q).slice(0,Math.min(c.size,q.byteLength)),b=>b.toString(16).padStart(2,'0')).join('')};
  // A pointer is the target's own width (4 bytes in a 32-bit process).
  const n=c.ptr?Process.pointerSize:c.size;
  if(c.value_only)return {pointer:q.toString(),hex:Array.from({length:n},(_,i)=>q.shr(8*i).and(255).toInt32().toString(16).padStart(2,'0')).join('')};
  for(const off of c.deref){if(!readable(q.add(off),Process.pointerSize))return {error:'unreadable pointer at '+q.add(off)};q=q.add(off).readPointer();}
  if(!readable(q,n))return {pointer:q.toString(),error:'unreadable '+n+' bytes'};
  return {pointer:q.toString(),hex:Array.from(new Uint8Array(q.readVolatile(n)),b=>b.toString(16).padStart(2,'0')).join('')};
 }catch(e){return {error:String(e)};}});}
// Sampled observation: count every call, keep min/max/last of one captured number, send one summary per window.
const agg={count:0,min:null,max:null,last:null};
if(p.sample){setInterval(()=>{send({event:'sample',hook_id:p.id,window_s:p.sample.window_s,count:agg.count,
  rate:agg.count/p.sample.window_s,min:agg.min,max:agg.max,last:agg.last});agg.count=0;agg.min=agg.max=null;},p.sample.window_s*1000);}
function sampleValue(hexed){const b=new Uint8Array(hexed.match(/../g).map(x=>parseInt(x,16))).buffer,v=new DataView(b);
  switch(p.sample.as){case 'f32':return v.getFloat32(0,true);case 'f64':return v.getFloat64(0,true);case 'i32':return v.getInt32(0,true);
   case 'u32':return v.getUint32(0,true);case 'i16':return v.getInt16(0,true);case 'u16':return v.getUint16(0,true);case 'u8':return v.getUint8(0);default:return b.byteLength>=8?Number(v.getBigUint64(0,true)):v.getUint32(0,true);}}
function enter(args){
  if(p.sample){agg.count++;const c=captureArgs(args,this.context)[p.sample.capture];
   if(c&&c.hex){const x=sampleValue(c.hex);agg.last=x;agg.min=agg.min===null||x<agg.min?x:agg.min;agg.max=agg.max===null||x>agg.max?x:agg.max;}return;}
  this.capture=hits++<p.limit;
  if(!this.capture)return;
  const context=captureContext(this.context);
  let backtrace=[];try{backtrace=Thread.backtrace(this.context,Backtracer.ACCURATE).slice(0,16).map(a=>a.toString());}catch(e){}
  send({event:p.pause?'break':'enter',hook_id:p.id,hit:hits,thread:this.threadId,
    address:site.toString(),return_address:p.instruction?null:this.returnAddress.toString(),context,
    arguments:Array.from({length:8},(_,i)=>String(argAt(this.context,args,i))),backtrace,captures:captureArgs(args,this.context)});
  if(p.pause)recv('continue:'+p.id,()=>{}).wait();
 }
// Inside a function (a store, the instruction after a call) a probe is a plain callback: no
// invocation is tracked, so nothing waits for that function to return (a main loop never
// does) and the return address is never touched. At a function entry the return is captured.
const listener=p.instruction?Interceptor.attach(site,enter):Interceptor.attach(site,{onEnter:enter,
 onLeave(retval){if(this.capture)send({event:'return',hook_id:p.id,thread:this.threadId,value:retval.toString()});}
});
send({event:'probe_installed',hook_id:p.id,address:site.toString(),verified_bytes:got});
rpc.exports={status(){return {installed:true};},release(){send({event:'probe_removed',hook_id:p.id});listener.detach();}};
""".replace("PARAMETERS", parameters)


class RuntimeAgent:
    def __init__(self, directory: Path, device):
        self.directory = directory
        self.device = device
        self.session = None
        self.control = None
        self.pid = 0
        self.target_created_ms = 0
        self.target_exe = ""
        self.target_sha256 = ""
        self.paused_spawn = False
        self.detached = False
        self.ended = ""
        self.scripts = {}
        self.pauses = {}
        self.events = collections.deque()
        self.event_bytes = 0
        self.sequence = 0
        self.dropped = 0
        self.lock = threading.RLock()
        self.write_lock = threading.Lock()
        self.state = "starting"
        self.closed = False

    def snapshot(self):
        with self.lock:
            return {"session": self.directory.name, "state": self.state, "pid": self.pid,
                     "target_created_ms": self.target_created_ms, "spawn_paused": self.paused_spawn,
                     "detached": self.detached, "scripts": list(self.scripts), "paused_hooks": list(self.pauses),
                     "last_sequence": self.sequence, "dropped_events": self.dropped,
                     **({"ended": self.ended} if self.ended else {})}

    def publish(self):
        state = self.snapshot()
        with self.write_lock:
            _write(self.directory / "state.json", state)

    def message(self, script_id: str, message: dict, data=None):
        encoded = json.dumps(message, ensure_ascii=False, default=str).encode("utf-8")
        if len(encoded) > 8192:
            message = {"type": "truncated", "original_bytes": len(encoded), "head": encoded[:4096].decode("utf-8", "replace")}
        if data is not None:
            message = {**message, "data_hex": bytes(data[:1024]).hex(), "data_truncated": len(data) > 1024}
        with self.lock:
            self.sequence += 1
            event = {"sequence": self.sequence, "script": script_id, "message": message}
            size = len(json.dumps(event, ensure_ascii=False).encode("utf-8"))
            self.events.append((event, size))
            self.event_bytes += size
            while self.event_bytes > 262144 or len(self.events) > 1000:
                _, old_size = self.events.popleft()
                self.event_bytes -= old_size
                self.dropped += 1
            payload = message.get("payload", {})
            specs = (self.scripts.get(script_id) or {}).get("captures")
            if specs and isinstance(payload, dict) and payload.get("captures") is not None:
                from rusticre.runtime_decode import decode_event
                payload["decoded"] = decode_event(specs, payload.pop("captures"))
            if message.get("type") == "error" and script_id in self.scripts:
                self.scripts[script_id]["script_error"] = str(message.get("description") or message.get("stack") or "script error")[:1000]
            if message.get("type") == "send" and isinstance(payload, dict) and payload.get("event") == "break":
                hook_id = payload["hook_id"]
                self.pauses[hook_id] = time.monotonic()
        self.publish()

    def startup(self, initial: dict):
        exe = initial["exe"]
        if hashlib.sha256(Path(exe).read_bytes()).hexdigest() != initial["sha256"]:
            raise ValueError("target build changed before runtime startup")
        self.target_exe = exe
        self.target_sha256 = initial["sha256"]
        if initial["action"] == "spawn":
            options = {"envp": target_environment(initial.get("env") or {})}
            if initial.get("cwd"):
                options["cwd"] = initial["cwd"]
            self.pid = self.device.spawn([exe, *initial["argv"]], **options)
            self.paused_spawn = True
        else:
            self.pid = int(initial["pid"])
            if not _same_path(_process_path(self.pid), exe):
                raise ValueError("selected PID executable path differs from exe; attach refused")
        self.target_created_ms = _created_ms(self.pid)
        self.session = self.device.attach(self.pid)
        self.session.on("detached", self._detached)
        identity_error = None
        try:
            identity_ok = (_created_ms(self.pid) == self.target_created_ms
                           and _same_path(_process_path(self.pid), exe))
        except OSError as exc:
            identity_error = exc
            identity_ok = False
        if not identity_ok:
            try:
                self.session.detach()
                self.detached = True
            except Exception as exc:
                raise RuntimeError("target identity changed during attach; detach failed before any probe loaded: %s" % exc) from exc
            if identity_error is not None:
                raise RuntimeError("target identity recheck failed; detached before any probe loaded: errno=%s winerror=%s: %s"
                                   % (identity_error.errno, getattr(identity_error, "winerror", None), identity_error)) from identity_error
            raise ValueError("target identity changed during attach; detached before any probe loaded")
        self.control = self.session.create_script(CONTROL)
        self.control.on("message", lambda message, data: self.message("control", message, data))
        self.control.load()
        info = self.control.exports_sync.info(exe)
        if not _same_path(info["main"]["path"], exe):
            raise ValueError("attached process main module differs from selected executable: observed=%r selected=%r" % (info["main"]["path"], exe))
        self.state = "spawn_paused" if self.paused_spawn else "running"
        self.publish()
        return {"target": info, "sha256": initial["sha256"], "state": self.state,
                "pid": self.pid, "target_created_ms": self.target_created_ms}

    def _detached(self, *args):
        self.detached = True
        self.state = "detached"
        self.publish()

    def _module(self, args: dict) -> dict:
        name = str(args.get("module") or "")
        if not name:
            raise ValueError("select one loaded module by exact name or path")
        module = self.control.exports_sync.module(name)
        path = Path(module["path"])
        module["file_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        expected = str(args.get("sha256") or "").lower()
        if expected and expected != module["file_sha256"]:
            raise ValueError("loaded module's backing file SHA256 differs from expected build")
        return module

    def _site(self, args: dict, hook: bool = False):
        module = self._module(args)
        rva = int(str(args.get("rva", "")), 0)
        if not 0 <= rva < module["size"]:
            raise ValueError("RVA is outside selected module")
        if hook and not re.fullmatch("[0-9a-f]{64}", str(args.get("sha256") or "").lower()):
            raise ValueError("live probes require options.sha256: the full SHA-256 of the selected module's file "
                             "(for the main executable, the same hash as spawn/attach)")
        return module, rva, hex(int(module["base"], 16) + rva)

    def _patcher(self, address: int) -> dict | None:
        """Follow a live detour (through a relay page if needed) to the module that installed it."""
        data = bytes(self.control.exports_sync.read(hex(address), 16))
        detour = decode_detour(data, address)
        hops = []
        for _ in range(3):
            if detour is None:
                break
            located = self.control.exports_sync.locate(hex(detour["target"]))
            hop = {**detour, "target": hex(detour["target"]), "module": (located.get("module") or {}).get("name"),
                   "module_path": (located.get("module") or {}).get("path")}
            if located.get("module"):
                hop["target_rva"] = hex(detour["target"] - int(located["module"]["base"], 16))
            hops.append(hop)
            if located.get("module") or not located.get("range"):
                break
            # A trampoline relay outside any module (MinHook-style): read where it jumps.
            detour = decode_detour(bytes(self.control.exports_sync.read(hex(detour["target"]), 16)), detour["target"])
        if not hops:
            return None
        return {"jump": hops[0]["kind"], "hops": hops, "patcher_module": hops[-1].get("module"),
                "patcher_path": hops[-1].get("module_path"), "detour": hops[-1]["target"]}

    def patches(self, args: dict) -> dict:
        rows = args.get("rows")
        if not isinstance(rows, list) or not 1 <= len(rows) <= 200:
            raise ValueError("patches needs rows=[{module, rva, size?}], 1..200")
        results, patched = [], 0
        for row in rows:
            module, rva, address = self._site({**row, "sha256": row.get("sha256", args.get("sha256"))})
            size = int(row.get("size", 16))
            if not 1 <= size <= 64 or rva + size > module["size"]:
                raise ValueError("patch check size must be 1..64 bytes inside the module")
            live = bytes(self.control.exports_sync.read(address, size))
            # The loader's base relocations are not patches: compare with the bytes as loaded.
            original = file_bytes(module["path"], rva, size, int(module["base"], 16))
            item = {"name": row.get("name", ""), "module": module["name"], "rva": hex(rva), "address": address,
                    "file_bytes": original.hex(" ").upper(), "live_bytes": live.hex(" ").upper(), "patched": live != original}
            if item["patched"]:
                patched += 1
                item["patch"] = self._patcher(int(address, 16))
            results.append(item)
        return {"rows": results, "checked": len(results), "patched": patched,
                "provenance": "file bytes from the module's file on disk; live bytes read now; detours decoded, not executed"}

    def _continue(self, hook_id: str):
        entry = self.scripts.get(hook_id)
        if entry is not None:
            entry["handle"].post({"type": "continue:" + hook_id})
        self.pauses.pop(hook_id, None)

    def watchdog(self):
        while not self.closed:
            with self.lock:
                expired = [hook for hook, started in self.pauses.items() if time.monotonic() - started >= 30]
            for hook in expired:
                try:
                    self._continue(hook)
                    self.message(hook, {"type": "send", "payload": {"event": "auto_continue", "hook_id": hook, "reason": "30s pause deadline"}})
                except Exception as exc:
                    print("breakpoint auto-continue failed:", repr(exc), flush=True)
            time.sleep(0.1)

    def handle(self, action: str, args: dict) -> dict:
        if action == "status":
            limit = int(args.get("limit", 40))
            after = int(args.get("after", 0))
            if not 1 <= limit <= 200 or after < 0:
                raise ValueError("status limit must be 1..200; after must be nonnegative")
            with self.lock:
                matching = [item for item, _ in self.events if item["sequence"] > after]
                events = matching[:limit]
                return {**self.snapshot(), "worker_alive": True, "events": events,
                        "truncated": len(matching) > limit, "next_after": events[-1]["sequence"] if events else after}
        if action == "detach":
            return self.cleanup()
        if self.detached:
            raise RuntimeError("target session is detached")
        if action == "resume":
            if not self.paused_spawn:
                raise ValueError("resume is only for this session's paused spawn; use continue for a breakpoint")
            self.device.resume(self.pid)
            self.paused_spawn = False
            self.state = "running"
            self.publish()
            return {"state": self.state, "pid": self.pid}
        if action == "continue":
            hook_id = str(args.get("hook_id") or "")
            if hook_id and hook_id not in self.pauses:
                raise ValueError("hook is not currently paused")
            for item in [hook_id] if hook_id else list(self.pauses):
                self._continue(item)
            self.publish()
            return {"continued": hook_id or "all", "state": self.state}
        if action == "modules":
            limit = int(args.get("limit", 40))
            if not 1 <= limit <= 200:
                raise ValueError("limit must be 1..200")
            return self.control.exports_sync.modules(limit)
        if action == "threads":
            limit = int(args.get("limit", 40))
            if not 1 <= limit <= 200:
                raise ValueError("limit must be 1..200")
            return self.control.exports_sync.threads(limit)
        if action == "read":
            size = int(args.get("size", 64))
            if not 1 <= size <= 4096:
                raise ValueError("read size must be 1..4096")
            if args.get("address"):
                if args.get("module") or "rva" in args:
                    raise ValueError("read requires address or module+rva, not both")
                value = int(str(args["address"]).removeprefix("va:"), 0)
                info = self.control.exports_sync.info()
                maximum = 1 << (int(info["pointer_size"]) * 8)
                if not 0 < value < maximum or value + size > maximum:
                    raise ValueError("absolute read address overflows the target pointer width")
                address = hex(value)
                provenance = self.control.exports_sync.locate(address)
                module = provenance.get("module")
                rva = value - int(module["base"], 16) if module else None
            else:
                module, rva, address = self._site(args)
                if rva + size > module["size"]:
                    raise ValueError("read must remain inside selected module")
                provenance = self.control.exports_sync.locate(address)
            data = self.control.exports_sync.read(address, size)
            layout = args.get("layout")
            typed = None
            if layout is not None:
                from rusticre.runtime_decode import layout_values
                if not isinstance(layout, list) or len(layout) > 512:
                    raise ValueError("layout is a list of at most 512 {name, offset, type, size?} fields")
                typed = layout_values(layout, bytes(data))
            return {"module": module, "rva": hex(rva) if rva is not None else None, "address": address,
                    **({"fields": typed, "type": args.get("type_name")} if typed is not None else {}),
                    "range": provenance.get("range"), "target": {"pid": self.pid, "created_ms": self.target_created_ms,
                    "exe": self.target_exe, "exe_sha256": self.target_sha256},
                    "bytes": " ".join("%02X" % x for x in data)}
        if action in ("observe", "break"):
            module, rva, address = self._site(args, hook=True)
            expected = _expect(str(args.get("expect") or ""))
            if rva + len(expected) > module["size"]:
                raise ValueError("expected bytes extend outside selected module")
            actual = self.control.exports_sync.read(address, len(expected))
            patch = None
            # expect is the file's bytes; a relocated module holds them with the loader's fixups.
            if list(actual) != expected and _relocated(module, rva, expected, list(actual)):
                expected = list(actual)
            if list(actual) != expected:
                patch = self._patcher(int(address, 16))
                # accept_patch: expect is the original prologue; the live bytes may differ only by a
                # detour another tool wrote, and the module's file must still hold expect exactly.
                if not args.get("accept_patch") or patch is None:
                    raise ValueError("PROLOGUE MISMATCH; hook refused: got " + " ".join("%02X" % x for x in actual)
                                     + ("; live detour %s to %s (%s); pass accept_patch=true with the original prologue to probe past it"
                                        % (patch["jump"], patch["detour"], patch["patcher_module"] or "no module") if patch else ""))
                original = list(file_bytes(module["path"], rva, len(expected)))
                if original != expected:
                    raise ValueError("accept_patch needs expect to be the module file's original prologue; the file holds "
                                     + " ".join("%02X" % x for x in original))
                expected = list(actual)
            limit = int(args.get("limit", 20))
            if not 1 <= limit <= 200:
                raise ValueError("probe limit must be 1..200")
            from rusticre.runtime_decode import SCALARS, normalize
            captures = normalize(args.get("capture"))
            sample = args.get("sample")
            if sample is not None:
                if action != "observe" or not isinstance(sample, dict) or set(sample) - {"window_s", "capture"}:
                    raise ValueError("sample is for observe: {window_s 1..300, capture: index of a numeric capture}")
                window, index = int(sample.get("window_s", 10)), int(sample.get("capture", 0))
                if not 1 <= window <= 300 or not 0 <= index < len(captures) or captures[index]["as"] not in SCALARS:
                    raise ValueError("sample needs window_s 1..300 and a capture index whose decoder is a number")
                sample = {"window_s": window, "capture": index, "as": captures[index]["as"]}
            convention = str(args.get("convention") or "native")
            if convention not in ("native", "thiscall", "fastcall"):
                raise ValueError("convention is native, thiscall or fastcall (the last two for 32-bit x86)")
            call = _call_in_span(module["path"], rva)
            if call:
                raise ValueError("probe refused: the bytes it would overwrite hold a call (%s), which the instrumentation "
                                 "cannot release again; probe the call's target, or an instruction after the call" % call)
            # A probe inside a function (a store, a call site) must not hook the return: say so with
            # instruction=true; on x64 a site that is not the start of a pdata function is one.
            instruction = bool(args.get("instruction"))
            if not instruction:
                instruction = _inside_function(module["path"], rva)
            hook_id = uuid.uuid4().hex
            source = _probe_source(module, rva, expected, hook_id, limit, action == "break", captures, sample, convention,
                                   instruction)
            handle = self._load(hook_id, source, {"kind": action, "module": module, "rva": hex(rva), "expected_bytes": expected,
                                                  "captures": captures, "sample": sample,
                                                  "convention": convention})
            return {"hook_id": hook_id, "verified": True, "module": module, "rva": hex(rva), "instruction": instruction,
                    "address": address, "script_sha256": handle["source_sha256"], "pause_deadline_s": 30 if action == "break" else None,
                    **({"past_patch": patch} if patch else {})}
        if action == "patches":
            return self.patches(args)
        if action == "unload":
            script_id = str(args.get("script_id") or args.get("hook_id") or "")
            if script_id not in self.scripts:
                raise ValueError("script_id/hook_id is not owned by this session")
            self._unload(script_id)
            self.publish()
            return {"unloaded": script_id}
        raise ValueError("unsupported runtime action; use guarded observe/break or bounded read; arbitrary scripts are not accepted")

    def _load(self, script_id: str, source: str, metadata: dict) -> dict:
        script = self.session.create_script(source)
        script.on("message", lambda message, data: self.message(script_id, message, data))
        entry = {**metadata, "handle": script, "source_sha256": hashlib.sha256(source.encode()).hexdigest()}
        self.scripts[script_id] = entry
        try:
            script.load()
            if entry.get("script_error"):
                raise RuntimeError("runtime script failed: " + entry["script_error"])
            if metadata.get("kind") in ("observe", "break") and not script.exports_sync.status().get("installed"):
                raise RuntimeError("runtime probe did not confirm installation")
        except Exception as original:
            try:
                script.unload()
                self.scripts.pop(script_id)
            except Exception as cleanup:
                # Retain ownership for explicit cleanup retry.
                entry["cleanup_pending"] = True
                error_type = PermissionError if isinstance(original, PermissionError) or isinstance(cleanup, PermissionError) else RuntimeError
                raise error_type("runtime script %s failed to load (%s); cleanup failed (%s); "
                                 "script retained for unload retry" % (script_id, original, cleanup)) from original
            raise
        self.publish()
        return entry

    def _unload(self, script_id: str):
        entry = self.scripts[script_id]
        if script_id in self.pauses:
            self._continue(script_id)
        try:
            entry["handle"].unload()
        except Exception as exc:
            # A script the target's exit (or the session's end) destroyed is already gone.
            if "destroyed" not in str(exc):
                raise
        self.scripts.pop(script_id)

    def cleanup(self) -> dict:
        errors = []
        for script_id in list(self.scripts):
            try:
                self._unload(script_id)
            except Exception as exc:
                errors.append("unload %s: %s" % (script_id, exc))
        detached = self.detached
        if self.session is not None and not detached:
            try:
                self.session.detach()
                detached = self.detached = True
                self.scripts.clear()
                self.pauses.clear()
            except Exception as exc:
                errors.append("detach: " + str(exc))
        if self.paused_spawn and (detached or not self.scripts):
            try:
                if _created_ms(self.pid) != self.target_created_ms:
                    raise RuntimeError("spawn PID identity changed; refusing resume")
                self.device.resume(self.pid)
                self.paused_spawn = False
            except Exception as exc:
                errors.append("resume owned spawn: " + str(exc))
        self.state = "cleanup_failed" if errors else "detached"
        self.publish()
        if errors:
            raise RuntimeError("runtime cleanup incomplete: " + "; ".join(errors))
        self.closed = True
        return {"state": "detached", "target_state": "unknown", "pid": self.pid,
                "spawn_resumed": not self.paused_spawn, "scripts_released": not self.scripts}


def main() -> int:
    import frida
    if len(sys.argv) > 1 and sys.argv[1] == "--processes":
        limit = int(sys.argv[2])
        processes = frida.get_local_device().enumerate_processes()
        print(json.dumps({"ok": True, "processes": [{"pid": p.pid, "name": p.name} for p in processes[:limit]],
                          "total": len(processes), "truncated": len(processes) > limit}))
        return 0
    directory = Path(sys.argv[1]).resolve()
    initial = _read(directory / "start.json")
    agent = RuntimeAgent(directory, frida.get_local_device())
    worker = {"pid": os.getpid(), "started_ms": _created_ms(os.getpid())}
    try:
        # A blocked native attach/spawn must not bypass the startup budget.
        startup_done = threading.Event()
        def startup_guard():
            if not startup_done.wait(25):
                try:
                    agent.cleanup()
                except Exception as exc:
                    print("startup cleanup failed:", repr(exc), flush=True)
        threading.Thread(target=startup_guard, daemon=True).start()
        try:
            observation = agent.startup(initial)
        finally:
            startup_done.set()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(0.25)
        secret = secrets.token_hex(32)
        _write(directory / "ready.json", {**_ready_record(worker, observation),
                                          "ipc": {"port": listener.getsockname()[1], "token": secret}})
    except Exception as exc:
        cleanup_error = None
        try:
            agent.cleanup()
        except Exception as cleanup:
            cleanup_error = str(cleanup)
        _write(directory / "ready.json", {**worker, "ok": False, "error": str(exc), "cleanup_error": cleanup_error})
        return 1
    threading.Thread(target=agent.watchdog, daemon=True).start()
    touched = time.monotonic()
    exit_code = 0
    def handle_request(action, args, budget):
        done = threading.Event()
        def deadline_guard():
            if not done.wait(budget):
                try:
                    agent.cleanup()
                except Exception as exc:
                    print("deadline cleanup failed:", repr(exc), flush=True)
        threading.Thread(target=deadline_guard, daemon=True).start()
        try:
            return agent.handle(action, args)
        finally:
            done.set()
    try:
        while not agent.closed and time.monotonic() - touched < int(initial.get("idle_s", 600)):
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(3)
                if ipc_serve(connection, secret, handle_request):
                    touched = time.monotonic()
    finally:
        listener.close()
        if not agent.closed:
            agent.ended = "idle: no request for %d s (runtime_idle_s)" % int(initial.get("idle_s", 600))
            try:
                agent.cleanup()
            except Exception as exc:
                print("runtime exit cleanup failed:", repr(exc), flush=True)
                exit_code = 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
