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
    stat = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
    boot = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))
    return int((boot + int(stat[19]) / os.sysconf("SC_CLK_TCK")) * 1000)


def _process_path(pid: int) -> str:
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


def _expect(text: str) -> list[int]:
    words = str(text).split()
    if not 5 <= len(words) <= 64 or any(not re.fullmatch("[0-9A-Fa-f]{2}", word) for word in words):
        raise ValueError("runtime probe requires 5..64 exact expected bytes; wildcards cannot validate a live hook")
    return [int(word, 16) for word in words]


def _probe_source(module: dict, rva: int, expected: list[int], hook_id: str, limit: int, pause: bool) -> str:
    parameters = json.dumps({"module": module["path"], "base": module["base"], "rva": rva,
                             "expect": expected, "id": hook_id, "limit": limit, "pause": pause})
    return CONTEXT_HELPER + MEMORY_HELPER + r"""const p=PARAMETERS;
const all=Process.enumerateModules().filter(m=>m.path===p.module);
if(all.length!==1||all[0].base.toString()!==p.base)throw new Error('module mapping changed before probe installation');
const site=all[0].base.add(p.rva);
const got=readExact(site,p.expect.length);
if(got.some((b,i)=>b!==p.expect[i]))throw new Error('PROLOGUE MISMATCH; probe refused');
let hits=0;
const listener=Interceptor.attach(site,{
 onEnter(args){
  this.capture=hits++<p.limit;
  if(!this.capture)return;
  const context=captureContext(this.context);
  let backtrace=[];try{backtrace=Thread.backtrace(this.context,Backtracer.ACCURATE).slice(0,16).map(a=>a.toString());}catch(e){}
  send({event:p.pause?'break':'enter',hook_id:p.id,hit:hits,thread:this.threadId,
    address:site.toString(),return_address:this.returnAddress.toString(),context,
    arguments:Array.from({length:8},(_,i)=>args[i].toString()),backtrace});
  if(p.pause)recv('continue:'+p.id,()=>{}).wait();
 },
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
                     "last_sequence": self.sequence, "dropped_events": self.dropped}

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
            return {"module": module, "rva": hex(rva) if rva is not None else None, "address": address,
                    "range": provenance.get("range"), "target": {"pid": self.pid, "created_ms": self.target_created_ms,
                    "exe": self.target_exe, "exe_sha256": self.target_sha256},
                    "bytes": " ".join("%02X" % x for x in data)}
        if action in ("observe", "break"):
            module, rva, address = self._site(args, hook=True)
            expected = _expect(str(args.get("expect") or ""))
            if rva + len(expected) > module["size"]:
                raise ValueError("expected bytes extend outside selected module")
            actual = self.control.exports_sync.read(address, len(expected))
            if list(actual) != expected:
                raise ValueError("PROLOGUE MISMATCH; hook refused: got " + " ".join("%02X" % x for x in actual))
            limit = int(args.get("limit", 20))
            if not 1 <= limit <= 200:
                raise ValueError("probe limit must be 1..200")
            hook_id = uuid.uuid4().hex
            source = _probe_source(module, rva, expected, hook_id, limit, action == "break")
            handle = self._load(hook_id, source, {"kind": action, "module": module, "rva": hex(rva), "expected_bytes": expected})
            return {"hook_id": hook_id, "verified": True, "module": module, "rva": hex(rva),
                    "address": address, "script_sha256": handle["source_sha256"], "pause_deadline_s": 30 if action == "break" else None}
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
        except Exception:
            try:
                script.unload()
                self.scripts.pop(script_id)
            except Exception:
                # Retain ownership for explicit cleanup retry.
                entry["cleanup_pending"] = True
            raise
        self.publish()
        return entry

    def _unload(self, script_id: str):
        entry = self.scripts[script_id]
        if script_id in self.pauses:
            self._continue(script_id)
        entry["handle"].unload()
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
            try:
                agent.cleanup()
            except Exception as exc:
                print("runtime exit cleanup failed:", repr(exc), flush=True)
                exit_code = 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
