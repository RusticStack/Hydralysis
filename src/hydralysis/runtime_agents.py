"""The scripts the runtime worker loads into a target (agent templates), and the checks on what they are given.

CONTROL is the one fixed control script; `_probe_source` renders one guarded probe. Nothing here runs a
caller's script: a probe is a template with parameters, installed only after its bytes match.
"""

from __future__ import annotations

import json
import re


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


def _expect(text: str) -> list[int]:
    words = str(text).split()
    if not 5 <= len(words) <= 64 or any(not re.fullmatch("[0-9A-Fa-f]{2}", word) for word in words):
        raise ValueError("runtime probe requires 5..64 exact expected bytes; wildcards cannot validate a live hook")
    return [int(word, 16) for word in words]


def _probe_source(module: dict, rva: int, expected: list[int], hook_id: str, limit: int, pause: bool,
                  captures: list | None = None, sample: dict | None = None, convention: str = "native",
                  instruction: bool = False, export: str | None = None) -> str:
    parameters = json.dumps({"module": module["path"], "base": module["base"], "rva": rva,
                             "expect": expected, "id": hook_id, "limit": limit, "pause": pause,
                             "captures": [{"arg": c["arg"], "reg": c.get("reg"), "deref": c["deref"], "size": c["size"],
                                           "value_only": c["value_only"], "ptr": c["as"] == "pointer"} for c in (captures or [])],
                             "sample": sample, "convention": convention, "instruction": instruction,
                             "export": export})
    return CONTEXT_HELPER + MEMORY_HELPER + r"""const p=PARAMETERS;
const all=Process.enumerateModules().filter(m=>m.path===p.module);
if(all.length!==1||all[0].base.toString()!==p.base)throw new Error('module mapping changed before probe installation');
const site=all[0].base.add(p.rva);
// A hook named by export: the module's own export table must agree with the file's (checked before this).
if(p.export!==null){let found=null;try{found=all[0].getExportByName(p.export);}catch(e){}
 if(found===null||!found.equals(site))throw new Error('EXPORT MISMATCH; probe refused');}
const got=readExact(site,p.expect.length);
if(got.some((b,i)=>b!==p.expect[i]))throw new Error('PROLOGUE MISMATCH; probe refused');
let hits=0,seen=0;
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
  seen++;
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
rpc.exports={status(){return {installed:true};},
 counters(){return {seen:seen,hits:hits,limit:p.limit};},release(){send({event:'probe_removed',hook_id:p.id});listener.detach();}};
""".replace("PARAMETERS", parameters)


# ---- the semantic trace agent (TRACE-1 capture, in process) ---------------------------------------------------------
#
# The hot path is a CModule (native code, no JavaScript in a hook): each hooked call writes one fixed-layout record
# into the calling thread's own single-producer ring (no lock, no allocation, no JSON, no hashing, no symbolization,
# no file I/O). A timer in the script drains the rings into one binary batch and `send(..., data)`s it. The counters
# that say what was lost (attempted, dropped, read failures, threads without a ring) live outside the rings and are
# sent on their own message, so a full ring cannot hide its own overflow. Memory is read with ReadProcessMemory on the
# calling process: the kernel refuses an unreadable range with an error code, so no fault is raised in the target and
# no handler (the host's, ours) is ever entered by a probe's read. The layout is documented in `trace_wire`.
# A thread claims a free ring on its first hit and its exit retires the ring (a fiber-local-storage callback), so a
# short-lived thread never exhausts the pool. A full ring makes the hook wait, for a bounded time, for the drain; only
# after that budget is the record dropped, and a drop is counted out of band and cited, never silent. The worker
# acknowledges each batch; with `window` batches unacknowledged the agent stops draining and the rings fill instead.
# (CModule calls a function named `init` itself on construction, so the recorder's is `trace_init`; a CModule's own data
# is read-only on this Frida, so every mutable cell lives in memory the script allocates and the hooks reach it through
# the site they were attached with.)

TRACE_C = r"""
#include <glib.h>
#include <gum/guminterceptor.h>
#include <string.h>

extern int QueryPerformanceCounter(gint64 *);
extern int ReadProcessMemory(void *, const void *, void *, gsize, gsize *);
extern void *FlsGetValue(guint);
extern int FlsSetValue(guint, void *);
extern guint GetLastError(void);
extern guint GetCurrentThreadId(void);
extern int SwitchToThread(void);
extern void *RtlLookupFunctionEntry(guint64, guint64 *, void *);
extern void *RtlVirtualUnwind(guint, guint64, guint64, void *, void *, void **, guint64 *, void *);

#define MAX_RINGS 128
#define BUFMAX 256
#define REC_HDR 64
#define MAX_STACK 15
#define WINDOW 4096
#define SCRATCH 6144

/* One ring per thread that hits a probe, 128 bytes so that two threads never share a cache line. A thread claims a
   free ring on its first hit; when the thread exits the fiber-local-storage callback retires the ring, and the drain
   frees it once it has been read to the end, so the next thread reuses it. */
typedef struct {
  volatile guint32 head;
  volatile guint32 tail;
  guint32 attempted, dropped, read_failed, tid, entered, left, busy, ring_id;
  guint32 stalls, pad1;
  guint64 stall_ticks;
  volatile gint state;      /* 0 free, 1 owned, 2 retired (owner gone, waiting to be drained) */
  guint32 owners;
  guint8 *buf;
  guint8 pad[56];
} Ring;

/* All mutable state lives in memory the script allocates (a CModule's own data is not writable). */
typedef struct {
  guint32 nrings, ring_mask, fls_index, pad;
  volatile gint mode, no_ring_hits, reuses, claim_lock;
  guint64 bp_ticks;
  guint8 *walk_mem;
  Ring rings[MAX_RINGS];
} Shared;

typedef struct { Shared *sh; guint32 id, nargs, flags, buf_max; gint32 buf_ptr_arg, buf_len_arg; guint32 buf_fixed, stack_depth; } Site;

typedef struct {
  guint16 size; guint8 kind, flags; guint16 site, ring;
  guint64 qpc; guint32 tid, ring_seq;
  guint64 ret_addr, qpc_end, retval;
  guint32 last_error; guint16 nargs, buflen;
  guint64 buf_addr;
} Rec;

typedef struct {
  guint64 args[8]; guint64 qpc; guint64 ret_addr; guint64 buf_addr; guint64 stack[MAX_STACK];
  Ring *ring; guint32 live, bflags; guint32 buflen, nstack; guint8 buf[BUFMAX];
} Inv;

guint shared_size(void) { return sizeof(Shared); }
guint site_size(void) { return sizeof(Site); }
guint ring_size(void) { return sizeof(Ring); }

void trace_init(Shared *sh, guint8 *mem, guint count, guint bytes, guint fls, guint64 bp_ticks, guint8 *walk_mem) {
  guint i;
  sh->nrings = count > MAX_RINGS ? MAX_RINGS : count; sh->ring_mask = bytes - 1; sh->fls_index = fls; sh->bp_ticks = bp_ticks; sh->walk_mem = walk_mem;
  for (i = 0; i < sh->nrings; i++) { sh->rings[i].buf = mem + (gsize)i * bytes; sh->rings[i].ring_id = i; }
}

void site_init(Site *s, Shared *sh, guint id, guint nargs, guint flags, gint buf_ptr_arg, gint buf_len_arg, guint buf_fixed, guint buf_max, guint stack_depth) {
  s->sh = sh; s->id = id; s->nargs = nargs > 8 ? 8 : nargs; s->flags = flags;
  s->buf_ptr_arg = buf_ptr_arg; s->buf_len_arg = buf_len_arg; s->buf_fixed = buf_fixed;
  s->buf_max = buf_max > BUFMAX ? BUFMAX : buf_max;
  s->stack_depth = stack_depth > MAX_STACK ? MAX_STACK : stack_depth;
}

void set_mode(Shared *sh, gint m) { sh->mode = m; }

/* The thread is gone: its ring waits to be drained, then it is free for the next thread. */
void exit_cb(void *p) {
  Ring *r = (Ring *)p;
  if (r) r->state = 2;
}

static Ring *claim(Shared *sh) {
  guint i;
  Ring *found = 0;
  /* Claiming is rare (a thread's first hit): a ticket lock built from the one atomic the runtime gives a CModule. */
  while (g_atomic_int_add(&sh->claim_lock, 1) != 0) { g_atomic_int_add(&sh->claim_lock, -1); SwitchToThread(); }
  for (i = 0; i < sh->nrings; i++) {
    Ring *r = &sh->rings[i];
    if (r->state == 0) {
      r->state = 1;
      r->tid = GetCurrentThreadId();
      if (r->owners++) g_atomic_int_add(&sh->reuses, 1);
      FlsSetValue(sh->fls_index, r);
      found = r;
      break;
    }
  }
  g_atomic_int_add(&sh->claim_lock, -1);
  return found;
}

static Ring *get_ring(Shared *sh) {
  Ring *r = (Ring *)FlsGetValue(sh->fls_index);
  if (r) return r;
  r = claim(sh);
  if (!r) g_atomic_int_add(&sh->no_ring_hits, 1);
  return r;
}

static void read_buf(Site *s, Inv *inv, Ring *r) {
  gsize want, got = 0;
  guint64 p;
  guint i;
  if (s->buf_ptr_arg < 0) return;
  p = inv->args[s->buf_ptr_arg];
  if (!p) return;
  inv->buf_addr = p;
  inv->bflags = 16;
  if (s->flags & 2) { want = s->buf_max; inv->bflags |= 8; }
  else if (s->buf_len_arg >= 0) { want = (gsize)(inv->args[s->buf_len_arg] & 0xFFFFFFFFu); if (want > s->buf_max) { want = s->buf_max; inv->bflags |= 4; } }
  else { want = s->buf_fixed > s->buf_max ? s->buf_max : s->buf_fixed; }
  if (want == 0) return;
  ReadProcessMemory((void *)-1, (const void *)(gsize)p, inv->buf, want, &got);
  if (got == 0) { inv->bflags = 16 | 2; inv->buflen = 0; r->read_failed++; return; }
  if (got < want && !(s->flags & 2)) inv->bflags |= 4;
  if (s->flags & 2) {
    for (i = 0; i + 1 < got; i += 2) if (inv->buf[i] == 0 && inv->buf[i + 1] == 0) { got = i + 2; want = got; break; }
    if (got == want && !(want >= 2 && inv->buf[want - 2] == 0 && inv->buf[want - 1] == 0)) inv->bflags |= 4;
  }
  inv->buflen = (guint32)got;
}

/* The caller chain by the OS unwind tables (.pdata), never by guessing and never by touching memory that might not be
   there: the stack above the hooked function is copied with ReadProcessMemory on this process (the kernel refuses an
   unreadable range with an error code, it does not fault), RtlVirtualUnwind runs against the copy, and the registers it
   restores from the copy are mapped back into it. Frames whose code has no unwind data (a leaf, or our own trampoline)
   are read as a return address at the top of the stack. At most MAX_STACK addresses, none past the copied window. */
static guint walk(GumInvocationContext *ic, Shared *sh, Ring *ring, guint64 *out, guint depth) {
  static const guint regs[8] = { 0x90, 0xA0, 0xA8, 0xB0, 0xD8, 0xE0, 0xE8, 0xF0 };  /* rbx rbp rsi rdi r12..r15 */
  GumCpuContext *cpu = ic->cpu_context;
  guint8 *raw = sh->walk_mem + (gsize)ring->ring_id * SCRATCH;
  guint64 *ctx, real, pc, base, frame, *slot, sp;
  guint8 *win;
  gsize got = 0;
  guint n = 0, i;
  void *entry, *handler;
  ctx = (guint64 *)(((gsize)raw + 15) & ~(gsize)15);
  win = (guint8 *)ctx + 1232;
  memset(ctx, 0, 1232);
  memset(win + WINDOW, 0, 256);
  real = (guint64)cpu->rsp + 8;
  ReadProcessMemory((void *)-1, (const void *)(gsize)real, win, WINDOW, &got);
  if (got < 16) return 0;
  pc = (guint64)(gsize)gum_invocation_context_get_return_address(ic);
  out[n++] = pc;
  *(guint32 *)((guint8 *)ctx + 0x30) = 0x10000B;
  ctx[0x90 / 8] = (guint64)cpu->rbx; ctx[0xA0 / 8] = (guint64)cpu->rbp; ctx[0xA8 / 8] = (guint64)cpu->rsi; ctx[0xB0 / 8] = (guint64)cpu->rdi;
  ctx[0xD8 / 8] = (guint64)cpu->r12; ctx[0xE0 / 8] = (guint64)cpu->r13; ctx[0xE8 / 8] = (guint64)cpu->r14; ctx[0xF0 / 8] = (guint64)cpu->r15;
  ctx[0x98 / 8] = (guint64)(gsize)win;
  ctx[0xF8 / 8] = pc;
  while (n < depth) {
    for (i = 0; i < 8; i++) {
      slot = &ctx[regs[i] / 8];
      if (*slot >= real && *slot < real + got) *slot = (guint64)(gsize)win + (*slot - real);
    }
    sp = ctx[0x98 / 8];
    if (sp < (guint64)(gsize)win || sp + 16 > (guint64)(gsize)win + got) break;
    entry = RtlLookupFunctionEntry(pc, &base, 0);
    if (!entry) { pc = *(guint64 *)(gsize)sp; ctx[0x98 / 8] = sp + 8; }
    else { RtlVirtualUnwind(0, base, pc, entry, ctx, &handler, &frame, 0); pc = ctx[0xF8 / 8]; }
    if (pc < 0x10000) break;
    out[n++] = pc;
  }
  return n;
}

static void emit(Ring *r, Site *s, Inv *inv, guint64 ret, guint32 last_error, guint64 qpc_end, gint has_ret) {
  guint32 buflen = inv->buflen, total, head, tail, pos, mask = s->sh->ring_mask, cap = mask + 1, pad = 0, seq, nst = inv->nstack;
  gint64 t0 = 0, t1 = 0;
  Rec *rec;
  guint i;
  total = REC_HDR + 8 * s->nargs + 8 * nst + ((buflen + 7) & ~7u);
  seq = r->attempted++;
  for (;;) {
    head = r->head; tail = r->tail;
    pos = head & mask;
    pad = (pos + total > cap) ? cap - pos : 0;
    if ((guint32)(head - tail) + pad + total <= cap) break;
    /* Full ring: wait for the drain, for a bounded time. A target that is stalled is slower, never wrong; a ring that
       is still full after the budget drops the record, and the drop is counted (out of band) and cited. */
    if (!t0) { QueryPerformanceCounter(&t0); r->stalls++; }
    QueryPerformanceCounter(&t1);
    if ((guint64)(t1 - t0) > s->sh->bp_ticks || total > cap) { r->dropped++; r->stall_ticks += (guint64)(t1 - t0); return; }
    SwitchToThread();
  }
  if (t0) { QueryPerformanceCounter(&t1); r->stall_ticks += (guint64)(t1 - t0); }
  if (pad) { *(guint16 *)(r->buf + pos) = (guint16)pad; r->buf[pos + 2] = 2; r->buf[pos + 3] = 0; head += pad; pos = 0; }
  rec = (Rec *)(r->buf + pos);
  rec->size = (guint16)total; rec->kind = (guint8)(1 | (nst << 4));
  rec->flags = (guint8)(inv->bflags | (has_ret ? 1 : 0));
  rec->site = (guint16)s->id; rec->ring = (guint16)r->ring_id;
  rec->qpc = inv->qpc; rec->tid = r->tid; rec->ring_seq = seq;
  rec->ret_addr = inv->ret_addr; rec->qpc_end = qpc_end; rec->retval = ret;
  rec->last_error = last_error; rec->nargs = (guint16)s->nargs; rec->buflen = (guint16)buflen;
  rec->buf_addr = inv->buf_addr;
  for (i = 0; i < s->nargs; i++) ((guint64 *)(r->buf + pos + REC_HDR))[i] = inv->args[i];
  for (i = 0; i < nst; i++) ((guint64 *)(r->buf + pos + REC_HDR + 8 * s->nargs))[i] = inv->stack[i];
  if (buflen) memcpy(r->buf + pos + REC_HDR + 8 * s->nargs + 8 * nst, inv->buf, buflen);
  r->head = head + total;
}

void on_enter(GumInvocationContext *ic) {
  Site *s = (Site *)gum_invocation_context_get_listener_function_data(ic);
  Ring *r;
  Inv local, *inv;
  guint i;
  gint64 t;
  if (!s->sh->mode) return;
  r = get_ring(s->sh);
  if (!r) return;
  r->busy++;
  inv = (s->flags & 1) ? (Inv *)gum_invocation_context_get_listener_invocation_data(ic, sizeof(Inv)) : &local;
  inv->buflen = 0; inv->bflags = 0; inv->buf_addr = 0; inv->live = 0; inv->nstack = 0;
  for (i = 0; i < s->nargs; i++) inv->args[i] = (guint64)(gsize)gum_invocation_context_get_nth_argument(ic, i);
  inv->ret_addr = (guint64)(gsize)gum_invocation_context_get_return_address(ic);
  if (s->stack_depth > 1) inv->nstack = walk(ic, s->sh, r, inv->stack, s->stack_depth);
  if (s->buf_ptr_arg >= 0) read_buf(s, inv, r);
  QueryPerformanceCounter(&t);
  inv->qpc = (guint64)t;
  inv->ring = r;
  if (s->flags & 1) { inv->live = 1; r->entered++; }
  else emit(r, s, inv, 0, 0, 0, 0);
  r->busy--;
}

void on_leave(GumInvocationContext *ic) {
  Site *s = (Site *)gum_invocation_context_get_listener_function_data(ic);
  Inv *inv = (Inv *)gum_invocation_context_get_listener_invocation_data(ic, sizeof(Inv));
  Ring *r;
  gint64 t;
  guint32 err;
  if (!inv || !inv->live) return;
  r = inv->ring;
  r->busy++;
  err = GetLastError();
  QueryPerformanceCounter(&t);
  if (s->sh->mode) emit(r, s, inv, (guint64)(gsize)gum_invocation_context_get_return_value(ic), err, (guint64)t, 1);
  inv->live = 0;
  r->left++;
  r->busy--;
}

guint drain(Shared *sh, guint8 *out, guint cap, guint *records) {
  guint i, used = 0, n = 0;
  for (i = 0; i < sh->nrings; i++) {
    Ring *r = &sh->rings[i];
    guint32 tail, head;
    if (r->state == 0) continue;
    tail = r->tail; head = r->head;
    while (tail != head) {
      guint8 *p = r->buf + (tail & sh->ring_mask);
      guint16 size = *(guint16 *)p;
      if (size < 8) { tail = head; break; }
      if ((p[2] & 15) == 1) {
        if (used + size > cap) break;
        memcpy(out + used, p, size); used += size; n++;
      }
      tail += size;
    }
    r->tail = tail;
    if (r->state == 2 && r->tail == r->head && r->busy == 0) r->state = 0;
  }
  *records = n;
  return used;
}

void counters(Shared *sh, guint64 *out) {
  guint i;
  guint64 a = 0, d = 0, f = 0, e = 0, l = 0, b = 0, st = 0, stt = 0, used = 0;
  for (i = 0; i < sh->nrings; i++) {
    Ring *r = &sh->rings[i];
    a += r->attempted; d += r->dropped; f += r->read_failed; e += r->entered; l += r->left; b += r->busy; st += r->stalls; stt += r->stall_ticks;
    if (r->owners) used = i + 1;
  }
  out[0] = a; out[1] = d; out[2] = f; out[3] = (guint64)sh->no_ring_hits; out[4] = e; out[5] = l; out[6] = b; out[7] = used;
  out[8] = st; out[9] = stt; out[10] = (guint64)sh->reuses;
}

void ring_stats(Shared *sh, guint i, guint64 *out) {
  Ring *r = &sh->rings[i];
  out[0] = r->attempted; out[1] = r->dropped; out[2] = r->read_failed; out[3] = r->tid;
  out[4] = (guint32)(r->head - r->tail); out[5] = r->entered; out[6] = r->left; out[7] = r->busy;
  out[8] = r->stalls; out[9] = r->stall_ticks; out[10] = (guint64)r->state; out[11] = r->owners;
}
"""

TRACE_AGENT = r"""
const P=PARAMETERS;
const k32=Process.getModuleByName('kernel32.dll'),ntdll=Process.getModuleByName('ntdll.dll');
const x=(m,n)=>m.getExportByName(n);
const qpcFn=x(k32,'QueryPerformanceCounter');
const qpcNative=new NativeFunction(qpcFn,'int',['pointer']);
const scratch=Memory.alloc(64);
function qpcNow(){qpcNative(scratch);return scratch.readU64();}
// ---- non-faulting reads (attach time): a validated readable range, then readVolatile; null on any failure ----------
function rv(address,n){try{const q=ptr(address),r=Process.findRangeByAddress(q);
  if(r===null||r.protection.indexOf('r')<0||q.add(n).compare(r.base.add(r.size))>0)return null;
  const b=q.readVolatile(n);return b===null||b.byteLength!==n?null:b;}catch(e){return null;}}
function rptr(address){const b=rv(address,Process.pointerSize);if(b===null)return null;
  return Process.pointerSize===8?ptr(new DataView(b).getBigUint64(0,true).toString()):ptr(new DataView(b).getUint32(0,true));}
function where(a){if(a===null)return null;const m=Process.findModuleByAddress(a);
  return m===null?{address:a.toString(),module:null}:{address:a.toString(),module:m.name,rva:a.sub(m.base).toString()};}
// ---- the host's fault policy as it stands at attach (spec 15.1) -----------------------------------------------------
function faultContext(){
  const ctx={debugger_present:Process.isDebuggerAttached(),veh:[],veh_error:null,uef:null,uef_error:null,frida_handler_index:null};
  try{const isdbg=new NativeFunction(x(k32,'IsDebuggerPresent'),'int',[]);ctx.is_debugger_present_api=isdbg()!==0;}catch(e){ctx.is_debugger_present_api=null;}
  if(Process.pointerSize===8){try{
    const add=new NativeFunction(x(ntdll,'RtlAddVectoredExceptionHandler'),'pointer',['uint','pointer']);
    const rem=new NativeFunction(x(ntdll,'RtlRemoveVectoredExceptionHandler'),'uint',['pointer']);
    const dec=new NativeFunction(x(ntdll,'RtlDecodePointer'),'pointer',['pointer']);
    const mine=new NativeCallback(()=>0,'int',['pointer']);
    const entry=add(1,mine);
    if(entry.isNull())throw new Error('could not add the probe handler');
    // The handler slot is found by decoding candidates until one is our own callback.
    let slot=null;for(const off of [0x10,0x18,0x20,0x8]){const e=rptr(entry.add(off));if(e!==null&&dec(e).equals(mine)){slot=off;break;}}
    if(slot===null){rem(entry);throw new Error('unrecognised vectored handler entry layout');}
    let node=rptr(entry),guard=0;const base=ntdll.base,end=ntdll.base.add(ntdll.size);
    while(node!==null&&!node.isNull()&&guard++<64){
      if(node.compare(base)>=0&&node.compare(end)<0)break;
      if(node.equals(entry))break;
      const enc=rptr(node.add(slot));if(enc===null){ctx.veh.push({error:'unreadable entry at '+node});break;}
      ctx.veh.push(where(dec(enc)));node=rptr(node);
    }
    rem(entry);
    const fi=ctx.veh.findIndex(v=>v&&v.module&&/frida/i.test(v.module));
    ctx.frida_handler_index=fi<0?null:fi;
  }catch(e){ctx.veh_error=String(e);}}
  try{const set=new NativeFunction(x(k32,'SetUnhandledExceptionFilter'),'pointer',['pointer']);
    const prev=set(ptr(0));set(prev);ctx.uef=prev.isNull()?null:where(prev);}catch(e){ctx.uef_error=String(e);}
  return ctx;
}
const context=faultContext();
// ---- the probes: each must match its build before anything is attached ----------------------------------------------
const mods=Process.enumerateModules();
function readExact(address,n){const b=rv(address,n);if(b===null)throw new Error('live memory read was incomplete at '+address);return Array.from(new Uint8Array(b));}
const verified=[];
for(const pr of P.probes){
  const hit=mods.filter(m=>m.path===pr.module);
  if(hit.length!==1||hit[0].base.toString()!==pr.base)throw new Error('module mapping changed before probe installation: '+pr.name);
  const site=hit[0].base.add(pr.rva);
  const got=readExact(site,pr.expect.length);
  if(got.some((b,i)=>b!==pr.expect[i]))throw new Error('PROLOGUE MISMATCH; probe refused: '+pr.name);
  verified.push({probe:pr,site});
}
// ---- the native recorder ------------------------------------------------------------------------------------------------
const freqFn=new NativeFunction(x(k32,'QueryPerformanceFrequency'),'int',['pointer']);freqFn(scratch);
const qpcFreq=scratch.readU64();
const cm=new CModule(P.c_source,{QueryPerformanceCounter:qpcFn,ReadProcessMemory:x(k32,'ReadProcessMemory'),
  FlsGetValue:x(k32,'FlsGetValue'),FlsSetValue:x(k32,'FlsSetValue'),GetLastError:x(k32,'GetLastError'),
  GetCurrentThreadId:x(k32,'GetCurrentThreadId'),SwitchToThread:x(k32,'SwitchToThread'),
  RtlLookupFunctionEntry:x(ntdll,'RtlLookupFunctionEntry'),RtlVirtualUnwind:x(ntdll,'RtlVirtualUnwind')});
const flsAlloc=new NativeFunction(x(k32,'FlsAlloc'),'uint',['pointer']);
const flsFree=new NativeFunction(x(k32,'FlsFree'),'int',['uint']);
const fls=flsAlloc(cm.exit_cb);
const f={init:new NativeFunction(cm.trace_init,'void',['pointer','pointer','uint','uint','uint','uint64','pointer']),
  shared_size:new NativeFunction(cm.shared_size,'uint',[]),site_size:new NativeFunction(cm.site_size,'uint',[]),
  site_init:new NativeFunction(cm.site_init,'void',['pointer','pointer','uint','uint','uint','int','int','uint','uint','uint']),
  set_mode:new NativeFunction(cm.set_mode,'void',['pointer','int']),
  drain:new NativeFunction(cm.drain,'uint',['pointer','pointer','uint','pointer']),
  counters:new NativeFunction(cm.counters,'void',['pointer','pointer']),
  ring_stats:new NativeFunction(cm.ring_stats,'void',['pointer','uint','pointer'])};
const shared=Memory.alloc(f.shared_size()),siteSize=f.site_size(),siteMem=Memory.alloc(siteSize*(P.probes.length+1));
const ringMem=Memory.alloc(P.rings*P.ring_bytes),walkMem=Memory.alloc(P.rings*6144);
// a stalled producer waits at most this long for the drain before a record is dropped (and counted)
const bpTicks=Math.floor(qpcFreq.toNumber()*P.bp_us/1000000);
f.init(shared,ringMem,P.rings,P.ring_bytes,fls,bpTicks,walkMem);
const HDR=64,outCap=P.batch_bytes,out=Memory.alloc(HDR+outCap),cnt=Memory.alloc(128),nrec=Memory.alloc(8),rs=Memory.alloc(128);
let batchSeq=0,acked=0,released=false,sentBatches=0,sentBytes=0,windowWaits=0,flushTimer=null;
function readCounters(){f.counters(shared,cnt);const v=[];for(let i=0;i<11;i++)v.push(cnt.add(8*i).readU64().toNumber());return v;}
function ringRows(){const c=readCounters(),rows=[];for(let i=0;i<c[7];i++){f.ring_stats(shared,i,rs);
  rows.push({ring:i,attempted:rs.readU64().toNumber(),dropped:rs.add(8).readU64().toNumber(),read_failed:rs.add(16).readU64().toNumber(),
   tid:rs.add(24).readU64().toNumber(),occupancy:rs.add(32).readU64().toNumber(),stalls:rs.add(64).readU64().toNumber(),
   stall_ticks:rs.add(72).readU64().toNumber(),state:rs.add(80).readU64().toNumber(),owners:rs.add(88).readU64().toNumber()});}return rows;}
// The worker acknowledges every batch it has written. At most `window` batches are in flight, so a slow writer fills the
// rings (and stalls, then counts, the producers) instead of growing the agent's memory without bound.
recv('ack',function onAck(m){if(m.seq+1>acked)acked=m.seq+1;recv('ack',onAck);});
function flush(){
  let total=0,sent=0;
  for(;;){
    if(batchSeq-acked>=P.window){windowWaits++;break;}
    const used=f.drain(shared,out.add(HDR),outCap,nrec);if(used===0)break;
    const c=readCounters();
    out.writeU32(0x31425448);out.add(4).writeU16(1);out.add(6).writeU16(HDR);out.add(8).writeU32(P.producer_gen);
    out.add(12).writeU32(batchSeq>>>0);out.add(16).writeU64(qpcNow());out.add(24).writeU32(nrec.readU32());out.add(28).writeU32(used);
    out.add(32).writeU64(c[0]);out.add(40).writeU64(c[1]);out.add(48).writeU64(c[2]);out.add(56).writeU64(c[3]);
    send({event:'trace_batch',batch_seq:batchSeq},out.readByteArray(HDR+used));
    batchSeq++;sentBatches++;sentBytes+=used;total+=used;sent++;if(sent>=16)break;
  }
  return total;
}
function counterMessage(final){const c=readCounters();
  send({event:'trace_counters',final:!!final,t:qpcNow().toString(),attempted:c[0],dropped:c[1],read_failed:c[2],no_ring:c[3],
    entered:c[4],left:c[5],busy:c[6],rings_used:c[7],stalls:c[8],stall_ticks:c[9],ring_reuses:c[10],qpc_freq:qpcFreq.toString(),
    window_waits:windowWaits,bp_us:P.bp_us,batches_sent:sentBatches,batches_next:batchSeq,rings:ringRows()});}
// A drain that found data runs again at once; an idle one waits batch_ms.
function pump(){flushTimer=setTimeout(()=>{let n=0;try{n=flush();}catch(e){}pump2(n);},0);}
function pump2(n){if(released)return;flushTimer=setTimeout(()=>{let m=0;try{m=flush();}catch(e){}pump2(m);},n>0?0:P.batch_ms);}
pump();
const counterTimer=setInterval(()=>counterMessage(false),P.counter_ms);
// ---- attach (everything is verified above) -----------------------------------------------------------------------------
const listeners=[],installed=[];
for(const v of verified){const pr=v.probe,t0=Date.now(),b=pr.buf;
  const flags=(pr.with_leave?1:0)|(b&&b.wide?2:0);
  const s=siteMem.add(siteSize*installed.length);
  f.site_init(s,shared,pr.id,pr.nargs,flags,b?b.ptr_arg:-1,b&&b.len_arg!==null&&b.len_arg!==undefined?b.len_arg:-1,b&&b.fixed?b.fixed:0,b?b.max:0,pr.stack||1);
  listeners.push(Interceptor.attach(v.site,pr.with_leave?{onEnter:cm.on_enter,onLeave:cm.on_leave}:{onEnter:cm.on_enter},s));
  installed.push({id:pr.id,name:pr.name,address:v.site.toString(),install_ms:Date.now()-t0});}
f.set_mode(shared,1);
send({event:'trace_ready',context,qpc_freq:qpcFreq.toString(),producer_gen:P.producer_gen,pid:Process.id,arch:Process.arch,
  rings:P.rings,ring_bytes:P.ring_bytes,batch_ms:P.batch_ms,bp_us:P.bp_us,window:P.window,installed,qpc:qpcNow().toString(),fls_index:fls});
rpc.exports={
  status(){return {installed:true,mode:released?'released':'recording'};},
  counters(){return {counters:readCounters(),rings:ringRows(),batches_sent:sentBatches};},
  flush(){return flush();},
  // Pass-through, detach, prove the callbacks quiescent. A failed proof keeps the recorder in place, in pass-through,
  // and says so; the worker must not unload the script then (unloading frees the callbacks).
  release(timeoutMs){
    f.set_mode(shared,0);
    Thread.sleep(0.05);
    acked=batchSeq;           // the writer is being closed: drain what is left without waiting for acknowledgements
    for(let i=0;i<64;i++){if(flush()===0)break;acked=batchSeq;}
    for(const l of listeners)l.detach();
    Interceptor.flush();
    const t0=Date.now();let stable=0,ok=false;
    while(Date.now()-t0<timeoutMs){
      const c=readCounters();
      if(c[6]===0&&c[4]===c[5]){stable++;if(stable>=3){ok=true;break;}}else stable=0;
      Thread.sleep(0.025);}
    const c=readCounters();
    const result={quiescent:ok,waited_ms:Date.now()-t0,busy:c[6],entered:c[4],left:c[5]};
    if(ok){released=true;if(flushTimer!==null)clearTimeout(flushTimer);clearInterval(counterTimer);
      acked=batchSeq;for(let i=0;i<64;i++){if(flush()===0)break;acked=batchSeq;}
      counterMessage(true);
      flsFree(fls);          // runs the exit callback for every thread still holding a ring, while the code is still loaded
      result.note='detached and quiescent; the script may be unloaded';}
    else{flush();result.note='callbacks still in flight; recorder retained in pass-through';}
    return result;}
};
"""


def trace_agent_source(parameters: dict) -> str:
    """The trace agent script for one session. `parameters` is rendered as JSON; the C source travels with it."""
    return TRACE_AGENT.replace("PARAMETERS", json.dumps({**parameters, "c_source": TRACE_C}), 1)
