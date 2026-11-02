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
extern int TlsSetValue(guint, void *);
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
#define MAX_SITES 64
#define CREC_HDR 32
#define F_SAMPLED 32

/* One ring per thread that hits a probe. The producer's fields share one 64-byte line (only the owning thread writes
   them) and the drain's share another (only the drain thread writes them), so a drain never takes the producer's line
   away from it on every hit. A thread claims a free ring on its first hit; when the thread exits the fiber-local-storage
   callback retires the ring, and the drain frees it once it has been read to the end, so the next thread reuses it. */
/* Per ring and probe: every hit counted, and the ones that were kept (took a ring_seq). hits - kept is the exact number
   of hits the sampling policy skipped; nothing is estimated. */
typedef struct { guint64 hits, kept, next, pad; } SCtr;   /* next: hits to skip before the next kept one (0 keeps this one) */

typedef struct {
  guint8 *buf;
  volatile guint32 head;    /* the one release store that publishes a record */
  guint32 tail_seen;        /* the producer's last look at tail: a hit only re-reads the drain's line when this says full */
  guint32 attempted, dropped, read_failed, tid;
  guint32 entered, left, busy, ring_id;
  volatile gint shedding;   /* a stall ran out of patience: drop (and count) at once until the drain has freed half the ring */
  guint32 owners, stalls, pad1;
  volatile guint32 tail;    /* ---- the drain's line ---- */
  volatile gint state;      /* 0 free, 1 owned, 2 retired (owner gone, waiting to be drained) */
  guint64 stall_ticks;
  guint8 pad2[48];
  SCtr ctr[MAX_SITES];      /* offset 128: the inline stub's gate counts hits here with a fixed displacement */
} Ring;

/* All mutable state lives in memory the script allocates (a CModule's own data is not writable). */
typedef struct {
  guint32 nrings, ring_mask, fls_index, nsites;
  volatile gint mode, no_ring_hits, reuses, claim_lock;
  guint64 bp_ticks;
  guint8 *walk_mem;
  gint32 tls_index, use_qpc;
  guint64 tsc0, qpc0;
  double ratio;             /* QPC ticks per TSC tick, refined from the whole interval since init at every drain */
  guint8 pad[48];
  Ring rings[MAX_RINGS];
} Shared;

typedef struct { Shared *sh; guint32 id, nargs, flags, buf_max; gint32 buf_ptr_arg, buf_len_arg; guint32 buf_fixed, stack_depth;
  volatile guint32 mask; guint32 fast; } Site;   /* mask: stride - 1; after a kept hit the next `mask` hits of a thread are skipped */

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

static inline guint64 rdtsc_(void) { guint32 lo, hi; __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi)); return ((guint64)hi << 32) | lo; }
/* gs:[0x1480 + 8 * i] is TEB.TlsSlots[i]: the thread's own pointer without a call (valid for the first 64 TLS indexes). */
static inline void *tls_slot_(guint i) { guint64 v; __asm__ __volatile__("movq %%gs:0x1480(,%1,8), %0" : "=r"(v) : "r"((guint64)i)); return (void *)v; }
/* CPUID 0x80000007 EDX bit 8: the TSC ticks at one rate whatever the core does, and is kept in step across cores. */
static guint invariant_tsc_(void) {
  guint32 a = 0x80000000u, b, c = 0, d;
  __asm__ __volatile__("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
  if (a < 0x80000007u) return 0;
  a = 0x80000007u; c = 0;
  __asm__ __volatile__("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
  return (d >> 8) & 1;
}

/* Refine the TSC -> QPC ratio from the whole interval since init, so the error of converting a record shrinks as the
   run goes on. Called by the drain (never by a hit). */
static void recalibrate(Shared *sh) {
  gint64 q; guint64 t;
  if (sh->use_qpc) return;
  QueryPerformanceCounter(&q); t = rdtsc_();
  if (t - sh->tsc0 > 3000000u && (guint64)q > sh->qpc0) sh->ratio = (double)(gint64)((guint64)q - sh->qpc0) / (double)(gint64)(t - sh->tsc0);
}

void trace_init(Shared *sh, guint8 *mem, guint count, guint bytes, guint fls, guint64 bp_ticks, guint8 *walk_mem, gint tls, guint nsites) {
  guint i;
  gint64 q0, q1;
  guint64 t0, t1;
  sh->nrings = count > MAX_RINGS ? MAX_RINGS : count; sh->ring_mask = bytes - 1; sh->fls_index = fls; sh->bp_ticks = bp_ticks; sh->walk_mem = walk_mem;
  sh->tls_index = (tls >= 0 && tls < 64) ? tls : -1;
  sh->nsites = nsites > MAX_SITES ? MAX_SITES : nsites;
  for (i = 0; i < sh->nrings; i++) { sh->rings[i].buf = mem + (gsize)i * bytes; sh->rings[i].ring_id = i; }
  /* The hit stamps with the TSC (a few ns, no call); the drain converts to QPC. A 2 ms look at both gives the first ratio. */
  sh->use_qpc = invariant_tsc_() ? 0 : 1;
  QueryPerformanceCounter(&q0); t0 = rdtsc_();
  do { QueryPerformanceCounter(&q1); } while (q1 - q0 < 20000);
  t1 = rdtsc_();
  sh->tsc0 = t0; sh->qpc0 = (guint64)q0;
  sh->ratio = (double)(q1 - q0) / (double)(gint64)(t1 - t0);
}

void site_init(Site *s, Shared *sh, guint id, guint nargs, guint flags, gint buf_ptr_arg, gint buf_len_arg, guint buf_fixed, guint buf_max, guint stack_depth) {
  s->sh = sh; s->id = id < MAX_SITES ? id : MAX_SITES - 1; s->nargs = nargs > 8 ? 8 : nargs; s->flags = flags;
  s->buf_ptr_arg = buf_ptr_arg; s->buf_len_arg = buf_len_arg; s->buf_fixed = buf_fixed;
  s->buf_max = buf_max > BUFMAX ? BUFMAX : buf_max;
  s->stack_depth = stack_depth > MAX_STACK ? MAX_STACK : stack_depth;
  s->mask = 0;
  /* the lean record: a plain call site (no return, no buffer, no stack walk) */
  s->fast = (!(flags & 1) && buf_ptr_arg < 0 && stack_depth <= 1) ? 1 : 0;
}

void set_mode(Shared *sh, gint m) { sh->mode = m; }
void set_mask(Site *s, guint m) { s->mask = m; }

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
      if (sh->tls_index >= 0) TlsSetValue((guint)sh->tls_index, r);
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
  else if (s->flags & 4) { want = s->buf_max; }
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
  if ((s->flags & 4) && !(s->flags & 2)) {
    /* a NUL-terminated byte string: the id is of the characters, not of what follows them in memory */
    for (i = 0; i < got; i++) if (inv->buf[i] == 0) break;
    if (i == got && got == want) inv->bflags |= 4; else got = i;
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

/* Room for `total` bytes in the ring, or -1. The slow half of a write: a full ring makes the hit wait for the drain for a
   bounded time (bp_ticks; 0 means never wait), then the record is dropped, counted, and the ring sheds until the drain
   has freed half of it. Returns the position and, in *padp, the bytes of padding to write before it. */
static gint reserve(Ring *r, Shared *sh, guint32 total, guint32 *padp) {
  guint32 head, mask = sh->ring_mask, cap = mask + 1, pos, pad;
  gint64 t0 = 0, t1 = 0;
  if (r->shedding) {
    if ((guint32)(r->head - r->tail) <= cap / 2) r->shedding = 0;
    else { r->dropped++; return -1; }
  }
  for (;;) {
    head = r->head; r->tail_seen = r->tail;
    pos = head & mask;
    pad = (pos + total > cap) ? cap - pos : 0;
    if ((guint32)(head - r->tail_seen) + pad + total <= cap) break;
    if (!t0) { QueryPerformanceCounter(&t0); r->stalls++; }
    QueryPerformanceCounter(&t1);
    if ((guint64)(t1 - t0) > sh->bp_ticks || total > cap) { r->dropped++; r->shedding = 1; r->stall_ticks += (guint64)(t1 - t0); return -1; }
    SwitchToThread();
  }
  if (t0) { QueryPerformanceCounter(&t1); r->stall_ticks += (guint64)(t1 - t0); }
  *padp = pad;
  return (gint)pos;
}

/* Writes the padding record that ends the ring's last lap and publishes it; the record then starts at position 0. */
static void put_pad(Ring *r, Shared *sh, guint32 pad) {
  guint32 head = r->head, at = head & sh->ring_mask;
  *(guint16 *)(r->buf + at) = (guint16)pad; r->buf[at + 2] = 2; r->buf[at + 3] = 0;
  r->head = head + pad;
}

/* The full-format record: a site with a return, a buffer or a stack walk. */
static void emit(Ring *r, Site *s, Inv *inv, guint64 ret, guint32 last_error, guint64 qpc_end, gint has_ret) {
  guint32 buflen = inv->buflen, total, pos, pad = 0, seq, nst = inv->nstack;
  gint p;
  Rec *rec;
  guint8 *base;
  guint i;
  total = REC_HDR + 8 * s->nargs + 8 * nst + ((buflen + 7) & ~7u);
  seq = r->attempted++;
  p = reserve(r, s->sh, total, &pad);
  if (p < 0) return;
  if (pad) { put_pad(r, s->sh, pad); p = 0; }
  pos = (guint32)p;
  base = r->buf + pos;
  rec = (Rec *)base;
  rec->size = (guint16)total; rec->kind = (guint8)(1 | (nst << 4));
  rec->flags = (guint8)(inv->bflags | (has_ret ? 1 : 0) | (s->mask ? F_SAMPLED : 0));
  rec->site = (guint16)s->id; rec->ring = (guint16)r->ring_id;
  rec->qpc = inv->qpc; rec->tid = r->tid; rec->ring_seq = seq;
  rec->ret_addr = inv->ret_addr; rec->qpc_end = qpc_end; rec->retval = ret;
  rec->last_error = last_error; rec->nargs = (guint16)s->nargs; rec->buflen = (guint16)buflen;
  rec->buf_addr = inv->buf_addr;
  for (i = 0; i < s->nargs; i++) ((guint64 *)(base + REC_HDR))[i] = inv->args[i];
  for (i = 0; i < nst; i++) ((guint64 *)(base + REC_HDR + 8 * s->nargs))[i] = inv->stack[i];
  if (buflen) memcpy(base + REC_HDR + 8 * s->nargs + 8 * nst, inv->buf, buflen);
  r->head = r->head + total;
}

/* The lean record of a plain site, the whole hit: a TSC read, a few register copies and one release store. Layout:
   0 u16 size, 2 u8 kind 3, 3 u8 nargs, 4 u16 site, 6 u16 flags, 8 u32 ring_seq, 16 u64 tsc, 24 u64 return address,
   32 u64 args[nargs]. The drain turns it into the wire record.
   `fr` is the frame the inline stub (or on_enter) builds: argument i < 4 is fr[5 - i], argument i >= 4 is fr[9 + i]. */
static void emit_fast(Ring *r, Site *s, Shared *sh, guint64 ret, const guint64 *fr) {
  guint32 n = s->nargs, total = CREC_HDR + 8 * n, head = r->head, mask = sh->ring_mask, pos = head & mask, pad = 0;
  guint8 *rec;
  guint64 t, *a;
  gint64 q;
  guint i;
  if (r->shedding || pos + total > mask + 1 || (guint32)(head - r->tail_seen) + total > mask + 1) {
    gint p;
    guint32 seq0 = r->attempted;
    r->attempted = seq0 + 1;       /* a dropped record takes its ring_seq too */
    p = reserve(r, sh, total, &pad);
    if (p < 0) return;
    r->attempted = seq0;           /* kept: the common path below takes the ticket */
    if (pad) put_pad(r, sh, pad);
    head = r->head;
    pos = head & mask;
  }
  if (sh->use_qpc) { QueryPerformanceCounter(&q); t = (guint64)q; } else t = rdtsc_();
  rec = r->buf + pos;
  *(guint64 *)rec = (guint64)(guint16)total | ((guint64)3 << 16) | ((guint64)n << 24) | ((guint64)s->id << 32) | ((guint64)(s->mask ? F_SAMPLED : 0) << 48);
  *(guint32 *)(rec + 8) = r->attempted++;
  *(guint64 *)(rec + 16) = t;
  *(guint64 *)(rec + 24) = ret;
  a = (guint64 *)(rec + 32);
  for (i = 0; i < n; i++) a[i] = i < 4 ? fr[5 - i] : fr[9 + i];
  r->head = head + total;
}

/* The inline hooks' entries (no Interceptor). The stub has saved the volatile registers and calls one of these with the
   site and the frame it pushed (fr[8] is the return address). hit_keep: the stub's own gate already counted the hit and
   decided to keep it. hit_full: the thread has no ring yet (or the gate could not run): the whole of on_enter's work. */
void hit_keep(Site *s, guint64 *fr) {
  Shared *sh = s->sh;
  Ring *r;
  SCtr *c;
  r = (Ring *)tls_slot_((guint)sh->tls_index);
  if (!r) return;
  c = &r->ctr[s->id];
  c->next = s->mask;           /* the gate counted this hit and let it through: the next `mask` are skipped */
  if (!sh->mode) return;
  r->busy++;
  c->kept++;
  emit_fast(r, s, sh, fr[8], fr);
  r->busy--;
}

void hit_full(Site *s, guint64 *fr) {
  Shared *sh = s->sh;
  Ring *r;
  SCtr *c;
  if (!sh->mode) return;
  r = sh->tls_index >= 0 ? (Ring *)tls_slot_((guint)sh->tls_index) : (Ring *)FlsGetValue(sh->fls_index);
  if (!r) { r = get_ring(sh); if (!r) return; }
  r->busy++;
  c = &r->ctr[s->id];
  c->hits++;
  if (c->next) c->next--;
  else { c->next = s->mask; c->kept++; emit_fast(r, s, sh, fr[8], fr); }
  r->busy--;
}

void on_enter(GumInvocationContext *ic) {
  Site *s = (Site *)gum_invocation_context_get_listener_function_data(ic);
  Shared *sh = s->sh;
  Ring *r;
  SCtr *c;
  Inv local, *inv;
  guint i;
  gint64 t;
  if (!sh->mode) return;
  r = sh->tls_index >= 0 ? (Ring *)tls_slot_((guint)sh->tls_index) : (Ring *)FlsGetValue(sh->fls_index);
  if (!r) { r = get_ring(sh); if (!r) return; }
  r->busy++;
  c = &r->ctr[s->id];
  if (s->flags & 1) {
    inv = (Inv *)gum_invocation_context_get_listener_invocation_data(ic, sizeof(Inv));
    inv->live = 0;
  } else inv = &local;
  c->hits++;
  if (c->next) { c->next--; r->busy--; return; }       /* skipped by the sampling policy: counted, nothing else */
  c->next = s->mask; c->kept++;
  if (s->fast) {
    GumCpuContext *cpu = ic->cpu_context;
    guint64 fr[18];
    fr[5] = (guint64)cpu->rcx; fr[4] = (guint64)cpu->rdx; fr[3] = (guint64)cpu->r8; fr[2] = (guint64)cpu->r9;
    for (i = 4; i < s->nargs; i++) fr[9 + i] = (guint64)(gsize)gum_invocation_context_get_nth_argument(ic, i);
    emit_fast(r, s, sh, *(guint64 *)(gsize)cpu->rsp, fr);
    r->busy--; return;
  }
  inv->buflen = 0; inv->bflags = 0; inv->buf_addr = 0; inv->nstack = 0;
  for (i = 0; i < s->nargs; i++) inv->args[i] = (guint64)(gsize)gum_invocation_context_get_nth_argument(ic, i);
  inv->ret_addr = (guint64)(gsize)gum_invocation_context_get_return_address(ic);
  if (s->stack_depth > 1) inv->nstack = walk(ic, sh, r, inv->stack, s->stack_depth);
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
  recalibrate(sh);
  for (i = 0; i < sh->nrings; i++) {
    Ring *r = &sh->rings[i];
    guint32 tail, head;
    if (r->state == 0) continue;
    tail = r->tail; head = r->head;
    while (tail != head) {
      guint8 *p = r->buf + (tail & sh->ring_mask);
      guint16 size = *(guint16 *)p;
      guint kind;
      if (size < 8) { tail = head; break; }
      kind = p[2] & 15;
      if (kind == 1) {
        if (used + size > cap) break;
        memcpy(out + used, p, size); used += size; n++;
      } else if (kind == 3) {
        guint nargs = p[3], wire = REC_HDR + 8 * nargs;
        Rec *w;
        guint64 t = *(guint64 *)(p + 16);
        if (used + wire > cap) break;
        w = (Rec *)(out + used);
        w->size = (guint16)wire; w->kind = 1; w->flags = (guint8)(*(guint16 *)(p + 6));
        w->site = *(guint16 *)(p + 4); w->ring = (guint16)r->ring_id;
        w->qpc = sh->use_qpc ? t : sh->qpc0 + (guint64)(gint64)((double)(gint64)(t - sh->tsc0) * sh->ratio);
        w->tid = r->tid; w->ring_seq = *(guint32 *)(p + 8);
        w->ret_addr = *(guint64 *)(p + 24); w->qpc_end = 0; w->retval = 0;
        w->last_error = 0; w->nargs = (guint16)nargs; w->buflen = 0; w->buf_addr = 0;
        memcpy(out + used + REC_HDR, p + 32, 8 * nargs);
        used += wire; n++;
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

/* Per probe, over every ring: out[2i] = hits, out[2i+1] = kept. hits - kept is the exact count the policy skipped. */
void site_stats(Shared *sh, guint64 *out) {
  guint i, j;
  for (j = 0; j < sh->nsites; j++) { out[2 * j] = 0; out[2 * j + 1] = 0; }
  for (i = 0; i < sh->nrings; i++)
    for (j = 0; j < sh->nsites; j++) { out[2 * j] += sh->rings[i].ctr[j].hits; out[2 * j + 1] += sh->rings[i].ctr[j].kept; }
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
  FlsGetValue:x(k32,'FlsGetValue'),FlsSetValue:x(k32,'FlsSetValue'),TlsSetValue:x(k32,'TlsSetValue'),GetLastError:x(k32,'GetLastError'),
  GetCurrentThreadId:x(k32,'GetCurrentThreadId'),SwitchToThread:x(k32,'SwitchToThread'),
  RtlLookupFunctionEntry:x(ntdll,'RtlLookupFunctionEntry'),RtlVirtualUnwind:x(ntdll,'RtlVirtualUnwind')});
const flsAlloc=new NativeFunction(x(k32,'FlsAlloc'),'uint',['pointer']);
const flsFree=new NativeFunction(x(k32,'FlsFree'),'int',['uint']);
const fls=flsAlloc(cm.exit_cb);
// The hot path finds its thread's ring through the TEB's TLS slot (no call); that needs an index below 64.
const tlsAlloc=new NativeFunction(x(k32,'TlsAlloc'),'uint',[]),tlsFree=new NativeFunction(x(k32,'TlsFree'),'int',['uint']);
let tls=tlsAlloc();if(tls>=64){tlsFree(tls);tls=-1;}
const f={init:new NativeFunction(cm.trace_init,'void',['pointer','pointer','uint','uint','uint','uint64','pointer','int','uint']),
  set_mask:new NativeFunction(cm.set_mask,'void',['pointer','uint']),site_stats:new NativeFunction(cm.site_stats,'void',['pointer','pointer']),
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
const nSites=P.probes.reduce((m,p)=>Math.max(m,p.id+1),1);
f.init(shared,ringMem,P.rings,P.ring_bytes,fls,bpTicks,walkMem,tls,nSites);
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
    batchSeq++;sentBatches++;sentBytes+=used;total+=used;sent++;if(sentBatches===1)counterMessage(false);if(sent>=16)break;
  }
  return total;
}
// ---- the sampling policy (declared in the trace parameters, reported in the health) -------------------------------------
// Every hit is counted per probe in the hook (hits, and kept = took a ring_seq); a hit the policy skips costs a counter
// and a mask test, nothing else, and is reported exactly (hits - kept). `adaptive` (the default) keeps every hit while the
// offered rate fits the budget and, when it does not, thins the busiest probes by a power-of-two stride so that the kept
// records fit: a probe that cannot be thinned fairly (under its fair share) stays exact. A record kept while a probe is
// thinned carries the `sampled` flag. A function that is entered and left is decided at its enter: a skipped enter never
// has an exit, so a pair is whole or absent. `exact` never thins (a full ring still drops, counted); `fixed` keeps one hit
// in `stride`. Ring overflow halves the effective budget; calm periods win it back.
const SP=Object.assign({mode:'adaptive',rate_budget:120000,stride:1,exact:[],interval_ms:25},P.sampling||{});
const sites=[],ss=Memory.alloc(16*64+64);
const sampler={t0:qpcNow().toNumber(),mode:SP.mode,budget:SP.rate_budget,effective:SP.rate_budget,lastT:null,lastHits:{},lastDrops:0,rate:{},stride:{},changes:0,thinned_ms:0};
function strideFor(id,name){return SP.exact.indexOf(name)>=0?1:null;}
function pow2ge(x){let p=1;while(p<x&&p<65536)p*=2;return p;}
function readSiteStats(){f.site_stats(shared,ss);const o={};for(const st of sites){o[st.id]={hits:ss.add(16*st.id).readU64().toNumber(),kept:ss.add(16*st.id+8).readU64().toNumber()};}return o;}
function applyStride(st,stride){if(sampler.stride[st.id]!==stride){sampler.stride[st.id]=stride;f.set_mask(st.ptr,stride-1);sampler.changes++;}}
function policy(){
  if(sites.length===0)return;
  const nowT=qpcNow().toNumber();
  if(sampler.mode==='exact')return;
  if(sampler.mode==='fixed'){for(const st of sites)applyStride(st,st.exact?1:pow2ge(SP.stride));return;}
  if(sampler.lastT===null){sampler.lastT=nowT;sampler.lastHits=readSiteStats();return;}
  const dt=(nowT-sampler.lastT)/qpcFreq.toNumber();
  // the first moments decide whether a hot probe fills a ring before the policy has seen it: look sooner then
  if(dt<(nowT-sampler.t0<0.5*qpcFreq.toNumber()?0.005:SP.interval_ms/1000))return;
  const cur=readSiteStats(),c=readCounters(),dropped=c[1],dd=dropped-sampler.lastDrops;
  sampler.lastDrops=dropped;sampler.lastT=nowT;
  for(const st of sites){const r=(cur[st.id].hits-sampler.lastHits[st.id].hits)/dt;
    sampler.rate[st.id]=sampler.rate[st.id]===undefined?r:0.5*sampler.rate[st.id]+0.5*r;}
  sampler.lastHits=cur;
  if(dd>0)sampler.effective=Math.max(sampler.budget/16,sampler.effective/2);
  else sampler.effective=Math.min(sampler.budget,sampler.effective*1.25);
  // water-filling: probes that fit under the fair share stay exact, the rest share what is left
  let left=sampler.effective;const open=[];
  for(const st of sites){if(st.exact){left-=sampler.rate[st.id];}else open.push(st);}
  open.sort((a,b)=>sampler.rate[a.id]-sampler.rate[b.id]);
  left=Math.max(left,sampler.effective*0.1);
  for(let i=0;i<open.length;i++){const st=open[i],share=left/(open.length-i),r=sampler.rate[st.id];
    if(r<=share){left-=r;applyStride(st,1);}
    else{const stride=pow2ge(Math.ceil(r/share));applyStride(st,stride);left-=r/stride;}}
}
function samplingReport(){const cur=readSiteStats(),rows=[];let hits=0,skipped=0;
  for(const st of sites){const h=cur[st.id].hits,k=cur[st.id].kept;hits+=h;skipped+=h-k;
    rows.push({site:st.id,probe:st.name,hits:h,kept:k,skipped:h-k,stride:sampler.stride[st.id]||1,rate_per_s:Math.round(sampler.rate[st.id]||0),exact:!!st.exact});}
  return {policy:sampler.mode,rate_budget_per_s:sampler.budget,effective_budget_per_s:Math.round(sampler.effective),stride_changes:sampler.changes,
    hits,skipped,sites:rows};}
function counterMessage(final){const c=readCounters();
  send({event:'trace_counters',final:!!final,t:qpcNow().toString(),attempted:c[0],dropped:c[1],read_failed:c[2],no_ring:c[3],
    entered:c[4],left:c[5],busy:c[6],rings_used:c[7],stalls:c[8],stall_ticks:c[9],ring_reuses:c[10],qpc_freq:qpcFreq.toString(),
    window_waits:windowWaits,bp_us:P.bp_us,batches_sent:sentBatches,batches_next:batchSeq,rings:ringRows(),sampling:samplingReport()});}
// A drain that found data runs again at once; an idle one waits batch_ms.
function pump(){flushTimer=setTimeout(()=>{let n=0;try{n=flush();}catch(e){}try{policy();}catch(e){}pump2(n);},0);}
function pump2(n){if(released)return;flushTimer=setTimeout(()=>{let m=0;try{m=flush();}catch(e){}try{policy();}catch(e){}pump2(m);},n>0?0:P.batch_ms);}
pump();
const counterTimer=setInterval(()=>counterMessage(false),P.counter_ms);
// ---- inline hooks (no Interceptor trampoline) -----------------------------------------------------------------------
// A plain call site (no return value, no buffer, no stack walk) is hooked with a 5-byte jump to a small stub that saves
// the volatile registers (and xmm0-5, so a float argument survives the hit), calls `hit_inline` in the recorder with the
// site and the saved frame, restores, runs the instructions the jump replaced (relocated, RIP-relative operands fixed by
// the relocator) and jumps back. The Frida Interceptor's per-hit trampoline costs about 200 ns on the reference machine;
// this costs a few tens. Anything that is not simple falls back to the Interceptor: a branch, call or return among the
// replaced bytes, a prologue shorter than 5 bytes, no room for a stub within +-2 GB, or a refused page. The stubs live in
// pages that are never freed, and release() points them at a bare `ret` first, so a thread that is inside a stub when the
// recorder is torn down returns into the target's code, not into freed memory.
const kVirtualAlloc=new NativeFunction(x(k32,'VirtualAlloc'),'pointer',['pointer','size_t','uint','uint']);
const stubPages=[],inlineSites=[];
function reach(a,b){return a.compare(b)>0?a.sub(b):b.sub(a);}
function stubPage(site){
  for(const pg of stubPages)if(pg.used+320<=pg.size&&reach(pg.base,site).compare(ptr(0x60000000))<0)return pg;
  const want=16384;
  for(let k=1;k<=4096;k++){
    for(const sign of [-1,1]){
      const addr=sign<0?site.sub(k*0x10000):site.add(k*0x10000);
      if(addr.compare(ptr(0x10000))<0||addr.compare(ptr('0x7ffffff00000'))>0)continue;
      const p=kVirtualAlloc(addr.and(ptr('0xFFFFFFFFFFFF0000')),want,0x3000,0x40);
      if(p.isNull())continue;
      if(reach(p,site).compare(ptr(0x70000000))>0)return null;
      p.writeU8(0xC3);                                    // a bare `ret`, where a released stub's call is pointed
      p.add(16).writePointer(P.dbg_cellret?p:cm.hit_keep);p.add(24).writePointer(P.dbg_cellret?p:cm.hit_full);   // the call target cells
      const pg={base:p,used:64,size:want};stubPages.push(pg);return pg;
    }
  }
  return null;
}
const XMM=6,FRAME=40+16*XMM,STUB=768,RING_CTR=128;   // RING_CTR: offset of Ring.ctr; each counter is 32 bytes (hits, kept, next)
// The stub, in two halves. The gate (a dozen instructions, no call) counts the hit in the calling thread's ring through
// the TEB's TLS slot and tests it against the probe's sampling mask in the stub's own data word: a skipped hit costs
// those instructions and the relocated prologue, nothing else. A kept hit (or a thread with no ring yet) goes on to the
// full half, which saves the volatile registers, calls the recorder and restores. The flags are saved around both.
function inlineHook(site,sitePtr,id){
  try{
    if(tls<0)return {ok:false,why:'no TEB TLS slot below 64'};
    const pg=stubPage(site);if(pg===null)return {ok:false,why:'no room for a stub within 2 GB'};
    let n=0;const insns=[];
    while(n<5){const i=Instruction.parse(site.add(n));const m=i.mnemonic;
      if(/^(j|call|ret|loop|syscall|int|ud|hlt|xbegin|enter|leave)/.test(m))return {ok:false,why:'control flow in the first bytes: '+m};
      insns.push(i);n+=i.size;}
    if(n>15)return {ok:false,why:'prologue too long to relocate'};
    if(pg.used+STUB>pg.size)return {ok:false,why:'stub page full'};
    const orig=Array.from(new Uint8Array(site.readByteArray(n)));
    const block=pg.base.add(pg.used),stub=block.add(16);
    const w=new X86Writer(stub,{pc:stub});
    const tail=()=>{      // the relocated prologue and the way back
      const rel=new X86Relocator(site,w);let got=0;
      while(got<n){const k=rel.readOne();if(k===0)throw new Error('relocator could not read the prologue');got=k;}
      if(got!==n)throw new Error('relocator and decoder disagree about the prologue');
      rel.writeAll();w.putJmpAddress(site.add(n));};
    const full=(cellOffset)=>{
      w.putPushfx();
      for(const r of ['rax','rcx','rdx','r8','r9','r10','r11'])w.putPushReg(r);
      w.putSubRegImm('rsp',FRAME);
      for(let i=0;i<XMM;i++)w.putBytes([0x0F,0x11,0x44|(i<<3),0x24,32+16*i]);       // movups [rsp+32+16i], xmm_i
      w.putLeaRegRegOffset('rdx','rsp',FRAME);
      w.putMovRegAddress('rcx',sitePtr);
      w.putMovRegAddress('rax',pg.base.add(cellOffset));
      w.putCallRegOffsetPtr('rax',0);
      for(let i=0;i<XMM;i++)w.putBytes([0x0F,0x10,0x44|(i<<3),0x24,32+16*i]);       // movups xmm_i, [rsp+32+16i]
      w.putAddRegImm('rsp',FRAME);
      for(const r of ['r11','r10','r9','r8','rdx','rcx','rax'])w.putPopReg(r);
      w.putPopfx();
      tail();};
    const d32=(v)=>[v&255,(v>>>8)&255,(v>>>16)&255,(v>>>24)&255];
    const hits=RING_CTR+32*id,next=hits+16,tlsOff=0x1480+8*tls;
    // ---- the gate: no flags touched (jrcxz and lea leave them alone), so none are saved
    w.putPushReg('rax');w.putPushReg('rcx');w.putPushReg('rdx');
    w.putBytes([0x65,0x48,0x8B,0x0C,0x25,...d32(tlsOff)]);                // mov rcx, gs:[TlsSlots[tls]]  (this thread's ring)
    w.putJccShortLabel('jrcxz','isnull','no-hint');
    w.putJmpShortLabel('go');
    w.putLabel('isnull');w.putJmpNearLabel('null');
    w.putLabel('go');
    w.putBytes([0x48,0x8B,0x91,...d32(hits)]);                            // mov rdx, [rcx+hits]
    w.putBytes([0x48,0x8D,0x52,0x01]);                                    // lea rdx, [rdx+1]
    w.putBytes([0x48,0x89,0x91,...d32(hits)]);                            // mov [rcx+hits], rdx
    w.putBytes([0x48,0x8B,0x81,...d32(next)]);                            // mov rax, [rcx+next]
    w.putBytes([0x48,0x8D,0x50,0xFF]);                                    // lea rdx, [rax-1]
    w.putBytes([0x48,0x89,0x91,...d32(next)]);                            // mov [rcx+next], rdx
    w.putBytes([0x48,0x89,0xC1]);                                         // mov rcx, rax
    w.putJccShortLabel('jrcxz','keep','no-hint');
    // skipped: restore and run the prologue
    w.putPopReg('rdx');w.putPopReg('rcx');w.putPopReg('rax');
    tail();
    w.putLabel('keep');
    w.putPopReg('rdx');w.putPopReg('rcx');w.putPopReg('rax');
    full(16);
    w.putLabel('null');
    w.putPopReg('rdx');w.putPopReg('rcx');w.putPopReg('rax');
    full(24);
    w.flush();
    const used=(w.offset+15)&~15;
    const delta=stub.compare(site)>0?stub.sub(site).toInt32():-(site.sub(stub).toInt32());
    const rel32=delta-5;
    Memory.patchCode(site,n,code=>{
      code.writeU8(0xE9);code.add(1).writeS32(rel32);
      for(let i=5;i<n;i++)code.add(i).writeU8(0x90);});
    pg.used+=Math.max(used,STUB);
    inlineSites.push({site,n,orig,jmp:Array.from(new Uint8Array(site.readByteArray(5))),page:pg});
    return {ok:true};
  }catch(e){return {ok:false,why:String(e).slice(0,160)};}
}
function inlineRestore(){
  let bad=0;
  for(const h of inlineSites){
    const now=Array.from(new Uint8Array(h.site.readByteArray(5)));
    if(now.some((b,i)=>b!==h.jmp[i])){bad++;continue;}      // someone else rewrote the site: leave it, report it
    Memory.patchCode(h.site,h.n,code=>{for(let i=0;i<h.n;i++)code.add(i).writeU8(h.orig[i]);});
  }
  return bad;
}
function inlineRetire(){for(const pg of stubPages){pg.base.add(16).writePointer(pg.base);pg.base.add(24).writePointer(pg.base);}}   // calls land on `ret`
// ---- attach (everything is verified above) -----------------------------------------------------------------------------
const listeners=[],installed=[];
for(const v of verified){const pr=v.probe,t0=Date.now(),b=pr.buf;
  const flags=(pr.with_leave?1:0)|(b&&b.wide?2:0)|(b&&b.cstr?4:0);
  const s=siteMem.add(siteSize*installed.length);
  f.site_init(s,shared,pr.id,pr.nargs,flags,b?b.ptr_arg:-1,b&&b.len_arg!==null&&b.len_arg!==undefined?b.len_arg:-1,b&&b.fixed?b.fixed:0,b?b.max:0,pr.stack||1);
  sites.push({id:pr.id,name:pr.name,ptr:s,exact:strideFor(pr.id,pr.name)===1});
  let how='interceptor',why=null;
  if(P.hooking!=='interceptor'&&!pr.with_leave&&!b&&(pr.stack||1)<=1){
    const r=inlineHook(v.site,s,pr.id);if(r.ok)how='inline';else why=r.why;}
  else if(P.hooking!=='interceptor')why=pr.with_leave?'return value needed':(b?'buffer read needed':'stack walk needed');
  if(how==='interceptor')listeners.push(Interceptor.attach(v.site,pr.with_leave?{onEnter:cm.on_enter,onLeave:cm.on_leave}:{onEnter:cm.on_enter},s));
  installed.push({id:pr.id,name:pr.name,address:v.site.toString(),install_ms:Date.now()-t0,hook:how,inline_refused:why});}
// Modules loaded and unloaded while recording: a reload at another base is a new instance (TRACE-1 section 7). The
// observer reports the modules already mapped first; those are recorded by the worker at start, so they are skipped.
let moduleObserver=null,observing=false;
try{moduleObserver=Process.attachModuleObserver({
  onAdded(m){if(observing)send({event:'trace_module',op:'load',name:m.name,path:m.path,base:m.base.toString(),size:m.size,t:qpcNow().toString()});},
  onRemoved(m){if(observing)send({event:'trace_module',op:'unload',name:m.name,path:m.path,base:m.base.toString(),size:m.size,t:qpcNow().toString()});}});}catch(e){moduleObserver=null;}
observing=true;
sampler.t0=qpcNow().toNumber();
f.set_mode(shared,1);
send({event:'trace_ready',context,qpc_freq:qpcFreq.toString(),producer_gen:P.producer_gen,pid:Process.id,arch:Process.arch,
  rings:P.rings,ring_bytes:P.ring_bytes,batch_ms:P.batch_ms,bp_us:P.bp_us,window:P.window,installed,qpc:qpcNow().toString(),fls_index:fls,
  sampling:{policy:SP.mode,rate_budget_per_s:SP.rate_budget,stride:SP.stride,exact:SP.exact,interval_ms:SP.interval_ms},tls_index:tls});
rpc.exports={
  status(){return {installed:true,mode:released?'released':'recording'};},
  counters(){return {counters:readCounters(),rings:ringRows(),batches_sent:sentBatches,sampling:samplingReport()};},
  flush(){return flush();},
  // Pass-through, detach, prove the callbacks quiescent. A failed proof keeps the recorder in place, in pass-through,
  // and says so; the worker must not unload the script then (unloading frees the callbacks).
  release(timeoutMs){
    f.set_mode(shared,0);
    Thread.sleep(0.05);
    acked=batchSeq;           // the writer is being closed: drain what is left without waiting for acknowledgements
    for(let i=0;i<64;i++){if(flush()===0)break;acked=batchSeq;}
    const inlineBad=inlineRestore();
    for(const l of listeners)l.detach();
    observing=false;if(moduleObserver!==null){try{moduleObserver.detach();}catch(e){}moduleObserver=null;}
    Interceptor.flush();
    const t0=Date.now();let stable=0,ok=false;
    while(Date.now()-t0<timeoutMs){
      const c=readCounters();
      if(c[6]===0&&c[4]===c[5]){stable++;if(stable>=3){ok=true;break;}}else stable=0;
      Thread.sleep(0.025);}
    const c=readCounters();
    inlineRetire();
    Thread.sleep(0.05);
    const result={quiescent:ok&&inlineBad===0,waited_ms:Date.now()-t0,busy:c[6],entered:c[4],left:c[5],inline_sites:inlineSites.length,inline_not_restored:inlineBad};
    if(ok&&inlineBad===0){released=true;if(flushTimer!==null)clearTimeout(flushTimer);clearInterval(counterTimer);
      acked=batchSeq;for(let i=0;i<64;i++){if(flush()===0)break;acked=batchSeq;}
      counterMessage(true);
      if(tls>=0)tlsFree(tls);
      flsFree(fls);          // runs the exit callback for every thread still holding a ring, while the code is still loaded
      result.note='detached and quiescent; the script may be unloaded';}
    else{flush();result.note='callbacks still in flight; recorder retained in pass-through';}
    return result;}
};
"""


SAMPLING_MODES = ("adaptive", "exact", "fixed")
DEFAULT_RATE_BUDGET = 120_000       # kept records per second, all probes together, before the adaptive policy thins


def normalize_sampling(value) -> dict:
    """The declared sampling policy of a trace session. `None` is the default: adaptive, exact below the rate budget.

    `{"mode": "adaptive"|"exact"|"fixed", "rate_budget": records/s, "stride": N (fixed), "exact": [probe names]}`."""
    if value is None:
        value = {}
    if isinstance(value, str):
        value = {"mode": value}
    if not isinstance(value, dict) or set(value) - {"mode", "rate_budget", "stride", "exact", "interval_ms"}:
        raise ValueError("sampling is {mode: adaptive|exact|fixed, rate_budget, stride, exact: [probe names]}")
    mode = str(value.get("mode", "adaptive"))
    if mode not in SAMPLING_MODES:
        raise ValueError("sampling mode is one of %s" % ", ".join(SAMPLING_MODES))
    budget = value.get("rate_budget", DEFAULT_RATE_BUDGET)
    stride = value.get("stride", 1)
    interval = value.get("interval_ms", 25)
    for name, item, low, high in (("rate_budget", budget, 1000, 50_000_000), ("stride", stride, 1, 65536), ("interval_ms", interval, 5, 5000)):
        if isinstance(item, bool) or not isinstance(item, (int, float)) or not low <= item <= high:
            raise ValueError("sampling %s is %d..%d" % (name, low, high))
    exact = value.get("exact") or []
    if not isinstance(exact, list) or not all(isinstance(x, str) for x in exact):
        raise ValueError("sampling exact is a list of probe names")
    return {"mode": mode, "rate_budget": int(budget), "stride": int(stride), "exact": list(exact), "interval_ms": int(interval)}


def trace_agent_source(parameters: dict) -> str:
    """The trace agent script for one session. `parameters` is rendered as JSON; the C source travels with it."""
    return TRACE_AGENT.replace("PARAMETERS", json.dumps({**parameters, "c_source": TRACE_C}), 1)
