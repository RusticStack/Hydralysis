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
