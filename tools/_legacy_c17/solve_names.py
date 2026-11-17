#!/usr/bin/env python3
import struct
data=open("unpacked_C17/kernel.decompressed","rb").read(); n=len(data)
def u16(o): return struct.unpack_from("<H",data,o)[0]
def u32(o): return struct.unpack_from("<I",data,o)[0]
def u64(o): return struct.unpack_from("<Q",data,o)[0]

O=0x1380744; num=135791; T=0x15ac800; p_tok=0x15acc00
print(f"num={num} token_table@{T:#x} token_idx@{p_tok:#x}")

# --- find markers_start: u64 non-decreasing ending near T, markers[0]==0 ---
# walk backward from just before T (skip zero padding)
q=T-8
while q>0 and u64(q)==0: q-=8
end_markers=q+8  # first zero after last nonzero marker
print(f"last nonzero marker @ {q:#x} = {u64(q):#x} ; markers_end~{end_markers:#x}")
ms=None
prev=u64(q)
pos=q
vals=[]
while pos>=8:
    v=u64(pos-8)
    if pos-8<0: break
    if v<=prev and v < 0x400000:   # forward non-decreasing => backward v<=next
        vals.append((pos-8,v)); prev=v; pos-=8
        if v==0:
            ms=pos; break
    else:
        break
print(f"markers_start(ms)={ms if ms is None else hex(ms)}  count~{(end_markers-ms)//8 if ms else '?'}")
if ms is None:
    print("[!] markers not found"); raise SystemExit

names_end=ms
print(f"names_end={names_end:#x}  expected names_len~{names_end-0x1405104:#x}")

# --- scan names_start: length-prefixed walk of num entries must end at names_end ---
def try_start(s):
    pos=s
    for _ in range(num):
        ln=data[pos]
        if ln==0 or ln>64: return None
        pos+=1+ln
        if pos>names_end: return None
    return pos if pos==names_end else None

found=0x1405200
print(f"[direct] names_start={found:#x}")
if found is None:
    print("[!] names_start not found"); raise SystemExit
names_start=found
print(f"[+] names_start={names_start:#x}")

# --- build tokens from token_idx p_tok ---
region=data[T:p_tok]
ti=[u16(p_tok+2*k) for k in range(256)]
toks=[]
for i in range(256):
    off=ti[i]; e=region.find(b'\x00',off)
    if e==-1: e=len(region)
    toks.append(region[off:e].rstrip(b'\x00'))
print("nonempty tokens:",sum(1 for t in toks if t)," distinct:",len(set(toks)))
print("token sample:", [t.decode('latin1') for t in toks[:30]])

# --- decode all names ---
syms=[]; pos=names_start
for _ in range(num):
    ln=data[pos]; pos+=1
    b=bytearray()
    for _ in range(ln):
        b+=toks[data[pos]]; pos+=1
    syms.append(b.decode('latin1','replace'))
print(f"[+] decoded {len(syms)} names, end={pos:#x} (expected {names_end:#x})")
ident=sum(1 for s in syms if s and all(c.isalnum() or c in "_.$" for c in s))
print(f"    identifier-like {100*ident/len(syms):.1f}%")
rel=[u32(O+4*i) for i in range(num)]
out=list(zip(rel,syms))
open("tools/kallsyms_out.txt","w",encoding="latin1").write("".join(f"{v:#010x} {nm}\n" for v,nm in out))
print("[+] wrote tools/kallsyms_out.txt")

print("\n=== sample first 20 ===")
for v,nm in out[:20]: print(f"  {v:#010x} {nm}")
print("\n=== anchors ===")
for a in ["_text","stext","_etext","start_kernel","do_futex","futex_wait","SyS_futex","__arm64_sys_futex","futex_lock_pi","futex_unlock_pi","rt_mutex_lock","rt_mutex_unlock"]:
    r=[(v,nm) for v,nm in out if nm==a]
    if r: print(f"  {r[0][0]:#010x}  {r[0][1]}")
print("\n=== futex / rt_mutex / rtmutex / proxy / requeue ===")
cnt=0
for v,nm in out:
    if any(k in nm for k in ("futex","rt_mutex","rtmutex","proxy","requeue","pi_state")):
        print(f"  {v:#010x}  {nm}"); cnt+=1
print(f"[*] matched {cnt}")
