#!/usr/bin/env python3
# Recover compressed kallsyms from raw ARM64 kernel Image (K3 C.17, Linux 4.9.186).
#
# Key facts about the layout (Linux 4.9, CONFIG_KALLSYMS_BASE_RELATIVE=y):
#   [kallsyms_offsets  u32[num]] [kallsyms_num_syms u32/u64] [kallsyms_names]
#   [kallsyms_markers  u32[m]]   [kallsyms_token_table]      [kallsyms_token_index u16[256]]
# Notes:
#   * offsets[] is *almost* ascending; a handful of percpu symbols wrap -> allow <=40 drops.
#   * decoding a name consumes 1 + (name_len) bytes ; the END position depends only on the
#     length prefixes, NOT on the token strings. So we can locate (offsets,num,names_start,markersz)
#     by walking length prefixes and requiring the walk to end exactly at markers_start.
#   * token table only affects readability of the final rendered names.
import struct, sys
import numpy as np

PATH="unpacked_C17/kernel.decompressed"
def u16(o): return struct.unpack_from("<H",data,o)[0]
def u32(o): return struct.unpack_from("<I",data,o)[0]
def u64(o): return struct.unpack_from("<Q",data,o)[0]
IDENT=set(range(0x30,0x39+1))|set(range(0x41,0x5a+1))|set(range(0x61,0x7a+1))|{0x5f,0x2e,0x24}

data=open(PATH,"rb").read(); n=len(data)
print(f"[*] file size = {n:#x}",flush=True)

# ---------- 1) offsets array (long, almost ascending) ----------
a32=np.frombuffer(data[:n//4*4],dtype='<u4').astype(np.int64)
cand_idx=np.nonzero((a32>=50000)&(a32<=400000))[0]
ocands=[]
for j in cand_idx:
    e=int(j); num=int(a32[e]); Oidx=e-num
    if Oidx<2: continue
    # cheap prefilter: first offset small (relative_base just below first symbol)
    if not(0<a32[Oidx]<0x100000): continue
    arr=a32[Oidx:e]
    if int(arr.max())-int(arr.min())<0x400000: continue   # image-sized span
    viol=int(np.count_nonzero(np.diff(arr)<0))
    if viol>60: continue
    ocands.append((Oidx*4,num,viol))
ocands.sort(key=lambda x:(x[2],-x[1]))
print(f"[*] offset-array candidates: {len(ocands)}",flush=True)
for O_,nm_,v_ in ocands[:8]:
    print(f"    O={O_:#x} num={nm_} viol={v_} off0={u32(O_):#x} offN={u32(O_+4*(nm_-1)):#x}",flush=True)
if not ocands:
    print("[!] offsets not found"); sys.exit(1)

# ---------- 2) token tables (dedup by T) ----------
a16=np.frombuffer(data[:n//2*2],dtype='<u2').astype(np.int32); N16=len(a16)
d=(np.diff(a16)>=0); cs=np.concatenate(([0],np.cumsum(d,dtype=np.int64)))
st=np.arange(0,N16-255); ok=(cs[st+255]-cs[st])==255
wins=st[ok]; cw=wins[(a16[wins]==0)&(a16[wins+255]>0)]

def find_T(p,ti):
    maxoff=max(ti); start=min(p-1,p-maxoff-1); lo=max(0,p-15000)
    for T in range(start,lo,-1):
        if T<1 or data[T-1]!=0: continue
        if not(T+ti[1]<p and T+ti[2]<p and T+ti[128]<p and T+ti[255]<p): continue
        if not(data[T+ti[1]-1]==0 and data[T+ti[2]-1]==0 and data[T+ti[128]-1]==0 and data[T+ti[255]-1]==0): continue
        g=True
        for i in range(1,256):
            if T+ti[i]>=p or data[T+ti[i]-1]!=0: g=False; break
        if g: return T
    return None

def build_tok(T,p,ti):
    t=[]
    for i in range(256):
        s=T+ti[i]; e=p if i==255 else T+ti[i+1]-1
        t.append(data[s:e].rstrip(b'\x00'))
    return t

byT={}
for i in cw:
    p=int(i)*2
    if p+512>n: continue
    ti=[u16(p+2*k) for k in range(256)]
    T=find_T(p,ti)
    if T is None: continue
    toks=build_tok(T,p,ti)
    ne=sum(1 for x in toks if x)
    if ne<200: continue
    dist=len(set(toks))
    if dist<200: continue
    good=sum(1 for x in toks if x and all(c in IDENT for c in x))
    if good<ne*0.95: continue
    byT.setdefault(T,[]).append((p,toks,dist,good))
print(f"[*] distinct token_table positions: {len(byT)}",flush=True)
for T in list(byT)[:6]:
    best=sorted(byT[T],key=lambda x:(-x[2],-x[3]))[0]
    print(f"    T={T:#x} variants={len(byT[T])} best_p={best[0]:#x} distinct={best[2]}",flush=True)

# ---------- 3) locate names block via length-prefix walk ----------
def walk_end(ns,num):
    pos=ns
    for _ in range(num):
        if pos>=n: return -1
        ln=data[pos]
        if ln==0 or ln>80: return -1
        pos+=1+ln
    return pos

found=None
for O,num,viol in ocands:
    m=(num+255)//256
    for T in byT:
        for msz in (4,8):
            ne=T-msz*m
            for off in (4,8,12,16,20,24):
                ns=O+4*num+off
                L=ne-ns
                if not(3*num<L<45*num): continue
                if walk_end(ns,num)==ne:
                    found=(O,num,T,msz,ns,off); break
            if found: break
        if found: break
    if found: break
if not found:
    print("[!] names block not located"); sys.exit(1)
O,num,T,msz,ns,off=found
print(f"\n[+] LOCATED offsets@{O:#x} num={num} token_table@{T:#x} markersz={msz} names@{ns:#x}(+{off})",flush=True)

# ---------- 4) pick best token table for this T and render ----------
variants=sorted(byT[T],key=lambda x:(-x[2],-x[3]))[:8]
best=None
for p,toks,dist,good in variants:
    # decode full, score readability
    pos=ns; names=[]; okd=True
    for _ in range(num):
        ln=data[pos]; pos+=1
        b=bytearray()
        for _ in range(ln):
            b+=toks[data[pos]]; pos+=1
        names.append(b.decode('latin1','replace'))
    ident=sum(1 for s in names if s and all(c.isalnum() or c in "_.$" for c in s))
    score=ident
    if best is None or score>best[0]:
        best=(score,p,toks,names,ident)
score,p,toks,syms,ident=best
print(f"[+] token_idx@{p:#x} distinct={len(set(toks))} identifier_like={100*ident/num:.1f}%",flush=True)

rel=[u32(O+4*i) for i in range(num)]
out=list(zip(rel,syms))
open("tools/kallsyms_out.txt","w",encoding="latin1").write("".join(f"{v:#010x} {nm}\n" for v,nm in out))
print(f"[+] wrote tools/kallsyms_out.txt ({num} symbols)",flush=True)

print("\n=== sample (first 15) ===",flush=True)
for v,nm in out[:15]: print(f"  {v:#010x} {nm}")
print("\n=== anchors ===",flush=True)
for a in ["_text","stext","_etext","start_kernel","do_futex","futex_wait","__arm64_sys_futex","SyS_futex","__do_sys_futex","futex_lock_pi","futex_unlock_pi"]:
    r=[(v,nm) for v,nm in out if nm==a]
    if r: print(f"  {r[0][0]:#010x}  {r[0][1]}")
print("\n=== futex / rt_mutex / rtmutex / proxy / requeue ===",flush=True)
keys=("futex","rt_mutex","rtmutex","proxy","requeue","pi_state")
cnt=0
for v,nm in out:
    if any(k in nm for k in keys):
        print(f"  {v:#010x}  {nm}",flush=True); cnt+=1
print(f"[*] matched {cnt}",flush=True)
