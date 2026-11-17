#!/usr/bin/env python3
# F.16 (Linux 4.9.227) compressed kallsyms recovery — working pipeline.
# Usage: python3 tools/f16_kallsyms.py [kernel.decompressed]
# Output: <dir>/kallsyms_out.txt  (relative offset + symbol name)
import struct, sys, os
import numpy as np

PATH = sys.argv[1] if len(sys.argv) > 1 else "firmware_F16/kernel.decompressed"
data = open(PATH, "rb").read(); n = len(data)
def u16(o): return struct.unpack_from("<H", data, o)[0]
def u32(o): return struct.unpack_from("<I", data, o)[0]
IDENT = set(range(0x30,0x39+1))|set(range(0x41,0x5a+1))|set(range(0x61,0x7a+1))|{0x5f,0x2e,0x24}
print(f"[*] {PATH} size={n:#x}", flush=True)

# ---- 1) kallsyms_offsets: u32 array, length==num_syms, almost ascending, offset[0] small, image-size span
a32 = np.frombuffer(data[:n//4*4], dtype='<u4').astype(np.int64)
oc = []
for j in np.nonzero((a32 >= 20000) & (a32 <= 2_000_000))[0]:
    e = int(j); num = int(a32[e]); Oi = e - num
    if Oi < 0 or not (0 < a32[Oi] < 0x200000): continue
    arr = a32[Oi:e]
    if len(arr) != num: continue
    if int(arr.max()) - int(arr.min()) < 0x400000: continue
    viol = int(np.count_nonzero(np.diff(arr) < 0))
    if viol > 80: continue
    oc.append((viol, num, Oi*4))
oc.sort(key=lambda x: (x[0], -x[1]))
if not oc: sys.exit("[!] offsets not found")
viol, num, O = oc[0]
print(f"[+] offsets@{O:#x} num_syms={num} viol={viol}", flush=True)

# ---- 2) token table: 256-u16 non-decreasing window + null-boundary pin
a16 = np.frombuffer(data[:n//2*2], dtype='<u2').astype(np.int32); N16 = len(a16)
d = (np.diff(a16) >= 0); cs = np.concatenate(([0], np.cumsum(d, dtype=np.int64)))
st = np.arange(0, N16-255); ok = (cs[st+255]-cs[st]) == 255
wins = st[ok]; cw = wins[(a16[wins] == 0) & (a16[wins+255] > 0)]
def find_T(p, ti):
    mo = max(ti); start = min(p-1, p-mo-1); lo = max(0, p-15000)
    for T in range(start, lo, -1):
        if T < 1 or data[T-1] != 0: continue
        if not (T+ti[1] < p and T+ti[2] < p and T+ti[128] < p and T+ti[255] < p): continue
        if not (data[T+ti[1]-1]==0 and data[T+ti[2]-1]==0 and data[T+ti[128]-1]==0 and data[T+ti[255]-1]==0): continue
        if all(T+ti[i] < p and data[T+ti[i]-1] == 0 for i in range(1, 256)): return T
    return None
Ts = []
for i in cw:
    p = int(i)*2
    if p+512 > n: continue
    ti = [u16(p+2*k) for k in range(256)]
    T = find_T(p, ti)
    if T is None: continue
    toks = [data[T+ti[k]:(p if k==255 else T+ti[k+1]-1)].rstrip(b'\x00') for k in range(256)]
    if sum(1 for t in toks if t) < 200 or len(set(toks)) < 200: continue
    if sum(1 for t in toks if t and all(c in IDENT for c in t)) < 0.95*sum(1 for t in toks if t): continue
    Ts.append(T)
Ts = sorted(set(Ts))
print(f"[+] token_table candidates: {[hex(t) for t in Ts]}", flush=True)
if not Ts: sys.exit("[!] no token table")

# ---- 3) names_start: walk length-prefixes; accept near-match to T - markersz*ceil(num/256)
m = (num+255)//256
def walk(s, k):
    pos = s
    for _ in range(k):
        if pos >= n: return None
        ln = data[pos]
        if ln == 0 or ln > 80: return None
        pos += 1+ln
    return pos
q = O + 4*num
chosen = None
for T in Ts:
    starts = []
    for s in range(q, min(n-1, q+0x60000)):
        if data[s] != 0 and (s == q or data[s-1] == 0):
            starts.append(s)
            if len(starts) >= 80: break
    for s in starts:
        end = walk(s, num)
        if end is None: continue
        for msz in (8, 4):
            if abs(end - (T - msz*m)) < 2048:
                chosen = (s, T, msz); break
        if chosen: break
    if chosen: break
if not chosen: sys.exit("[!] names block not located")
ns, T, msz = chosen
print(f"[+] names@{ns:#x} token_table@{T:#x} markersz={msz}", flush=True)

# ---- 4) derive token_index from token lengths (robust; avoids the 'all-ff' degenerate)
toks = []; cur = T
for _ in range(256):
    e = data.find(b'\x00', cur)
    toks.append(data[cur:e]); cur = e+1
# ---- 5) decode
pos = ns; syms = []
for _ in range(num):
    ln = data[pos]; pos += 1
    b = bytearray()
    for _ in range(ln): b += toks[data[pos]]; pos += 1
    syms.append(b.decode('latin1', 'replace'))
ident = sum(1 for s in syms if s and all(c.isalnum() or c in "_.$" for c in s))
print(f"[+] decoded {len(syms)}  end={pos:#x}  identifier-like={100*ident/num:.1f}%", flush=True)
print(f"[+] sample: {syms[:6]}", flush=True)

out = os.path.join(os.path.dirname(PATH), "kallsyms_out.txt")
with open(out, "w", encoding="latin1") as f:
    for i, nm in enumerate(syms):
        f.write(f"{u32(O+4*i):#010x} {nm}\n")
print(f"[+] wrote {out}", flush=True)
