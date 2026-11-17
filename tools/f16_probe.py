#!/usr/bin/env python3
# F.16 定点探针：入口跳转、kgsl align 符号、io_pgtable vtable、iommu 簇函数清单
import bisect
import re
import struct
import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

P = "firmware_F16/kernel.decompressed"
K = "firmware_F16/kallsyms_out.txt"
D = open(P, "rb").read()
N = len(D)
u32 = lambda o: struct.unpack_from("<I", D, o)[0]
u64 = lambda o: struct.unpack_from("<Q", D, o)[0]
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); MD.detail = False
W = np.frombuffer(D[:N // 4 * 4], dtype="<u4").astype(np.uint32)
p1 = (W & np.uint32(0xffc07fff)) == np.uint32(0xa9807bfd)
p2 = (W & np.uint32(0xffc003ff)) == np.uint32(0xd10003ff)
PRO = set((np.nonzero(p1 | p2)[0] * 4).tolist())
SY = []
for line in open(K, encoding="latin1"):
    line = line.rstrip("\n")
    if len(line) >= 13:
        SY.append((int(line[:10], 16), line[11], line[12:]))
KV = {nm: v for v, t, nm in SY}
BYVAL = {}
for v, t, nm in SY:
    BYVAL.setdefault(v, []).append((t, nm))
VALS = sorted(BYVAL)


def nm(v):
    return "/".join(x[1] for x in BYVAL.get(v, [])[:2]) or "?"


def dis(o, n=6):
    return " | ".join(f"{i.mnemonic} {i.op_str}".strip()
                      for i in MD.disasm(D[o:o + 4*n], o))


def cstr(o, maxlen=90):
    if not (0 <= o < N):
        return None
    e = D.find(b"\x00", o, min(N, o + maxlen))
    if e < 0 or e == o:
        return None
    s = D[o:e]
    return s.decode("ascii") if all(32 <= c < 127 for c in s) else None


def strs_in(start, end):
    """ADRP/ADD 字符串引用"""
    regs, out = {}, []
    for x in MD.disasm(D[start:end], start):
        op = x.op_str.replace("#", "").strip()
        if x.mnemonic == "adrp":
            p = [q.strip() for q in op.split(",")]
            if len(p) == 2:
                try: regs[p[0]] = int(p[1], 16)
                except ValueError: pass
        elif x.mnemonic == "add" and "," in op:
            p = [q.strip() for q in op.split(",")]
            if len(p) >= 3 and p[1] in regs and p[2].startswith("0x"):
                try:
                    a = regs[p[1]] + int(p[2], 16)
                    s = cstr(a)
                    if s and len(s) >= 6: out.append(s)
                except ValueError: pass
    return out[:5]


print("=== A. 入口跳转目标 & stext 符号 ===")
for o in (0x40, 0x100, 0x1980000, 0x5bb8):
    print(f"  0x{o:08x}: {dis(o, 4)}   [{nm(o)}]")
for key in ("_stext", "_text", "_head", "stext", "__entry_text_start",
            "vectors", "__sched_text_start", "tramp_vectors"):
    print(f"    kallsyms {key} = {hex(KV.get(key, 0))}")

print("\n=== B. kgsl 符号中含 align / memdesc 的全部 ===")
for pat in ("align", "memdesc_get", "get_align"):
    s = sorted((v, n) for v, t, n in SY if "kgsl" in n and pat in n)
    print(f"  含 '{pat}': {len(s)} 个")
    for v, n in s[:25]:
        print(f"    {n} @0x{v:x}")

print("\n=== C. io_pgtable 静态 vtable（4 个连续绝对 vaddr 函数指针） ===")
BASE = 0xffffff8008080000
U = np.frombuffer(D[:N // 8 * 8], dtype="<u8")
ok = np.zeros(len(U), dtype=bool)
lo, hi = BASE + 0x1000, BASE + 0x1200000
cand = np.nonzero((U >= lo) & (U < hi))[0]
hits = []
for i in cand:
    j = int(i)
    if j + 3 >= len(U):
        break
    vs = [(int(U[j+k]) - BASE) for k in range(4)]
    if not all(0x1000 < x < 0x1200000 for x in vs):
        continue
    if not all(x in PRO for x in vs):
        continue
    if max(vs) - min(vs) > 0x4000:
        continue
    hits.append((j*8, vs))
print(f"  候选 {len(hits)} 组（前 25）：")
for o, vs in hits[:25]:
    print(f"    文件0x{o:x}: " + ", ".join(f"0x{x:x}={nm(x)}" for x in vs))

print("\n=== D. 0x5b0000..0x5c2000 的函数序言 + 字符串引用（找 iommu 簇） ===")
rows = []
for o in sorted(x for x in PRO if 0x5b0000 <= x < 0x5c2000):
    i = bisect.bisect_right(VALS, o)
    end = VALS[i] if i < len(VALS) else o + 0x100
    end = min(end, o + 0x600)
    ss = strs_in(o, end)
    rows.append((o, nm(o), ss))
print(f"  共 {len(rows)} 个函数起点；含字符串引用的：")
for o, name, ss in rows:
    if ss:
        print(f"    0x{o:x} [{name}]  {ss}")
print("  前 40 个函数起点（无字符串）：")
print("    " + ", ".join(f"0x{o:x}={n}" for o, n, s in rows[:40] if not s))

print("\n=== E. io_pgtable_arm_*_init_fns 数据符号附近 ===")
for v, n in sorted((v, n) for v, t, n in SY if "init_fns" in n)[:8]:
    print(f"    {n} @0x{v:x}  值: " + " ".join(hex(u64(v + 8*k)) for k in range(4)))
