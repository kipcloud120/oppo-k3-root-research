#!/usr/bin/env python3
# D 阶段补充：在 iommu 簇邻域做内容锚定（最后一次收敛尝试）
#  a) 源码中 arm_lpae_alloc_pgtable 的 printk 字符串是否在本镜像存在
#  b) 0x500000..0x700000 内 adrp+add 得到 >=6 个函数地址的窗口（vtable 赋值点）
#  c) 同范围内 bl 之后未检查 w0 即 add wN,wN,#1 的位置（ms.num_pte++ 特征）
import re
import struct

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

P = "firmware_F16/kernel.decompressed"
K = "firmware_F16/kallsyms_out.txt"
D = open(P, "rb").read()
N = len(D)
W = np.frombuffer(D[:N // 4 * 4], dtype="<u4").astype(np.uint32)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = False
p1 = (W & np.uint32(0xffc07fff)) == np.uint32(0xa9807bfd)
p2 = (W & np.uint32(0xffc003ff)) == np.uint32(0xd10003ff)
PRO = set((np.nonzero(p1 | p2)[0] * 4).tolist())
SY = []
for line in open(K, encoding="latin1"):
    line = line.rstrip("\n")
    if len(line) >= 13:
        SY.append((int(line[:10], 16), line[11], line[12:]))
BYVAL = {}
for v, t, nm in SY:
    BYVAL.setdefault(v, []).append((t, nm))


def nm(v):
    return "/".join(x[1] for x in BYVAL.get(v, [])[:1]) or "?"


LO, HI = 0x500000, 0x700000

print("=== a) 源码 printk 字符串在本镜像的存在性 ===")
for s in (b"Cannot accommodate DMA offset for IOMMU page tables",
          b"Cannot accommodate DMA offset",
          b"io-pgtable-arm", b"IOMMU page tables",
          b"arm_lpae", b"pgtable_dma_sync"):
    pos = [m.start() for m in re.finditer(re.escape(s), D)]
    print(f"    {s[:48]!r:52s}: {len(pos)} 处 " +
          " ".join(hex(p) for p in pos[:6]))

print("\n=== b) 邻域内 vtable 赋值点（>=6 个函数地址） ===")
isadrp = (W & np.uint32(0x9f000000)) == np.uint32(0x90000000)
ap = (np.nonzero(isadrp)[0] * 4).astype(np.int64)
ap = ap[(ap >= LO) & (ap < HI)]
print(f"    邻域 adrp 站点 {len(ap)}")
seen, out = set(), []
for x in ap:
    start = int(x)
    if start in seen:
        continue
    seen.add(start)
    regs, vals = {}, []
    for ins in MD.disasm(D[start:start + 0x180], start):
        q = [z.strip() for z in ins.op_str.replace("#", "").strip().split(",")]
        m = ins.mnemonic
        if m == "adrp" and len(q) == 2:
            try:
                regs[q[0]] = int(q[1], 16)
            except ValueError:
                pass
        elif m == "add" and len(q) == 3 and q[1] in regs and q[2].startswith("0x"):
            try:
                v = regs[q[1]] + int(q[2], 16)
                regs[q[0]] = v
                if v in PRO and v not in vals:
                    vals.append(v)
            except ValueError:
                pass
    if len(vals) >= 6:
        out.append((start, sorted(vals)))
# 去重：相邻起点只保留第一个
uniq = []
for s, v in out:
    if not uniq or s - uniq[-1][0] > 0x80:
        uniq.append((s, v))
print(f"    命中窗口 {len(uniq)} 个（去重后），前 15：")
for s, v in uniq[:15]:
    print(f"    0x{s:x}: " + " ".join(hex(y) for y in v[:8]))

print("\n=== c) 邻域内 bl 后未检查 w0 且自增 wN 的位置 ===")
isbl = (W & np.uint32(0xfc000000)) == np.uint32(0x94000000)
blp = (np.nonzero(isbl)[0] * 4)
blp = blp[(blp >= LO) & (blp < HI)]
hits = []
for p in blp:
    p = int(p)
    ins = list(MD.disasm(D[p:p + 32], p))
    if len(ins) < 3:
        continue
    txt = " ".join(f"{x.mnemonic} {x.op_str}" for x in ins[1:])
    if any(t in txt for t in ("cbz w0", "cbnz w0", "tbz w0", "tbnz w0",
                              "cmp w0", "cmn w0")):
        continue
    if re.search(r"add\s+w\d+,\s*w\d+,\s*#1\b", txt) and "str w" in txt:
        m = re.search(r"0x[0-9a-f]+", ins[0].op_str)
        tgt = int(m.group(), 16) if m else 0
        hits.append((p, tgt, txt[:130]))
print(f"    命中 {len(hits)} 处：")
for p, tgt, txt in hits[:30]:
    print(f"    0x{p:x} bl->0x{tgt:x}={nm(tgt)} | {txt}")

print("\n=== d) 对命中处反汇编上下文（前 3 个） ===")
for p, tgt, txt in hits[:3]:
    print(f"  --- 0x{p-0x30:x} ---")
    for ins in MD.disasm(D[p - 0x30:p + 0x40], p - 0x30):
        print(f"    0x{ins.address:x}: {ins.mnemonic:8s} {ins.op_str}")
