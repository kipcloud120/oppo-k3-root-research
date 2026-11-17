#!/usr/bin/env python3
# D 阶段终局：printk 字符串 -> arm_lpae_alloc_pgtable -> ops vtable -> arm_lpae_map_sg
#
# 依据 realmeX 官方源码 L975/L994-1001：dev_err("Cannot accommodate DMA offset
# for IOMMU page tables") 与 data->iop.ops = {map, map_sg, unmap, iova_to_phys,
# is_iova_coherent, iova_to_pte} 位于同一函数 arm_lpae_alloc_pgtable()。
# 该字符串在本镜像 0x161c400 逐字存在，可作内容锚点（不依赖符号表）。
import bisect
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
PRO = np.sort((np.nonzero(p1 | p2)[0] * 4).astype(np.int64))
PROSET = set(PRO.tolist())
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


STR = b"Cannot accommodate DMA offset for IOMMU page tables"
so = D.find(STR)
print(f"[*] 字符串 @0x{so:x}  页=0x{so & ~0xfff:x}  lo12=0x{so & 0xfff:x}")

# ---- 1) 向量化解码所有 ADRP，筛出目标页 ----
idx = np.nonzero((W & np.uint32(0x9f000000)) == np.uint32(0x90000000))[0].astype(np.int64)
w = W[idx].astype(np.int64)
immhi, immlo = (w >> 5) & 0x7ffff, (w >> 29) & 0x3
imm = (immhi << 2) | immlo
imm = np.where(imm & 0x100000, imm - 0x200000, imm)
pc = idx * 4
page = (pc & ~np.int64(0xfff)) + (imm << 12)
sel = np.nonzero(page == (so & ~0xfff))[0]
print(f"[*] 引用该页的 ADRP 指令 {len(sel)} 条: " +
      " ".join(hex(int(idx[s] * 4)) for s in sel[:12]))

refs = []
for s in sel:
    a = int(idx[s] * 4)
    for ins in MD.disasm(D[a:a + 24], a):
        if ins.mnemonic == "add":
            q = [z.strip() for z in ins.op_str.replace("#", "").strip().split(",")]
            if len(q) == 3 and q[2].startswith("0x") and int(q[2], 16) == (so & 0xfff):
                refs.append(a)
                break
print(f"[*] 精确引用字符串（add lo12=0x{so & 0xfff:x}）的位置: " +
      " ".join(hex(r) for r in refs))

# ---- 2) 定位所在函数并收集 vtable 函数地址 ----
def collect(start, size=0x600):
    regs, vals = {}, []
    for ins in MD.disasm(D[start:start + size], start):
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
                if v in PROSET and v not in [x[1] for x in vals]:
                    vals.append((ins.address, v))
            except ValueError:
                pass
    return vals


for r in refs:
    i = bisect.bisect_right(PRO, r)
    fstart = int(PRO[i - 1]) if i else 0
    print(f"\n=== 引用点 0x{r:x} 所在函数起点 0x{fstart:x} [kallsyms: {nm(fstart)}] ===")
    vals = collect(fstart)
    print(f"    函数内 adrp+add 得到的函数地址 {len(vals)} 个:")
    for a, v in vals[:12]:
        print(f"      0x{a:x} -> 0x{v:x}  [kallsyms: {nm(v)}]")

    # ---- 3) 对每个候选函数检查 pre-fix 指令模式 ----
    print("    --- 各候选函数的 bl 后返回值检查 ---")
    for a, v in vals[:12]:
        body = list(MD.disasm(D[v:v + 0x500], v))
        found = []
        for j, ins in enumerate(body[:-2]):
            if ins.mnemonic != "bl":
                continue
            nxt = " ".join(f"{x.mnemonic} {x.op_str}" for x in body[j + 1:j + 7])
            m = re.search(r"0x[0-9a-f]+", ins.op_str)
            tgt = int(m.group(), 16) if m else 0
            has_check = any(t in nxt for t in
                            ("cbz w0", "cbnz w0", "tbz w0", "tbnz w0",
                             "cmp w0", "cmn w0"))
            has_inc = bool(re.search(r"add\s+w\d+,\s*w\d+,\s*#1\b", nxt))
            if has_inc and not has_check:
                found.append((ins.address, tgt, nxt[:100]))
        if found:
            print(f"      0x{v:x}: {len(found)} 处「bl 后未检查 w0 且自增 wN」")
            for fa, tgt, tx in found[:4]:
                print(f"        @0x{fa:x} bl->0x{tgt:x} | {tx}")
