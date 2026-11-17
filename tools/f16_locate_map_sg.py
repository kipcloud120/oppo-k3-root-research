#!/usr/bin/env python3
# D 阶段：用「io_pgtable_ops 运行时赋值点」内容锚定 arm_lpae_* 簇真实文件偏移
#
# 依据（src_ref/realmeX_master_io-pgtable-arm.c L994-1001）：
#   data->iop.ops = (struct io_pgtable_ops) {
#       .map = arm_lpae_map, .map_sg = arm_lpae_map_sg,
#       .unmap = arm_lpae_unmap, .iova_to_phys = arm_lpae_iova_to_phys,
#       .is_iova_coherent = ..., .iova_to_pte = ... };
# 编译后通常是一串 adrp + add(#:lo12:) 把 6 个函数地址写入结构体。
# ADRP 的页相对量在「文件偏移坐标系」下仍然正确（vaddr 与文件偏移只差
# 页对齐常数），因此 capstone 以文件偏移为 PC 即可还原真实文件偏移。
#
# 方案 1：adrp 密集窗口 + 数据流（adrp/add -> 落在函数序言的地址）
# 方案 2：.rodata 中连续 6 个绝对 vaddr 函数指针（静态模板情形）
# 方案 3：bl 之后未检查 w0 就自增计数器的 pre-fix 指令模式
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


def near_arm_lpae(vals):
    return [v for v, t, n in SY if n.startswith("arm_lpae") and
            min((abs(v - x) for x in vals), default=1 << 60) < 0x20000]


print(f"[*] size=0x{N:x}  PRO={len(PRO)}")

# ---------- 方案 1 ----------
isadrp = (W & np.uint32(0x9f000000)) == np.uint32(0x90000000)
ap = (np.nonzero(isadrp)[0] * 4).astype(np.int64)
print(f"\n=== 方案1: adrp 站点 {len(ap)} ===")
span = ap[5:] - ap[:-5]
cand = np.nonzero(span <= 0x140)[0]
print(f"    6 个 adrp 落在 0x140 内的密集窗口: {len(cand)}")


def scan(off, size=0x260):
    regs, hits = {}, []
    for ins in MD.disasm(D[off:off + size], off):
        m = ins.mnemonic
        q = [s.strip() for s in ins.op_str.replace("#", "").strip().split(",")]
        if m == "adrp" and len(q) == 2:
            try:
                regs[q[0]] = int(q[1], 16)
            except ValueError:
                pass
        elif m == "add" and len(q) == 3 and q[1] in regs and q[2].startswith("0x"):
            try:
                v = regs[q[1]] + int(q[2], 16)
                regs[q[0]] = v
                if v in PRO:
                    hits.append((ins.address, v, q[0]))
            except ValueError:
                pass
        elif m == "mov" and len(q) == 2 and q[1] in regs:
            regs[q[0]] = regs[q[1]]
    return hits


seen, results = set(), []
for k in cand:
    start = int(ap[k]) - 0x20
    if start < 0 or start in seen:
        continue
    seen.add(start)
    hits = scan(start)
    vals = sorted(set(v for _, v, _ in hits))
    if len(vals) >= 5 and max(vals) - min(vals) < 0x30000:
        results.append((start, vals, hits))
print(f"    命中 >=5 个函数地址且跨度 <0x30000 的窗口: {len(results)}")
for start, vals, hits in results[:12]:
    print(f"    窗口 0x{start:x}: " + " ".join(f"0x{v:x}={nm(v)}" for v in vals[:8]))

# ---------- 方案 2 ----------
print("\n=== 方案2: .rodata 连续绝对 vaddr 函数指针 ===")
U = np.frombuffer(D[:N // 8 * 8], dtype="<u8")
BASE = 0xffffff8008080000
lo, hi = BASE + 0x1000, BASE + 0x1200000
ok = (U >= lo) & (U < hi)
L = 6
c = np.ones(len(U) - L + 1, dtype=bool)
for j in range(L):
    c &= ok[j:j + len(U) - L + 1]
idx = np.nonzero(c)[0]
print(f"    连续 {L} 个内核 vaddr 的候选: {len(idx)}")
hits2 = []
for i in idx:
    vs = [int(U[i + j]) - BASE for j in range(L)]
    score = sum(v in PRO for v in vs)
    if score >= 4:
        hits2.append((int(i) * 8, vs, score))
print(f"    其中 >=4 个落在函数序言: {len(hits2)}")
for o, vs, sc in hits2[:10]:
    print(f"    文件0x{o:x}: " + " ".join(f"0x{v:x}={nm(v)}" for v in vs))

# ---------- 方案 3 ----------
print("\n=== 方案3: bl 后未检查 w0 即自增计数的 pre-fix 模式 ===")
# 找所有 bl，取其后 6 条指令；判据：无 cbz/cbnz/tbz/cmp w0 且出现 add wN,wN,#1
isbl = (W & np.uint32(0xfc000000)) == np.uint32(0x94000000)
blp = np.nonzero(isbl)[0] * 4
pre = []
for p in blp:
    p = int(p)
    if p + 28 > N:
        break
    ins = list(MD.disasm(D[p:p + 28], p))
    txt = " ".join(f"{x.mnemonic} {x.op_str}" for x in ins[1:])
    if any(t in txt for t in ("cbz w0", "cbnz w0", "tbz w0", "tbnz w0",
                              "cmp w0", "cmn w0")):
        continue
    if re.search(r"add\s+w\d+,\s*w\d+,\s*#1\b", txt):
        m = re.search(r"0x[0-9a-f]+", ins[0].op_str)
        tgt = int(m.group(), 16) if m else 0
        pre.append((p, tgt, txt[:110]))
print(f"    命中 {len(pre)} 处（前 12）")
for p, tgt, txt in pre[:12]:
    print(f"    0x{p:x} bl->0x{tgt:x}={nm(tgt)} | {txt}")

print("\n=== 汇总 ===")
print(f"    方案1 候选窗口 {len(results)}；方案2 候选 {len(hits2)}；方案3 pre-fix 模式 {len(pre)}")
