#!/usr/bin/env python3
# F.16 真实「符号值 ↔ 文件偏移」映射求解
#
# 思路：不预设结论，先看 Image header 与关键位置的真实内容，再用两组
# 大样本统计求解映射：
#   S1 __ksymtab_strings 指针数组：11043 组 (kallsyms 值 V, 字符串文件偏移 f)
#   S2 函数序言：对每个 T/t 符号值 V，找最近的序言位置 P，统计 delta=P-V
# 若 delta 全局为 0 → 恒等映射；若为分段常数 → 分段线性映射；若散乱 → 布局重排。
import struct
import collections
import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

P = "firmware_F16/kernel.decompressed"
K = "firmware_F16/kallsyms_out.txt"
D = open(P, "rb").read()
N = len(D)
u32 = lambda o: struct.unpack_from("<I", D, o)[0]
u64 = lambda o: struct.unpack_from("<Q", D, o)[0]
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = False
W = np.frombuffer(D[:N // 4 * 4], dtype="<u4").astype(np.uint32)

SY = []
for line in open(K, encoding="latin1"):
    line = line.rstrip("\n")
    if len(line) >= 13:
        SY.append((int(line[:10], 16), line[11], line[12:]))
KV = {nm: v for v, t, nm in SY}


def hexdump(o, n=8):
    return " ".join(f"{u32(o + 4*i):08x}" for i in range(n))


def dis(o, n=8):
    return " | ".join(f"{i.mnemonic} {i.op_str}".strip()
                      for i in MD.disasm(D[o:o + 4*n], o))


print(f"[*] size=0x{N:x}  symbols={len(SY)}")

print("\n=== 1. arm64 Image header（文件 0 起） ===")
print(f"    code0/1     = {hex(u32(0))} {hex(u32(4))}")
print(f"    text_offset = {hex(u64(8))}")
print(f"    image_size  = {hex(u64(0x10))}   (文件实际 0x{N:x})")
print(f"    flags       = {hex(u64(0x18))}")
print(f"    magic@0x38  = {hex(u32(0x38))}  (ARMd=0x644d5241)")
print(f"    head[0..0x20] = {hexdump(0)}")
print(f"    disasm@0      : {dis(0, 4)}")

print("\n=== 2. 关键位置内容 ===")
for o in (0x2074, 0x5a10, 0x5b88, 0x6720, 0x10a6000,
          KV.get("sys_call_table", 0), KV.get("vectors", 0)):
    if o + 32 > N:
        continue
    print(f"  0x{o:08x}: {hexdump(o)}")
    print(f"              {dis(o, 6)}")

print("\n=== 3. 两处 ventry 表的 16 个分支目标 ===")
for base in (0x2074, 0x10a6000):
    tg = []
    for k in range(16):
        w = u32(base + 0x80*k)
        imm = w & 0x03ffffff
        if imm & 0x02000000:
            imm -= 0x04000000
        tg.append(base + 0x80*k + imm*4)
    print(f"  基址 0x{base:x}: " + " ".join(hex(x) for x in tg[:8]) + " ...")
    sym0 = [(hex(v), nm) for v, t, nm in SY if v == tg[0]][:3]
    print(f"    首目标 0x{tg[0]:x} 对应符号 {sym0}")

print("\n=== 4. sys_call_table 声称值处的内容 ===")
st = KV.get("sys_call_table", 0)
if st:
    print(f"    kallsyms sys_call_table=0x{st:x}（注意: 类型 R，可能是 u64 指针表）")
    print(f"    u32[0..8] = " + " ".join(hex(u32(st + 4*i)) for i in range(8)))
    print(f"    u64[0..4] = " + " ".join(hex(u64(st + 8*i)) for i in range(4)))
    for slot in (0, 1, 98):
        for step, rd in ((4, u32), (8, u64)):
            v = rd(st + slot*step)
            print(f"    slot{slot}@{step}B = 0x{v:x}", end="")
        print()

print("\n=== 5. S1: __ksymtab_strings 的 (V, f) delta 曲线 ===")
a = W
m = (a > 0x1000000) & (a < 0x1900000)
idx = np.nonzero(m)[0]
runs, s, p = [], None, None
for i in idx:
    i = int(i)
    if s is None:
        s = p = i; continue
    if i == p + 1 and a[i] > a[p]:
        p = i
    else:
        if p - s >= 1000:
            runs.append((s, p))
        s = p = i
if s is not None and p - s >= 1000:
    runs.append((s, p))
s0, p0 = max(runs, key=lambda r: r[1] - r[0])
pairs = []
for x in a[s0:p0 + 1]:
    f = int(x)
    e = D.find(b"\x00", f, f + 80)
    if e < 0:
        continue
    nm = D[f:e].decode("latin1", "ignore")
    key = "__kstrtab_" + nm
    if key in KV:
        pairs.append((KV[key], f, nm))
pairs.sort()
print(f"    样本 {len(pairs)}；按 kallsyms 值 V 排序后每 1000 条统计 delta=f-V：")
for i in range(0, len(pairs), 1000):
    ch = pairs[i:i+1000]
    dl = [f - v for v, f, _ in ch]
    print(f"      V 0x{ch[0][0]:08x}..0x{ch[-1][0]:08x}  "
          f"delta 0x{min(dl):x}..0x{max(dl):x}  中位 0x{int(np.median(dl)):x}")

print("\n=== 6. S2: 序言最近距离 delta=P-V ===")
p1 = (W & np.uint32(0xffc07fff)) == np.uint32(0xa9807bfd)   # stp x29,x30,[sp,#-imm]!
p2 = (W & np.uint32(0xffc003ff)) == np.uint32(0xd10003ff)   # sub sp,sp,#imm
PRO = np.nonzero(p1 | p2)[0].astype(np.int64) * 4
V = np.array(sorted(v for v, t, nm in SY if t in "Tt" and 0 < v < N - 4),
             dtype=np.int64)
i = np.searchsorted(PRO, V)
lo = PRO[np.clip(i - 1, 0, len(PRO) - 1)]
hi = PRO[np.clip(i, 0, len(PRO) - 1)]
near = np.where(np.abs(lo - V) <= np.abs(hi - V), lo, hi)
d = near - V
exact = np.isin(V, PRO)
print(f"    PRO 站点 {len(PRO)}；T/t 符号 {len(V)}；V 精确落在序言 {exact.sum()} "
      f"({exact.mean():.1%})")
sel = np.abs(d) < 0x40000
cnt = collections.Counter(d[sel].tolist())
print(f"    |delta|<0x40000 的样本 {sel.sum()}；出现最多的 15 个 delta：")
for val, c in cnt.most_common(15):
    print(f"      delta 0x{val:x} : {c}")
print("    按 V 分桶（0x80000 宽）的 delta 众数：")
for b in range(0, 0x2400000, 0x80000):
    s = (V >= b) & (V < b + 0x80000) & (np.abs(d) < 0x20000)
    if s.sum() < 40:
        continue
    c = collections.Counter(d[s].tolist())
    top = c.most_common(2)
    ex = exact[s].mean()
    print(f"      0x{b:08x}  n={s.sum():4d}  精确命中={ex:5.1%}  "
          f"众数=" + ", ".join(f"0x{k:x}:{n}" for k, n in top))
