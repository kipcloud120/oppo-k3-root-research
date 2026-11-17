#!/usr/bin/env python3
# F.16 符号↔文件偏移：独立诊断（检验 交接文档 §11 是否为探针伪影）
#
# 不预设任何映射，只从镜像内容出发做 6 组独立检验：
#   1) 全范围 ventry 表扫描（不限 0x800 对齐）——检验锚点 A 的"唯一性"
#   2) 关键偏移处反汇编 + 字符串引用——检验 §11.2 的反例
#   3) 0x1383e74 数组的真实身份——检验锚点 B 是否就是 kallsyms_offsets
#   4) 锚点 C 数组的真实身份
#   5) __ksymtab (value,name) 结构：镜像自证的"符号名↔地址"配对
#   6) 按符号值分桶统计"落在函数序言"的命中率，定位真正的错位边界
#
# 用法: python tools/f16_diag.py
import struct
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

SY = []
for line in open(K, encoding="latin1"):
    line = line.rstrip("\n")
    if len(line) < 13:
        continue
    SY.append((int(line[:10], 16), line[11], line[12:]))
KV = {nm: (v, t) for v, t, nm in SY}
BYVAL = {}
for v, t, nm in SY:
    BYVAL.setdefault(v, []).append((t, nm))

W = np.frombuffer(D[:N // 4 * 4], dtype="<u4").astype(np.uint32)
PRO = set((np.nonzero((W & np.uint32(0xffc07fff)) == np.uint32(0xa9807bfd))[0] * 4).tolist())


def dis(off, count=12, label=""):
    print(f"  --- disasm @0x{off:x} {label} ---")
    for ins in MD.disasm(D[off:off + 4 * count], off):
        print(f"   0x{ins.address:x}: {ins.mnemonic:8s} {ins.op_str}")


def syms_near(v, radius=0x40):
    return [f"{nm}@{hex(x)}" for x in range(max(0, v - radius), v + 1)
            for _, nm in BYVAL.get(x, [])][:6]


def cstr(o, maxlen=80):
    e = D.find(b"\x00", o, o + maxlen)
    if e < 0:
        return None
    s = D[o:e]
    try:
        t = s.decode("ascii")
    except UnicodeDecodeError:
        return None
    return t if t and all(32 <= c < 127 for c in s) else None


print(f"[*] {P} size=0x{N:x}  symbols={len(SY)}  value range "
      f"0x{SY[0][0]:x}..0x{SY[-1][0]:x}  prologue sites={len(PRO)}")

# ---- 1) 全范围 ventry 表（16 项，间隔 0x80，b/nop） ----
print("\n[1] 全范围 ventry 表扫描（不限 0x800 对齐）")
ISB = ((W & np.uint32(0xFC000000)) == np.uint32(0x14000000)) | (W == np.uint32(0xD503201F))
cand = np.nonzero(ISB)[0].astype(np.int64)
step = 0x80 // 4
mask = np.ones(len(cand), dtype=bool)
for k in range(16):
    q = cand + step * k
    ok = q < len(W)
    vals = np.zeros(len(q), dtype=bool)
    vals[ok] = ISB[q[ok]]
    mask &= vals
vt = (cand[mask] * 4)
print(f"    候选起点 {len(cand)} 个；完整 16 项表 {len(vt)} 处")
for p in vt[:40]:
    al = "0x800对齐" if p % 0x800 == 0 else f"非对齐(+0x{p % 0x800:x})"
    near = syms_near(int(p), 0x20)
    print(f"    0x{p:x}  {al}  邻近符号={near}")
if len(vt) > 40:
    print(f"    ... 另 {len(vt)-40} 处")

# ---- 2) 关键偏移反汇编 ----
print("\n[2] 关键偏移处内容")
v = KV.get("vectors", (0,))[0]
print(f"    kallsyms vectors = 0x{v:x}  (0x800 对齐? {v % 0x800 == 0})")
for p in (v, 0x10a6000, 0x5bf650, 0x5bfd48, 0xae9c8, 0xe7da0):
    if p + 64 > N:
        continue
    print(f"  @0x{p:x}: " + " ".join(f"{u32(p+4*i):08x}" for i in range(8)))
dis(v, 6, "vectors 声称处")
dis(0x10a6000, 6, "锚点 A 找到的向量表")
dis(0x5bf650, 14, "arm_lpae_map_sg 声称处")
dis(0xae9c8, 8, "remove_waiter 声称处")

# ---- 3) 0x1383e74 数组身份 ----
print("\n[3] 锚点 B 数组身份检验")
O = 0x13807e0
print(f"    kallsyms_offsets 数组起点 O=0x{O:x}；前 8 项="
      + " ".join(hex(u32(O + 4*i)) for i in range(8)))
B = 0x1383e74
print(f"    锚点 B 基址 0x{B:x} 距 O = {B-O} bytes = {(B-O)//4} 个 u32")
print(f"    该处前 12 项=" + " ".join(hex(u32(B + 4*i)) for i in range(12)))
# kallsyms_offsets 长度 = num_syms，检查是否严格非递减贯穿
seg = W[O//4: (O + 4*len(SY))//4]
print(f"    O 起 {len(SY)} 项：非递减比例 "
      f"{np.mean(np.diff(seg.astype(np.int64)) >= 0):.4f}; "
      f"min={hex(int(seg.min()))} max={hex(int(seg.max()))}")
print(f"    O 起数组第 {(B-O)//4} 项 = {hex(int(seg[(B-O)//4]))}")
print("    → 若一致，则锚点 B 命中的是 kallsyms_offsets 自身，属自证循环")

# ---- 4) 锚点 C 数组身份 ----
print("\n[4] 锚点 C 数组身份检验")
a = W
m = (a > 0x1000000) & (a < 0x1900000)
idx = np.nonzero(m)[0]
runs, s, p = [], None, None
for i in idx:
    i = int(i)
    if s is None:
        s = p = i
        continue
    if i == p + 1 and a[i] > a[p]:
        p = i
    else:
        if p - s >= 1000:
            runs.append((s, p))
        s = p = i
if s is not None and p - s >= 1000:
    runs.append((s, p))
print(f"    符合 C 判据的递增游程 {len(runs)} 段，最长 3 段：")
for s0, p0 in sorted(runs, key=lambda r: r[1]-r[0], reverse=True)[:3]:
    print(f"      文件 0x{s0*4:x}..0x{p0*4:x}  长度 {p0-s0+1}  "
          f"值域 0x{int(a[s0]):x}..0x{int(a[p0]):x}")
    st = int(a[s0])
    print(f"      首值指向字符串: {cstr(st)!r}")
# 该游程位于哪个已知块
if runs:
    s0, p0 = max(runs, key=lambda r: r[1]-r[0])
    print(f"    与已知块对比: offsets@0x13807e0 names@0x13f9700 token@0x1594c00")
    print(f"    最长游程起点 0x{s0*4:x} 落在 "
          + ("names 区间" if 0x13f9700 <= s0*4 < 0x1594c00 else "其它区间"))

# ---- 5) __ksymtab (value,name) 结构：镜像自证配对 ----
print("\n[5] __ksymtab 结构搜索（u64 value + u64 name_ptr，均为绝对 vaddr）")
U = np.frombuffer(D[:N // 8 * 8], dtype="<u8")
hi = U >> np.uint64(32)
is_va = (hi >= np.uint64(0xffff0000)) & (hi <= np.uint64(0xffffffff))
pairs = []
for i in np.nonzero(is_va[:-1] & is_va[1:])[0][:200000]:
    o = int(i) * 8
    val, nptr = u64(o), u64(o + 8)
    pairs.append((o, int(val), int(nptr)))
print(f"    相邻两个内核 vaddr 的候选对：{len(pairs)}")
if pairs:
    print("    前 6 组：")
    for o, val, nptr in pairs[:6]:
        print(f"      文件0x{o:x} value=0x{val:x} name_ptr=0x{nptr:x}")
    # nptr 与 value 的低 32 位差，应等于 __kstrtab 与符号地址的固定间距分布
    lv = np.array([v & 0xffffffff for _, v, _ in pairs], dtype=np.int64)
    ln = np.array([p & 0xffffffff for _, _, p in pairs], dtype=np.int64)
    d = ln - lv
    print(f"    (name_ptr - value) 低32位：min=0x{d.min():x} max=0x{d.max():x} "
          f"中位=0x{int(np.median(d)):x}")

# ---- 6) 分桶命中率 ----
print("\n[6] T/t 符号按值分桶：落在函数序言的命中率（桶宽 0x10000）")
buck = {}
for v, t, nm in SY:
    if t not in "Tt" or v + 4 > N:
        continue
    b = v >> 16
    dd = buck.setdefault(b, [0, 0])
    dd[1] += 1
    if v in PRO:
        dd[0] += 1
allrows = [(b, h, n) for b, (h, n) in buck.items()]
bad = [(b, h, n) for b, h, n in allrows if n >= 20 and h / n < 0.6]
good = [(b, h, n) for b, h, n in allrows if n >= 20 and h / n >= 0.9]
print(f"    总桶数 {len(buck)}；命中率<60% 的桶 {len(bad)}；>=90% 的桶 {len(good)}")
print("    命中率最低的 15 个桶（值区间 / 命中 / 总数）：")
for b, h, n in sorted(bad, key=lambda x: x[1]/x[2])[:15]:
    print(f"      0x{b<<16:08x}..0x{(b+1)<<16:08x}  {h:4d}/{n:4d} = {h/n:.1%}")
print("    抽样 10 个高命中桶：")
for b, h, n in good[::max(1, len(good)//10)][:10]:
    print(f"      0x{b<<16:08x}..0x{(b+1)<<16:08x}  {h:4d}/{n:4d} = {h/n:.1%}")
