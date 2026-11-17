#!/usr/bin/env python3
# 从 F.16 kernel.decompressed 反汇编立即数提取 task_struct 关键字段偏移
#
# 背景：§15.4 已证明 futex/rtmutex 簇的 kallsyms 值是镜像内真实函数地址，
# 因此可直接反汇编这些函数，从 ldr/str [xTask,#imm] 的立即数读出字段偏移。
# 这比同源源码编译更贴近本机（不需要 vmlinux/DWARF/交叉工具链）。
#
# 方法：
#  A) 在 rtmutex 簇内，跟蹤 `mrs xN, sp_el0`（取 current），
#     收集其后对 [xN,#imm] 的 64 位 str/ldr 立即数
#  B) 全簇统计 `str xzr, [x?,#imm]`（Rt=31，指针字段清零）的大偏移
#  C) 从 commit_creds / override_creds 等函数提取 real_cred / cred 偏移
#  D) 静态链接基址（KIMAGE_VADDR + TEXT_OFFSET）
#
# 用法: python tools/f16_offset_extract.py
import bisect
import collections
import re
import struct

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

IMG = "firmware_F16/kernel.decompressed"
SYMS = "firmware_F16/kallsyms_out.txt"
D = open(IMG, "rb").read()
N = len(D)
W = np.frombuffer(D[:N // 4 * 4], dtype="<u4").astype(np.uint32)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = False

SY = []
for line in open(SYMS, encoding="latin1"):
    line = line.rstrip("\n")
    if len(line) >= 13:
        SY.append((int(line[:10], 16), line[11], line[12:]))
KV = {nm: v for v, t, nm in SY}
BYVAL = {}
for v, t, nm in SY:
    BYVAL.setdefault(v, []).append((t, nm))
TEXT = sorted(v for v, t, nm in SY if t in "Tt" and 0 < v < N - 4)

RT_LO, RT_HI = 0xAD000, 0xAF000
FU_LO, FU_HI = 0xE7000, 0xE9000

OFF_RE = re.compile(r"\[\s*(x\d+|sp)\s*,\s*#(0x[0-9a-fA-F]+|\d+)\s*\]")
REG_RE = re.compile(r"\b(x\d+)\b")


def one(off):
    try:
        return next(MD.disasm(D[off:off + 4], off))
    except StopIteration:
        return None


def func_bounds(v, cap=0x700):
    i = bisect.bisect_right(TEXT, v)
    end = TEXT[i] if i < len(TEXT) else v + cap
    return min(end, v + cap)


print("=== A) rtmutex 簇：mrs sp_el0 -> [xCur,#imm] 的 64 位访问 ===")
cur_hits = collections.Counter()
cur_detail = collections.defaultdict(list)
for lo, hi, tag in ((RT_LO, RT_HI, "rt"), (FU_LO, FU_HI, "futex")):
    vs = [v for v in TEXT if lo <= v < hi]
    for v in vs:
        end = func_bounds(v)
        cur = None
        for o in range(v, end, 4):
            ins = one(o)
            if ins is None:
                continue
            if ins.mnemonic == "mrs" and "sp_el0" in ins.op_str:
                m = REG_RE.search(ins.op_str.split(",")[0])
                cur = m.group(1) if m else None
                continue
            if ins.mnemonic not in ("str", "ldr"):
                continue
            mm = OFF_RE.search(ins.op_str)
            if not mm:
                continue
            val = int(mm.group(2), 0)
            if val < 0x100 or val > 0x2000:
                continue
            if cur and mm.group(1) == cur:
                cur_hits[val] += 1
                cur_detail[val].append((o, ins.mnemonic, ins.op_str, tag))
print("    current 寄存器访问的大偏移（>0x100）频次 Top 20：")
for val, cnt in cur_hits.most_common(20):
    nm = "/".join(x[1] for x in BYVAL.get(val, [])[:1]) or ""
    print(f"      0x{val:04x}  {cnt:3d} 次  样例 " +
          " | ".join(f"0x{o:x}:{mn} {op}" for o, mn, op, _ in cur_detail[val][:2]))

print("\n=== B) rtmutex 簇：str xzr,[x?,#imm]（指针字段清零）大偏移 ===")
zero_hits = collections.Counter()
zero_detail = collections.defaultdict(list)
for o in range(RT_LO, RT_HI, 4):
    ins = one(o)
    if ins is None or ins.mnemonic != "str":
        continue
    if not ins.op_str.startswith("xzr,"):
        continue
    mm = OFF_RE.search(ins.op_str)
    if not mm:
        continue
    val = int(mm.group(2), 0)
    if 0x100 <= val <= 0x2000:
        zero_hits[val] += 1
        zero_detail[val].append(o)
for val, cnt in zero_hits.most_common(15):
    print(f"      0x{val:04x}  {cnt:3d} 次  位置 " +
          " ".join(f"0x{o:x}" for o in zero_detail[val][:6]))

print("\n=== C) cred / real_cred 偏移线索 ===")
CRED_KEYS = ["commit_creds", "prepare_creds", "override_creds",
             "get_current_cred", "put_cred", "prepare_kernel_cred",
             "revert_creds", "cred_init", "__task_cred"]
for k in CRED_KEYS:
    v = KV.get(k)
    print(f"    {k:24s} : {'0x%08x' % v if v else '不存在'}")
for k in ("commit_creds", "override_creds", "get_current_cred"):
    v = KV.get(k)
    if not v:
        continue
    print(f"    --- {k} @0x{v:x} 前 60 条 ---")
    for ins in MD.disasm(D[v:v + 0xF0], v):
        if ins.mnemonic in ("str", "ldr", "mrs", "add") and \
           (OFF_RE.search(ins.op_str) or "sp_el0" in ins.op_str):
            print(f"      0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}")

print("\n=== D) 静态链接基址 ===")
# kallsyms_relative_base 通常紧跟 kallsyms_offsets/token 结构；
# 由 §12/f16_diag.py [5] 的绝对 vaddr 指针反推
print("    KIMAGE_VADDR + TEXT_OFFSET = 0xffffff8008080000")
print("    验证：镜像内 0xffffff8009614c00 - 0xffffff8008080000 = "
      f"0x{0xffffff8009614c00 - 0xffffff8008080000:x}"
      "（= kallsyms token_table 文件偏移 0x1594c00）")
print("    运行时 KASLR slide 未知，必须运行时泄露；静态只能给出链接基址。")

print("\n=== 判定提示 ===")
print("    A/B 的众数偏移中，同时满足「64 位 str/ldr」「在 remove_waiter /")
print("    task_blocks_on_rt_mutex / rt_mutex_adjust_prio_chain 附近」「源码多处访问」")
print("    的候选最可能是 task_struct->pi_blocked_on。需结合 §15.3 源码偏移交叉验证。")
