#!/usr/bin/env python3
# 确认 f16_offset_extract.py 的偏移候选：定位访问点所属符号 + 反汇编上下文
import bisect
import re

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

IMG = "firmware_F16/kernel.decompressed"
SYMS = "firmware_F16/kallsyms_out.txt"
D = open(IMG, "rb").read()
N = len(D)
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
VALS = sorted(BYVAL)


def sym_at(addr):
    i = bisect.bisect_right(VALS, addr)
    v = VALS[i - 1] if i else 0
    names = "/".join(x[1] for x in BYVAL.get(v, [])[:2])
    return f"0x{v:x}({names})"


print("=== 1) 0xae780..0xaea40 区间的 kallsyms 符号 ===")
for v in VALS:
    if 0xAE780 <= v <= 0xAEA40:
        print(f"    0x{v:08x}  " + "/".join(x[1] for x in BYVAL[v][:2]))

print("\n=== 2) 候选指令所在函数与上下文（0xae7d0..0xae860）===")
for ins in MD.disasm(D[0xAE7D0:0xAE870], 0xAE7D0):
    flag = ""
    if "sp_el0" in ins.op_str:
        flag = "  <== 取 current"
    if ins.op_str.startswith("xzr,") or "#0xb70" in ins.op_str or "#0xb58" in ins.op_str:
        flag += "  <== 候选偏移访问"
    print(f"    0x{ins.address:x}: {ins.mnemonic:8s} {ins.op_str}{flag}")

print("\n=== 3) 各候选偏移的全部访问点（rtmutex 簇）===")
import numpy as np
W = np.frombuffer(D[:N // 4 * 4], dtype="<u4").astype(np.uint32)
for cand in (0xB58, 0xB60, 0xB68, 0xB70, 0xA80, 0x3E0):
    print(f"  --- 0x{cand:04x} ---")
    n = 0
    for o in range(0xAD000, 0xAF000, 4):
        w = int(W[o // 4])
        # 只筛 ldr/str unsigned offset，64 位 (0xF9/0xB9 前缀由 capstone 判定)
        if (w & 0xFFC00000) not in (0xF9000000, 0xF9400000):
            continue
        imm12 = (w >> 10) & 0xFFF
        if imm12 * 8 != cand:
            continue
        ins = next(MD.disasm(D[o:o + 4], o), None)
        if ins:
            print(f"      0x{o:x}: {ins.mnemonic:6s} {ins.op_str:32s} in {sym_at(o)}")
            n += 1
            if n >= 8:
                break
    if not n:
        print("      （无 64 位访问）")

print("\n=== 4) commit_creds 中 current 寄存器访问（找 real_cred/cred 偏移）===")
v = KV.get("commit_creds", 0)
end = VALS[bisect.bisect_right(VALS, v)] if v else 0
cur = None
for ins in MD.disasm(D[v:min(end, v + 0x300)], v):
    if ins.mnemonic == "mrs" and "sp_el0" in ins.op_str:
        m = re.search(r"\b(x\d+)\b", ins.op_str.split(",")[0])
        cur = m.group(1) if m else None
        print(f"    0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}  <== current={cur}")
    elif ins.mnemonic in ("ldr", "str") and cur and f"[{cur}," in ins.op_str:
        print(f"    0x{ins.address:x}: {ins.mnemonic:6s} {ins.op_str}")
