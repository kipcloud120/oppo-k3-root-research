#!/usr/bin/env python3
# F.16 符号配对交叉验证：用函数内 bl 目标 + 字符串引用判断「名字↔值」是否自洽
#
# 判据：
#   * 若 SyS_futex 声称处 bl 到 do_futex 声称处 → futex 区段配对自洽
#   * 若 arm_lpae_map_sg 声称处是 arm-smmu 探测代码 → 该簇确有错位
#   * 复现 §11.2 的 ADRP/ADD 字符串引用，确认不是判读误差
# 用法: python tools/f16_verify.py
import re
import struct
import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

P = "firmware_F16/kernel.decompressed"
K = "firmware_F16/kallsyms_out.txt"
D = open(P, "rb").read()
N = len(D)
u32 = lambda o: struct.unpack_from("<I", D, o)[0]
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = False

SY = []
for line in open(K, encoding="latin1"):
    line = line.rstrip("\n")
    if len(line) >= 13:
        SY.append((int(line[:10], 16), line[11], line[12:]))
KV = {nm: v for v, t, nm in SY}
VALS = sorted(set(v for v, t, nm in SY if 0 < v < N))
BYVAL = {}
for v, t, nm in SY:
    BYVAL.setdefault(v, []).append((t, nm))


def name_at(v):
    return "/".join(nm for t, nm in BYVAL.get(v, [])[:3]) or "?"


def next_sym(v):
    import bisect
    i = bisect.bisect_right(VALS, v)
    return VALS[i] if i < len(VALS) else v + 0x400


def cstr(o, maxlen=100):
    if not (0 <= o < N):
        return None
    e = D.find(b"\x00", o, min(N, o + maxlen))
    if e < 0 or e == o:
        return None
    s = D[o:e]
    if len(s) > maxlen or any(c < 32 or c > 126 for c in s):
        return None
    return s.decode("ascii")


def analyze(nm, limit=0x300):
    v = KV.get(nm)
    if v is None:
        print(f"  {nm}: 符号不存在")
        return
    end = min(v + limit, next_sym(v) + 4, N)
    ins = list(MD.disasm(D[v:end], v))
    bls = []
    strs = []
    regs = {}
    for x in ins:
        op = x.op_str.replace("#", "").strip()
        if x.mnemonic == "bl" or (x.mnemonic == "b" and x.address > v + 8):
            m = re.search(r"0x[0-9a-f]+", op)
            if m:
                t = int(m.group(), 16)
                bls.append((t, name_at(t)))
        elif x.mnemonic == "adrp":
            p = [s.strip() for s in op.split(",")]
            if len(p) == 2:
                try:
                    regs[p[0]] = int(p[1], 16)
                except ValueError:
                    pass
        elif x.mnemonic in ("add", "ldr") and "," in op:
            p = [s.strip() for s in op.split(",")]
            if len(p) >= 3 and p[1] in regs and p[2].startswith("0x"):
                try:
                    addr = regs[p[1]] + int(p[2], 16)
                    s = cstr(addr)
                    if s:
                        strs.append((addr, s))
                except ValueError:
                    pass
    head = " | ".join(f"{x.mnemonic} {x.op_str}".strip() for x in ins[:5])
    print(f"  {nm} @0x{v:x} (下一个符号 0x{next_sym(v):x})")
    print(f"    前5条: {head}")
    if bls:
        print(f"    bl/b 目标: " + ", ".join(f"0x{t:x}={n}" for t, n in bls[:8]))
    if strs:
        print(f"    字符串引用: " + ", ".join(f"0x{a:x}={s!r}" for a, s in strs[:8]))


TARGETS = [
    "SyS_futex", "do_futex", "futex_requeue", "futex_lock_pi",
    "remove_waiter", "task_blocks_on_rt_mutex", "rt_mutex_start_proxy_lock",
    "arm_lpae_map_sg", "arm_lpae_map", "__arm_lpae_map", "arm_lpae_init_pte",
    "arm_smmu_device_probe", "arm_smmu_domain_alloc", "kgsl_iommu_map",
    "kgsl_mmu_set_svm_region", "kgsl_memdesc_get_align",
    "kgsl_ioctl_gpuobj_alloc", "kgsl_ioctl_map_user_mem",
]
print("=== 1. 目标函数交叉引用 ===")
for nm in TARGETS:
    analyze(nm)

print("\n=== 2. §11.2 反例复现：0x5bf650 起的 ADRP/ADD 字符串引用 ===")
start, end = 0x5bf650, 0x5bf650 + 0x700
regs = {}
for x in MD.disasm(D[start:end], start):
    op = x.op_str.replace("#", "").strip()
    if x.mnemonic == "adrp":
        p = [s.strip() for s in op.split(",")]
        if len(p) == 2:
            try:
                regs[p[0]] = int(p[1], 16)
            except ValueError:
                pass
    elif x.mnemonic == "add" and "," in op:
        p = [s.strip() for s in op.split(",")]
        if len(p) >= 3 and p[1] in regs and p[2].startswith("0x"):
            try:
                addr = regs[p[1]] + int(p[2], 16)
                s = cstr(addr)
                if s and len(s) > 3:
                    print(f"    0x{x.address:x} add -> 0x{addr:x}  {s!r}")
            except ValueError:
                pass

print("\n=== 3. arm_lpae_* / arm_smmu_* / io_pgtable 符号值分布 ===")
for pref in ("arm_lpae_", "__arm_lpae_", "arm_smmu_", "io_pgtable_",
             "kgsl_memdesc_get_align", "kgsl_iommu_"):
    s = sorted((v, nm) for v, t, nm in SY if nm.startswith(pref))
    print(f"    {pref}: {len(s)} 个, 值域 "
          + (f"0x{s[0][0]:x}..0x{s[-1][0]:x}" if s else "-"))
    if s:
        print("      " + ", ".join(f"{nm}@{hex(v)}" for v, nm in s[:6]))

print("\n=== 4. 与 0x10a6000 同值的符号 / vectors 附近符号 ===")
for v0 in (0x10a6000, 0x6720, 0x1189b88, 0x5bf650):
    print(f"    值 0x{v0:x}: {name_at(v0)}")
s = sorted((v, nm) for v, t, nm in SY if 0x6600 <= v <= 0x6900)
print("    kallsyms 0x6600..0x6900: " +
      ", ".join(f"{nm}@{hex(v)}" for v, nm in s[:20]))
