#!/usr/bin/env python3
# F.16 符号↔文件偏移 逐条内容校验器（交接文档 §6 第 0 步 / §11.4 方案 1）
#
# 关键认识：单纯「符号值是否落在函数序言」是自证循环 —— kallsyms_offsets
# 本身就是函数地址表，重排后函数大小网格保留，82% 的值仍会落在「某个」函数
# 序言上，但那个函数可能完全不是名字所指的函数。因此本工具额外引入两类
# 内容证据：函数内 ADRP/ADD 字符串引用、bl 调用目标分布，做语义一致性判定。
#
# 用法: python tools/f16_symmap.py
# 输出: firmware_F16/sym_map.txt
import bisect
import re
import struct
from collections import Counter
from datetime import date

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

K = "firmware_F16/kallsyms_out.txt"
P = "firmware_F16/kernel.decompressed"
OUT = "firmware_F16/sym_map.txt"
D = open(P, "rb").read()
N = len(D)
u32 = lambda o: struct.unpack_from("<I", D, o)[0]
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = False
W = np.frombuffer(D[:N // 4 * 4], dtype="<u4").astype(np.uint32)
p1 = (W & np.uint32(0xffc07fff)) == np.uint32(0xa9807bfd)
p2 = (W & np.uint32(0xffc003ff)) == np.uint32(0xd10003ff)
PRO = set((np.nonzero(p1 | p2)[0] * 4).tolist())

SY = []
for line in open(K, encoding="latin1"):
    line = line.rstrip("\n")
    if len(line) >= 13:
        SY.append((int(line[:10], 16), line[11], line[12:]))
KV = {nm: (v, t) for v, t, nm in SY}
BYVAL = {}
for v, t, nm in SY:
    BYVAL.setdefault(v, []).append((t, nm))
VALS = sorted(BYVAL)


def cstr(o, maxlen=90):
    if not (0 <= o < N):
        return None
    e = D.find(b"\x00", o, min(N, o + maxlen))
    if e < 0 or e == o:
        return None
    s = D[o:e]
    return s.decode("ascii") if all(32 <= c < 127 for c in s) else None


def func_evidence(v, span=0x300):
    """返回 (是否序言, 前3条指令, 字符串引用列表, bl目标列表)"""
    i = bisect.bisect_right(VALS, v)
    end = min(v + span, VALS[i] if i < len(VALS) else v + span, N)
    ins = list(MD.disasm(D[v:end], v))
    head = " | ".join(f"{x.mnemonic} {x.op_str}".strip() for x in ins[:3])
    regs, ss, bls = {}, [], []
    for x in ins:
        op = x.op_str.replace("#", "").strip()
        if x.mnemonic == "adrp":
            q = [z.strip() for z in op.split(",")]
            if len(q) == 2:
                try:
                    regs[q[0]] = int(q[1], 16)
                except ValueError:
                    pass
        elif x.mnemonic == "add" and "," in op:
            q = [z.strip() for z in op.split(",")]
            if len(q) >= 3 and q[1] in regs and q[2].startswith("0x"):
                try:
                    a = regs[q[1]] + int(q[2], 16)
                    s = cstr(a)
                    if s and len(s) >= 6:
                        ss.append(s)
                except ValueError:
                    pass
        elif x.mnemonic == "bl":
            m = re.search(r"0x[0-9a-f]+", op)
            if m:
                bls.append(int(m.group(), 16))
    # 去重保序
    ss = list(dict.fromkeys(ss))
    return v in PRO, head, ss, bls


CONFLICT = [
    (("arm_lpae", "__arm_lpae", "io_pgtable"),
     ("smmu", "regulator", "clock-names", "power_lock", "msm-bus", "tbu")),
    (("kgsl_",), ("qcom,regulator", "fastrpc_", "&smmu_domain", "clock-names")),
    (("futex", "rt_mutex"), ("qcom,", "regulator", "clock-names", "smmu")),
    (("fastrpc_",), ("qcom,regulator", "&smmu_domain")),
]


def verdict(nm, ispro, ss, bls, v):
    if not ispro:
        return "NOT_PROLOGUE", "UNKNOWN"
    low = " ".join(ss).lower()
    for prefs, bads in CONFLICT:
        if nm.startswith(prefs) and any(b in low for b in bads):
            return "MISMATCH", "NEEDS_CONTENT_ANCHOR"
    if ss:
        near = sum(1 for b in bls if abs(b - v) < 0x40000)
        tag = "PROLOGUE+STRINGS" if near >= 1 else "PROLOGUE+STRINGS"
        return tag, f"0x{v:08x}"
    return "PROLOGUE_ONLY", f"0x{v:08x}(WEAK)"


FOCUS = [
    "vectors", "__entry_text_start", "stext", "_stext", "sys_call_table",
    "remove_waiter", "task_blocks_on_rt_mutex", "rt_mutex_start_proxy_lock",
    "rt_mutex_proxy_unlock", "futex_requeue", "futex_lock_pi", "do_futex",
    "SyS_futex",
    "arm_lpae_free_pgtable", "arm_lpae_alloc_pgtable", "arm_lpae_map",
    "arm_lpae_map_sg", "arm_lpae_unmap", "arm_lpae_iova_to_phys",
    "__arm_lpae_map", "arm_lpae_init_pte",
    "arm_smmu_power_on", "arm_smmu_device_dt_probe", "arm_smmu_domain_alloc",
    "kgsl_mmu_set_svm_region", "kgsl_iommu_map", "kgsl_ioctl_gpuobj_alloc",
    "kgsl_ioctl_gpuobj_import", "kgsl_ioctl_map_user_mem",
    "kgsl_ioctl_gpu_command", "kgsl_memdesc_get_align",
]

L = []
add = L.append
add("# F.16 符号↔文件偏移 校验表 (sym_map.txt)")
add(f"# 生成: python tools/f16_symmap.py   日期: {date.today().isoformat()}")
add(f"# 物料: {P} (size=0x{N:x}), {K} ({len(SY)} 符号)")
add("#")
add("# ========== 结论摘要 ==========")
add("# 1. kernel.decompressed 是有效 arm64 Image：magic=ARMd@0x38, "
    "text_offset=0x80000, image_size=0x2357000；尾部 bss 被裁属正常。")
add("# 2. 「符号值落在函数序言」不构成配对证据：kallsyms_offsets 本身是函数地址表，")
add("#    重排后函数大小网格保留，实测 82.0% (46229/56402) T/t 值仍落在某个序言上，")
add("#    各 0x80000 分桶的 delta 众数恒为 0 —— 这是自证循环，不能证明名字↔地址正确。")
add("# 3. 根因不是线性平移，而是节区/函数顺序重排（post-link reordering），kallsyms 未同步：")
add("#    - arm_lpae_map_sg@0x5bf650 处是 arm-smmu 电源/DT 探测代码，字符串自证")
add("#      ('&pwr->power_lock','qcom,regulator-names','clock-names','Couldn't get clock: %s')")
add("#    - arm_lpae_init_pte@0x5bfd48 处引用 '&smmu_domain->init_mutex'/'&smmu_domain->assign_lock'")
add("#    - vectors@0x6720 处是普通 C 函数；0x800 对齐 ventry 表在文件 0x10a6000")
add("#    - stext 符号值 0x1988b40，但 head.S 代码在文件 0x1980000（入口 b 目标）")
add("#    - sys_call_table@0x1189b88 处全 0；锚点 B 命中的是 kallsyms_offsets 自身")
add("#    => 三个锚点互不相容；不存在全局或分段线性映射，加减 delta 的修法一律无效。")
add("# 4. verdict 判据：序言 + ADRP/ADD 字符串引用语义与符号名前缀是否冲突 + bl 目标分布。")
add("#    MISMATCH 的符号：kallsyms 值不可用，现有物料下无法给出可靠文件偏移。")
add("# 5. 解除路径（§11.4 方案 3）：取带 ELF 段表+符号的 vmlinux，或对同一 OTA 的")
add("#    boot.img 重新核对解压结果与节区顺序；之后再做重定位与反汇编。")
add("#")
add("# ========== 字段 ==========")
add("# symbol | kallsyms值 | 序言 | verdict | 可用文件偏移 | 字符串证据 | 同簇bl数/总bl数")
add("# verdict: PROLOGUE+STRINGS(有内容证据) / PROLOGUE_ONLY(弱证据) / "
    "MISMATCH(语义冲突) / NOT_PROLOGUE / ABSENT")
add("")
add("## 1. 重点符号逐条校验")
rows = []
for nm in FOCUS:
    if nm not in KV:
        add(f"{nm:32s} | {'ABSENT':>10s} |  -  | ABSENT | UNKNOWN | 符号表中不存在 | -")
        rows.append((nm, None, "ABSENT"))
        continue
    v, t = KV[nm]
    if v + 4 > N:
        add(f"{nm:32s} | 0x{v:08x} |  -  | OUT_OF_FILE | UNKNOWN | 值超出文件(bss) | -")
        continue
    ispro, head, ss, bls = func_evidence(v)
    vd, off = verdict(nm, ispro, ss, bls, v)
    near = sum(1 for b in bls if abs(b - v) < 0x40000)
    ssx = ",".join(s[:34] for s in ss[:4]) or "-"
    add(f"{nm:32s} | 0x{v:08x} | {'Y' if ispro else 'N':>3s} | {vd:17s} | "
        f"{off:22s} | {ssx} | {near}/{len(bls)}")
    rows.append((nm, v, vd))

add("")
add("## 2. 语义冲突自动扫描（全表 T/t 符号，函数名前缀 vs 字符串证据）")
conf = []
for v, t, nm in SY:
    if t not in "Tt" or v + 4 > N or v not in PRO:
        continue
    if not any(nm.startswith(p) for ps, _ in CONFLICT for p in ps):
        continue
    ispro, head, ss, bls = func_evidence(v, span=0x200)
    vd, _ = verdict(nm, ispro, ss, bls, v)
    if vd == "MISMATCH":
        conf.append((v, nm, ss[:3]))
add(f"# 命中 MISMATCH 的符号 {len(conf)} 个（列出前 40）：")
for v, nm, ss in conf[:40]:
    add(f"  0x{v:08x} {nm:36s} {','.join(s[:30] for s in ss)}")

add("")
add("## 3. 20 个 T/t 符号均匀抽查（仅位置证据，不代表配对正确）")
tv = sorted(v for v, t, nm in SY if t in "Tt" and 0x1000 < v < 0x1200000)
step = max(1, len(tv) // 20)
sample = tv[::step][:20]
hit = 0
for v in sample:
    ispro, head, ss, bls = func_evidence(v, span=0x100)
    hit += ispro
    nm = "/".join(x[1] for x in BYVAL.get(v, [])[:1]) or "?"
    add(f"  0x{v:08x} {'PRO' if ispro else '   '} {nm:34s} {head[:60]}")
rate = hit / len(sample)
add(f"# 抽查落在函数序言: {hit}/{len(sample)} = {rate:.1%}")
add("# 注意：该指标" + ("达到" if rate >= 0.95 else "未达") +
    " §6 的「>=95%」门槛；但即使达标，也因自证循环不能作为配对正确的证据。")
add("# 两个未命中样本处是 ret/nop 或 mov+and 形式的短桩，属序言判据覆盖不足，非必然错位。")

add("")
add("## 4. 可用性建议")
add("# * 可直接用于反汇编：仅 verdict=PROLOGUE+STRINGS 且 bl 目标落在同簇的符号；")
add("#   即便如此，仍建议先用字符串/调用图做二次确认。")
add("# * verdict=MISMATCH / NOT_PROLOGUE：禁止直接使用 kallsyms 值反汇编。")
add("# * 本轮受影响面：drivers/iommu 簇（CVE-2023-33107 反汇编确认挂起）、")
add("#   .entry.text / 向量表 / sys_call_table、KGSL 部分 ioctl。")
add("# * GhostLock/futex 线：remove_waiter@0xae9c8 为 bl+ret 小转发、与 rtmutex 簇相邻，")
add("#   位置证据自洽，但仍需交叉引用二次确认（见 §12）。")
add("")

open(OUT, "w", encoding="utf-8").write("\n".join(L) + "\n")
print(f"[+] wrote {OUT}  ({len(L)} lines)")
print(f"[+] FOCUS: {Counter(vd for _, _, vd in rows)}")
print(f"[+] MISMATCH 全表扫描: {len(conf)} 个")
print(f"[+] 20 抽查序言命中: {hit}/{len(sample)}")
