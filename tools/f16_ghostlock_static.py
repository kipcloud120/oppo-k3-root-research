#!/usr/bin/env python3
# GhostLock (CVE-2026-43499) 4.9 静态适配工具
#  A) 按 LP64/arm64 对齐规则推导关键结构体字段偏移（依据 realme 官方 4.9 源码
#     + 本机 k3_kernel_config.txt 的 DEBUG_* 全关配置）
#  B) 源码字符串在 F.16 镜像中的逐字命中率（同源性）
#  C) 关键 kallsyms 值被 bl 指令引用的次数（符号配对独立性检验，不依赖名字）
#  D) remove_waiter 声称偏移处的反汇编形态
#
# 用法: python tools/f16_ghostlock_static.py
import re
import struct

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

IMG = "firmware_F16/kernel.decompressed"
SYMS = "firmware_F16/kallsyms_out.txt"
SRC = ["src_ref/futex_4.9/futex.c", "src_ref/futex_4.9/rtmutex.c"]
D = open(IMG, "rb").read()
N = len(D)
W = np.frombuffer(D[:N // 4 * 4], dtype="<u4").astype(np.uint32)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = False

# ---------- A) 结构体偏移 ----------
# (size, align)；均来自 4.9 源码 + arm64 LP64；DEBUG_RT_MUTEXES/
# DEBUG_SPINLOCK/PROVE_LOCKING/DEBUG_PI_LIST 本机全部为 n
SZ = {
    "rb_node": (24, 8),          # ulong + 2 ptr
    "rb_root": (8, 8),           # ptr
    "list_head": (16, 8),        # 2 ptr
    "plist_node": (40, 8),       # int + pad + 2 list_head
    "raw_spinlock_t": (4, 4),    # arch_spinlock_t = 2*u16, __aligned(4)
    "spinlock_t": (4, 4),
    "futex_key": (24, 8),        # union: max member 8+8+4 -> align 8 -> 24
    "rt_mutex": (32, 8),         # 见 STRUCTS
    "rt_mutex_waiter": (80, 8),  # 见 STRUCTS
    "ptr": (8, 8), "u64": (8, 8), "u32": (4, 4),
    "int": (4, 4), "atomic_t": (4, 4),
}

STRUCTS = {
    "rt_mutex_waiter": [
        ("tree_entry", "rb_node"), ("pi_tree_entry", "rb_node"),
        ("task", "ptr"), ("lock", "ptr"), ("prio", "int"),
        ("deadline", "u64"),
    ],
    "rt_mutex": [
        ("wait_lock", "raw_spinlock_t"), ("waiters", "rb_root"),
        ("waiters_leftmost", "ptr"), ("owner", "ptr"),
    ],
    "futex_pi_state": [
        ("list", "list_head"), ("pi_mutex", "rt_mutex"),
        ("owner", "ptr"), ("refcount", "atomic_t"), ("key", "futex_key"),
    ],
    "futex_q": [
        ("list", "plist_node"), ("task", "ptr"), ("lock_ptr", "ptr"),
        ("key", "futex_key"), ("pi_state", "ptr"), ("rt_waiter", "ptr"),
        ("requeue_pi_key", "ptr"), ("bitset", "u32"),
    ],
}


def layout(fields):
    off, res, maxal = 0, [], 1
    for name, typ in fields:
        size, al = SZ[typ]
        maxal = max(maxal, al)
        off = (off + al - 1) // al * al
        res.append((name, typ, off, size))
        off += size
    total = (off + maxal - 1) // maxal * maxal
    return res, total


print("=== A) 4.9 结构体字段偏移推导（LP64 / arm64，DEBUG_* 全关）===")
for name, fields in STRUCTS.items():
    rows, total = layout(fields)
    print(f"  struct {name}  size=0x{total:x} ({total} B)")
    for fn, typ, o, s in rows:
        print(f"    0x{o:02x}  {fn:18s} {typ:16s} ({s} B)")
    SZ[name] = (total, max(SZ[t][1] for _, t in fields))

# ---------- B) 源码字符串同源性 ----------
print("\n=== B) 4.9 futex/rtmutex 源码字符串在 F.16 镜像中的命中 ===")
allstr, hits, misses = set(), [], []
for path in SRC:
    src = open(path, encoding="utf-8", errors="ignore").read()
    for m in re.finditer(r'"((?:\\.|[^"\\])*)"', src):
        s = m.group(1).split("\\")[0].strip()
        if len(s) >= 14:
            allstr.add(s)
for s in sorted(allstr):
    (hits if s.encode() in D else misses).append(s)
print(f"    源码字符串(>=14字符, 去重) = {len(allstr)}；"
      f"逐字命中 = {len(hits)}  命中率 = {len(hits)/max(1,len(allstr)):.1%}")
print("    命中样例：")
for s in hits[:12]:
    print(f"      {s[:88]!r}  @0x{D.find(s.encode()):x}")

# ---------- C) 符号配对独立性检验 ----------
print("\n=== C) 关键 kallsyms 值被 bl 指令引用的次数 ===")
KV = {}
for line in open(SYMS, encoding="latin1"):
    line = line.rstrip("\n")
    if len(line) >= 13:
        KV[line[12:]] = int(line[:10], 16)

isbl = (W & np.uint32(0xfc000000)) == np.uint32(0x94000000)
bp = (np.nonzero(isbl)[0] * 4).astype(np.int64)
w = W[bp // 4].astype(np.int64)
imm = w & 0x03ffffff
imm = np.where(imm & 0x02000000, imm - 0x04000000, imm)
targets = bp + imm * 4
KEYS = [
    "remove_waiter", "rt_mutex_adjust_prio_chain", "rt_mutex_start_proxy_lock",
    "task_blocks_on_rt_mutex", "rt_mutex_proxy_unlock", "try_to_take_rt_mutex",
    "futex_requeue", "futex_lock_pi", "do_futex", "SyS_futex",
    "rt_mutex_cleanup_proxy_lock", "rt_mutex_wait_proxy_lock",
]
for k in KEYS:
    v = KV.get(k)
    if v is None:
        print(f"    {k:34s} 符号不存在")
        continue
    c = int(np.count_nonzero(targets == v))
    print(f"    {k:34s} 0x{v:08x}  bl 引用 {c:4d} 次  "
          f"{'<- 值是真实函数地址' if c else '<- 未被引用，配对存疑'}")

# ---------- D) remove_waiter 声称处形态 ----------
print("\n=== D) remove_waiter 声称偏移处的反汇编形态 ===")
for k in ("remove_waiter", "rt_mutex_start_proxy_lock", "task_blocks_on_rt_mutex"):
    v = KV.get(k, 0)
    print(f"  --- {k} @0x{v:x} ---")
    for ins in MD.disasm(D[v:v + 0x50], v):
        print(f"    0x{ins.address:x}: {ins.mnemonic:8s} {ins.op_str}")

print("\n=== 说明 ===")
print("    A 为按源码 + 本机 config 的推导值，需 vmlinux/pahole 或反汇编立即数复核；")
print("    task_struct->pi_blocked_on 偏移无法由本工具推导（结构体过大且 config 相关），")
print("    需从 remove_waiter 中 'str xzr,[xN,#imm]' 的立即数或 vmlinux DWARF 提取。")
print("    C 的 bl 引用计数不依赖符号名：命中说明该值确为镜像内被调用的函数地址。")
