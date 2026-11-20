#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""b3_audit.py — 阶段 3 / G4 复算工具：B3 全局静态 rt_mutex 的链走查关键点。

只读、离线。依赖 pyelftools + capstone（本仓库其它工具已使用 capstone）。

用法:
  python tools/b3_audit.py [--vmlinux firmware_F16/vmlinux.elf] [--slide 0x1953600000]

输出（全部可由源码行号 + 二进制指令双重对照）:
  1) 关键符号（_text / rt_mutex_adjust_pi / rt_mutex_adjust_prio_chain / B3 四实例 / init_task）
  2) B3 四实例的对象字节（DEFINE_RT_MUTEX 未加锁初值 = 0x20 字节全零 ⇒ 等待树为空）
  3) rt_mutex_adjust_pi 的调用参数（x2=orig_lock=NULL / x4=orig_waiter=NULL / w1=MIN_CHAINWALK）
  4) 链走查 :702 处 rt_mutex_top_waiter() 的内联形态（ldr [lock,#0x10] → ldr [w,#0x38]）
  5) 等待者布局字段（tree_entry@0 / pi_tree_entry@0x18 / task@0x30 / lock@0x38 / prio@0x40 / deadline@0x48）
  6) BUG_ON（rtmutex_common.h:54）→ brk #0x800 的目标地址
  7) 断言汇总（PASS/FAIL）

注意：静态 VA 与 slide 的换算只对 KASLR_EVIDENCE.md 登记的那次 boot
（boot_id b9f9f06a-…，slide 0x1953600000）成立；重启后 slide 失效，静态 VA 不变。
"""
import argparse
import re
import sys

from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

B3_SYMBOLS = [
    "uid_lock",
    "msm_bus_adhoc_lock",
    "msm_bus_dbg_cllist_lock",
    "proc_uid_lock",
]

# 源码事实：rtmutex_common.h 的 struct rt_mutex_waiter（CONFIG_DEBUG_RT_MUTEXES=n）
WAITER_FIELDS = {
    "tree_entry": 0x00,
    "pi_tree_entry": 0x18,
    "task": 0x30,
    "lock": 0x38,
    "prio": 0x40,
    "deadline": 0x48,
}


def load(path):
    f = open(path, "rb")
    return ELFFile(f), f


def symbols(elf):
    """name -> [(value, shndx)]，允许同名（uid_lock 有 rt_mutex 与 spinlock 两个）。"""
    out = {}
    for sec in elf.iter_sections():
        if sec.name != ".symtab":
            continue
        for s in sec.iter_symbols():
            if s.name:
                out.setdefault(s.name, []).append((s["st_value"], s["st_shndx"]))
    return out


def section_of(elf, va):
    for s in elf.iter_sections():
        if s["sh_addr"] <= va < s["sh_addr"] + s["sh_size"]:
            return s
    return None


def read_bytes(elf, va, n):
    s = section_of(elf, va)
    if s is None:
        return None, None
    off = va - s["sh_addr"]
    if s["sh_type"] == "SHT_NOBITS":
        return b"\x00" * n, s
    data = s.data()
    return data[off:off + n], s


def disasm(elf, va, n, md):
    s = section_of(elf, va)
    off = va - s["sh_addr"]
    data = s.data() if s["sh_type"] != "SHT_NOBITS" else b"\x00" * n
    return list(md.disasm(data[off:off + n], va))


def find_sites(ins, pred):
    return [i for i in ins if pred(i)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vmlinux", default="firmware_F16/vmlinux.elf")
    ap.add_argument("--slide", default="0x1953600000")
    args = ap.parse_args()
    slide = int(args.slide, 16)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    elf, fh = load(args.vmlinux)
    syms = symbols(elf)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    fails, passes = [], []

    def chk(ok, label):
        (passes if ok else fails).append(label)

    def one(name):
        v = syms.get(name)
        if not v:
            return None
        return v[0][0]

    print("== 1. 符号 ==")
    text = one("_text")
    chain = one("rt_mutex_adjust_prio_chain")
    adjpi = one("rt_mutex_adjust_pi")
    init_task = one("init_task")
    for name, va in [("_text", text), ("rt_mutex_adjust_pi", adjpi),
                     ("rt_mutex_adjust_prio_chain", chain), ("init_task", init_task)]:
        if va is None:
            print(f"  {name}: <missing>")
            continue
        sec = section_of(elf, va)
        print(f"  {name:32s} static={va:#018x}  section={sec.name if sec else '?'}  "
              f"runtime(+slide)={va + slide:#018x}")
    chk(all(x is not None for x in (text, chain, adjpi)), "关键函数符号齐全")

    print("\n== 2. B3 四实例对象字节（.kernel2/.bss 的 DEFINE_RT_MUTEX 初值） ==")
    b3 = {}
    for name in B3_SYMBOLS:
        entries = syms.get(name, [])
        # 只取 .kernel2/.bss 中 0x20 字节对象；同名 spinlock 单独标注
        for va, shndx in entries:
            sec = section_of(elf, va)
            data, _ = read_bytes(elf, va, 0x20)
            if data is None:
                continue
            kind = "rt_mutex(0x20)" if name != "uid_lock" or sec.name == ".kernel2" else "同名符号"
            if kind == "同名符号":
                kind = "excluded:spinlock"
            print(f"  {name:24s} {va:#018x} sec={sec.name:9s} {kind:18s} "
                  f"bytes={data.hex()}")
            if kind.startswith("rt_mutex"):
                b3[name] = (va, data)
    chk(len(b3) == 4, "找到 4 个 B3 静态 rt_mutex 实例")
    chk(all(d == b"\x00" * 0x20 for _, d in b3.values()),
        "4 个实例初值全零（waiters 空树 / owner=NULL）")

    print("\n== 3. rt_mutex_adjust_pi 的链走查调用参数 ==")
    ins = disasm(elf, adjpi, 0x100, md)
    # 源码 rtmutex.c:1163-1178：waiter=task->pi_blocked_on; gate prio; next_lock=waiter->lock;
    # chain(task, MIN_CHAINWALK, NULL, next_lock, NULL, task)
    gate = find_sites(ins, lambda i: i.mnemonic == "ldr" and "#0x928" in i.op_str)
    nextl = find_sites(ins, lambda i: i.mnemonic == "ldr" and "#0x38" in i.op_str)
    zeros = find_sites(ins, lambda i: i.mnemonic == "mov" and i.op_str.replace(" ", "") in
                       ("w1,wzr", "x2,xzr", "x4,xzr"))
    print(f"  pi_blocked_on 读取点: {[hex(i.address) for i in gate] or 'NONE'}")
    print(f"  waiter->lock 读取点: {[hex(i.address) for i in nextl] or 'NONE'}")
    print(f"  置零参数(mov w1/wzr, x2/xzr, x4/xzr): {[hex(i.address) for i in zeros]}")
    for i in ins:
        if i.address in [x.address for x in gate + nextl + zeros]:
            print(f"    {i.address:#x}: {i.mnemonic:8s} {i.op_str}")
    chk(bool(gate) and bool(nextl) and len(zeros) >= 3,
        "adjust_pi 以 orig_lock=NULL/orig_waiter=NULL/MIN_CHAINWALK 进入链走查")

    print("\n== 4. 链走查 :702 rt_mutex_top_waiter() 内联形态 ==")
    ins = disasm(elf, chain, 0x900, md)
    top_pairs = []
    # ldr Xd,[Xb,#0x10]  ;  ldr Xt,[Xd,#0x38]  （rtmutex_common.h:52-54 的 BUG_ON 读）
    re_first = re.compile(r"^ldr\s+(x\d+),\s*\[x\d+,\s*#0x10\]$")
    re_second = re.compile(r"^ldr\s+x\d+,\s*\[(x\d+),\s*#0x38\]$")
    for idx, i in enumerate(ins):
        m = re_first.match(f"{i.mnemonic} {i.op_str}")
        if not m:
            continue
        dst = m.group(1)
        for j in ins[idx + 1:idx + 5]:
            m2 = re_second.match(f"{j.mnemonic} {j.op_str}")
            if m2 and m2.group(1) == dst:
                top_pairs.append((i, j))
                break
    for a, b in top_pairs:
        print(f"    {a.address:#x}: {a.mnemonic:8s} {a.op_str}")
        print(f"    {b.address:#x}: {b.mnemonic:8s} {b.op_str}")
    brks = [i for i in ins if i.mnemonic == "brk"]
    print(f"  brk #0x800 站点: {[hex(i.address) for i in brks]}")
    chk(len(top_pairs) >= 2, "找到 ≥2 处 lock+0x10 → w+0x38 序列（:702 与 :745/:757 前置）")
    chk(len(brks) >= 3, "BUG_ON 的 brk #0x800 目标存在")

    print("\n== 5. 等待者布局字段核对 ==")
    # 源码 rtmutex.c:723 waiter->prio / :724 waiter->deadline；:765 enqueue_pi 用 waiter
    prio_sites = find_sites(ins, lambda i: i.mnemonic == "str" and "#0x40]" in i.op_str)
    dl_sites = find_sites(ins, lambda i: i.mnemonic == "str" and "#0x48]" in i.op_str)
    print(f"  waiter->prio 写点([w,#0x40]): {[hex(i.address) for i in prio_sites]}")
    print(f"  waiter->deadline 写点([w,#0x48]): {[hex(i.address) for i in dl_sites]}")
    chk(bool(prio_sites) and bool(dl_sites), "waiter 布局 prio@0x40 / deadline@0x48 与源码一致")
    print(f"  预期布局: {WAITER_FIELDS}")

    print("\n== 6. 判定汇总 ==")
    for p in passes:
        print(f"  [PASS] {p}")
    for p in fails:
        print(f"  [FAIL] {p}")
    print(f"\n  slide 说明: 上表 runtime 值仅对 boot b9f9f06a-…（slide {slide:#x}）成立。")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
