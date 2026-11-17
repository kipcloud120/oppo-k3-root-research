#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GhostLock 载体「NUL 截断」约束的静态取证工具（离线，只读）。

对应 docs_archive/审核意见CHATGPT-v001.txt 的 P0 第 2 项："NUL 截断约束下，是否可能
满足 fake waiter 所需的字段条件"。只回答三个可以静态确定的问题：

  (1) xattr 路径调用的 strncpy_from_user 是 C 实现还是 arm64 asm 实现
      —— 决定「NUL 之后、同一 8 字节字内」的字节是否被强制写 0；
  (2) 拷贝点之后，同一栈缓冲区是否还有内核 store（fake waiter 是否被覆写）；
  (3) fake waiter 的 9 个字段，相对「拷贝起点」的字节索引表（用户可控 / 残余）。

判据均为纯静态，可在无设备条件下复现。

用法：
  python tools/gl_nul_analysis.py
  python tools/gl_nul_analysis.py --fn getxattr
"""
import argparse
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

VMLINUX = "firmware_F16/vmlinux.elf"

# rt_mutex_waiter = 72B（v4.9，DEBUG_RT_MUTEXES=n），见 HANDOVER §8.1
WAITER_FIELDS = [
    ("tree_entry.__rb_parent_color", 0x00, 8),
    ("tree_entry.rb_right", 0x08, 8),
    ("tree_entry.rb_left", 0x10, 8),
    ("pi_tree_entry.__rb_parent_color", 0x18, 8),
    ("pi_tree_entry.rb_right", 0x20, 8),
    ("pi_tree_entry.rb_left", 0x28, 8),
    ("task", 0x30, 8),
    ("lock", 0x38, 8),
    ("prio", 0x40, 4),
]

# 三条候选路径的（缓冲绝对位置, waiter 绝对位置）来自 GHOSTLOCK_RESCAN.md §3
CANDIDATES = [
    ("SyS_fgetxattr->getxattr", -0x298, -0x288),
    ("SyS_getxattr->getxattr", -0x2C8, -0x288),
    ("SyS_setxattr->path_setxattr->setxattr", -0x2E8, -0x288),
]


class SymTab:
    def __init__(self, elf):
        raw = []
        for secname in (".symtab", ".dynsym"):
            sec = elf.get_section_by_name(secname)
            if not sec:
                continue
            for s in sec.iter_symbols():
                if s.name and s["st_value"]:
                    raw.append((s["st_value"], s.name, s["st_size"]))
        raw.sort()
        self.by_name = {}
        self.by_addr = {}
        for i, (va, name, size) in enumerate(raw):
            if not size and i + 1 < len(raw):
                nxt = raw[i + 1][0]
                size = nxt - va if 0 < nxt - va <= 0x2000 else 0
            self.by_name.setdefault(name, (va, size))
            self.by_addr.setdefault(va, name)
        self._sorted = sorted(self.by_addr.items())

    def name_of(self, addr):
        if addr in self.by_addr:
            return self.by_addr[addr]
        best, bestva = None, 0
        for va, nm in self._sorted:
            if va <= addr:
                best, bestva = nm, va
            else:
                break
        if best and addr - bestva < 0x2000:
            return f"{best}+0x{addr - bestva:x}"
        return None


def text_bytes(elf, va, size, fh=None):
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue
        start = seg["p_vaddr"]
        if start <= va < start + seg["p_filesz"]:
            off = va - start
            return seg.data()[off:off + size]
    # 兜底：HANDOVER §3.1 的地址换算 file_offset = 0x240 + (va - 0xffffff8008080000)
    if fh is not None:
        off = 0x240 + (va - 0xFFFFFF8008080000)
        if 0 <= off:
            fh.seek(off)
            data = fh.read(size)
            if len(data) == size:
                return data
    return None


def analyze_fn(elf, md, symtab, name, va, size, fh=None):
    if not size:
        size = 0x200
    code = text_bytes(elf, va, size, fh)
    if not code:
        print(f"\n=== {name}: 无法从 PT_LOAD 读取 (va=0x{va:x}) ===")
        return
    print(f"\n=== {name} @0x{va:x}  size=0x{size:x} ===")
    for i in md.disasm(code, va):
        if i.mnemonic == "bl":
            imm = i.operands[0].imm & 0xFFFFFFFFFFFFFFFF  # capstone 返回有符号
            callee = symtab.name_of(imm) or symtab.name_of(i.address + imm)
            tgt = imm
            if callee and ("strncpy" in callee or "copy_from_user" in callee):
                print(f"  0x{i.address:x}  bl  {callee}")
                continue
        if i.mnemonic.startswith("st") and "sp" in i.op_str:
            print(f"  0x{i.address:x}  {i.mnemonic:7s} {i.op_str}   <- 栈写")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fn", default=None)
    ap.add_argument("--elf", default=VMLINUX)
    args = ap.parse_args()

    f = open(args.elf, "rb")
    elf = ELFFile(f)
    symtab = SymTab(elf)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    print("=== [1] strncpy_from_user 实现归属（决定 NUL 之后字节是否被清零）===")
    for n in ("strncpy_from_user", "__strncpy_from_user", "do_strncpy_from_user",
              "_copy_from_user", "__arch_copy_from_user"):
        if n in symtab.by_name:
            v, s = symtab.by_name[n]
            print(f"  {n:24s} @0x{v:x}  size=0x{s:x}")
        else:
            print(f"  {n:24s} <不存在>")
    asm_variant = "__strncpy_from_user" in symtab.by_name
    print("  => " + ("存在 asm 变体，NUL 之后行为由 asm 决定"
                     if asm_variant else
                     "无 asm 变体 => 走 lib/strncpy_from_user.c（含 NUL 的 8B 字被 zero_bytemask 掩码）"))

    names = [args.fn] if args.fn else ["getxattr", "setxattr", "SyS_fgetxattr", "SyS_getxattr"]
    for n in names:
        if n not in symtab.by_name:
            print(f"\n=== {n}: 符号不存在（或已被内联）===")
            continue
        v, s = symtab.by_name[n]
        analyze_fn(elf, md, symtab, n, v, s, f)

    print("\n=== [3] fake waiter 字段 <-> 用户串字节索引（三条候选路径）===")
    print("    串自 buffer 起点写入 => 串索引 = waiter偏移 + (waiter - buffer)")
    print("    waiter(72B) 整体落在 256B 缓冲内 => 全部 72B 由用户串覆盖，NUL 之前须全非零")
    for pname, buf, wtr in CANDIDATES:
        boff = wtr - buf
        print(f"\n  -- {pname}: buf=0x{buf:x}  waiter=0x{wtr:x}  boff=0x{boff:x}")
        print(f"     {'field':32s} {'waiter':>7s} {'str_idx':>8s} {'len':>4s}")
        last = 0
        for fname, off, ln in WAITER_FIELDS:
            idx = off + boff
            print(f"     {fname:32s} 0x{off:02x}     0x{idx:02x}  {ln:>4d}")
            last = max(last, idx + ln)
        pri = [off + boff for f2, off, _l in WAITER_FIELDS if f2 == "prio"][0]
        print(f"     => 覆盖整个 72B 需串长 >= {last} (0x{last:x})；"
              f"触及 prio 低字节需前 {pri + 1} (0x{pri + 1:x}) 字节全非零")
        if last > 255:
            print("     !! 超出 XATTR_NAME_MAX(255)，该路径不可用")

    f.close()


if __name__ == "__main__":
    sys.exit(main())
