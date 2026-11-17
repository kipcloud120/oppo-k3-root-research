#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""elf_analyze.py — 通用 ELF 静态分析：符号表、危险导入、字符串、指定函数调用图。

用法:
  python elf_analyze.py FILE --strings            # 提取可打印字符串
  python elf_analyze.py FILE --symbols            # 符号表中有价值的符号
  python elf_analyze.py FILE --calls FUNC         # 反汇编 FUNC 的调用目标（解析 PLT）
  python elf_analyze.py FILE --xrefs SYMBOL       # 找调用 SYMBOL 的函数
"""
import sys
import re
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM

DANGER = re.compile(r'(^|[^a-z])(system|popen|execl|execv|execve|execvp|fork|'
                    r'setprop|property_set|__system_property_set|/system/bin/sh|sh -c|'
                    r'chmod|mount|setuid)([^a-z]|$)', re.I)


def load(path):
    raw = open(path, "rb").read()
    return raw, ELFFile(open(path, "rb"))


def all_symbols(elf):
    syms = {}       # value -> name
    byname = {}     # name -> (value, size)
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for s in sec.iter_symbols():
                if s["st_value"]:
                    syms[s["st_value"]] = s.name
                    byname[s.name] = (s["st_value"], s["st_size"])
    return syms, byname


def plt_resolver(elf):
    dynsym = elf.get_section_by_name(".dynsym")
    if not dynsym:
        return lambda a: hex(a), {}
    names = [s.name for s in dynsym.iter_symbols()]
    order = []
    for sec in elf.iter_sections():
        if isinstance(sec, RelocationSection) and "plt" in sec.name:
            order = [names[r["r_info_sym"]] for r in sec.iter_relocations()]
            break
    plt = elf.get_section_by_name(".plt")
    if not plt:
        return lambda a: hex(a), {}
    # 从 .plt 指令里找第一个 adrp 的页，作为 entry 起点
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    code = open(elf.stream.name, "rb").read()[plt["sh_offset"]:plt["sh_offset"] + plt["sh_size"]]
    ins = list(md.disasm(code, plt["sh_addr"]))
    start = None
    for i, x in enumerate(ins):
        if x.mnemonic == "adrp":
            start = x.address
            break
    def resolve(addr):
        if start is None or addr < start or (addr - start) % 0x10:
            return hex(addr)
        idx = (addr - start) // 0x10
        return order[idx] if idx < len(order) else hex(addr)
    return resolve, order


def do_strings(raw):
    out = [m.decode("latin1") for m in re.findall(rb"[\x20-\x7e]{4,}", raw)]
    hits = [s for s in out if DANGER.search(s)]
    print(f"=== 危险字符串/符号 ({len(hits)}) ===")
    for s in hits[:60]:
        print("  ", s[:140])
    print(f"\n=== 全部字符串数: {len(out)} ===")
    return out


def do_symbols(byname):
    print("=== 有价值的符号 ===")
    for n, (v, sz) in sorted(byname.items(), key=lambda x: x[1][0]):
        if DANGER.search(n) or any(k in n.lower() for k in ("system", "popen", "property", "exec", "command")):
            print(f"  0x{v:x} size={sz}: {n}")


def do_calls(elf, raw, resolve, byname, fname):
    if fname not in byname:
        # 尝试部分匹配
        cands = [n for n in byname if fname.lower() in n.lower()]
        if not cands:
            print(f"未找到符号 {fname}")
            return
        print(f"匹配到: {cands[:10]}")
        fname = cands[0]
    v, sz = byname[fname]
    text = elf.get_section_by_name(".text")
    base, off = text["sh_addr"], text["sh_offset"]
    code = raw[off + (v - base):off + (v - base) + sz]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
    print(f"=== {fname} @0x{v:x} size={sz} 的调用目标 ===")
    for ins in md.disasm(code, v):
        if ins.mnemonic in ("bl", "blr") and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            print(f"  0x{ins.address:x}: {resolve(ins.operands[0].imm)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--strings", action="store_true")
    ap.add_argument("--symbols", action="store_true")
    ap.add_argument("--calls")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    raw, elf = load(a.file)
    if a.strings or a.all:
        do_strings(raw)
    syms, byname = all_symbols(elf)
    if a.symbols or a.all:
        do_symbols(byname)
    if a.calls:
        resolve, _ = plt_resolver(elf)
        do_calls(elf, raw, resolve, byname, a.calls)


if __name__ == "__main__":
    main()
