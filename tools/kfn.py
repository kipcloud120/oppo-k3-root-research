#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kfn.py — 内核 ELF 函数级反汇编助手（给 diagchar 审计用）。

不依赖 objdump：pyelftools 取符号 + capstone 反汇编。

用法:
  python kfn.py SYM                  # 反汇编整个符号
  python kfn.py SYM --calls          # 只列直接调用/跳转目标（解析到符号名）
  python kfn.py SYM --grep PAT       # 过滤含 PAT 的指令行
  python kfn.py --addr 0x58c5b8      # 按地址反汇编（自动取所在符号边界）
  python kfn.py --xrefs SYM          # 谁调用 SYM
  python kfn.py --list PAT           # 符号名匹配 PAT
"""
import sys
import re
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ELF = "firmware_F16/vmlinux.elf"


class Kernel:
    def __init__(self, path=ELF):
        self.f = open(path, "rb")
        self.raw = open(path, "rb").read()
        self.elf = ELFFile(self.f)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True
        self.byname = {}
        self.byaddr = {}
        for sec in self.elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for s in sec.iter_symbols():
                    n = s.name
                    if not n or not s["st_value"]:
                        continue
                    t = s["st_info"]["type"]
                    if t != "STT_FUNC":
                        continue
                    self.byname.setdefault(n, (s["st_value"], s["st_size"]))
                    self.byaddr.setdefault(s["st_value"], n)
        self.funcs = sorted((a, n) for n, (a, _) in self.byname.items())

    def segs(self):
        # vmlinux-to-elf 产物用 .kernel/.kernel2 而非 .text
        return [s for s in self.elf.iter_sections()
                if s["sh_type"] == "SHT_PROGBITS" and s["sh_addr"] and s["sh_size"]]

    def read(self, addr, n):
        for sec in self.segs():
            base = sec["sh_addr"]
            if base <= addr < base + sec["sh_size"]:
                off = sec["sh_offset"] + (addr - base)
                return self.raw[off:off + n]
        raise ValueError("addr 0x%x 不落在任何可执行段内" % addr)

    def next_func_addr(self, addr):
        for a, n in self.funcs:
            if a > addr:
                return a, n
        return addr + 0x400, None

    def disas(self, addr, nbytes=None, stop_at_next_sym=True):
        size = None
        for a, name in self.funcs:
            if a == addr:
                size = self.byname[name][1]
                break
        end = None
        if size:
            end = addr + size
        elif stop_at_next_sym:
            end, _ = self.next_func_addr(addr)
        if nbytes:
            end = addr + nbytes
        if end is None:
            end = addr + 0x200
        code = self.read(addr, end - addr)
        return list(self.md.disasm(code, addr))

    def name_of(self, addr):
        # 精确命中，或落在某函数体内
        if addr in self.byaddr:
            return self.byaddr[addr]
        best = None
        for a, n in self.funcs:
            if a > addr:
                break
            best = (a, n)
        if best and addr - best[0] < 0x2000:
            return "%s+0x%x" % (best[1], addr - best[0])
        return None


def _imm(ins):
    """capstone 把 64 位地址当有符号数返回，统一掩到 u64。"""
    v = ins.operands[0].imm
    if v is None:
        return None
    return v & 0xFFFFFFFFFFFFFFFF


def calls_of(k, ins):
    out = []
    for i in ins:
        if i.mnemonic in ("bl", "b", "blraa", "blr", "cbz", "cbnz", "tbz", "tbnz"):
            if i.operands and i.operands[0].type == 2:
                tgt = _imm(i)
                out.append((i, tgt, k.name_of(tgt)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sym", nargs="?")
    ap.add_argument("--addr", type=lambda x: int(x, 0))
    ap.add_argument("--calls", action="store_true")
    ap.add_argument("--grep")
    ap.add_argument("--xrefs")
    ap.add_argument("--list")
    ap.add_argument("--n", type=lambda x: int(x, 0))
    a = ap.parse_args()
    k = Kernel()

    if a.list:
        rx = re.compile(a.list, re.I)
        for n in sorted(k.byname):
            if rx.search(n):
                print("0x%08x %s" % (k.byname[n][0], n))
        return

    if a.xrefs:
        tgt = k.byname.get(a.xrefs)
        if not tgt:
            print("no such symbol:", a.xrefs)
            return
        taddr = tgt[0]
        hits = []
        for n, (addr, _) in k.byname.items():
            ins = k.disas(addr)
            for i in ins:
                if i.mnemonic in ("bl", "b") and i.operands and i.operands[0].type == 2:
                    if i.operands[0].imm == taddr:
                        hits.append((n, i.address))
        for n, addr in sorted(set(hits)):
            print("0x%08x  %s" % (addr, n))
        print("# xrefs total:", len(set(hits)))
        return

    if a.addr is not None:
        addr = a.addr
    else:
        if a.sym not in k.byname:
            print("no such symbol:", a.sym)
            return
        addr = k.byname[a.sym][0]

    ins = k.disas(addr, a.n)
    for i in ins:
        line = "0x%08x  %-8s %s" % (i.address, i.mnemonic, i.op_str)
        if a.grep and not re.search(a.grep, line, re.I):
            continue
        if a.calls:
            continue
        print(line)
    if a.calls:
        for i, tgt, name in calls_of(k, ins):
            print("0x%08x  %-6s -> 0x%08x  %s" % (i.address, i.mnemonic, tgt, name or "?"))


if __name__ == "__main__":
    main()
