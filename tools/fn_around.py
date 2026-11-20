#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fn_around.py — 在无符号用户态 ELF 中按地址定位函数（启发式）并反汇编 + 字符串/PLT 标注。

用法：python tools/fn_around.py <elf> <addr> [--before N] [--after N]
"""
import argparse
import re
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def build(path):
    f = open(path, 'rb')
    e = ELFFile(f)
    secs = {s.name: s for s in e.iter_sections()}
    plt = []
    for s in e.iter_sections():
        if isinstance(s, RelocationSection) and s.name == '.rela.plt':
            symtab = e.get_section(s['sh_link'])
            for r in s.iter_relocations():
                sym = symtab.get_symbol(r['r_info_sym'])
                plt.append(sym.name)
    return f, e, secs, plt


def cstr(data, off):
    if not (0 <= off < len(data)):
        return None
    end = data.find(b'\x00', off)
    if end < 0 or end - off > 90:
        return None
    try:
        s = data[off:end].decode('ascii')
    except UnicodeDecodeError:
        return None
    return s if s and all(32 <= ord(c) < 127 for c in s) else None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('elf')
    ap.add_argument('addr')
    ap.add_argument('--pad', type=int, default=0x40)
    args = ap.parse_args(argv)
    target = int(args.addr, 16)
    f, e, secs, plt = build(args.elf)
    text = secs['.text'].data()
    base = secs['.text']['sh_addr']
    rodata = secs['.rodata'].data() if '.rodata' in secs else b''
    rbase = secs['.rodata']['sh_addr'] if '.rodata' in secs else 0
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    ins = list(md.disasm(text, base))
    idx = None
    for i, x in enumerate(ins):
        if x.address == target:
            idx = i
            break
    if idx is None:
        print('address not on instruction boundary')
        return 2
    # find function start: walk back to a ret followed by stp/sub prologue, or 60 insns
    start = max(0, idx - 160)
    for i in range(idx, max(0, idx - 400), -1):
        if ins[i].mnemonic == 'ret':
            start = i + 1
            break
    # find end: next ret after idx
    end = min(len(ins), idx + 400)
    for i in range(idx, min(len(ins), idx + 800)):
        if ins[i].mnemonic == 'ret':
            end = i + 1
            break
    pend = {}
    for x in ins[start:end]:
        line = '0x%06x  %-8s %s' % (x.address, x.mnemonic, x.op_str)
        if x.mnemonic == 'adrp':
            m = re.match(r'(x\d+), #(0x[0-9a-f]+)', x.op_str)
            if m:
                pend[m.group(1)] = int(m.group(2), 16)
        elif x.mnemonic == 'add':
            m = re.match(r'(x\d+), (x\d+), #(0x[0-9a-f]+)', x.op_str)
            if m and m.group(2) in pend:
                s = cstr(rodata, pend[m.group(2)] + int(m.group(3), 16) - rbase)
                if s:
                    line += '   ; "%s"' % s[:80]
        if x.mnemonic in ('bl', 'b') and x.op_str.startswith('#0x'):
            tgt = int(x.op_str[1:], 16)
            plt_sec = secs.get('.plt')
            if plt_sec and plt_sec['sh_addr'] <= tgt < plt_sec['sh_addr'] + plt_sec['sh_size']:
                j = (tgt - (plt_sec['sh_addr'] + 0x20)) // 0x10
                if 0 <= j < len(plt):
                    line += '   ; PLT %s' % plt[j]
        mark = '  <<<<' if x.address == target else ''
        print(line + mark)
    return 0


if __name__ == '__main__':
    sys.exit(main())
