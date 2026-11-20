#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""disasm_user.py — 对无符号用户态 ELF（AArch64）做线性反汇编 + 常量/字符串/PLT 标注。

用法：
  python tools/disasm_user.py <elf> [--out FILE] [--grep REGEX] [--plt]
"""
import argparse
import re
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def load(path):
    f = open(path, 'rb')
    e = ELFFile(f)
    secs = {s.name: s for s in e.iter_sections()}
    text = secs['.text'].data()
    base = secs['.text']['sh_addr']
    # plt entries: .rela.plt r_offset = GOT slot; PLT[i] -> GOT+? Use dynsym
    plt = []
    got = {}
    for s in e.iter_sections():
        if isinstance(s, RelocationSection) and s.name == '.rela.plt':
            symtab = e.get_section(s['sh_link'])
            for r in s.iter_relocations():
                sym = symtab.get_symbol(r['r_info_sym'])
                got[r['r_offset']] = sym.name
                plt.append((r['r_offset'], sym.name))
    return f, e, secs, text, base, plt


def cstr_at(secdata, off):
    if not (0 <= off < len(secdata)):
        return None
    end = secdata.find(b'\x00', off)
    if end < 0:
        return None
    try:
        s = secdata[off:end].decode('ascii')
    except UnicodeDecodeError:
        return None
    return s if s and all(32 <= ord(c) < 127 for c in s) else None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('elf')
    ap.add_argument('--out')
    ap.add_argument('--grep')
    ap.add_argument('--no-annotate', action='store_true')
    args = ap.parse_args(argv)
    f, e, secs, text, base, plt = load(args.elf)
    rodata_sec = None
    for n in ('.rodata', '.rodata.str1.1'):
        if n in secs:
            rodata_sec = secs[n]
            rodata = rodata_sec.data()
            break
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    # PLT stubs: find adrp+ldr from .got then br; simpler: map PLT address range
    plt_sec = secs.get('.plt')
    lines = []
    pend = {}
    for i in md.disasm(text, base):
        line = '0x%06x  %-8s %s' % (i.address, i.mnemonic, i.op_str)
        if i.mnemonic == 'adrp':
            # adrp xN, #imm (absolute page)
            m = re.match(r'(x\d+), #(0x[0-9a-f]+)', i.op_str)
            if m:
                pend[m.group(1)] = int(m.group(2), 16)
        elif i.mnemonic == 'add' and not args.no_annotate:
            m = re.match(r'(x\d+), (x\d+), #(0x[0-9a-f]+)', i.op_str)
            if m and m.group(2) in pend:
                addr = pend[m.group(2)] + int(m.group(3), 16)
                if rodata_sec is not None:
                    off = addr - rodata_sec['sh_addr']
                    s = cstr_at(rodata, off)
                    if s:
                        line += '   ; "%s"' % s[:70]
        if i.mnemonic in ('bl', 'b') and i.op_str.startswith('#0x'):
            tgt = int(i.op_str[1:], 16)
            if plt_sec is not None and plt_sec['sh_addr'] <= tgt < plt_sec['sh_addr'] + plt_sec['sh_size']:
                # PLT0 (resolver) at sh_addr; stub i at sh_addr+0x20+i*0x10
                idx = (tgt - (plt_sec['sh_addr'] + 0x20)) // 0x10
                if 0 <= idx < len(plt):
                    line += '   ; PLT %s' % plt[idx][1]
        lines.append(line)
    if args.grep:
        rx = re.compile(args.grep)
        lines = [l for l in lines if rx.search(l)]
    out = '\n'.join(lines)
    if args.out:
        open(args.out, 'w', encoding='utf-8').write(out + '\n')
        print('wrote', args.out, len(lines), 'lines')
    else:
        print(out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
