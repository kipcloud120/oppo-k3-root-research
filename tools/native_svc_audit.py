#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
native_svc_audit.py —— stripped AArch64 native Binder 服务的导入级 xref（离线）

与 `elf_analyze.py` 的区别：不依赖符号表。通过 `.rela.plt` 的顺序与 `.plt` 中
`adrp/ldr/add/br` 四指令桩建立 **PLT 地址 → 导入名** 的精确映射，再在线性反汇编中找 `bl`。

用法：
  python tools/native_svc_audit.py FILE --xref getCallingUid --context 14
  python tools/native_svc_audit.py FILE --strings          # 接口描述符/服务名候选
"""

import argparse
import os
import re
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def plt_map(e, raw):
    dyn = e.get_section_by_name('.dynsym')
    if dyn is None:
        return {}
    names = [s.name for s in dyn.iter_symbols()]
    rel = None
    for sec in e.iter_sections():
        if isinstance(sec, RelocationSection) and 'plt' in sec.name:
            rel = [names[r['r_info_sym']] for r in sec.iter_relocations()]
            break
    plt = e.get_section_by_name('.plt')
    if rel is None or plt is None:
        return {}
    code = raw[plt['sh_offset']:plt['sh_offset'] + plt['sh_size']]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    ins = list(md.disasm(code, plt['sh_addr']))
    m = {}
    k = 0
    for i, x in enumerate(ins[:-3]):
        if x.mnemonic != 'adrp' or not x.op_str.startswith('x16'):
            continue
        g = ins[i:i + 4]
        if (g[1].mnemonic == 'ldr' and g[1].op_str.startswith('x17')
                and g[2].mnemonic == 'add' and g[2].op_str.startswith('x16')
                and g[3].mnemonic == 'br' and g[3].op_str == 'x17'):
            if k < len(rel):
                m[x.address] = rel[k]
            k += 1
    return m


def strings(e, raw):
    ro = e.get_section_by_name('.rodata')
    if ro is None:
        return []
    b = raw[ro['sh_offset']:ro['sh_offset'] + ro['sh_size']]
    return [(ro['sh_addr'] + m.start(), m.group().decode('latin1'))
            for m in re.finditer(rb'[\x20-\x7e]{5,}\x00', b)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('file')
    ap.add_argument('--xref', action='append', default=[])
    ap.add_argument('--context', type=int, default=12)
    ap.add_argument('--strings', action='store_true')
    a = ap.parse_args()

    raw = open(a.file, 'rb').read()
    e = ELFFile(open(a.file, 'rb'))
    pm = plt_map(e, raw)
    sm = dict(strings(e, raw))

    if a.strings:
        print('=== 接口/服务名候选 ===')
        for addr, s in strings(e, raw):
            if re.search(r'^[a-zA-Z_][\w.]*(@|::|[A-Z][a-z])|\.I[A-Z]|Service|service', s):
                print('  %#x %s' % (addr, s[:120]))
        return 0

    tx = e.get_section_by_name('.text')
    code = raw[tx['sh_offset']:tx['sh_offset'] + tx['sh_size']]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True                      # operands[] 需要 detail 才能访问
    ins = list(md.disasm(code, tx['sh_addr']))

    # adrp+add 的字符串引用注释
    page = {}
    for x in ins:
        if x.mnemonic == 'adrp':
            page[x.operands[0].reg] = x.operands[1].imm

    def annotate(x):
        s = x.op_str
        if x.mnemonic in ('bl', 'b') and x.operands and x.operands[0].type == ARM64_OP_IMM:
            nm = pm.get(x.operands[0].imm)
            if nm:
                return ' ; -> %s' % nm
        if x.mnemonic == 'add' and len(x.operands) == 3 and x.operands[2].type == 2:
            b = page.get(x.operands[1].reg)
            if b is not None:
                t = b + x.operands[2].imm
                if t in sm:
                    return ' ; "%s"' % sm[t]
        return ''

    for pat in a.xref:
        hits = [(i, ins[i]) for i, x in enumerate(ins)
                if x.mnemonic in ('bl', 'blr') and x.operands
                and x.operands[0].type == ARM64_OP_IMM
                and pat.lower() in pm.get(x.operands[0].imm, '').lower()]
        print('=== xref %-22s : %d 处 ===' % (pat, len(hits)))
        for idx, x in hits:
            print('  -- call @%#x -> %s' % (x.address, pm.get(x.operands[0].imm, '?')))
            lo, hi = max(0, idx - a.context), min(len(ins), idx + a.context)
            for y in ins[lo:hi]:
                print('     %#x  %-9s %-42s%s' % (y.address, y.mnemonic, y.op_str, annotate(y)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
