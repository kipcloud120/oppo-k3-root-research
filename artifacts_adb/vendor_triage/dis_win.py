#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Disassemble a window of .text in an ET_REL module and annotate relocations
(MOVW_UABS_G* string refs resolved from section symbols). Triage use only.
usage: python dis_win.py <ko> <start_hex> <end_hex>
"""
import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


def main(ko, start, end):
    e = ELFFile(open(ko, 'rb'))
    secs = {i: s for i, s in enumerate(e.iter_sections())}
    text = e.get_section_by_name('.text')
    rel = e.get_section_by_name('.rela.text')
    lnk = e.get_section(rel['sh_link'])

    def cstr(shndx, off):
        s = secs.get(shndx)
        if s is None:
            return None
        d = s.data()
        if off >= len(d):
            return None
        z = d.find(b'\x00', off)
        raw = d[off:z]
        if 0 < len(raw) < 90 and all(32 <= c < 127 for c in raw):
            return raw.decode()
        return None

    notes = {}
    for r in rel.iter_relocations():
        if not (start <= r['r_offset'] <= end):
            continue
        sym = lnk.get_symbol(r['r_info_sym'])
        sh = sym['st_shndx']
        if not isinstance(sh, int) or sh == 0:
            notes.setdefault(r['r_offset'], []).append(sym.name or '?')
            continue
        off = r['r_addend'] if r['r_addend'] else sym['st_value']
        notes.setdefault(r['r_offset'], []).append(cstr(sh, off) or ('%s+0x%x' % (secs[sh].name, off)))

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for i in md.disasm(text.data()[start:end], start):
        ann = notes.get(i.address)
        print('%05x  %-8s %-28s%s' % (i.address, i.mnemonic, i.op_str, ('   ; ' + ' | '.join(ann)) if ann else ''))


if __name__ == '__main__':
    main(sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16))
