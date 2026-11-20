#!/usr/bin/env python3
"""Find .text references to a named symbol (via any relocation in .rela.text) and
report containing function + offset. Usage: python tools/ko_xref.py <sym> [sym2 ...]"""
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

path = 'vendor_ko/qca_cld3_wlan.ko'
wanted = set(sys.argv[1:])
with open(path, 'rb') as f:
    e = ELFFile(f)
    secs = list(e.iter_sections())
    byname = {s.name: s for s in secs}
    funcs = []
    for sym in byname['.symtab'].iter_symbols():
        if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size']:
            funcs.append((sym['st_value'], sym['st_size'], sym.name))
    funcs.sort()

    def owner(off):
        for v, sz, n in funcs:
            if v <= off < v + sz:
                return n, off - v
        return '?', off

    for s in secs:
        if not isinstance(s, RelocationSection):
            continue
        symtab = e.get_section(s['sh_link'])
        for r in s.iter_relocations():
            sym = symtab.get_symbol(r['r_info_sym'])
            nm = sym.name
            if nm not in wanted:
                continue
            fn, rel = owner(r['r_offset']) if 'text' in s.name else ('?', r['r_offset'])
            print('%-8s off=%#x type=%-4d sym=%-20s fn=%s+0x%x' % (
                s.name, r['r_offset'], r['r_info_type'], nm, fn, rel))
