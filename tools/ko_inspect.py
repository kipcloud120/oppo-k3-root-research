#!/usr/bin/env python3
"""Inspect ET_REL sections + relocations around given .text offsets.

Usage: python tools/ko_inspect.py <ko> [text_off ...]
"""
import sys
from collections import Counter

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def main(argv):
    path = argv[1]
    offs = [int(x, 16) for x in argv[2:]]
    with open(path, "rb") as f:
        e = ELFFile(f)
        print("== sections ==")
        for s in e.iter_sections():
            if s.name.startswith(".rela") or s.name in (".text", ".rodata", ".data", ".data.rel.ro",
                                                        ".dynstr", ".symtab"):
                print("  %-18s type=%-12s addr=%#x size=%#x entsize=%#x link=%s info=%s" % (
                    s.name, s['sh_type'], s['sh_addr'], s['sh_size'],
                    s['sh_entsize'], s['sh_link'], s['sh_info']))
        print("== reloc types ==")
        for s in e.iter_sections():
            if isinstance(s, RelocationSection):
                c = Counter(r['r_info_type'] for r in s.iter_relocations())
                print("  %-18s %s" % (s.name, dict(c)))
        if not offs:
            return
        # index relocs by section+offset
        for s in e.iter_sections():
            if not isinstance(s, RelocationSection):
                continue
            symtab = e.get_section(s['sh_link'])
            for r in s.iter_relocations():
                o = r['r_offset']
                if o in offs:
                    sym = symtab.get_symbol(r['r_info_sym'])
                    print("%s off=%#x type=%d sym=%r st_value=%#x addend=%#x info=%#x" % (
                        s.name, o, r['r_info_type'], sym.name or '.rodata+%#x' % sym['st_value'],
                        sym['st_value'], r['r_addend'], r['r_info']))


if __name__ == "__main__":
    main(sys.argv)
