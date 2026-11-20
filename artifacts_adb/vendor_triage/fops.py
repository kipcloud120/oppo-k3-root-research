#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Resolve a file_operations struct inside an ET_REL module .rodata.
usage: python fops.py <ko> <hex_off> [<hex_off> ...]
"""
import sys
from elftools.elf.elffile import ELFFile

FIELDS = ['owner', 'llseek', 'read', 'write', 'read_iter', 'write_iter', 'iterate', 'poll',
          'unlocked_ioctl', 'compat_ioctl', 'mmap', 'open', 'flush', 'release']


def main(ko, offs):
    e = ELFFile(open(ko, 'rb'))
    ro = e.get_section_by_name('.rodata')
    secs = {i: s for i, s in enumerate(e.iter_sections())}
    relmap = {}
    for sec in e.iter_sections():
        if not sec.name.startswith('.rela'):
            continue
        lnk = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            sym = lnk.get_symbol(r['r_info_sym'])
            relmap[(sec.name, r['r_offset'])] = sym.name or ''
    for off in offs:
        print('--- fops @ .rodata+0x%x' % off)
        for i, name in enumerate(FIELDS):
            o = off + i * 8
            target = relmap.get(('.rela.rodata', o))
            if target is None:
                raw = int.from_bytes(ro.data()[o:o + 8], 'little')
                if raw:
                    print('   %-14s = 0x%x (no reloc)' % (name, raw))
                continue
            print('   %-14s -> %s' % (name, target))


if __name__ == '__main__':
    main(sys.argv[1], [int(x, 16) for x in sys.argv[2:]])
