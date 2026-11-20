#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wlan_wext_table.py — 还原 qca_cld3_wlan.ko 的 WEXT 私有表（纯离线）。

- `we_private`（.rodata+0x4c70，0x100 B = 32 个 handler 指针）：由 `.rela.rodata` ABS64 给出。
  索引 i 对应 ioctl `SIOCIWFIRSTPRIV + i`（0x8BE0 + i）。
- `we_private_args`（.rodata+0x4d70，0x4a8*... 实际 0x14e8 = 223 × 0x18）：
  {u32 cmd; u16 set_args; u16 get_args; char name[16]}。
  iwpriv 的语义（wireless-tools 30~pre9）：
    * cmd >= SIOCDEVPRIVATE 的条目是"真实 ioctl"（父项），ioctl 号 = cmd；
    * cmd <  SIOCDEVPRIVATE 的条目是子命令：按 (set_args,get_args) 匹配一个 **name 为空** 的父项，
      实际 ioctl 号 = 父项 cmd，子命令号放在 `wrq.u.mode`（offset 0）。
  因此"可达 ioctl 集合" = 全部父项 cmd（0x8BE0..0x8BFF 范围内）。

用法：
  python tools/wlan_wext_table.py                # 打印 handler 表 + 父子映射摘要
  python tools/wlan_wext_table.py --csv          # 输出条目 CSV
"""
import argparse
import struct
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

KO = 'vendor_ko/qca_cld3_wlan.ko'
WE_PRIVATE = 0x4c70
WE_PRIVATE_N = 32
ARGS = 0x4d70
ARGS_N = 223
R_AARCH64_ABS64 = 257


class Ko:
    def __init__(self, path):
        self.f = open(path, 'rb')
        self.e = ELFFile(self.f)
        self.secs = list(self.e.iter_sections())
        self.byname = {s.name: s for s in self.secs}
        self.funcs = []
        for sym in self.byname['.symtab'].iter_symbols():
            if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size']:
                self.funcs.append((sym['st_value'], sym['st_size'], sym.name))
        self.funcs.sort()
        self.rel = {}
        for s in self.secs:
            if isinstance(s, RelocationSection):
                symtab = self.e.get_section(s['sh_link'])
                for r in s.iter_relocations():
                    if r['r_info_type'] != R_AARCH64_ABS64:
                        continue
                    sym = symtab.get_symbol(r['r_info_sym'])
                    shndx = sym['st_shndx']
                    sname = self.secs[shndx].name if isinstance(shndx, int) and shndx < len(self.secs) else str(shndx)
                    # 关键：若重定位引用的是具名函数符号（STT_FUNC），地址 = st_value + addend；
                    # 若引用节符号（.text/.rodata，st_value=0），地址 = addend。
                    addr = sym['st_value'] + r['r_addend'] if sym['st_info']['type'] == 'STT_FUNC' else r['r_addend']
                    self.rel[(s.name, r['r_offset'])] = (sname, addr)

    def func_at(self, addr):
        for v, sz, n in self.funcs:
            if v <= addr < v + sz:
                return n
        return '?+%#x' % addr

    def data(self, name):
        return self.byname[name].data()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', action='store_true')
    args = ap.parse_args(argv)
    k = Ko(KO)
    rodata = k.data('.rodata')
    print('== we_private (32 handlers, index i -> ioctl 0x%X+i) ==' % 0x8BE0)
    handlers = []
    for i in range(WE_PRIVATE_N):
        off = WE_PRIVATE + i * 8
        r = k.rel.get(('.rela.rodata', off))
        if r and r[0] == '.text':
            name = k.func_at(r[1])
        else:
            name = 'NULL' if int.from_bytes(rodata[off:off + 8], 'little') == 0 else '?'
        handlers.append(name)
        print('  [%2d] 0x%04X  %s' % (i, 0x8BE0 + i, name))
    print('\n== we_private_args (%d entries) ==' % ARGS_N)
    entries = []
    for i in range(ARGS_N):
        off = ARGS + i * 0x18
        cmd, seta, geta = struct.unpack_from('<IHH', rodata, off)
        nm = rodata[off + 8:off + 24].split(b'\x00')[0].decode('latin-1')
        entries.append({'i': i, 'cmd': cmd, 'set': seta, 'get': geta, 'name': nm})
    parents = [e for e in entries if e['cmd'] >= 0x89F0]
    subs = [e for e in entries if e['cmd'] < 0x89F0]
    print('parents (real ioctl): %d   sub-commands: %d' % (len(parents), len(subs)))
    for e in parents:
        print('  parent cmd=0x%04X set=0x%04X get=0x%04X name=%r' % (e['cmd'], e['set'], e['get'], e['name']))
    # pair subs to parents by (set,get) with empty name
    unmatched = 0
    print('\nsub-commands (id -> name -> parent):')
    for e in subs:
        cand = [p for p in parents if p['name'] == '' and p['set'] == e['set'] and p['get'] == e['get']]
        par = '0x%04X' % cand[0]['cmd'] if cand else 'UNMATCHED'
        if not cand:
            unmatched += 1
        print('  id=%3d %-16s set=0x%04X get=0x%04X -> %s' % (e['cmd'], e['name'], e['set'], e['get'], par))
    print('\nunmatched subs: %d' % unmatched)
    if args.csv:
        print('\ni,cmd,set,get,name,kind,parent')
        for e in entries:
            kind = 'parent' if e['cmd'] >= 0x89F0 else 'sub'
            par = ''
            if kind == 'sub':
                cand = [p for p in parents if p['name'] == '' and p['set'] == e['set'] and p['get'] == e['get']]
                par = '0x%04X' % cand[0]['cmd'] if cand else ''
            print('%d,0x%04X,0x%04X,0x%04X,%s,%s,%s' % (e['i'], e['cmd'], e['set'], e['get'], e['name'], kind, par))
    return 0


if __name__ == '__main__':
    sys.exit(main())
