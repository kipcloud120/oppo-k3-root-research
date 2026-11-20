#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wlan_cmd_table.py — 还原 qcacld `hdd_driver_command` 的 98 项命令表（纯离线）。

原理：`hdd_driver_command`（0x38320）用 MOVW_UABS_G0..G3 把表基址装进 x8
（四条 `.rela.text` 重定位均指向 `.rodata`，addend 0x2bb8），随后 `add x28,x8,#0x10`。
表项布局 0x18 字节：{char *name @+0; int (*handler) @+8; u8 flag @+0x10; pad}。
名称/处理器指针由 `.rela.rodata` 的 R_AARCH64_ABS64(257) 重定位给出：
  - 名称：符号为 `.rodata.str1.1` 节符号 + addend ⇒ 字符串偏移；
  - 处理器：符号为 `.text` 节符号 + addend ⇒ 函数地址（按 st_value 归并到符号）。

用法：
  python tools/wlan_cmd_table.py
  python tools/wlan_cmd_table.py --csv > artifacts_adb/r1_wlan_reach/cmd_table.csv
"""
import argparse
import json
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

KO_DEFAULT = 'vendor_ko/qca_cld3_wlan.ko'
TABLE_RODATA_OFF = 0x2bb8
ENTRY = 0x18
COUNT = 98
R_AARCH64_ABS64 = 257


def cstr(data, off, maxlen=200):
    if not (0 <= off < len(data)):
        return None
    end = data.find(b'\x00', off)
    if end < 0 or end - off > maxlen:
        return None
    try:
        s = data[off:end].decode('ascii')
    except UnicodeDecodeError:
        return None
    return s


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
        # relocations with section+addend
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
                    self.rel[(s.name, r['r_offset'])] = (sname, r['r_addend'])

    def sec_data(self, name):
        return self.byname[name].data()

    def func_name(self, addr):
        for v, sz, n in self.funcs:
            if v <= addr < v + sz:
                return n
        return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--ko', default=KO_DEFAULT)
    ap.add_argument('--csv', action='store_true')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args(argv)
    k = Ko(args.ko)
    rows = []
    for i in range(COUNT):
        base = TABLE_RODATA_OFF + i * ENTRY
        rel_n = k.rel.get(('.rela.rodata', base))
        rel_h = k.rel.get(('.rela.rodata', base + 8))
        if not rel_n or not rel_h:
            rows.append({'i': i, 'name': None, 'handler': None, 'flag': None, 'hsize': 0})
            continue
        sn, an = rel_n
        sh, ah = rel_h
        name = cstr(k.sec_data(sn), an) if sn in k.byname else None
        handler = k.func_name(ah) if sh == '.text' else None
        flag = int.from_bytes(k.sec_data('.rodata')[base + 0x10:base + 0x14], 'little')
        hsize = 0
        if handler:
            for v, sz, n in k.funcs:
                if n == handler:
                    hsize = sz
                    break
        rows.append({'i': i, 'name': name, 'handler': handler, 'handler_addr': ah if sh == '.text' else None,
                     'flag': flag, 'hsize': hsize})
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=1))
        return 0
    if args.csv:
        print('i,name,handler,flag,handler_size')
        for r in rows:
            print('%d,%s,%s,%d,%d' % (r['i'], r['name'] or '', r['handler'] or '', r['flag'] or 0, r['hsize']))
        return 0
    print('%-3s %-38s %-52s %-5s %s' % ('#', 'name', 'handler', 'flag', 'size'))
    for r in rows:
        print('%-3d %-38s %-52s %-5s %s' % (r['i'], r['name'], r['handler'], r['flag'], r['hsize']))
    missing = [r for r in rows if not r['name'] or not r['handler']]
    print('\nentries=%d  unresolved=%d' % (len(rows), len(missing)), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
