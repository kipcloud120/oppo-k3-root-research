#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wlan_wext_scan.py — qca_cld3_wlan.ko WEXT 私有 ioctl handler 静态审计辅助（纯离线）。

这个 .ko 是 ET_REL/AArch64，但编译器**不用** adrp/add 引用数据，改用
`movz/movk` 绝对地址链（.rela.text 里只有 R_AARCH64_MOVW_UABS_G0_NC..G3_NC=264/266/268/269
和 CALL26=283）。因此 tools/ko_fn.py 的 ADRP 字符串注解在此文件上完全失效。
本工具做完整的重定位解析，并提供：

  --handlers            打印 we_private[0..31]（ioctl 0x8BE0+i）-> 函数
  --table SEC+OFF+N     转储函数指针表（.rela 解析为符号名）
  --fn SYM              带注解反汇编（调用名 / 绝对数据地址 / 字符串 / 指针表）
  --relocs SYM          只列该函数内所有重定位（目标 + 类型 + 指令）
  --callers SYM         谁调用它（CALL26）
  --list PAT            按正则列符号

用法示例：
  python tools/wlan_wext_scan.py --handlers
  python tools/wlan_wext_scan.py --table .rodata+0x6280+101
  python tools/wlan_wext_scan.py --fn iw_set_packet_filter_params
  python tools/wlan_wext_scan.py --relocs iw_set_two_ints_getnone
"""
import argparse
import re
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

KO_DEFAULT = 'vendor_ko/qca_cld3_wlan.ko'

R_ABS64 = 257
R_MOVW_UABS_G0 = 264
R_MOVW_UABS_G0_NC = 265
R_MOVW_UABS_G1 = 266
R_MOVW_UABS_G1_NC = 267
R_MOVW_UABS_G2 = 268
R_MOVW_UABS_G2_NC = 269
R_MOVW_UABS_G3 = 270
R_JUMP26 = 282
R_CALL26 = 283
MOVW_TYPES = {264, 265, 266, 267, 268, 269, 270}
BRANCH_TYPES = {R_CALL26, R_JUMP26}
HW_ADDR = 0x8BE0   # SIOCIWFIRSTPRIV


class Ko:
    def __init__(self, path):
        self.f = open(path, 'rb')
        self.elf = ELFFile(self.f)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = False
        self.secs = list(self.elf.iter_sections())
        self.byname = {s.name: s for s in self.secs}
        self.data = {s.name: s.data() for s in self.secs
                     if s['sh_type'] in ('SHT_PROGBITS', 'SHT_NOBITS') and s['sh_size']}
        self.funcs = []          # (addr, size, name) in .text
        self.fn_by_name = {}
        text_ndx = self.sec_index('.text')
        for sec in self.elf.iter_sections():
            if sec.name == '.symtab':
                for s in sec.iter_symbols():
                    # 只看 .text 段内的函数：.exit.text 的符号 st_value 也是 0，
                    # 不加这个过滤会把 .text 前 0x388 字节全标成 cleanup_module。
                    if not (s.name and s['st_info']['type'] == 'STT_FUNC'
                            and s['st_size'] and s['st_shndx'] == text_ndx):
                        continue
                    self.funcs.append((s['st_value'], s['st_size'], s.name))
                    self.fn_by_name[s.name] = (s['st_value'], s['st_size'])
        self.funcs.sort()
        # (secname, off) -> (type, symname_or_sectionref, addend)
        self.relocs = {}
        for sec in self.secs:
            if not isinstance(sec, RelocationSection):
                continue
            tgt = sec.name[len('.rela'):] if sec.name.startswith('.rela') else sec.name
            symtab = self.elf.get_section(sec['sh_link'])
            for r in sec.iter_relocations():
                sym = symtab.get_symbol(r['r_info_sym'])
                self.relocs[(tgt, r['r_offset'])] = (
                    r['r_info_type'], sym, r['r_addend'])

    # ---------- 基础解析 ----------
    def sec_index(self, name):
        for i, s in enumerate(self.secs):
            if s.name == name:
                return i
        return None

    def sym_target(self, sym, addend):
        """(secname, offset) —— ET_REL 里 st_value 是节内偏移；节符号 st_value=0。"""
        shndx = sym['st_shndx']
        if isinstance(shndx, int) and shndx < len(self.secs):
            sname = self.secs[shndx].name
            return sname, sym['st_value'] + addend
        return str(shndx), addend

    def resolve(self, secname, off):
        """返回 (kind, label, sec, off) 或 None。kind: call/data/imm"""
        r = self.relocs.get((secname, off))
        if not r:
            return None
        typ, sym, addend = r
        tsec, toff = self.sym_target(sym, addend)
        label = sym.name or ('%s+0x%x' % (tsec, toff))
        kind = 'call' if typ in BRANCH_TYPES else ('imm' if typ in MOVW_TYPES
                                                   else 'data')
        return kind, label, tsec, toff

    def func_at(self, addr):
        for v, sz, n in self.funcs:
            if v <= addr < v + sz:
                return n
        return None

    def cstr(self, secname, off):
        b = self.data.get(secname)
        if not b or not (0 <= off < len(b)):
            return None
        e = b.find(b'\x00', off)
        if e < 0 or e - off > 200:
            return None
        s = b[off:e]
        if not s or not all(32 <= c < 127 for c in s):
            return None
        return s.decode('ascii')

    def u64(self, secname, off):
        b = self.data.get(secname)
        if not b or off + 8 > len(b):
            return None
        return int.from_bytes(b[off:off + 8], 'little')

    def u32(self, secname, off):
        b = self.data.get(secname)
        if not b or off + 4 > len(b):
            return None
        return int.from_bytes(b[off:off + 4], 'little')

    # ---------- 指针表 ----------
    def ptr_table(self, secname, off, count):
        rows = []
        for i in range(count):
            o = off + i * 8
            r = self.resolve(secname, o)
            if r:
                tsec, toff = r[2], r[3]
                nm = self.func_at(toff) if tsec == '.text' else None
                rows.append((i, nm or '%s+0x%x' % (tsec, toff), r[1]))
            else:
                v = self.u64(secname, o)
                rows.append((i, 'NULL' if v == 0 else '0x%x' % v, ''))
        return rows

    # ---------- 反汇编 + 注解 ----------
    def annotate(self, addr, size):
        ins = list(self.md.disasm(self.data['.text'][addr:addr + size], addr))
        out = []
        movw_accum = {}
        for i in ins:
            line = '0x%06x  %-8s %s' % (i.address, i.mnemonic, i.op_str)
            r = self.resolve('.text', i.address)
            if r:
                kind, label, tsec, toff = r
                if kind == 'call':
                    nm = self.func_at(toff) if tsec == '.text' else None
                    line += '        ; -> %s' % (nm or label)
                elif kind == 'imm':
                    # movz/movk 链：把 (sec,off) 记到目标寄存器，后续 add 用
                    dst = i.op_str.split(',')[0].strip()
                    movw_accum[dst] = (tsec, toff)
                    line += '        ; = %s+0x%x' % (tsec, toff) if tsec else ''
                    s = self.cstr(tsec, toff)
                    if s:
                        line += '   ; "%s"' % s[:60]
                else:
                    line += '        ; @%s' % label
            # 指针表提示：ldr xN,[xM,xK,lsl #3] 且 xM 是刚加载的绝对地址
            if i.mnemonic == 'ldr' and 'lsl #3' in i.op_str:
                m = re.match(r'(\w+), \[(\w+), (\w+), lsl #3\]', i.op_str)
                if m and m.group(2) in movw_accum:
                    tsec, toff = movw_accum[m.group(2)]
                    line += '        ; fnptr-table @%s+0x%x' % (tsec, toff)
            out.append(line)
        return out

    def relocs_in(self, addr, size):
        rows = []
        for (secname, off), (typ, sym, addend) in sorted(self.relocs.items(),
                                                         key=lambda kv: kv[0][1]):
            if secname != '.text' or not (addr <= off < addr + size):
                continue
            tsec, toff = self.sym_target(sym, addend)
            nm = self.func_at(toff) if tsec == '.text' else None
            rows.append((off, typ, sym.name or '%s+0x%x' % (tsec, toff),
                         nm or '%s+0x%x' % (tsec, toff)))
        return rows

    def callers(self, target):
        rows = []
        for (secname, off), (typ, sym, addend) in self.relocs.items():
            if secname != '.text' or typ not in BRANCH_TYPES:
                continue
            tsec, toff = self.sym_target(sym, addend)
            if sym.name != target:
                continue
            owner = self.func_at(off)
            rows.append((owner or '?', off))
        return rows


def parse_table(spec):
    # ".rodata+0x6280+101"
    m = re.match(r'^([.\w]+)\+0x([0-9a-fA-F]+)\+(\d+)$', spec)
    if not m:
        raise SystemExit('table spec 形如 .rodata+0x6280+101')
    return m.group(1), int(m.group(2), 16), int(m.group(3))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--ko', default=KO_DEFAULT)
    ap.add_argument('--handlers', action='store_true')
    ap.add_argument('--table')
    ap.add_argument('--fn')
    ap.add_argument('--relocs')
    ap.add_argument('--callers')
    ap.add_argument('--list', dest='pat')
    ap.add_argument('--max', type=int, default=0)
    args = ap.parse_args(argv)
    k = Ko(args.ko)

    if args.handlers:
        print('== we_private @ .rodata+0x4c70 (32 entries; i -> ioctl 0x%X+i) ==' % HW_ADDR)
        for i, nm, raw in k.ptr_table('.rodata', 0x4c70, 32):
            print('  [%2d] 0x%04X  %-40s %s' % (i, HW_ADDR + i, nm, raw))
        return 0
    if args.table:
        sec, off, n = parse_table(args.table)
        print('== table %s+0x%x, %d entries ==' % (sec, off, n))
        for i, nm, raw in k.ptr_table(sec, off, n):
            print('  [%3d] %-44s %s' % (i, nm, raw))
        return 0
    if args.callers:
        rows = k.callers(args.callers)
        print('callers of %s: %d' % (args.callers, len(rows)))
        for nm, off in rows:
            print('  %-52s +0x%x' % (nm, off - k.fn_by_name.get(nm, (0, 0))[0]))
        return 0
    if args.pat:
        rx = re.compile(args.pat, re.I)
        rows = sorted(((sz, n) for (n, (v, sz)) in k.fn_by_name.items()
                       if rx.search(n)), reverse=True)
        print('matches: %d' % len(rows))
        for sz, n in rows[:args.max or 100]:
            print('  %8d  0x%06x  %s' % (sz, k.fn_by_name[n][0], n))
        return 0
    sym = args.fn or args.relocs
    if not sym:
        ap.print_help()
        return 2
    if sym not in k.fn_by_name:
        print('symbol not found: %s' % sym, file=sys.stderr)
        return 2
    addr, size = k.fn_by_name[sym]
    if args.relocs:
        print('== relocs in %s (0x%x..0x%x) ==' % (sym, addr, addr + size))
        for off, typ, label, pretty in k.relocs_in(addr, size):
            print('  +0x%-6x type=%-3d %-28s -> %s' % (off - addr, typ, label, pretty))
        return 0
    print('== %s @0x%x size=0x%x ==' % (sym, addr, size))
    lines = k.annotate(addr, size)
    print('\n'.join(lines[:args.max] if args.max else lines))
    return 0


if __name__ == '__main__':
    sys.exit(main())
