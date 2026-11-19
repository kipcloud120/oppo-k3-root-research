#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ko_fn.py — 厂商 .ko（ET_REL）函数级反汇编 + 调用/字符串解析。

内核镜像是 ET_EXEC，地址即符号值；模块是 ET_REL，函数地址为节内偏移，
调用与数据引用都要靠 `.rela.text` 重定位才能解析成名字。本工具做三件事：
  1) 按符号表取函数边界（st_size），反汇编 `.text` 对应区间；
  2) 把 `bl` 目标按 R_AARCH64_CALL26/JUMP26 重定位解析为符号名；
  3) 把 adrp+add 组合按 ADR_PREL_PG_HI21/ADD_ABS_LO12_NC 解析为 .rodata 字符串。

用法：
  python tools/ko_fn.py --list PAT
  python tools/ko_fn.py SYM [--calls] [--grep PAT] [--max N]
"""
import argparse
import re
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

KO_DEFAULT = 'vendor_ko/qca_cld3_wlan.ko'
R_AARCH64_CALL26 = 283
R_AARCH64_JUMP26 = 282
R_AARCH64_ADR_PREL_PG_HI21 = 275
R_AARCH64_ADD_ABS_LO12_NC = 277


class Ko:
    def __init__(self, path):
        self.f = open(path, 'rb')
        self.elf = ELFFile(self.f)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = False
        self.text = b''
        self.syms = {}          # addr -> (name, size)
        self.by_name = {}
        self.calls = {}         # text offset -> symbol name
        self.strrefs = {}       # text offset(adrp) -> rodata addr
        self.rodata = b''
        self.rodata_off = 0
        for sec in self.elf.iter_sections():
            if sec.name == '.text':
                self.text = sec.data()
            elif sec.name == '.rodata':
                self.rodata = sec.data()
                self.rodata_off = sec['sh_offset']
        for sec in self.elf.iter_sections():
            if sec.name == '.symtab':
                for s in sec.iter_symbols():
                    if s.name and s['st_info']['type'] == 'STT_FUNC' and s['st_size']:
                        self.syms[s['st_value']] = (s.name, s['st_size'])
                        self.by_name[s.name] = (s['st_value'], s['st_size'])
        self._load_relocs()

    def _load_relocs(self):
        for sec in self.elf.iter_sections():
            if not isinstance(sec, RelocationSection) or sec.name != '.rela.text':
                continue
            symtab = self.elf.get_section(sec['sh_link'])
            for r in sec.iter_relocations():
                off = r['r_offset']
                typ = r['r_info_type']
                sym = symtab.get_symbol(r['r_info_sym'])
                nm = sym.name or ('.rodata+0x%x' % sym['st_value'])
                if typ in (R_AARCH64_CALL26, R_AARCH64_JUMP26):
                    self.calls[off] = nm
                elif typ == R_AARCH64_ADR_PREL_PG_HI21:
                    self.strrefs[off] = nm


    def callers(self, target):
        """返回调用 target 的函数名列表（按 CALL26 重定位统计）。"""
        rows = []
        for off, nm in self.calls.items():
            if nm != target:
                continue
            best = None
            for a, (n, sz) in self.syms.items():
                if a <= off < a + sz:
                    best = (a, n, sz)
                    break
            rows.append((best[1] if best else '?', off - (best[0] if best else 0)))
        return rows

    def copy_sites(self, addr, size, names, ctx=10):
        """列出函数内对指定被调用者的调用点 + 前 ctx 条指令上下文。"""
        ins = self.disas(addr, size)
        out = []
        for i, ins_i in enumerate(ins):
            t = self.calls.get(ins_i.address)
            if t not in names:
                continue
            lo = max(0, i - ctx)
            out.append('---- %s @0x%06x (call #%d) ----' % (t, ins_i.address, i))
            for j in ins[lo:i + 1]:
                line = '0x%06x  %-8s %s' % (j.address, j.mnemonic, j.op_str)
                if j.address in self.calls:
                    line += '   ; -> %s' % self.calls[j.address]
                out.append(line)
        return out

    def cstr_at_rodata(self, addr):
        if not (0 <= addr < len(self.rodata)):
            return None
        end = self.rodata.find(b'\x00', addr)
        if end < 0:
            return None
        s = self.rodata[addr:end]
        try:
            t = s.decode('ascii')
        except UnicodeDecodeError:
            return None
        return t if t and all(32 <= c < 127 for c in s) else None

    def disas(self, addr, size):
        return list(self.md.disasm(self.text[addr:addr + size], addr))

    def annotate(self, addr, size):
        out = []
        pend = {}
        for i in self.disas(addr, size):
            line = '0x%06x  %-8s %s' % (i.address, i.mnemonic, i.op_str)
            if i.address in self.calls:
                line += '        ; -> %s' % self.calls[i.address]
            if i.address in self.strrefs:
                name = self.strrefs[i.address]
                line += '        ; &%s' % name
                pend[i.op_str.split(',')[0]] = name
            if i.mnemonic == 'add' and pend:
                parts = [p.strip() for p in i.op_str.split(',')]
                if len(parts) == 3 and parts[1] in pend and parts[2].startswith('#0x'):
                    base = pend[parts[1]]
                    m = re.match(r'(\.rodata|\.data|\.bss)(\+0x([0-9a-f]+))?$', base)
                    if m and m.group(1) == '.rodata':
                        s = self.cstr_at_rodata(int(m.group(3) or 0, 16) + int(parts[2][1:], 16))
                        if s:
                            line += '   ; "%s"' % s[:60]
            out.append(line)
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('sym', nargs='?')
    ap.add_argument('--ko', default=KO_DEFAULT)
    ap.add_argument('--list', dest='pat', help='按正则列函数')
    ap.add_argument('--calls', action='store_true', help='只列调用目标')
    ap.add_argument('--grep', help='过滤指令行')
    ap.add_argument('--max', type=int, default=0, help='最大输出行数')
    ap.add_argument('--callers', help='列出调用该符号的所有函数')
    ap.add_argument('--copy-sites', dest='copy_sites', action='store_true',
                    help='列出函数内 memcpy/strlcpy/sscanf 等调用点及上下文')
    args = ap.parse_args()
    k = Ko(args.ko)
    if args.callers:
        rows = k.callers(args.callers)
        print('callers of %s: %d' % (args.callers, len(rows)))
        for n, off in rows[:args.max or 200]:
            print('  %-52s +0x%x' % (n, off))
        return 0
    if args.pat:
        rx = re.compile(args.pat, re.I)
        rows = sorted(((sz, n) for (n, (v, sz)) in k.by_name.items() if rx.search(n)), reverse=True)
        print('matches: %d' % len(rows))
        for sz, n in rows[:args.max or 60]:
            print('  %8d  %s' % (sz, n))
        return 0
    if not args.sym or args.sym not in k.by_name:
        print('symbol not found', file=sys.stderr)
        return 2
    addr, size = k.by_name[args.sym]
    if args.copy_sites:
        names = {'memcpy', '__memcpy', 'memmove', 'strlcpy', 'strscpy', 'strncpy',
                 'sscanf', 'qdf_mem_copy', 'qdf_mem_multi_page_memcpy',
                 'strnlen', 'strlen', 'qdf_str_len', 'qdf_str_cmp'}
        print("\n".join(k.copy_sites(addr, size, names)))
        return 0
    lines = k.annotate(addr, size)
    if args.calls:
        for l in lines:
            if '; -> ' in l:
                print(l)
        return 0
    if args.grep:
        lines = [l for l in lines if args.grep in l]
    if args.max:
        lines = lines[:args.max]
    print('\n'.join(lines))
    return 0


if __name__ == '__main__':
    sys.exit(main())
