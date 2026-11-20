#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_ioctl_const.py — 在用户态 ELF 中定位 `ioctl(fd, cmd, ...)` 的 cmd 常量。

粗筛两层：
  1) 线性反汇编，记录 `mov[w] wN, #0x8xxx` / `movz wN, #0x89f1` 等立即数；
  2) 对每个候选地址，打印前后 12 条指令，便于人工确认哪条是 ioctl 的 request 参数。

用法：python tools/scan_ioctl_const.py <elf> [--vals 0x89f0,0x89f1,0x89fd] [--max 40]
"""
import argparse
import re
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('elf')
    ap.add_argument('--vals', default='0x89f0,0x89f1,0x89fd,0x8be0')
    ap.add_argument('--max', type=int, default=40)
    ap.add_argument('--ctx', type=int, default=10)
    args = ap.parse_args(argv)
    wanted = {int(x, 16) for x in args.vals.split(',')}
    with open(args.elf, 'rb') as f:
        e = ELFFile(f)
        secs = {s.name: s for s in e.iter_sections()}
        sec = secs['.text']
        text = sec.data()
        base = sec['sh_addr']
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    ins = list(md.disasm(text, base))
    hits = []
    for i, x in enumerate(ins):
        if x.mnemonic not in ('mov', 'movz', 'movk', 'movn', 'orr'):
            continue
        m = re.search(r'#(0x[0-9a-f]+)$', x.op_str)
        if not m:
            continue
        if int(m.group(1), 16) in wanted:
            hits.append(i)
    print('hits: %d' % len(hits))
    for k, i in enumerate(hits[:args.max]):
        print('---- hit %d @0x%x ----' % (k, ins[i].address))
        for j in ins[max(0, i - args.ctx):i + args.ctx]:
            print('  0x%06x  %-8s %s' % (j.address, j.mnemonic, j.op_str))
    return 0


if __name__ == '__main__':
    sys.exit(main())
