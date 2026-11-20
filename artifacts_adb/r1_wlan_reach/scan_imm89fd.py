#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_imm89fd.py — 快速、完备地判定 0x89fd 是否作为请求码出现在 AArch64 用户态/内核模块里。

判定方式（不依赖 capstone，只做位模式匹配）：
  1) movz/movk/movn wN|xN, #0x89fd 的 32-bit 指令编码：
       movz  {0x52800000, 0xD2800000}
       movk  {0x72800000, 0xF2800000}
       movn  {0x12800000, 0x92800000}
     条件 ((w & 0xFFE0001F) == base) and (((w >> 5) & 0xFFFF) == 0x89fd)
  2) 4 字节小端字面量 0x000089fd（表驱动请求码常见于 .data/.rodata）。
  3) 顺带统计 SIOCDEVPRIVATE(0x89f0) 的同类出现，用于“是否用了 WEXT private”对照。

用法: python scan_imm89fd.py <root...>
"""
import os
import struct
import sys

BASES = (0x52800000, 0xD2800000, 0x72800000, 0xF2800000, 0x12800000, 0x92800000)
MASK = 0xFFE0001F


def scan_file(path, want):
    hits = []
    try:
        if os.path.getsize(path) > 80_000_000:
            return hits
        data = open(path, 'rb').read()
    except OSError:
        return hits
    # 1) instruction encodings
    n = len(data) & ~3
    for off in range(0, n, 4):
        w = struct.unpack_from('<I', data, off)[0]
        if (w & MASK) in BASES and ((w >> 5) & 0xFFFF) == want:
            hits.append(('insn', off, w))
            if len(hits) > 40:
                return hits
    # 2) literal u32
    pat = struct.pack('<I', want)
    pos = data.find(pat)
    while pos >= 0:
        hits.append(('u32', pos, want))
        pos = data.find(pat, pos + 1)
        if len(hits) > 40:
            break
    return hits


def main():
    roots = sys.argv[1:] or ['.']
    total = 0
    for root in roots:
        for dp, dn, fn in os.walk(root):
            for f in fn:
                p = os.path.join(dp, f)
                for want, label in ((0x89fd, '0x89fd'), (0x89f0, '0x89f0/SIOCDEVPRIVATE')):
                    h = scan_file(p, want)
                    if h:
                        total += 1
                        print('%s  [%s]  %d hit(s)' % (p, label, len(h)))
                        for kind, off, val in h[:6]:
                            print('    %-4s @%#x  %#x' % (kind, off, val))
    print('files with hits:', total)


if __name__ == '__main__':
    main()
