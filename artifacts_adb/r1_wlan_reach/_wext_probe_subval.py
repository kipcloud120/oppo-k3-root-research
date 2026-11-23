# -*- coding: utf-8 -*-
"""_wext_probe_subval.py — 0x8BE0 子命令 handler 的第二参数（value）用途摘要。

（中间产物生成器，不属于交付工具；交付工具是 tools/wlan_wext_subcmd.py）

子命令 handler 由 `.rodata+0x6280[sub_cmd]` 给出，签名 exp(adapter=x0, value=w1)。
本探针把每个目标的 movz/movk 噪声过滤掉，只保留：
  * 所有分支/调用指令（bl / br / cbz / tbz …）
  * 所有提到 w1/x1/w2/x2/w3/x3 的指令（value 及其去向）
  * 所有寄存器索引寻址 `[xN, xM]`（"value 当索引"的形态）
输出用于人工判定"value 是否被当长度/索引"。
"""
import re
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

sys.path.insert(0, 'tools')
from wlan_wext_scan import Ko

NOISE = ('movz', 'movk')


def dump(k, addr, size, tag):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    out = []
    for i in md.disasm(k.data['.text'][addr:addr + size], addr):
        mn, ops = i.mnemonic, i.op_str
        if mn in NOISE:
            continue
        keep = False
        if mn in ('bl', 'blr', 'b', 'br', 'cbz', 'cbnz', 'tbz', 'tbnz'):
            keep = True
        if re.search(r'\b[wx][123]\b', ops):
            keep = True
        idx = re.search(r'\[[^\[\]]*,\s*x\d+\s*\]', ops) and 'lsl' not in ops
        if idx:
            keep = True
        if not keep:
            continue
        out.append('    0x%06x %-7s %-44s%s' % (i.address, mn, ops,
                                                '   <== REG-INDEXED' if idx else ''))
    print('=== %s 0x%06x size=%d' % (tag, addr, size))
    print('\n'.join(out))


def main():
    k = Ko('vendor_ko/qca_cld3_wlan.ko')
    for i, nm, raw in k.ptr_table('.rodata', 0x6280, 101):
        if nm == 'NULL':
            continue
        r = k.resolve('.rodata', 0x6280 + i * 8)
        toff = r[3]
        size = 0
        for v, sz, n in k.funcs:
            if v <= toff < v + sz:
                size, nm = sz, n
                break
        dump(k, toff, size, '[%3d] %s' % (i, nm))


if __name__ == '__main__':
    main()
