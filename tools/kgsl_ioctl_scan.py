#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kgsl_ioctl_scan.py — KGSL ioctl 面首扫：每个 ioctl 内的用户态拷贝点 + 长度来源。

判据沿用 §25（diag 审计）的口径：
  对每个 `bl copy_from_user / __arch_copy_from_user / copy_to_user` 点，
  回溯 `w2`（长度）最后一次写：
    - `mov w2, #imm` / `orr w2, wzr, #imm`  ⇒ CONST（记下立即数，人工核对是否 ≤ 目标对象）
    - 其他（ldr / mov reg / add）⇒ REG（需要人工复盘，风险高）
输出：每个 ioctl 一行摘要 + 明细（REG 优先）。

用法: python tools/kgsl_ioctl_scan.py [--detail] [--only PAT]
"""
import argparse
import re
import sys

sys.path.insert(0, 'tools')
from kfn import Kernel  # noqa: E402

COPY = {'copy_from_user', '__arch_copy_from_user', '_copy_from_user',
        'copy_to_user', '__arch_copy_to_user', '_copy_to_user'}


def len_source(ins, idx):
    """回溯 idx 之前 w2 的最后一次写。返回 ('CONST', imm) / ('REG', ins) / (None, None)。"""
    for j in range(idx - 1, max(-1, idx - 14), -1):
        i = ins[j]
        if i.op_str.startswith('w2,') or i.op_str.startswith('w2 ') or i.op_str.startswith('x2,'):
            if i.mnemonic in ('mov', 'movz'):
                m = re.search(r'#(0x[0-9a-fA-F]+|\d+)', i.op_str)
                if m:
                    return 'CONST', int(m.group(1), 0)
                return 'REG', i
            if i.mnemonic in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'add', 'sub', 'and', 'orr', 'movk'):
                return 'REG', i
            if i.mnemonic in ('mov',):
                return 'REG', i
        if i.mnemonic in ('bl', 'ret'):
            break
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--detail', action='store_true')
    ap.add_argument('--only', default='kgsl_ioctl')
    args = ap.parse_args()
    k = Kernel()
    names = sorted(n for n in k.byname if n.startswith(args.only))
    print('== KGSL ioctl 首扫：%d 个入口 ==' % len(names))
    print('%-46s %4s %5s %5s  %s' % ('ioctl', 'copy', 'CONST', 'REG', '备注'))
    tot_c = tot_const = tot_reg = 0
    risky = []
    for n in names:
        addr, size = k.byname[n]
        ins = k.disas(addr, size)
        sites = []
        for i, x in enumerate(ins):
            if x.mnemonic != 'bl':
                continue
            # 解析调用目标
            tgt = None
            m = re.match(r'#(0x[0-9a-f]+)', x.op_str)
            if m:
                t = int(m.group(1), 16)
                if t in k.byaddr:
                    tgt = k.byaddr[t][0] if isinstance(k.byaddr[t], tuple) else k.byaddr[t]
            if tgt not in COPY:
                continue
            kind, val = len_source(ins, i)
            sites.append((x.address, tgt, kind, val))
        if not sites:
            continue
        c = sum(1 for s in sites if s[2] == 'CONST')
        r = sum(1 for s in sites if s[2] == 'REG')
        todo = len(sites) - c - r
        note = '' if r == 0 else 'REG 需复盘'
        print('%-46s %4d %5d %5d  %s' % (n, len(sites), c, r, note))
        tot_c += len(sites)
        tot_const += c
        tot_reg += r
        if r:
            risky.append(n)
        if args.detail:
            for a, t, kind, val in sites:
                if kind == 'CONST':
                    print('      0x%x  %-22s CONST len=%d' % (a, t, val))
                elif kind == 'REG':
                    print('      0x%x  %-22s REG   <- %s %s' % (a, t, val.mnemonic, val.op_str))
                else:
                    print('      0x%x  %-22s ?     （未回溯到 w2 写入）' % (a, t))
    print('\n== 合计：拷贝点 %d（CONST %d / REG %d）==' % (tot_c, tot_const, tot_reg))
    if risky:
        print('REG 类入口（需人工复盘）：')
        for n in risky:
            print('  -', n)
    return 0


if __name__ == '__main__':
    sys.exit(main())
