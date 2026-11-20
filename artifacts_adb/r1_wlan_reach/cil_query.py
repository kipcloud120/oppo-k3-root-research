#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cil_query.py — 在 CIL 文本里做定向查询（跳过超长 typeattributeset 行）。

用法:
  python cil_query.py allow <substr> [<substr2> ...]   # 只匹配 "(allow ..." 行
  python cil_query.py grep  <regex>                    # 任意行，但截断到 400 字符
"""
import re
import sys

CIL = r'.build\sepolicy\vendor_sepolicy.cil'
PLAT = r'.build\sepolicy\plat_sepolicy.cil'
SYS = r'.build\sepolicy\system_ext_sepolicy.cil'


def lines(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        for i, l in enumerate(f, 1):
            yield i, l.rstrip('\n')


def main():
    mode = sys.argv[1]
    pats = sys.argv[2:]
    for path in (CIL, PLAT, SYS):
        try:
            it = lines(path)
        except FileNotFoundError:
            continue
        for i, l in it:
            if len(l) > 2000:
                continue
            if mode == 'allow':
                if not l.startswith('(allow '):
                    continue
                if not all(p in l for p in pats):
                    continue
            else:
                if not all(p in l for p in pats):
                    continue
            tag = path.split('\\')[-1]
            print('%s:%d: %s' % (tag, i, l[:400]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
