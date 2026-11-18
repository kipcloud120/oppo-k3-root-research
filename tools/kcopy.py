#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kcopy.py — 扫描函数内的 copy_from_user / copy_to_user 调用，打印长度来源。

用法:
  python kcopy.py SYM [SYM...]        # 每个符号内所有拷贝点 + 前 10 条上下文
  python kcopy.py --list              # 列出被测符号是否解析成功
"""
import sys
import re
sys.path.insert(0, "tools")
from kfn import Kernel, _imm

COPY_FROM = ("__arch_copy_from_user", "copy_from_user", "_copy_from_user")
COPY_TO = ("__arch_copy_to_user", "copy_to_user", "_copy_to_user")


def fn_body(k, addr, limit=0x600):
    ins = k.disas(addr, limit)
    out = []
    for i in ins:
        out.append(i)
        if i.mnemonic == "ret":
            break
    return out


def describe(k, name):
    a = k.byname.get(name, (None,))[0]
    if not a:
        print("[skip] %s 未解析" % name)
        return
    ins = fn_body(k, a)
    print("\n===== %s @ 0x%x (%d insns) =====" % (name, a, len(ins)))
    idx = {i.address: n for n, i in enumerate(ins)}
    hits = 0
    for n, i in enumerate(ins):
        if i.mnemonic != "bl" or not i.operands or i.operands[0].type != 2:
            continue
        tgt = k.name_of(_imm(i))
        if tgt not in COPY_FROM + COPY_TO:
            continue
        hits += 1
        kind = "FROM_USER" if tgt in COPY_FROM else "TO_USER"
        print("  --- %s @0x%x -> %s" % (kind, i.address, tgt))
        for j in range(max(0, n - 10), n + 1):
            x = ins[j]
            print("      0x%08x  %-8s %s" % (x.address, x.mnemonic, x.op_str))
    if not hits:
        # 也许调用了拷贝包装函数
        calls = []
        for i in ins:
            if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2:
                calls.append(k.name_of(_imm(i)) or hex(_imm(i)))
        print("  (无直接拷贝；调用链: %s)" % ", ".join(dict.fromkeys(calls)))


def main():
    k = Kernel()
    for n in sys.argv[1:]:
        describe(k, n)


if __name__ == "__main__":
    main()
