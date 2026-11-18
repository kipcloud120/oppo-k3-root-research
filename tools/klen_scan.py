#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""klen_scan.py — 全量扫描 diag* 函数内的用户态拷贝，判定长度来源是常量还是寄存器。

判据（对每条 `bl copy_from_user/copy_to_user` 向前回溯 20 条）：
  - 最后一次写 w2/x2 是 `mov w2,#imm` / `mov x2,#imm` / `movz` ⇒ CONST
  - 否则 ⇒ REG（长度来自内存/计算，需人工复核）

用法: python klen_scan.py [正则]
"""
import sys
import re
sys.path.insert(0, "tools")
from kfn import Kernel, _imm

CF = ("__arch_copy_from_user", "copy_from_user", "_copy_from_user",
      "__arch_copy_to_user", "copy_to_user", "_copy_to_user")


def last_write_x2(ins, n):
    for j in range(n - 1, max(-1, n - 21), -1):
        x = ins[j]
        ops = x.op_str
        if not re.search(r"\b[wx]2\b", ops):
            continue
        # 目标操作数必须是 w2/x2
        dst = ops.split(",")[0].strip()
        if dst in ("w2", "x2"):
            if x.mnemonic in ("mov", "movz") and "#" in ops:
                return ("CONST", x)
            if x.mnemonic == "mov" and ops.split(",")[1].strip() in ("wzr", "xzr"):
                return ("ZERO", x)
            return ("REG", x)
        # stp/str 的 dst 不是写
    return ("UNKNOWN", None)


def main():
    pat = sys.argv[1] if len(sys.argv) > 1 else r"^diag"
    rx = re.compile(pat, re.I)
    k = Kernel()
    names = sorted(n for n in k.byname if rx.search(n))
    ndone = 0
    for name in names:
        addr = k.byname[name][0]
        try:
            ins = k.disas(addr, 0x800)
        except Exception:
            continue
        ins = ins[:next((i for i, x in enumerate(ins) if x.mnemonic == "ret"), len(ins)) + 1]
        rows = []
        for n, i in enumerate(ins):
            if i.mnemonic != "bl" or not i.operands or i.operands[0].type != 2:
                continue
            tgt = k.name_of(_imm(i))
            if tgt not in CF:
                continue
            kind = "FROM" if "from_user" in tgt else "TO"
            cls, w = last_write_x2(ins, n)
            rows.append((kind, cls, w, i.address))
        if not rows:
            continue
        ndone += 1
        for kind, cls, w, a in rows:
            detail = ""
            if w is not None:
                detail = "len<-%s %s" % (w.mnemonic, w.op_str)
            flag = "  <<< 复核" if cls == "REG" else ""
            print("%-42s %-4s %-7s @0x%08x  %s%s" % (name, kind, cls, a, detail, flag))
    print("# 含拷贝的函数数:", ndone, " 扫描符号数:", len(names))


if __name__ == "__main__":
    main()
