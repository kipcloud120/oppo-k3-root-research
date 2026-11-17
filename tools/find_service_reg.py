#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在 dex 中定位「谁注册/引用了某个 binder 服务名」——回答"这个服务名由哪个类注册、
由哪个 onTransact 分派、有无 `getCallingUid`/权限检查"。

本机 framework dex 带 hiddenapi 数据，androguard 4.1.4 解析该 map item 时会抛
ValueError（`DomapiApiFlag(flag>>3)` 越界）。这里把该项解析打桩——它与本项目要看的
class / method / 指令流无关。

用法：
  python tools/find_service_reg.py <dex> <service_name>
"""
import sys

from loguru import logger

logger.remove()

import androguard.core.dex as dx


def _stub_hiddenapi():
    def _init(self, buff, cm):
        self.CM = cm
        self.items = []

    def _parse(self):
        pass

    dx.HiddenApiClassDataItem.__init__ = _init
    dx.HiddenApiClassDataItem.parse = _parse


def main():
    path, needle = sys.argv[1], sys.argv[2]
    global WIN
    WIN = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    _stub_hiddenapi()
    d = dx.DEX(open(path, "rb").read())
    hits = 0
    for c in d.get_classes():
        cn = c.get_name()
        for m in c.get_methods():
            code = m.get_code()
            if not code:
                continue
            ins = [i.get_output() or "" for i in code.get_bc().get_instructions()]
            if not any(needle in l for l in ins):
                continue
            hits += 1
            print("=" * 88)
            print(f"CLASS : {cn}")
            print(f"METHOD: {m.get_name()}{m.get_descriptor()}  ({len(ins)} insns)")
            idxs = [i for i, l in enumerate(ins) if needle in l]
            shown = set()
            for k in idxs:
                for j in range(max(0, k - WIN), min(len(ins), k + WIN + 1)):
                    shown.add(j)
            for j in sorted(shown):
                l = ins[j]
                mark = "   <<< string" if needle in l else ""
                print(f"   [{j:4d}] {l}{mark}")
            if len(shown) < len(ins):
                print(f"   ... ({len(ins) - len(shown)} insns unrelated, suppressed)")
    if not hits:
        print(f"[no hit] {needle} in {path}")
    else:
        print(f"\n[total] {hits} method(s)")


if __name__ == "__main__":
    main()
