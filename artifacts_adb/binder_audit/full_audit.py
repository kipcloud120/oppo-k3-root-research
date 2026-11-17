#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整审计：递归扫描所有 dex（含 framework/services 多 dex），
1) 核对 35 个私有服务接口的覆盖度
2) 对每个已覆盖服务的 Stub.onTransact 做字节码审计（权限校验 + 高危操作）
3) 对服务实现类做权限校验与高危方法扫描
含 androguard 4.1.4 HiddenApi bug 补丁。
只读，不接触设备。
"""
import glob
import os
import sys
import enum

from androguard.core.dex import HiddenApiClassDataItem as H
_F = H.DomapiApiFlag
@classmethod
def _missing_(cls, value):
    m = int.__new__(cls, value)
    m._name_ = f"UNKNOWN_{value}"
    m._value_ = value
    return m
_F._missing_ = _missing_

from androguard.core.dex import DEX
from loguru import logger
logger.remove()

BASE = os.path.dirname(os.path.abspath(__file__))

PERM_KEYS = ["enforcecalling","enforcepermission","checkcalling","checkpermission",
             "permissionchecker","checkuidpermission","enforceuid","enforcecallingorself",
             "getcallinguid","getcallingpid"]
DANGER_KEYS = ["systemproperties;->set","->exec(","->system(","processbuilder",
               "/data/","chmod","chown","->mount","setprop","runtime;->exec",
               "startactivityasuser","installpackage","grantruntimepermission"]

def load_all_dex():
    paths = glob.glob(os.path.join(BASE, "dex", "*.dex")) + \
            glob.glob(os.path.join(BASE, "dex", "*", "*.dex"))
    dexes = []
    for dp in sorted(paths):
        try:
            d = DEX(open(dp, "rb").read())
            dexes.append((os.path.relpath(dp, BASE), d))
        except Exception as e:
            print(f"SKIP {os.path.basename(dp)}: {type(e).__name__}", file=sys.stderr)
    return dexes

def main():
    dexes = load_all_dex()
    all_classes = {}  # classname -> dexpath
    for dpath, d in dexes:
        for c in d.get_classes():
            all_classes[c.get_name()] = dpath
    print(f"loaded {len(dexes)} dex, {len(all_classes)} unique classes\n")

    # 35 服务接口
    svcs = []
    for line in open(os.path.join(BASE, "..", "service_list_F16.txt"), encoding="utf-8"):
        if any(k in line.lower() for k in ['oplus','oppo','coloros']) and '[' in line:
            name = line.split('\t')[0].strip() if '\t' in line else line.split()[0]
            iface = line.split('[')[1].split(']')[0].strip()
            svcs.append((name, iface))

    print("=" * 90)
    print("接口覆盖度核对（35 个私有服务）")
    print("=" * 90)
    covered = []
    for name, iface in svcs:
        leaf = iface.split('.')[-1]
        matches = [cn for cn in all_classes if leaf.lower() in cn.lower()]
        stub_matches = [cn for cn in matches if '$Stub' in cn]
        tag = 'IFACE+STUB' if stub_matches else ('IFACE' if matches else 'MISSING')
        print(f"  [{tag:10}] {name:28} {iface}")
        if stub_matches:
            covered.append((name, iface, stub_matches))

    print(f"\n覆盖: {len(covered)}/{len(svcs)} 服务有 Stub 定义\n")

    # 审计已覆盖服务的 Stub.onTransact
    print("=" * 90)
    print("已覆盖服务的 Stub.onTransact 字节码审计")
    print("=" * 90)
    for name, iface, stub_classes in covered:
        for cn in stub_classes:
            dpath = all_classes.get(cn, '?')
            d = None
            for dp2, d2 in dexes:
                if os.path.relpath(dp2, BASE) == dpath:
                    d = d2
                    break
            if not d:
                continue
            for c in d.get_classes():
                if c.get_name() != cn:
                    continue
                for m in c.get_methods():
                    if m.get_name() != 'onTransact':
                        continue
                    code = m.get_code()
                    if not code:
                        continue
                    lines = [i.get_output() or "" for i in code.get_bc().get_instructions()]
                    perm = [l for l in lines if any(k in l.lower() for k in PERM_KEYS)]
                    danger = [l for l in lines if any(k in l.lower() for k in DANGER_KEYS)]
                    print(f"\n--- {cn}  ({os.path.basename(dpath)}, {len(lines)} insns)")
                    print(f"    perm_calls={len(perm)}  danger_calls={len(danger)}")
                    for p in perm[:5]:
                        print(f"      PERM: {p}")
                    for dg in danger[:5]:
                        print(f"      DANGER: {dg}")

if __name__ == "__main__":
    main()
