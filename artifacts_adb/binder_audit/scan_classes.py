#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描所有 dex，定位 OPPO/ColorOS 私有 Binder 服务接口与 Stub 类的归属。"""
import glob
import os
import sys

from androguard.core.dex import DEX

BASE = os.path.dirname(os.path.abspath(__file__))
DEXDIR = os.path.join(BASE, "dex")

# 目标服务接口关键字（来自 service list）
TARGETS = [
    "IOplusService", "IOplusExService", "IOppoMMAtlasService", "atlas",
    "IOplusEngineerManager", "engineer", "IOppoGuardElfThermalControl",
    "IOppoAppDataService", "IOIfaceService", "IHoraeService", "IOppoNwPower",
    "IOplusTraceService", "IOplusAccessControlManager", "IOplusScreenshotManager",
    "OplusResourceManagerService", "IOplusNetworkStatsService", "IOplusPowerMonitor",
    "IOplusUsageService", "IOplusDevicePolicyManagerService", "IOplusStorageManagerService",
    "IOplusNetworkingControlManager", "IOplusScreenMode", "IOplusDataLimit",
    "IHansComunication", "IOplusNecService", "IOplusNetworkStack",
]

def main():
    idx = {}
    for dexpath in sorted(glob.glob(os.path.join(DEXDIR, "*.dex"))):
        name = os.path.basename(dexpath)
        try:
            d = DEX(open(dexpath, "rb").read())
        except Exception as e:
            print(f"!! {name}: {e}", file=sys.stderr)
            continue
        classes = [c.get_name() for c in d.get_classes()]
        idx[name] = classes

    # 汇总：每个目标关键字命中哪些类的哪些 dex
    for t in TARGETS:
        tl = t.lower()
        hits = []
        for dexname, classes in idx.items():
            for cn in classes:
                if tl in cn.lower():
                    hits.append((dexname, cn))
        if hits:
            print(f"\n### {t}  ({len(hits)} hits)")
            for dexname, cn in hits[:40]:
                print(f"  [{dexname}] {cn}")
            if len(hits) > 40:
                print(f"  ... +{len(hits)-40} more")

    # 输出全部类清单
    with open(os.path.join(BASE, "all_classes.txt"), "w", encoding="utf-8") as f:
        for dexname, classes in sorted(idx.items()):
            for cn in sorted(classes):
                f.write(f"{dexname}\t{cn}\n")
    print(f"\n[total] {sum(len(c) for c in idx.values())} classes across {len(idx)} dex -> all_classes.txt")

if __name__ == "__main__":
    main()
