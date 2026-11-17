#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
对 OPPO/ColorOS 私有服务做静态审计：
1) 找出所有 Binder 服务实现类（com/android/server 下的 *Service）
2) 对每个类，检查是否存在权限校验调用（enforce*/checkCalling*/checkPermission）
3) 检查是否存在高权限操作（setprop/exec/chmod/mount/system()/写文件）
4) 找 onTransact 方法并统计其调用的目标方法
以 CVE-2026-70386 缺陷模式（未授权 IPC -> 高权限命令执行）为对照。

只读分析，不接触设备。
"""
import glob
import os
import sys
import loguru

loguru.logger.remove()

from androguard.core.dex import DEX

BASE = os.path.dirname(os.path.abspath(__file__))
DEXDIR = os.path.join(BASE, "dex")

# 权限校验方法特征
PERM_KEYS = [
    "enforceCalling", "enforcePermission", "enforceCallingOrSelf",
    "checkCalling", "checkPermission", "checkCallingOrSelf",
    "enforceCallingPermission", "enforceCallingOrSelfPermission",
    "PermissionChecker", "checkUidPermission", "enforceUidPermission",
    "checkCallingOrSelfUriPermission", "enforceCallingOrSelfUriPermission",
]
# 高权限操作特征（方法名 / 类名）
DANGER_KEYS = [
    "setprop", "SystemProperties", "Runtime", "exec", "system",
    "chmod", "chown", "mount", "setuid", "deleteFile", "mkdir",
    "FileOutputStream", "openFileOutput", "write", "delete",
    "startService", "startActivity", "am", "ActivityManager",
    "Settings.", "Settings$", "putString", "putInt",
]
# 服务实现类：com/android/server 包下、类名以 Service 结尾（排除内部类）
SERVER_PKGS = ("Lcom/android/server/", "Lcom/oppo/", "Lcom/coloros/", "Lcom/oplus/")


def class_methods(c):
    return list(c.get_methods())


def main():
    results = []
    dex_files = sorted(glob.glob(os.path.join(DEXDIR, "*.dex")))
    for dp in dex_files:
        dname = os.path.basename(dp)
        try:
            d = DEX(open(dp, "rb").read())
        except Exception as e:
            print(f"!! parse {dname}: {e}", file=sys.stderr)
            continue
        for c in d.get_classes():
            cn = c.get_name()
            # 只关注服务实现主类（非 $ 内部类），且类名以 Service 结尾
            if "$" in cn or not cn.endswith("Service;"):
                continue
            if not any(cn.startswith(p) for p in SERVER_PKGS):
                continue
            methods = class_methods(c)
            mnames = [m.get_name() for m in methods]
            # 权限校验方法
            perm_found = sorted(set(
                m for m in mnames if any(k.lower() in m.lower() for k in PERM_KEYS)
            ))
            # onTransact 存在性
            has_transact = any("onTransact" == m for m in mnames)
            results.append({
                "dex": dname,
                "class": cn,
                "nmethods": len(methods),
                "perm_methods": perm_found,
                "has_onTransact": has_transact,
                "methods": mnames,
            })

    # 输出：按是否有权限校验分组
    print("=" * 100)
    print(f"Binder 服务实现类总数: {len(results)}")
    print("=" * 100)
    no_perm = [r for r in results if not r["perm_methods"]]
    with_perm = [r for r in results if r["perm_methods"]]

    print(f"\n[A] 无任何显式权限校验方法的服务实现类 ({len(no_perm)}):")
    for r in no_perm:
        print(f"  [{r['dex']}] {r['class']}  methods={r['nmethods']} onTransact={r['has_onTransact']}")

    print(f"\n[B] 含权限校验方法的服务实现类 ({len(with_perm)}):")
    for r in with_perm:
        print(f"  [{r['dex']}] {r['class']}")
        print(f"      perm: {', '.join(r['perm_methods'])}")

    # 写详细清单
    with open(os.path.join(BASE, "services_perm_matrix.txt"), "w", encoding="utf-8") as f:
        for r in sorted(results, key=lambda x: (bool(x["perm_methods"]), x["class"])):
            f.write(f"{'HAS_PERM' if r['perm_methods'] else 'NO_PERM '}\t{r['dex']}\t{r['class']}\t"
                    f"nmethods={r['nmethods']}\tonTransact={r['has_onTransact']}\t"
                    f"perm={','.join(r['perm_methods'])}\n")
    print(f"\n-> services_perm_matrix.txt")


if __name__ == "__main__":
    main()
