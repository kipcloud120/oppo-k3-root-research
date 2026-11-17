#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
审计所有 AIDL Stub.onTransact 的实际字节码：
- 提取 onTransact 方法体中的 invoke 调用目标
- 判定是否含权限校验（enforceCallingPermission / checkCalling* / enforceUid 等）
- 判定是否含高危操作（SystemProperties.set / Runtime.exec / File write / setprop 等）
以 CVE-2026-70386（无授权 IPC -> root 命令执行）为对照，找"无权限校验 + 高权限操作"的分支。

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

PERM_CALLS = [
    "enforceCalling", "enforcePermission", "enforceCallingOrSelf",
    "checkCalling", "checkPermission", "checkCallingOrSelf",
    "PermissionChecker", "checkUidPermission", "enforceUidPermission",
    "enforceCallingOrSelfUriPermission", "checkCallingOrSelfUriPermission",
    "getCallingUid", "getCallingPid",
]
DANGER_CALLS = [
    "SystemProperties", "Runtime", "->exec(", "->system(", "->loadLibrary",
    "chmod", "chown", "->mount", "setprop", "ProcessBuilder",
]

def mref(inst):
    """返回指令的操作目标字符串（方法引用 / 字符串常量）。"""
    out = []
    try:
        op = inst.get_opcode()
        # androguard: 通过 get_output() 得到反汇编文本
        txt = inst.get_output()
        if txt:
            out.append(str(txt))
    except Exception:
        pass
    return out

def method_text(method):
    try:
        code = method.get_code()
        if not code:
            return ""
        bc = code.get_bc()
        lines = []
        for ins in bc.get_instructions():
            lines.append(ins.get_output() or "")
        return "\n".join(lines)
    except Exception:
        return ""

def main():
    dex_files = sorted(glob.glob(os.path.join(DEXDIR, "*.dex")))
    audited = 0
    findings = []
    for dp in dex_files:
        dname = os.path.basename(dp)
        try:
            d = DEX(open(dp, "rb").read())
        except Exception:
            continue
        for c in d.get_classes():
            cn = c.get_name()
            if "$Stub" not in cn:
                continue
            for m in c.get_methods():
                if m.get_name() != "onTransact":
                    continue
                asm = method_text(m)
                if not asm:
                    continue
                audited += 1
                lines = asm.splitlines()
                perm_hits = []
                danger_hits = []
                for ln in lines:
                    low = ln.lower()
                    for k in PERM_CALLS:
                        if k.lower() in low and ln not in perm_hits:
                            perm_hits.append(ln.strip())
                    for k in DANGER_CALLS:
                        if k.lower() in low and ln not in danger_hits:
                            danger_hits.append(ln.strip())
                findings.append({
                    "dex": dname, "class": cn,
                    "nlines": len(lines),
                    "perm": perm_hits, "danger": danger_hits,
                })

    print("=" * 100)
    print(f"审计 Stub.onTransact 方法数: {audited}")
    print("=" * 100)
    # 分类
    no_perm_with_danger = [f for f in findings if not f["perm"] and f["danger"]]
    no_perm = [f for f in findings if not f["perm"]]
    with_perm = [f for f in findings if f["perm"]]

    print(f"\n[!] 无权限校验 且 含高危操作 的 onTransact ({len(no_perm_with_danger)}):")
    for f in no_perm_with_danger:
        print(f"  [{f['dex']}] {f['class']}  lines={f['nlines']}")
        for d in f["danger"][:8]:
            print(f"      DANGER: {d}")

    print(f"\n[A] 无权限校验的 onTransact ({len(no_perm)}):")
    for f in no_perm:
        print(f"  [{f['dex']}] {f['class']}  lines={f['nlines']} danger={len(f['danger'])}")

    print(f"\n[B] 含权限校验的 onTransact ({len(with_perm)}):")
    for f in with_perm:
        print(f"  [{f['dex']}] {f['class']}  lines={f['nlines']}")
        print(f"      perm: {', '.join(p.strip() for p in f['perm'][:6])}")

    with open(os.path.join(BASE, "ontransact_matrix.txt"), "w", encoding="utf-8") as fo:
        for f in findings:
            fo.write(f"CLASS\t{f['dex']}\t{f['class']}\tlines={f['nlines']}\n")
            for p in f["perm"]:
                fo.write(f"  PERM\t{p}\n")
            for d in f["danger"]:
                fo.write(f"  DANGER\t{d}\n")
    print(f"\n-> ontransact_matrix.txt")

if __name__ == "__main__":
    main()
