#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""深度反编译指定类的所有方法，检查权限校验与高危操作调用。"""
import sys
from androguard.core.dex import DEX

PERM_KEYS = ["enforceCalling","enforcePermission","checkCalling","checkPermission",
             "PermissionChecker","checkUidPermission","enforceUid","enforceCallingOrSelf"]
DANGER_KEYS = ["SystemProperties","Runtime","->exec(","->system(","chmod","chown",
               "setprop","ProcessBuilder","FileOutputStream","->write(","->delete(",
               "openFileOutput","Settings$","Settings."]

def dump(dexfile, cls_filter):
    d = DEX(open(dexfile, "rb").read())
    for c in d.get_classes():
        cn = c.get_name()
        if cls_filter not in cn:
            continue
        print("=" * 90)
        print("CLASS:", cn)
        for m in c.get_methods():
            code = m.get_code()
            if not code:
                continue
            lines = [i.get_output() or "" for i in code.get_bc().get_instructions()]
            perm = [l for l in lines if any(k.lower() in l.lower() for k in PERM_KEYS)]
            danger = [l for l in lines if any(k.lower() in l.lower() for k in DANGER_KEYS)]
            flag = ""
            if danger:
                flag += " [DANGER]"
            if perm:
                flag += " [PERM]"
            print(f"\n--- {m.get_name()}{flag} ({len(lines)} insns) ---")
            for l in lines:
                print("   ", l)

if __name__ == "__main__":
    dump(sys.argv[1], sys.argv[2])
