#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
svc_registrar_index.py —— 在 dex/jar 语料里定位"服务名 → 注册点"（离线）

动机（§35）：
  §34 证明 shell 能 `find` 228/235 个服务、36 个 OPPO 私有服务全在其中。
  于是"服务面是否安全"这个问题，收缩为**逐个服务看它的 `onTransact` 有没有鉴权、有没有危险 sink**。
  但第一步是知道每个服务由谁注册——本脚本做这件事：
  扫所有方法的 `addService(...)` 调用，把同一方法里的字符串字面量当作候选服务名。

用法：
  python tools/svc_registrar_index.py --corpus artifacts_adb/binder_audit/dex \
         --apk artifacts_adb/binder_audit/rootbin/_p2/OppoExSystemService.apk \
         --json .build/sepolicy/svc_registrar.json
  python tools/svc_registrar_index.py --match .build/svc_names.txt      # 只报这些名字的命中
"""

import argparse
import glob
import json
import os
import re
import sys
import zipfile


def load_dex_objs(jar_or_dex):
    """返回 [(label, DEX)]。jar/apk 里取 classes*.dex。"""
    from androguard.core.dex import DEX
    out = []
    if jar_or_dex.lower().endswith(('.jar', '.apk', '.zip')):
        try:
            z = zipfile.ZipFile(jar_or_dex)
        except Exception:
            return out
        for n in z.namelist():
            if re.match(r'classes\d*\.dex$', n):
                try:
                    out.append((os.path.basename(jar_or_dex) + '!' + n,
                                DEX(z.read(n))))
                except Exception:
                    pass
    else:
        try:
            out.append((os.path.basename(jar_or_dex), DEX(open(jar_or_dex, 'rb').read())))
        except Exception:
            pass
    return out


def scan(d, label, targets=None, any_string=False):
    """返回 {(svc_name, class, method)}，只保留带 addService 的方法。"""
    hits = []
    for c in d.get_classes():
        for m in c.get_methods():
            try:
                ins = m.get_instructions()
            except Exception:
                continue
            if not ins:
                continue
            strs, has_add = [], False
            for i in ins:
                s = i.get_output()
                if 'addService' in s:
                    has_add = True
                mo = re.search(r'"([^"]{2,64})"', s)
                if mo:
                    strs.append(mo.group(1))
            if not has_add and not any_string:
                continue
            for s in strs:
                if targets is not None and s not in targets:
                    continue
                hits.append({'svc': s, 'class': c.get_name(),
                             'method': m.get_name() + m.get_descriptor(),
                             'dex': label})
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--corpus', default='artifacts_adb/binder_audit/dex')
    ap.add_argument('--apk', default='artifacts_adb/binder_audit/rootbin/_p2/OppoExSystemService.apk')
    ap.add_argument('--jars', default='artifacts_adb/binder_audit/jars')
    ap.add_argument('--match', help='文件：每行一个服务名，只报这些')
    ap.add_argument('--json')
    ap.add_argument('--any-string', action='store_true', help='不要求同方法里有 addService（用于走了封装 helper 的注册）')
    args = ap.parse_args()

    targets = None
    if args.match:
        targets = {l.strip() for l in open(args.match, encoding='utf-8') if l.strip()}

    files = sorted(glob.glob(os.path.join(args.corpus, '*.dex')))
    if os.path.isdir(args.jars):
        files += sorted(glob.glob(os.path.join(args.jars, '*.jar')))
    if args.apk and os.path.exists(args.apk):
        files.append(args.apk)

    allhits = []
    for f in files:
        for label, d in load_dex_objs(f):
            h = scan(d, label, targets, args.any_string)
            allhits += h
            ncls = len(d.get_classes())
            print('  %-58s 类 %5d  命中 %3d' % (label[:58], ncls, len(h)))

    print('\n命中合计 %d' % len(allhits))
    bysvc = {}
    for h in allhits:
        bysvc.setdefault(h['svc'], []).append(h)
    for s in sorted(bysvc):
        for h in bysvc[s]:
            print('  %-34s <- %-56s %s' % (s, h['class'][:56], h['method'][:44]))

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(allhits, f, ensure_ascii=False, indent=1)
        print('\nJSON: %s' % args.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
