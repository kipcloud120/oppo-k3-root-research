#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
svc_impl_triage.py —— 对"服务注册点"批量做鉴权/危险调用初筛（离线）

输入：`tools/svc_registrar_index.py --any-string` 产出的 JSON（服务名 → 注册所在类/方法）
做法：
  1. 回到注册方法里，收集 `new-instance` 的类型 —— 这些是实现体（Binder/Stub）的候选；
  2. 对候选类（及其内部类、以及注册类本身）做两类统计：
       A. 鉴权 API：checkCallingPermission / enforceCallingPermission / checkCallingOrSelfPermission
                   / getCallingUid / checkUidPermission / AppOps / checkPermission
       B. 危险 sink：Runtime.exec / ProcessBuilder / exec* / reboot / startService / sendBroadcast
                   / SystemProperties.set / Settings.*.put* / FileOutputStream / deleteFile
  3. 输出一表：服务 / 注册类 / 实现候选 / 鉴权命中 / sink 命中

**性质说明**：这是**初筛**，不是审计。命中数为 0 只说明这几个类里没有出现这些调用，
不覆盖跨类数据流。判读口径写进报告 §4。
"""

import argparse
import json
import os
import re
import sys
import zipfile
from collections import Counter

PERM = re.compile(r'(checkCallingPermission|enforceCallingPermission|checkCallingOrSelfPermission|'
                  r'getCallingUid|checkUidPermission|checkPermission|AppOpsManager|noteOp|'
                  r'enforceCallingUid|getCallingPid)', re.I)
# 注意：不能用 `Ljava/lang/Runtime` 作模式——它会匹配 `Ljava/lang/RuntimeException`
# （v2.24+ 初筛中确实出现过这个假阳性）。只认真正的 exec 调用。
SINK = re.compile(r'(Ljava/lang/Runtime;->exec|Ljava/lang/ProcessBuilder;|'
                  r'PowerManager;->reboot|startService|sendBroadcast|'
                  r'SystemProperties;->set|Settings\$|deleteFile|FileOutputStream|'
                  r'PackageManager;->(?:install|delete)|grantRuntimePermission)', re.I)


def load(path):
    from androguard.core.dex import DEX
    if path.lower().endswith(('.jar', '.apk', '.zip')):
        out = []
        z = zipfile.ZipFile(path)
        for n in z.namelist():
            if re.match(r'classes\d*\.dex$', n):
                out.append((os.path.basename(path) + '!' + n, DEX(z.read(n))))
        return out
    return [(os.path.basename(path), DEX(open(path, 'rb').read()))]


def triage_class(c):
    perm, sink, names = 0, [], []
    for m in c.get_methods():
        try:
            ins = m.get_instructions()
        except Exception:
            continue
        for i in ins:
            s = i.get_output()
            if PERM.search(s):
                perm += 1
            mo = SINK.search(s)
            if mo:
                sink.append('%s@%s' % (mo.group(1)[:34], m.get_name()))
    return perm, sorted(set(sink))[:6], names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--hits', default='.build/sepolicy/svc_any.json')
    ap.add_argument('--corpus', default='artifacts_adb/binder_audit/dex')
    ap.add_argument('--apk', default='artifacts_adb/binder_audit/rootbin/_p2/OppoExSystemService.apk')
    ap.add_argument('--jars', default='artifacts_adb/binder_audit/jars')
    ap.add_argument('--json')
    args = ap.parse_args()

    hits = json.load(open(args.hits, encoding='utf-8'))
    bydex = {}
    for h in hits:
        bydex.setdefault(h['dex'], []).append(h)

    files = []
    for d in (args.corpus, args.jars):
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.endswith(('.dex', '.jar')):
                    files.append(os.path.join(d, f))
    if args.apk and os.path.exists(args.apk):
        files.append(args.apk)

    rows = []
    for f in files:
        base = os.path.basename(f)
        if not any(k.startswith(base) for k in bydex):
            continue
        for label, d in load(f):
            if label not in bydex:
                continue
            cm = {c.get_name(): c for c in d.get_classes()}
            for h in bydex[label]:
                c = cm.get(h['class'])
                if c is None:
                    continue
                # 注册方法里的 new-instance → 实现候选
                cands = []
                for m in c.get_methods():
                    if m.get_name() + m.get_descriptor() != h['method']:
                        continue
                    for i in m.get_instructions():
                        s = i.get_output()
                        mo = re.search(r'new-instance[^,]*, (L[\w/$]+;)', s)
                        if mo:
                            cands.append(mo.group(1))
                cands = [x for x in dict.fromkeys(cands) if not x.endswith('$1;')]
                for cc in cands[:3]:
                    impl = cm.get(cc)
                    if impl is None:
                        continue
                    perm, sink, _ = triage_class(impl)
                    rows.append({'svc': h['svc'], 'registrar': h['class'],
                                 'method': h['method'], 'impl': cc,
                                 'perm_hits': perm, 'sinks': sink, 'dex': label})
                # 注册类自身也统计（有的实现直接写在注册类里）
                perm, sink, _ = triage_class(c)
                rows.append({'svc': h['svc'], 'registrar': h['class'],
                             'method': h['method'], 'impl': h['class'] + '(self)',
                             'perm_hits': perm, 'sinks': sink, 'dex': label})

    # 去重（同一服务/同一实现可能因 jar+dex 重复）
    seen, uniq = set(), []
    for r in rows:
        k = (r['svc'], r['impl'])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)
    uniq.sort(key=lambda x: (x['svc'], x['impl']))

    print('%-32s %-52s %-8s %-6s %s' % ('服务', '实现类', '鉴权命中', 'sink', 'dex'))
    for r in uniq:
        print('%-32s %-52s %-8d %-6d %s'
              % (r['svc'][:32], r['impl'][:52], r['perm_hits'], len(r['sinks']),
                 ','.join(r['sinks'])[:40]))
    print('\n共 %d 行；鉴权命中=0 且 sink>0 的（需人工看）：' % len(uniq))
    for r in uniq:
        if r['perm_hits'] == 0 and r['sinks']:
            print('  %-30s %-46s %s' % (r['svc'], r['impl'][:46], r['sinks']))

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(uniq, f, ensure_ascii=False, indent=1)
        print('\nJSON: %s' % args.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
