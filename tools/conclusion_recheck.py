#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
conclusion_recheck.py —— 对 CLOSURE.md / HANDOVER 中**策略级否证**逐条重算（响应 §33.9 遗留项）

为什么需要这一步：
  §33 只回归了 `shell`、七个私有服务域与本域。其余否证（"可写类型上持有 execute 的域数 = 0"、
  "消费者域全都没有 system_server binder"…）都是**旧引擎**算出来的，且属于"全量表里没有这一行"
  这一类**最脆弱**的论证形式。本脚本把这些否证重新编码成**可执行判据**，在 A（v2.23 口径）
  与 C（新基线）下各跑一遍，差异即风险。

与 §26 的区别：消费者集合不再手工列举，而是**从策略反推**——
"对本域可写的每个类型持有 read/open 的域"，这样也顺带回应了"枚举完备性"这条批评。

用法：python tools/conclusion_recheck.py --cil .build/sepolicy --json .build/sepolicy/recheck.json
"""

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cil_policy import Policy, CilError  # noqa: E402

DOM = 'oplus_wifi_service'
READISH = {'read', 'open', 'getattr', 'map', 'search', 'execute', 'execute_no_trans'}
WRITEISH = {
    'file': {'write', 'append', 'create', 'unlink', 'rename', 'setattr'},
    'dir': {'write', 'add_name', 'remove_name', 'create', 'rmdir', 'rename', 'setattr'},
    'sock_file': {'write', 'create', 'unlink'},
    'fifo_file': {'write', 'create', 'unlink'},
}
# 高权限下游：判定"跳板方向"的关键目标
DOWNSTREAM = ['system_server', 'vold', 'installd', 'servicemanager', 'netd', 'zygote',
              'surfaceflinger', 'keystore']


def build(naming, semantics):
    p = Policy(semantics=semantics, naming=naming)
    p.load_dir(CIL_DIR)
    return p


def writable(p, dom=DOM):
    """本域可写的 (class,target) 集合。"""
    agg = defaultdict(set)
    for r in p.rules_for(dom):
        agg[(r['cls'], r['tgt'])] |= set(r['perms'])
    out = []
    for (cls, tgt), perms in agg.items():
        w = WRITEISH.get(cls)
        if w and (perms & w):
            out.append((cls, tgt))
    return sorted(out)


def holders(p, cls, tgt, permset):
    """对 (cls,tgt) 持有给定权限集合中任一权限的域（属性展开后）。"""
    res = defaultdict(set)
    for r_src, r_tgt, r_cls, r_perms, origin in p.allows:
        if origin != 'allow' or r_cls != cls:
            continue
        if r_tgt != tgt and not (r_tgt in p.attrs and tgt in p.expand(r_tgt)):
            continue
        if r_perms & permset:
            res[r_src] |= set(r_perms)
    return res


def downstream_of(p, domains):
    """每个域对高权限下游的 binder/service_manager 权限。"""
    out = {}
    for d in domains:
        row = {}
        for tgt in DOWNSTREAM:
            perms = p.perms(d, tgt, 'binder').get('binder')
            if perms:
                row['binder:' + tgt] = sorted(perms)
        for svc in ('alarm_service', 'activity_service', 'settings_service'):
            perms = p.perms(d, svc, 'service_manager').get('service_manager')
            if perms:
                row['svc:' + svc] = sorted(perms)
        if row:
            out[d] = row
    return out


CIL_DIR = '.build/sepolicy'


def analyse(p):
    w = writable(p)
    r = {'writable': [{'cls': c, 'tgt': t} for c, t in w]}

    # R1 可写类型上持有 execute 的域（§24.1 的核心否定）
    ex = {}
    for cls, tgt in w:
        h = holders(p, cls, tgt, {'execute'})
        if h:
            ex['%s:%s' % (cls, tgt)] = sorted(h)
    r['execute_holders'] = ex

    # R2 消费者域（从策略反推）及其对高权限下游的通道
    consumers = set()
    for cls, tgt in w:
        consumers |= set(holders(p, cls, tgt, READISH))
    consumers.discard(DOM)
    r['consumers'] = sorted(consumers)
    r['consumer_downstream'] = downstream_of(p, sorted(consumers))

    # R3 本域 socket 连接目标（"只能连 init"）
    conn = defaultdict(set)
    for r_src, r_tgt, r_cls, r_perms, origin in p.allows:
        if origin == 'allow' and r_cls == 'unix_stream_socket' and r_src == DOM:
            conn[r_tgt] |= set(r_perms)
    r['connectto'] = {k: sorted(v) for k, v in conn.items()}

    # R4 本域可写的属性类型
    props = defaultdict(set)
    for r_src, r_tgt, r_cls, r_perms, origin in p.allows:
        if origin == 'allow' and r_cls == 'property_service' and r_src == DOM:
            props[r_tgt] |= set(r_perms)
    r['writable_props'] = {k: sorted(v) for k, v in props.items()}

    # R5 域转换
    r['transitions'] = sorted('%s -> %s (class %s)' % (t[0], t[2], t[1])
                              for t in p.transitions if t[0] == DOM)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cil', default='.build/sepolicy')
    ap.add_argument('--json')
    args = ap.parse_args()
    global CIL_DIR
    CIL_DIR = args.cil

    try:
        pa = build('canon', 'legacy')
        pc = build('alias', 'cil')
    except CilError as e:
        print('审计失败：%s' % e, file=sys.stderr)
        return 2

    A = analyse(pa)
    C = analyse(pc)

    print('== R1 可写类型上持有 execute 的域（§24.1） ==')
    print('  A: %s' % (A['execute_holders'] or '∅'))
    print('  C: %s' % (C['execute_holders'] or '∅'))

    print('\n== R2 消费者域（从策略反推） ==')
    print('  A: %d 个' % len(A['consumers']))
    print('  C: %d 个  %s' % (len(C['consumers']), C['consumers']))
    onlyA = set(A['consumers']) - set(C['consumers'])
    onlyC = set(C['consumers']) - set(A['consumers'])
    print('  仅 A 有: %s' % (sorted(onlyA) or '-'))
    print('  仅 C 有: %s' % (sorted(onlyC) or '-'))

    print('\n== R2b 消费者对高权限下游的通道（A → C） ==')
    keys = sorted(set(A['consumer_downstream']) | set(C['consumer_downstream']))
    if not keys:
        print('  无任何消费者持有下游 binder/service_manager 权限')
    for d in keys:
        print('  %-34s A=%-28s C=%s'
              % (d, json.dumps(A['consumer_downstream'].get(d, {}), ensure_ascii=False)[:28],
                 json.dumps(C['consumer_downstream'].get(d, {}), ensure_ascii=False)))

    print('\n== R3 本域 connectto ==')
    print('  A: %s' % (A['connectto'] or '∅'))
    print('  C: %s' % (C['connectto'] or '∅'))

    print('\n== R4 本域可写属性类型 ==')
    print('  A: %s' % (list(A['writable_props']) or '∅'))
    print('  C: %s' % (list(C['writable_props']) or '∅'))

    print('\n== R5 本域域转换 ==')
    print('  A: %s' % (A['transitions'] or '∅'))
    print('  C: %s' % (C['transitions'] or '∅'))

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump({'domain': DOM, 'A_v223': A, 'C_new': C}, f,
                      ensure_ascii=False, indent=1)
        print('\nJSON: %s' % args.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
