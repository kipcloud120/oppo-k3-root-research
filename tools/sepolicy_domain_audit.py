#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sepolicy_domain_audit.py v3 —— SELinux 域权限边界审计（离线，纯静态）

v3 变更（2026-11-18，响应审核意见 v006 的 P0）：
  本脚本不再自带 CIL 解析，改为调用 `tools/cil_policy.py`。
  旧版（v2.23）自带的两处缺陷已移除：
    * 集合表达式 and/or/not/xor 的近似处理；
    * 版本化名字一律去后缀合并。
  语义正确性由 `tools/cil_selftest.py` 的 28 条用例守护。

用法：
  python tools/sepolicy_domain_audit.py --domain oplus_wifi_service \
         --cil .build/sepolicy --json .build/sepolicy/audit.json [--top 60]
  python tools/sepolicy_domain_audit.py --domain shell --naming canon --semantics legacy
         （仅用于与 v2.23 旧数字对账）
  python tools/sepolicy_domain_audit.py --query 'shell,anti_root_dialog_service,service_manager'
"""

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cil_policy import Policy, CilError, NAMING_MODES  # noqa: E402

WRITE = {
    'file': {'write', 'append', 'create', 'unlink', 'rename', 'setattr', 'relabelfrom',
             'relabelto', 'link', 'mounton', 'swapon', 'quotaon'},
    'dir': {'write', 'add_name', 'remove_name', 'create', 'rmdir', 'rename', 'setattr',
            'relabelfrom', 'relabelto', 'mounton', 'reparent'},
    'lnk_file': {'create', 'unlink', 'rename', 'setattr', 'relabelfrom', 'relabelto'},
    'sock_file': {'write', 'create', 'unlink', 'setattr', 'relabelfrom', 'relabelto',
                  'append'},
    'fifo_file': {'write', 'create', 'unlink', 'setattr', 'append'},
    'chr_file': {'write', 'create', 'unlink', 'setattr', 'ioctl', 'open', 'append'},
    'blk_file': {'write', 'create', 'unlink', 'setattr', 'mounton'},
    'property_service': {'set'},
    'service_manager': {'add'},
    'hwservice_manager': {'add'},
    'system': {'module_load', 'ipc_info', 'syslog_read', 'syslog_mod'},
    'security': {'setenforce', 'setbool', 'setsecparam', 'load_policy', 'check_context'},
    'process': {'transition', 'dyntransition', 'setcurrent', 'ptrace', 'setcap', 'share',
                'setfscreate', 'nosuid_transition'},
    'capability': {'sys_admin', 'sys_module', 'sys_ptrace', 'sys_rawio', 'dac_override',
                   'dac_read_search', 'setuid', 'setgid', 'chown', 'fowner', 'mknod'},
    'capability2': {'*'},
    'unix_stream_socket': {'connectto', 'write', 'sendto'},
    'tcp_socket': {'connectto', 'write', 'sendto', 'name_connect'},
    'netlink_kernel_socket': {'*'},
}

CONSUMER_PRIORITY = [
    'init', 'vendor_init', 'ueventd', 'vold', 'installd', 'system_server', 'zygote',
    'servicemanager', 'hwservicemanager', 'vndservicemanager', 'netd', 'keystore',
    'surfaceflinger', 'audioserver', 'wificond', 'dumpstate', 'debuggerd',
]


def consumer_rank(src):
    if src in CONSUMER_PRIORITY:
        return 100 - CONSUMER_PRIORITY.index(src)
    if src.startswith(('hal_', 'vendor_hal_', 'oppo_hal_')):
        return 10
    return 0


def load_ctx(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            p = line.split()
            if len(p) >= 2:
                out.append((p[0], p[-1].split(':')[-2] if ':' in p[-1] else p[-1]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--domain')
    ap.add_argument('--query', help='src,tgt[,class] —— 单点查询模式')
    ap.add_argument('--cil', default='.build/sepolicy')
    ap.add_argument('--json')
    ap.add_argument('--top', type=int, default=60)
    ap.add_argument('--naming', default='alias', choices=NAMING_MODES)
    ap.add_argument('--semantics', default='cil', choices=['cil', 'legacy'])
    ap.add_argument('--allow-partial', action='store_true')
    args = ap.parse_args()

    pol = Policy(semantics=args.semantics, naming=args.naming,
                 allow_partial=args.allow_partial)
    try:
        loaded = pol.load_dir(args.cil)
    except CilError as e:
        print('审计失败（CIL 语义无法求值）：%s' % e, file=sys.stderr)
        return 2

    st = pol.stats()

    # ---------------- 单点查询
    if args.query:
        parts = [x.strip() for x in args.query.split(',')]
        src, tgt = parts[0], parts[1]
        cls = parts[2] if len(parts) > 2 else None
        r = pol.perms(src, tgt, cls, prov=True)
        print('查询 %s -> %s%s' % (src, tgt, (' [%s]' % cls) if cls else ''))
        if not r:
            print('  并集 = ∅（该类别下无任何适用 allow）')
        for c, d in sorted(r.items()):
            print('  %-22s %s' % (c, ' '.join(sorted(d['perms']))))
            for v in sorted({x for x in d['via']})[:8]:
                print('      <- %-18s 目标 %s' % v)
        print('\n口径：%s / %s | allow %d | 属性 %d'
              % (st['semantics'], st['naming'], st['allows'], st['attrs_declared']))
        return 0

    if not args.domain:
        print('需要 --domain 或 --query', file=sys.stderr)
        return 2

    dom = args.domain
    attrs = pol.attrs_of(dom)
    rules = pol.rules_for(dom)

    merged = {}
    for r in rules:
        k = (r['cls'], r['tgt'])
        m = merged.setdefault(k, {'perms': set(), 'via': set(), 'direct': False})
        m['perms'] |= set(r['perms'])
        m['via'].add(r['via'])
        if r['via'] == 'direct':
            m['direct'] = True

    fctx = load_ctx(os.path.join(args.cil, 'plat_file_contexts')) + \
        load_ctx(os.path.join(args.cil, 'vendor_file_contexts'))
    pctx = load_ctx(os.path.join(args.cil, 'plat_property_contexts')) + \
        load_ctx(os.path.join(args.cil, 'vendor_property_contexts'))
    hctx = load_ctx(os.path.join(args.cil, 'vendor_hwservice_contexts'))
    sctx = load_ctx(os.path.join(args.cil, 'plat_service_contexts')) + \
        load_ctx(os.path.join(args.cil, 'vendor_service_contexts'))

    def paths(t):
        return [rx for rx, ty in fctx if ty == t]

    def props(t):
        return [rx for rx, ty in pctx if ty == t]

    def hwsvc(t):
        return [rx for rx, ty in hctx if ty == t]

    def svc(t):
        return [rx for rx, ty in sctx if ty == t]

    items = []
    for (cls, tgt), m in merged.items():
        wset = WRITE.get(cls)
        eff = sorted(m['perms'] & wset) if wset else []
        if not eff:
            continue
        cons = []
        for src, perms in pol.consumers_of(cls, tgt):
            if src == dom or consumer_rank(src) <= 0:
                continue
            cons.append({'src': src, 'perms': perms, 'rank': consumer_rank(src)})
        cons.sort(key=lambda x: -x['rank'])
        seen, uniq = set(), []
        for c in cons:
            if c['src'] not in seen:
                seen.add(c['src'])
                uniq.append(c)
        items.append({
            'class': cls, 'target': tgt, 'write_perms': eff,
            'all_perms': sorted(m['perms']), 'direct': m['direct'],
            'via': sorted(v for v in m['via'] if v != 'direct')[:6],
            'paths': paths(tgt)[:10], 'props': props(tgt)[:14],
            'hwservices': hwsvc(tgt)[:6], 'services': svc(tgt)[:6],
            'consumers': uniq[:12],
        })

    order = {'capability': 0, 'capability2': 0, 'security': 1, 'system': 2,
             'property_service': 3, 'hwservice_manager': 4, 'service_manager': 5,
             'file': 6, 'dir': 7, 'sock_file': 8, 'chr_file': 9, 'lnk_file': 10,
             'blk_file': 11, 'process': 12, 'binder': 13}
    items.sort(key=lambda x: (order.get(x['class'], 20), -x['direct'], x['target']))

    print('域 %s | 口径 %s/%s | 5 份 CIL allow %d'
          % (dom, st['semantics'], st['naming'], st['allows']))
    print('所属属性 %d | 适用 allow %d | 显式目标类型 %d | 审计失败 %d'
          % (len(attrs), len(rules),
             sum(1 for k, v in merged.items() if v['direct']), st['errors']))
    print('可写面（按 class 计）: %s' % dict(sorted(
        ((c, sum(1 for i in items if i['class'] == c)) for c in
         {i['class'] for i in items}), key=lambda x: -x[1])))
    print()
    for it in items[:args.top]:
        tag = 'D' if it['direct'] else 'A'
        loc = ''
        if it['class'] in ('file', 'dir', 'lnk_file', 'sock_file', 'chr_file', 'blk_file'):
            loc = ' | '.join(it['paths'][:3]) or '(无 file_contexts 落点)'
        elif it['class'] == 'property_service':
            loc = ' | '.join(it['props'][:5]) or '(无 property_contexts 落点)'
        elif it['class'] == 'hwservice_manager':
            loc = ' | '.join(it['hwservices'][:3])
        elif it['class'] == 'service_manager':
            loc = ' | '.join(it['services'][:3])
        print('[%s] %-18s %-42s %-34s %s'
              % (tag, it['class'], it['target'], '/'.join(it['write_perms'])[:34], loc[:64]))
        if it['consumers']:
            print('     消费: %s' % ', '.join(c['src'] for c in it['consumers'][:6])[:110])

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump({'domain': dom, 'stats': st, 'cil_loaded': loaded,
                       'attrs_count': len(attrs), 'attrs': sorted(attrs),
                       'allow_applicable': len(rules), 'items': items},
                      f, ensure_ascii=False, indent=1)
        print('\nJSON: %s' % args.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
