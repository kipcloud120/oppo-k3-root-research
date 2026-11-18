#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prop_trigger_audit.py —— 属性写面 -> init 触发器 交叉审计（离线，纯静态）

目的：SELinux 域逃逸的经典路径之一是「低权域可写某类属性 -> 高权组件消费该属性」。
      本工具把三者连起来：
        1. property_contexts 把属性名映射到 SELinux 类型；
        2. CIL 策略给出「哪个域对该类型有 property_service:set」；
        3. init rc 的 `on property:NAME=VALUE` 触发器给出「谁消费」，以及消费动作（start/exec/...）。

用法：
  python tools/prop_trigger_audit.py --cil .build/sepolicy --rc .build/sepolicy/rc \
      --domain oplus_wifi_service [--all-types] [--json out.json]

输出：按"可写属性类型"分组的触发器清单，含 rc 文件、行号、动作块首行。
      只读，不连接设备。
"""

import argparse
import importlib.util
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))


def load_audit_module():
    spec = importlib.util.spec_from_file_location('sda', os.path.join(HERE, 'sepolicy_domain_audit.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_prop_contexts(cildir):
    """返回 [(prefix, type)]，按 prefix 长度降序，便于最长前缀匹配。"""
    out = []
    for f in ('plat_property_contexts', 'vendor_property_contexts'):
        p = os.path.join(cildir, f)
        if not os.path.exists(p):
            continue
        with open(p, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                m = re.match(r'u:object_r:([A-Za-z0-9_]+):s0', parts[-1])
                if not m:
                    continue
                out.append((parts[0], m.group(1)))
    out.sort(key=lambda x: -len(x[0]))
    return out


def prop_type(prop, ctx):
    """Android 属性匹配语义：完全相等，或 prefix 以 '.' 结尾且 prop 以其开头；取最长匹配。"""
    best = None
    for prefix, ty in ctx:
        if prefix == prop:
            return ty
        if prefix.endswith('.'):
            if prop.startswith(prefix):
                if best is None or len(prefix) > len(best[0]):
                    best = (prefix, ty)
    if best:
        return best[1]
    return 'default_prop' if prop.startswith('default.') else ('user_prop' if prop.startswith('user.') else None)


def parse_rc_triggers(rc_root):
    """返回 [(file, lineno, prop, action_lines)]"""
    out = []
    for dirpath, _, files in os.walk(rc_root):
        for fn in sorted(files):
            if not fn.endswith('.rc'):
                continue
            path = os.path.join(dirpath, fn)
            try:
                lines = open(path, 'r', encoding='utf-8', errors='replace').read().splitlines()
            except OSError:
                continue
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                m = re.match(r'^on\s+property:([A-Za-z0-9_.\-]+)=(\S*)\s*$', line)
                if m:
                    prop = m.group(1)
                    body = []
                    j = i + 1
                    while j < len(lines):
                        nxt = lines[j]
                        if nxt.strip() == '' or nxt.strip().startswith('#'):
                            j += 1
                            continue
                        if not nxt.startswith((' ', '\t')):
                            break
                        body.append(nxt.strip())
                        j += 1
                    out.append((os.path.relpath(path, rc_root), i + 1, prop, m.group(2), body))
                    i = j
                    continue
                i += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cil', default='.build/sepolicy')
    ap.add_argument('--rc', default='.build/sepolicy/rc')
    ap.add_argument('--domain', required=True)
    ap.add_argument('--json')
    ap.add_argument('--max-body', type=int, default=4)
    args = ap.parse_args()

    m = load_audit_module()
    pol = m.Policy()
    for f in ('plat_sepolicy.cil', 'plat_pub_versioned.cil', 'vendor_sepolicy.cil'):
        p = os.path.join(args.cil, f)
        if os.path.exists(p):
            pol.load(p)

    dom = m.canon(args.domain)

    # 1) 该域可写的属性类型
    settable = defaultdict(set)          # type -> {'direct','via:x'}
    for src, tgt, cls, perms in pol.allows:
        if cls != 'property_service' or 'set' not in perms:
            continue
        if src == dom:
            settable[tgt].add('direct')
        elif src in pol.attrs and dom in pol.closure(src):
            settable[tgt].add('via:' + src)
    print('域 %s 可写属性类型 (%d): %s' % (dom, len(settable), ', '.join(sorted(settable))))

    # 2) 属性类型 -> 读方
    readers = defaultdict(set)
    for src, tgt, cls, perms in pol.allows:
        if cls == 'file' and 'read' in perms and not src.startswith('base_typeattr'):
            readers[tgt].add(src)

    # 3) 属性名
    pctx = load_prop_contexts(args.cil)
    names_by_type = defaultdict(list)
    for prefix, ty in pctx:
        names_by_type[ty].append(prefix)

    # 4) rc 触发器
    trig = parse_rc_triggers(args.rc)
    print('init rc 属性触发器 %d 条' % len(trig))

    # 5) 交叉
    hits = []
    for rel, lineno, prop, val, body in trig:
        ty = prop_type(prop, pctx)
        if ty in settable:
            hits.append({
                'prop': prop, 'value': val, 'type': ty,
                'rc': rel, 'line': lineno, 'body': body[:args.max_body],
                'readers': sorted(readers.get(ty, ()))[:10],
            })

    print('\n== 可写属性类型命中的 init 触发器 (%d) ==' % len(hits))
    for h in hits:
        print('[%s] %s:%d  %s=%s' % (h['type'], h['rc'], h['line'], h['prop'], h['value'] or '(任意)'))
        for b in h['body']:
            print('        %s' % b[:110])
    if not hits:
        print('（无：该域可写的属性类型未被任何 init 触发器消费）')

    # 6) 可写类型下的具体属性名（样本，供人工判读）
    print('\n== 可写属性类型的名字样本 ==')
    for ty in sorted(settable):
        names = names_by_type.get(ty, [])
        print('  %-24s 前缀条目 %4d  例: %s' % (ty, len(names), ', '.join(names[:6])))

    if args.json:
        out = {'domain': dom, 'settable': {k: sorted(v) for k, v in settable.items()},
               'triggers_hit': hits,
               'writable_prop_names': {k: names_by_type.get(k, [])[:200] for k in settable}}
        json.dump(out, open(args.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print('\nJSON: %s' % args.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
