#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sepolicy_domain_audit.py v2 —— SELinux 域权限边界审计（离线，纯静态）

用途：给定一个 SELinux domain（如 oplus_wifi_service），从 Android CIL 策略文本中展开该域
      的完整 allow 集合，并区分
        * direct  —— 策略中直接以该域名为源的规则（厂商"显式授予"）
        * via X   —— 通过属性 X 继承的规则（平台基线或厂商属性模板）
      然后按「可写面 → 落点路径 → 被哪些域消费」三段式输出候选逃逸点。

输入（从设备只读拉取，见 artifacts_adb/binder_audit/sepolicy/PULL.md）：
      plat_sepolicy.cil / plat_pub_versioned.cil / vendor_sepolicy.cil
      plat|vendor_file_contexts / *_property_contexts / *_service_contexts / *_hwservice_contexts

用法：
  python tools/sepolicy_domain_audit.py --domain oplus_wifi_service --cil .build/sepolicy \
         --json .build/sepolicy/audit.json [--top 80] [--class file,dir,property_service]

设计约束：
  * 全部结论来自策略原文；无法解析的语句计数上报，不静默丢弃。
  * 类型名归一化：CIL 中同一类型会以 `X` 与 `X_30_0` 两种形式出现，统一去版本后缀。
  * 只读：不连接设备、不修改设备。
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

VER_SUFFIX = re.compile(r'_\d+_\d+$')


def canon(name):
    return VER_SUFFIX.sub('', name)


# ---------------------------------------------------------------- S-expression


def tokenize(text):
    stmts, stack, cur = [], [], []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == ';':
            j = text.find('\n', i)
            i = n if j < 0 else j + 1
            continue
        if c == '(':
            stack.append(cur)
            cur = []
            i += 1
        elif c == ')':
            if not stack:
                raise ValueError('unbalanced ) at %d' % i)
            done, cur = cur, stack.pop()
            cur.append(done)
            i += 1
        elif c in ' \t\r\n':
            i += 1
        else:
            j = i
            while j < n and text[j] not in ' \t\r\n()':
                j += 1
            cur.append(text[i:j])
            i = j
    while stack:
        done, cur = cur, stack.pop()
        cur.append(done)
    return cur if (cur and isinstance(cur[0], list)) else [cur]


def flatten(node):
    """CIL 集合表达式 -> (names, unknown)"""
    if isinstance(node, str):
        return {canon(node)}, []
    if not node:
        return set(), []
    head = node[0] if isinstance(node[0], str) else None
    if head == 'and':
        base, unknown = None, []
        for x in node[1:]:
            names, unk = flatten(x)
            unknown += unk
            base = names if base is None else (base & names)
        return (base or set()), unknown
    if head == 'or':
        out, unknown = set(), []
        for x in node[1:]:
            names, unk = flatten(x)
            out |= names
            unknown += unk
        return out, unknown
    if head in ('not', 'xor', 'range'):
        return set(), ['(%s ...)' % head]
    out, unknown = set(), []
    for x in node:
        names, unk = flatten(x)
        out |= names
        unknown += unk
    return out, unknown


# ---------------------------------------------------------------- 策略模型


class Policy:
    def __init__(self):
        self.attr_members = defaultdict(set)   # 属性 -> 直接成员（已归一化）
        self.attr_expr = {}                    # 属性 -> 原始表达式
        self.types = set()
        self.attrs = set()
        self.allows = []                       # (src, tgt, cls, frozenset(perms))
        self.transitions = []
        self.stats = defaultdict(int)
        self._closure = {}

    def load(self, path):
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
        for stmt in tokenize(text):
            self._feed(stmt)

    def _feed(self, node):
        if not isinstance(node, list) or not node:
            return
        head = node[0] if isinstance(node[0], str) else None
        if head is None:
            for sub in node:
                self._feed(sub)
            return
        self.stats[head] += 1
        if head == 'type' and len(node) >= 2 and isinstance(node[1], str):
            self.types.add(canon(node[1]))
        elif head == 'typeattribute' and len(node) >= 2 and isinstance(node[1], str):
            self.attrs.add(canon(node[1]))
        elif head == 'typeattributeset' and len(node) >= 3:
            if not isinstance(node[1], str):
                self.stats['!typeattributeset-noname'] += 1
                return
            a = canon(node[1])
            self.attrs.add(a)
            self.attr_expr[a] = node[2]
            names, unknown = flatten(node[2])
            for u in unknown:
                self.stats['!typeattributeset%s' % u] += 1
            self.attr_members[a] |= names
        elif head == 'allow' and len(node) >= 4:
            src, tgt, spec = node[1], node[2], node[3]
            if not isinstance(src, str) or not isinstance(tgt, str):
                self.stats['!allow-noname'] += 1
                return
            if isinstance(spec, list) and len(spec) >= 2 and isinstance(spec[0], str):
                cls = spec[0]
                perms, _ = flatten(spec[1])
                self.allows.append((canon(src), canon(tgt), cls, frozenset(perms)))
            else:
                self.stats['!allow-form'] += 1
        elif head == 'typetransition' and len(node) >= 5:
            self.transitions.append(tuple(canon(x) if isinstance(x, str) else '?' for x in node[1:5]))

    def closure(self, attr):
        if attr in self._closure:
            return self._closure[attr]
        seen, result = set(), set()

        def walk(a):
            if a in seen:
                return
            seen.add(a)
            names = set(self.attr_members.get(a, ()))
            expr = self.attr_expr.get(a)
            if isinstance(expr, list) and expr and isinstance(expr[0], str) and expr[0] in ('and', 'or', 'not', 'xor'):
                for sub in expr[1:]:
                    names |= flatten(sub)[0]
            for m in names:
                # 修正（2026-11-18）：CIL 中同一名字可能既是 type 又是 attribute
                # （shell / bluetooth / sensors / mediaserver …）。旧实现只对 attr 展开、
                # 不入结果集，导致这类成员被静默丢弃，经由它们继承的 allow 被漏计。
                # 正确语义：先计入成员集，若它本身也是属性则继续展开。
                result.add(m)
                if m in self.attrs:
                    walk(m)

        walk(attr)
        self._closure[attr] = result
        return result


# ---------------------------------------------------------------- 上下文文件


def load_ctx(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ty = parts[-1]
            m = re.match(r'u:object_r:([A-Za-z0-9_]+):s0', ty)
            out.append((parts[0], canon(m.group(1)) if m else canon(ty)))
    return out


# ---------------------------------------------------------------- 权限语义

WRITE = {
    'file': {'write', 'append', 'create', 'unlink', 'rename', 'setattr', 'relabelfrom',
             'relabelto', 'link', 'mounton', 'swapon', 'quotaon'},
    'dir': {'write', 'add_name', 'remove_name', 'create', 'rmdir', 'rename', 'setattr',
            'relabelfrom', 'relabelto', 'mounton', 'reparent'},
    'lnk_file': {'create', 'unlink', 'rename', 'setattr', 'relabelfrom', 'relabelto'},
    'sock_file': {'write', 'create', 'unlink', 'setattr', 'relabelfrom', 'relabelto', 'append'},
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

# 消费侧：真正比该 HAL 域权限更高的域（按需增删，避免把 shell/app 算进去）
CONSUMER_PRIORITY = [
    'init', 'vendor_init', 'ueventd', 'vold', 'installd', 'system_server', 'zygote',
    'servicemanager', 'hwservicemanager', 'vndservicemanager', 'netd', 'keystore',
    'surfaceflinger', 'audioserver', 'wificond', 'dumpstate', 'debuggerd',
]
CONSUMER_PREFIX = ('hal_', 'vendor_hal_', 'oppo_hal_')


def consumer_rank(src):
    if src in CONSUMER_PRIORITY:
        return 100 - CONSUMER_PRIORITY.index(src)
    if src.startswith(CONSUMER_PREFIX):
        return 10
    return 0


# ---------------------------------------------------------------- 主流程


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--domain', required=True)
    ap.add_argument('--cil', default='.build/sepolicy')
    ap.add_argument('--json')
    ap.add_argument('--top', type=int, default=60)
    ap.add_argument('--class', dest='classes', default=None, help='逗号分隔，只看这些 class')
    args = ap.parse_args()

    pol = Policy()
    loaded = []
    # 运行期策略由 5 份 CIL 合成：plat(+pub_versioned) / vendor / product / system_ext。
    # 只取非 debug 版本；漏掉 product/system_ext 会得出错误的"权限全集"（2026-11-18 踩坑）。
    cil_names = ['plat_sepolicy.cil', 'plat_pub_versioned.cil', 'vendor_sepolicy.cil',
                 'system_ext_sepolicy.cil', 'product_sepolicy.cil']
    for f in cil_names:
        p = os.path.join(args.cil, f)
        if os.path.exists(p):
            before = len(pol.allows)
            pol.load(p)
            loaded.append({'file': f, 'allow_added': len(pol.allows) - before})
    if not loaded:
        print('未找到 CIL 文件: %s' % args.cil, file=sys.stderr)
        return 2

    dom = canon(args.domain)
    dom_attrs = sorted(a for a in pol.attrs if dom in pol.closure(a))

    # 采集规则 + 溯源
    rules = []          # dict(src_raw, tgt, cls, perms, via)
    for src, tgt, cls, perms in pol.allows:
        if src == dom:
            rules.append({'via': 'direct', 'tgt': tgt, 'cls': cls, 'perms': perms})
        elif src in pol.attrs and dom in pol.closure(src):
            rules.append({'via': 'via:' + src, 'tgt': tgt, 'cls': cls, 'perms': perms})

    # 按 (cls,tgt) 合并
    merged = {}
    for r in rules:
        k = (r['cls'], r['tgt'])
        m = merged.setdefault(k, {'perms': set(), 'via': set(), 'direct': False})
        m['perms'] |= r['perms']
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

    # 消费侧索引：目标类型 -> [(src, cls, perms)]
    cons_index = defaultdict(list)
    for src, tgt, cls, perms in pol.allows:
        cons_index[(cls, tgt)].append((src, perms))

    def consumers(cls, tgt):
        out = []
        cands = [(tgt, None)]
        if tgt in pol.attrs:
            cands = [(m, None) for m in pol.closure(tgt)]
        for ct, _ in cands:
            for src, perms in cons_index.get((cls, ct), ()):
                if src == dom:
                    continue
                r = consumer_rank(src)
                if r <= 0:
                    continue
                if not (perms & {'read', 'open', 'getattr', 'execute', 'map', 'get', 'search'}):
                    continue
                out.append((r, src, sorted(perms)))
        out.sort(key=lambda x: -x[0])
        seen, uniq = set(), []
        for r, src, perms in out:
            if src in seen:
                continue
            seen.add(src)
            uniq.append({'src': src, 'perms': perms, 'rank': r})
        return uniq[:12]

    items = []
    for (cls, tgt), m in merged.items():
        wset = WRITE.get(cls)
        eff = sorted(m['perms'] & wset) if wset else []
        if not eff:
            continue
        it = {
            'class': cls, 'target': tgt, 'write_perms': eff,
            'all_perms': sorted(m['perms']),
            'direct': m['direct'],
            'via': sorted(v for v in m['via'] if v != 'direct')[:6],
            'paths': paths(tgt)[:10], 'props': props(tgt)[:14],
            'hwservices': hwsvc(tgt)[:6], 'services': svc(tgt)[:6],
            'consumers': consumers(cls, tgt),
        }
        items.append(it)

    order = {'capability': 0, 'capability2': 0, 'security': 1, 'system': 2,
             'property_service': 3, 'hwservice_manager': 4, 'service_manager': 5,
             'file': 6, 'dir': 7, 'sock_file': 8, 'chr_file': 9, 'lnk_file': 10,
             'process': 11, 'binder': 12}
    items.sort(key=lambda x: (order.get(x['class'], 20), -int(x['direct']), x['target']))

    if args.classes:
        keep = {c.strip() for c in args.classes.split(',')}
        items = [i for i in items if i['class'] in keep]

    result = {
        'domain': dom, 'cil_loaded': loaded,
        'statements': dict(sorted(pol.stats.items())),
        'allow_applicable': len(rules),
        'attrs_count': len(dom_attrs), 'attrs': dom_attrs,
        'types_total': len(pol.types), 'attrs_total': len(pol.attrs),
        'items': items,
    }

    # ---- 控制台输出
    print('域 %s | 策略语句 %d | 适用 allow %d | 所属属性 %d'
          % (dom, len(pol.allows), len(rules), len(dom_attrs)))
    print('解析告警: %s' % {k: v for k, v in pol.stats.items() if k.startswith('!')})
    print('由该域显式授予(direct)的规则目标数: %d' % sum(1 for k, v in merged.items() if v['direct']))
    print()
    for it in items[:args.top]:
        tag = 'D' if it['direct'] else 'A'
        loc = ''
        if it['class'] in ('file', 'dir', 'lnk_file', 'sock_file', 'chr_file'):
            loc = ' | '.join(it['paths'][:3]) or '(无 file_contexts 落点)'
        elif it['class'] == 'property_service':
            loc = ' | '.join(it['props'][:5]) or '(无 property_contexts 落点)'
        elif it['class'] == 'hwservice_manager':
            loc = ' | '.join(it['hwservices'][:3])
        elif it['class'] == 'service_manager':
            loc = ' | '.join(it['services'][:3])
        cons = ', '.join(c['src'] for c in it['consumers'][:5]) or '-'
        print('[%s] %-16s %-40s %-38s %s' % (
            tag, it['class'], it['target'], '/'.join(it['write_perms'])[:38], loc[:70]))
        if it['consumers']:
            print('     消费: %s' % cons[:120])

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=1)
        print('\nJSON: %s' % args.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
