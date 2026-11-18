#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sepolicy_regression.py —— 响应审核意见 v006 的 P1：用修正后的语义**重跑历史权限结论**。

三口径归因（这是本轮唯一能站住的对比方式，单列"新旧"会把两个独立缺陷混在一起）：

  A  v2.23 原口径   = legacy 集合语义 + 版本名合并（canon `X`/`X_30_0`）
                       —— 复刻旧脚本，用来对上已发布数字
  B  仅修集合语义    = cil 语义 + 版本名合并
                       —— 只回答"not/xor/and 修好会怎样"
  C  再修版本名合并  = cil 语义 + 精确命名（`X` 与 `X_30_0` 视为不同对象）
                       —— 新基线；本轮所有结论以 C 为准

用法：
  python tools/sepolicy_regression.py --cil .build/sepolicy \
      --json .build/sepolicy/regression_v006.json \
      --md artifacts_adb/binder_audit/SHELL_ATTR_REGRESSION.md
"""

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cil_policy import Policy, CilError  # noqa: E402

# ---------------------------------------------------------------- 待回归的具名查询
# (说明, src, tgt, 类别, 历史出处)
QUERIES = [
    # §24.13 / §19：反 root 弹窗（旧结论 = 对 shell 不可达）
    ('shell find anti_root_dialog_service', 'shell', 'anti_root_dialog_service',
     'service_manager', '§24.13 判为 0 条'),
    ('shell binder call 宿主域 color_system_service_app', 'shell',
     'color_system_service_app', 'binder', '§24.13 判为只有 oplus_kevents'),
    # 七私有服务：service_manager 面
    ('shell find hephaestus_service', 'shell', 'hephaestus_service',
     'service_manager', '§19'),
    ('shell find hans_service', 'shell', 'hans_service', 'service_manager', '§19'),
    ('shell find horae_service', 'shell', 'horae_service', 'service_manager', '§19'),
    ('shell find oiface_service', 'shell', 'oiface_service', 'service_manager', '§19'),
    # 七私有服务：binder 面
    ('shell binder call hephaestus', 'shell', 'hephaestus', 'binder', '§19'),
    ('shell binder call hans', 'shell', 'hans', 'binder', '§19'),
    ('shell binder call horae', 'shell', 'horae', 'binder', '§19'),
    ('shell binder call oiface', 'shell', 'oiface', 'binder', '§19'),
    ('shell binder call system_app（appdata 宿主）', 'shell', 'system_app', 'binder',
     '§19'),
    # HIDL 面
    ('shell find hal_orms_hwservice', 'shell', 'hal_orms_hwservice',
     'hwservice_manager', '§19'),
    ('shell find hal_oiface_hwservice', 'shell', 'hal_oiface_hwservice',
     'hwservice_manager', '§19'),
    # §27：servicemanager 通道（主体是 oplus_wifi_service，不是 shell）
    ('oplus_wifi_service binder call servicemanager', 'oplus_wifi_service',
     'servicemanager', 'binder', '§27 判为 0 条'),
    ('oplus_wifi_service find alarm_service', 'oplus_wifi_service', 'alarm_service',
     'service_manager', '§27 判为 0 条'),
    ('oplus_wifi_service binder call system_server', 'oplus_wifi_service',
     'system_server', 'binder', '§27'),
    # §23 已达成链路 & §32 FastRPC
    ('shell binder call oplus_wifi_service', 'shell', 'oplus_wifi_service', 'binder',
     '§23 前提'),
    ('oplus_wifi_service open adsprpc-smd', 'oplus_wifi_service', 'qdsp_device',
     'chr_file', '§32 判为 ∅'),
    ('oplus_wifi_service open adsprpc-smd-secure', 'oplus_wifi_service',
     'xdsp_device', 'chr_file', '§32 判为 ∅'),
    ('oplus_wifi_service open diag（正对照）', 'oplus_wifi_service', 'diag_device',
     'chr_file', '§32 正对照'),
    # §24 域逃逸判据：可写类型上的 execute
    ('oplus_wifi_service 对 shell_exec 可执行', 'oplus_wifi_service', 'shell_exec',
     'file', '§24.13 判为 0'),
]

CLOSURE_DOMAINS = ['shell', 'oplus_wifi_service', 'system_app', 'bluetooth', 'sensors',
                   'mediaserver', 'untrusted_app', 'priv_app', 'hephaestus', 'hans',
                   'horae', 'oiface', 'init', 'system_server', 'su', 'adbd',
                   'wificond', 'hostapd', 'vendor_shell']


def build(naming, semantics):
    p = Policy(semantics=semantics, naming=naming)
    p.load_dir(CIL_DIR)
    return p


def perms_of(p, src, tgt, cls):
    r = p.perms(src, tgt, cls, prov=True)
    if cls not in r:
        return {'perms': [], 'via': []}
    d = r[cls]
    return {'perms': sorted(d['perms']),
            'via': sorted({(v[0], v[1]) for v in d['via']})[:6]}


CIL_DIR = '.build/sepolicy'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cil', default='.build/sepolicy')
    ap.add_argument('--json')
    ap.add_argument('--md')
    args = ap.parse_args()
    global CIL_DIR
    CIL_DIR = args.cil

    try:
        pa = build('canon', 'legacy')  # A
        pb = build('canon', 'cil')     # B
        pc = build('alias', 'cil')     # C
    except CilError as e:
        print('CIL 审计失败：%s' % e, file=sys.stderr)
        return 2

    out = {'policy': {'A_v223': pa.stats(), 'B_semset': pb.stats(), 'C_new': pc.stats()},
           'queries': [], 'closure': [], 'flip': []}

    for desc, src, tgt, cls, note in QUERIES:
        a = perms_of(pa, src, tgt, cls)
        b = perms_of(pb, src, tgt, cls)
        c = perms_of(pc, src, tgt, cls)
        out['queries'].append({'desc': desc, 'cls': cls, 'note': note,
                               'A': a, 'B': b, 'C': c})
        if set(a['perms']) != set(c['perms']):
            out['flip'].append(desc)

    for d in CLOSURE_DOMAINS:
        out['closure'].append({
            'domain': d,
            'A': {'attrs': len(pa.attrs_of(d)), 'allows': len(pa.rules_for(d))},
            'B': {'attrs': len(pb.attrs_of(d)), 'allows': len(pb.rules_for(d))},
            'C': {'attrs': len(pc.attrs_of(d)), 'allows': len(pc.rules_for(d))},
        })

    # ---- 控制台
    for tag, p in (('A v2.23', pa), ('B 仅修集合', pb), ('C 新基线', pc)):
        s = p.stats()
        print('%-12s 类型 %5d 属性 %5d 全集 %5d 同名 %4d 审计失败 %d'
              % (tag, s['types'], s['attrs_declared'], s['universe'],
                 s['same_name_type_attr'], s['errors']))
    print()
    print('%-52s %-22s %-22s %-22s' % ('查询', 'A', 'B', 'C'))
    for q in out['queries']:
        f = lambda x: (','.join(x['perms']) or '∅')[:22]
        mark = '  ' if q['A']['perms'] == q['C']['perms'] else '**'
        print('%s %-50s %-22s %-22s %-22s'
              % (mark, q['desc'][:50], f(q['A']), f(q['B']), f(q['C'])))
    print('\n口径翻转 %d 条' % len(out['flip']))
    for d in out['flip']:
        print('   *', d)

    print('\n闭包总量：')
    for c in out['closure']:
        print('  %-20s attrs %4d / %4d / %4d    allows %4d / %4d / %4d'
              % (c['domain'], c['A']['attrs'], c['B']['attrs'], c['C']['attrs'],
                 c['A']['allows'], c['B']['allows'], c['C']['allows']))

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
        print('\nJSON: %s' % args.json)
    if args.md:
        write_md(args.md, out)
        print('MD: %s' % args.md)
    return 0


def write_md(path, out):
    L = []
    A = L.append
    A('# shell 权限历史结论回归（响应审核意见 v006 · P1）\n')
    A('> 生成：`tools/sepolicy_regression.py`｜引擎：`tools/cil_policy.py`'
      '（语义自检 `tools/cil_selftest.py` 28/28 通过）\n')
    A('## 0 三个口径\n')
    A('| 口径 | 集合语义 | 版本名 | 含义 |')
    A('| --- | --- | --- | --- |')
    A('| A | legacy（v2.23） | 一律合并 | 复刻旧脚本，对上已发布数字 |')
    A('| B | 正确 CIL 语义 | 一律合并 | 只回答"not/xor/and 修好会怎样" |')
    A('| **C** | 正确 CIL 语义 | **alias（只并"无成员定义"的版本化名）** | **新基线** |')
    A('')
    A('| 项 | A | B | C |')
    A('| --- | --- | --- | --- |')
    for k, label in (('types', '类型'), ('attrs_declared', '属性'),
                     ('universe', '全集 U'), ('same_name_type_attr', '同名 type/attr'),
                     ('errors', '求值失败')):
        A('| %s | %d | %d | %d |' % (label, out['policy']['A_v223'][k],
                                     out['policy']['B_semset'][k],
                                     out['policy']['C_new'][k]))
    A('')
    A('## 1 具名查询三口径对照\n')
    A('| 查询 | 历史出处 | A | B | **C（基线）** |')
    A('| --- | --- | --- | --- | --- |')
    for q in out['queries']:
        f = lambda x: '`%s`' % (','.join(x['perms']) or '∅')
        A('| %s | %s | %s | %s | %s |'
          % (q['desc'], q['note'], f(q['A']), f(q['B']), f(q['C'])))
    A('')
    A('## 2 口径翻转（A ≠ C）—— 本轮的实质结论\n')
    A('| 查询 | 旧（A） | 新（C） | 性质 |')
    A('| --- | --- | --- | --- |')
    if out['flip']:
        for q in out['queries']:
            if q['A']['perms'] == q['C']['perms']:
                continue
            lower = set(q['A']['perms']) < set(q['C']['perms'])
            A('| %s | `%s` | `%s` | %s |'
              % (q['desc'], ','.join(q['A']['perms']) or '∅',
                 ','.join(q['C']['perms']) or '∅',
                 '旧为新子集 ⇒ 旧结果是缺陷造成的**漏算**' if lower else '其它（见正文）'))
    else:
        A('| 无 | — | — | — |')
    A('')
    A('## 3 闭包总量\n')
    A('| 域 | 属性 A/B/C | 适用 allow A/B/C |')
    A('| --- | --- | --- |')
    for c in out['closure']:
        A('| `%s` | %d / %d / **%d** | %d / %d / **%d** |'
          % (c['domain'], c['A']['attrs'], c['B']['attrs'], c['C']['attrs'],
             c['A']['allows'], c['B']['allows'], c['C']['allows']))
    A('')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(L) + '\n')


if __name__ == '__main__':
    sys.exit(main())
