#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fastrpc_domain_gate.py —— FastRPC 设备节点在指定域下的可访问性判定（离线，纯静态）

用途：响应审核意见 CHATGPT-v005 的唯一 P0 建议 —— 把 CVE-2023-33063 的"封闭"结论
      从 shell(uid 2000) 身份扩展到 oplus_wifi_service(uid 0) 身份，并给出
      设备标签 → CIL 授权全集 → 判定 三段式证据。

判定口径（三层，任一层为否即不可达）：
  L1 标签层：/dev/adsprpc-smd* 在 file_contexts 中的类型；须与设备侧实测标签一致。
  L2 策略层：该域对目标类型的 chr_file 权限并集（direct + 全部所属属性），
             且**目标侧也要展开属性**（dev_type / base_typeattr_* 等），否则会漏掉
             `allow X dev_type (chr_file (open))` 这类规则。
  L3 遮蔽层：是否存在 dontaudit —— 若有，运行期"没看到 avc denied"不能当作放行证据。

注意：本脚本依赖 sepolicy_domain_audit.Policy 的闭包实现，该实现 2026-11-18 修正过
      「同名既是 type 又是 attribute」的静默丢弃缺陷；未修正版本会漏计 appdomain 继承。

用法：
  python tools/fastrpc_domain_gate.py --domain oplus_wifi_service \
         --cil .build/sepolicy --json .build/sepolicy/fastrpc_gate.json
  python tools/fastrpc_domain_gate.py --domain shell --targets qdsp_device,xdsp_device
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sepolicy_domain_audit import Policy, canon, load_ctx  # noqa: E402

DEFAULT_PATHS = ('/dev/adsprpc-smd', '/dev/adsprpc-smd-secure')
CIL_FILES = ['plat_sepolicy.cil', 'plat_pub_versioned.cil', 'vendor_sepolicy.cil',
             'system_ext_sepolicy.cil', 'product_sepolicy.cil']
CTX_FILES = ['plat_file_contexts', 'vendor_file_contexts', 'product_file_contexts',
             'system_ext_file_contexts']


def target_expand(pol, tgt):
    """目标类型自身 + 包含它的全部属性（用于匹配 'allow X <attr> (...)' 形式的规则）"""
    out = {tgt}
    for a in pol.attrs:
        if tgt in pol.closure(a):
            out.add(a)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--domain', required=True)
    ap.add_argument('--cil', default='.build/sepolicy')
    ap.add_argument('--paths', default=','.join(DEFAULT_PATHS))
    ap.add_argument('--targets', help='直接给类型名（逗号分隔），跳过 file_contexts 解析')
    ap.add_argument('--json')
    args = ap.parse_args()

    pol = Policy()
    loaded = []
    for f in CIL_FILES:
        p = os.path.join(args.cil, f)
        if os.path.exists(p):
            pol.load(p)
            loaded.append(f)

    dom = canon(args.domain)

    # ---- L1 标签层
    labels = []
    if args.targets:
        targets = sorted(canon(t) for t in args.targets.split(','))
        for t in targets:
            labels.append({'path': '(命令行指定)', 'type': t})
    else:
        fctx = []
        for f in CTX_FILES:
            fctx += load_ctx(os.path.join(args.cil, f))
        for pat in args.paths.split(','):
            hit = [(rx, ty) for rx, ty in fctx if rx == pat]
            labels.append({'path': pat, 'match': hit or None})
        targets = sorted({ty for e in labels for rx, ty in (e['match'] or [])})

    # ---- 域的属性归属
    dom_attrs = sorted(a for a in pol.attrs if dom in pol.closure(a))

    # ---- L2 策略层
    per_type = {}
    for tgt in targets:
        te = target_expand(pol, tgt)
        got = {'direct': [], 'via': [], 'via_target_attr': []}
        for src, t, cls, perms in pol.allows:
            if cls != 'chr_file' or t not in te:
                continue
            applies = (src == dom) or (src in pol.attrs and dom in pol.closure(src))
            if not applies:
                continue
            row = {'src': src, 'tgt': t, 'perms': sorted(perms)}
            if src == dom and t == tgt:
                got['direct'].append(row)
            elif src != dom:
                got['via'].append(row)
            else:
                got['via_target_attr'].append(row)
        union = set()
        for k in ('direct', 'via', 'via_target_attr'):
            for r in got[k]:
                union |= set(r['perms'])
        got['union'] = sorted(union)
        for p in ('open', 'ioctl', 'write', 'read'):
            got[p] = p in union
        got['target_attrs'] = sorted(te - {tgt})
        per_type[tgt] = got

    # ---- 全策略侧对照：谁有 open（证明规则确有、只是不含本域）
    holders = {}
    for tgt in targets:
        te = target_expand(pol, tgt)
        doms, attrs = [], []
        for src, t, cls, perms in pol.allows:
            if cls != 'chr_file' or t not in te or 'open' not in perms:
                continue
            if src in pol.attrs:
                attrs.append({'attr': src, 'member': dom in pol.closure(src)})
            else:
                doms.append(src)
        holders[tgt] = {'domains': sorted(set(doms)), 'attributes': attrs}

    # ---- L3 遮蔽层：dontaudit（Policy 不解析，直接扫原文）
    pat = re.compile(r'\(dontaudit\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s+\(chr_file\s+\(([^)]*)\)')
    dontaudits = []
    for f in CIL_FILES:
        p = os.path.join(args.cil, f)
        if not os.path.exists(p):
            continue
        txt = open(p, encoding='utf-8', errors='replace').read()
        for m in pat.finditer(txt):
            src, tgt2, perms = m.group(1), m.group(2), m.group(3).split()
            if any(t in target_expand(pol, tg) for tg in targets for t in [tgt2]):
                applies = (src == dom) or (src in pol.attrs and dom in pol.closure(src))
                dontaudits.append({'src': src, 'tgt': tgt2, 'perms': perms, 'applies': applies})

    # ---- allowx（ioctl 扩展权限，Android 用 xperm 区分具体 ioctl 号）
    allowx = []
    for f in CIL_FILES:
        p = os.path.join(args.cil, f)
        if not os.path.exists(p):
            continue
        for m in re.finditer(r'\(allowx\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s+\(ioctl\s+chr_file', 
                             open(p, encoding='utf-8', errors='replace').read()):
            src, tgt2 = m.group(1), m.group(2)
            te = set()
            for tg in targets:
                te |= target_expand(pol, tg)
            if tgt2 in te:
                applies = (src == dom) or (src in pol.attrs and dom in pol.closure(src))
                allowx.append({'src': src, 'tgt': tgt2, 'applies': applies})

    result = {
        'domain': dom, 'cil_loaded': loaded,
        'domain_attr_count': len(dom_attrs),
        'labels': labels, 'targets': targets,
        'per_type': per_type, 'holders': holders,
        'dontaudits': dontaudits, 'allowx': allowx,
        'allow_statements': len(pol.allows),
    }

    print('域 %s ｜ 策略 allow 语句 %d ｜ 所属属性 %d' % (dom, len(pol.allows), len(dom_attrs)))
    print()
    print('== L1 标签层 ==')
    for e in labels:
        if e.get('match'):
            for rx, ty in e['match']:
                print('  %-32s -> u:object_r:%s:s0' % (rx, ty))
        elif e.get('type'):
            print('  %-32s -> %s' % (e['path'], e['type']))
        else:
            print('  %-32s -> (无 file_contexts 匹配)' % e['path'])
    print()
    print('== L2 策略层（chr_file，目标侧已展开属性）==')
    for tgt in targets:
        g = per_type[tgt]
        print('  %s：并集=%s' % (tgt, g['union'] or '∅'))
        print('         open=%s ioctl=%s write=%s read=%s ｜ direct=%d via=%d via目标属性=%d'
              % (g['open'], g['ioctl'], g['write'], g['read'],
                 len(g['direct']), len(g['via']), len(g['via_target_attr'])))
        for r in (g['direct'] + g['via'] + g['via_target_attr'])[:6]:
            print('          %s -> %s: %s' % (r['src'], r['tgt'], ','.join(r['perms'])))
        if g['target_attrs']:
            print('         目标所属属性: %s' % ', '.join(g['target_attrs']))
    print()
    print('== 对照：全策略中对该类型有 open 权的源 ==')
    for tgt in targets:
        h = holders[tgt]
        print('  %s：显式域 %d 个 %s' % (tgt, len(h['domains']), h['domains']))
        if h['attributes']:
            inside = [a['attr'] for a in h['attributes'] if a['member']]
            print('     属性 %d 个，本域为其成员的：%s'
                  % (len(h['attributes']), inside or '无'))
    print()
    print('== L3 遮蔽层 ==')
    if not dontaudits:
        print('  无 dontaudit（denial 必被审计，运行期无 AVC 记录 ≠ 放行）')
    for d in dontaudits:
        print('  %s -> %s (%s) 适用于本域=%s' % (d['src'], d['tgt'], ','.join(d['perms']), d['applies']))
    print()
    print('== ioctl xperm（allowx）==')
    mine = [a for a in allowx if a['applies']]
    print('  涉及该类型的 allowx 共 %d 条，其中适用于本域 %d 条' % (len(allowx), len(mine)))

    verdict = 'NO-GO'
    for tgt in targets:
        g = per_type[tgt]
        if g['open'] or g['ioctl'] or g['write']:
            verdict = 'OPEN（%s 上存在授权）' % tgt
            break
    print()
    print('判定：%s' % verdict)

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=1)
        print('JSON: %s' % args.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
