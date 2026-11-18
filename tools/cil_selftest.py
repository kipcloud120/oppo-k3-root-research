#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cil_selftest.py —— 对 cil_policy.py 的集合语义做可复现的单元验证。

为什么要这一步：v2.23 的工具缺陷是"看起来在解析、实际语义错"，
因此修复本身必须有一套**先登记期望值、再跑**的用例，而不是靠"跑通了"。

用法：python tools/cil_selftest.py
退出码 0 = 全部通过；非 0 = 有不符预期项。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cil_policy import Policy, CilError  # noqa: E402

FIXTURE = """
(type ta) (type tb) (type tc) (type td)
(typeattribute A) (typeattribute B) (typeattribute domain)
(typeattribute Excl)
(typeattributeset A (or (ta) (tb)))
(typeattributeset B (tb td))
(typeattribute domain)
(typeattributeset domain (ta tb tc td))
(typeattributeset Excl (td))
"""

CASES = []


def case(name, got, want):
    CASES.append((name, got, want))


def build(semantics='cil'):
    p = Policy(semantics=semantics)
    p.load_text(FIXTURE)
    p.finalize()
    return p


def add(p, text):
    p.load_text(text)
    p.finalize()
    return p


def main():
    p = build()

    # 1 原子成员的传递展开
    case('expand(A) 含自身与直接成员',
         set(p.expand('A')), {'A', 'ta', 'tb'})
    case('expand(ta) 未声明表达式 ⇒ 单元素',
         set(p.expand('ta')), {'ta'})

    # 2 or
    add(p, "(typeattribute C) (typeattributeset C (or (A) (B)))")
    case('or = 并集（含属性引用展开）',
         set(p.expand('C')), {'C', 'A', 'ta', 'tb', 'B', 'td'})

    # 3 and —— 必须是交集，不是并集
    add(p, "(typeattribute I) (typeattributeset I (and (A) (ta)))")
    case('and = 交集（A∩{ta} = {ta}）',
         set(p.expand('I')), {'I', 'ta'})
    add(p, "(typeattribute J) (typeattributeset J (and (A) (B)))")
    case('and = 交集（A∩B = {tb}）',
         set(p.expand('J')), {'J', 'tb'})

    # 4 not —— 必须是全集补集，且被取反的名字不得成为成员
    add(p, "(typeattribute N) (typeattributeset N (not (Excl)))")
    univ = p.universe
    case('not = 全集 − 操作数', set(p.expand('N')), set(univ - {'Excl', 'td'}))
    case('not 的被取反名字不在结果里', 'td' in p.expand('N'), False)
    case('not 的补集覆盖了未参与运算的类型', 'ta' in p.expand('N'), True)

    # 4b and + not 的组合（本策略里 1,463 处的真实形态）
    add(p, "(typeattribute K) (typeattributeset K (and (domain) (not (Excl))))")
    case('and(domain, not Excl) = domain 成员 − Excl',
         set(p.expand('K')), {'K', 'domain', 'ta', 'tb', 'tc'})
    case('  └ td 被排除', 'td' in p.expand('K'), False)

    # 5 xor = 对称差
    add(p, "(typeattribute X) (typeattributeset X (xor (A) (B)))")
    case('xor = 对称差（A△B = {A,ta,td,B}）',
         set(p.expand('X')), {'X', 'A', 'ta', 'B', 'td'})

    # 6 all = 全集
    add(p, "(typeattribute Q) (typeattributeset Q (all))")
    case('all = 全集', set(p.expand('Q')), set(univ | {'C', 'I', 'J', 'N', 'K', 'X', 'Q'}))

    # 7 同一属性多条 typeattributeset 为累加
    add(p, "(typeattribute M) (typeattributeset M (ta)) (typeattributeset M (tb))")
    case('多条 typeattributeset 累加', set(p.expand('M')), {'M', 'ta', 'tb'})

    # 8 不支持的算子必须硬失败
    try:
        bad = Policy()
        bad.load_text("(type tz) (typeattribute R) (typeattributeset R (range (ta) (tz)))")
        bad.finalize()
        raise AssertionError('(range ...) 未被判定为审计失败')
    except CilError:
        case('(range ...) ⇒ CilError（审计失败）', True, True)

    # 8b allow_partial 下降级为"记录告警"，但必须留下记录
    partial = Policy(allow_partial=True)
    partial.load_text("(type tz) (typeattribute R) (typeattributeset R (range (ta) (tz)))")
    partial.finalize()
    case('allow_partial 仍留 err 记录', len(partial.errors) > 0, True)

    # 9 allow 查询：目标侧属性展开 + self 语义
    add(p, """
      (allow K ta (file (read write)))
      (allow A td (service_manager (find)))
      (allow domain self (process (transition)))
    """)
    r = p.perms('ta', 'ta')
    case('self 目标等价于 src==tgt', r.get('process'), {'transition'})
    r = p.perms('tb', 'ta')
    case('self 目标在 src!=tgt 时不命中', 'process' in r, False)
    r = p.perms('ta', 'td', 'service_manager')
    case('目标侧按属性展开：A⊇ta ⇒ ta→td 可 find',
         r.get('service_manager'), {'find'})
    r = p.perms('ta', 'td', 'file')
    case('类别过滤生效', r.get('file'), None)

    # 10 legacy 语义必须复现出 v2.23 的缺陷（证明缺陷真实存在，而非"改了也没差"）
    lg = build('legacy')
    add(lg, "(typeattribute K) (typeattributeset K (not (Excl)))")
    case('legacy：(not X) 把被取反的 td 当成成员（方向相反）',
         'td' in lg.expand('K'), True)
    case('legacy：且丢失了绝大多数真实成员（同时是下界）',
         'ta' in lg.expand('K'), False)
    cil = build('cil')
    add(cil, "(typeattribute K) (typeattributeset K (not (Excl)))")
    case('cil：同一表达式为全集补集', set(cil.expand('K')), set(cil.universe - {'Excl', 'td'}))

    # 11 版本化名字的三档处理（P0 的第二个独立缺陷）
    VFIX = """
    (type real) (type other) (typeattribute real_30_0)
    (typeattribute placeholder) (typeattribute placeholder_30_0)
    (typeattributeset placeholder (or (real)))
    (typeattributeset placeholder_30_0 (all))
    (allow real_30_0 placeholder_30_0 (binder (call)))
    """
    al = Policy(naming='alias')
    add(al, VFIX)
    case('alias：无成员定义的 X_30_0 并入 X', 'real_30_0' not in al.types, True)
    case('alias：vendor 侧规则因此对 real 生效',
         al.perms('real', 'real').get('binder'), {'call'})
    case('alias：自身有定义的占位保持独立（placeholder 不被撑满）',
         set(al.expand('placeholder')), {'placeholder', 'real'})

    ca = Policy(naming='canon')
    add(ca, VFIX)
    case('canon：((all)) 占位把无关类型 other 也并进基准属性（缺陷复现）',
         'other' in ca.expand('placeholder'), True)
    case('alias：同一属性不含无关类型 other（无污染）',
         'other' in al.expand('placeholder'), False)

    ex = Policy(naming='exact')
    add(ex, VFIX)
    case('exact：vendor 侧规则变成空规则',
         ex.perms('real', 'real').get('binder'), None)

    # ---- 汇总
    bad = 0
    for name, got, want in CASES:
        ok = (got == want)
        if not ok:
            bad += 1
        print('%-4s %-56s got=%r want=%r' % ('PASS' if ok else 'FAIL', name, got, want))
    print('\n%d/%d 通过' % (len(CASES) - bad, len(CASES)))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
