#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cil_policy.py —— Android CIL 策略的**正确**集合语义实现（离线，纯静态）

背景（2026-11-18，响应审核意见 v006 的 P0）：

  v2.23 的 `sepolicy_domain_audit.py` 有两处独立缺陷，此前被混在一起看：

  （1）集合语义
      `flatten()` 对 (not ...) / (xor ...) / (range ...) 一律返回空集 + 'unknown'；
      `Policy.closure()` 又把 and/or/not/xor 的**子项统一做并集**。
      后果：`(not X)` 里的 X 被当成该属性的**成员**；本策略 1,491 处 `not` 全部失真。

  （2）版本化名字
      plat_pub_versioned.cil 为 vendor 侧另建 `X_<api>_<minor>` 名字。旧脚本一律
      去后缀合并，于是 `(typeattributeset base_typeattr_179_30_0 ((all)))` 这类
      占位定义会把基准属性撑成"全类型"，规则扩散到所有对象（过授权）。

本模块把两者拆开处理，各自有可验证的判据：
  * 集合语义按 CIL Reference：原子 = {name} ∪ 该属性成员；
    and 交、or 并、xor 对称差、not 全集补、all 全集；
    不支持的算子（range 等）→ **审计失败**，不静默按空集处理。
  * 版本化名字三档（默认 'alias'），理由见 NAMING_MODES 注释。

自检：`python tools/cil_selftest.py`（22 例，含旧语义的缺陷复现）。
"""

import os
import re
from collections import defaultdict

VER_SUFFIX = re.compile(r'_\d+_\d+$')

SET_OPS = ('and', 'or', 'xor', 'not', 'all', 'range')

CIL_FILES = ['plat_sepolicy.cil', 'plat_pub_versioned.cil', 'vendor_sepolicy.cil',
             'system_ext_sepolicy.cil', 'product_sepolicy.cil']


class CilError(Exception):
    """策略中出现无法按 CIL 语义求值的构造 —— 审计失败，不得降级为"无权限"。"""


# ---------------------------------------------------------------- 版本化名字的三档
#
# plat_pub_versioned.cil 为 vendor 侧另建 `X_<api>_<minor>` 名字。它们在 CIL 里是
# 独立对象，但 Android 的意图是"指代同一个东西"——否则 vendor 策略里
#   (allow oplus_wifi_service system_server_30_0 (binder (call)))
# 会变成指向无人所属的空属性的空规则。
# 反之，若一律合并，`(typeattributeset base_typeattr_179_30_0 ((all)))` 这类
# 版本化占位会把基准属性撑成全类型，规则扩散到所有对象。
#
#   'canon' —— 一律去后缀合并（旧口径，含 ((all)) 污染）
#   'exact' —— 一律不合并（vendor 侧版本化规则失效）
#   'alias' —— 默认：仅当 `X_N_M` **自身没有任何成员定义**且存在基准 `X` 时，
#              视为 `X` 的别名；自身有定义者保持独立。
NAMING_MODES = ('alias', 'canon', 'exact')


def _dedup_suffix(name, mode):
    return VER_SUFFIX.sub('', name) if mode == 'canon' else name


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
                raise CilError('unbalanced ) at offset %d' % i)
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


def _collect_atoms(node, out, policy, allow_lists=False):
    """把权限段（可能嵌套列表，如 (file (read write))）摊平成原子集合。"""
    for x in node:
        if isinstance(x, str):
            out.add(x)
        elif isinstance(x, list):
            if allow_lists and x and isinstance(x[0], str) and x[0] == 'ioctl':
                out.add('ioctl:' + '|'.join(sorted(str(y) for y in x[1:])))
            else:
                _collect_atoms(x, out, policy, allow_lists)
        else:
            policy._fail('权限段出现非原子：%r' % (x,))


# ---------------------------------------------------------------- 策略模型

class Policy:
    """一份合并后的 CIL 策略。

    semantics='cil'    —— 正确语义（默认）
    semantics='legacy' —— 复刻 v2.23 旧脚本，仅用于 A/B 对照
    naming             —— 'alias'（默认） / 'canon' / 'exact'
    """

    def __init__(self, semantics='cil', naming='alias', allow_partial=False):
        if naming not in NAMING_MODES:
            raise ValueError('naming 必须是 %s' % (NAMING_MODES,))
        self.semantics = semantics
        self.naming = naming
        self.allow_partial = allow_partial

        self.types = set()
        self.attrs = set()
        self.attr_exprs = defaultdict(list)     # 属性 -> 全部 typeattributeset 表达式（累加）
        self.allows = []                        # (src, tgt, cls, frozenset(perms), origin)
        self.dontaudits = []
        self.allowx = []
        self.transitions = []
        self.errors = []
        self.counts = defaultdict(int)
        self._alias = {}

        self._finalized = False
        self._expand_cache = {}
        self._busy = set()
        self._attrs_of_cache = {}
        self._idx = None

    # ------------------------------------------------------------ 载入

    def load_dir(self, path, files=None):
        loaded = []
        for f in (files or CIL_FILES):
            p = os.path.join(path, f)
            if os.path.exists(p):
                before = len(self.allows)
                self.load_file(p)
                loaded.append({'file': f, 'allow_added': len(self.allows) - before})
        if not loaded:
            raise CilError('目录下没有可载入的 CIL：%s' % path)
        self.finalize()
        return loaded

    def load_file(self, path):
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
        for stmt in tokenize(text):
            self._feed(stmt)

    def load_text(self, text):
        for stmt in tokenize(text):
            self._feed(stmt)
        self._finalized = False

    # ------------------------------------------------------------ 语句解析（存原始名）

    def _feed(self, node):
        if not isinstance(node, list) or not node:
            return
        head = node[0] if isinstance(node[0], str) else None
        if head is None:
            for sub in node:
                self._feed(sub)
            return

        if head == 'type' and len(node) >= 2 and isinstance(node[1], str):
            self.types.add(node[1])
        elif head == 'typeattribute' and len(node) >= 2 and isinstance(node[1], str):
            self.attrs.add(node[1])
        elif head == 'typeattributeset' and len(node) >= 3:
            if not isinstance(node[1], str):
                self._fail('typeattributeset 的名字不是原子：%r' % (node[1],))
                return
            self.attrs.add(node[1])
            body = node[2] if len(node) == 3 else ['or'] + list(node[2:])
            self.attr_exprs[node[1]].append(body)
            self.counts['typeattributeset'] += 1
        elif head in ('allow', 'dontaudit', 'auditallow'):
            self._feed_allow(head, node)
        elif head in ('allowx', 'dontauditx', 'auditallowx'):
            self._feed_allowx(head, node)
        elif head == 'typetransition' and len(node) >= 5:
            self.transitions.append(tuple(x if isinstance(x, str) else '?'
                                          for x in node[1:5]))
        else:
            self.counts[head] += 1

    def _feed_allow(self, head, node):
        if len(node) < 4:
            self._fail('%s 参数不足：%r' % (head, node[:4]))
            return
        src, tgt = node[1], node[2]
        if not isinstance(src, str) or not isinstance(tgt, str):
            self._fail('%s 的源/目标不是原子：%r' % (head, node[:3]))
            return
        for spec in node[3:]:
            if not (isinstance(spec, list) and len(spec) >= 2 and isinstance(spec[0], str)):
                self._fail('%s 的类别段形态未知：%r' % (head, spec))
                continue
            perms = set()
            _collect_atoms(spec[1:], perms, self)
            rec = (src, tgt, spec[0], frozenset(perms))
            self.allows.append(rec + (head,))

    def _feed_allowx(self, head, node):
        if len(node) < 4:
            self._fail('%s 参数不足' % head)
            return
        src, tgt = node[1], node[2]
        if not isinstance(src, str) or not isinstance(tgt, str):
            self._fail('%s 的源/目标不是原子' % head)
            return
        for spec in node[3:]:
            if not (isinstance(spec, list) and len(spec) >= 2 and isinstance(spec[0], str)):
                self._fail('%s 的类别段形态未知：%r' % (head, spec))
                continue
            ops = set()
            _collect_atoms(spec[1:], ops, self, allow_lists=True)
            self.allowx.append((src, tgt, spec[0], frozenset(ops), head))

    def _fail(self, msg):
        if not self.allow_partial:
            raise CilError(msg)
        self.errors.append(msg)

    # ------------------------------------------------------------ 命名归一 + 校验

    def finalize(self):
        if self._finalized:
            return self
        self._apply_naming()
        self._finalized = True
        self._validate()
        return self

    def _apply_naming(self):
        mode = self.naming
        alias = {}

        if mode == 'alias':
            base_names = self.types | self.attrs
            for n in sorted(base_names):
                if not VER_SUFFIX.search(n):
                    continue
                base = VER_SUFFIX.sub('', n)
                # 只有"自身没有成员定义"的版本化名字才当作别名
                if n not in self.attr_exprs and base in base_names and base != n:
                    alias[n] = base

        def rn(n):
            if mode == 'canon':
                return VER_SUFFIX.sub('', n)
            return alias.get(n, n)

        def rn_expr(node):
            if isinstance(node, str):
                return rn(node)
            if isinstance(node, list):
                return [rn_expr(x) for x in node]
            return node

        self._alias = alias
        self.types = {rn(t) for t in self.types}
        self.attrs = {rn(a) for a in self.attrs}

        new_exprs = defaultdict(list)
        for a, exprs in self.attr_exprs.items():
            for e in exprs:
                new_exprs[rn(a)].append(rn_expr(e))
        self.attr_exprs = new_exprs

        def fix(rec):
            return (rn(rec[0]), rn(rec[1])) + tuple(rec[2:])

        self.allows = [fix(r) for r in self.allows]
        self.dontaudits = [fix(r) for r in self.dontaudits]
        self.allowx = [fix(r) for r in self.allowx]
        self.transitions = [tuple(rn(x) if x != '?' else '?' for x in t)
                            for t in self.transitions]
        self._expand_cache.clear()
        self._attrs_of_cache.clear()
        self._idx = None

    def _validate(self):
        if not self.types:
            self._fail('策略中没有任何 (type ...) 声明')
            return 0
        n = 0
        for a in sorted(self.attr_exprs):
            try:
                self.expand(a)
                n += 1
            except CilError:
                if not self.allow_partial:
                    raise
        self.counts['validated_attrs'] = n
        return n

    # ------------------------------------------------------------ 集合求值

    @property
    def universe(self):
        return frozenset(self.types | self.attrs)

    def expand(self, name):
        """原子 name 的取值：{name} ∪ 该属性的全部成员（若 name 是属性）。"""
        if name in self._expand_cache:
            return self._expand_cache[name]
        if self.semantics == 'legacy':
            out = self._legacy_expand(name)
            self._expand_cache[name] = out
            return out
        if name in self._busy:
            self._fail('属性定义成环：%s' % name)
            return frozenset([name])

        if name not in self.attrs or name not in self.attr_exprs:
            out = frozenset([name])
        else:
            self._busy.add(name)
            acc = {name}
            for expr in self.attr_exprs[name]:
                acc |= self._eval(expr)
            self._busy.discard(name)
            out = frozenset(acc)

        self._expand_cache[name] = out
        return out

    def _eval(self, node):
        if isinstance(node, str):
            return self.expand(node)
        if not node:
            return frozenset()
        head = node[0] if isinstance(node[0], str) else None

        if self.semantics == 'legacy':
            return self._legacy_eval(node)

        if head == 'and':
            sets = [self._eval(x) for x in node[1:]]
            if not sets:
                return self.universe
            out = sets[0]
            for s in sets[1:]:
                out = out & s
            return out
        if head == 'or':
            out = set()
            for x in node[1:]:
                out |= self._eval(x)
            return frozenset(out)
        if head == 'xor':
            out = frozenset()
            for x in node[1:]:
                out = out ^ self._eval(x)
            return out
        if head == 'not':
            out = set()
            for x in node[1:]:
                out |= self._eval(x)
            return self.universe - frozenset(out)
        if head == 'all':
            if len(node) > 1:
                self._fail('(all) 不接受参数：%r' % (node,))
            return self.universe
        if head == 'range':
            self._fail('不支持的集合算子 (range ...)：%r' % (node,))
            return frozenset()
        # 无算子的列表 = 隐式并集：(a b c)
        out = set()
        for x in node:
            out |= self._eval(x)
        return frozenset(out)

    # ------------------------------------------------------------ legacy 语义（仅对照）

    def _legacy_eval(self, node):
        """复刻 v2.23 的 flatten()：and/or 粗略处理，not/xor/range 丢空。"""
        if isinstance(node, str):
            return frozenset([node])
        if not node:
            return frozenset()
        head = node[0] if isinstance(node[0], str) else None
        if head == 'and':
            base = None
            for x in node[1:]:
                s = self._legacy_eval(x)
                base = s if base is None else (base & s)
            return base or frozenset()
        if head == 'or':
            out = set()
            for x in node[1:]:
                out |= self._legacy_eval(x)
            return frozenset(out)
        if head in ('not', 'xor', 'range'):
            return frozenset()
        out = set()
        for x in node:
            out |= self._legacy_eval(x)
        return frozenset(out)

    def _legacy_expand(self, name):
        """逐字复刻 v2.23 的 Policy.closure() + attr_members 的累加语义。

        v2.23 的实际行为是三段拼起来的，必须一起复刻才能对上已发布的数字：
          1. attr_members[a] = 各条 typeattributeset 经 flatten() 后的并集（累加）；
          2. 若**最后一条**表达式是 and/or/not/xor，再把 expr[1:] 各自 flatten 一遍并入；
          3. 对每个成员：计入结果，若它本身是属性则递归。
        与正确语义的差别即差异来源：(not X) 的 flatten 为空，第 2 步却把 X 及其成员并入，
        方向相反；且非最后一条语句的成员关系会被第 2 步的 dict 覆盖效应掩盖。
        """
        if name not in self.attrs:
            return frozenset([name])
        seen, result = set(), set()

        def walk(a):
            if a in seen:
                return
            seen.add(a)
            exprs = self.attr_exprs.get(a) or ()
            names = set()
            for e in exprs:                       # 第 1 段：累加
                names |= self._legacy_eval(e)
            if exprs:                             # 第 2 段：只用最后一条
                last = exprs[-1]
                if isinstance(last, list) and last and isinstance(last[0], str) \
                        and last[0] in ('and', 'or', 'not', 'xor'):
                    for sub in last[1:]:
                        names |= self._legacy_eval(sub)
            for m in names:                       # 第 3 段：递归
                result.add(m)
                if m in self.attrs:
                    walk(m)

        walk(name)
        return frozenset(result)

    # ------------------------------------------------------------ 查询

    def attrs_of(self, name):
        """哪些属性的取值集合里含 name（即 name 属于哪些属性）。"""
        if name in self._attrs_of_cache:
            return self._attrs_of_cache[name]
        out = {a for a in self.attrs if name in self.expand(a)}
        self._attrs_of_cache[name] = out
        return out

    def perms(self, src, tgt, cls=None, prov=False):
        """src 域对 tgt 类型在某类别下的权限并集（两侧均按属性展开判定）。"""
        out = defaultdict(set)
        vias = defaultdict(list)
        for r_src, r_tgt, r_cls, r_perms, origin in self.allows:
            if origin != 'allow':
                continue
            if cls and r_cls != cls:
                continue
            if r_src == src:
                pass
            elif r_src in self.attrs and src in self.expand(r_src):
                pass
            else:
                continue
            if r_tgt == tgt:
                pass
            elif r_tgt == 'self':
                if tgt != src:
                    continue
            elif r_tgt in self.attrs and tgt in self.expand(r_tgt):
                pass
            else:
                continue
            out[r_cls] |= r_perms
            vias[r_cls].append(('direct' if r_src == src else 'via:' + r_src, r_tgt))
        if prov:
            return {c: {'perms': set(out[c]), 'via': vias[c]} for c in out}
        return {c: set(v) for c, v in out.items()}

    def rules_for(self, domain):
        """该域适用的全部 allow 规则（含溯源）。"""
        idx = self._src_index()
        out, seen = [], set()

        def emit(ids):
            for i in ids:
                if i not in seen:
                    seen.add(i)
                    out.append(i)

        emit(idx.get(domain, ()))
        for a in self.attrs_of(domain):
            if a != domain:
                emit(idx.get(a, ()))

        res = []
        for i in out:
            r_src, r_tgt, r_cls, r_perms, origin = self.allows[i]
            res.append({'via': 'direct' if r_src == domain else 'via:' + r_src,
                        'tgt': r_tgt, 'cls': r_cls, 'perms': r_perms})
        return res

    def _src_index(self):
        if self._idx is None:
            idx = defaultdict(list)
            for i, r in enumerate(self.allows):
                if r[4] != 'allow':
                    continue
                idx[r[0]].append(i)
            self._idx = idx
        return self._idx

    def consumers_of(self, cls, tgt):
        """哪些域对 (cls,tgt) 持有读/执行类权限。"""
        out = []
        for r_src, r_tgt, r_cls, r_perms, origin in self.allows:
            if origin != 'allow' or r_cls != cls:
                continue
            if r_tgt != tgt and not (r_tgt in self.attrs and tgt in self.expand(r_tgt)):
                continue
            if r_perms & {'read', 'open', 'getattr', 'execute', 'map', 'get', 'search'}:
                out.append((r_src, sorted(r_perms)))
        return out

    # ------------------------------------------------------------ 诊断

    def stats(self):
        allows = [1 for a in self.allows if a[4] == 'allow']
        return {
            'semantics': self.semantics,
            'naming': self.naming,
            'types': len(self.types),
            'attrs_declared': len(self.attrs),
            'attrs_with_expr': len(self.attr_exprs),
            'attr_stmts': self.counts.get('typeattributeset', 0),
            'allows': len(allows),
            'dontaudits': len(self.dontaudits),
            'allowx': len(self.allowx),
            'errors': len(self.errors),
            'error_samples': self.errors[:8],
            'universe': len(self.types | self.attrs),
            'same_name_type_attr': len(self.types & self.attrs),
            'aliased': len(self._alias),
        }
