#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kgsl_lifecycle.py — KGSL 内存对象（kgsl_mem_entry）生命周期取证。

目的（v12-K1）：把"谁在什么路径上持有/释放 mem_entry 引用"从源码推断变成
**本机二进制上的调用点清单**。不判断漏洞，只做四件事：

  1. **取/放点普查**：每个 kgsl_* 函数对 `kgsl_sharedmem_find*`（取引用）、
     `kgsl_mem_entry_destroy`（内联 kref_put 的归零分支）、`idr_*`、`kgsl_mem_entry_attach/detach_process`
     的直接调用点计数与地址。
  2. **pending_free 访问点**：结构体偏移由二进制反推（本机 0xb0，见 §61.2），
     统计每个函数对 `[xN, #0xb0]` 的读/写次数 —— 这是"待释放"状态的唯一门。
     ⚠️ 该统计是**按偏移的启发式**，不跟踪基址寄存器：同一偏移在其他结构体里可能是别的字段
     （实测假阳性：`kgsl_mem_entry_detach_process` 的 `[x8,#0xb0]` 其实是 `priv->stats[type]`，
     `kgsl_devfreq_target`/`kgsl_pwrscale_init` 同理）。判定前必须人工确认基址。
  3. **idr 归属图**：alloc / remove / replace / find / get_next 的分布，
     即 id→对象映射的建立与撤销只发生在哪些函数里。
  4. **不一致提示**：只标"取引用数 > 释放点数"之类的机械可疑项，不做结论。

用法:
  python tools/kgsl_lifecycle.py                # 汇总表
  python tools/kgsl_lifecycle.py --fn SYM       # 单函数明细
  python tools/kgsl_lifecycle.py --pending      # 只看 pending_free 访问点
"""
import argparse
import re
import sys

sys.path.insert(0, 'tools')
from kfn import Kernel  # noqa: E402

# 本机二进制反推（见 HANDOVER §61.2）：struct kgsl_mem_entry
OFF_REFCOUNT = 0x00      # kref
OFF_MEMDESC_FLAGS = 0x50  # memdesc.flags
OFF_PENDING_FREE = 0xb0  # int pending_free

FIND = {'kgsl_sharedmem_find', 'kgsl_sharedmem_find_id',
        'kgsl_sharedmem_find_id_flags'}
PUT = {'kgsl_mem_entry_destroy'}
IDR = {'idr_alloc', 'idr_alloc_cyclic', 'idr_remove', 'idr_replace',
       'idr_find_slowpath', 'idr_get_next', 'idr_for_each', 'idr_destroy',
       'idr_preload', 'idr_is_empty'}
ATTACH = {'kgsl_mem_entry_attach_process', 'kgsl_mem_entry_detach_process',
          'kgsl_mem_entry_commit_process'}

CATS = [('find', FIND), ('put', PUT), ('idr', IDR), ('att', ATTACH)]


def mem_refs(k, ins):
    """返回 [(offset, 'r'|'w', ins)]：对 [xN, #imm] 的访存，只保留关注偏移。"""
    out = []
    watch = {OFF_PENDING_FREE: 'pending_free'}
    for i in ins:
        m = re.search(r'\[(x\d+|sp|w\d+)(?:, #(0x[0-9a-f]+|\d+))?\]', i.op_str)
        if not m:
            continue
        off = int(m.group(2), 0) if m.group(2) else 0
        if off not in watch:
            continue
        kind = 'w' if i.mnemonic.startswith('st') else 'r'
        out.append((off, kind, i))
    return out


def scan(k, name, addr, size):
    ins = k.disas(addr, size)
    rec = {c: [] for c, _ in CATS}
    pend = []
    for i in ins:
        if i.mnemonic == 'bl' and i.operands and i.operands[0].type == 2:
            tgt = i.operands[0].imm & 0xFFFFFFFFFFFFFFFF
            tn = k.byaddr.get(tgt)
            if not tn:
                continue
            for cat, names in CATS:
                if tn in names:
                    rec[cat].append((i.address, tn))
        if i.mnemonic.startswith(('ldr', 'str', 'ldur', 'stur', 'ldxr', 'stxr',
                                  'ldaxr', 'stlxr', 'ldar', 'stlr', 'cbnz')):
            for off, kind, ins_i in mem_refs(k, [i]):
                pend.append((ins_i.address, kind, ins_i.mnemonic, ins_i.op_str))
    return rec, pend


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--fn')
    ap.add_argument('--pending', action='store_true')
    ap.add_argument('--min', type=int, default=1)
    a = ap.parse_args()
    k = Kernel()

    # KGSL 的静态辅助函数不带 kgsl_ 前缀（sparse_* / gpuobj_* / gpumem_* / _deferred_put），
    # 一并纳入，否则"取/放配对"会在函数边界处断链。
    rx = re.compile(r'^(kgsl|sparse|gpuobj|gpumem|mem_entry|_deferred|_sparse)')
    names = [n for n in k.byname if rx.match(n)]
    if a.fn:
        names = [n for n in names if a.fn in n]

    rows = []
    for n in sorted(names):
        if n == 'kgsl_mem_entry_destroy':
            continue
        addr, size = k.byname[n]
        rec, pend = scan(k, n, addr, size)
        rows.append((n, addr, rec, pend))

    if a.pending:
        print('== pending_free([xN,#0x%x]) 访问点 ==' % OFF_PENDING_FREE)
        for n, addr, rec, pend in rows:
            if not pend:
                continue
            w = sum(1 for p in pend if p[1] == 'w')
            print('%-46s 读%2d 写%2d  %s' % (n, len(pend) - w, w,
                  ', '.join('0x%x:%s' % (p[0], p[1]) for p in pend[:6])))
        return

    print('== KGSL mem_entry 生命周期调用点普查（本机 vmlinux.elf）==')
    print('%-46s %4s %4s %4s %4s  %s' % ('function', 'find', 'put', 'idr', 'att', 'note'))
    tot = dict((c, 0) for c, _ in CATS)
    flags = []
    for n, addr, rec, pend in rows:
        cnt = dict((c, len(rec[c])) for c, _ in CATS)
        if sum(cnt.values()) < a.min:
            continue
        for c in cnt:
            tot[c] += cnt[c]
        note = []
        if cnt['find'] > cnt['put']:
            note.append('find>put')
        w = sum(1 for p in pend if p[1] == 'w')
        if w:
            note.append('pend_w=%d' % w)
        if note:
            flags.append(n)
        print('%-46s %4d %4d %4d %4d  %s' % (n, cnt['find'], cnt['put'],
              cnt['idr'], cnt['att'], ' '.join(note)))
    print('\n合计: find=%d put=%d idr=%d att=%d' %
          (tot['find'], tot['put'], tot['idr'], tot['att']))
    if flags:
        print('机械可疑（需人工判读，不等于缺陷）：' + ', '.join(flags))
    return 0


if __name__ == '__main__':
    sys.exit(main())
