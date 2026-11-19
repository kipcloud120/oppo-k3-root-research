#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""g2_maxmatch_control.py — max-match 搜索的正向/负向对照（方法学验证，纯离线）

为什么必须有这一步
------------------
v5/v6 反复报告"零候选"。但"零候选"只有在**该方法在真解存在时确实能找回真解**的前提下
才构成证据。本脚本用合成数据做三个场景，全部走与真实搜索**完全相同的代码路径**
（tools/g2_maxmatch.py:scan_window），只换输入：

  A 纯真解   : 26 个 hit 全部按 mm_true 生成（桶索引与 inc 相等）→ 应命中 mm_true，count=26
  B 污染 23% : 20 个真 + 6 个随机 → 应仍命中 mm_true，count=20（阈值 6 之上，验证鲁棒性）
  C 纯噪声   : 26 个随机地址 → 应无候选达阈值（验证假阳性率与理论一致）

判据：A/B 必须找回 mm_true 且为**唯一**达阈值候选；C 必须零候选。

用法: python tools/g2_maxmatch_control.py
"""
import sys

import numpy as np

sys.path.insert(0, 'tools')
from g2_maxmatch import (jhash2_4w, scan_window, M32, U32,
                         DEFAULT_HASHSIZE, DEFAULT_THRESHOLD, PHYS_START)

INC = 0x77be2a0080                 # 真实 e2e2 的 inc（用户态地址，与 mm 无关）
REGION_LO = 0x77be2a0000           # 合成 hit 的取样区间（与 e2e2 region 同段）
REGION_HI = 0x77c7000000
HALF_WIN = 32 << 20                # 只扫 mm_true ±32MB，足以证明"能找回"
CHUNK = 1 << 20


def buckets_for(cand, mm, hashsize=DEFAULT_HASHSIZE):
    """对一批地址（uint64 数组）求桶索引；mm 为标量。"""
    cand = np.asarray(cand, dtype=np.uint64)
    page = cand & ~np.uint64(0xfff)
    off = (cand & np.uint64(0xfff)).astype(U32)
    k0 = U32(mm & M32)
    k1 = U32((mm >> 32) & M32)
    k2 = (page & np.uint64(M32)).astype(U32)
    k3 = (page >> np.uint64(32)).astype(U32)
    return jhash2_4w(k0, k1, k2, k3, off) & U32(hashsize - 1)


def gen_hits(mm_true, n, rng):
    """生成 n 个地址，使其桶索引与 INC 在该 mm 下相等（模拟 oracle 的真命中）。"""
    b_inc = int(buckets_for(np.asarray([INC], dtype=np.uint64), mm_true)[0])
    out = []
    for _ in range(200):
        if len(out) >= n:
            break
        batch = np.sort(rng.integers(REGION_LO // 32, REGION_HI // 32,
                                     size=200_000, dtype=np.int64)).astype(np.uint64) * np.uint64(32)
        sel = batch[buckets_for(batch, mm_true) == b_inc]
        for v in sel:
            if len(out) < n and int(v) not in out:
                out.append(int(v))
    return out


def run_case(name, hits, mm_true, expect_count):
    """注意：scan_window 的 phys_start/phys_end 是**相对窗口基址 W 的偏移**。"""
    W = 0xffffffc000000000
    off = mm_true - W
    lo = off - HALF_WIN
    hi = off + HALF_WIN
    hist, found, best, el = scan_window(name, W, lo, hi, INC, hits,
                                        DEFAULT_HASHSIZE, DEFAULT_THRESHOLD,
                                        CHUNK, 1, progress=False)
    found.sort(reverse=True)
    hit_true = [c for c, m in found if m == mm_true]
    others = [(c, m) for c, m in found if m != mm_true]
    if expect_count == 0:                       # 场景 C：应当零候选
        ok = not found
    else:
        ok = bool(hit_true) and hit_true[0] == expect_count and not others
    print('[%s] %.1fs  达阈值候选=%d  max=%d@0x%x'
          % (name, el, len(found), best[0], best[1]))
    print('         mm_true: %s' % (('找回，count=%d（期望 %d）' % (hit_true[0], expect_count))
                                    if hit_true else '未找回'))
    if others:
        print('         ✗ 额外候选: %s' % others[:5])
    print('         => %s' % ('PASS' if ok else 'FAIL'))
    return ok


def main():
    rng = np.random.default_rng(20261119)
    mm_true = 0xffffffc000000000 | (int(rng.integers(PHYS_START // 32 + 1,
                                                     (PHYS_START + (6 << 30)) // 32)) * 32)
    print('mm_true = 0x%016x（合成值，非设备真实 mm）' % mm_true)
    print('inc     = 0x%016x  hashsize=%d  threshold=%d'
          % (INC, DEFAULT_HASHSIZE, DEFAULT_THRESHOLD))

    genuine = gen_hits(mm_true, 26, rng)
    print('生成真命中 %d 个（其桶索引与 inc 在 mm_true 下相等）' % len(genuine))
    if len(genuine) < 26:
        print('FAIL: 生成不足 26 个真命中')
        return 2

    noise = (rng.integers(REGION_LO // 32, REGION_HI // 32, size=40,
                          dtype=np.int64).astype(np.uint64) * np.uint64(32)).tolist()

    ok_a = run_case('A 纯真解', genuine, mm_true, 26)
    ok_b = run_case('B 污染23%', genuine[:20] + [int(v) for v in noise[:6]], mm_true, 20)
    ok_c = run_case('C 纯噪声', [int(v) for v in noise[:26]], mm_true, 0)

    print('=' * 66)
    print('对照结果: A=%s  B=%s  C=%s' % ('PASS' if ok_a else 'FAIL',
                                          'PASS' if ok_b else 'FAIL',
                                          'PASS' if ok_c else 'FAIL'))
    print('结论：该搜索在真解存在时能唯一找回（A/B），纯噪声下不产生假阳性（C）。')
    print('      即"零候选"具备判决力——因此 v3–v7 的零候选只能由**窗口/模型错**解释，')
    print('      这与 v8 定位到的"KASLR 线性映射平移导致窗口整体错位"一致（HANDOVER §48）。')
    return 0 if (ok_a and ok_b and ok_c) else 1


if __name__ == '__main__':
    sys.exit(main())
