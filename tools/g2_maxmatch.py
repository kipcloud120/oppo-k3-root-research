#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""g2_maxmatch.py v3 — 桶索引最大匹配 G2 搜索（v009 审核修正 + 多进程并行）

== v1 的缺陷（v009 P0，已确认） ==
v1 的 hash_va() 返回完整 32 位 jhash2 结果，后续用 `==` 比较。
但设备侧 oracle 与 live_probe/e2e2_probe.c:hash_from() 的判据是
        bucket = jhash2(...) & (futex_hashsize - 1)        # hashsize=2048 -> & 0x7ff
即"桶索引相同"，不是"哈希值相同"。

后果（比审核意见描述更严重）：真 mm 只能保证 26 个 hit 与 inc 同桶，
其完整 32 位哈希几乎必然互不相等；因此 v1 连真 mm 也判为候选外，
必然输出"零命中"。该输出对 G2 不具任何判决力，v1 的统计注释
（随机期望 26/2048）也与之自相矛盾（那是桶索引模型的期望）。
（v2 selftest 已量化：同一区域 20000 个样本中，full-hash 相等 0 次、同桶 13 次。）

== v3 ==
  bucket(x, mm) = jhash2(k=[mm_lo,mm_hi,pg_lo,pg_hi], 4, off=x&0xfff) & (hashsize-1)
  count(mm)     = #{ hit_i : bucket(hit_i,mm) == bucket(inc,mm) }
  H0（mm 为随机地址）: count ~ Binomial(n_hits, 1/hashsize)，E = n_hits/2048 ≈ 0.0127

判决阈值：默认 6。P(单个随机候选 count>=6) ≈ C(26,6)·2048^-6 ≈ 2.4e-16；
本搜索空间 2×235M 候选 ⇒ 期望假阳性 < 1e-7。故 count>=6 的候选若出现，
即为强候选（真 mm 若 26 个 hit 全真，count=26）。

无解的解释边界：若模型与窗口均无错且无候选达到 k，则 26 个 hit 中
"与同一 mm 同桶"的真 hit 数 ≤ k-1 —— 这是可证伪的污染量化，而非否定 G1。

用法:
  python tools/g2_maxmatch.py --selftest              # 三方对拍（numpy / C 转录 / 逐指令模拟器）
  python tools/g2_maxmatch.py                         # 双窗口全搜索（默认多进程）
  python tools/g2_maxmatch.py --jobs 1                # 单进程（调试）
  python tools/g2_maxmatch.py --hashsize 1024 --threshold 5
"""
import argparse
import os
import random
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

import numpy as np

M32 = 0xFFFFFFFF
U32 = np.uint32
DEFAULT_HASHSIZE = 2048
DEFAULT_THRESHOLD = 6
RESULT = 'live_probe/ks_e2e2_result.txt'

# 私有 futex 走 get_futex_key 的 !fshared 快路径：key->both.offset = address % PAGE_SIZE，
# **不加标志位**（futex.c 的 `offset |= FUT_OFF_MMSHARED` 只出现在 PageAnon 的 shared 分支，
# 对应二进制 0xffffff8008162138 的 orr #2）。故默认 seed_flag=0。
MM_SHARED_FLAG = 0

# 默认扫**整个线性映射区**（PAGE_OFFSET 起 256 GB）。
# 教训（§48）：memstart_addr 被 KASLR 以 1 GB 为单位下移，本次开机约 100–105 GB，
# 故任何"PAGE_OFFSET + 小偏移"的窗口都可能整体落空；64 B 粒度 256 GB = 4.29 G 候选（≈19 min）。
PHYS_START = 0
PHYS_END = 0x4000000000


# ---------------------------------------------------------------- 核心哈希
def _rol(w, s):
    r = (w << s) | (w >> (32 - s))
    if isinstance(r, np.ndarray):
        return r.astype(U32)
    return U32(int(r) & M32)


def jhash2_4w(k0, k1, k2, k3, seed):
    """jhash2(length=4) 向量化实现；k0..k3 可为 uint32 标量或数组，seed 同。

    与 e2e2_probe.c:jhash2() 语义一致：init = 0xdeadbeef + (4<<2) + seed。
    内联块中 movz 0xdeadbeff 即编译器对 0xdeadbeef+16 的折叠（§45.3）。
    """
    with np.errstate(over='ignore'):        # uint32 回绕是算法语义的一部分
        init = (U32(0xdeadbeef + 16) + np.asarray(seed, dtype=U32))
        a = (k0 + init)
        b = (k1 + init)
        c = (k2 + init)
        a = (a - c); a = (a ^ _rol(c, 4));  c = (c + b)
        b = (b - a); b = (b ^ _rol(a, 6));  a = (a + c)
        c = (c - b); c = (c ^ _rol(b, 8));  b = (b + a)
        a = (a - c); a = (a ^ _rol(c, 16)); c = (c + b)
        b = (b - a); b = (b ^ _rol(a, 19)); a = (a + c)
        c = (c - b); c = (c ^ _rol(b, 4));  b = (b + a)
        a = (a + k3)                        # tail: length=4 余 1 字
        c = (c ^ b); c = (c - _rol(b, 14))
        a = (a ^ c); a = (a - _rol(c, 11))
        b = (b ^ a); b = (b - _rol(a, 25))
        c = (c ^ b); c = (c - _rol(b, 16))
        a = (a ^ c); a = (a - _rol(c, 4))
        b = (b ^ a); b = (b - _rol(a, 14))
        c = (c ^ b); c = (c - _rol(b, 24))
    return c


def seed_of(va, seed_flag=MM_SHARED_FLAG):
    """key->both.offset = (va % PAGE_SIZE) | FUT_OFF_MMSHARED（私有 futex）。

    v1–v3 一直用 va & 0xfff（无标志位）作种子，是系统性模型错误：
    源码 futex.c:629 `key->both.offset |= FUT_OFF_MMSHARED` 与二进制
    `0xffffff8008162138: orr w8, w8, #2` 一致。种子差 2 ⇒ 哈希完全不同。
    """
    return (int(va) & 0xfff) | seed_flag


def hash_va(va, mm, seed_flag=MM_SHARED_FLAG):
    """完整 32 位 jhash2（未掩码）。mm 可为 uint64 数组。"""
    va = int(va)
    mm = np.asarray(mm, dtype=np.uint64)
    page = va & ~0xfff
    k0 = (mm & np.uint64(M32)).astype(U32)
    k1 = (mm >> np.uint64(32)).astype(U32)
    return jhash2_4w(k0, k1, U32(page & M32), U32((page >> 32) & M32),
                     seed_of(va, seed_flag))


def bucket_va(va, mm, hashsize=DEFAULT_HASHSIZE, seed_flag=MM_SHARED_FLAG):
    """桶索引（设备 oracle 的实际判据）。"""
    return hash_va(va, mm, seed_flag) & U32(hashsize - 1)


def bucket_from_ab(k0, k1, va, hashsize, seed_flag=MM_SHARED_FLAG):
    """由预计算的候选 mm 低/高 32 位（k0/k1 数组）求桶索引。

    逐 hit 只做 32 位运算，省去重复的 uint64 拆字（k0/k1 每 chunk 只算一次）。
    MODEL 用于模型变体筛查（key->both.ptr 的取值方式）。
    """
    va = int(va)
    m = MODEL[0]
    if m == 'full':
        p = va
    elif m == 'pfn':
        p = va >> 12
    else:
        p = va & ~0xfff
    k2 = U32(p & M32)
    k3 = U32((p >> 32) & M32)
    seed = seed_of(va, seed_flag)
    if m == 'swap':
        return jhash2_4w(k2, k3, k0, k1, seed) & U32(hashsize - 1)
    return jhash2_4w(k0, k1, k2, k3, seed) & U32(hashsize - 1)


# ---------------- C 实现转录（e2e2_probe.c:jhash2，标量 32 位，用于对拍）
def c_jhash2(va, mm, seed_flag=MM_SHARED_FLAG):
    k = [(mm & M32), ((mm >> 32) & M32), ((va & ~0xfff) & M32), (((va & ~0xfff) >> 32) & M32)]
    seed = seed_of(va, seed_flag)
    a = b = c = (0xdeadbeef + 16 + seed) & M32
    a = (a + k[0]) & M32
    b = (b + k[1]) & M32
    c = (c + k[2]) & M32

    def rol(w, s):
        return ((w << s) | (w >> (32 - s))) & M32

    a = (a - c) & M32; a = (a ^ rol(c, 4)) & M32;  c = (c + b) & M32
    b = (b - a) & M32; b = (b ^ rol(a, 6)) & M32;  a = (a + c) & M32
    c = (c - b) & M32; c = (c ^ rol(b, 8)) & M32;  b = (b + a) & M32
    a = (a - c) & M32; a = (a ^ rol(c, 16)) & M32; c = (c + b) & M32
    b = (b - a) & M32; b = (b ^ rol(a, 19)) & M32; a = (a + c) & M32
    c = (c - b) & M32; c = (c ^ rol(b, 4)) & M32;  b = (b + a) & M32
    a = (a + k[3]) & M32
    c = (c ^ b) & M32; c = (c - rol(b, 14)) & M32
    a = (a ^ c) & M32; a = (a - rol(c, 11)) & M32
    b = (b ^ a) & M32; b = (b - rol(a, 25)) & M32
    c = (c ^ b) & M32; c = (c - rol(b, 16)) & M32
    a = (a ^ c) & M32; a = (a - rol(c, 4)) & M32
    b = (b ^ a) & M32; b = (b - rol(a, 14)) & M32
    c = (c ^ b) & M32; c = (c - rol(b, 24)) & M32
    return c


# ---------------------------------------------------------------- 自检
def selftest(n=300, hashsize=DEFAULT_HASHSIZE):
    """三方对拍：numpy 向量化 / C 转录 / vmlinux 逐指令模拟器（ground truth）。"""
    sys.path.insert(0, 'tools')
    from hash_emu import bucket_of          # 依赖 capstone + firmware_F16/vmlinux.elf

    rng = random.Random(0xC0FFEE)
    bad = {'vec_vs_c': 0, 'vec_vs_emu': 0, 'c_vs_emu': 0}
    for _ in range(n):
        mm = rng.getrandbits(64)
        va = (rng.getrandbits(64) & ~0xfff) | rng.choice([0x0, 0x8, 0x80, 0x123, 0xffc])

        hv = int(hash_va(va, np.asarray([mm], dtype=np.uint64))[0])
        hc = int(c_jhash2(va, mm))
        he = bucket_of(mm, va, hashsize)

        bad['vec_vs_c'] += (hv & (hashsize - 1)) != (hc & (hashsize - 1))
        bad['vec_vs_emu'] += (hv & (hashsize - 1)) != he
        bad['c_vs_emu'] += (hc & (hashsize - 1)) != he

    print('selftest: %d cases, hashsize=%d' % (n, hashsize))
    print('  numpy-vec  vs C-transcript : %d mismatch' % bad['vec_vs_c'])
    print('  numpy-vec  vs vmlinux-emu  : %d mismatch' % bad['vec_vs_emu'])
    print('  C-transcript vs vmlinux-emu: %d mismatch' % bad['c_vs_emu'])

    # 掩码语义回归：完整哈希相等 ⇒ 桶相等，反之不成立（证明 v1 的比较是过强约束）
    va_inc = 0x77be2a0080
    mm_a = np.asarray([0xffffffc012345680], dtype=np.uint64)
    inc_full = int(hash_va(va_inc, mm_a)[0])
    inc_bkt = int(bucket_va(va_inc, mm_a)[0])
    full_eq = bucket_eq = 0
    for _ in range(20000):
        va = 0x77be2a0000 + rng.randrange(0, 1 << 24, 32)
        full_eq += int(hash_va(va, mm_a)[0]) == inc_full
        bucket_eq += int(bucket_va(va, mm_a)[0]) == inc_bkt
    print('  semantic: 20000 samples, full-hash== %d, bucket== %d (expect ~0 / ~10)'
          % (full_eq, bucket_eq))
    ok = all(v == 0 for v in bad.values())
    print('selftest %s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


# ---------------------------------------------------------------- 搜索
def load_result(path=RESULT):
    hits, inc = [], None
    for line in open(path):
        p = line.split()
        if p and p[0] == 'hit':
            hits.append(int(p[2], 16))
        elif p and p[0] == 'inc':
            inc = int(p[1], 16)
    return inc, hits


def _scan_chunk(task):
    """子进程任务：扫描 [n_start, n_end) 的 32B 网格，返回 (hist, found, best)。

    shift=0: 同桶（bucket 相等）
    shift=1: 同 64B cache line 对（bucket>>1 相等）——桶 stride=128B，
             两个桶共享一条 cache line，crowd 的锁流量会污染邻桶的计时。
    """
    W, n_start, n_end, inc, hits, hashsize, threshold, shift, seed_flag = task
    n = np.arange(n_start, n_end, dtype=np.uint64)
    cand = np.uint64(W) + n * np.uint64(GRID_BYTES[0])
    k0 = (cand & np.uint64(M32)).astype(U32)
    k1 = (cand >> np.uint64(32)).astype(U32)
    with np.errstate(over='ignore'):
        b_inc = bucket_from_ab(k0, k1, inc, hashsize, seed_flag)
        if shift:
            b_inc = b_inc >> U32(shift)
        cnt = np.zeros(len(cand), dtype=np.uint8)
        for hv in hits:
            bh = bucket_from_ab(k0, k1, hv, hashsize, seed_flag)
            if shift:
                bh = bh >> U32(shift)
            cnt += (bh == b_inc)
    mx = int(cnt.max())
    vals, counts = np.unique(cnt, return_counts=True)
    hist = {int(v): int(c) for v, c in zip(vals, counts)}
    found = [(int(cnt[i]), int(cand[i])) for i in np.nonzero(cnt >= threshold)[0]]
    return hist, found, (mx, int(cand[int(cnt.argmax())]))


GRID_BYTES = [32]      # 候选网格步长（模块级，供子进程继承；Windows spawn 下由 _init_grid 设置）
MODEL = ['page']       # page | full | pfn | swap：key->both.ptr 的取值方式
MODEL_VARIANTS = ('page', 'full', 'pfn', 'swap')


def _init_grid(g, model='page'):
    GRID_BYTES[0] = g
    MODEL[0] = model


def scan_window(name, W, phys_start, phys_end, inc, hits, hashsize, threshold,
                chunk, jobs, progress=True, line_pair=False,
                seed_flag=MM_SHARED_FLAG, grid=32, model='page'):
    MODEL[0] = model
    shift = 1 if line_pair else 0
    n_lo = phys_start // grid
    n_hi = phys_end // grid
    tasks = [(W, a * 1, min(a + chunk, n_hi), inc, hits, hashsize, threshold,
              shift, seed_flag) for a in range(n_lo, n_hi, chunk)]
    hist = Counter()
    found = []
    best = (-1, 0)
    t0 = time.time()
    done = 0
    if jobs <= 1:
        results = map(_scan_chunk, tasks)
    else:
        ex = ProcessPoolExecutor(max_workers=jobs, initializer=_init_grid,
                                 initargs=(grid, MODEL[0]))
        results = ex.map(_scan_chunk, tasks, chunksize=1)
    for h, f, b in results:
        done += 1
        hist.update(h)
        found.extend(f)
        if b[0] > best[0]:
            best = b
        for c, m in f:
            print('  CAND %-9s mm=0x%016x count=%d' % (name, m, c), flush=True)
        if progress and (done % max(1, len(tasks) // 10) == 0 or done == len(tasks)):
            el = time.time() - t0
            print('  [%s] %5.1f%% chunks=%d/%d max=%d elapsed=%.1fs'
                  % (name, 100.0 * done / len(tasks), done, len(tasks), best[0], el),
                  flush=True)
    if jobs > 1:
        ex.shutdown()
    return hist, found, best, time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--hashsize', type=int, default=DEFAULT_HASHSIZE)
    ap.add_argument('--threshold', type=int, default=DEFAULT_THRESHOLD)
    ap.add_argument('--chunk-bits', type=int, default=22)
    ap.add_argument('--model', default='page', choices=MODEL_VARIANTS,
                    help='key->both.ptr 取值变体（默认 page=页基址）')
    ap.add_argument('--max-hits', type=int, default=0,
                    help='只用前 N 个 hit（变体筛查提速）')
    ap.add_argument('--grid-bytes', type=int, default=64,
                    help='候选网格步长：32 覆盖 896 步长 slab；8 覆盖任意 SLUB 对齐')
    ap.add_argument('--jobs', type=int, default=0, help='并行进程数，0=自动')
    ap.add_argument('--result', default=RESULT)
    ap.add_argument('--windows', default='page_offset:0xffffffc000000000')
    ap.add_argument('--phys-start', default=hex(PHYS_START))
    ap.add_argument('--phys-end', default=hex(PHYS_END))
    ap.add_argument('--seed-flag', type=int, default=MM_SHARED_FLAG,
                    help='key->offset 的标志位（私有 futex=2；设 0 复现旧错误模型）')
    ap.add_argument('--line-pair', action='store_true',
                    help='同 64B cache line 对约束（bucket>>1 相等），用于邻桶污染假设')
    args = ap.parse_args()

    if args.selftest:
        return selftest(300, args.hashsize)

    jobs = args.jobs or max(1, min(20, (os.cpu_count() or 4) - 4))
    inc, hits = load_result(args.result)
    if inc is None or not hits:
        print('FAIL: cannot parse %s' % args.result)
        return 2
    if args.max_hits:
        hits = hits[:args.max_hits]
    ps, pe = int(args.phys_start, 16), int(args.phys_end, 16)
    mode = 'line-pair(bucket>>1)' if args.line_pair else 'same-bucket(mask)'
    rate = (2.0 if args.line_pair else 1.0) / args.hashsize
    print('inc=0x%x  hits=%d  hashsize=%d  threshold=%d  jobs=%d  mode=%s'
          % (inc, len(hits), args.hashsize, args.threshold, jobs, mode))
    print('phys window [0x%x, 0x%x) = %.0f MiB; grid=%dB candidates/window = %d'
          % (ps, pe, (pe - ps) / 2**20, args.grid_bytes,
             (pe - ps) // args.grid_bytes))
    print('H0: count ~ Binomial(%d, %.6f), E=%.4f per random candidate'
          % (len(hits), rate, len(hits) * rate))

    out, all_found = [], []
    for spec in args.windows.split(','):
        name, w = spec.split(':')
        W = int(w, 16)
        hist, found, best, el = scan_window(name, W, ps, pe, inc, hits,
                                            args.hashsize, args.threshold,
                                            1 << args.chunk_bits, jobs,
                                            line_pair=args.line_pair,
                                            seed_flag=args.seed_flag,
                                            grid=args.grid_bytes,
                                            model=args.model)
        ncand = sum(hist.values())
        print('[%s] done in %.1fs: candidates=%d count>=1=%d max_count=%d (@0x%016x)'
              % (name, el, ncand, ncand - hist.get(0, 0), best[0], best[1]))
        print('       histogram: %s' % dict(sorted(hist.items())[:8]))
        out.append('[%s] window=0x%x candidates=%d count>=1=%d max=%d@0x%x'
                   % (name, W, ncand, ncand - hist.get(0, 0), best[0], best[1]))
        out.append('  histogram: %s' % dict(sorted(hist.items())))
        out.extend('  CAND count=%d mm=0x%016x' % (c, m) for c, m in found)
        all_found.extend(found)

    print('=' * 70)
    if all_found:
        all_found.sort(reverse=True)
        print('RESULT: %d candidate(s) >= threshold %d; best = count %d mm=0x%016x'
              % (len(all_found), args.threshold, all_found[0][0], all_found[0][1]))
        print('NEXT: 设备端 mask-%d 预测命中率验证（e2e2 VERIFY 段）' % args.hashsize)
    else:
        print('RESULT: 无候选达到 count>=%d。' % args.threshold)
        print('解释边界（v8 教训）：本工具的"零候选"已由 tools/g2_maxmatch_control.py 证明具备判决力，')
        print('故零候选首先应怀疑 **窗口**——memstart_addr 的 KASLR 平移（1 GB 量化，可大至 ~261 GB）')
        print('会让任何"PAGE_OFFSET + 小偏移"的窗口整体落空（这正是 v3–v7 全部失败的原因，见 HANDOVER §48）。')
        print('请改用默认全线性映射窗口（--phys-start 0 --phys-end 0x4000000000 --grid-bytes 64）。')

    outfile = ('live_probe/ks_g2_maxmatch_linepair.txt' if args.line_pair
               else 'live_probe/ks_g2_maxmatch_result.txt')
    with open(outfile, 'w') as f:
        f.write('# g2_maxmatch v3 — %s, hashsize=%d threshold=%d\n'
                % (mode, args.hashsize, args.threshold))
        f.write('inc %016x\nhits %d\nphys [%x,%x)\n' % (inc, len(hits), ps, pe))
        f.write('\n'.join(out) + '\n')
        f.write('found %d\n' % len(all_found))
    print('written: %s' % outfile)
    return 0


if __name__ == '__main__':
    sys.exit(main())
