#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""debug_g2_models.py — 模型隔离：5 种哈希变体 × 32字节对齐全窗口

目的：判定 0 候选的原因 —— (a) 网格对齐假设错误 (b) 哈希词序/对齐假设错误
     (c) hits 并非全部同桶。
"""
import numpy as np
import sys, time

MASK32 = 0xFFFFFFFF
INITVAL = 0xDEADBEEF
U32 = np.uint32
U64 = np.uint64
np.seterr(over='ignore')

def rol(x, s):
    return ((x << U32(s)) | (x >> U32(32 - s))).astype(U32)

def mix(a, b, c):
    a = (a - c).astype(U32); a = (a ^ rol(c, 4)).astype(U32);  c = (c + b).astype(U32)
    b = (b - a).astype(U32); b = (b ^ rol(a, 6)).astype(U32);  a = (a + c).astype(U32)
    c = (c - b).astype(U32); c = (c ^ rol(b, 8)).astype(U32);  b = (b + a).astype(U32)
    a = (a - c).astype(U32); a = (a ^ rol(c, 16)).astype(U32); c = (c + b).astype(U32)
    b = (b - a).astype(U32); b = (b ^ rol(a, 19)).astype(U32); a = (a + c).astype(U32)
    c = (c - b).astype(U32); c = (c ^ rol(b, 4)).astype(U32);  b = (b + a).astype(U32)
    return a, b, c

def final(a, b, c):
    c ^= b; c = (c - rol(b, 14)).astype(U32)
    a ^= c; a = (a - rol(c, 11)).astype(U32)
    b ^= a; b = (b - rol(a, 25)).astype(U32)
    c ^= b; c = (c - rol(b, 16)).astype(U32)
    a ^= c; a = (a - rol(c, 4)).astype(U32)
    b ^= a; b = (b - rol(a, 14)).astype(U32)
    c ^= b; c = (c - rol(b, 24)).astype(U32)
    return a, b, c

def jhash_words(k0, k1, k2, k3, initval):
    a = b = c = (U32(INITVAL) + U32(16) + initval).astype(U32)
    a = (a + k0).astype(U32); b = (b + k1).astype(U32); c = (c + k2).astype(U32)
    a, b, c = mix(a, b, c)
    a = (a + k3).astype(U32)
    a, b, c = final(a, b, c)
    return c

hits = []
with open('live_probe/ks_e2e_result_run2.txt') as f:
    for line in f:
        p = line.split()
        if p and p[0] == 'hit':
            hits.append(int(p[2], 16))
print(f"hits = {len(hits)}")

MM_START = np.uint64(0xffffffc000000000)
WINDOW = np.uint64(8 * 1024**3)

# 32 字节对齐网格（真实 mm 集合的超集：slab 页 16384 对齐 + 896*j 全是 32 的倍数）
STEP = np.uint64(32)
ncand = int(WINDOW // STEP)
print(f"grid: 32-byte aligned, {ncand:,} candidates")

def split64(x):
    return (x & U64(MASK32)).astype(U32), (x >> U64(32)).astype(U32)

# 模型定义: (词序标志, 页对齐标志, initval来源)
# M1 canonical: [mm,page], page-aligned, initval=off   (反汇编口径)
# M2 raw addr:  [mm,raw_addr], initval=off
# M3 no initval:[mm,page], initval=0
# M4 raw+0:     [mm,raw_addr], initval=0
# M5 swapped:   [page,mm], page-aligned, initval=off
def build_arrays(cand, model):
    mm_lo, mm_hi = split64(cand)
    offs = []
    for h in hits:
        page = h & ~0xFFF
        raw = h
        initval = U32(h & 0xFFF)
        if model in ('M1', 'M3', 'M5'):
            a_lo, a_hi = split64(np.uint64(page))
        else:
            a_lo, a_hi = split64(np.uint64(raw))
        iv = U32(0) if model in ('M3', 'M4') else initval
        offs.append((a_lo, a_hi, iv))
    return mm_lo, mm_hi, offs

def scan(model):
    t0 = time.time()
    ref = None
    alive = None
    CH = 8_000_000
    total_alive = 0
    for c0 in range(0, ncand, CH):
        k = np.arange(c0, min(c0 + CH, ncand), dtype=U64)
        cand = MM_START + k * STEP
        mm_lo, mm_hi, offs = build_arrays(cand, model)
        h0 = jhash_words(mm_lo, mm_hi, offs[0][0], offs[0][1], offs[0][2]) & U32(255)
        alive = h0 == h0
        for (a_lo, a_hi, iv) in offs:
            hi = jhash_words(mm_lo, mm_hi, a_lo, a_hi, iv) & U32(255)
            alive &= (hi == h0)
            if not alive.any():
                break
        total_alive += int(alive.sum())
        if alive.any():
            idx = np.where(alive)[0]
            for i in idx[:8]:
                print(f"  [{model}] candidate mm=0x{int(cand[i]):016x}")
    print(f"[{model}] survivors={total_alive}  elapsed={time.time()-t0:.0f}s")
    return total_alive

for m in ('M1', 'M2', 'M3', 'M4', 'M5'):
    scan(m)
