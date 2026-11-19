#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""g2_maxmatch.py — 最大匹配 G2 搜索（对假阳性 hit 鲁棒）。

对每个候选 mm 统计 hits 中与 inc 同桶的数量 count(mm)。
真 mm: count ≈ 真实命中数（~16-26）；随机 mm: E[count] = 26/2048 ≈ 0.013。
哈希模型: 标准 jhash2(k=[mm_lo,mm_hi,page_lo,page_hi],4,off) — 已与
本机内核二进制逐指令模拟器对拍 (300/300)。
"""
import numpy as np

U32 = np.uint32
M32 = 0xFFFFFFFF

def rol(w, s):
    return ((w << np.uint32(s)) | (w >> np.uint32(32 - s))) & U32(M32)

def jhash2_vec(k0, k1, k2, k3, seed):
    init = (0xdeadbeef + np.uint32(16) + seed) & U32(M32)
    a = (k0 + init) & U32(M32)
    b = (k1 + init) & U32(M32)
    c = (k2 + init) & U32(M32)
    a = (a - c) & U32(M32); a = (a ^ rol(c, 4)) & U32(M32);  c = (c + b) & U32(M32)
    b = (b - a) & U32(M32); b = (b ^ rol(a, 6)) & U32(M32);  a = (a + c) & U32(M32)
    c = (c - b) & U32(M32); c = (c ^ rol(b, 8)) & U32(M32);  b = (b + a) & U32(M32)
    a = (a - c) & U32(M32); a = (a ^ rol(c, 16)) & U32(M32); c = (c + b) & U32(M32)
    b = (b - a) & U32(M32); b = (b ^ rol(a, 19)) & U32(M32); a = (a + c) & U32(M32)
    c = (c - b) & U32(M32); c = (c ^ rol(b, 4)) & U32(M32);  b = (b + a) & U32(M32)
    a = (a + k3) & U32(M32)
    c = (c ^ b) & U32(M32); c = (c - rol(b, 14)) & U32(M32)
    a = (a ^ c) & U32(M32); a = (a - rol(c, 11)) & U32(M32)
    b = (b ^ a) & U32(M32); b = (b - rol(a, 25)) & U32(M32)
    c = (c ^ b) & U32(M32); c = (c - rol(b, 16)) & U32(M32)
    a = (a ^ c) & U32(M32); a = (a - rol(c, 4)) & U32(M32)
    b = (b ^ a) & U32(M32); b = (b - rol(a, 14)) & U32(M32)
    c = (c ^ b) & U32(M32); c = (c - rol(b, 24)) & U32(M32)
    return c

def hash_va(va, mm):
    va = np.uint64(va); mm = np.asarray(mm, dtype=np.uint64)
    page = va & ~np.uint64(0xfff)
    off = np.uint32(va & np.uint64(0xfff))
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
    print('inc=0x%x hits=%d' % (inc, len(hits)), flush=True)
    WINDOWS = [('corrected', 0xffffffc000000000, 8 << 30),
               ('legacy   ', 0xffffff8000000000, 8 << 30)]
    best = []
    for name, W, size in WINDOWS:
        n32 = size // 32
        CH = 8_000_000
        for start in range(0, n32, CH):
            end = min(start + CH, n32)
            n = np.arange(start, end, dtype=np.uint64)
            cand = np.uint64(W) + n * np.uint64(32)
            h0 = hash_va(inc, cand)
            cnt = np.zeros(len(cand), dtype=np.int16)
            for hv in hits:
                cnt += (hash_va(hv, cand) == h0)
            mx = cnt.max()
            if mx >= 3:
                idx = np.nonzero(cnt >= 3)[0]
                for t in idx:
                    print('CAND %s mm=0x%016x count=%d' % (name, int(cand[t]), cnt[t]), flush=True)
                best.append((mx, name, int(cand[idx[cnt.argmax()]])))
            if (start // CH) % 8 == 0:
                print('  %s [%dM/%dM) max_in_chunk=%d' % (name, start//1_000_000, n32//1_000_000, mx), flush=True)
    best.sort(reverse=True)
    print('BEST:', best[:5])

if __name__ == '__main__':
    main()
