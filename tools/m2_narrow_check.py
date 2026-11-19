#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""定点复扫验证：hMXNkK（6GB 窗口）漏检 0xffffffdb05179880 的执行异常排查。"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))
from g2_maxmatch import scan_window, load_result

inc, hits = load_result('live_probe/ks_tracer_run1_0.txt')
print('inc=0x%x hits=%d' % (inc, len(hits)))
W = 0xFFFFFFDA00000000
ps, pe = 0x105178000, 0x10517A000   # 覆盖 0xffffffdb05179880

if __name__ == '__main__':
    hist, found, best, el = scan_window('narrow', W, ps, pe, inc, hits, 2048, 6, 1 << 22, 4, grid=64)
    print('narrow best=%s found=%s elapsed=%.1fs' % (best, found, el))
