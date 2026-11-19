#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""m2_unique_globals.py — 对在 1 GB 邻域内出解的示踪，补做 16 GB 宽窗复核（v10.1）

背景：`m2_tracer_analysis.recover_mm` 先扫 1 GB 邻域（W1），命中即返回。
      凡 window=W1 的示踪，其"唯一解"只在该 1 GB 内成立，不构成全局唯一性。
本脚本对这些示踪强制只扫 W2(16 GB)，给出全局候选数 / 次高分。

用法:
  python tools/m2_unique_globals.py run1:T3 run2:T3        # 指定 run:T 列表
  python tools/m2_unique_globals.py --auto                 # 自动挑出 summary 里 window=W1 的项
"""
import argparse
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from m2_tracer_analysis import recover_mm  # noqa: E402

RUNS = {
    'run1': 'live_probe/ks_tracer_run1_',
    'run2': 'live_probe/ks_tracer_run2_',
}


def auto_targets():
    out = []
    for f in glob.glob('live_probe/ks_m2_tracer_summary_*_v101.txt'):
        run = 'run1' if '_run1' in f else 'run2'
        for line in open(f):
            m = re.match(r'T(\d+) .*window=W1', line)
            if m:
                out.append('%s:T%s' % (run, m.group(1)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('targets', nargs='*')
    ap.add_argument('--auto', action='store_true')
    ap.add_argument('--jobs', type=int, default=16)
    args = ap.parse_args()

    targets = auto_targets() if args.auto else args.targets
    if not targets:
        print('no targets (pass run1:T3 ... or --auto)')
        return 1
    print('== global uniqueness recheck (W2 16GB only) ==')
    bad = 0
    for t in targets:
        run, step = t.split(':')
        p = os.path.join('live_probe', '%s%s.txt' % (RUNS[run].split('/')[-1], step[1:]))
        print('\n-- %s (%s)' % (t, p))
        mm, cnt, note, st = recover_mm(p, 6, args.jobs, windows='w2')
        if st is None:
            print('   NOT RECOVERED (%s)' % note)
            bad += 1
            continue
        ok = st['n_full'] == 1 and st['top_score'] == st['full_hits']
        print('   mm=%s top=%d n_top=%d n_full=%d second=%s n_ge6=%d scanned=%d -> %s'
              % (('0x%016x' % mm), st['top_score'], st['n_top'], st['n_full'],
                 st['second_score'], st['n_ge_thr'], st['scanned'],
                 'UNIQUE-FULL' if ok else 'NOT-UNIQUE'))
        if not ok:
            bad += 1
    print('\nGLOBAL-UNIQUENESS: %s' % ('ALL UNIQUE-FULL' if bad == 0
                                       else '%d/%d NOT unique' % (bad, len(targets))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
