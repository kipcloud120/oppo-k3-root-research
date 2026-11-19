#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""m2_tracer_analysis.py — M2 示踪实验离线分析（HANDOVER §50 配套）

输入：live_probe/ks_tracer{0..4}.txt（spray_tracer_probe 产出，格式兼容 g2_maxmatch.py）
      live_probe/ks_tracer_meta.txt（步序/时间/slabinfo 快照）

做什么：
  1) 对每个示踪进程跑 g2_maxmatch 同款同桶搜索（64B 网格），恢复其 mm；
     窗口从已知 mm 邻域 1GB 起，无解则放宽到 4GB。
  2) 计算相邻示踪 mm 的 slab 页（order-2, 16KB）delta（块数）。
  3) 对照步序模型 K={0,0,2048,2048,0}：
        d01 ≈ C, d12 ≈ C+2048, d23 ≈ d12, d34 ≈ C
     线性成立 ⇒ skb 喷射页可被夹在已知锚点之间（页级邻接可评估为可推导）。
  4) slabinfo 快照交叉验证（mm_struct slabdata 每步 +2~3，dummy/tracer 模型）。

用法：
  python tools/m2_tracer_analysis.py [--threshold 6] [--jobs 12]
"""
import argparse
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from g2_maxmatch import scan_window, load_result  # noqa: E402

NSTEP = 5
K_SEQ = [0, 0, 2048, 2048, 0]
PREFIX = 'ks_tracer'
MM_W1 = 0xFFFFFFDA42000000   # 已知 mm 邻域（v9 唯一解 0xffffffda42a97800）
W1_SPAN = 0x40000000         # 1 GB
MM_W2 = 0xFFFFFFD800000000
W2_SPAN = 0x400000000        # 16 GB 宽档（DRAM 基底未标定，双向覆盖）
PAGE_ORDER2 = 0x4000         # 16 KB


def _window_stats(hist, top_score, full_hits, thr):
    """从单窗口的分数直方图导出唯一性统计（v10.1 新增，响应审核 v010 第 ① 条）。

    hist: {score: n_candidates}，覆盖该窗口全部候选（无截断）。
    """
    top_n = int(hist.get(top_score, 0))
    below = [s for s in hist if s < top_score and hist[s] > 0]
    second = max(below) if below else None
    n_ge_thr = sum(int(hist[s]) for s in hist if s >= thr)
    return {
        'full_hits': full_hits,
        'top_score': int(top_score),
        'n_top': top_n,                    # 与 top 同分的候选数（唯一性判据）
        'n_full': int(hist.get(full_hits, 0)),   # 满命中候选数
        'second_score': second,            # 严格低于最高分的次高分
        'second_n': int(hist.get(second, 0)) if second is not None else 0,
        'n_ge_thr': n_ge_thr,              # >= 阈值（默认 6）的候选数
        'scanned': sum(int(v) for v in hist.values()),
    }


def recover_mm(path, threshold, jobs, verbose=True, windows=None):
    """恢复示踪 mm 地址，并返回可审计的唯一性统计。

    返回 (mm, score, note, stats)。**不再默认 found[0] 即唯一解**：
    调用方必须检查 stats['n_full'] == 1 才能声称"满命中唯一解"。
    windows=None ⇒ 先 1 GB 邻域、失败再 16 GB 宽窗；'w2' ⇒ 只扫宽窗（用于复核"全局唯一性"）。
    """
    inc, hits = load_result(path)
    if inc is None or not hits:
        return None, 0, 'no constraints (%s)' % path, None
    thr = min(threshold, max(3, len(hits)))
    if verbose:
        print('  %s: inc=0x%x hits=%d threshold=%d' % (os.path.basename(path), inc, len(hits), thr))
    seq = ((MM_W1, W1_SPAN, 'W1(1GB)'), (MM_W2, W2_SPAN, 'W2(16GB)'))
    if windows == 'w2':
        seq = (seq[1],)
    for W, span, name in seq:
        hist, found, best, el = scan_window(
            name, W, 0, span, inc, hits, 2048, thr,
            1 << 22, jobs, progress=True, grid=64, model='page')
        if found:
            found.sort(reverse=True)
            stats = _window_stats(hist, found[0][0], len(hits), thr)
            stats['window'] = name
            stats['elapsed'] = el
            if verbose:
                print('    [%s] %.1fs scanned=%d top=%d n_top=%d n_full=%d second=%s n_second=%d n_ge%d=%d'
                      % (name, el, stats['scanned'], stats['top_score'], stats['n_top'],
                         stats['n_full'], stats['second_score'], stats['second_n'],
                         thr, stats['n_ge_thr']))
            note = ('UNIQUE-FULL' if stats['n_full'] == 1 and len(hits) == stats['top_score']
                    else 'MULTI(top=%d,n=%d)' % (stats['top_score'], stats['n_top']))
            return found[0][1], found[0][0], 'ok window=%s %s' % (name, note), stats
    return None, 0, 'no candidate >= threshold in both windows', None


def parse_meta(path):
    """返回 (slabinfo 快照, 每步实际喷射手数 actual_K)。

    slabdata 列序: name active total objsize objs/slab pages/slab : tunables ... : slabdata N M 0
    """
    slabs = {}
    actual_k = {}
    if not os.path.exists(path):
        return slabs, actual_k
    pat2 = re.compile(r'slab (\S+)\s+mm_struct\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+: tunables\s+\d+\s+\d+\s+\d+ : slabdata\s+(\d+)')
    for line in open(path, errors='ignore'):
        m = pat2.match(line)
        if m:
            slabs.setdefault(m.group(1), []).append(int(m.group(7)))
        m2 = re.match(r'step (\d+) sprayed (-?\d+)', line)
        if m2:
            actual_k[int(m2.group(1))] = int(m2.group(2))
    return slabs, actual_k


def main():
    global PREFIX
    ap = argparse.ArgumentParser()
    ap.add_argument('--threshold', type=int, default=6)
    ap.add_argument('--jobs', type=int, default=12)
    ap.add_argument('--dir', default='live_probe')
    ap.add_argument('--prefix', default='ks_tracer',
                    help='示踪结果文件名前缀（run1 归档用 ks_tracer_run1_）')
    ap.add_argument('--meta', default=None, help='meta 文件路径（默认 live_probe/ks_tracer_meta.txt）')
    ap.add_argument('--out', default='live_probe/ks_m2_tracer_summary.txt')
    ap.add_argument('--windows', default='auto', choices=('auto', 'w2'),
                    help='auto=先 1GB 后 16GB；w2=只扫 16GB 宽窗（复核全局唯一性）')
    args = ap.parse_args()
    PREFIX = args.prefix
    win = None if args.windows == 'auto' else args.windows

    print('== M2 tracer analysis (prefix=%s) ==' % PREFIX)
    mms, counts, notes, stats_all = [], [], [], []
    for i in range(NSTEP):
        p = os.path.join(args.dir, '%s%d.txt' % (PREFIX, i))
        mm, cnt, note, st = recover_mm(p, args.threshold, args.jobs, windows=win)
        mms.append(mm)
        counts.append(cnt)
        notes.append(note)
        stats_all.append(st)
        print('  T%d -> %s count=%s (%s)' % (i, '0x%016x' % mm if mm else 'None', cnt, note))

    # —— 唯一性审计表（响应审核 v010 第 ① 条）——
    print('\n== 唯一性审计（满命中候选数 / 次高分，脚本级断言） ==')
    n_unique = n_recovered = 0
    for i, st in enumerate(stats_all):
        if st is None:
            print('  T%d : 未恢复，无统计' % i)
            continue
        n_recovered += 1
        ok = (st['n_full'] == 1 and st['full_hits'] == st['top_score'])
        n_unique += 1 if ok else 0
        print('  T%d : window=%s hits=%d top=%d n_top=%d n_full=%d second=%s(x%d) n_ge%d=%d -> %s'
              % (i, st['window'], st['full_hits'], st['top_score'], st['n_top'], st['n_full'],
                 st['second_score'], st['second_n'], 6, st['n_ge_thr'],
                 'UNIQUE-FULL' if ok else 'NOT-UNIQUE'))
    uniqueness_verdict = ('UNIQUE-FULL %d/%d recovered' % (n_unique, n_recovered)
                          if n_unique == n_recovered and n_recovered
                          else 'NOT-UNIQUE %d/%d' % (n_unique, n_recovered))
    print('  UNIQUENESS: %s' % uniqueness_verdict)

    print('\n== slab 页 delta（order-2, 16KB/块） ==')
    pages = [mm & ~(PAGE_ORDER2 - 1) if mm else None for mm in mms]
    deltas = []
    for i in range(NSTEP - 1):
        if pages[i] is None or pages[i + 1] is None:
            deltas.append(None)
            print('  d%d%d : N/A（T%d/T%d 未恢复）' % (i, i + 1, i, i + 1))
        else:
            d = (pages[i + 1] - pages[i]) >> 14
            deltas.append(d)
            print('  d%d%d = %+d blocks (%+.1f KB)  mm%d=0x%016x mm%d=0x%016x'
                  % (i, i + 1, d, (pages[i + 1] - pages[i]) / 1024.0, i, mms[i], i + 1, mms[i + 1]))

    # 模型对照：d(i,i+1) = C + K_{i+1}（K 取 meta 实测喷射手数，缺省回退 STEP 序列）
    meta_path = args.meta or os.path.join(args.dir, 'ks_tracer_meta.txt')
    slabs, actual_k = parse_meta(meta_path)
    if actual_k:
        K_step = [actual_k.get(i, K_SEQ[i]) for i in range(NSTEP)]
        print('\n== 模型对照（实测 K per step = %s；期望 d01≈C, d12≈C+K2, d23≈C+K3, d34≈C+K4） ==' % K_step)
    else:
        K_step = K_SEQ
        print('\n== 模型对照（配置 K=%s） ==' % K_SEQ)
    verdict = []
    overall = 'INSUFFICIENT'
    try:
        C = deltas[0]
        for i, d in enumerate(deltas):
            if d is None or C is None:
                verdict.append('N/A')
                continue
            exp = C + K_step[i + 1]
            verdict.append('%+d (exp %+d, dev %+d)' % (d, exp, d - exp))
        print('  deltas: %s' % verdict)
        Ks = [K_step[i + 1] for i in range(NSTEP - 1)]
        ok = (all(d is not None for d in deltas)
              and all(abs(deltas[i] - (C + Ks[i])) <= 96 for i in range(NSTEP - 1)))
        overall = 'LINEAR-STREAM CONFIRMED' if ok else 'NOT CONFIRMED / INSUFFICIENT'
    except Exception as e:
        overall = 'ANALYSIS ERROR: %s' % e
        print('  %s' % overall)
    print('VERDICT: %s' % overall)

    # slabinfo 交叉验证
    if slabs:
        print('\n== slabinfo mm_struct slabdata 快照 ==')
        for k in ('start', 'postdummy', 'postspray', 'posttracer', 'end'):
            if k in slabs:
                print('  %-9s %s' % (k, slabs[k]))

    with open(args.out, 'w') as f:
        f.write('# M2 tracer analysis — prefix=%s K_step=%s\n' % (PREFIX, K_step))
        for i in range(NSTEP):
            st = stats_all[i]
            if st:
                f.write('T%d mm=%s count=%s note=%s | window=%s hits=%d top=%d n_top=%d n_full=%d '
                        'second=%s(x%d) n_ge6=%d scanned=%d\n'
                        % (i, '0x%016x' % mms[i] if mms[i] else 'None', counts[i], notes[i],
                           st['window'], st['full_hits'], st['top_score'], st['n_top'],
                           st['n_full'], st['second_score'], st['second_n'], st['n_ge_thr'],
                           st['scanned']))
            else:
                f.write('T%d mm=%s count=%s note=%s | (no stats)\n'
                        % (i, '0x%016x' % mms[i] if mms[i] else 'None', counts[i], notes[i]))
        for i, d in enumerate(deltas):
            f.write('d%d%d = %s\n' % (i, i + 1, d))
        f.write('UNIQUENESS %s\n' % uniqueness_verdict)
        f.write('VERDICT %s\n' % overall)
    print('written: %s' % args.out)


if __name__ == '__main__':
    main()
