#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gl_carrier_rescan.py — 修正 gl_carrier_scan.py 的 seen 判重后重跑载体扫描。

审核意见（2026-11-17）指出：原版 seen 以函数名为唯一键、全局共享，
丢失"同一函数从累计栈帧不同的调用路径进入"的上下文，可能漏报载体。

本脚本：
- 模式 context：seen 键 = (name, frames)  ——保留不同累计栈帧
- 模式 nonext ：完全不做 seen 判重，仅 depth<=MAX_DEPTH（真·路径枚举，带访问上限防爆）
- 同时统计原版按 name 判重会跳过多少边、其中 contexts 不同的数量
- COPY_PREFIX 可通过 --copy-extra 扩充

判据与几何常数与 gl_carrier_scan.py 完全一致（不擅自改动）。
"""
import sys
import argparse
from collections import defaultdict

sys.path.insert(0, "tools")
import gl_carrier_scan as G


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["name", "context", "nonext"], default="context")
    ap.add_argument("--depth", type=int, default=G.MAX_DEPTH)
    ap.add_argument("--copy-extra", nargs="*", default=[])
    ap.add_argument("--max-visits", type=int, default=2_000_000)
    a = ap.parse_args()

    v = G.V(G.ELF)
    entries = set(G.EXTRA_ENTRIES)
    entries |= {n for n in v.syms if n.startswith(("SyS_", "compat_SyS_"))}
    entries = sorted(e for e in entries if e in v.syms)

    copy_prefix = G.COPY_PREFIX + tuple(a.copy_extra)

    def copies(va):
        # 复用 V.copies 但支持扩充前缀：直接按其逻辑内联
        ins = v.dis(va)
        hits = []
        for idx, i in enumerate(ins):
            if i.mnemonic != "bl":
                continue
            nm = v.by_addr.get(int(i.op_str.lstrip("#"), 0), "")
            if not nm.startswith(copy_prefix):
                continue
            off = size = None
            for j in range(idx - 1, max(idx - 10, -1), -1):
                o = ins[j].op_str.replace(" ", "")
                if off is None and ins[j].mnemonic in ("add", "mov") and o.startswith("x0,") and "sp" in o:
                    off = int(o.split("#")[-1], 0) if "#" in o else 0
                if size is None and o.startswith("w2,#") and ins[j].mnemonic in ("mov", "movz"):
                    try:
                        size = int(o.split("#")[1], 0)
                    except (ValueError, IndexError):
                        pass
            if off is not None:
                hits.append((i.address, off, size, nm))
        return hits

    found, near = [], []
    seen_name = set()          # 原版口径，仅用于统计漏报
    seen_ctx = set()           # context 口径
    visit_count = 0
    skipped_by_name = 0
    skipped_context_diff = 0
    name_ctxs = defaultdict(set)
    truncated = False

    def walk(name, depth, frames):
        nonlocal visit_count, skipped_by_name, skipped_context_diff, truncated
        visit_count += 1
        if visit_count > a.max_visits:
            truncated = True
            return
        if depth > a.depth:
            return
        if name in seen_name:
            skipped_by_name += 1
            name_ctxs[name].add(frames)
            # 该 name 已有不同 frames 上下文 => 原版漏报
            if any(c != frames for c in name_ctxs[name]):
                skipped_context_diff += 1
        else:
            seen_name.add(name)
            name_ctxs[name].add(frames)

        if a.mode == "context":
            key = (name, frames)
            if key in seen_ctx:
                return
            seen_ctx.add(key)

        va = v.syms[name]
        f = v.frame(va)
        cur = frames + f
        for addr, off, size, cn in copies(va):
            dminus = G.S_FRAME + cur - off
            eff = size if size is not None else 128
            hi = G.WAITER + eff - G.WAITER_SZ
            rec = (name, addr, off, size, dminus, cn, hex(cur), depth)
            if G.WAITER <= dminus <= hi:
                found.append(rec)
            elif G.WAITER - 0x100 <= dminus <= hi + 0x100:
                near.append(rec)
        for c in v.callees(va):
            walk(c, depth + 1, cur)

    for e in entries:
        walk(e, 0, 0)

    print(f"模式={a.mode} 深度<={a.depth} 前缀={copy_prefix}")
    print(f"入口 {len(entries)}，访问 {visit_count} 次，截断={truncated}")
    print(f"原版 name 判重跳过 {skipped_by_name} 次；其中不同累计帧上下文 {skipped_context_diff} 次")
    print(f"命中 {len(found)}，近失配 {len(near)}（原版基线：命中 0，近失配 66）\n")
    if found:
        print("=== 新命中 ===")
        for r in sorted(found, key=lambda x: x[4])[:30]:
            print(f"  {r[0]:26s} d-buf={r[4]:#x} off={r[2]:#x} size={r[3]} cum={r[6]} depth={r[7]} {r[5]}")
    if near:
        print("=== 近失配（按接近 0x2a3，前 20）===")
        for r in sorted(near, key=lambda x: abs(x[4] - 0x2A3))[:20]:
            print(f"  {r[0]:26s} d-buf={r[4]:#x} off={r[2]:#x} size={r[3]} cum={r[6]} depth={r[7]} {r[5]}")


if __name__ == "__main__":
    main()
