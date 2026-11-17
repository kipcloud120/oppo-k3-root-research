#!/usr/bin/env python3
"""
f16_rtmux_49_layout.py — v4.9 权威 rc 结构布局与 futex_wait_requeue_pi 帧估算

背景（第十轮）：
  src_ref/futex_4.9/ 这一套源码虽名为 4.9，实际含
  `rt_mutex_waiter::deadline`（v4.20 的 DL 感知 PI）与
  `rt_mutex_futex_unlock(wake_q)`（v4.14+），是 ~v4.20/5.0 的代码。
  它把 `rt_mutex_waiter` 算成 80 字节，而本机 4.9.227 是 72 字节。
  （注意：`waiters_leftmost` 并非差异点——4.9 的 `struct rt_mutex` 就带这个
   手工维护的字段，尺寸 32 在两边一致；第一版曾误判为 24，已修正。）

  本工具按**主线 v4.9 权威源码**重新推导：
    src_ref/kernel_49_mainline/include_linux_rtmutex.h  → struct rt_mutex
    src_ref/kernel_49_mainline/rtmutex_common.h        → struct rt_mutex_waiter
    src_ref/kernel_49_mainline/futex.c                 → futex_q / futex_pi_state / 局部变量序

产物：
  A) v4.9 关键结构字段偏移与尺寸（LP64/arm64，DEBUG_* 全关，与本机 config 一致）
  B) 与旧（误标）源码的差异对照，明确哪些旧数值必须作废
  C) futex_wait_requeue_pi 栈帧的下界估算（局部变量声明序）+ rt_waiter 偏移区间
  D) 走查语义要点自检：next_lock 与 waiter->lock 同源（退化守卫）

用法: python tools/f16_rtmux_49_layout.py
"""
import sys

DEBUG_RT = False   # CONFIG_DEBUG_RT_MUTEXES=n（本机 config 已核）
DEBUG_LOCKDEP = False

# ---------------------------------------------------------------- 基础类型
PTR = ("ptr", 8, 8)
U64 = ("u64", 8, 8)
U32 = ("u32", 4, 4)
INT = ("int", 4, 4)
U16 = ("u16", 2, 2)
U8 = ("u8", 1, 1)

# 结构体定义：(name, [(field, type_spec)])，type_spec 可直接是 (kind, size, align)
S = {}


def rb_node():
    return ("rb_node", [
        ("__rb_parent_color", U64),
        ("rb_right", PTR),
        ("rb_left", PTR),
    ])


def rb_root():
    return ("rb_root", [("rb_node", PTR)])


def list_head():
    return ("list_head", [("next", PTR), ("prev", PTR)])


def plist_node():
    return ("plist_node", [
        ("prio", INT),
        ("prio_list", list_head()),
        ("node_list", list_head()),
    ])


def arch_spinlock():
    # arm64 4.9: { u16 owner; u16 next; } (无 QUEUED_SPINLOCKS / DEBUG)
    return ("arch_spinlock_t", [("owner", U16), ("next", U16)])


def rt_mutex_49():
    # 4.9 include/linux/rtmutex.h：手工维护 waiters_leftmost（不是 rb_root_cached）
    f = [("wait_lock", arch_spinlock()), ("waiters", rb_root()),
         ("waiters_leftmost", PTR), ("owner", PTR)]
    if DEBUG_RT:
        f += [("save_state", INT), ("name", PTR), ("file", PTR),
              ("line", INT), ("magic", PTR)]
    return ("rt_mutex", f)


def rt_mutex_new():
    """旧（误标 4.9）源码的形态：含 waiters_leftmost"""
    return ("rt_mutex", [
        ("wait_lock", arch_spinlock()),
        ("waiters", rb_root()),
        ("waiters_leftmost", PTR),
        ("owner", PTR),
    ])


def rt_mutex_waiter_49():
    f = [("tree_entry", rb_node()), ("pi_tree_entry", rb_node()),
         ("task", PTR), ("lock", PTR)]
    if DEBUG_RT:
        f += [("ip", U64), ("deadlock_task_pid", PTR), ("deadlock_lock", PTR)]
    f.append(("prio", INT))
    return ("rt_mutex_waiter", f)


def rt_mutex_waiter_new():
    f = [("tree_entry", rb_node()), ("pi_tree_entry", rb_node()),
         ("task", PTR), ("lock", PTR), ("prio", INT), ("deadline", U64)]
    return ("rt_mutex_waiter", f)


def futex_key():
    return ("futex_key", [
        ("shared", ("anon", [
            ("pgoff", U64), ("inode", PTR), ("offset", U64)])),
        ("private", ("anon", [
            ("address", U64), ("mm", PTR), ("offset", U64)])),
        ("both", ("anon", [("ptr", U64), ("word", U64)])),
    ])


def hrtimer():
    # 4.9: timerqueue_node(24+8) + _softexpires + function + base + state(+is_rel 5.0+)
    return ("hrtimer", [
        ("node", ("timerqueue_node", [
            ("node", rb_node()), ("expires", U64)])),
        ("_softexpires", U64),
        ("function", PTR),
        ("base", PTR),
        ("state", U8),
    ])


def hrtimer_sleeper():
    return ("hrtimer_sleeper", [("timer", hrtimer()), ("task", PTR)])


def futex_pi_state():
    return ("futex_pi_state", [
        ("list", list_head()),
        ("pi_mutex", rt_mutex_49()),
        ("owner", PTR),
        ("refcount", INT),
        ("key", futex_key()),
    ])


def futex_q():
    return ("futex_q", [
        ("list", plist_node()),
        ("task", PTR),
        ("lock_ptr", PTR),
        ("key", futex_key()),
        ("pi_state", PTR),
        ("rt_waiter", PTR),
        ("requeue_pi_key", PTR),
        ("bitset", U32),
    ])


# ---------------------------------------------------------------- 布局引擎
def align_up(x, a):
    return (x + a - 1) // a * a


def layout(struct, cache):
    name = struct[0]
    if name in cache:
        return cache[name]
    off, mx_align, fields = 0, 1, {}
    for fname, ft in struct[1]:
        if ft[0] == "anon":                      # 匿名联合：按最大成员重叠
            sizes = [layout_sub(spec, cache) for _n, spec in ft[1]]
            sz = max(s[0] for s in sizes)
            al = max(s[1] for s in sizes)
        else:
            sz, al = layout_sub(ft, cache)[0], layout_sub(ft, cache)[1]
        off = align_up(off, al)
        fields[fname] = off
        off += sz
        mx_align = max(mx_align, al)
    size = align_up(off, mx_align)
    cache[name] = (size, mx_align, fields)
    return cache[name]


def layout_sub(t, cache):
    """返回 (size, align)"""
    if t is None:
        return (0, 1)
    if isinstance(t, tuple) and len(t) == 3 and isinstance(t[1], int):
        return (t[1], t[2])                       # 标量
    r = layout(t, cache)
    return (r[0], r[1])


def dump(struct, cache, title):
    size, al, fields = layout(struct, cache)
    print(f"  {title:<22} size={size:<4} (0x{size:03x})  align={al}")
    for k, v in fields.items():
        print(f"      {k:<20} @ 0x{v:03x} ({v})")
    return size


def main():
    cache = {}

    print("=" * 74)
    print("A) v4.9 权威布局（src_ref/kernel_49_mainline/，DEBUG_RT_MUTEXES=n）")
    print("=" * 74)
    rb = rb_node()
    dump(rb, cache, "rb_node")
    rtm = rt_mutex_49()
    sz_rtm = dump(rtm, cache, "rt_mutex")
    w49 = rt_mutex_waiter_49()
    sz_w49, _, fw49 = layout(w49, cache)
    dump(w49, cache, "rt_mutex_waiter")
    hts = hrtimer_sleeper()
    sz_hts = dump(hts, cache, "hrtimer_sleeper")
    ps = futex_pi_state()
    sz_ps, _, fps = layout(ps, cache)
    dump(ps, cache, "futex_pi_state")
    fq = futex_q()
    sz_fq, _, ffq = layout(fq, cache)
    dump(fq, cache, "futex_q")

    print()
    print("=" * 74)
    print("B) 与旧（误标 4.9，实为 ~v4.20/5.0）源码的差异 —— 旧值必须作废")
    print("=" * 74)
    cache2 = {}
    sz_rtm_new = layout(rt_mutex_new(), cache2)[0]
    sz_w_new, _, fw_new = layout(rt_mutex_waiter_new(), cache2)
    rows = [
        ("rt_mutex", sz_rtm_new, sz_rtm, "无差异：4.9 亦手工维护 waiters_leftmost"),
        ("rt_mutex_waiter", sz_w_new, sz_w49, "多 u64 deadline"),
    ]
    print(f"  {'struct':<18}{'旧(误标)':<12}{'v4.9 正确':<12}差异")
    for n, a, b, why in rows:
        print(f"  {n:<18}{a:<12}{b:<12}{'%+d' % (b - a)}  ({why})")

    print()
    print("  字段偏移对照（rt_mutex_waiter）：")
    for k in ("tree_entry", "pi_tree_entry", "task", "lock", "prio"):
        print(f"      {k:<16} v4.9=0x{fw49[k]:02x}   旧=0x{fw_new.get(k, -1):02x}")
    print(f"      {'deadline':<16} v4.9=不存在  旧=0x{fw_new['deadline']:02x}")
    print("  → 旧工具（f16_ghostlock_static.py 的 SZ/STRUCTS 表）以 80 字节建表，")
    print("    仅影响『同一栈槽内字段相对位置/size』的推断，不影响 §15.2 的缺陷结论。")

    print()
    print("=" * 74)
    print("C) futex_wait_requeue_pi 栈帧估算（声明序下界，arm64 / -O2）")
    print("=" * 74)
    # 局部变量声明序（主线 v4.9：futex.c 2810-2819）
    locals_ = [
        ("timeout", sz_hts),
        ("to", 8),
        ("rt_waiter", sz_w49),
        ("pi_mutex", 8),
        ("hb", 8),
        ("key2", 24),
        ("q", sz_fq),
        ("res", 4), ("ret", 4),
    ]
    off = 0
    print(f"  {'local':<12}{'size':<8}offset(下界)")
    for n, s in locals_:
        al = 8 if s % 8 == 0 else 4
        off = align_up(off, al)
        print(f"  {n:<12}{s:<8}0x{off:03x}")
        if n == "rt_waiter":
            rt_waiter_off_lo = off
        off += s
    total = align_up(off, 16)
    print(f"  合计局部区(下界) = 0x{total:03x} ({total} 字节)；实际帧还含：")
    print("    · 被优化后溢出到栈的调用者保存寄存器（stp x29/x30 + x19..x28）")
    print("    · 编译器插入的 padding / 临时地址槽（address-taken 的 &rt_waiter、&q）")
    print("    · 对齐填充（kernel 用 16B 栈对齐，且 -fno-omit-frame-pointer）")
    print(f"  ⇒ rt_waiter 帧内偏移区间估计：0x{rt_waiter_off_lo:02x} .. "
          f"0x{rt_waiter_off_lo + 0x40:02x}；帧长估计 0x{total:03x} .. 0x{total + 0x60:03x}")
    print("  ⇒ 该估算**仅用于选扫描窗口**，不作为可利用常量；实测见 §20.5 C1。")

    print()
    print("=" * 74)
    print("D) 走查语义自检：退化链变更守卫（4.9 与 v5.x 同形）")
    print("=" * 74)
    print("  rtmutex.c:422  task_blocked_on_lock(p) = p->pi_blocked_on->lock")
    print("  rtmutex.c:579  if (next_lock != waiter->lock) goto out_unlock_pi;")
    print("  rtmutex.c:549  waiter = task->pi_blocked_on  （与上一轮 next_lock 同一字段）")
    print("  ⇒ next_lock 与 waiter->lock 恒取自同一内存，守卫对本 UAF 恒真：")
    print("     任何被污染的 waiter->lock 都会被接受，随后 627 的")
    print("     raw_spin_trylock(&lock->wait_lock) 失败分支是**无界 goto retry**。")
    print("  ⇒ 『oracle 不返回』= 槽已被污染的确证签名，而不是『指针被清除』。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
