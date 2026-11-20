# GHOSTLOCK_HEAP_RECLAIM_FEASIBILITY.md —— G5：② 同页 slab 回收的纯离线可行性（2026-11-20）

> 承接 v13.1 阶段 3 收尾后的新线索（B3 之外）。**纯离线**：只读厂商 4.9 内核源码、本机 `vmlinux.elf`、既有实测数据（§50 / v4 P1）与公开 A17 代码；**零上机、零新增设备操作、未产出 PoC、不改变四层判定**。
> 本文回答一个具体问题：**K3 4.9 上能否把"被 KernelSnitch 泄露的 mm_struct 所在 slab 页"释放后，用同阶 AF_UNIX skb 数据页原页回收，从而得到一个"地址已知、内容可控"的内核堆页（即 ② 的地址锚点）？** 结论：**机制层可行、几何完全对齐、有公开实现范式；但"该页确实被 skb 复用"这一步无只读 oracle，纯离线无法实证——登记为"高置信候选、待上机判定"，不据此重开判定。**

---

## 0. 一句话

**K3 的几何比公开的 A17 更干净**：`mm_struct` 是 **16 KB / order-2 / 18 对象** 的 SLUB slab；`KMALLOC_MAX_CACHE_SIZE=8192` 使 16 KB 的 skb 数据走 `kmalloc_large → alloc_pages(order-2)`（不经 SLUB）；AF_UNIX **SOCK_DGRAM 16064 字节恰好等于 `SKB_MAX_ALLOC`**，走单块 linear skb，**payload 落在页基址 +0**。因此"释放 mm slab 页 → 同阶 skb 原页复用 → payload_base = 泄露页基址"在**阶、页大小、migratetype、页内偏移**四个维度上都成立；4.9 SLUB 的空 slab 丢弃条件（`min_partial=5` / `cpu_partial=13`）可用"先 seed 后 mass-free"的 groom 满足。**唯一未证的是设备上的实际页复用**（无只读 oracle），需按 §8 设计的最小判定（含一次高风险触发）才能闭合；当前"不重启"约束下不做。

---

## 1. 问题与 v10 的边界（先厘清"这不是什么"）

### 1.1 目标（② 的地址锚点）

GhostLock 的 N1 需要一个"有效、可控、结构合法"的 rt_mutex 对象地址。B3（真实静态锁）已被 G4 否证。② 的另一形态是：**在攻击者可控的堆页上伪造一个 rt_mutex + decoy waiter**，页地址已知。若能得到该页，4.9 的 `:702` 检查（G4 §3）可由页内 decoy waiter 满足，链走查可干净返回，并给出一个受约束写原语（§5）。

### 1.2 v10 否证的是"时间邻接/固定 delta"，不是"同页回收"

§50 的否证对象（原文口径）：以已知 mm 为锚，依赖 **buddy 分配流的时间邻接** 预测 **喷射页落点**；参考项目的 `SKB_DATA_DELTA=-0xe80` 固定 delta 被真机证伪——**相邻 fresh mm slab 页**（时间上相邻、中间隔 300–1000 次 order-2 分配）落点相距 1.0–5.5 GiB、方向随机。

| 模型 | 地址来源 | 是否被 v10 否证 |
|---|---|---|
| M2-a 时间邻接/固定 delta：由 mm 地址 + 常量推算"另一个" skb 页 | 跨页预测 | **是**（§50） |
| M2-b split-pair：同 order-2 块两半 ±16 KB 邻接 | 跨页几何 | 未被否证，但项目判定"不作为闭合依据"（§50.3） |
| **M2-c 同页回收（本文）**：释放 mm 所在 slab 页 → 同阶 skb 数据**复用同一页** | **泄露页本身** | **未被 v10 覆盖**（v10 测的是不同页之间的 delta） |

> **关键差异**：M2-c 不预测"另一个页在哪"，而是把**已知页**变成自由页再拿回来——地址恒为 `leaked_mm & ~0x3FFF`，**delta = 0**，不存在跨页 delta 公式。

---

## 2. 公开依据：A17（arm64 6.12）的同页回收范式

公开的 GhostLock Android 链（Mobile Hacking Lab / `ghostlock-a17`）在 arm64 上正是这个模型（源码可复算）：

```c
/* src/core/util.c（A17，6.12） */
uintptr_t base = leaked & ~(ORDER3_SIZE - 1);        /* 泄露 mm 的 slab 页基址 */
uintptr_t payload_base = base + SKB_DATA_DELTA;      /* A17 常量 -0xE80（stream/frag 路径） */
fake_lock = payload_base + LOCK_OFF;                 /* 页内伪造 rt_mutex */
...
/* prepare_kernel_page：先 kill 大量 pre/post/spray 子进程（释放 mm slab 页），
   再在同 CPU 上 sendmsg 喷射 skb，payload 写入该页 */
```

其 fake lock 的等待树**预置为页内的 decoy waiter**（`lock->waiters.rb_node = lock->waiters_leftmost = fake_w0`），这正是 4.9 `:702` 要求的"非空且一致"的 top waiter——**真实共享锁给不了，页内伪造锁可以**（与 G4 §4 的 P3 一致）。

**A17 与 K3 的差异（K3 更简单）**：

| 项 | A17（6.12, mt6789） | K3（4.9, sdm710） | 影响 |
|---|---|---|---|
| skb 发送 | `SOCK_STREAM` 64 KB（linear 3776 + frags） | **`SOCK_DGRAM` 16064 = 单块 linear** | K3 无 frags、无 `-0xE80` 类偏移 |
| skb data 分配 | 线性头 kmalloc + frag page_frag | `kmalloc_large → alloc_pages(order-2)` | K3 与 mm slab 同阶、原页级回收 |
| mm slab | 1280 B × 25，order-3 | 896 B × 18，**order-2** | 与 16 KB skb data 精确 1:1 |
| payload 偏移 | `SKB_DATA_DELTA=-0xE80` | **0（页基址）** | K3 无需负 delta |
| 触发链 | 6.12（`rt_mutex_top_waiter` 有空树保护） | 4.9（无保护，需 decoy） | 用页内 decoy 满足 `:702` |

> 公开代码是**范式依据**，不是 K3 的可执行结论；以下 4.9 侧事实全部来自本仓库厂商源码（`.build/vendor_kernel_full/`，提交 `bf9316a9`）。

---

## 3. 4.9 机制事实（逐条源码 + 既有实测）

### 3.1 skb 数据确实是一个 order-2 原页，且 payload 在页基址

| # | 事实 | 依据 |
|---|---|---|
| F1 | `CONFIG_SLUB` 下 `KMALLOC_SHIFT_HIGH = PAGE_SHIFT + 1 = 13` ⇒ `KMALLOC_MAX_CACHE_SIZE = 8192`；更大的 kmalloc 走 **`kmalloc_large`** | `include/linux/slab.h:223-233, 248-253` |
| F2 | `kmalloc_order(size, flags, order)`：`flags |= __GFP_COMP; page = alloc_pages(flags, order)` —— **直接 buddy 分配，不经 SLUB** | `mm/slab_common.c:1041-1050` |
| F3 | `__kmalloc`：`size > KMALLOC_MAX_CACHE_SIZE` ⇒ `kmalloc_large` | `mm/slub.c:3935-3941` |
| F4 | `SOCK_DGRAM` 的 `len > SKB_MAX_ALLOC` 才用 frags；`SKB_MAX_ALLOC = 16384 - 320 = 16064` ⇒ **len=16064 时 `data_len=0`** | `include/linux/skbuff.h:229-235`；`net/unix/af_unix.c:1692-1707` |
| F5 | `alloc_skb_with_frags(header_len=16064, data_len=0)` → 只 `alloc_skb(16064)`，无 frag | `net/core/skbuff.c:4843-4902`（`:4868`） |
| F6 | `__alloc_skb`：`size = ALIGN(16064,64) + ALIGN(320,64) = 16384`；`kmalloc_reserve(16384)` → order-2 | `net/core/skbuff.c:287-289` |
| F7 | `skb->head = data; skb->data = data;` 用户数据从 `skb->data` 起复制（`skb_copy_datagram_from_iter(skb, 0, ...)`）⇒ **payload 在页基址 +0** | `net/core/skbuff.c:309-311`；`net/unix/af_unix.c:1716-1719` |
| F8 | 既有实测：SOCK_DGRAM 16064 → 每轮 **3072** 个对象（256 socket × 12，RCVBUF 限制）、spread=0.00%，22–43 ms | `live_probe/LIVE_PROBE_RESULT_v4.md:62-77` |

> 结论：**payload_base = leaked_page_base + 0**；fake 结构直接写在页内任意偏移（≤16064，避开 16064–16383 的 `skb_shared_info`）。

### 3.2 mm_struct slab 是 order-2、18 对象，可整页释放

| # | 事实 | 依据 |
|---|---|---|
| F9 | `mm_struct`：896 B × 18 obj / 4 pages（**order-2**）；`slabdata 21` | 设备 `/proc/slabinfo`（`artifacts_adb/k3_info.txt:413`） |
| F10 | 厂商树把 `slub_min_objects` 固定为 **10**（`VENDOR_EDIT`），故 896 B 选 order-2/18 obj（与 slabinfo 一致） | `mm/slub.c:3444-3446`（`calculate_order`） |
| F11 | `mm_cachep` 的 `min_partial = max(5, ilog2(896)/2=4) = 5`；`cpu_partial = 13`（size∈[256,1024)） | `mm/slub.c:3777`、`:3607-3613`、`:173`；`:3796-3805` |
| F12 | 空 slab **只有当** `n->nr_partial >= s->min_partial` 时才 `discard_slab`（三条路径：`:2240` deactivate、`:2351` unfreeze、`:3056` __slab_free） | `mm/slub.c` |
| F13 | `discard_slab → __free_slab → __free_pages(page, order=2)`；order>0 走 `__free_pages_ok → free_one_page → __free_one_page`（**buddy free list**，非 PCP） | `mm/slub.c:1812-1892`；`mm/page_alloc.c:4285-4292`、`:1367`、`:904` |
| F14 | `exit_mm → mmput → __mmput → mmdrop → __mmdrop → free_mm = kmem_cache_free(mm_cachep, mm)`，**同步**、无 RCU 延迟 | `kernel/fork.c:733-734`、`:877-885`、`:913-925` |

> 结论：**只要让目标 slab 变空且 node partial ≥5，页就回到 buddy（order-2, MIGRATE_UNMOVABLE）**；随后同阶 `alloc_pages` 可取回。

### 3.3 同阶回收的分配器条件

| 条件 | 4.9 事实 |
|---|---|
| order 相同 | mm slab = 2；skb data = 2（F5/F6） |
| migratetype 相同 | slab 页由 `GFP_KERNEL`（UNMOVABLE）分配；skb data `GFP_KERNEL`（UNMOVABLE） |
| zone 相同 | 均为 ZONE_NORMAL（无 movable 隔离证据；`CONFIG_MEMCG` off） |
| 取回顺序 | 4.9 order>0 不走 PCP；buddy `free_list[order]` **头插/头取（LIFO）**，`__rmqueue_smallest` + `expand()` 劈裂大块 |
| 竞争者 | 其它 order-2 分配（网络/驱动/子进程退栈）会竞争；用"大量喷射 + 立即喷 + 绑核"对冲 |

### 3.4 SLUB 空 slab 丢弃的可控性（本模型最关键的一步）

4.9 SLUB 的两种空 slab 处理：

- **未冻结**（在 node partial 表上）的 slab 变空：`__slab_free` 直接判 `!new.inuse && n->nr_partial >= 5` → `discard_slab`（`:3056-3086`）；
- **冻结**（在 CPU partial 表上）的 slab 变空：最后 free 只更新 freelist（`n==NULL` 提前返回，`:3037-3053`），要等 `put_cpu_partial()` 触发 **CPU partial 排空**（`pobjects > cpu_partial`，`:2399-2412`）→ `unfreeze_partials()` 在 `nr_partial >= 5` 时丢弃空页（`:2351-2370`）。

⇒ 若直接 mass-free，前 5 个空 slab 可能被保留为 node partial（不返回 buddy），**取决于泄漏页排在第几个**。**稳健做法**（本模型的 groom）：

1. 先建 ≥32 个 slab（576 个子进程，绑同一 CPU）；
2. **seed**：每个 slab 杀 1 个对象 → slab 以"17 in use"进入 CPU partial；`pobjects` 累加，超过 13 后 `unfreeze_partials` 把它们移到 node partial（**非空**，不会丢），`nr_partial` 迅速 ≥5；
3. **mass-free**：杀掉剩余对象；每个 slab 已在 node partial 上，最后一 free 直接命中 `discard_slab`（**目标页必被释放**）；
4. **立即同 CPU 喷射** 16064 字节 dgram（3072 页 ≫ 32 页），把刚释放的 order-2 页从 buddy 取回，payload 写入页基址。

> 注：A17 的设计用 32 个 `prepare` slab + pre/leak/post 分组（先 free 其它、leak 子进程最后退出）达到同样的效果；K3 可沿用并把 seed 显式化以消除"前 5 个空 slab 被保留"的不确定性。

---

## 4. K3 的完整序列（离线设计，未执行）

```
[W 线程] 已存在（xattr 载体，栈上 fake waiter 的写入时机见 §4.2）
   │
[0] 绑核 CORE；fork 576 个子进程（每个 dup_mm 分配一个 mm_struct）
       └ 前 ~40 个用于"暖机"（消耗 mm_cachep 的 partial），随后按 18 对齐
[1] 在 pre=17 个之后 fork "leak child"（其 mm 恰好填满同一 slab 的最后一个槽）
[2] leak child 运行 KernelSnitch，得到它自己的 mm_struct VA；保持存活（pause）
[3] 父进程：leaked_base = mm_va & ~0x3FFF（16 KB 对齐）
       └ 该页的 18 个 mm 对象 = pre 17 个 + leak child（+ 暖机残留的最后一个 slab 由 pre 填满）
[4] seed：杀掉"每 slab 1 个"子进程（含 pre 组）→ node partial ≥5
[5] mass-free：杀掉剩余子进程 + leak child → 该 slab 页变空 → discard_slab → buddy
[6] 立即在同一 CPU 上 SOCK_DGRAM 喷射 3072 × 16064 字节
       └ payload 内容 = 页内 fake lock（+0x40）+ decoy waiter（+0x200）+ 预留 fake struct
       └ payload_base = leaked_base（delta 0）；fake_lock = leaked_base + 0x40
[7] 把 leaked_base + 0x40 写进 W 栈上 fake waiter 的 lock 字段（xattr 载体，NUL 约束见 §7）
[8] sched_setscheduler(W) 触发链走查（G4）：:702 读 decoy → :705 rb_erase(fake stack waiter)
       → 写原语（§5）→ :726 enqueue → owner=0 → 干净返回
```

### 4.1 页内布局（16 KB 页，payload 16064 B）

| 偏移 | 内容 | 说明 |
|---|---|---|
| 0x000 | 预留（会被 `rb_set_parent` 覆盖为 Q\|1，若 V=页基址） | 或选 V 避让 |
| 0x040 | fake `rt_mutex`（0x20 B） | `wait_lock=0`、`waiters.rb_node=decoy`、`waiters_leftmost=decoy`、`owner=0` |
| 0x200 | decoy waiter（0x50 B） | `tree.entry` 黑根、`pi_tree.entry` 自清、`task=&init_task`、`lock=fake_lock`、`prio=120` |
| 0x400+ | 预留 fake struct（endgame 用） | 不参与本阶段地址判定 |
| 16064–16383 | `skb_shared_info`（内核写） | 禁止放任何结构 |

### 4.2 与既有载体的接口

- W 的栈上 fake waiter（xattr 写入）**只需**把 `lock` 字段改成 `leaked_base+0x40`；其余字段（tree/pi_tree/task/prio）按 G4 §4 的写原语构造；
- 所有值必须满足 `strncpy_from_user` 的 **NUL 约束**（C2，已由 `GHOSTLOCK_NUL_ANALYSIS.md` 分析）；低概率的地址含 0 字节 → 重试新一轮回收即可（地址概率 ~1%/轮量级）。

---

## 5. 链走查后的写原语（4.9，G4 的延伸）

在 §4 的 fake lock/decoy 下，G4 §4 的 E2/E3 退化为**完全可控**：

| 步骤 | 行为 | 结果 |
|---|---|---|
| `:641` | `owner(lock)=0 ≠ top_task`，`lock≠orig_lock` | 继续 |
| `:702` | `top_waiter = decoy`；`decoy->lock == lock` | **BUG_ON 通过** |
| `:705` | `rb_erase(fake_stack_waiter)`：fake 不在树中，`parent_color=Q`、`left=0`、`right=V` | `Q->rb_right = V`（即 **`*(u64*)(Q+0x10)=V`**）；若 V≠0，`*(u64*)V = Q\|1` |
| `:726` | `rb_add(fake)` 到 decoy 的右子（等 prio，非 less）；decoy 黑 | 树自洽 |
| `:739` | `owner==0` → `top_waiter=decoy`；`prerequeue==top` | 不唤醒、解锁、**返回 0** |

⇒ **写原语**：`target = Q+0x10`；`V=0` 时为 **8 字节零写**；`V=可写内核地址` 时写入 `V` 并把 `*(u64*)V` 覆盖为 `Q|1`（V 选页内偏移即可承受）。
- 全程只触碰：目标静态地址 `Q+0x10`、我们自己的页（V）、W 的栈（fake）、以及 W 的 `pi_lock`；
- **不触碰任何真实内核锁对象**（与 B3 的本质区别），因此没有 G4 的"孤儿/幽灵 waiter/真实锁损坏"问题；
- 写原语是"一次写"，目标/值受上述代数约束；**endgame（用这次写做什么）是下一阶段问题**，不在本文范围。

---

## 6. 风险矩阵（离线可判定性 + 对策 + 可观测信号）

| # | 风险 | 离线判定 | 对策 | 设备可观测信号 |
|---|---|---|---|---|
| R1 | 空 slab 未被丢弃（node partial<5 / CPU partial 未排空） | 条件已源码确认（F12），可用 seed 满足 | §3.4 seed 32 slab | `/proc/slabinfo` mm_struct `slabdata` 是否回落 |
| R2 | 释放页被 buddy 合并成大块，未被同阶分配取回 | 合并/劈裂语义确认；大喷射可覆盖 | 3072 页 ≫ 32 页 | `/proc/buddyinfo` order-2/3 计数 |
| R3 | 释放与喷射之间被其它 order-2 分配抢走 | 窗口风险；绑核 + 立即喷 | 缩短窗口、增加页数 | 不可直接观测（见 §8 T3） |
| R4 | migratetype/zone 不匹配 | 两者均 GFP_KERNEL/UNMOVABLE/NORMAL | 无需处理 | `/proc/pagetypeinfo`（若可读） |
| R5 | 泄漏页不全是"我们的" mm（被其它进程占槽） | 暖机 + pre/leak/post 对齐可满足 | 40 slab 暖机 | slabdata 增量与 fork 数对齐 |
| R6 | dgram 路径在 16064 边界跳 frags | F4 已确认 16064 是闭区间上界 | 严格 16064，不加 1 字节 | v4 P1 已实测 order-2 |
| R7 | xattr NUL 约束截断 fake waiter | C2 已分析；地址含 0 概率低 | 重试/地址选择 | 触发前无法观测 |
| R8 | W 栈载体几何（C3） | 已静态解决 | 既有载体 | — |
| R9 | 链走查与 fake lock 不匹配 → `:702` fault | §5 静态推演通过；任何字段错即 panic | 离线复核 + 低风险预演 | 触发即知（有风险） |
| R10 | endgame（写目标/值）| **不在本文范围** | 下一阶段审计 | — |

---

## 7. 判定（R6 证据等级：源码推导 + 公开实现类比，未上机）

| 维度 | 结论 | 等级 |
|---|---|---|
| 几何（阶/页大小/对象数） | **完全对齐**（16 KB ↔ 16 KB；18 obj ↔ order-2） | 源码 + 设备 slabinfo（确认） |
| payload 落点 | **页基址 +0**（dgram 16064 单块 linear） | 源码（确认）+ v4 实测 order-2（确认） |
| mm 页可释放 | SLUB 条件明确、可 groom | 源码（确认） |
| 页可被 skb 原页复用 | **机制成立，未实证** | 公开 A17 范式（同类内核）+ 离线推导（未证） |
| 触发路径 | fake lock/decoy 满足 4.9 `:702`，写原语自洽 | 源码/二进制（G4）+ 离线推导 |
| 结论 | **② 的地址锚点存在一条"高置信、待上机判定"的可行路线**；不构成本机"已闭合" | 未证实候选 |

**对项目判定的影响**：

1. **不改变四层判定**：可用 ROOT / 持久 ROOT 仍 **NO-GO**；GhostLock 冻结维持；本路线只解决"N1 地址来源"的候选，不等于提权。
2. **② 的状态从"v10 否证后无路"更新为"时间邻接路线否证，但同页回收路线未被否证、机制可行"**——按 R6 记为"未证实候选"，不得写成"② 已闭合"或"可重开"。
3. **B3 不受影响**：B3（真实锁）仍是"已审计否决"；本文的路线不依赖任何真实内核锁，反而印证 G4 的 P3（必须可控的伪造锁）。
4. **v10 的口径需要补充说明**（不是撤回）：§50 否证的是"时间邻接/固定 delta"，本文的"同页回收"是不同机制；两者不可混用。

---

## 8. 最小上机判定设计（待用户逐次授权；当前"不重启"约束下不执行）

### T1（只读，低风险）：mm slab 页是否真的回到 buddy

- 绑核 fork 576 子进程；记录 `/proc/slabinfo` 的 `mm_struct` `slabdata`；
- 按 §3.4 seed 后 mass-free；再读 `slabdata`；
- 若 `slabdata` 回落 ≈32（或按 seed 数回落）且 `active_objs` 大幅下降，**F12 成立（页已释放）**；否则说明 seed/阈值需调。

### T2（只读，低风险）：dgram 喷射确实消耗 order-2 页

- T1 后立即喷 3072 页；读 `/proc/buddyinfo` 的 order-2/order-3 计数变化；排空后复读；
- 结合 v4 P1（3072/轮、order-2）与 `mm_struct slabdata` 不再增长，可确认"喷射拿到了刚释放的页区间"（仍非页级身份）。

### T3（高风险，需独立设备 + 明确授权）：页级身份与写原语

- 复用 §4 的页内布局，把 fake lock 的 `owner` 置 0、decoy 置好；写原语选 **8 字节零写** 到一个**可被 shell 读取**的静态 sysctl（候选：`kptr_restrict`，读回 0 即成功；失败 = 页不是我们的 → `:702` fault/panic）；
- 该测试**唯一能证明页级复用**，但违反本机"不重启"约束；必须在独立设备/可接受重启的环境、逐次授权下进行；
- 在 T1/T2 未先通过前不做 T3。

> 另有一个**弱负向只读检查**：T2 后若再 fork 一个子进程，其 mm 页面若落在 `leaked_base`，说明该页仍可被 mm cache 取回（喷射未占住它，至少不是"被 skb 稳定占用"）；但反过来不成立，不能作为正向证据。

---

## 9. 明确未做 / 未证

| 项 | 状态 |
|---|---|
| 设备上"释放页 → skb 同页复用"的页级证据 | **未做**（无只读 oracle；T3 需授权） |
| 4.9 实际 fork 上限（576 子进程）与 SELinux/RLIMIT 限制 | **未测**（纯离线；A17 用过 ~800，K3 需实测） |
| NUL 约束下 fake waiter 全字段的可写性 | 依赖 `GHOSTLOCK_NUL_ANALYSIS.md`（C2）既有结论，未在本轮重算 |
| 写原语的 endgame（目标/值/后续提权） | **未设计**（下一阶段） |
| 与 KernelSnitch 的时序（leak child 保活、kill 后立即喷） | **未实现**（需新工具） |
| 失败模式的真机表现（panic 收尾/恢复） | 未测（受"不重启"约束） |

---

## 10. 引用

- 公开范式：NebuSec IonStack II <https://nebusec.ai/research/ionstack-part-2/>；A17 移植源码 <https://github.com/mobilehackinglab/ghostlock-a17>（`src/core/util.c`、`src/core/common.h`、`src/core/target.h`）；HackTricks 摘要 <https://github.com/hacktricks-wiki/hacktricks/blob/c1ddd09679a6acbcdd268162683b1352d1a2e453/src/binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md>
- 4.9 源码：`mm/slub.c`（`:173`、`:2240`、`:2351`、`:2383-2429`、`:3004-3053`、`:3056-3086`、`:3444-3446`、`:3607-3613`、`:3777`、`:3796-3805`、`:3935-3941`）、`mm/page_alloc.c`（`:904`、`:1367`、`:4285-4292`）、`mm/slab_common.c`（`:1041-1050`）、`include/linux/slab.h`（`:223-233`）、`include/linux/skbuff.h`（`:229-235`）、`net/core/skbuff.c`（`:287-289`、`:309-311`、`:4843-4902`）、`net/core/sock.c`（`:1869-1900`）、`net/unix/af_unix.c`（`:1692-1719`、`:1858-1942`）、`kernel/fork.c`（`:733-734`、`:877-885`、`:913-925`）
- 设备实测：`artifacts_adb/k3_info.txt:413`（slabinfo）；`live_probe/LIVE_PROBE_RESULT_v4.md:62-77`（P1）；`HANDOVER.md` §50（v10 否证）与 §50.3（`kmalloc(16384)` 直连 buddy、mm_cachep order-2）
- 既有分析：`GHOSTLOCK_B3_CONCURRENCY_AUDIT.md`（G4）；`artifacts_adb/WAITER_ADDRESS_ANALYSIS.md`；`GHOSTLOCK_NUL_ANALYSIS.md`（C2）；`tools/KSNITCH_LOCAL_CHECK.md`（MM_ORDER=2 阻挡项）
- 复算：`python tools/reclaim_model.py`
