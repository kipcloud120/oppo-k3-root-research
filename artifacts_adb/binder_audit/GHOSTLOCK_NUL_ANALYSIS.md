# GhostLock 剩余两项的静态收束（响应审核意见 v001 · P0）

- 触发：`docs_archive/审核意见CHATGPT-v001.txt` 第五节 P0——"只解决剩余两个问题：① W 退出 futex wait 后调用 fgetxattr 是否复用原栈槽；② NUL 截断约束下能否满足 fake waiter 所需字段"。
- 日期：2026-11-17
- 性质：**纯静态**。未连设备、未触发内核、未改任何设备状态。
- 上游：`GHOSTLOCK_RESCAN.md`（载体候选已找到）。本文只处理"载体找到之后还缺什么"。

## 1. 结论

审核意见列出的四项待验证，本轮全部给出静态判定；其中两项被**改写**而非"继续待验证"。净结果是：GhostLock 的缺口从"栈载体/时机"推进到**"缺一次内核地址泄露"**。

| # | 待验证项 | 判定 | 依据 |
|---|---|---|---|
| 1 | 栈槽写入后被内核局部量覆写 | **已排除**（复核确认） | §2.2：`getxattr` 的 prologue store 区间 `[sp+0x110, sp+0x150)` 与 copy 缓冲 `[sp+8, sp+0x108)` **不相交**；copy 之后全函数无 store |
| 2 | 调用深度 >3 是否有新机制 | **已排除** | `GHOSTLOCK_RESCAN.md` §4.4（depth 4，78,944 次访问，无新原语） |
| 3 | **栈重生时机** | **不是"时机"问题，是几何问题；静态判定为确定性复用** | §3：同线程、每次异常入口 sp 复位到栈顶、帧长定长、无 VLA、`el0_svc_handler` 项相消 |
| 4 | **NUL 截断能否构造 fake waiter** | **NUL 本身不阻断**；但把约束精确化为"81/129/161 字节全非零"，并暴露真正的闸门 | §4、§5 |

**判定更新：GhostLock 面维持 no-go，但理由换成一条新的、可命名的阻断——"无内核地址泄露，因此 fake waiter 无法指向可控的 `rt_mutex`"。** 这不再是 `397/0 穷尽证明`，也不是"参数没调对"。

## 2. 取证事实（可离线复现）

工具：`tools/gl_nul_analysis.py`（新增；读 `firmware_F16/vmlinux.elf`）。

### 2.1 拷贝原语的语义

```
strncpy_from_user        @0xffffff80084b42b8  size=0x278
__strncpy_from_user      <不存在>          <- 无 arm64 asm 变体
__arch_copy_from_user    @0xffffff800847b500  size=0x280  <- 仅用于 xattr value（kvmalloc，堆）
```

无 `__strncpy_from_user` ⇒ 走 `lib/strncpy_from_user.c` 的 C 实现，语义为：

1. 逐 8 字节字拷贝，遇含 NUL 的字时按 `zero_bytemask` 掩码后整字存储 ⇒ **NUL 之后、同一字内的字节被写成 0**；
2. 再往后的字节**不被写**（保留内核栈残余）；
3. `getxattr()` 的 `kname[XATTR_NAME_MAX+1]`=256 B，`error == sizeof(kname)`（即串长无 NUL）返回 `-ERANGE`。

### 2.2 拷贝点之后无覆写（自带复现）

`getxattr @0xffffff8008271408`（size `0x1a0`）全部栈写只有 4 条，全在 prologue：

```
0x827140c  stp x29,x30,[sp,#0x110]
0x8271414  stp x28,x23,[sp,#0x120]
0x8271418  stp x22,x21,[sp,#0x130]
0x827141c  stp x20,x19,[sp,#0x140]
0x8271440  bl  strncpy_from_user          <- copy 目标 = sp+8，长度 0x100
（其后 0x8271440..0x82715a4 共 90 条指令，无任何 st*）
```

copy 缓冲 `[sp+8, sp+0x108)` 与寄存器保存区 `[sp+0x110, sp+0x150)` 不相交。**另有一条更强的性质**：缓冲整体位于 `getxattr` 自身 `sp` 之上（更浅），所以被调用者的帧与中断帧（压在该 `sp` 之下）**不可能**碰到它。

> 附带澄清：`setxattr` 里另有 `bl __arch_copy_from_user`（`0x82712f8`），那是 xattr **value** 的拷贝，方向是 `kvmalloc` 的堆缓冲，与栈载体的判据无关，不要混用。

### 2.3 字节映射（三条候选路径）

串自 buffer 起点写入 ⇒ `串索引 = waiter偏移 + (waiter - buffer)`。waiter(72 B) 整体落在 256 B 缓冲内 ⇒ **72 字节全部由用户串覆盖**，不存在"前面留下残余"的可能。

| 字段 | waiter 偏移 | fgetxattr (boff=0x10) | getxattr (0x40) | setxattr (0x60) |
|---|---|---|---|---|
| `tree_entry.__rb_parent_color` | 0x00 | 0x10 | 0x40 | 0x60 |
| `tree_entry.rb_right` | 0x08 | 0x18 | 0x48 | 0x68 |
| `tree_entry.rb_left` | 0x10 | 0x20 | 0x50 | 0x70 |
| `pi_tree_entry.__rb_parent_color` | 0x18 | 0x28 | 0x58 | 0x78 |
| `pi_tree_entry.rb_right` | 0x20 | 0x30 | 0x60 | 0x80 |
| `pi_tree_entry.rb_left` | 0x28 | 0x38 | 0x68 | 0x88 |
| `task` | 0x30 | 0x40 | 0x70 | 0x90 |
| `lock` | 0x38 | 0x48 | 0x78 | 0x98 |
| `prio` | 0x40 | 0x50 | 0x80 | 0xa0 |
| **覆盖全部被读字段需串长** | — | **84** | **132** | **168** |

三条均在 `XATTR_NAME_MAX`=255 之内 ⇒ **长度不是约束**。（若算到结构尾部 `0x48` 则为 88/136/172 B，byte `0x44..0x47` 不被任何字段读取。）

## 3. 栈重生：为什么它不是"时机"问题

审核意见把"栈槽复用"列为需要实机验证的未知量。它其实是一个**纯几何**命题：

1. 复用只在**同一线程**内发生（waiter 在 W 的内核栈上）；W 从 `futex_wait_requeue_pi` 返回后调 `fgetxattr`，两者共用 `el0_svc_handler`，该项在差额中相消（HANDOVER §5.2.4 已用同一口径算出 `-0x288`）。
2. arm64 每次异常入口把 `sp` 复位到该线程内核栈顶（`THREAD_SIZE` 顶端），不存在"栈指针漂移"。
3. `SyS_fgetxattr → getxattr` 全路径无 VLA／无 `alloca`、帧长定长（`getxattr` = `0x150`），因此**同一路径每次落点相同**。
4. 内核对内核栈不做清零 ⇒ 上一轮 syscall 的字节留在原处。

⇒ **"能否复用"由构造保证，不是概率事件；不需要用设备去"验证时机"**。程序序上唯一的前提是"futex 先返回、xattr 后调用"，这在用户态可由 `pthread` 顺序强制。

真正与中断有关的风险也已排除：缓冲在 `getxattr` 的 `sp` 之上，中断帧压在该 `sp` 之下（§2.2 末）。

**结论：第 3 项从"待实机验证"降级为"静态成立"。**

## 4. NUL 约束的真实形态

审核意见的担心是"`strncpy_from_user` 遇 NUL 停止，而指针/优先级字段含零字节"。精确化之后，这个担心**部分成立、但落在别处**：

1. **要写满 fake waiter，串必须是连续非零的前缀**，长度至少到 `prio` 低字节 +1：**81 / 129 / 161 字节**（三条路径各自）。
2. **`prio` 不必靠用户写满**：串终止 NUL 落在 `prio` 的第 2 字节，`zero_bytemask` 把同字剩余字节置 0 ⇒ `prio` 自动成为 `0x000000XX`，`XX ∈ [1,255]` 全部合法。这一项**反而被 NUL 语义帮了忙**。
3. **`prio` 必须 ≠ `task->prio`**：`rtmutex.c:611` 判等时若相等，`detect_deadlock=1` 只会把 `requeue` 置 false，链走查继续但**跳过 `[7]` 的 dequeue/enqueue**——写原语消失。W 的 `prio` 为 120（普通），故取 `XX=130` 一类即可。
4. **残余不可用**：想"少写一点、让内核残余补齐下游字段"是不成立的——终止 NUL 恰好落在**下一个字段的首字节**，任何指针首字节被清零即失效。⇒ 必须整段非零，不存在混合构造。

## 5. 决定性：fake waiter 的读取面（源码级）

`rt_mutex_adjust_prio_chain()`（v4.9，`src_ref/kernel_49_mainline/rtmutex.c`）对 `waiter = task->pi_blocked_on` 的读取顺序：

| 行 | 动作 | 对 fake waiter 的要求 |
|---|---|---|
| :560 | `if (!waiter) goto out` | 非 NULL |
| :579 | `if (next_lock != waiter->lock) goto out` | **天然通过**：`next_lock` 由 `task_blocked_on_lock()` 从同一字段读出（守卫退化，§5.2.6 已记录） |
| :611 | `if (waiter->prio == task->prio)` | 必须不等（否则无 requeue） |
| :621 | `lock = waiter->lock` | 必须是**可写、结构合法**的 `rt_mutex` |
| :627 | `raw_spin_trylock(&lock->wait_lock)` | 第一处内核对 fake 对象的写（`lock+0`），ticket 锁要求两半相等 |
| :642 | `lock == orig_lock \|\| rt_mutex_owner(lock) == top_task` | 不能命中，否则干净 `-EDEADLK` |
| :703 | `prerequeue_top_waiter = rt_mutex_top_waiter(lock)` | `lock->waiters_leftmost` 若非 NULL 会被当 waiter 解引用 |
| :706 | `rt_mutex_dequeue(lock, waiter)` | `RB_EMPTY_NODE(&waiter->tree_entry)` 为假时走到 `rb_erase`，按攻击者给的 `__rb_parent_color/left/right` **派生出写地址** |
| :707 | `waiter->prio = task->prio` | 自写，无害 |
| :708 | `rt_mutex_enqueue(lock, waiter)` | `rb_link_node` 会把 `tree_entry` 的 `left/right` 置 NULL 并挂进 `lock->waiters` |

**关键放宽**：`waiter->task`（0x30）在本路径**不被解引用**。全文件仅两处使用——`:975`（赋值）、`:1067`（`wake_q_add`，唤醒路径）；`rt_mutex_waiter_less()` 只在 `dl_prio(left->prio)`（`prio < 0`）时才读 `task->dl.deadline`。⇒ `task` 只要 8 字节全非零即可，不必是有效 `task_struct`。

## 6. 新增闸门（这就是现在的阻断点）

`rb_erase/insert` 的写地址由 fake waiter 的 `__rb_parent_color / rb_left / rb_right` 派生（`rb_parent()` 会清低 2 位）。这几项必须**非零**（§4.4），而"干净"取值恰好都需要零字节或需要栈地址：

| 想要的取值 | 为什么不成立 |
|---|---|
| `RB_EMPTY_NODE` 自引用（让 dequeue 直接返回） | 需要 `__rb_parent_color == &waiter->tree_entry`，即**内核栈地址**，本机无泄露 |
| `rb_left/rb_right = NULL`（叶子节点常态） | 含 `0x00`，串在此截断，后续字段全废 |
| `lock` 指向攻击者可控对象 | 需要该对象的**内核地址**；`pi_state` 在 `kmalloc-128`，地址随 KASLR/分配次序变化 |

⇒ 两个必要条件都归约为同一件事：**必须知道至少一个内核地址**。而本机不具备任何泄露通道（HANDOVER §2.3：`/proc/kallsyms`、`/proc/iomem`、`dmesg`、`/dev/kmsg`、`pstore` 全不可读；`RANDOMIZE_BASE=y`；无 `BPF`/`KPROBES`/`perf`）。

**这与"参数没调对"有本质区别**：即使栈载体、栈复用、payload 长度、`prio` 取值全部就位，缺的仍是"往哪里写"。审核意见把 GhostLock 定位为"已找到载体、待验证利用条件"——本轮的修正是：**载体这一侧已闭合，剩下的条件不在 GhostLock 里，而在"泄露原语"里。**

## 7. 若仍要上机：能否设计出可证伪的实验

按 HANDOVER §11 第 3 条（判据先登记再运行），先问"这个实验能不能给出结论"：

| 实验 | 设计方案 | 能否结论 |
|---|---|---|
| E1 验证栈槽复用 | W 在 futex 超时返回后调用 `fgetxattr` | **不能**。xattr 的返回值只反映文件系统语义（`-ENODATA`/`-ERANGE`），不暴露栈内容；没有任何无创 oracle 能观测"旧 waiter 槽是否被覆盖"。**"复用"只有触发链走查才能观测** |
| E2 端到端 | 需要 fake `lock` 地址 | **不能**。无泄露 ⇒ 无法给出地址 ⇒ 只能给随机/猜测地址 ⇒ 结果必然是 panic，而 panic 文本不可读（无 dmesg/pstore）⇒ **既不能证真也不能证伪** |

⇒ **在"无泄露"前提下，P0 的两次上机实验都不具备可证伪性。** 直接上机只会重现"帧死即 panic 3/3"这一已知现象，并消耗重启额度（§11 约定 2 次）。

**建议：P0 降级为"待泄露原语出现时再启动"**，并把触发条件写进 `HANDOVER.md` §7（已更新）。这一判断本身可被否证：若将来出现 ① 任何可用的内核地址泄露（含侧信道、`/proc` 侧信道、binder/驱动泄露），或 ② 可把用户数据写到 `[-0x288, -0x240)` 且**不经 NUL 语义**（如 `__copy_from_user` 原始字节）的载体 —— GhostLock 立刻重开。

> ② 这一点值得单列：`setxattr` 的 value 拷贝走 `__arch_copy_from_user`（原始字节，无 NUL 语义）。若某条路径让 **value** 落在 waiter 槽（而不是 `kname`），NUL 约束整体消失。本轮的三条候选都是 `kname`。这条线索已被记入负知识/重开条件，但**未**做全量扫描（`gl_carrier_rescan.py` 的 `COPY_PREFIX` 已含 `copy_from_user` 族，故理论上已被覆盖；仍建议下次复核时单独确认"raw-byte 载体"命中为 0）。

## 8. 对主文档的修改点

1. `HANDOVER.md` §1.1/§1.2：五面表述改为"四面 no-go + GhostLock 载体闭合、缺泄露"（审核意见"问题 2"）。
2. `HANDOVER.md` §5.2.4 更正块：追加本轮判定（§3/§4/§6 结论）。
3. `HANDOVER.md` §7 第 2 条：重开条件替换为"泄露原语"或"raw-byte 栈载体"。
4. `HANDOVER.md` §14.4：Binder 表述去掉"无剩余可改变结论的动作"的绝对化（审核意见"问题 3"），并把 7 个未覆盖服务与 `OplusWifiHalService.executeDriverCommand` 列为**已知未闭合项**。
5. `README.md`：首页结论、GhostLock 段落、重开条件与英文摘要同步（审核意见"问题 1"）。

## 9. 工具

```bash
python tools/gl_nul_analysis.py      # §2 的三项取证：原语归属 / 栈写区间 / 字节映射
```
