# GHOSTLOCK_B3_CONCURRENCY_AUDIT.md —— 阶段 3 / G4：B3 全局静态 rt_mutex 的并发语义与风险静态审计（2026-11-20）

> 阶段 3 收尾交付物（响应 `GHOSTLOCK_PHASE3_DECISION.md` §1 重开条件② / §6.3 第 1 项"并发语义静态审计尚未执行"）。
> **纯离线 / 只读静态审计**：读取厂商内核源码与 `firmware_F16/vmlinux.elf` 反汇编，**零上机、零新增设备操作、未产出 PoC、不改变四层判定**。
> 上游文档：`GHOSTLOCK_ADDRESS_BASELINE.md`（G0，规则 R1–R6）、`GHOSTLOCK_ADDRESS_REQUIREMENTS.md`（G1，需求 N1–N4）、`GHOSTLOCK_ADDRESS_SOURCE_MATRIX.md`（G2，§2.3 四实例枚举）、`GHOSTLOCK_PHASE3_DECISION.md`（G3，§6 B3 裁决）。

## 0. 一句话

**B3 的"地址可得性"成立（4 个静态实例，运行时 VA = 静态 VA + slide，对象类型与零初值均有源码 + 二进制证据），但"可用性"不成立：GhostLock 的链走查在 `rtmutex.c:702` 无条件读取 `lock->waiters_leftmost`（内联 `rt_mutex_top_waiter()` 的 `BUG_ON(w->lock != lock)`），该锁的等待树为空时对 NULL 解引用（必然 oops/panic）；非空时（首次使用）树中必然存在至少一个**真实、非攻击者控制**的 waiter 节点（其地址在另一线程内核栈上，无 oracle），随后的 `rb_erase(fake)`（`:705`）在真实锁树上产生不可控写 / 孤儿等待者 / 永久"幽灵顶层 waiter"，并由此把该全局锁钉死。因此 B3 不满足 N1 的"**可控**"限定，且唯一能触发写原语的路径必然越过"不制造新内核竞态 / 不强制异常"的边界。**G3 的"审计未做"状态就此终结：审计已执行，结论是否定；B3 维持冻结，四层判定 NO-GO 不变。**（证据等级：静态源码 + 精确固件反汇编 + 离线推导；无运行时观测，未上机。）**

---

## 1. 物料、方法与环境

### 1.1 物料（R2 时间归属：源码与镜像绑定同一构建家族；二进制只在当前固定资产上解释）

| 物料 | 标识 | SHA-256（LF 归一化） |
|---|---|---|
| 厂商内核树 | `oppo-source/android_kernel_oppo_sdm710`（`oppo/sdm710_r_11.0_reno`，PCAM00_11_F.56，QCOM TAG `LA.UM.9.8.R1.11.00.00.673.034_r2.1.1`） | `bf9316a9aa56ed29a4663aac968db52a73eba97d` |
| `kernel/locking/rtmutex.c` | 1826 行；与 `src_ref/vendor_sdm710_r11/` 入库副本逐字节一致（仅 CRLF/LF 差异） | `a4b9f439a72ca86eb09669ace0715501d8591d19ebe58c7057e6904a377ceb91` |
| `kernel/locking/rtmutex_common.h` | 126 行 | `6b518e9d959b5b07ff38aee06d9764f8f2a8f05830651a09166c07424bc79b03` |
| `include/linux/rtmutex.h` | 结构定义 | `fe8a7b85a333196c21af98db26a8e82bc11b345a34c27b660e56c8c69ef52309` |
| `include/linux/sched/deadline.h` | `MAX_DL_PRIO=0` | `bde95a629392b2443bec92689a2d3bb4d8cafa828e67e7bf15cdcea81605cde8` |
| `kernel/sched/core.c` | 触发点 `:4609-4610` | `25ab6e3bb82f7f6dd20a0b23c0f01839019a7019ec9b39f31bbfc8ac901d2471` |
| `lib/rbtree.c` | `rb_erase` 实现 | `912d15714ddf42418b3f0b33477ade241bb24d6afefff5471ff862bd86fed7d6` |
| `fs/proc/uid.c` | `proc_uid_lock` | `71d86b497df0d571d68db61ae1e234cbbef742aed6f800d6ef38facd3797ed53` |
| `drivers/misc/uid_sys_stats.c` | `uid_lock` | `674a7698afedc414853246d7e34430fc06f99cd516fb2318787ae4a5fa285652` |
| `drivers/soc/qcom/msm_bus/msm_bus_arb_adhoc.c` | `msm_bus_adhoc_lock` | `c0fc81f25bd783d4b95d9befdf1ecc1ee6df8fdbd3cd4555bb88a1b474fc0d80` |
| `drivers/soc/qcom/msm_bus/msm_bus_dbg.c` | `msm_bus_dbg_cllist_lock` | `763def61ceb1dc13be0f67327ee0a143b6738eba01ca839eef160d4999d88fbe` |
| `firmware_F16/vmlinux.elf` | 符号 + `.kernel`/`.kernel2`/`.bss` 段；`_text=0xffffff8008080000` | `6588c87178ecbf840f19d5fef4a0ce8f71343b7183eed721e06c546c6e36189a` |
| 内核配置（`artifacts_adb/k3_kernel_config.txt`） | `CONFIG_RT_MUTEXES=y`、`# CONFIG_DEBUG_RT_MUTEXES is not set`、`CONFIG_ARM64_UAO=y`、`CONFIG_SMP=y`、`CONFIG_PREEMPT=y`、`# CONFIG_PANIC_ON_OOPS is not set`（`PANIC_ON_OOPS_VALUE=0`） | — |

> 说明 1：`src_ref/vendor_sdm710_r11/kernel/locking/rtmutex.c` 与全树副本内容一致，仅因 CRLF 导致原始文件哈希不同；本文所有行号指向 LF 归一化后的 1826 行版本。
> 说明 2：设备内核为 K3 `PCGM00_11_F.16`，厂商树为 Reno `PCAM00_11_F.56`——同 SoC 同分支非同机型。本审计的**机制结论**只依赖 `rtmutex.c`/`rtmutex_common.h` 语义与**本机二进制**的逐指令形态（下文同时给出两者），不依赖 F.56 与 F.16 的行号一致；行号仅用于引用。
> 说明 3：本文的静态 VA 与 runtime 换算只在 `KASLR_EVIDENCE.md` 登记的当前 boot（`b9f9f06a-…`，slide `0x1953600000`）成立；重启后 slide 失效，静态 VA 不变。

### 1.2 方法（可复算）

1. **源码逐行**：`rt_mutex_adjust_pi()` → `rt_mutex_adjust_prio_chain()` 的每个分支、`rt_mutex_dequeue/enqueue`、`rb_erase`、四个锁的持锁点；
2. **本机二进制逐指令**：`firmware_F16/vmlinux.elf` 的 `.kernel` 段（capstone，静态 VA），核对调用参数、字段偏移、`BUG_ON` 的 `brk #0x800` 目标；
3. **对象字节**：四实例在 `.kernel2`/`.bss` 的 0x20 字节（`DEFINE_RT_MUTEX` 未加锁初值）；
4. 复算工具：`python tools/b3_audit.py`（只读；输出 §1.3 全部断言）。

### 1.3 复算输出（`python tools/b3_audit.py`，2026-11-20，本机）

| 断言 | 结果 |
|---|---|
| `rt_mutex_adjust_pi` = `0xffffff80081255b8`、`rt_mutex_adjust_prio_chain` = `0xffffff8008125658`（`.kernel`） | PASS |
| 4 个 B3 静态实例（`uid_lock`(rt_mutex)/`msm_bus_adhoc_lock`/`msm_bus_dbg_cllist_lock`/`proc_uid_lock`）初值 0x20 字节**全零**（空等待树 + `owner=NULL`） | PASS |
| `rt_mutex_adjust_pi` 以 `orig_lock=NULL` / `orig_waiter=NULL` / `MIN_CHAINWALK` 进入链走查（`0x8125614 mov w1,wzr`；`0x8125618 mov x2,xzr`；`0x8125620 mov x4,xzr`；`0x8125604 ldr x21,[x8,#0x38]`） | PASS |
| `:702` 内联 `rt_mutex_top_waiter()` 形态 `ldr x27,[x24,#0x10]` → `ldr x8,[x27,#0x38]` → `cmp` → `b.ne 0x8125e7c`（`brk #0x800`） | PASS（共 6 处同型序列） |
| `waiter->prio` 写点 `[w,#0x40]`、`waiter->deadline` 写点 `[w,#0x48]`（布局 0x50） | PASS |

---

## 2. 触发路径与入口参数（与 GhostLock 前提对齐）

GhostLock 的前提（N4，已复现）：W 线程的内核栈上残留一份 fake waiter，且 `W->pi_blocked_on` 仍指向它（`pi_blocked_on` 偏移 `0x928`）。用户态对 W 调用 `sched_setscheduler`（`__sched_setscheduler` 的 `pi` 参数为真）时：

- `kernel/sched/core.c:4609-4610`：`if (pi) rt_mutex_adjust_pi(p);`
- `kernel/locking/rtmutex.c:1157-1179`：
  - `:1165` `waiter = task->pi_blocked_on;`
  - `:1166-1170` 若 `waiter->prio == task->prio` 且非 DL，**直接返回**（无链走查）；
  - `:1171` `next_lock = waiter->lock;`
  - `:1174-1178` `get_task_struct(task)` 后调用
    `rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL /*orig_lock*/, next_lock, NULL /*orig_waiter*/, task /*top_task*/)`
- 二进制逐字段对应（静态 VA）：`0x81255d8 ldr x8,[x19,#0x928]`（`pi_blocked_on`）；`0x81255e4 ldr w10,[x8,#0x40]`（`waiter->prio`）；`0x81255e8 ldr w9,[x19,#0xa8]`（`task->prio`）；`0x8125604 ldr x21,[x8,#0x38]`（`waiter->lock`）；`0x8125610-0x8125624` 置 `x0=task, w1=0, x2=0, x3=next_lock, x4=0, x5=task`；`0x8125640 bl 0x8125658`。

据此，B3 场景下链走查的入口参数被**完全钉死**为：

| 参数 | 值 | 后果 |
|---|---|---|
| `chwalk` | `RT_MUTEX_MIN_CHAINWALK`（`0`） | `detect_deadlock = false`（`rtmutex.c:403-414`、`:503`） |
| `orig_lock` | `NULL` | `:641` 的 `lock == orig_lock` 永不成立 |
| `orig_waiter` | `NULL` | `top_waiter` 初值 `NULL`（`:496`），`:586-601` 整块跳过 |
| `top_task` | `W` | `:641` 的 `rt_mutex_owner(lock) == top_task` 仅在"W 自己持有目标锁"时成立 |
| `waiter->prio` | 攻击者设置（如 130），**必须 ≠ W 的 `task->prio`（120）**；`:723` 随后会把它**重写为 W 的 prio**（120）再入树 | 否则 `rt_mutex_adjust_pi :1166` 提前返回（链内 `:610` 同判），写原语消失；重写后 fake 以 120 参与排序（§4.3） |

> **推论 T0**：B3 的一切取值都必须让 `requeue = true`（`:501` 初始化）并一路走到 `:702`；`waiter->prio == task->prio` 时 `rt_mutex_adjust_pi()` 先在 `:1166-1170` 直接返回（即便进入链，`:610-615` 也会以同一条件提前退出），而 prio 相等同时消灭写原语。**"产生写"与"到达 :702"是同一件事。**

---

## 3. 核心判定点：`:702` 对 `lock->waiters_leftmost` 的无条件解引用

### 3.1 源码

```c
/* rtmutex.c:697-705 */
prerequeue_top_waiter = rt_mutex_top_waiter(lock);   /* :702 */
rt_mutex_dequeue(lock, waiter);                      /* :705 */
```

`rt_mutex_top_waiter()`（`rtmutex_common.h:47-57`）：

```c
w = rb_entry(lock->waiters_leftmost, struct rt_mutex_waiter, tree_entry);
BUG_ON(w->lock != lock);      /* :54 —— 读 w+0x38 */
```

`lock->waiters_leftmost` 为空树时为 `NULL`（`rt_mutex_enqueue` 在 `:263-264` 才置位；`rt_mutex_dequeue` 在 `:276-277` 用 `rb_next()` 维护，末节点退化为 `NULL`）。因此 **`rb_entry(NULL)` = `NULL`，`BUG_ON` 读 `NULL+0x38` ⇒ 数据异常**。

### 3.2 二进制（本机 `vmlinux.elf`，静态 VA）

```
0xffffff800812585c: tbnz  w28, #0, 0xffffff80081258d8   ; requeue 位=1 → :702 路径
0xffffff80081258d8: ldr   x27, [x24, #0x10]            ; x27 = lock->waiters_leftmost
0xffffff80081258dc: ldr   x8,  [x27, #0x38]            ; w->lock —— 空树时读 [0x38]
0xffffff80081258e0: cmp   x8,  x24                      ; BUG_ON(w->lock != lock)
0xffffff80081258e4: b.ne  0xffffff8008125e7c
...
0xffffff8008125e7c: brk   #0x800                        ; BUG_ON 的 brk
```

> 同型序列共 6 处（`top_waiter` 在 `:702`/`:745`/`:757`/`:805` 等处的多次内联），说明这不是某个编译分支的偶然：**凡 `requeue` 分支，第一步都是取 top waiter。**

### 3.3 命题 P1（空树必 fault）

> **在 `requeue = true` 的 B3 走查中，若目标锁在触发瞬间等待树为空（`waiters_leftmost == NULL`），内核在 `:702` 读 `NULL+0x38` 发生数据异常，且此时已持有 `W->pi_lock`（`:543`，IRQ 关闭）与目标锁 `lock->wait_lock`（`:626`）。该路径不产生任何写原语，结果只有 oops/panic。**

证据等级：**静态源码（确认）+ 精确固件反汇编（确认）**；未上机触发（按纪律不做）。

### 3.4 后果分级（如实登记）

- `panic_on_oops` **本机配置为未启用**（`k3_kernel_config.txt`：`# CONFIG_PANIC_ON_OOPS is not set`、`PANIC_ON_OOPS_VALUE=0`）；`boot.img` 头提取的 cmdline 中**没有** `panic_on_oops=`；但 shell 读 `/proc/sys/kernel/panic_on_oops` 被拒（`k3_info2.txt:1149`），**运行时是否被 init 改写未确认**。
- 若 `panic_on_oops=1`：立即 panic。
- 若 `panic_on_oops=0`：oops 走 `die()`/`oops_end()`，当前任务被杀；但故障点持有的 `W->pi_lock` 与目标锁 `wait_lock` 不会被释放 ⇒ 目标锁的其它使用者进入 `raw_spin_lock` 自旋（IRQ 关闭）不可恢复，该锁永久不可用（具体 oops 收尾路径未上机验证）。**无论 sysctl 取值，均属"致命"级，不是可恢复错误。**

---

## 4. 非空树：真实 waiter 必然存在，且不在攻击者控制之下

### 4.1 等待树的唯一填充者是真实任务

- `rt_mutex.c:971-1053`（`task_blocks_on_rt_mutex`）：真实任务在 `:1005` `rt_mutex_enqueue(lock, waiter)` 入树，`:1007` 置 `pi_blocked_on`；
- fake waiter 第一次进入该锁的等待树只可能发生在链走查的 `:726` `rt_mutex_enqueue(lock, waiter)`——**在 `:702` 之后**；
- ⇒ **命题 P2**：对 B3 的"首次使用"，若 `:702` 时等待树非空，则树中至少有一个节点是**真实等待者**（其 `struct rt_mutex_waiter` 位于该任务的内核栈，地址对攻击者不可知——这正是 ③ 类 oracle 缺口）。

> 注：若此前已有一次 B3 走查，fake 可能已被 `:726` 入树；但进入该状态本身必须先经过一次 P1 或 P2（见 E6），不构成"干净的首次路径"。

### 4.2 `:705` 的 `rb_erase(fake)` 语义

`rt_mutex_dequeue()`（`:270-281`）先判 `RB_EMPTY_NODE(&waiter->tree_entry)`（`:273-274`，比较 `[fake+0x00] == fake`）：

- 若 fake 的 `tree_entry` 是**自引用**（`&fake->tree_entry`，即 ③ 的当前栈精确地址），dequeue 直接返回，**跳过 `rb_erase`**——但 B3 的立项前提正是"不需要 ③"，此分支对 B3 自相矛盾（见 §6 R-i）；
- 否则 `:279` `rb_erase(&fake->tree_entry, &lock->waiters)` 照常执行：`rb_erase` 按 fake 的 `__rb_parent_color/rb_left/rb_right`（`lib/rbtree.c:424-430` → `__rb_erase_augmented`）修改 `parent->rb_left/right` 或 `root->rb_node`，并在需要时进入 `____rb_erase_color(parent, root)`（`rbtree.c:228-241`：`sibling = parent->rb_right;` 等）。**fake 从未在这棵树里，但代码把它当作树内节点擦除。**

### 4.3 两种可构造形态（均不可用）

| 形态 | fake 链接 | `:705` 之后 | 结果 |
|---|---|---|---|
| **A：全零链接**（`parent_color=left=right=0`） | `__rb_change_child(node, NULL, parent=NULL, root)` ⇒ `lock->waiters.rb_node = NULL`；`rebalance` 返回 `NULL`（`pc` 为黑、`parent` 为 NULL）⇒ 不进入 `____rb_erase_color` | 真实 waiter 节点被"拔根"成为**孤儿**（其任务陷入不可中断睡眠，永不唤醒）；`:726` 把 fake 插成唯一根；注意 `:723` 会把 `fake->prio` **重写为 W 的 prio（普通任务 120）**、`:724` 重写 deadline；`:757-766` 以 fake 为 top，把 fake 挂入真实 owner 的 `pi_waiters`（先 `dequeue_pi` 真实 waiter、再 `enqueue_pi` fake，均为合法树操作），并按 `min(fake->prio, owner->normal_prio)` 重算 owner 优先级（120 vs 120 ⇒ 不变）；owner 解锁时 `mark_wakeup_next_waiter()`（`:1061-1091`）把 fake 当作下一任等待者 → `wake_q_add(wake_q, fake->task)`（**前提：fake->task 指向有效 task_struct**；静态可见且可由 slide 复算的只有 `init_task`，指向垃圾则 `wake_q_add` 在 `get_task_struct()`/`task->wake_q` 处崩溃）；此后 `lock->owner = RT_MUTEX_HAS_WAITERS`、fake 成为唯一 top waiter 并**永久留在等待树里** | 没有任意写；但对一把真实全局锁造成**确定性永久破坏**：任何 `prio ≥ 120`（即普通 `nice≥0`）的新申请者在 `try_to_take_rt_mutex()` 的 `:913`（`task->prio >= top_waiter->prio`）失败后入树阻塞，而锁已无 owner 可解锁 ⇒ **该锁对普通任务永久不可用**（例：`/proc/uid_cputime/show_uid_stat` 读取永久 D 状态）；只有更高优先级（`prio<120`）任务才能夺取并再次唤醒 fake，普通等待者仍不会被唤醒 |
| **B：非零链接**（选定的 `parent`/`child`） | `__rb_change_child()` 向 `parent->rb_left/right` 写入 `child`（**任意写**）；若 `rebalance != NULL` 则 `____rb_erase_color()` 把 `parent` 当作红黑树节点继续读写（`sibling = parent->rb_right`、旋转、改色） | 期望的写只是这条路径的副作用；真实锁树与选定 `parent` 对象的红黑树不变式同时被破坏。要"安全地"完成 `:726` 的 `rb_insert_color()` 与后续 owner 树操作，必须同时把**真实 waiter 节点**与**选定 parent 对象**都建模成合法红黑树节点——前者地址不可知（③ 缺口），后者内容不可控 ⇒ 无法收敛为确定性原语 | 写原语**不可控**（写入值/地址/后续解引用耦合在一起），且必然伴随真实锁树损坏；panic 概率不可评估，属 step3 §六 明令禁止的"制造新内核竞态 / 强制异常" |

> **命题 P3**：B3 的第一笔"有意义的写"只能在"非空树 + fake 不在树中"的状态下发生；该状态下真实节点（真实 waiter / 选定 parent）不可能全部受控 ⇒ **B3 不满足 N1 的"可控"限定**。若强行把树清空到只剩 fake（形态 A 的后续状态），则必须先以一次 P1/P2 失败为代价，且 fake 的链接已被 `:280` 的 `RB_CLEAR_NODE` 与 `:726` 的 `rb_link_node` 重写，还需要"重写仍在树中的栈上 fake"这一新的 UAF 型原语才可能恢复可控——本机无此原语，且属于禁止的新竞态。

---

## 5. 分支完备性：没有"既安全又能出写"的第五种状态

| # | 触发瞬间的状态 | 走查落点 | 是否越过 `:702` | 结果 |
|---|---|---|---|---|
| E1 | 目标锁等待树为空（**四个实例的稳态**） | `:702` | 是 | **fault**（P1） |
| E2 | 非空（真实 waiter），fake 全零链接 | `:705/:726` | 是 | 无任意写；孤儿真实 waiter + 永久幽灵 waiter，目标锁对普通任务永久不可用（形态 A） |
| E3 | 非空（真实 waiter），fake 非零链接 | `:705` 起 | 是 | 不可控写 / 树损坏（形态 B） |
| E4 | `waiter->prio == W->prio` | `adjust_pi :1166`（链内 `:610` 同判） | **否** | 提前退出，无写原语 |
| E5 | `rt_mutex_owner(lock) == W`（W 自己持锁） | `:641` | **否** | `-EDEADLK` 返回，无写原语 |
| E6 | 树中只剩此前入树的 fake | `:702` | 是 | 非首次路径；`fake` 链接已被内核重写（见 P3 注），仍需新的栈重写原语 |

> 结论：**E4/E5 无写；E1 致命；E2/E3 越过 `:702` 后必然触碰非受控节点。** B3 无法在"不 panic、不制造竞态"的边界内提供 N1 所需的可控 rt_mutex 对象。

---

## 6. 四个实例的可达性与风险矩阵

（列 2 的"攻击者持锁路径"指能否**由用户态主动**让该锁处于"被持有 + 有阻塞等待者"；SELinux 门为静态推断，未上机验证。）

| 实例 | 使用者 / 入口 | 攻击者持锁路径 | 稳态树 | 若被 B3 瞄准 |
|---|---|---|---|---|
| `uid_lock`（`uid_sys_stats.c:36`） | `/proc/uid_cputime/show_uid_stat`（0444，`:672`）、`/proc/uid_io/stats`（0444，`:682`）、`/proc/uid_procstat/set`（0222，`:692`）、`/proc/uid_cputime/remove_uid_range`（0222，`:670`）；临界区遍历全部线程 + `seq_printf`（`:342-379`、`:532-553`），可达毫秒级（未实测） | **VFS 层可行**（权限允许时，两个线程并发读 0444 文件即可自造"持锁 + 阻塞"）；SELinux 是否放行未证 | 空 | E1 默认致命；自造 E2/E3 则破坏 batterystats/UID 统计锁，或不可控写 |
| `proc_uid_lock`（`fs/proc/uid.c:26`） | `/proc/uid/` 的 readdir（`:227-254`，0555）与 lookup（`:256-273`）；锁内在 `proc_fill_cache`（GFP_KERNEL，可睡眠）中 | **VFS 层可行**（两线程并发 getdents 自造）；SELinux/域门未证 | 空 | 同上；目录项分配路径持锁较久，自造窗口更大 |
| `msm_bus_dbg_cllist_lock`（`msm_bus_dbg.c:41`） | debugfs（`msm_bus_dbg.c:860-915`；`S_IRUGO`/`S_IWUSR`，root 属主）**+** `msm_bus_dbg_client_data()`（`:817-834`，`EXPORT_SYMBOL`，由 msm_bus 客户端注册/注销路径调用） | **不可直接构造**（shell 无 debugfs 权限；客户端注册由内核驱动触发，时序不可控） | 空/非空取决于驱动活动 | 无稳定状态可瞄准；E1 概率高，E2/E3 时序不可控 |
| `msm_bus_adhoc_lock`（`msm_bus_arb_adhoc.c:43`） | msm_bus 投票聚合（`msm_bus_arb_adhoc.c:859-1414` 多处），显示/摄像/总线客户端的内核路径 | **不可控**（真实并发持有者随时存在，无法精确制造/清空） | 空/非空随机 | E1 或 E2/E3 均不可控，且影响总线投票 |

> 注：四个实例在 `vmlinux.elf` 中的 0x20 字节**全零**（§1.3），即 `DEFINE_RT_MUTEX` 的未加锁初值；"稳态空树"不是猜测，是对象初值 + 短临界区结构共同决定的。

---

## 7. 与既有判定的关系（不改变四层）

1. **B3 的地址层结论维持**（G2 §2.3 / §70）：4 个实例真实存在、类型确定（符号级 `DEFINE_RT_MUTEX` + `.kernel2`/`.bss` + 二进制引用）、生命周期永活、地址可由 slide 复算（R2 限定当前 boot）。**"地址可得"与"对象可用"是两件事**，本审计只否证后者。
2. **G3 重开条件②"并发语义静态审计"至此执行完毕，结论为否**：B3 从"静态层已证实候选集（待审计）"变为"**静态层已证实、但可用性被否证的候选集**"。G3 §1 的重开条件不再满足，B3 维持冻结（不是"待办"）。
3. **N1 仍未满足**：B3 不构成 ② 的有效替代；③ 的 oracle 缺口（§68/§69 已裁决为"无可用 oracle"）不变。
4. **四层判定不变**：Wi-Fi 域内受限 UID 0 命令执行已达成；**可用 ROOT / 持久 ROOT 仍 NO-GO**。
5. 本审计**未上机、未申请授权、未做动态输入**；未评估/未构造任何 `rb_erase` 写原语的具体利用链（属完整提权 PoC 范畴，step3 §六 禁止）。

---

## 8. 明确"未做 / 未证"（防止过度外推）

| 项 | 状态 |
|---|---|
| 动态触发 `:702` 的 NULL 解引用 | **未做**（禁止；会 oops/panic） |
| `panic_on_oops` 运行时真值 | **未证**（shell 不可读；配置与 cmdline 均为 0/无，但 init 可改写） |
| `/proc/uid`、`/proc/uid_cputime` 对 shell 的 SELinux 可达性 | **未证**（本轮纯离线；不据此宣称"可自造争用"已成立，只登记为 VFS 层可行 + 域门待验） |
| E2/E3 的具体 `rb_erase` 写目标与后果 | **未构造**（需完整利用开发 + 独立授权；且形态 B 已静态证明不可控） |
| 修复/绕过方案（让 `:702` 跳过、或提供可控静态锁） | **未发现**；本机 4 个实例全部为共享真实锁 |

---

## 9. 结论与重开条件

**结论：B3 的并发语义静态审计完成，判定为否。** B3 满足"地址可得 + 对象结构合法 + 生命周期永活"，但**不满足 N1 的"可控"**，且其唯一能产生写的路径必然对真实内核锁造成确定性破坏或不可控写。**G3 冻结维持；阶段 3（G0–G4）至此全部完成；四层判定不变：可用 ROOT / 持久 ROOT 仍 NO-GO。**

**重开条件（需同时满足，缺一不可）**：

1. **R-i（对象条件）**：出现一个"**专供攻击者、无其它内核使用者、等待树生命周期受控**"的 rt_mutex 实例（静态或动态），使 `:702` 的 top waiter 与 `:705` 的树状态完全由攻击者决定；当前 4 个共享实例均不满足。
2. **R-ii（构造条件）**：在不制造新内核竞态、不强制异常的前提下，给出满足 N3 的 fake 链接构造，使 `:705/:726` 的 `rb_erase`/`rb_insert` 只触碰受控节点；若该构造需要 ③ 栈地址，则与 "B3 规避 ③" 的立项前提冲突（自相矛盾），须显式说明取舍。
3. **R-iii（授权条件）**：任何动态验证须在**独立、可接受重启/panic 的设备**上进行，并取得逐次明确授权；本机（不重启硬约束）不适用。

在上述条件满足之前：**B3 冻结、不投入；GhostLock ②/③ 冻结；不恢复 PoC；NO-GO。**

---

## 10. 引用

- 需求：`GHOSTLOCK_ADDRESS_REQUIREMENTS.md` §1（N1 "有效、可控、结构合法"）
- 基线规则：`GHOSTLOCK_ADDRESS_BASELINE.md` §3（R1–R6）
- 来源矩阵与枚举：`GHOSTLOCK_ADDRESS_SOURCE_MATRIX.md` §2.3
- 决策与重开条件：`GHOSTLOCK_PHASE3_DECISION.md` §1、§6
- 机制底层：`artifacts_adb/WAITER_ADDRESS_ANALYSIS.md` §2–§4；`artifacts_adb/binder_audit/GHOSTLOCK_NUL_ANALYSIS.md`
- 本审计源码：`src_ref/vendor_sdm710_r11/kernel/locking/rtmutex.c`（`:244-281`、`:489-837`、`:971-1091`、`:1157-1179`）、`rtmutex_common.h`（`:25-57`、`:77-82`）、`kernel/sched/core.c`（`:4609-4610`）、`lib/rbtree.c`（`:424-430`）、四个锁源文件（见 §1.1）
- 本审计二进制：`firmware_F16/vmlinux.elf`（§1.3 / §3.2 所列静态 VA）
- 复算工具：`tools/b3_audit.py`
