# src_ref/kernel_49_mainline — 主线 v4.9 权威源码（第十轮新增）

用途：本机内核为 `4.9.227-perf+`（vendor fork）。本目录存放 **torvalds/linux tag `v4.9`** 的
原始文件，作为 rtmutex / futex 相关**行号与结构体尺寸**的唯一引用依据。

| 文件 | 上游路径 | md5 |
|---|---|---|
| `rtmutex.c` | `kernel/locking/rtmutex.c` | `2f6216cd0360d32bfab123249337e329` |
| `locking_rtmutex.h` | `kernel/locking/rtmutex.h`（调试桩，**非**结构定义） | `cf6355dfea20366302dacb6d5ce5e4f3` |
| `rtmutex_common.h` | `kernel/locking/rtmutex_common.h`（`struct rt_mutex_waiter`） | `5ab843c0f1df7fcd0a6d97d76e84ca77` |
| `include_linux_rtmutex.h` | `include/linux/rtmutex.h`（`struct rt_mutex`） | `879b223cf72ce30cd6367e6a01ef0097` |
| `futex.c` | `kernel/futex.c` | `7ee118a447468027f8105da21d9ffb5c` |

## 与 `src_ref/futex_4.9/` 的关系（重要）

`src_ref/futex_4.9/` 一套文件**不是 4.9**，而是 ~v4.20/v5.0 的形态：

- `rtmutex_common.h` 的 `rt_mutex_waiter` 末尾有 `u64 deadline`（v4.20 的 DL 感知 PI）
- `rtmutex.c` 的 `rt_mutex_futex_unlock(lock, wake_q_head *)`（v4.14+）

由此它的 `rt_mutex_waiter` 是 **80 B**，本机 4.9.227 是 **72 B**。
`struct rt_mutex`（32 B）与 `futex_pi_state`（88 B）在两套源码中**一致**，不受影响。

## 两个易错点（已踩过，勿重犯）

1. **`waiters_leftmost` 不是版本判据**：4.9 的 `struct rt_mutex` 就带这个**手工维护**的字段
   （`rtmutex.c` 的 `rt_mutex_enqueue`/`rt_mutex_dequeue` 手动更新），与 v4.14+ 的
   `rb_root_cached` 无关。因此「`rb_first_cached` 符号不存在」不能推出 `rt_mutex` 尺寸。
   4.9 与 4.20 的 `struct rt_mutex` **都是 32 B**。
2. **`kernel/locking/rtmutex.h` 不是结构定义**：4.9 里它只是调试宏桩；`struct rt_mutex`
   在 `include/linux/rtmutex.h`。取错文件会得出"没有 `waiters_leftmost`"的错误结论。

关键尺寸（arm64 LP64，`DEBUG_RT_MUTEXES=n`）：

| 结构 | 尺寸 | 关键字段 |
|---|---|---|
| `rt_mutex` | 32 (0x20) | `wait_lock=0x00`、`waiters=0x08`、`waiters_leftmost=0x10`、`owner=0x18` |
| `rt_mutex_waiter` | 72 (0x48) | `tree_entry=0x00`、`pi_tree_entry=0x18`、`task=0x30`、`lock=0x38`、`prio=0x40` |
| `futex_pi_state` | 88 (0x58) | `pi_mutex=0x10` |

## 引用约定

- 一切 `rtmutex.c:NNNN` / `futex.c:NNNN` 行号**必须**取自本目录文件。
- 4.9 关键行：`remove_waiter`@1076（`current->pi_blocked_on = NULL`@1085，
  `adjust_prio_chain(..., MIN_CHAINWALK, ..., current)`@1121）、
  `task_blocks_on_rt_mutex`（`owner == task` 早退@970、`waiter->lock = lock`@976、
  释放 `wait_lock` 后才走链@1022-1024）、
  `rt_mutex_adjust_prio_chain`@549/560/567/579/588/611/621/627/642、
  `handle_early_requeue_pi_wakeup`@futex.c:2738、`futex_wait_requeue_pi`@futex.c:2810。
