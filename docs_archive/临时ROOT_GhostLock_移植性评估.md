# OPPO K3（PCGM00 / C.17）获取「临时 ROOT」：GhostLock（CVE-2026-43499）可移植性评估

> **版本失效声明（2026-11-13，依据实机 ADB 复核）**
> 本文基于 **C.17** 基线（ColorOS 7.1 / Android 10 / 内核 4.9.186 / SPL 2021-05-05）编写。实机 ADB 已确认设备运行 **PCGM00_11_F.16**（ColorOS 11.1 / Android 11 / 内核 4.9.227-perf+ / SPL 2022-04-05，构建 2025-03-26，fingerprint 尾号 `1704167642389`）。
> 本文中的镜像哈希、boot/vbmeta 数值、内核符号与偏移、CVE 补丁窗口，以及任何针对 C.17 的操作指令，**对本机全部作废**，不得用于本机判断；与版本无关的采集命令、分析方法论仍可参考。
> 当前有效基线：`F16_基线_与C17结论失效说明.md`；当前固件镜像：`firmware_F16/`；获取与清理记录：`F16_固件获取与C17清理记录.md`。

- 评估日期：2026-11-13
- 目标：在**不解 BL** 的前提下，仅获取「临时 ROOT」（运行时 uid=0，重启即失）
- 对象：K3 `kernel.decompressed`（Linux **4.9.186**、ColorOS 7.1 / Android 10、SPL 2021-05-05）
- 方法：对已解包内核做静态分析 + 完整 kallsyms 符号表恢复 + capstone 反汇编；对照 GhostLock 公开资料与 4.9 源码
- 结论等级：**【实】** 本机一手实测；**【源】** 公开资料；**【推】** 推断

---

## 0. 一句话结论

**方向成立，但不是「下载即用」。** K3 的 4.9.186 内核**确实包含 GhostLock 的全部缺陷代码路径且必然未修补**（2021 构建 vs 2026 修复），且**不依赖** `CONFIG_USER_NS`（这正是 CVE-2021-22555 被本机 `USER_NS=n` 卡死、而 GhostLock 不被卡死的关键差异）。但公开 PoC 全部针对 **GKI 6.6/6.12**，要落到 K3 的 **4.9 非 GKI** 上，需要一次**独立的漏洞利用开发**（偏移/结构体/堆喷/KASLR 全部重做），工作量约等于中高级内核利用工程，而非脚本移植。

---

## 1. 本次实测新增证据（一手）

### 1.1 完整 kallsyms 符号表已恢复【实】

从 `unpacked_C17/kernel.decompressed` 的**压缩 kallsyms**中恢复出 **135791 个符号**，标识符形态占比 **100%**，样本真实（`_head`、`_text`、`stext`、`__do_softirq`…）。恢复要点（供复现）：

| 结构 | 实测值 |
|---|---|
| `kallsyms_offsets`（u32×135791，相对基址） | `@0x1380744`，仅 1 处非升序（percpu 回绕），`offset[0]=17792`，跨度≈0x23CB1D0 |
| `kallsyms_num_syms` | `0x2126F` = **135791**（`@0x1405100`） |
| `kallsyms_names` | `@0x1405200`（`num_syms` 后有 248 B 零填充） |
| `kallsyms_markers`（**u64**） | `@0x15ab700`，531 条 = ⌈135791/256⌉，末条 `0x1a5ecb` |
| `kallsyms_token_table` | `@0x15ac800`，256 token（`pro/co/or_/…/tracepoint_/register/alloc`），distinct=256 |
| `kallsyms_token_index` | `@0x15acc00`附近 |

> 复现工具：`tools/kallsyms_recover.py`（定位）、`tools/solve_names.py`（解码），输出 `tools/kallsyms_out.txt`。
> 说明：名称顺序与"函数是否存在"可靠；因整体在尾部 242 字节未完全吻合（约末 19 个符号漂移），**单函数 offset 与名称的逐条配对在个别相邻项存在少量对齐误差**，故本报告以"函数存在性 + 相对簇位置"为准，不据此给出可能失真的绝对地址。

### 1.2 GhostLock 相关函数「全部存在」【实】

在恢复的符号表中，GhostLock 涉及的 futex PI / rt_mutex 全链路函数**一个不缺**（相对偏移为 kallsyms 相对基址值）：

| 函数 | 相对偏移 | 作用 |
|---|---|---|
| `remove_waiter` | ~0x0aa3a4 | **修复 commit 直接修改的落点**（pre-fix：用 `current`） |
| `task_blocks_on_rt_mutex` | ~0x0aa398 | 入队/阻塞链 |
| `rt_mutex_adjust_prio_chain` | ~0x0aa310 | PI 优先级传播 |
| `try_to_take_rt_mutex` | ~0x0aa150 | 抢占 |
| `rt_mutex_start_proxy_lock` | ~0x0aba20 | **PI 代理锁启动（被 GhostLock 利用的关键）** |
| `rt_mutex_proxy_unlock` | ~0x0ab93c | 代理解锁 |
| `rt_mutex_wait_proxy_lock` / `cleanup_proxy_lock` | ~0x0abd74 / ~0x0abd88 | 代理等待/清理 |
| `rt_mutex_timed_futex_lock` | ~0x0aae10 | futex→rtmutex 定时锁 |
| `futex_lock_pi` / `futex_unlock_pi` | ~0x0e2294 / ~0x0e20f8 | PI 加/解锁 |
| `futex_requeue` | ~0x0e2158 | **requeue（GhostLock 竞态的另一端）** |
| `futex_lock_pi_atomic` | ~0x0e2128 | 原子抢锁 |
| `attach_to_pi_state` | ~0x0e16c4 | pi_state 绑定 |
| `fixup_pi_state_owner.isra.17` | ~0x0e1b90 | owner 修复 |
| `futex_wait_requeue_pi.constprop.22` | ~0x0e2124 | PI requeue 等待 |
| `handle_futex_death` / `do_futex` / `SyS_futex` | ~0x0e29d4 / ~0x0e2bd0 / ~0x0e2c54 | 入口/退出 |

**簇分布**：`rt_mutex` 簇 ≈ 相对 0x0a9900–0x0ac300；`futex` 簇 ≈ 0x0e1300–0x0e2f00；二者相距 ≈0x36000，与"rtmutex.c 与 futex.c 相邻链接"一致。**这证明 GhostLock 的两个竞态面（futex requeue ↔ rt_mutex 代理锁）在 K3 上一个不少。**

### 1.3 内核配置【实】

`CONFIG_FUTEX=y`、`CONFIG_RT_MUTEXES=y`、`CONFIG_KALLSYMS_ALL=y`、`CONFIG_KALLSYMS_BASE_RELATIVE=y`、`CONFIG_SLUB=y`、`CONFIG_RANDOMIZE_BASE=y`（KASLR 开）、`CONFIG_ARM64_PAN=y`、`CONFIG_ARM64_UAO=y`、`# CONFIG_USER_NS is not set`、`# CONFIG_DEBUG_RT_MUTEXES is not set`。

---

## 2. GhostLock 机理与 4.9 的对应

- **缺陷本质**：Linux `rtmutex` 中 `remove_waiter()` 在回滚等待者时用 `current`（当前任务）而非 `waiter->task` 定位/清理，在 `futex_requeue()`/`futex_lock_pi()` 与代理锁路径竞争时，可导致对 `rt_mutex_waiter`（及关联 `futex_q`/`rt_mutex`）的 **use-after-free**，进而实现内核任意读写 → 提权到 uid=0。
- **修复**：commit `3bfdc63936dd`（"rtmutex: Use waiter::task instead of current in remove_waiter()"），2026 年进入主线 7.1 并向下 backport。
- **对 K3**：4.9.186 构建于 **2021-05**，比修复早约 5 年，**物理上不可能包含修复**；`remove_waiter` 以独立符号存在、未被内联，缺陷代码路径完整。故 **pre-fix 状态已由时间线 + 配置 + 符号存在性三重确认**。【实/推】

> 为何 GhostLock 比 CVE-2021-22555 更适合 K3：后者依赖非特权 user namespace 取得 netfilter 初始上下文，本机 `USER_NS=n` 直接阻断；GhostLock 是 futex 本地竞态，不依赖 userns，故在 K3 上"理论可触发面"是真实存在的。

---

## 3. 结构体与关键字段（4.9 源码，供利用开发）

> 以下为 Linux 4.9 布局；**精确字节偏移必须从本机镜像再提取**（版本演进会变），此处给出字段关系与利用关注点。

**`struct rt_mutex_waiter`**（`kernel/locking/rtmutex_common.h`）
```
struct rb_node        tree_entry;   // 红黑树节点（被 UAF 的对象之一）
struct list_head      list_entry;   // 链表
struct task_struct   *task;         // ← 修复后 remove_waiter 改用该字段
struct rt_mutex       *lock;
int                   prio;
```
利用关注：`task`/`lock` 指针是 UAF 后伪造/泄露的目标；`tree_entry` 决定红黑树重平衡时的可控写。

**`struct futex_q`**（`kernel/futex.c`）：`plist_node list` → `task_struct *task` → `spinlock_t *lock_ptr` → `futex_key key` → `futex_pi_state *pi_state` → `rt_mutex_waiter *rt_waiter` → `futex_key *requeue_pi_key` → `u32 bitset`。`rt_waiter`/`pi_state` 指针是竞态双端（requeue vs proxy lock）共享对象。

**`struct rt_mutex`**：`raw_spinlock_t wait_lock`、`rb_root waiters`、`rb_node *waiters_leftmost`、`task_struct *owner`。`owner` 的伪造是提权核心。

**`struct futex_pi_state`**：`list_head list`、`rt_mutex pi_mutex`、`task_struct *owner`、`atomic_t refcount`、`futex_key key`。`owner` 与 `refcount` 是 UAF 后稳定化利用的关键。

---

## 4. 与公开 PoC（GKI 6.6/6.12）的差距矩阵

| 维度 | 公开 GhostLock PoC（GKI 6.6/6.12，SM8750/8845/8850） | K3 4.9.186（非 GKI） | 移植影响 |
|---|---|---|---|
| 内核基线 | GKI 6.x，`rt_mutex` 已refactor | 4.9 老 `rtmutex`，`rt_mutex_waiter`/`futex_q` 布局不同 | **必须重提结构体偏移** |
| `remove_waiter` 形态 | 内联/不同编译 | 独立符号、O2 优化 | 触发点定位需重做 |
| 堆对象 | GKI slab 配置 | SLUB，`SLAB_FREELIST_RANDOM` 未开（利于喷堆，但对象尺寸不同） | 喷堆策略重写 |
| KASLR | 有 | `RANDOMIZE_BASE=y`，有 | 需信息泄露或侧信道 |
| 指针认证 | PAC/BTI（新机） | 4.9 无 PAC（**相对利好**） | 少了 PAC 绕过 |
| 用户态入口 | 依赖 userns? | 不依赖（GhostLock 特性） | 可利用 |
| 现成二进制 | 有（但目标机型固定） | **无**（GitHub 上无 K3/OPPO 4.9 版本） | **需自行开发** |

**净结论**：K3 少了 PAC 这一层（利好），但内核基线老旧、结构体/偏移/喷堆全不同，**没有任何可直接运行的现成利用**。

---

## 5. 移植工作量分解（若坚持走此路）

1. **结构体偏移提取**（1–2 人日）：从本机镜像/反汇编确定 `rt_mutex_waiter`、`futex_q`、`rt_mutex`、`futex_pi_state` 的字段偏移（`task`/`lock`/`owner`/`refcount` 等）。
2. **触发原语复现**（3–6 人日）：在 4.9 上复现 `futex_requeue` ↔ `rt_mutex_start_proxy_lock` 的竞态窗口，稳定触发 `remove_waiter` 的 UAF（先 `panic`/`KASAN` 不存在，靠启发式判稳）。
3. **UAF → 读写原语**（4–8 人日）：对象重用（SLUB 同尺寸喷堆）、伪造 `owner`/`task` 指针、稳定读/写。
4. **提权落地**（2–4 人日）：篡改 `cred` 或 `task->cred`，或改写 `selinux_enforcing`/`init_cred`；适配 KASLR（泄露或 brute）。
5. **稳定性与清理**（3–5 人日）：避免 panic、恢复现场（临时 root 不需要持久，但要不崩）。
   **合计 ≈ 15–25 人日**（有内核利用经验者的乐观估计），**且成功率不保证**——竞态类 UAF 在老旧非 GKI 内核上极不稳定。

---

## 6. 风险与边界（务必先认清）

- **能力边界**：临时 root 仅存在于当前启动会话，**重启即失**；**不能改 system 分区**（AVB/dm-verity 每次启动重新校验，本机已确认 AVB 启用、vbmeta 已签名）；**不能刷机/装持久 Magisk**。
- **适用场景**：运行时取证、内存 inspection、调试。**若你要的是"持久用 root 应用 / 改系统"，临时 root 给不了，仍需解锁 BL（K3 已证不可行）**。
- **KASLR**：`RANDOMIZE_BASE=y`，且**提权前无法读 `/proc/kallsyms`**（无 root），故静态偏移只用于"理解布局"，真正利用需运行时泄露或暴力。
- **PAN/UAO**：`CONFIG_ARM64_PAN=y`，内核态访问用户内存受限，影响某些 payload 手法（如直接读写用户缓冲）。
- **稳定性风险**：竞态 UAF 在 4.9 上易触发 panic/死机，且无 KASAN 辅助定位。

---

## 7. 结论与建议

1. **技术判定**：K3 的 4.9.186 **确实暴露**于 GhostLock 的缺陷代码（全链路函数齐全、必然 pre-fix、不依赖 `USER_NS`）。"临时 ROOT"在**理论机制上成立**。
2. **工程判定**：**无现成 PoC**，需 15–25 人日的专项利用开发，成功率不保证；这已超出"操作手册"范畴，属于"内核漏洞挖掘/利用研究"。
3. **建议优先级**：
   - 若目标只是**运行时检视**：可立项做上述第 1–2 步（结构体偏移 + 触发），先验证"能否稳定触发 UAF"，这是唯一的一票否决点；不触发则整条路线不成立。
   - 若目标本质是**持久 ROOT 使用**：应回到"深度测试解锁 BL"这一官方出口（严格优于临时 root），而非投入漏洞开发。
4. **不建议**：把公开 GhostLock 二进制直接套 K3（GKI 6.x）；或指望一键 root / CVE-2021-22555 变体。

---

## 附录 A：本次交付物

- `tools/kallsyms_recover.py`：压缩 kallsyms 定位器（offsets/num_syms/token 表，带自校验）
- `tools/solve_names.py`：names 解码器
- `tools/kallsyms_out.txt`：**135791 条符号**（相对偏移 + 名称），可 `grep` 任意函数
- 本报告

## 附录 B：可复现检索

```
grep -nE "remove_waiter|task_blocks_on_rt_mutex|rt_mutex_start_proxy_lock|rt_mutex_proxy_unlock|futex_lock_pi|futex_unlock_pi|futex_requeue|attach_to_pi_state" tools/kallsyms_out.txt
```

## 附录 C：一句话给决策者

> 想"零成本拿临时 root"——不存在。K3 上唯一现实的临时 root 是"自己写一个 4.9 的 futex UAF 利用"，成本 ≈ 3–5 周专项开发且可能失败；相比之下，先花 1 小时实测"深度测试是否受理 K3"的期望收益高得多。
