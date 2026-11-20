# WARN_ADDRESS_SURFACE_AUDIT.md —— 阶段 2：运行期 WARNING 观察面静态审计（2026-11-20）

> v13 阶段 2 交付物（审核 v013 §四.2 / P1.1–P1.5）。**纯静态审计 + 既有日志离线统计；零上机、零设备授权申请、不制造任何内核异常；不改变四层判定。**
> 原始目录工件：`.build/bugreport_20261120/vmlinux_bug_catalog.json`、`wlan_bug_catalog.json`（不入库）；可复跑工具：`tools/bugtable_scan.py`。

## 0. 一句话

**WARN() 寄存器 dump 是本机已实证的、非致命的、上下文本地的 sp 观测通道（dumpstate 双 boot 已证系统继续运行）——这是 ③ 类地址迄今唯一的潜在 oracle 形态；但审计结论：稳态运行期自然 WARN 为 0，全部自然 WARN 发生在内核线程上下文（swapper/kworker），已审可达入口函数（`hdd_driver_command`、KGSL 非 sparse ioctl 链）内均为 0 个 WARN 点，futex PI 路径 68 个 WARN 点的逐点触发条件裁决因物料缺口（厂商源码行号漂移）未完成。无"安全、明确"的候选，不申请任何额外授权。**

---

## 1. 方法与物证（P1.1）

### 1.1 目录重建方法

`CONFIG_DEBUG_BUGVERBOSE=y`（`artifacts_adb/k3_kernel_config.txt`）⇒ bug 表条目为 12 字节
`{bug_addr_disp, file_disp, line, flags}`；arm64 WARN/BUG 编译为 `brk #0x800`（指令字 `0xD4210000`）；
`flags` 语义经实测校准：bit0 = WARN，0 = BUG，高 8 位 = taint 索引（`0x901` = WARN + TAINT_WARN，与本机 WARN 后 `Tainted: G W` 实测一致）。

| 物料 | 方法 | 校验 |
|---|---|---|
| `vmlinux.elf` | 启发式扫描（段已合并为 `.kernel/.kernel2`，无独立 `__bug_table`）：12 字节滑动窗 + brk 指令字校验 + 文件字符串可打印性校验 | 每条 insn_va 处指令字 == `0xD4210000` |
| `qca_cld3_wlan.ko` | 精确解析 `__bug_table`（612 条）+ `.rela__bug_table`（R_AARCH64_PREL32，insn 偏移与文件字符串偏移均可解析） | **612/612 全部通过 brk 校验** |

### 1.2 目录总量

| 物料 | 条目 | WARN（bit0） | BUG（flags==0） |
|---|---|---|---|
| `vmlinux.elf` | **11,283** | **6,846** | 4,437 |
| `qca_cld3_wlan.ko` | **612** | **497** | 115 |

vmlinux WARN 按目录分布（前几项）：`drivers/gpu/msm`（KGSL）994、`include/linux` 头内联 834、btrfs 333、net 241、`gpu/drm` 219、wireless 210、clk 186、ipa 172、qcom soc 147、**futex 68**。

---

## 2. 关键机制发现：WARN dump 是"上下文本地 sp"的非致命观测通道

### 2.1 通道语义（真机已实证）

WARN 触发时打印 `pc/lr/sp/x0–x29` **并返回继续执行**（`CONFIG_PANIC_ON_OOPS` 未编译置位；WARN 非 oops，不走 die/panic 路径）。真机实证：

| boot | WARN 事件 | 系统状态 |
|---|---|---|
| 重启前 boot（76 h） | 3 次（t=0.278/0.966/0.967 s） | 继续运行 76 h |
| 重启后 boot（`b9f9f06a-…`） | 1 次（t=0.278 s） | uptime 连续，bugreport 正常 |

⇒ **对 v11 ③ 结论的正式修订**：§53/§60 的"唯一含 sp 的输出是 oops 寄存器 dump（触发即重启）"在**已审接口范围**内成立；WARN 寄存器 dump 是该范围外的**第二条 sp 通道，且非致命**。它给出的 `sp` 属**触发 WARN 的执行上下文**（R4 规则：谁的上下文就是谁的栈）。

### 2.2 对 ③ 的含义（本审计的核心登记）

若某个 WARN 点能被 **GhostLock 的 W 线程**（持 stale waiter 的攻击者线程）在 stale 窗口内经**合法参数**自然触发，则该 WARN 的寄存器 dump 即给出 W 线程内核栈 sp ⇒ `栈基址 = sp & ~(THREAD_SIZE-1)`（16 KB 对齐，`!VMAP_STACK` 实测）⇒ **③ 满足**。几何换算（栈基址 → waiter 自引用值）早已静态解决，缺的正是这一步 oracle。

**但这是假设形态，不是结论**——成立前提是存在"合法可触发、无 BUG 升级、不破坏状态"的 WARN 点，本轮未能确认任何一点（§4）。

---

## 3. 自然发生率（P1.4，经验数据）

| 数据源 | 窗口 | 内核 WARN 事件 | 上下文 |
|---|---|---|---|
| 76 h boot 的 dumpstate KERNEL LOG 段（8,997 行） | 稳态最近 ~26 分钟 | **0**（仅 2 条用户态日志字符串含 "WARNING" 字样，非内核事件） | — |
| 全量 boot console（last_kmsg，353 KB 全程） | t=0 → 关机 | **3**：sysfs(t=0.278, swapper/0)、proc_register(t=0.966, kworker/u16:1)、proc_register(t=0.967, kworker/u16:1) | **全部内核线程**，无任何用户态 comm |

**判定**：自然 WARN (a) 只在 boot 早期内核线程上下文出现，(b) 稳态运行期频率为 0，(c) 从未在用户态线程上下文出现 ⇒ **自然发生不足以提供 ③**；对 ①A 仅在"重启后尽早 dumpstate"窗口内有效（`KASLR_EVIDENCE.md` §5 的时序边界不变）。

---

## 4. 可达面候选筛选（P1.2 / P1.3）

### 4.1 已审可达入口的直接筛选

| 可达面 | 入口函数 | 该函数内 WARN/BUG 点 | 判定 |
|---|---|---|---|
| WLAN UID0 域首选候选 | `hdd_driver_command`（`0x89f1`） | **0 / 0** | 从首选入口无法触发 WARN |
| WLAN 次选 | FTM testmode（`0x89fd`）函数族 | 未逐点裁决（入口函数本身 0） | 同上倾向 |
| KGSL 非 sparse ioctl（shell 可达） | `kgsl_ioctl_gpuobj_alloc/free`、`gpumem_free_id`、`drawctxt_create`、`gpu_command` 等已审处理函数 | **0 / 0** | 已审可达链上无 WARN 点 |
| KGSL 全模块 | `a5xx_start`(111)、`a4xx_enable_hwcg`(77)、perfcounter、snapshot 等初始化/调试路径 | 994 WARN / 23 BUG | **不可合法触发**：设备初始化与调试快照路径，非 ioctl 按需路径；触发形态不满足"合法、必现、无副作用" |

### 4.2 futex PI 路径（唯一与 W 线程上下文相关的候选集）

68 个 WARN 点全部位于 GhostLock 链路核心函数：`futex_lock_pi`(7)、`futex_requeue`(20)、`futex_wait`(7)、`futex_wake`(4)、`attach_to_pi_owner`(2)、`fixup_pi_state_owner`(2)、`exit_pi_state_list`(2)、`futex_wait_setup`(2)、`futex_lock_pi_atomic`(1)、`do_futex`(20)。
守卫模式粗分类：**WARN_ON_ONCE 型 7 条 / 直接断言型 61 条**；另有 3 条 **flags==0 的 BUG 点**（`futex.c:2198/2178` 两处 fault_in_user_writeable 路径 + 1 处）已**排除出候选**（BUG 升级 = panic 面，P1.3）。

**未完成裁决的原因（已于同日续审完成，见 §8）**：厂商构建的 `futex.c` 行号与本仓库 mainline 副本**存在漂移**——按 R6 证据等级，逐点判定需要厂商匹配源码。本节保留原始状态记录；裁决结果见 §8。

### 4.3 BUG 升级排除（P1.3）

- 全部 4,437（vmlinux）+ 115（ko）个 BUG 点不进入候选（BUG = die/panic 面）。
- KGSL CVE-2023-33107 类"命中即 BUG()"路径维持排除（既有判定）。
- futex 路径 3 个 BUG 点（`futex.c:2178/2198` 等）同规则排除。

---

## 5. 结论（P1.5）

1. **无"安全、明确"的 WARN 候选**：可达入口函数内 0 个 WARN 点；自然 WARN 全部在内核线程上下文；futex 候选集（68 点）因物料缺口未完成逐点裁决。⇒ **不申请任何额外授权、不做任何动态触发**。
2. **通道价值正式登记**：WARN dump = 非致命、上下文本地的 sp/pc/lr/寄存器族观测通道——它是 ③ 迄今唯一的潜在 oracle 形态；其成立需逐点裁决 futex 候选集（或发现其他用户态可合法触达的 WARN 点）。
3. **③ 判定更新（精确化，非解除）**：v11"无可用 oracle"的结论维持，但**oracle 的可能形态**从"无"更新为"WARN 上下文本地 dump（候选 68 点待裁决）"。按 G0 R6 规则，此为"未证实候选"，不得写成"已解决"。
4. **①A 判定不变**：dumpstate 路径已实证（`KASLR_EVIDENCE.md`），自然发生面仅提供 boot 早期窗口。
5. **四层判定不变：可用 root / 持久 ROOT 仍 NO-GO。**

## 6. 重开 / 推进条件

| 项 | 条件 |
|---|---|
| futex 候选集逐点裁决 | 获得厂商匹配的 `futex.c` 源码（或从 OTA full bootimg 重建带调试信息的符号映射）→ 纯静态裁决"合法参数可触发 + 无 BUG 升级 + 无状态破坏"三点判据 |
| 任何动态验证 | 须先产出候选清单并获用户**单独授权**；遵守"不制造内核异常"边界——仅在"参数合法、路径本来就会自然走到"的形态下考虑 |
| ③ 填充判据 | WARN dump 的 sp 必须属于 W 线程上下文（R4），且采集时 stale waiter 存续（R5） |

## 7. 引用

- 通道实证：`live_probe/DUMPSTATE_KASLR_PATH.md` §2/§8、`KASLR_EVIDENCE.md` §1/§4
- ③ 几何与 v11 接口审计：`artifacts_adb/WAITER_ADDRESS_ANALYSIS.md` §5.5、`HANDOVER.md` §53/§55/§60
- 需求框架与规则：`GHOSTLOCK_ADDRESS_REQUIREMENTS.md`（N1/N3）、`GHOSTLOCK_ADDRESS_BASELINE.md` §2–§3
- 工具：`tools/bugtable_scan.py`（`python tools/bugtable_scan.py all` 离线复跑）

---

## 8. 候选集裁决完成（同日续，2026-11-20）——**68 点全部排除，③ 的 WARN-oracle 假设被源码层否决**

### 8.1 厂商匹配源码的取得与可信度校准

| 项 | 值 |
|---|---|
| 来源 | `https://github.com/oppo-source/android_kernel_oppo_sdm710`（OPPO 官方 GPL 开源组织） |
| 分支 | `oppo/sdm710_r_11.0_reno`（SDM710 Android 11，PCAM00_11_F.56 同步） |
| 拉取文件 | `kernel/futex.c`（3,487 行，SHA-256 `2b3c2678519641468eb09e051f7331abfb2d216570654b2398af5df8d29952f6`）、`fs/sysfs/dir.c`、`fs/proc/generic.c`，存于 `src_ref/vendor_sdm710_r11/`（GPLv2 原许可） |
| 设备差异边界 | 该树为 **PCAM00（Reno）F.56**，本机为 **PCGM00（K3）F.16**——同 SoC、同 Android 11 分支，但非同一机型固件 |
| **行号校准（通过）** | 两个真机实测锚点逐字命中：`fs/sysfs/dir.c:31` = `WARN(1, "sysfs: cannot create duplicate filename '%s/%s'…")` ✓；`fs/proc/generic.c:345` = `WARN(1, "proc_dir_entry '%s/%s' already registered"…)` ✓（与本机 dmesg 消息逐字一致） |
| futex 对齐度 | bug 表中 **20 个去重行号全部精确落在 WARN/BUG 语句上**（含 `470: WARN_ON_ONCE(1)`、`1283/1284` 对、`1302` 两参 WARN）——若树错位，此对齐概率为天文数字级不可能 |
| 残余风险 | F.56 与 F.16 的 futex.c 若存在厂商补丁差异则行号仍可能偏移；以 2/2 锚点 + 20/20 行命中作为"高度可信、非绝对"的证据等级（R6：源码证明 + 真机锚点交叉验证） |

### 8.2 逐点裁决表（68 个编译点 → 20 个去重源码行）

| 行号 | 语句（厂商 futex.c） | 所属函数 | 裁决 |
|---|---|---|---|
| 1302 | `WARN(q->pi_state \|\| q->rt_waiter, "refusing to wake PI futex\n")` | `mark_wake_futex`（内联进 futex_wake/futex_wake_op/futex_requeue） | **被否决（见 8.3）——唯一涉及用户路径的点** |
| 470 | `WARN_ON_ONCE(1)` | `drop_futex_key_refs`（"put 未 get 的 key"，内联多调用者） | 排除：内核自身 bug 态才可达 |
| 833 / 1018 / 1134 | `WARN_ON(!pi_state)` / `!refcount` / `!list_empty` | `attach_to_pi_state` / `attach_to_pi_owner` | 排除：内部不变量 |
| 937 / 938 | `WARN_ON(pi_state->owner != curr)` / `list_empty(&pi_state->list)` | `exit_pi_state_list` | 排除：内部不变量 |
| 1283 / 1284 | `WARN_ON_SMP(!q->lock_ptr \|\| !spin_is_locked(…))` / `WARN_ON(plist_node_empty(&q->list))` | `__unqueue_futex`（内联多调用者） | 排除：持锁不变量 |
| 1382 / 1387 | `list_empty` 对 | `wake_futex_pi`（FUTEX_UNLOCK_PI 路径） | 排除：内部不变量 |
| 1688 | `WARN_ON(!q->rt_waiter)` | `requeue_pi_wake_futex` | 排除：内部不变量 |
| 1896 | `WARN_ON(pi_state)` | `futex_requeue` | 排除：内部不变量 |
| 2178 / 2198 | `BUG_ON(q->pi_state)` / `BUG_ON(!q->pi_state)` | `unqueue_me`（内联） | 排除：BUG 面（P1.3） |
| 2261 / 2269 | `list_empty` 对 | `fixup_pi_state_owner` | 排除：内部不变量 |
| 2709 | `WARN_ON(!q.pi_state)` | `futex_lock_pi` | 排除：内部不变量 |
| 2898 | `WARN_ON(q->lock_ptr && (&hb->lock != q->lock_ptr))` | `handle_early_requeue_pi_wakeup` | 排除：内部不变量 |
| 3062 | `WARN_ON(!q.pi_state)` | `futex_wait_requeue_pi` | 排除：内部不变量 |

### 8.3 唯一用户路径候选（1302）的否决证据

**触发形态**（假设路径）：对存在 PI 阻塞 waiter（`q->rt_waiter != NULL`）的 uaddr 执行 `FUTEX_WAKE`——参数完全合法。

**否决证据**：`mark_wake_futex` 的全部 4 个调用点在调用**之前**都有等价的 `-EINVAL` 前置检查，PI waiter 根本到不了 1302 行：

| 调用点（厂商源码行） | 前置检查 | 行为 |
|---|---|---|
| `futex_wake` @1480 | `1463-1466`：`if (this->pi_state \|\| this->rt_waiter) { ret = -EINVAL; break; }` | 先返回后跳过 |
| `futex_wake_op` @1605 / @1619 | `1601-1604` / `1615-1618`：同型检查 → `-EINVAL; goto out_unlock;` | 同上 |
| `futex_requeue` @1974 | `1962-1965`：`(!requeue_pi && this->rt_waiter) \|\| this->pi_state` → `-EINVAL; break;` | 同上 |

二进制侧交叉印证（证据等级：精确固件反汇编）：WARN 点 `0xffffff800815e038`（静态 VA，内联于 `futex_wake`）前为 `adrp/add x0 = 0xffffff800962460d`（rodata 中 `"refusing to wake PI futex"`）+ `bl printk` + `brk`——确认该 brk 即此语句；紧随其后的 `mov w21, #-0x16`（**-EINVAL**）出口与源码前置检查一致。**1302 是前置检查之后的死防御代码，任何用户态路径不可达。**

### 8.4 裁决后的最终判定

1. **futex 68 点候选集全部排除**——不存在"合法参数可触发、无 BUG 升级、无状态破坏"的 WARN 点。③ 的 WARN-oracle 假设**在源码层被否决**（证据等级：厂商源码 + 双锚点校准 + 反汇编交叉印证）。
2. WARN dump 通道本身（非致命、上下文本地 sp）仍为已实证机制，但**在本内核的 futex 路径上没有可达触发点**；其余子系统的 WARN 点维持 §4 的排除（可达入口函数 0 点 / 初始化路径不可按需触发）。
3. **③ 回到"无可用 oracle"，且从"待裁决"升级为"已完整裁决为否"**。③ 冻结条件不变：除非出现本审计范围外的新观测原语。
4. **不需要任何上机动作、不申请任何授权**（P1.5 终态）。
5. 四层判定不变：**可用 root / 持久 ROOT 仍 NO-GO**。

---

## §9 厂商 rtmutex 机制核验与 waiter 布局修正（2026-11-20，补做：厂商源码到手后）

> 承接 §8 裁决。获取厂商 rtmutex 全套源码（`src_ref/vendor_sdm710_r11/kernel/locking/{rtmutex.c,rtmutex_common.h}`、`include/linux/rtmutex.h`、`include/linux/sched/deadline.h`）后，对 §3/§8 依赖的机制事实做全面核验，并**修正一处既有记录错误**。

### 9.1 修正：`rt_mutex_waiter` 布局（HANDOVER §8.1 的"无 deadline 字段"记录错误）

- 厂商 `rtmutex_common.h`（非 debug，`CONFIG_DEBUG_RT_MUTEXES` 未启用）：waiter 布局为 `tree_entry@0x00 / pi_tree_entry@0x18 / task@0x30 / lock@0x38 / prio@0x40 / **deadline@0x48**`，**结构体大小 0x50**（android-4.9-q 血统，等价 4.14 前向移植）。
- **二进制交叉印证**：`rt_mutex_adjust_prio_chain`（0xffffff8008125658–0x5eb0）内出现 `ldr xN, [x waiter, #0x48]` 加载模式——本机内核确实按 0x50 布局读取 deadline 字段。
- **影响**：此前 NUL 字节图分析假设 72 字节（0x48）waiter 是**错误几何**；正确 waiter 为 0x50，deadline 字段落在 payload 范围内（对伪造 waiter 属有利位置）。
- **无害性确认**：厂商 `include/linux/sched/deadline.h:10` `#define MAX_DL_PRIO 0`，`dl_prio(prio)` 仅 `prio < 0` 为真 ⇒ 对一切合法用户优先级恒为假，`deadline` **永不被解引用**（sha256 `bde95a62…05cde8`，与本地副本一致）。伪造 waiter 携带任意 prio（≥0）不会触发 deadline 路径。
- 相关机制行号在厂商源码中全部核验通过：`rtmutex.c:273` RB_EMPTY_NODE 提前返回、`:626` raw_spin_trylock、`:641/665/671` rt_mutex_owner 解引用链、`:745` 附近 top_waiter `BUG_ON(w->lock != lock)`；`futex_pi_state` 内嵌 `pi_mutex` 确认；厂商 `struct rt_mutex` 非 debug 尺寸 0x20 确认。厂商 rtmutex.c 与主线 4.9 差异 99 行，核心差异为 deadline 比较改用内嵌字段（`dl_time_before(left->deadline, right->deadline)`）+ `waiter->deadline = task->dl.deadline` 写入。

### 9.2 对 §8 裁决的影响：**无**

waiter 布局修正不影响 §8 的 68 点排除结论（该结论基于 WARN 语句可达性/前置 -EINVAL 检查，与 waiter 尺寸无关）。WARN-oracle 否决维持。
