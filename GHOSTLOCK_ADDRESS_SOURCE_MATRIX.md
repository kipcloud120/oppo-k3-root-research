# GHOSTLOCK_ADDRESS_SOURCE_MATRIX.md —— 阶段 3 / G2：替代地址来源评估矩阵（2026-11-20）

> v13 阶段 3 第三步（响应审核 step3 意见 G2 与 §三）。**纯离线评估；除两轮本地符号表/源码枚举外无新增计算，未上机、未产出 PoC、不改变四层判定。**
> 任务：对"方向 A（W 线程栈地址）"与"方向 B（现有合法内核锁对象）"分别评估**现有证据、技术前提、可观测性**，不预先决定路线（step3 意见 §三原文）。

## 0. 一句话

**两条路线各有一个候选来源，且都卡在同一个缺口上——"定位该对象/该线程的 oracle"不存在：A 路线的 W 线程栈无任何观测原语（futex key 不含栈地址 + VMAP_STACK 关闭 + dumpstate 的 sp 属 init/swapper）；B 路线的 pi_state / skb 喷页均无地址锚点（M2 已否证）。唯一由 v13 slide 直接受益的是 B 路线新子项 B3（全局静态 rt_mutex：地址 = 静态 VA + slide 可计算），但本轮离线枚举在现有物料上无法确认任何实例存在——登记为未证实候选，不据此重开。**

---

## 1. 方向 A：W 线程内核栈地址（③）

### 1.1 候选来源清单与评估

| 来源 | 现有证据 | 技术前提 | 可观测性 | 判定 |
|---|---|---|---|---|
| A1 KernelSnitch 平移到栈 | futex key 仅含用户地址 + mm/inode（`futex.c:391-396`），**栈地址不进哈希**；mm（slab）与栈（buddy order-2）无固定偏移 | 需要"栈地址作为可观测键"的新原语 | 无 | **不可行**（源码层确认，WAITER §5.5.1） |
| A2 USENIX'25 TLB 侧信道 | 依赖 `CONFIG_VMAP_STACK`/`SLAB_VIRTUAL` 的 4 KB 细粒度信号 | 本机两者均无（config + 实测） | 无 | **不适用**（WAITER §5.2/§5.5.3） |
| A3 oops 寄存器 dump 的 sp | 唯一含 sp 的已审输出（16 条可达接口，§53/§60） | `panic_on_oops` 不可观测；触发即重启并作废 ① 类地址 | 触发即越界（重启需单独授权 + 高破坏） | **排除**（维持 v11 结论） |
| A4 dumpstate WARN 的 sp（v13 新增观测面） | 已实测：两类 boot 的 sp 均为 **init/swapper**（`0xffffffc51fa1f910` 等） | 需 WARN 发生在**目标 W 线程上下文**——而 W 是执行 xattr/futex 路径的用户态线程，该路径无自然 WARN 点；人为制造 = 违反"不制造内核异常"边界 | 仅 init/swapper/kworker 类上下文可自然出现 | **不满足 ③ 判据（R4）**；维持旁证登记 |
| A5 阶段 2（已跳过）静态审计可能发现的 WARN 调用点 | 未执行 | 同 A4：WARN 上下文属于触发线程；kworker/init 的栈均非 W 栈 | 同上 | 即便产出候选，也**只能补充 ①A 类证据**，不构成 ③ |

### 1.2 方向 A 小结

- ③ 的判据（R4：地址属于目标 W 线程）自 v11 成立以来**没有任何新 oracle**；v13 的 dumpstate 观测面**没有也没有可能**改变这一点——它输出的 sp 属于内核线程上下文，与 W 线程栈是不同分配实体。
- 几何换算（栈基址 → waiter 自引用值）早已静态解决，**瓶颈自始至终是"拿到 W 栈基址"这一步**，本轮无新证据。
- **方向 A 维持：无可用来源，继续冻结。**

---

## 2. 方向 B：现有合法内核锁对象（②）

### 2.1 候选来源清单与评估

| 来源 | 对象身份证据 | 运行时地址可得性 | 生命周期 | 可控性/风险 | 判定 |
|---|---|---|---|---|---|
| **B1 `pi_state.pi_mutex`**（futex PI 路径，`futex.c:207` 内嵌 `struct rt_mutex pi_mutex`） | 源码级确认（内嵌结构，类型合法） | **无 oracle**：kmalloc-128 分配，地址取决于分配序；KernelSnitch 只给 mm 点；M2 时间邻接已否证 | 研究者可创建/持有（PI futex 可控创建），对象活性可保证 | 结构可控性有限（对象内容非全控）；主要是地址不可得 | **维持缺口**：缺地址锚点，与 v10 结论一致 |
| **B2 AF_UNIX 16 KB skb 喷页上的伪造 rt_mutex** | v4 P1 实测：3072 对象/轮、spread 0.00%，生命周期可控；payload = 16064+320 = 16384，每包恰一个 order-2 块 | **无地址锚点**：落点 1.0–5.5 GiB 随机散布（v10 示踪否证固定 delta）；slide 属镜像映射，帮不了 DPM 落点 | 可控（喷/收可控） | 内容全可控；缺的只是"落点在哪" | **维持缺口**：v10 否证不被 slide 修复 |
| **B3 全局/静态 rt_mutex（v13 新登记子项）** | **未证实**：部分源码树（`src_ref/kernel_49_mainline/`）`DEFINE_RT_MUTEX` 全局实例 **0 处**（仅 `include_linux_rtmutex.h:75` 宏定义）；`vmlinux.elf` 符号表 **st_size 全为 0**（vmlinux-to-elf 产物），无法按 `sizeof(struct rt_mutex)=0x20`（`CONFIG_DEBUG_RT_MUTEXES is not set`）做尺寸过滤枚举 | **若实例存在，地址 = 静态 VA + slide，当前 boot 可计算**（①A 唯一直接受益点） | 静态存储 ⇒ 永活（R5 天然满足） | **高风险未审**：向真实内核锁的 waiter 树做 enqueue/dequeue = 操作真实内核对象；并发竞争 + 链式优先级传播 + 真实 owner 语义（owner==NULL 时走 wake 分支）均未审计；**误判生命周期或并发语义可能直接 panic**（step3 意见 §六警告） | **登记为未证实候选**：枚举未完成（物料不足），未证伪亦未证实；仅在"出现完整源码/带尺寸符号表"后可完成静态枚举 |
| B4 任何"看起来像锁的"内核地址 | 无对象身份证据 | — | — | — | **不纳入**（R3 规则；§八"泛化非零地址搜集不作为进展"） |

### 2.2 本轮新增离线核查记录（B3 枚举）

| 检查 | 命令/方法 | 结果 |
|---|---|---|
| `CONFIG_DEBUG_RT_MUTEXES` | `artifacts_adb/k3_kernel_config.txt` | 未启用 ⇒ 非 debug 布局尺寸 = `raw_spinlock_t + rb_root + 2 指针` = **0x20** |
| 源码树全局实例 | `grep DEFINE_RT_MUTEX src_ref/kernel_49_mainline/` | **0 处**使用（futex.c 的 `pi_mutex` 为内嵌成员，非全局实例） |
| 符号表尺寸枚举 | pyelftools 扫 `vmlinux.elf` 全部 67,189 个 `STT_OBJECT` | **st_size 全为 0** ⇒ 尺寸过滤不可用；仅名称可查，无法判型 |
| 名称含 `mutex` 的对象符号 | 同上 | 全部为 `__ksymtab_*`（0 尺寸跳转表项），无实例符号 |

> 结论：**B3 在现有物料上不可判定**。这是一个"物料缺口"而非"方向否证"——按 R6 证据等级，此处正确状态是"未证实候选 + 枚举前置条件缺失"，不得写成"不存在"（枚举不完备），也不得写成"存在可用对象"（无对象身份证据）。
> **【v13-补做后已失效，见 §2.3——物料缺口已闭合，枚举完成】**

### 2.3 B3 静态枚举完成（厂商源码到手后补做，2026-11-20）

前置：用户指示"已经拿到厂商源码，那些之前因为没有源码做不到的工作先补做"。全树克隆 `oppo-source/android_kernel_oppo_sdm710` 分支 `oppo/sdm710_r_11.0_reno`（提交 `bf9316a9`，PCAM00_11_F.56，LA.UM.9.8.R1.11.00.00.673.034_r2.1.1），经本地代理 127.0.0.1:7890 获取，入库 `.build/vendor_kernel_full/`（Windows 保留名导致仅 `drivers/gpu/drm/nouveau/.../i2c/aux.{c,h}` 2 个无关文件未检出）。

**源码枚举**（全树 grep）：

| 检查 | 结果 |
|---|---|
| `DEFINE_RT_MUTEX` 使用点 | 9 处：`torture_rtmutex`(locktorture)、`rpm_clock_lock`(clk/msm/clock-rpm)、`voter_clk_lock`(clock-voter)、`uid_lock`(misc/uid_sys_stats)、`msm_bus_adhoc_lock`(msm_bus_arb_adhoc，非 static)、`msm_bus_adhoc_lock`(msm_bus_arb_rpmh)、`msm_bus_dbg_cllist_lock`、`msm_bus_dbg_floor_vote_lock`、`proc_uid_lock`(fs/proc/uid) |
| 文件作用域裸 `struct rt_mutex` 声明 | 0 处 |
| `rtmutex-tester.c` | 不存在于此树（tester 数组排除） |
| 嵌套成员 | `i2c_adapter.bus_lock/mux_lock`、`em28xx.i2c_bus_lock`：动态分配，无静态实例；`rcu_node.boost_mtx`：`CONFIG_RCU_BOOST` 全部 defconfig 未开启，死成员 |

**符号表裁决**（vmlinux.elf symtab，STT_OBJECT）：9 个源码候选中 **4 个编入内核**，3 个未编入（`torture_rtmutex`/`rpm_clock_lock`/`voter_clk_lock` 无符号；`floor_vote_lock` 亦无），2 个 `msm_bus_adhoc_lock` 中仅 1 个符号存在。`cpufreq_times.c:35` 的第二个 `uid_lock` 为 **spinlock**（非 rt_mutex），排除。

**确认的静态实例集（当前 boot slide `0x1953600000`，运行时 VA = 静态 VA + slide）**：

| 符号 | 源文件 | 静态 VA | 运行时 VA | 节 |
|---|---|---|---|---|
| `uid_lock` | drivers/misc/uid_sys_stats.c:36 | `0xffffff8009e0ca80` | `0xffffff995d40ca80` | .kernel2（合并数据节） |
| `msm_bus_adhoc_lock` | drivers/soc/qcom/msm_bus/msm_bus_arb_adhoc.c:43 | `0xffffff800a139530` | `0xffffff995d739530` | .bss |
| `msm_bus_dbg_cllist_lock` | drivers/soc/qcom/msm_bus/msm_bus_dbg.c:41 | `0xffffff800a139590` | `0xffffff995d739590` | .bss |
| `proc_uid_lock` | fs/proc/uid.c:26 | `0xffffff800a05b150` | `0xffffff995d65b150` | .bss |

全部为 `DEFINE_RT_MUTEX` 初始化的真实内核锁（对象身份 R2/R3 满足：符号级类型确定；生命周期 R5 满足：静态存储永活；地址 R4 满足：可由 slide 复算，boot 随机但一次性算出）。

**对 §2.2 结论的替代**：B3 从"未证实候选"升级为 **"静态层已证实候选集（4 实例）"**——"是否存在全局 rt_mutex 实例"这一前提已实证为**存在**。

**对 §3 的更新**：B3 仍**不构成重开依据**。理由不变且更强：这 4 个是**真实在用的内核锁**（proc_uid/uid_sys_stats/msm_bus 均有运行时并发持有者），向其 waiter 树做 enqueue/dequeue = 操作真实内核对象，链式优先级传播会写入**真实 owner 任务**的优先级；并发语义审计（step3 §六要求）尚未进行，panic 风险未评估。静态枚举只闭合了"对象存在性 + 地址可得性"，N1–N4/C1–C3 的其余条件与安全审计仍缺。G3 冻结判定维持。

### 2.4 B3 并发语义静态审计（G4，已执行，结论为否）

> 阶段 3 的收尾工作（G3 §1 重开条件②）已完成：`GHOSTLOCK_B3_CONCURRENCY_AUDIT.md`（G4），纯离线源码 + 本机 `vmlinux.elf` 逐指令。

| 项 | 结论 | 依据 |
|---|---|---|
| 链走查入口 | `sched_setscheduler` → `rt_mutex_adjust_pi` → `rt_mutex_adjust_prio_chain(task=W, MIN_CHAINWALK, orig_lock=NULL, next_lock=waiter->lock, orig_waiter=NULL, top_task=W)` | `rtmutex.c:1157-1179`；二进制 `0x81255b8`/`0x8125658`（参数 `x2=0`/`x4=0`） |
| 关键判定点 | `:702` 无条件 `rt_mutex_top_waiter(lock)`：`lock->waiters_leftmost == NULL` ⇒ 读 `NULL+0x38` 数据异常（`BUG_ON` 之前） | `rtmutex_common.h:47-57`；二进制 `0x81258d8 ldr [x24,#0x10]` → `0x81258dc ldr [x27,#0x38]` → `brk` 目标 `0x8125e7c` |
| 非空树 | 树中至少一个**真实等待者**节点（地址在其它任务内核栈；fake 首次入树在 `:726`，晚于 `:702`） | `rtmutex.c:1005` / `:726` |
| `:705` `rb_erase(fake)` | fake 不在树中；全零链接 ⇒ 清根 + 孤儿真实 waiter + 永久幽灵顶层 waiter；非零链接 ⇒ 任意写与树损坏不可分离（rebalance 把选定 parent 当 rb_node） | `rtmutex.c:270-281`、`lib/rbtree.c:424-430` |
| 判定 | **B3 不满足 N1 的"可控"**；唯一出写路径必然越过"不制造新竞态/不强制异常"边界 ⇒ **维持冻结** | G4 §4–§9 |

**对 §2.3 的补充**：B3 现在是"**静态层已证实、可用性已否证**"的候选集（4 实例地址仍真实、可复算；但不可用作 N1 的 rt_mutex 对象）。G3 §1 的重开条件②已执行并失败，故 B3 不是"待办审计"，而是"已审计否决"。

---

## 3. 对比结论（step3 意见 §三要求的"先比较、不预决"）

| 维度 | 方向 A（W 线程栈） | 方向 B（合法锁对象） |
|---|---|---|
| 机制地位 | N1 的途径 a1（K3 载体下最直接），本质是**载体设计条件**（C1） | N1 的途径 a2，**与载体无关** |
| 现有证据量 | 几何已解决；oracle 全缺（16 接口 + dumpstate 双 boot 已审） | B1/B2 对象与生命周期证据充分；地址锚点全缺；**B3 地址可得但可用性已被 G4 否证** |
| v13 slide 增益 | **零**（栈在 DPM，与镜像映射独立） | **仅 B3 受益**（地址可计算性），但实例均共享真实锁、不可控（G4） |
| 可观测性缺口 | "W 线程栈基址 oracle"不存在 | "堆对象地址锚点 oracle"不存在（B3 不需要 oracle，但需要"专供攻击者的锁"，本机不存在） |
| 风险 | 无观测手段即无风险 | B3 已过静态审计：空树必 oops、非空树不可控写/孤儿等待者（G4），维持冻结 |
| 证据等级上限 | 上机观测类（需越界授权） | B3 理论上可达最高级（静态符号身份 + slide 可复算地址 + 静态存储生命周期） |

**G2 交付核心判定**：两条路线的"常规候选"（A1–A4 / B1–B2）都卡在同一类缺口——无地址 oracle，本轮均无新证据。**唯一值得后续投入的差异点是 B3**：它是全矩阵中唯一一个"地址可由已取得 slide 直接计算"的候选，且证据等级可以做到最高（静态身份 + 可复算地址 + 永活生命周期）。**该差异点已在 G4 完成审计并否证**：B3 的 4 个实例都是共享的真实内核锁，链走查在空树上必然 `NULL+0x38` fault、在非空树上必然触碰不可控真实 waiter，因此不能满足 N1 的"可控"；它已从"唯一候选"变为"已审计否决的候选"（`GHOSTLOCK_B3_CONCURRENCY_AUDIT.md`）。

---

## 4. 引用

- 需求框架：`GHOSTLOCK_ADDRESS_REQUIREMENTS.md`（N1–N4 / C1–C3）
- 源码级依据：`artifacts_adb/WAITER_ADDRESS_ANALYSIS.md` §3.3/§4/§5.5、`GHOSTLOCK_NUL_ANALYSIS.md`
- 喷射与否证：`HANDOVER.md` §50（v10）、CLOSURE §2.2
- 基线规则：`GHOSTLOCK_ADDRESS_BASELINE.md` §2–§3（R1–R6）
- B3 并发语义审计（G4）：`GHOSTLOCK_B3_CONCURRENCY_AUDIT.md`；复算工具 `tools/b3_audit.py`
