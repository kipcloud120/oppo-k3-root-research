# OPPO K3「临时 ROOT」项目 · 交接文档

| 项 | 值 |
|---|---|
| 版本 | **v2.2（结项版 + Binder 面审计完整闭合）**，2026-11-17；v2 重写替代 v1 的 13 轮增补式长文，§14 为同日新增并完成五轮的 Binder 面审计 |
| 状态 | **已结项（no-go）**：四类组件、五个候选面全部判定完毕；§14 追加审计的 Binder 服务面亦基本否证，结论不变 |
| 原件 | `docs_archive/HANDOVER_v1_2026-11-17_full.md`（v1 全文 3368 行，含全部过程推理，**仅备查**） |
| 唯一入口 | 本文件。数值以本文件为准；v1 与 `docs_archive/` 的其余文档一律视为历史证据，不得引用其数值 |
| 设备终态 | `PCGM00_11_F.16` 未变；**未刷写、未解锁、未改分区、未 root**；`/data/local/tmp` 为空；§14 全程只读 |
| Binder 面审计 | `artifacts_adb/binder_audit/AUDIT_REPORT.md`（五轮结论：atlas 线索 5/5 闭合、确定否证）；**厂商二进制与系统镜像不入库**，脚本与报告已提交 |

---

## 0. 阅读指引

按目的选路径，不必通读：

| 目的 | 读 |
|---|---|
| 只要结论 | §1 |
| 接手继续做 | §1 → §2（基线）→ §5（逐面）→ §7（重开条件）→ §8（关键常数） |
| 复核某个判断 | §5 对应小节 + §6 负知识清单 + `artifacts_adb/` 原始日志 |
| 只想避坑 | §6 负知识清单 + §10 方法论 |
| Binder 服务面（§4 唯一未闭合面）| **§14**（五轮审计：28/35 覆盖、atlas 线索 5/5 闭合确定否证、结论仍 no-go）|

**三条硬规则**

1. **反汇编只用 `firmware_F16/vmlinux.elf`**。`kallsyms_out.txt` 只用于查名字，其偏移在 futex/binder 区偏差 0x6–0x9 万字节。
2. **不要用构建日期推断代码版本**。本机 2025-03 构建，binder 却仍是 2018 年的语义（§5.3）。
3. **每重启一次设备，先补完文档再继续实验**（用户约定，全程遵守）。

---

## 1. 结论页

### 1.1 目标与判定

**目标**：在不解 BL 的前提下取得 OPPO K3 的**临时 ROOT**（运行时 uid=0，重启即失）。官方"深度测试"/持久 root 出口（A 线）已按用户决定移除。

**判定**：在设备现状下，评估过的**五个候选面（4 类组件）全部不可达成本目标**，且每一面都已定位到"卡在哪一环、缺什么能力"——不是"跑崩了"。

### 1.2 逐面结论

| 面 | 机制是否成立 | 卡点 | 章节 |
|---|---|---|---|
| **KGSL** CVE-2023-33107 | 成立（源码级 pre-fix 确定） | `arm_lpae_init_pte()` 的 `BUG_ON(!suppress_map_failures)`，该静态变量运行期恒 false ⇒ 进入缺陷路径即 `BUG()` panic，无中间状态可用 | §5.1 |
| **GhostLock** CVE-2026-43499 | 成立（`-EDEADLK` 10+ 次确定性复现） | **无栈覆盖载体**：waiter 位于 `-0x288`，397 个 syscall 入口全扫、0 命中（合格带仅 54 字节宽，落在"浅 syscall"与"select 家族"之间的死区） | §5.2 |
| **binder** CVE-2023-20938 | **不成立**（漏洞未引入） | `off_end_offset` 形态处于 `44d8047f1d87 … 32e9f56a96d8` 之间，`is_failure=1 且 failed_at=0` 时循环 0 次 | §5.3 |
| **binder** CVE-2022-20421 | 成立（pre-fix 形态确证） | 本机为 **ticket spinlock**，公开技术依赖 qspinlock；本机原语退化为"对两半相等的 4 字节字加 `0x00010001`"，并带 `wfe` 死等风险 | §5.3 |
| **FastRPC** CVE-2023-33063 | 面存在 | 对 shell **双重封闭**：`O_RDWR` 被 SELinux `EACCES`；只读 fd 上 7 个已实现 ioctl 全 `EPERM` | §5.4 |

### 1.3 主要资产与代价

- **可复用最大产出**：`firmware_F16/vmlinux.elf`（123784 符号、基址 `0xffffff8008080000`），用 `vmlinux-to-elf` 从 `kernel.decompressed` 重建，`head.S` 反汇编自证 —— 一举解决了困扰 v1 §11/§12/§16 三节的"符号不可用"问题。**v1 关于"节区/函数重排、无线性映射"的判断已作废。**
- **代价**：累计 **5 次内核重启**（`run1`/`run3`/`run4`/`D2`/`v6`，全部发生在 GhostLock 竞态实验期，均由 panic 自动重启恢复），此后 0 次；未推送任何持久化改动。
- **建议**：**关闭系统 OTA**。任何版本前进都会使本文件的全部偏移与形态判定作废（§7 第 3 条）。

---

## 2. 设备与权限基线

### 2.1 设备事实（ADB 一手，`artifacts_adb/k3_info*.txt`）

| 维度 | 值 |
|---|---|
| 型号 / 代号 / 板 | `PCGM00`（OPPO K3）/ `ro.product.device=OP4679` / `sdm710` |
| 系统 | `PCGM00_11_F.16`，Android **11**（SDK 30），ColorOS V11.1；完整号 `PCGM00_11_F.16_2025032621191106` |
| 内核 | **`4.9.227-perf+`**，`#1 SMP PREEMPT Wed Mar 26 16:32:43 CST 2025`，clang 10.0.7 |
| 安全补丁 | **2022-04-05**（判定的时间基准线） |
| fingerprint | `OPPO/PCGM00/OP4679:11/RKQ1.201217.002/1704167642389:user/release-keys` |
| 启动 / AVB | `verifiedbootstate=green`、`flash.locked=1`、`veritymode=enforcing`、`avb_version=1.1`；A-only |
| 会话身份 | `uid=2000(shell)`、`u:r:shell:s0`、SELinux Enforcing、**`Seccomp: 0`** |
| 设备序列 | `<redacted>` |

### 2.2 对本项目有决定意义的配置（`artifacts_adb/k3_kernel_config.txt`）

| 配置 | 值 | 影响 |
|---|---|---|
| `FUTEX` / `RT_MUTEXES` | `=y` | GhostLock 面可达 |
| `USER_NS` | **未设置** | netfilter / 多数 nf_tables 类 CVE 全部排除 |
| `ARM64_PAN` / `UAO` / `UNMAP_KERNEL_AT_EL0` | `=y` | 排除"用户态内存伪造内核对象"；KPTI 开启削弱 prefetch 侧信道 |
| `RANDOMIZE_BASE` | `=y` | KASLR 需运行时泄露；`RANDOMIZE_TEXT_OFFSET` 未设 |
| `SLAB_FREELIST_RANDOM` / `SLAB_FREELIST_HARDENED` | **均未设置** | 堆布局可预测（binder 面唯一利好） |
| `SYSVIPC` | **未编译** | `msg_msg` 喷堆原语不存在（`msgget()` → `ENOSYS`） |
| `CHECKPOINT_RESTORE` | **未设置** | `prctl(PR_SET_MM_MAP)` 载体不可用 ⇒ GhostLock 官方 x86 链的载体被否 |
| `KEYS` | `=y` | `keyctl` 备用栈载体理论可用 |
| `QUEUED_SPINLOCKS` | **不存在**（且有 `ARCH_USE_QUEUED_RWLOCKS=y`） | 本机是 **ticket spinlock**，直接决定 binder 面原语强度（§5.3） |
| `SECURITY_SELINUX_DEVELOP` | `=y` | `selinux_enforcing` 可写 0（若走到收尾阶段有用） |
| `KASAN` / `KPROBES` / `DEVMEM` / `PROC_KCORE` / `BPF_JIT` | 均无 | 调试与观测能力极低 |
| `perf_event_paranoid` | `3` | — |

### 2.3 观测能力（决定每一轮实验的设计）

| 通道 | 状态 |
|---|---|
| `dmesg` / `/dev/kmsg` / `/sys/fs/pstore` / `last_kmsg` | **全部不可读** ⇒ 无法取得 panic 文本，崩溃点只能由"帧死活"等间接变量反推 |
| `/proc/kallsyms` / `/proc/iomem` / `/proc/modules` / `dmesg` | 不可得；模块基址为 `0x0` |
| `logcat` 主缓冲 | **可用**，能读到 SELinux `avc: denied` ⇒ 可区分"MAC 拦截"与"内核逻辑拒绝" |
| `logcat -b kernel` | 缓冲存在但内容为空，不能替代 dmesg |
| 崩溃判定 | ADB 掉线 / `uptime` 归零 / `loadavg` 异常 |
| `/proc/slabinfo` | 可读（用于 cache 清单，但 `active_objs` 抖动 ±100，不足以判别小规模变化） |

### 2.4 关注的结构体尺寸（`/proc/slabinfo` 实测）

`task_struct=3840 (0xF00)`、`cred_jar=192`、`filp=320`、`vm_area_struct=184`、`dentry=192`。
kmalloc 仅存在**2 的幂次** cache（`…256/512/1024/2048/4096`），**无 `kmalloc-96`、无 `kmalloc-192`** ⇒ 88 B 的 `futex_pi_state` 必落 `kmalloc-128`。

---

## 3. 物料与工具链

### 3.1 固件与符号

| 文件 | 尺寸 | 说明 |
|---|---|---|
| `firmware_F16/vmlinux.elf` | 39,151,975 | **唯一反汇编物料**。`vmlinux-to-elf` 1.4.0 重建，123784 符号，基址 `0xffffff8008080000` |
| `firmware_F16/boot.img` | 67,108,864 | F.16 原版，SHA256 `22fc0926…a36c3f` |
| `firmware_F16/kernel.decompressed` | 33,155,096 | gzip 单 member 解出，SHA256 `95a70412…baebc` |
| `firmware_F16/kallsyms_out.txt` | 4,682,865 | 123784 符号，**只查名字**；偏移不可用 |
| `firmware_F16/kernel_appended.dtb` | 2,298,167 | 7 个 DTB |
| `firmware_F16/sym_map.txt` | 9,777 | 旧逐符号校验表，**已被 `vmlinux.elf` 取代**，仅作历史 |

**地址换算（关键）**：`file_offset = 0x240 + (va - 0xffffff8008080000)`（`.kernel` 节）。
**自证**：`stext @0xffffff8009a00000` 反汇编为 `bl preserve_boot_args / bl el2_setup / bl set_cpu_boot_mode_flag / bl __create_page_tables / bl __cpu_setup / bl __primary_switch` —— arm64 `head.S` 真实内容，符号空间对齐。

### 3.2 交叉编译与推送

```bash
ZIG=.build/zig-windows-x86_64-0.13.0/zig.exe     # Zig 0.13.0，79 MB，本地工具链，不入库
ADB=./scrcpy-win64-v3.3.4/adb.exe

$ZIG cc -target aarch64-linux-musl -static -O2 -pthread -o .build/<name> tools/<name>.c

export MSYS_NO_PATHCONV=1                        # Git Bash 必须关闭路径转换
$ADB push .build/<name> /data/local/tmp/
$ADB shell "chmod 755 /data/local/tmp/<name>; timeout 25 /data/local/tmp/<name>"
$ADB pull /data/local/tmp/<name>.log artifacts_adb/g_logs/
```

静态 musl 二进制在 Android 11 `/data/local/tmp` 可直接执行，无 SELinux 拦截（已多次验证）。

### 3.3 静态分析环境

| 项 | 状态 |
|---|---|
| Python 依赖 | `pyelftools` + `capstone`（`tools/gl_frame_calc.py` 需要）；**须用 `python -m pip` 安装**——本机 `pip` 指向 Python312，而 `python` 是 WorkBuddy 自带 3.13，两者不是同一环境 |
| Linux 构建环境 | **无 WSL 发行版、无 Docker** ⇒ 不能走"编内核"路线，符号问题只能靠 `vmlinux-to-elf`（已解决） |
| 已有参考实现 | `NebuSec/CyberMeowfia`、`JoinChang/ghostlock-oneplus`、`mobilehackinglab/ghostlock-a17`、`0xkol` 论文（`.build/refs/racing_lock.pdf`） |

---

## 4. shell 域攻击面普查（零副作用，`artifacts_adb/attack_surface.md`）

方法：**只测 `open()`，不写任何字节**；`open(O_WRONLY)` 会走 DAC + SELinux 写检查，成功即可写，且零状态变化。

| 组 | 结果 |
|---|---|
| `/dev`（198 个节点） | 可读 12 个；白名单内**可写仅 4 个**：`binder`、`hwbinder`、`ashmem<uuid>`、`kgsl-3d0`（均 0666） |
| `/proc/sys` + `/sys/module/*/parameters/*` + 16 个高危节点（764 项） | **可写仅 1 个**：`/sys/kernel/tracing/trace`（正常设计） |
| SUID / `run-as` / debuggable | 四分区 `-perm -4000` 命中 **0**；`run-as` SUID 已移除（0750）；`ro.debuggable=0`、无 `su` |
| binder 服务 | **236 个**（229 个可 `dumpsys`），含 10+ 个 OPPO/ColorOS 私有服务与已开启的工程模式 —— 本文件 v2 时"从未审计、唯一未闭合的未知面"；**已于 2026-11-17 审计，见 §14：35 个私有服务覆盖 28 个，atlas 线索否证，结论 no-go** |

**两条对早期记录的修正**

1. **没有 `/dev/ashmem`**，只有按实例命名的 `ashmem<uuid>`（0666），shell 三种模式全可开。
2. **`/dev/ion` 是 0664**（owner/group=system），shell 属 other ⇒ **只有读权限**。早期"用 ion 喷堆"的设想从权限位即不可行。

**工程模式**：`persist.sys.adb.engineermode=1`、`init.svc.oplus.engineer-1-0=running`，但 `/my_engineering` 近乎空（仅 `build.prop` + `etc/*`）⇒ **不是提权入口**，价值仅在于多了几个待审计服务。

**若将来要动 binder 服务面**：不要盲试 `service call` 事务号。应静态审计各 `Stub.onTransact` 分支是否缺 `enforceCallingOrSelfPermission`/`checkCallingPermission`，再找"无权限校验 + 高权限操作（写 `/data`、`chmod`、`exec`、`mount`、`setprop`）"的分支。成本 5–10 人日，成功率不保证（2025-03 构建，该类问题近年多已收紧）。

---

## 5. 逐面结论

### 5.1 KGSL CVE-2023-33107 —— 不可利用

**判定**：pre-fix（源码级确定），但**本机构建上不可利用**。

**证据链**

1. 同源官方 4.9 源码 `src_ref/realmeX_master_io-pgtable-arm.c` L596-603：`arm_lpae_map_sg()` 调用 `arm_lpae_init_pte()` **不接返回值**且**无条件 `ms.num_pte++`**；修复 diff 见 `src_ref/lineage_388401.patch`（Qualcomm 2023-09，2023-12 进 CISA KEV）。
2. 本机 SPL 2022-04 ≪ 修复 2023-12；SDM710 已 EOL，不再收 CAF tag。
3. **决定性阻断**：同文件 L286 `static bool suppress_map_failures = false`，L368 `if (*ptep & VALID) { BUG_ON(!suppress_map_failures); return -EEXIST; }`。该变量仅在驱动自检期间为 `true`，运行期恒 `false` ⇒ 一旦 `mmap` 命中 UAF 已存在的有效 PTE，**不是** RCA 所述的"返回 `-EEXIST` 但计数仍自增"，而是 **`BUG()` → panic**。

**实测吻合（三重）**

| 观测 | 解释 |
|---|---|
| 竞速延时 300 µs：日志停在"起 racer"，设备立即离线 | 主线程 `mmap` 执行到 `map_sg` 撞上有效 PTE → `BUG_ON` |
| 延时 3000/5000 µs：安全，`OVERLAP mmap` 返回 `ENOMEM` | 该时序下 `map_sg` 未执行，未触 `BUG_ON` |
| `k3_dangling` 第 6 步 mmap 成功、无残留 PTE | `out_err` 返回 0，驱动把映射失败伪装成成功，此路从未建立悬垂 PTE |

⇒ **"进入漏洞路径"与"内核 panic"在本机是同一件事**，不存在"先命中、再利用"的中间态。

**已判定无用的历史判据**：PoC 以 `OVERLAP mmap` 返回 `ENODEV(19)` 为命中标志（`poc_ex.c:1861`）。逐条核对 4.9 全部 `ENODEV` 来源后确认：`kgsl_get_unmapped_area()`/`kgsl_mmap()` 的返回码只有 `EINVAL/EBUSY/ERANGE/ENOMEM/EPERM`，**结构上不可能返回 `ENODEV`**。该判据在本机是"永远等不到"的条件。

**阶段 A/B 的正面成果（对其它线仍有复用价值）**

- UAPI 全兼容：7 个 ioctl 号、8 个结构体逐字段与 4.9 一致；结构体尺寸实测 `getproperty=24 drawctxt=8 map_user_mem=48 gpuobj_alloc=48 gpuobj_free=32 gpuobj_info=48`。
- **`DRAWCTXT_CREATE` 的 `flags` 必须为 `0x12`**（`PREAMBLE 0x10 | NO_GMEM_ALLOC 0x2`），否则 `-EINVAL`。
- **SVM 窗口实测与源码常量 9 点全对**：SVM64 `[0x700000000, 0x800000000)`、GLOBAL `[0x500000000, 0x600000000)`（禁注册）、compat `[0x300000, 0xBEF00000)`（**低地址同样合法注册**，是一条此前未记录的旁路）。
- 四段 range 满尺寸几何可建立；`munmap` 后 rbtree 条目仍占位（PoC"PTE/rbtree 残留"前提的真机证据）。

---

### 5.2 GhostLock CVE-2026-43499 —— 机制成立，无栈覆盖载体

**这是本项目投入最深、结论最细的一面。** 缺陷真实、触发确定性可达、换向机制已被正面证实，唯一缺口是"把攻击者数据放进那块栈槽"。

#### 5.2.1 缺陷本体

| 项 | 值 |
|---|---|
| CVE / 别名 | `CVE-2026-43499` / GhostLock；rtmutex PI futex **栈 UAF**（CWE-416），CVSS 7.8 |
| 根因 | `remove_waiter()` 用 `current` 而非 `waiter->task` 清 `pi_blocked_on` 并遍历 PI 链（`rtmutex.c:1076-1121`） |
| 触发面 | `futex_requeue()`（`FUTEX_CMP_REQUEUE_PI`）→ `rt_mutex_start_proxy_lock()` 的 `-EDEADLK` 回滚；此时 waiter 属于**另一个睡眠线程** |
| 引入 / 修复 | `8161239a8bcc`（2.6.39）→ 修复 `3bfdc63936dd`（主线 7.1，2026-05-04 backport），diff 见 `src_ref/ghostlock_fix.patch` |
| 依赖 | `CONFIG_FUTEX_PI`；**不依赖 `USER_NS`**（本机 `USER_NS=n` 不阻断） |

权威源码：`src_ref/kernel_49_mainline/`（v4.9 tag，含 `rtmutex.c`/`futex.c` 与行号索引）。
⚠️ `src_ref/futex_4.9/` **实为 ~v4.20 代码**（含 `u64 deadline`、`rt_mutex_futex_unlock(lock, wake_q)`），**不得再用于行号或尺寸引用**。

#### 5.2.2 已确证的四件事

| # | 结论 | 证据 |
|---|---|---|
| 1 | **漏洞路径确定性可达、可重复** | `-EDEADLK` 累计 **10+ 次**复现（4/4、6+、2/2、2/2），设备零损伤 |
| 2 | **`remove_waiter()` 清错任务 ⇒ 悬垂 `pi_blocked_on` 确实留存** | 三锁环命中后，"帧死即 panic 3/3"本身就是内核仍在解引用该指针的反证 |
| 3 | **"定向换向"机制成立**（A′ 活帧对照） | 帧存活时 `[12]` 命中 `lock == C2 == orig_lock` → 干净 `-EDEADLK`，`uptime` 连续 |
| 4 | **panic 与走查形态无关，唯一变量是"帧是否已死"** | 同构造同参数：帧活 ⇒ `-EDEADLK`；帧死 ⇒ panic 3/3，与窗口 0.05 ms 还是 2.1 s 无关 |

**A′ 的三重意义**（本项目唯一正面里程碑）：① `task_blocks_on_rt_mutex()` 的 `waiter->lock = lock`（`rtmutex.c:976`）确实落在被 requeue 的 waiter 上；② 本机 `rt_mutex_adjust_prio_chain` 在 `C2→O2→B3→W→waiter` 三跳链上的行为与主线 4.9 一致；③ `-EDEADLK` 的收尾（在 refcount ≥2 时）不会破坏目标 `pi_state`。

#### 5.2.3 触发构造（可直接复用）

三锁环，不可用自环（自环走 `rtmutex.c:993` 的 `owner == task` 提前返回，waiter 尚未入队，无副作用）：

| 角色 | 动作 |
|---|---|
| W | `LOCK_PI(B)` 持 B；随后 `WAIT_REQUEUE_PI(A→C, 600 ms)` 睡在 A（`rt_waiter` 在其内核栈） |
| O | `LOCK_PI(C)` 持 C；再 `LOCK_PI(B)` 阻塞（`O->pi_blocked_on` 置位） |
| R | `CMP_REQUEUE_PI(A→C, 1)` → 链走查 `C(owner=O) → B(owner=W)` → `rtmutex.c:642` 判死锁 → `-EDEADLK` |

关键约束：`rtmutex.c:1708` 有 `if (ret && !rt_mutex_owner(lock)) ret = 0;` ⇒ **O 必须始终保持持有 C**，否则 `-EDEADLK` 被复位为 0。
判据二元化（已用 `noring` 对照组证实）：有环 → `-EDEADLK`；无环 → 返回 `1`。

**W 必须从"不自愈"的出口返回**：`FUTEX_WAKE(A)` 会被拒（`futex_wake()` 对 `q->rt_waiter != NULL` 返回 `-EINVAL`）；正解是**超时早退** `handle_early_requeue_pi_wakeup()`（`futex.c:2738`），它绕过 `rt_mutex_finish_proxy_lock()`，因此不清 `pi_blocked_on`。

#### 5.2.4 卡点：无栈覆盖载体（决定性）

**几何**（以进入内核时的栈顶为 0，两条路径共用 `el0_svc_handler`，该项相消）：

```
waiter 绝对位置      = -(0x110 + 0x070 + 0x1f0) + 0xE8 = -0x288   [占 -0x288 … -0x240)
```

| 函数 | 帧大小 | 关键局部 |
|---|---|---|
| `SyS_futex` | `0x070` | — |
| `do_futex` | `0x1f0` | `x29 = sp+0x190`；**`rt_mutex_waiter` 在 `do_futex+0xE8`**（三重确证：`sub x2/x1/x0, x29, #0xa8`） |
| `SyS_pselect6` | `0x0a0` | — |
| `core_sys_select` | `0x1c0` | `fds @ sp+0x20`、`stack_fds @ sp+0x50`（256 B） |
| `SyS_select` | `0x080` | 同上 |
| `compat_SyS_pselect6` / `compat_core_sys_select` | `0x090` / `0x1c0` | 同上 |
| `SyS_poll` / `do_sys_poll` | `0x060` / `0x400` | `stack_pps @ sp+0x60` |

> 本机 `futex_wait_requeue_pi` **被内联进 `do_futex`**（无独立符号），waiter 比"独立函数"形态浅一帧。

**载体判据**：`d - buf_off ∈ [0x288, 0x288 + size - 72]`；fake waiter 需完整 72 字节 ⇒ 起始偏移须 ≤ 54 字节。

| 载体 | `d-buf` | waiter 在缓冲内偏移 | 判定 |
|---|---|---|---|
| `pselect6` | `0x320` | `0x98 = 152` | ❌ 差 98 字节 |
| `select` | `0x300` | `0x78 = 120` | ❌ 差 66 |
| `compat pselect6` | `0x310` | `0x88 = 136` | ❌ 差 82 |
| `poll` / `ppoll` | `0x510` | 负 | ❌ 方向相反 |
| `sendto` / `sendmsg` / `recvmsg` | `0x260` / `0x328` / `0x318` | — | ❌ 太浅 / 太深且不足 72 B |
| `readv`/`writev`（`iovstack @ sp+0`） | `0x1d0` | — | ❌ 太浅 |

**全量扫描（`tools/gl_carrier_scan.py`）**：397 个 syscall 入口（含全部 `SyS_*`/`compat_SyS_*`，调用深度 ≤3）→ **命中 0，近失配 66**。

| 最接近的候选 | `d-buf` | 长度 | 缺口 |
|---|---|---|---|
| `fcntl_getlk` | `0x298` | 32 | 起点比 waiter 深 `0x10`，只覆盖前 16 字节 |
| `SyS_quotactl` | `0x2c8` | 72–112 | 比允许上限（`0x2b0`）深 `0x18` |
| `SyS_prctl` | `0x2e0` | 未知 | 深 `0x30` 以上 |

⇒ **合格带（54 字节宽）恰落在"浅 syscall（0x1d8–0x260）"与"select 家族（0x300+）"之间的死区。** 这不是参数没调对：`core_sys_select` 单帧 `0x1c0` 就把下限钉在 `0x320`，任何 NFDS 都够不到；公开实现的 `PSELECT_SHIFT`（±2 字）量级远小于此差值。

**为什么这条缺口是结构性的**：栈槽内容只能由内核写（`task`/`lock`/`prio` 均为内核按自身逻辑写入的值），本身不构成写原语；`PAN`/`UAO` 开启排除用户态伪造 `rt_mutex`；`kmalloc-128` 外部喷堆原语在本机不存在（`SYSVIPC` 未编译；`setxattr` 2000 次仅 33 次成功且 `kmalloc-128` delta = 0）。**"缺的正好是一个本机不存在的原语"**——这是不可利用性判定与"还没试出来"的本质区别。

#### 5.2.5 过程中的两个方法论产出

1. **无创状态 oracle**：对 PI futex 发 `FUTEX_WAKE(f,1)`，返回 `EINVAL` = 有已入队 PI waiter（且在唤醒前 `break`，零副作用），返回 `0` = 无。`futex_wake()` 源码即 `if (this->pi_state || this->rt_waiter) { ret = -EINVAL; break; }`。**用一个 syscall 的返回值替代一次设备重启。**
2. **`-EDEADLK` 不是无害早退**：当目标锁上**没有**其它已入队 PI waiter 时，`put_pi_state()` 归零 → `free_pi_state` → `rt_mutex_proxy_unlock()` + `kfree`，用户态字值不变（D2 系列实测：此后 requeue 返回 1 ⇒ 内核侧 owner 已为 NULL）。**但若已有 waiter 入队（refcount ≥2），则不会释放**（`X2` 探针实测 `EINVAL`）——两种现象必须分开，不可混谈。

#### 5.2.6 已判无效的探针（避免重复）

| 探针 | 为何无效 |
|---|---|
| `FUTEX_LOCK_PI` 作链走查探针 | 走 `RT_MUTEX_MIN_CHAINWALK`，`waiter->prio == task->prio` 时在 `rtmutex.c:611` 早退，结构上到不了死锁判定点 ⇒ 只能看到 `ETIMEDOUT` |
| `FUTEX_TRYLOCK_PI` 作 `rt_mutex.owner` 探针 | 它按 futex 字值查 owner，而字值始终是原 owner 的 tid ⇒ 必然 `EAGAIN`，与 `rt_mutex.owner` 无关 |
| `rtmutex.c:627` 无界 `trylock` 重试解释"不返回" | 若 `waiter->lock != next_lock`，走查在 `:579` 干净退出并返回 0；真正机理是链变更守卫退化（`next_lock` 与 `waiter->lock` 同源，恒相等 ⇒ 任何被污染的 `lock` 都被接受）+ trylock 失败无界重试 |
| 窗口量化（W1/W2） | 决定性变量是**帧是否已死**，不是"多久之后"：0.05 ms 与 2.1 s 无差别 |

---

### 5.3 binder —— 一个未引入、一个 pre-fix 但无可用原语

#### 5.3.1 CVE-2023-20938：**不适用（漏洞未引入）**

判定方法是"补丁形态比对"（优于反汇编猜寄存器）：

| 阶段 | commit | `off_end_offset` 形态 | 语义 |
|---|---|---|---|
| 加 `is_failure` | `44d8047f1d87` | `is_failure ? failed_at : off_start + offsets_size` | `is_failure=1, failed_at=0` ⇒ `off_end=0` ⇒ **循环 0 次（安全）** |
| **引入漏洞** | `32e9f56a96d8` | `is_failure && failed_at ? failed_at : …` | `&&` 短路 ⇒ 清理整个缓冲区 ⇒ 多减 `local_strong_refs` ⇒ UAF |
| 完整修复 | `bdc1c5fac982`（= android `1ca1130ec62d`） | 由 helper 显式算边界 | 修复（含 CVE-2023-21255） |

本机反汇编（`binder_transaction_buffer_release @0xffffff8008e1da30`，size `0x948`）：

```
0x8e1dbc4  ldr  x8, [x20, #0x40]      ; buffer->data_size
0x8e1dbd0  and  x9, x8, #~7           ; off_start = ALIGN(data_size,8)
0x8e1dbd4  tbnz w23, #0, 0x8e1dbe0    ; if (is_failure) 跳过下面两条 —— 无条件
0x8e1dbd8  ldr  x8, [x20, #0x48]      ;   offsets_size
0x8e1dbdc  add  x19, x8, x9           ;   off_end = off_start + offsets_size
0x8e1dbe0  cmp  x9, x19 ; b.hs <结束>
```

`tbnz` 之后**没有**对 `failed_at` 的第二道测试 —— 这正是 `is_failure ? failed_at : …` 的编译形态。⇒ 本机处于 `44d8047f1d87 … 32e9f56a96d8` **之间**，尚未引入该漏洞。

**措辞必须准确**：不是"OPPO 打了 2023-07 的补丁"（SPL 2022-04 不可能），而是**这个旧形态本身不具备可触发性**。

**连带推论**：本机 binder 带有 `binder_alloc_*` 拆分与 `is_failure` 参数，却没有 `32e9f56a96d8` 的语义改动 ⇒ binder 来自某个**特定中间版本** backport。**每个 binder CVE 都必须单独做"commit 演变 + 反汇编形态"比对**，不能按构建日期推断。

#### 5.3.2 CVE-2022-20421：**pre-fix 确证，但无可用原语**

修复 `a0e44c64b606`（ASB 2022-10）的判定特征是：`_raw_spin_unlock` 之前存在一次 `binder_cleanup_ref_olocked()` 调用。本机 `binder_inc_ref_for_node @0x8e1d258`（size `0x3f8`）：

```
0x8e1d5b0  bl binder_inc_node
0x8e1d600  bl printk                  ; trace_binder_ref
0x8e1d608  bl _raw_spin_unlock        ; ← 前面无 cleanup 调用
0x8e1d60c  cbz x24, 0x8e1d620         ; if (!new_ref) 返回
0x8e1d610  cmp x22, x24 ; b.eq …      ; ref == new_ref ?
0x8e1d61c  bl kfree                   ; kfree(new_ref)
```

尾部结构精确等于 **pre-fix** 的 `unlock; if (new_ref && ref != new_ref) kfree(new_ref);` ⇒ 结构前提成立。

缺陷与触发（据 commit message）：`BINDER_TYPE_WEAK_HANDLE` 事务递增新引用失败（`ret != 0`）→ 目标进程并发死亡与 `binder_deferred_release()` 竞态 → 该"失败引用"无人清理，`ref->proc` 悬垂 → 关闭 `ref->node` 时 `spin_lock(&ref->proc->inner_lock)` ⇒ **4 字节 UAF 写**。

**决定性阻断：本机是 ticket spinlock（二进制确证）**

| 证据 | 内容 |
|---|---|
| 配置 | 有 `ARCH_USE_QUEUED_RWLOCKS=y`，**无** `ARCH_USE_QUEUED_SPINLOCKS` / `QUEUED_SPINLOCKS` |
| 符号 | `queued_spin_lock_slowpath` **不存在** |
| `_raw_spin_lock @0x9125678` | `ldaxr` → `add w9, w8, #0x10, lsl #12`（= **+0x10000**）→ `stxr` → `owner==next` 则返回，否则 `wfe` 死等 |
| `_raw_spin_unlock @0x91257a8` | `ldrh` → `add #1` → `stlrh`（低 16 位 +1） |

| 锁实现 | 一次 lock+unlock 的效果 |
|---|---|
| qspinlock（论文目标） | `(0,0,x)` 且 x>0 时把指针低 2 位置零 → 对齐破坏 → 类型混淆 |
| **ticket（本机）** | 高 16 位 +1、低 16 位 +1；**前置条件：两半必须相等**，否则 `wfe` 死等（挂死而非写入） |

⇒ 本机可用原语 = **"对一个两半相等的 4 字节字加 `0x00010001`"**，与论文的"指针低位清零"不同类，**不能套用其后续链条**。

**判定记录方式很重要**：这不是"不可利用"，而是 **"pre-fix 但无可用原语"**。若将来出现面向 4.9/arm64 ticket spinlock 的 UAF 原语，本项目已备好靶点地址、pre-fix 证据、触发条件与堆条件（`binder_proc` 在 `kmalloc-1k`；`SLAB_FREELIST_RANDOM` 未开）。

**本机有利条件（供将来复用）**：`/dev/binder` `/dev/hwbinder` `/dev/vndbinder` 均 `0666`；`u:r:shell:s0`、`Seccomp: 0`；`CONFIG_ANDROID_BINDER_IPC=y`；无 freelist 随机化（比公开 PoC 目标 5.10.107 更弱，更易预测）。

---

### 5.4 FastRPC CVE-2023-33063 —— 对 shell 双重封闭

| 检查 | 结果 |
|---|---|
| `/dev/adsprpc-smd` | `crw-rw-r-- system system`；`open(O_RDONLY)` OK |
| `ioctl(fd, 0)` | `ENOTTY(25)` ⇒ **已穿过 SELinux `file_ioctl` 钩子**，请求进了驱动 |
| `open(O_RDWR)` | **`EACCES(13)`** ⇒ SELinux 策略（非 DAC 权限位）拒绝写打开 |
| `/dev/adsprpc-smd-secure` | `0640`，`O_RDONLY`/`O_RDWR` 双拒 |

**ioctl 表枚举**（`tools/frpc_ioctl_probe.c`；因 `_IOWR` 把 `sizeof(struct)` 编进 cmd 的 size 位，须扫 `nr × size(1..160) × dir`，共 3840 组，每组 `arg=NULL`）：

```
命中 7 条，全部 EPERM(1)：
 nr=1 INVOKE  0xc0105201 size=16   | nr=2 INIT   0xc0205202 size=32
 nr=3 MMAP    0xc0105203 size=16   | nr=4 MUNMAP 0xc0185204 size=24
 nr=7 SETMODE 0xc0205207 size=32 (主线为 4，本机已改)
 nr=8 GETPERF 0xc0045208 size=4    | nr=9 CTRLINIT 0xc0185209 size=24
ENOTTY（未实现）3833
```

`EPERM` 发生在 NULL 解引用之前，且同一 fd 上 `ioctl(fd,0)` 返回 `ENOTTY`（LSM 无法按 cmd 区别放行）⇒ **`EPERM` 来自驱动自身**（fd 模式位或能力检查）。

⇒ **双重封闭：写通道被 SELinux 拒；已实现 ioctl 在只读 fd 上被驱动以 `EPERM` 拒。不存在可行组合。**

---

### 5.5 其它已排除的 CVE

| CVE | 排除依据 |
|---|---|
| CVE-2023-33106（KGSL） | 靶点 `kgsl_ioctl_gpu_aux_command` 在 F.16 **不存在**（4.9 无此 ioctl，补丁目标 msm-4.19） |
| CVE-2022-22057（KGSL） | 靶点 `kgsl_timeline` **不存在** |
| CVE-2021-1905（KGSL） | 修复早于本机 SPL（≤2022-04） |
| CVE-2026-21385（KGSL） | `kgsl_memdesc_get_align` 在 123784 个符号中**不存在**，kgsl 下含 `align`/`get_align` 的符号数为 0 |
| CVE-2023-0266（ALSA） | 需 `/dev/snd`（`0660 audio`），shell 无 audio 组，SELinux 亦挡 |
| netfilter / `nf_tables` 类 | 需非特权 `USER_NS`，本机 `USER_NS=n` |

---

## 6. 负知识清单：已作废的结论（**必须遵守，否则会重走死路**）

保留"已作废 + 依据"比删掉更有价值。以下每条都曾是"确定"结论。

| 旧结论 | 现状 | 依据 |
|---|---|---|
| "镜像节区/函数顺序重排，kallsyms 未同步，无线性映射，加减 delta 无效"（v1 §11/§12/§13.1） | **作废** | 病因是解析器基址处理错误：旧工具定位 `kallsyms_offsets@0x13807e0`，`vmlinux-to-elf` 定位 `0x1380600` 且报告"偏移是绝对地址"。`vmlinux.elf` 的 `head.S` 反汇编自证 |
| "82% 符号落在函数序言 ⇒ 符号可用" | **作废（自证循环）** | `kallsyms_offsets` 本身就是函数地址表；重排保尺寸网格时旧地址仍会落在新序言上 |
| "`bl` 引用计数证明符号↔名字配对正确" | **作废** | 只证明地址有效；反例：`0xae290` 标 `rt_mutex_proxy_unlock` 实为 1504 B 大函数 |
| "racer 的 `MAP_USER_MEM` 会毒化 rbtree，进程退出时崩溃"（v1 §18.9） | **撤回** | `k3_poison_test`：单独执行返回 `ENOMEM`，rbtree 仍可插入，正常退出，设备存活 |
| "`OVERLAP mmap` 返回 `ENODEV` = 竞速命中" | **作废** | 4.9 的 `kgsl_mmap`/`get_unmapped_area` 结构上不返回 `ENODEV` |
| "`-EDEADLK` 是安全的状态 oracle"（v1 §19.10） | **作废** | 该 `-EDEADLK` 在目标锁无其它 waiter 时会销毁目标 `pi_state` |
| "判据 P：requeue 返回 1 ⇒ `pi_state` 已释放" | **作废** | `lookup_pi_state()` 在对象不存在时新建、`owner` 为 NULL ⇒ `try_to_take` 立即成功，返回 1 是伪影 |
| "窗口 ≤10 ms 即安全"（v1 §21.24） | **否证** | v6 在 0.05 ms 窗口下同样 panic；真正变量是**帧是否已死** |
| "`rtmutex.c:627` 无界 trylock 重试解释'不返回'" | **修正（补前提）** | trylock 无界重试本身成立，但必须先有"守卫退化"这一步：`next_lock` 与 `waiter->lock` 同源（`rtmutex.c:422`）⇒ `:579` 的 `next_lock != waiter->lock` 恒为假，任何被污染的 `lock` 都被接受。缺此前提时，若 `lock != next_lock` 本会在 `:579` 干净退出并返回 0 |
| "G-3b 的'不返回' = 槽被复用成普通垃圾" | **修正** | 槽内 `lock` 指向已 `kfree` 的 `rt_mutex`，`wait_lock` 读到释放后内存 |
| "GhostLock 卡在'缺 `kmalloc-128` 喷堆原语'"（v1 §22） | **理由作废** | 正确的问题是"能否用栈内缓冲区覆盖栈帧"，不是堆喷。结论（不可利用）不变，但原因改为"无栈覆盖载体" |
| "`PR_SET_MM_MAP`/`user_auxv` 是可用载体" | **本机不适用** | `CONFIG_CHECKPOINT_RESTORE` 未设置 ⇒ 直接 `-EINVAL` |
| "`TRYLOCK_PI` 可探 `rt_mutex.owner`" | **作废** | 只按 futex 字值查找，必然 `EAGAIN` |
| "`src_ref/futex_4.9/` 是 4.9 源码" | **作废** | 实为 ~v4.20；`rt_mutex_waiter` 72 vs 80、`rt_mutex_futex_unlock(lock, wake_q)` |
| "`rt_mutex` 应为 24 B"（v1 §20.1 初稿） | **自我更正** | 4.9 的 `struct rt_mutex` 本就带手工 `waiters_leftmost`，与 `rb_first_cached` 无关 ⇒ **32 B** |
| "`rt_mutex_get_effective_prio` 是 vendor 回填 DL 的证据" | **误判** | 该函数 4.9 主线本来就有 |
| "ion 可作喷堆" | **作废** | `0664`，shell 只有读权限 |

---

## 7. 何时应重开（可证伪条件）

出现或触发**任一条**即须重评；否则"再试一次同样的构造"不会改变结论。

1. 出现**面向 4.9 / arm64 ticket spinlock 的 UAF 原语**研究 ⇒ binder 线可直接接上（靶点、pre-fix 证据、堆条件已备，§5.3.2）。
2. 出现能把用户数据写到 **`[-0x288, -0x240)`** 的**新 syscall / 驱动 ioctl**（含内核升级带入的新入口）⇒ GhostLock 线可直接接上。
3. 设备 **SPL 或内核构建发生变化** ⇒ 帧几何、binder 形态、全部符号偏移同时改变，须整体重跑（**故建议关闭 OTA**）。
4. 取得 **pstore / dmesg / last_kmsg** 中任一个 ⇒ 可定位 GhostLock panic 的精确点，判断是否为 vendor 差异。
5. GhostLock 上游出现**非栈复用**的利用路线（例如改用 `sched_setattr` 之外的链遍历入口）。
6. binder 服务面（236 个服务，含 10+ OPPO 私有服务）出现**具体线索**（某个 `onTransact` 分支疑似缺权限校验）⇒ 走静态审计，不盲试 `service call`。**【2026-11-17 已执行，见 §14】** 结果：审计了 28/35 个私有服务，atlas 线索追到 native 反汇编后基本否证，未发现"无鉴权 + 命令注入"可达分支；该面判定从"未审计"更新为"已审计、no-go"。

---

## 8. 关键常数与判据（附录，供复核与复算）

### 8.1 结构体布局（v4.9 权威源，`DEBUG_RT_MUTEXES=n`）

| 结构 | 尺寸 | 关键字段 |
|---|---|---|
| `rt_mutex` | **32** (0x20) | `wait_lock=0x00`、`waiters=0x08`、`waiters_leftmost=0x10`、`owner=0x18` |
| `rt_mutex_waiter` | **72** (0x48) | `tree_entry=0x00`、`pi_tree_entry=0x18`、**`task=0x30`**、**`lock=0x38`**、**`prio=0x40`**（无 `deadline`） |
| `futex_pi_state` | **88** (0x58) | `list=0x00`、`pi_mutex=0x10`、`owner=0x30`、`refcount=0x38`、`key=0x40` |
| `futex_q` | **112** (0x70) | `list=0x00`、`task=0x28`、`lock_ptr=0x30`、`key=0x38`、`pi_state=0x50`、`rt_waiter=0x58`、`requeue_pi_key=0x60`、`bitset=0x68` |
| `hrtimer_sleeper` | **72** (0x48) | `timer=0x00`、`task=0x40` |

> 链走查真正读取的三个字段 `task`/`lock`/`prio` 在 72 B 与 80 B 两种 waiter 形态下偏移**完全相同**（`deadline` 只能追加在 `prio` 之后）⇒ 该不确定性不影响任何可操作结论。

### 8.2 `task_struct` 偏移（mainline-4.9 + 本机 config 推导，**须运行时锚定**）

| 字段 | 偏移 | 运行时锚点（相对 `comm`） |
|---|---|---|
| `real_cred` | `0x0728` | `comm - 0x10` |
| `cred` | `0x0730` | `comm - 0x8` |
| `comm` | `0x0738` | — （16 B 任务名，内容可识别） |
| `pi_waiters` | `0x0808` | `comm + 0xD0` |
| `pi_waiters_leftmost` | `0x0810` | `comm + 0xD8` |
| `pi_blocked_on` | `0x0818` | `comm + 0xE0` |

**置信度**：字段顺序/邻接为高置信（版本稳定）；绝对偏移为中置信 —— 推导尺寸 3456 比真实 slab 3840 小 384 B，且 `cred`（168→192）、`sighand_struct`（1552→2112）同向偏小，加之 config 有 90 条 `CONFIG_OPLUS_*`/`CONFIG_OPPO_*` ⇒ **本机是 vendor 改过的 4.9**。上机须用 `comm`/`pid`/`tgid` 锚点把偏移从"推导"升级为"实测"。

### 8.3 地址与窗口

| 项 | 值 |
|---|---|
| 静态链接基址 | `0xffffff8008080000`（由镜像内绝对指针反推：`0xffffff8009614c00 − base = 0x1594c00` = token_table 文件偏移） |
| runtime slide | 未知，须运行时泄露（KPTI 开启 ⇒ 走 linear map + `.data` 指针重指） |
| SVM64（可注册） | `[0x700000000, 0x800000000)` |
| GLOBAL（禁注册） | `[0x500000000, 0x600000000)` |
| compat（同样可注册） | `[0x300000, 0xBEF00000)` |
| `kernel_phys_load` | SM710 未知，候选 `0x80000000` / `0x40000000`；错值静默失败（不 panic），可逐个试 |

### 8.4 errno 语义（本机实测，极易误读）

| 返回值 | 真实含义 |
|---|---|
| `ENOMEM(12)`（`OVERLAP mmap` / SVM 注册） | 来自 **map 阶段的区间校验**，不是 `set_svm_region`；`munmap` 后 UAF 的 rbtree 条目仍占位 |
| `-EDEADLK(35)` | 走查命中 `rtmutex.c:642`（`lock == orig_lock` 或 `owner(lock) == top_task`）；**不等于"状态安全"**，见 §5.2.5 |
| `EINVAL(22)`（`FUTEX_WAKE` 于 PI futex） | 有已入队 PI waiter ⇒ 可用作零成本断言 |
| `EINVAL(22)`（`FUTEX_LOCK_PI`/`WAIT_REQUEUE_PI` 立即返回） | **大概率是用户态超时参数问题**：`tv_nsec` 未循环归一化，或 `FUTEX_LOCK_PI` 的时钟基准与 `WAIT_REQUEUE_PI` 不同（传 monotonic 绝对时刻会被判已过期） |
| `ETIMEDOUT(110)` | — |
| `ENOTTY(25)` | 命令号未被驱动实现，且**已穿过 LSM** |
| `EACCES(13)`（`open`） | SELinux 策略拒绝（不是 DAC 权限位） |
| `EPERM(1)`（ioctl） | 驱动自身在参数拷贝前拒绝（非 SELinux） |
| `ENOSYS(38)`（`msgget`） | `CONFIG_SYSVIPC` 未编译 |

### 8.5 已知的内核 futex 行为（本机实测）

- `futex_requeue()` 对 `requeue_pi` **强制 `nr_wake == 1`**，否则 `-EINVAL`。
- `do_futex()` 对 `FUTEX_WAIT_REQUEUE_PI` **强制 `val3 = FUTEX_BITSET_MATCH_ANY`**，用户传 0 不会触发 `if (!bitset) return -EINVAL`。
- 私有 futex 的 key = `{页基址, mm, 页内偏移}`，同页不同地址**不会**误判为同一 futex。
- `futex_wake()` 拒绝唤醒 requeue_pi waiter（源码字符串 `"refusing to wake PI futex"`）。
- `task_blocks_on_rt_mutex()` 在调用链走查**之前**就释放 `lock->wait_lock`（`rtmutex.c:1022-1024`）⇒ 不存在"走查自锁在原锁上"的隐忧。

---

## 9. 资产索引

| 类别 | 位置 |
|---|---|
| **符号物料** | `firmware_F16/vmlinux.elf`（唯一反汇编物料，`file = 0x240 + (va - base)`） |
| 固件物料 | `firmware_F16/`：`boot.img`、`kernel.decompressed`、`kallsyms_out.txt`（123784 符号，仅查名字）、`kernel_appended.dtb` |
| 权威源码 | `src_ref/kernel_49_mainline/`（v4.9 tag 的 `rtmutex.c`/`futex.c`/`include_linux_rtmutex.h`/`rtmutex_common.h`，含 `README.md` 行号索引） |
| 补丁与 PoC | `src_ref/lineage_388401.patch`（KGSL 修复）、`src_ref/ghostlock_fix.patch`、`src_ref/poc_ex.c`、`src_ref/projectzero_33107_rca.md` |
| 同源驱动源码 | `src_ref/realmeX_master_io-pgtable-arm.c`、`src_ref/kgsl_4.9/` |
| ⚠️ 降级 | `src_ref/futex_4.9/`（~v4.20，仅作新版形态对照，**不得引用行号/尺寸**） |
| 设备证据 | `artifacts_adb/k3_info*.txt`、`k3_kernel_config.txt`、`attack_surface.md`、`surface_probe_output.txt` |
| 实验日志 | `artifacts_adb/g_logs/`：`g1.log`、`g2c.log`、`g3.log`、`g3c_run{1,3,4,5_12c,6_probe}.log`、`g3c_v6_run1.log`、`g3c_v7_run1_run2.log`、`g3d_*.log`、`frpc_probe.log` |
| 分析工具 | `tools/gl_frame_calc.py`（帧几何）、`tools/gl_carrier_scan.py`（载体扫描）、`tools/f16_rtmux_49_layout.py`（4.9 布局）、`tools/f16_layout_v2.py`（`task_struct` 布局引擎）、`tools/pdf_text.py`、`tools/par_dl.py`（多连接分段下载） |
| 实验程序 | `tools/g1_edeadlk.c` → `tools/g3c_v7.c`（三锁环 + 三段式 C1 + A′ 活帧对照）、`tools/g3d_*.c`、`tools/k3_*.c`、`tools/surface_probe.c`、`tools/frpc_ioctl_probe.c` |
| 工具链 | `.build/zig-windows-x86_64-0.13.0/`（79 MB，本地，不入库）、`scrcpy-win64-v3.3.4/adb.exe` |

**复现帧几何与载体扫描**

```bash
python tools/gl_frame_calc.py        # 依赖 pyelftools + capstone（用 python -m pip 安装）
python tools/gl_carrier_scan.py      # 397 个 syscall 入口，判据 d-buf ∈ [0x288, 0x2BE]
python tools/f16_rtmux_49_layout.py  # 4.9 结构体布局（离线可复跑）
```

---

## 10. 方法论（比结论更耐用）

1. **补丁形态比对优于反汇编猜寄存器**。用修复 commit 的语义演变定位 pre/post-fix：`off_end` 三元式判定 20938、`cleanup` 调用位置判定 20421，两次都在 1–2 小时内给出定论。
2. **零风险探针优先于任何"动手"**。`open()` 判权限、`ioctl(fd,0)` 判 LSM 闸门、`FUTEX_WAKE` 返回值判 PI waiter 是否入队 —— 共同点：**用一个 syscall 的返回值替代一次设备重启**。
3. **闸门必须量化且可被否证**。`[0x288, 0x2BE]`、`off_end` 三元式、spinlock 指令序列、`EPERM` 实测 —— 都能被数据推翻，而不是靠"感觉不对"。
4. **任何"窗口"都要用至少三组不同量级的数据交叉验证**。本项目两次把"看起来相关的时间间隔"当窗口（W2、W1），均被新对照组推翻；最终结论是"窗口根本不是变量"。
5. **不可利用性判定写成五段式**：可达 → 悬垂 → 可控改写 → 复填 → 任意写，逐段给证据与缺口。"试到崩"只能证明某条路径不通，五段式才能说清**为什么**不通、**缺哪一块**。
6. **旧结论必须现场作废**。本项目已作废 17 条曾"确定"的结论（§6）。文档保留"已作废 + 依据"比删掉更有价值 —— 否则下一轮会重走同一条死路。
7. **不要用构建日期推断代码版本**。本机 2025-03 构建，binder 仍是 2018 年语义。
8. **会触发内核缺陷的程序必须每步落盘**（`write(2)` + `fsync`），且成功路径也要输出 —— 否则崩溃点不可判定。

---

## 11. 设备终态与运营约定

| 项 | 状态 |
|---|---|
| 系统 | `PCGM00_11_F.16` 未变；未刷写、未解锁、未改分区、未 root |
| 最近一轮操作 | 全部只读（`ls -lZ`、`cat /proc/self/status`、`service list`、`open()` 探测）；未推送任何二进制 |
| `/data/local/tmp` | 空（清理后未再写入；日志已全部拉回 `artifacts_adb/dev_tmp_backup/` 与 `g_logs/`，16/16 齐全） |
| 内核重启 | 累计 **5 次**（run1 / run3 / run4 / D2 / v6，均为前期竞态实验），此后 0 次 |
| 建议 | **关闭系统 OTA**（§7 第 3 条） |

**运营约定（继续本项目时沿用）**

1. 每重启一次设备，先把交接文档补完再继续实验。
2. 单次会话重启上限 3 次（前期）→ 后期收紧为 2 次；触及即停机复盘。
3. 任何会解引用悬垂指针的新实验，**先登记判据再运行**，判据不得事后修改。
4. 实验前确认用户人在设备旁（部分失败形态只能长按电源键恢复）。

---

## 12. 轮次索引（v1 的 13 轮，一行一轮）

| 轮 | 主题 | 净结果 |
|---|---|---|
| 1–4 | 固件取证、符号恢复、KGSL 判定 | F.16 基线确立；CVE-2023-33107 判定 pre-fix（源码级），反汇编双确认当时挂起 |
| 5 | KGSL 4.9 适配 | UAPI 全兼容（7 ioctl + 8 结构体）；缺口全在运行时标定 |
| 6 | GhostLock 静态适配 | 源码级 pre-fix 确证；4 个结构体偏移推导 |
| 7 | vmlinux 路径核查 | 负结果；下调"符号配对"置信度 |
| 8 | `task_struct` 布局自动推导 | 给出偏移表 + slab 校准，结论是本机为 vendor 改过的 4.9 |
| 9 | **首次连机** | Zig 交叉编译打通；KGSL 阶段 A/B 通过；阶段 C 进入即崩 → 定位 `BUG_ON` → **KGSL 判死**；转 GhostLock，`-EDEADLK` 4/4，确认栈 UAF |
| 10 | 4.9 源码保真性修正 | `rt_mutex_waiter` 80→72；G-3b 挂起根因定为"退化守卫 + 无界 trylock"；设计三段式 C1 |
| 11 | C1 首次上机 | `[5]`/`[10]` 均 `-EDEADLK`（换向写入成立）；`[12]` 崩溃 3/3；`-EDEADLK` 会销毁 `pi_state` 的模型被提出 |
| 12 | 窗口量化 + 亚毫秒版 | 证明窗口不是变量（0.05 ms 仍 panic）；提出 W1/W2 → 随即被自身探针否证 |
| 13 | 探针判定 + A′ 活帧对照 | **A′ 证明"换向 + 走查"形态成立，panic 只由"帧已死"引起**；载体扫描 397 入口 0 命中 → GhostLock 收束 |
| — | 补丁窗口扫描 + binder | 20938 未引入；20421 pre-fix 但 ticket 锁无原语；FastRPC 双重封闭 |

---

## 13. 一句话交接

> 五个候选面、13 轮工作，缺陷与触发多次被证实是真的；**每一面都停在一个可命名的缺口上**——
> KGSL 停在 `BUG_ON`（进入即 panic，没有中间态），GhostLock 停在"54 字节的栈覆盖窗口在本机构建下不存在"，
> binder 停在"ticket spinlock 只给 +0x00010001"，FastRPC 停在"驱动对只读 fd 一律 `EPERM`"。
> 这不是"没试够"，是本机权限模型与代码形态共同决定的 no-go。
> 若将来要重开，**不要重复同样的构造**，只看 §7 的六条触发条件。

---

## 14. 增补：Binder 服务面审计（2026-11-17，§7 第 6 条触发）

> 本节执行并闭合了 §4 标注的"唯一未闭合未知面"。完整过程、字节码证据与五轮报告见
> `artifacts_adb/binder_audit/AUDIT_REPORT.md`（脚本与文本报告入库；**厂商 jar/apk/so/dex/系统镜像不入库**，
> 读者从自己设备 `adb pull` 或 OTA 重建后用同目录脚本本地重跑）。

**触发**：`docs_archive/审核意见CHATGPT.txt` 主张把"OPPO 私有 Binder 服务审计"提升 P0，
以 CVE-2026-70386（OnePlus atlasservice 未授权 → root 命令执行）等为历史证据。
外部核验：审核意见引用的 5 个 CVE **全部属实**，但均为跨设备/跨版本案例，无一直接指向 K3。

### 14.1 结论

**Binder 服务面亦判定 no-go；§7 第 6 条从"未执行"变为"已执行且未命中"。** 项目维持整体结项。

| 轮 | 动作 | 结果 |
|---|---|---|
| 1 | 从设备只读拉 9 个 jar（`adb pull`，`/system/framework` 全可读） | 接口覆盖仅 **2/35**，材料不足 |
| 2 | 补拉 `framework.jar`/`services.jar`/atlas apk + 多 dex | 覆盖升至 **28/35**；发现 atlasservice 结构同构线索 |
| 3 | avc oracle 验证可达性（只读 `dumpsys` 探针） | **shell → root atlasservice binder 可达** |
| 4 | 对可读 `libatlasservice.so` 做符号级反汇编 | **命令注入模式否证** |
| 5 | 纯静态从 OTA 解出 root 二进制（直连 Range 取 2.55 GiB → 重建 system.img → 7-Zip 提取） | root 二进制为薄壳、加载 so 与第四轮字节一致；**证据链 5/5 闭合，线索确定否证** |

### 14.2 决定性证据链：atlasservice 从发现到否证

本机结构与 CVE-2026-70386 四环同构，但第五环（注入）经反汇编否定：

| 环节 | CVE-2026-70386 | K3 F.16 实测 | 判定 |
|---|---|---|---|
| 入口 | `atlasservice.setEvent(String8,String8)` | `IOppoMMAtlasService`/`IOppoAtlasService` 的 `setEvent(int,String)`，方法集一致 | 同族 |
| 鉴权 | 缺失 | `Stub.onTransact` 仅 `enforceInterface`，0 处 `getCallingUid` | 同样缺失 |
| 可达性 | 任意本地应用 | avc `denied { use } pipe, scontext=u:r:atlasservice:s0 ← u:r:shell:s0` 证明调用到达 root 域 | 可达 |
| root 服务 | `audiodumpinfo`, `u:r:dumpstate:s0` | `atlasservice`, `user root`, `u:r:atlasservice:s0`, init rc | 存在 |
| **命令注入** | `system(未转义参数)` | `system()` 确实 3 处，但模板硬编码 `dmesg > %s%s%s` / `chmod 0777 %s`；value 只进路径构造与 `kill` pid | **本质差异，否证** |

反汇编还原的调用链：`setEvent(int,String8)` → `OplusAtlasLogWriter::caputureLogs` →
`OplusAtlasLogThread::threadLoop` → `doLogCaputure`/`checkPath` → `system()`（命令模板在 rodata 硬编码）。

**第五轮闭合**：解出的 root 二进制 `system_ext/bin/atlasservice`（11608 B，ELF64，SHA256 `c7807798…`）
是薄壳——65 个字符串、无 `system`/`popen`，`main()` 仅 `AtlasService()` → `addService("AtlasService")` →
binder 线程池；其加载的 `lib64/libatlasservice.so` 与第四轮所反汇编的设备拉取版 SHA256 一致
（`b65dde22…`）。故 root 侧无第二处注入逻辑，**第五环由"存疑"升级为"确定否证"**。

### 14.3 方法论产出（复用价值）

1. **AIDL/HIDL `Stub.onTransact` 的 `enforceInterface` 不是鉴权**。28 个服务里 27 个 perm_calls=0 是结构正常现象，
   唯一例外 `IOplusCustomizeService` 才在 Stub 层 `checkPermission()`。鉴权在服务实现方法或 SELinux 层，
   不可据 Stub 无鉴权就判漏洞——与 §10 的"补丁形态比对优于猜寄存器"同类教训。
2. **avc oracle 测可达性**：只读 `dumpsys <service>`（DUMP_TRANSACTION 固定事务号，非业务事务）
   前后的 avc 增量可判断 shell 能否触达某服务，对照组 `dumpsys commondcs` → "Can't find service"。零副作用。
3. **工具可用性必须先自证**（§10 新增强调）：本机 Git Bash 无 `strings` 命令，
   其"返回空"曾被误读为"so 无 system() 字符串"，改用 Python 正则后结论反转。**已作为负知识登记。**
4. **OTA 分区重建（第五轮，纯静态）**：`transfer.list` v4 逗号分隔为**范围编码**（覆盖度自检
   uncovered=0/overlap=0）；`new.dat` 是**固定 4096B 块原始流、无长度前缀**
   （`len(new.dat)==Σ(e−s)×4096`，diff=0）。此前按"4B 长度+数据"解析在块 256 失败。脚本见
   `tools/dl_range.py`/`sdat2img.py`/`rebuild_system.py`/`elf_analyze.py`。大文件下载**直连不走代理**。

### 14.4 覆盖度缺口与不重开判据

- 35 个私有服务覆盖 28 个；7 个 MISSING（`IAntiRootDialog`/`IHephaestus`/`IHoraeService`/`IOIfaceService`/
  `IHansComunication`/`IOppoAppDataService`/`OplusResourceManagerService`）实现在独立 apk/服务，未纳入。
  **但最高价值的 atlas 线索已 5/5 闭合，7 个未覆盖项无 CVE 类比指向，不单独重开。**
- ~~唯一还能改变结论的动作：解出 root 二进制~~ **已完成（第五轮），确定否证**；**无剩余可改变结论的动作**。
- **路径 B（受控 setEvent 探针）不建议**：净执行 0.5–1 h，但命令模板硬编码、无输出 oracle
  （dmesg/kmsg/pstore 全不可读），且违反 §7"不盲试事务号"约定；成本不是时间，是无效性。
- 全程只读：未推送二进制到设备、未调用业务事务号、未改分区；大文件下载直连不走代理；设备终态同 §11。
