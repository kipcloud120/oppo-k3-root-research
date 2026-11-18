# OPPO K3「临时 ROOT」项目 · 交接文档

| 项 | 值 |
|---|---|
| 版本 | **v2.12**，2026-11-18；v2 重写替代 v1 的 13 轮增补式长文。§14 = Binder 五轮审计，§5.2 + §15 = GhostLock 复核与静态收束，§16 = Wi-Fi 私有事务面（含 §16.11 **误判撤回**），§17 = 接手清单。**v2.8=§18 P0 静态定性；v2.9=§19 P2 六服务；v2.10=§20 外部复评重开 myftm；v2.11=§21 执行复评的新 P0/新 P1：Java/HIDL 传输无过滤确认 + myftm 本体逆向；v2.12=§22 同族九类命令全映射 + **regex 黑名单缺口（缺 `\n`/反引号/`<`/`>`）** + 更正 iwpriv 分支无整数转换 + 三接口不可达否证**。下次会话**从 §17 开始**，再按需查 §22 / §20 / §18 / §16 / §15 / §14 |
| 状态 | **整体 no-go（未翻转）。** 四个内核面判定不可达；GhostLock 载体已闭合、缺内核地址泄露。Wi-Fi 私有事务面：从 shell 可调、入参被 uid 0 服务接收，历史注入串（均 `myft ` 空格前缀）被 `INVAILD_PARAMETER` 拒绝，未回显 uid=0（§16.11）。**§20 复评更正：`-3` 归因仅适用于 iwpriv 分支；myftm 分支（前缀 5 字节）实为 `/vendor/bin/myftm <原始尾串>` 裸拼进 `sh -c`，无引号/转义/过滤，shell 元字符可被解析 ⇒ 静态注入面开放、Wi-Fi P0 重开、待用户授权上机验证 L3。§22 进一步更正：iwpriv 分支同样是 `裸拼整条入参`，且黑名单只覆盖 11 个字符、缺 `\n`/反引号/`<`/`>` ⇒ 注入面不依赖 myftm 前缀。v2.9"非任意命令执行"断言已撤销** |
| 原件 | `docs_archive/HANDOVER_v1_2026-11-17_full.md`（v1 全文 3368 行，含全部过程推理，**仅备查**） |
| 唯一入口 | 本文件。数值以本文件为准；v1 与 `docs_archive/` 的其余文档一律视为历史证据，不得引用其数值 |
| 设备终态 | `PCGM00_11_F.16` 未变；**未刷写、未解锁、未改分区、未 root**；`/data/local/tmp` 为空（§16 的实验探针已清理）；shell `id` 仍为 uid 2000；崩溃的 HAL 已自动重启。累计 5 次内核重启（均在前期竞态实验期） |
| Binder 面审计 | `artifacts_adb/binder_audit/AUDIT_REPORT.md`（五轮：atlas 线索 5/5 闭合、确定否证）；**厂商二进制与系统镜像不入库** |
| GhostLock 复核 | `artifacts_adb/binder_audit/GHOSTLOCK_RESCAN.md`（扫描器判重 bug 证实；3 条 xattr 栈覆盖候选）→ **`GHOSTLOCK_NUL_ANALYSIS.md`（剩余两项的静态收束：栈复用为几何确定性；NUL 不阻断；缺口 = 内核地址知识）** |

---

## 0. 阅读指引

按目的选路径，不必通读：

| 目的 | 读 |
|---|---|
| 只要结论 | §1 |
| 接手继续做 | §1 → §2（基线）→ §5（逐面）→ §7（重开条件）→ §8（关键常数） |
| 复核某个判断 | §5 对应小节 + §6 负知识清单 + `artifacts_adb/` 原始日志 |
| 只想避坑 | §6 负知识清单 + §10 方法论 |
| GhostLock 现状（唯一活面）| **§15**（剩余两项的静态收束）→ §5.2.4 更正块 → §7 第 2 条 |
| Binder 服务面 | §14（五轮审计：28/35 覆盖、atlas 线索 5/5 闭合否证）+ §19（P2 补审 6/7：hephaestus system 面被 uid==1000 门禁挡住；**antirootdialog 未完成，复评升为新 P1**）|
| Wi-Fi 私有事务面（当前主线索）| **§22 → §20 → §18 → §16.11**（v2.12：九类 HIDL 命令全映射；黑名单缺 `\n`/反引号/`<`/`>` ⇒ iwpriv 分支亦可穿越；`sendSupplicantCommand`/`runWiFiScript` 无 Java 调用方 ⇒ 不可达；L3 仍待授权）|

**三条硬规则**

1. **反汇编只用 `firmware_F16/vmlinux.elf`**。`kallsyms_out.txt` 只用于查名字，其偏移在 futex/binder 区偏差 0x6–0x9 万字节。
2. **不要用构建日期推断代码版本**。本机 2025-03 构建，binder 却仍是 2018 年的语义（§5.3）。
3. **每重启一次设备，先补完文档再继续实验**（用户约定，全程遵守）。

---

## 1. 结论页

### 1.1 目标与判定

**目标**：在不解 BL 的前提下取得 OPPO K3 的**临时 ROOT**（运行时 uid=0，重启即失）。官方"深度测试"/持久 root 出口（A 线）已按用户决定移除。

**判定**：在设备现状下，**四个候选面（KGSL / binder×2 / FastRPC）判定不可达**；**GhostLock 面机制与载体均已成立，但阻断在"无内核地址泄露"**。每一面都定位到"卡在哪一环、缺什么能力"——不是"跑崩了"。

### 1.2 逐面结论

| 面 | 机制是否成立 | 卡点 | 章节 |
|---|---|---|---|
| **KGSL** CVE-2023-33107 | 成立（源码级 pre-fix 确定） | `arm_lpae_init_pte()` 的 `BUG_ON(!suppress_map_failures)`，该静态变量运行期恒 false ⇒ 进入缺陷路径即 `BUG()` panic，无中间状态可用 | §5.1 |
| **GhostLock** CVE-2026-43499 | 成立（`-EDEADLK` 10+ 次确定性复现）| **【2026-11-17 二次更正】载体侧已闭合**：修正扫描器判重 bug 后发现 3 条 xattr 栈覆盖候选；进一步静态判定"栈槽复用"是几何确定性、NUL 截断不阻断，但 fake waiter 的 `lock`/rb 链接必须为**非零内核地址** ⇒ 阻断点变为**无信息泄露**（§5.2.4 + §15） | §5.2 / §15 |
| **binder** CVE-2023-20938 | **不成立**（漏洞未引入） | `off_end_offset` 形态处于 `44d8047f1d87 … 32e9f56a96d8` 之间，`is_failure=1 且 failed_at=0` 时循环 0 次 | §5.3 |
| **binder** CVE-2022-20421 | 成立（pre-fix 形态确证） | 本机为 **ticket spinlock**，公开技术依赖 qspinlock；本机原语退化为"对两半相等的 4 字节字加 `0x00010001`"，并带 `wfe` 死等风险 | §5.3 |
| **FastRPC** CVE-2023-33063 | 面存在 | 对 shell **双重封闭**：`O_RDWR` 被 SELinux `EACCES`；只读 fd 上 7 个已实现 ioctl 全 `EPERM` | §5.4 |
| **OPPO Wi-Fi 私有事务**（非内核面）| tx10069/10070 从 shell 可达，字符串被 uid 0 服务接收 | **regex 黑名单只覆盖 11 字符（缺 `\n`/反引号/`<`/`>`），且 myftm 分支完全无过滤 ⇒ shell 可达分支存在可绕过的注入面；L3（`uid=0` 回显）未证**（§22 / §20 / §16.11） | §22 / §20 / §16.11 |

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
| binder 服务 | **236 个**（229 个可 `dumpsys`），含 10+ 个 OPPO/ColorOS 私有服务与已开启的工程模式 —— 本文件 v2 时"从未审计、唯一未闭合的未知面"；**已于 2026-11-17 审计，见 §14：35 个私有服务覆盖 28 个，atlas 线索 5/5 闭合否证；7 项未覆盖，不宣称穷尽（§14.4）** |

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

### 5.2 GhostLock CVE-2026-43499 —— 机制成立；载体已闭合，缺口为「无地址泄露」（原标题「无栈覆盖载体」已作废，见 5.2.4 末更正块与 §15）

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

#### 5.2.4 卡点（历史结论：无栈覆盖载体）—— **已作废**，见本小节末两条更正块

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

> ⚠️ **2026-11-17 更正：上述"无栈覆盖载体/不可利用"判定作废（依据见 `artifacts_adb/binder_audit/GHOSTLOCK_RESCAN.md`）。**
> 审核意见指出 `gl_carrier_scan.py` 的 `seen` 以函数名为唯一键全局共享，丢失不同调用路径的累计栈帧上下文。
> 复核证实：原口径跳过 18,691 次中 **18,074 次是不同累计帧上下文**；且 `COPY_PREFIX` 遗漏
> `strncpy_from_user` 等原语。修正后从"0 命中"变为 **3 条满足几何判据的栈覆盖候选**：
> `SyS_fgetxattr→getxattr`（d-buf=0x298, size=256, waiter 起点偏移 0x10）、
> `SyS_getxattr→getxattr`（0x2c8）、`SyS_setxattr→setxattr`（0x2e8）——均经
> `add x0,sp,#8; mov w2,#0x100; bl strncpy_from_user` 把用户串写到栈上。
> **判定更新：从"不可利用(no-go)"降级为"公开 select/pselect 路线不成立，但 xattr 栈覆盖候选已找到、
> 可利用性待验证"**。原 4 项待验证中 **2 项已静态排除**：内核局部量覆写（getxattr copy 点后无 store）、
> 深度>3（扩到 4 无新机制）。**仅剩 2 项需受控上机**：栈重生时机（W 超时早退后是否复用同一栈槽进入
> xattr）、NUL 截断能否构造合法 fake waiter。详见 `GHOSTLOCK_RESCAN.md` §4（接手必读）。
> **"397/0/66"不再是穷尽证明；原版脚本保留为历史基线，修正版为 `tools/gl_carrier_rescan.py`。**
>
> ⚠️ **2026-11-17 二次更正（载体侧闭合，见 §15）：** 剩余 2 项已在纯静态层面收束，**不再需要上机验证**：
> ① **栈重生不是"时机"问题而是几何问题**——同线程、每次异常入口 sp 复位到栈顶、`SyS_fgetxattr→getxattr`
> 全路径无 VLA／帧长定长 ⇒ 复用由构造保证；
> ② **NUL 截断不构成阻断**——`strncpy_from_user` 无 arm64 asm 变体（走 C 实现），终止 NUL 落在 `prio`
> 第 2 字节时 `zero_bytemask` 自动把上位 3 字节置 0（`prio∈[1,255]` 全部合法），但要求 **81/129/161 字节
> 连续非零**（三条路径各自），且"少写一点靠残余补齐"不成立（NUL 恰好清零下一字段首字节）。
> ⇒ **新阻断点**：`lock` 与 rb 链接必须取非零内核地址，而"干净"取值要么含 `0x00`、要么需 `RB_EMPTY_NODE`
> 自引用（= 栈地址）。两者都要求**内核地址知识**，本机无泄露通道。判定由"待验证"改为
> **"载体成立、缺信息泄露"**，面维持 no-go。

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

## 6. 负知识清单：23 条已作废的结论（**必须遵守，否则会重走死路**）

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
| "GhostLock 卡在'缺 `kmalloc-128` 喷堆原语'"（v1 §22） | **理由作废** | 正确的问题是"能否用栈内缓冲区覆盖栈帧"，不是堆喷 |
| "GhostLock 无栈覆盖载体、397 入口全扫 0 命中"（v2 §5.2.4） | **2026-11-17 作废** | 扫描器 `seen` 函数名判重漏报 18,074 个不同上下文 + `COPY_PREFIX` 漏 `strncpy_from_user`。修正后发现 3 条 xattr 栈覆盖候选。详见 `GHOSTLOCK_RESCAN.md` |
| "`PR_SET_MM_MAP`/`user_auxv` 是可用载体" | **本机不适用** | `CONFIG_CHECKPOINT_RESTORE` 未设置 ⇒ 直接 `-EINVAL` |
| "`TRYLOCK_PI` 可探 `rt_mutex.owner`" | **作废** | 只按 futex 字值查找，必然 `EAGAIN` |
| "`src_ref/futex_4.9/` 是 4.9 源码" | **作废** | 实为 ~v4.20；`rt_mutex_waiter` 72 vs 80、`rt_mutex_futex_unlock(lock, wake_q)` |
| "`rt_mutex` 应为 24 B"（v1 §20.1 初稿） | **自我更正** | 4.9 的 `struct rt_mutex` 本就带手工 `waiters_leftmost`，与 `rb_first_cached` 无关 ⇒ **32 B** |
| "`rt_mutex_get_effective_prio` 是 vendor 回填 DL 的证据" | **误判** | 该函数 4.9 主线本来就有 |
| "ion 可作喷堆" | **作废** | `0664`，shell 只有读权限 |
| "没有 `Permission Denial` ⇒ 拒绝不在授权层"（Wi-Fi 面中途判断，§16.5） | **作废** | 11 次探测全部得到 `Binder invocation to an incorrect interface`，但对照实验证明工具与通路正常、拒绝发生在服务端；厂商可以用 `enforceInterface` 的报文掩盖 uid 门禁 ⇒ **报文类型不能反推门禁类型** |
| "Wi-Fi 私有事务只差一次正确调用"（同上） | **作废** | 穷尽所有可获得的描述符组合（单令牌 4 种 / 双令牌 4 种排列 / 无参）后仍全部失败；外层分派所在的 `com.android.server.wifi` 实现类不在任何已解出 jar 中 |
| "`executeDriverCommand` 前缀判据是 4 字节 `myft`，历史注入串进了 myftm 分支"（§7.7 / §16.11，2026-11-18 P0 前） | **更正** | native `0x9a38/0x9a4c` 还比较第 5 字节 `'m'`，真实前缀是 5 字节 `myftm`；历史 4 个注入串全是 `myft `（空格），走的是 iwpriv 分支。见 §18.3 |
| "`-3 INVAILD_PARAMETER` 的码表在 Java 层 `onValues`" | **更正** | `uD6hk53bOimZNTzE924fVOYf3t8.onValues` 是 3 指令 lambda 壳，无码表；`-3` 在 native `0x9ddc` 写入，根因是 regex 黑名单。见 §18.2 |
| "myftm 分支参数无法跳出固定 token、不是任意命令执行，不建议上机"（§18.4/§18.5，v2.8–v2.9） | **撤销（外部复评指出）** | 混淆了 shell 参数分隔与**控制操作符**：`;` `|` `&&` `$()` 不依赖空格即被 `sh -c` 解析。逐指令重建确认 cmd=`/vendor/bin/myftm `+input[5:]，无引号/转义/过滤 ⇒ 注入面静态开放，Wi-Fi P0 重开。见 §20 |

---

## 7. 何时应重开（可证伪条件）

出现或触发**任一条**即须重评；否则"再试一次同样的构造"不会改变结论。

1. 出现**面向 4.9 / arm64 ticket spinlock 的 UAF 原语**研究 ⇒ binder 线可直接接上（靶点、pre-fix 证据、堆条件已备，§5.3.2）。
2. **【2026-11-17 二次更新：已不是"等载体"，而是"等泄露"】** 出现下列任一条，GhostLock 立刻重开：
   (a) **任一可用的内核地址泄露**（`/proc` 侧信道、binder/驱动泄露、侧信道皆可）⇒ fake waiter 的 `lock`
   与 rb 链接才有可填的值（§15 §6）；
   (b) 出现**不经 NUL 语义**、能把用户数据写到 `[-0x288, -0x240)` 的载体（如某条路径让 xattr 的 **value**
   经 `__arch_copy_from_user` 落在 waiter 槽，而非 `kname` 经 `strncpy_from_user`）⇒ NUL 约束整体消失；
   (c) 出现**非栈复用**的利用路线（见第 5 条）。
   ~~旧条件：xattr 栈覆盖候选的"栈重生 + NUL 构造"两项上机验证~~ **已静态收束（§15）**：
   栈复用是几何确定性、NUL 不阻断、payload 长度 84/132/168 B 全部合规；且这两项**在无泄露前提下
   不具可证伪性**（xattr 返回值不暴露栈内容；无地址只能猜测地址 ⇒ 必然 panic 而 panic 文本不可读）。
   **接手步骤：不要再上机重跑同类构造；静态侧无需再扫描。**
3. 设备 **SPL 或内核构建发生变化** ⇒ 帧几何、binder 形态、全部符号偏移同时改变，须整体重跑（**故建议关闭 OTA**）。
4. 取得 **pstore / dmesg / last_kmsg** 中任一个 ⇒ 可定位 GhostLock panic 的精确点，判断是否为 vendor 差异。
5. GhostLock 上游出现**非栈复用**的利用路线（例如改用 `sched_setattr` 之外的链遍历入口）。
6. **Wi-Fi 私有事务面**：从 shell 可达已证（真客户端 `app_process`，§16.9），但注入被参数校验拒绝。
   重开条件：**先静态确定 `-3 INVAILD_PARAMETER` 的来源与合法命令格式表**（§16.11 / §17 P0）。
   ⚠️ **不要再猜令牌、不要再用 `service call` 试**（16 次证明是工具 ABI 问题，非授权）；
   **也不要再用元字符试注入**（全部失败且导致 HAL 崩溃）。
7. binder 服务面（236 个服务，含 10+ OPPO 私有服务）出现**具体线索**（某个 `onTransact` 分支疑似缺权限校验）⇒ 走静态审计，不盲试 `service call`。**【2026-11-17 已执行，见 §14】** 结果：审计了 28/35 个私有服务，atlas 线索追到 native 反汇编后基本否证，未发现"无鉴权 + 命令注入"可达分支；该面判定从"未审计"更新为"已审计、no-go"。

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
6. **旧结论必须现场作废**。本项目已作废 23 条曾"确定"的结论（§6）。文档保留"已作废 + 依据"比删掉更有价值 —— 否则下一轮会重走同一条死路。
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
| 13 | 探针判定 + A′ 活帧对照 | **A′ 证明"换向 + 走查"形态成立，panic 只由"帧已死"引起**；载体扫描 397 入口 0 命中 → GhostLock 收束【**2026-11-17 更正：该 0 命中因扫描器判重 bug 漏报而作废，见 §5.2.4 更正块**】 |
| — | 补丁窗口扫描 + binder | 20938 未引入；20421 pre-fix 但 ticket 锁无原语；FastRPC 双重封闭 |
| 14 | Binder 私有服务审计（五轮） | 覆盖 2/35 → 28/35；atlas 结构与 CVE-2026-70386 同构，但命令模板硬编码 ⇒ **线索 5/5 闭合否证**；7 项未闭合（§14） |
| 15 | 审核意见 v001 响应（静态） | 判重 bug 复核 → 3 条 xattr 候选；**栈复用=几何确定性、NUL 不阻断 ⇒ 缺口改为"无地址泄露"**（§15） |
| 16 | Wi-Fi 私有事务面追溯（设备在环） | OTA → vendor.img → **内嵌 `euclid/odm.img`** 解出 `@1.1-service`；rc 为 `user root`；真客户端证明 shell 可达、无 uid 门禁；**但注入全被 `INVAILD_PARAMETER` 拒绝，"实锤"已撤回**（§16.11） |
| 17 | 误判撤回（用户指出） | 两次过度声称（"shell 不可达"→"结论翻转"→"临时 ROOT 实锤"）均撤回；根因：把参数回显当执行证据、把参数拒绝当 SELinux 问题（§16.11） |

---

## 13. 一句话交接

> 五个候选面、16 轮工作，缺陷与触发多次被证实是真的；KGSL 停在 `BUG_ON`（进入即 panic，没有中间态），
> binder 内核 CVE 停在"ticket spinlock 只给 `+0x00010001`"，FastRPC 停在"驱动对只读 fd 一律 `EPERM`"——
> 这三面是本机权限模型与代码形态共同决定的 no-go。Binder 服务面（§14）：atlas 线索 5/5 闭合否证，
> **7 个未覆盖服务仍是开口，不宣称穷尽**。
> **Wi-Fi 私有事务面（§16）是最曲折的一条：三次结论、两次撤回。** 最终状态：shell（uid 2000）
> 可调用私有事务、`executeDriverCommand` 的入参被 uid 0 服务接收——**但所有注入均被 `INVAILD_PARAMETER`
> 拒绝，未回显 `uid=0`**。此前"入口在 shell 之外"与"已获临时 ROOT"均为误判，已撤回（§16.11）。
> 它是"有 root 权限的私有命令接口"，不是"已证明的提权路径"。
> ⚠️ **GhostLock 的判定在 2026-11-17 经过两次更正，现在是终态（§15）**：第一次更正推翻了"全扫 0 命中"
> （扫描器判重 bug 漏报 18,074 个不同栈上下文），找到 3 条 xattr 栈覆盖候选；第二次更正在纯静态层面
> 判定"栈槽复用"是几何确定性、NUL 截断不阻断，**缺口因此从"载体/时机"换成"缺一次内核地址泄露"**。
> 结论仍是 no-go，但理由完全换过了：**不是"没找到能把数据写进去的办法"，而是"数据能写进去，但不知道往哪写"**。
> 若继续，不要重复同类构造，只看 §7 第 2 条的两类触发条件。
> **Wi-Fi 面：`-3` = iwpriv 分支 regex 黑名单；myftm 分支前缀 5 字节（历史串全是 `myft ` 从未进该分支）。
> v2.10 外部复评（§20）撤销了 v2.9"myftm 非任意命令执行"的断言：逐指令证实 cmd=`/vendor/bin/myftm `+input[5:]
> 无引号/转义/过滤，`sh -c` 会解析 `;` `|` `$()` ⇒ **myftm 注入面静态开放、Wi-Fi P0 重开、待授权验证 L3**。
> P2（§19）六服务否证仍成立（hephaestus uid==1000 门禁挡 shell），第七个 antirootdialog 未完成。
> 复评结论 Conditional GO；**整体 no-go 不翻转，不上机**，先补静态过滤路径（新 P0）与 antirootdialog（新 P1）。**

---

## 14. 增补：Binder 服务面审计（2026-11-17，§7 第 6 条触发）

> 本节执行并闭合了 §4 标注的"唯一未闭合未知面"。完整过程、字节码证据与五轮报告见
> `artifacts_adb/binder_audit/AUDIT_REPORT.md`（脚本与文本报告入库；**厂商 jar/apk/so/dex/系统镜像不入库**，
> 读者从自己设备 `adb pull` 或 OTA 重建后用同目录脚本本地重跑）。

**触发**：`docs_archive/审核意见CHATGPT.txt` 主张把"OPPO 私有 Binder 服务审计"提升 P0，
以 CVE-2026-70386（OnePlus atlasservice 未授权 → root 命令执行）等为历史证据。
外部核验：审核意见引用的 5 个 CVE **全部属实**，但均为跨设备/跨版本案例，无一直接指向 K3。

### 14.1 结论

**Binder 服务面的 atlas 线索确定否证；整体私有服务面为「已审计、7 项未闭合、1 条待验证」，不宣称穷尽；§7 第 6 条从"未执行"变为"已执行且未命中"。** 项目维持整体结项。

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
  **这 7 个是"已知未闭合项"，不是"已排除项"**；atlas 线索 5/5 闭合只关闭了该条特定类比链。
- **`executeDriverCommand` 线索已定性（2026-11-17，设备在环）**，详见 `F16_WIFI_FTM_TRACE.md`：
  ① 它是**内部 helper**（44 条指令），不是 Binder 接口；真正的暴露点是手写的
  `OplusWifiTransactionHelper.onTransact`（798 条指令，实现 `IOplusWifiManager`+`IWifiTransactionHelper`）；
  ② 客户端 `android.net.wifi.OplusWifiManager` 经 `ServiceManager.getService("wifi")` + 裸 `transact`
  调用 **tx 10070 = `sendFTMCommand(String)`**、10069 = `getFTMState`；服务运行在 **system_server**
  （uid 1000，`u:r:system_server:s0`）；
  ③ 该分支**只有 `enforceInterface()`，无调用者身份检查**，`enforceAccessPermission()` 为空实现；
  ④ **外部可达性未证明**：7 次只读探测（含 AOSP 对照组）全部止于描述符校验，**未出现 `Permission Denial`**；
  ⑤ **下游已解出（2026-11-17 同日，比预期严重）**：ODM 分区封装在 `vendor.img` 的 `euclid/odm.img` 里，
  目标是 `/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service`（115,408 B）；其 init rc 为
  **`user root`** + caps `NET_ADMIN NET_RAW SYS_MODULE`；二进制内自实现
  `system()` = `execv("/vendor/bin/sh", {sh,-c,cmd})`，9 个调用点；vtable slot5（HIDL code 4）
  = `executeDriverCommand`，其中 `hidl_string::c_str()` → 拷入命令缓冲 → 按前缀（`myft`）分支 →
  `std::string::append` → `sh -c` 执行。
  ⇒ **"入参进入 shell 命令、以 uid 0 执行"已证**。
  ⑥ **可达性：实测不可达**（同日 18:38–18:47，11 次只读探测 + 2 组对照，全部止于服务端
  `enforceInterface`；AOSP tx1 与 `iphonesubinfo` 对照均正常）⇒ 该事务号只对 system_uid 上下文开放，
  而拿到 system_uid 本身即 root 的前置，形成循环。**对"临时 ROOT"无直接价值**，
  仅作为"若将来有 system 上下文执行点"的组合链第二段保留。见 `F16_WIFI_FTM_TRACE.md` §8。
- ~~唯一还能改变结论的动作：解出 root 二进制~~ **已完成（第五轮），确定否证**。
  **措辞更正（2026-11-17，响应审核意见 v001 问题 3）：应表述为"atlas 这条类比链已无可改变结论的动作"，
  而非"整个私有 Binder 面已无剩余动作"**——7 个未覆盖服务仍是开口；`executeDriverCommand` 已于同日
  定性（见上一条与 `F16_WIFI_FTM_TRACE.md`），不再列为开口。
- **路径 B（受控 setEvent 探针）不建议**：净执行 0.5–1 h，但命令模板硬编码、无输出 oracle
  （dmesg/kmsg/pstore 全不可读），且违反 §7"不盲试事务号"约定；成本不是时间，是无效性。
- 全程只读：未推送二进制到设备、未调用业务事务号、未改分区；大文件下载直连不走代理；设备终态同 §11。

---

## 15. 增补：GhostLock 剩余两项的静态收束（2026-11-17，响应审核意见 v001 · P0）

> 完整推导、反汇编证据与工具见 `artifacts_adb/binder_audit/GHOSTLOCK_NUL_ANALYSIS.md`；
> 工具 `tools/gl_nul_analysis.py`（离线，读 `vmlinux.elf`）。**全程未连设备。**

### 15.1 结论

审核意见把剩余工作定为"上机验证栈槽复用 + NUL 截断构造"。本轮的静态判定是：**这两项都不需要上机**，而且它们把阻断点改写成了一条新缺口。

| 待验证项 | 判定 | 依据 |
|---|---|---|
| 拷贝后内核局部量覆写 | **排除** | `getxattr` 的 prologue store 区间 `[sp+0x110, sp+0x150)` 与 copy 缓冲 `[sp+8, sp+0x108)` 不相交；copy 之后全函数 0 条 `st*` |
| 深度 >3 新机制 | **排除** | depth 4，78,944 次访问，无新原语（`GHOSTLOCK_RESCAN.md`） |
| **栈重生时机** | **不是时机问题；几何确定性成立** | 同线程、异常入口 sp 复位到栈顶、路径无 VLA 且帧长定长、`el0_svc_handler` 项相消 |
| **NUL 截断构造** | **NUL 不阻断；约束精确化为"连续非零前缀"** | 见 15.2、15.3 |

**判定：GhostLock 维持 no-go，但理由换成"缺一次内核地址泄露"。** 载体侧已闭合。

### 15.2 三个硬事实（可离线复现）

1. **无 `__strncpy_from_user` asm 变体** ⇒ 走 `lib/strncpy_from_user.c` 的 C 实现：含 NUL 的 8 字节字按
   `zero_bytemask` 掩码后整字存储（NUL 之后同字内字节被写 0），再往后保留栈残余。
2. **`getxattr @0xffffff8008271408`**：`0x8271440 bl strncpy_from_user`，目标 `sp+8`、长度 `0x100`；
   全部栈写只有 prologue 4 条 `stp`，区间 `[sp+0x110, sp+0x150)`；缓冲整体在自身 `sp` 之上
   ⇒ 被调用者帧与中断帧（压在该 `sp` 之下）不可能碰到它。
3. **字节映射**（串自 buffer 起点写入 ⇒ `串索引 = waiter偏移 + (waiter−buffer)`）：waiter 72 B 全部落在
   256 B 缓冲内，**没有"前面留残余"的可能**。覆盖全部被读字段所需串长：`fgetxattr` **84 B**、
   `getxattr` **132 B**、`setxattr` **168 B**（若算到结构尾部 `0x48` 则 88/136/172 B），
   全部在 `XATTR_NAME_MAX`=255 内。

### 15.3 NUL 约束的真实形态

- 必须提供**到 `prio` 低字节为止的连续非零前缀**：81 / 129 / 161 字节（三条路径）。
- `prio` 上位 3 字节**由掩码自动补 0** ⇒ `prio ∈ [1,255]` 全部合法（NUL 语义在这里是帮忙而非阻碍）。
- `prio` 必须 **≠ `task->prio`**（`rtmutex.c:611` 相等时只置 `requeue=false`，跳过 `[7]` 的 dequeue/enqueue，
  写原语消失）。W 为 120，取 130 一类即可。
- **"少写一点靠残余补齐"不成立**：终止 NUL 恰好落在下一个字段的首字节，任何指针首字节被清零即失效
  ⇒ 不存在"用户段 + 内核残余"的混合构造。

### 15.4 新的阻断点（本轮核心）

`rt_mutex_adjust_prio_chain()` 对 fake waiter 的读取面已逐行核对（原因子见分析文档 §5）。两处关键：
`:579` 守卫天然通过（`next_lock` 与 `waiter->lock` 同源）；`waiter->task` **在 `prio ≥ 0` 时不被解引用**
（全文件仅 `:975` 赋值、`:1067` `wake_q_add`）⇒ `task` 只要 8 字节全非零。

真正的约束是 `lock`（0x38）与 `tree_entry` 的三个链接：它们必须**非零**（否者串在此截断），而"干净"取值
全部不可得：

| 想要的取值 | 为何不成立 |
|---|---|
| `RB_EMPTY_NODE` 自引用（让 `rt_mutex_dequeue` 直接返回） | 需 `__rb_parent_color == &waiter->tree_entry`，即**内核栈地址**，本机无泄露 |
| `rb_left/rb_right = NULL`（叶子节点常态） | 含 `0x00`，串在此截断，后续字段全废 |
| `lock` 指向攻击者可控对象 | 需该对象的**内核地址**；`pi_state` 在 `kmalloc-128`，随 KASLR 与分配序变化 |

⇒ **两个必要条件归约为同一件事：必须知道至少一个内核地址。** 本机泄露面为空（§2.3：`/proc/kallsyms`、
`/proc/iomem`、`dmesg`、`/dev/kmsg`、`pstore` 全不可读；`RANDOMIZE_BASE=y`；无 `BPF`/`KPROBES`/`perf`）。

### 15.5 为什么不再上机

| 实验 | 能否结论 |
|---|---|
| E1 只验"栈槽复用" | **不能**：xattr 返回值只反映文件系统语义（`-ENODATA`/`-ERANGE`），不暴露栈内容；没有无创 oracle |
| E2 端到端 | **不能**：无泄露 ⇒ 只能填猜测地址 ⇒ 必然 panic，而 panic 文本不可读 ⇒ 既不能证真也不能证伪 |

⇒ **在"无泄露"前提下，这两项实验不具可证伪性**；重跑只会重现"帧死即 panic 3/3"的已知现象并消耗重启额度
（§11 约定 2 次）。P0 降级为"等泄露原语或 raw-byte 载体"（§7 第 2 条）。此判断可被否证，否证条件即 §7 第 2 条。

### 15.6 方法论产出

1. **"待验证"要先问可证伪性**：一个实验若在现有观测面上既不能证真也不能证伪，它不是实验，是重启。
   本轮因此把两项"待验证"直接改判为"静态成立 / 静态阻断"。
2. **C 实现的边界语义要按 8 字节字算，不是按字节算**：`zero_bytemask` 会在 NUL 之后多清 0–7 字节，
   这既是 `prio` 合法取值的来源，也是"残余不可用"的原因。
3. **掩码位宽要双向检查**：`rb_parent()` 清低 2 位 ⇒ 攻击者给的链接地址不是任意值，这既放宽了构造，
   也意味着"随便填一个非零垃圾"必然把写操作打到不可控地址。

---

## 16. 增补：OPPO Wi-Fi 私有事务面（2026-11-17，设备在环）

> 完整逐指令证据、11 次探测原始输出与负知识见 `artifacts_adb/binder_audit/F16_WIFI_FTM_TRACE.md`。
> 本轮**动了设备**（只读：`service list`/`service check`/`dumpsys`/`service call` 无参与单字符串事务/OTA 下载），
> 未 push、未安装、未改分区、未触发内核。

### 16.1 结论（一句话）

**线索真实、危害真实、入口在 shell 之外。** `executeDriverCommand(String)` 的入参确实进 `sh -c`、
服务确实以 `user root` 运行，但该事务号（`wifi` binder `code≥10069`）**只对 system_uid 上下文开放**；
而拿到 system 上下文本身就是 root 的前置 ⇒ 对"临时 ROOT"目标形成循环，无直接价值。

### 16.2 调用链（已证部分）

```
app / system_server
  └─ android.net.wifi.OplusWifiManager（framework/classes2.dex）
       mService = ServiceManager.getService("wifi")
       Parcel.writeInterfaceToken("android.net.wifi.IOplusWifiManager")
       transact(10070 = sendFTMCommand(String) / 10069 = getFTMState)
  └─ wifi 服务（system_server, uid 1000）内 OPPO 分派
       └─ com.oplus.server.wifi.common.OplusWifiTransactionHelper.onTransact（手写 798 条指令，
          实现 IOplusWifiManager + IWifiTransactionHelper；FTM 分支只有 enforceInterface，
          `enforceAccessPermission()` 是 1 条指令的空实现）
            └─ OplusWifiHalService.executeDriverCommand(String)
                 └─ HIDL vendor.oplus.hardware.wifi@1.1::IOppoWifiService.executeDriverCommand(String, cb)
                      └─ /odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service  ← **user root**
```

### 16.3 下游实证（关键：它不是普通 HAL 进程）

- **取数路径**：OTA zip（Range 584 MiB）→ `vendor.new.dat.br` → brotli → `vendor.new.dat`（`diff=0`）
  → `sdat2img` → `vendor.img`（2.09 GiB）→ **`euclid/odm.img`（166 MiB）** → `bin/hw/vendor.oplus.hardware.wifi@1.1-service`（115,408 B）。
  `/odm` 不是独立分区，而是封装在 `vendor.img` 里——这是此前四条取数路径全部失败的原因。
- **运行身份**（`etc/init/vendor.oplus.hardware.wifi@1.1-service.rc`）：
  `user root`，group `wifi system vendor_qti_diag net_admin`，caps `NET_ADMIN NET_RAW SYS_MODULE`。
- **shell 执行原语**：二进制无 `system`/`popen` 导入，而是手写
  `execv("/vendor/bin/sh", {"/vendor/bin/sh","-c",cmd,NULL})`（入口 `0x95b4`，**9 个调用点**）。
- **入参直通（最后一跳）**：vtable @`0x1a0a0` 与 HIDL 事务号严格对应，`code 4 = executeDriverCommand = slot5 = 0x992c`；
  该函数体内 `hidl_string::c_str()` → 拷入命令缓冲 → 按前缀（`myft`）分支 → `std::string::append` → `sh -c`。
  **⇒ "入参进入 shell 命令、以 uid 0 执行" 已证。**
- 同族接口（同样以 root 执行）：`sendSupplicantCommand`（`wpa_cli`）、`runWiFiScript`、
  `catchSnifferLog`（`tar … && rm -rf …`）、`changeConnectionMode`（写 `/sys/module/wlan/parameters/con_mode`）。

### 16.4 可达性实测（本节最重要的否定）

判据先登记后执行：只用 `10069 = getFTMState`（无参、只读），返回整型即"可达"。

| 构造 | 次数 | 结果 |
|---|---|---|
| 单令牌 4 种（`IOplusWifiManager` / `IWifiManager` / `IWifiTransactionHelper` / `IOplusWifiP2pManager`） | 4 | `SecurityException: Binder invocation to an incorrect interface` |
| 无参 | 1 | 同 |
| 双令牌 4 种排列 | 4 | 同 |
| **对照 A** `service call wifi 1`（AOSP 事务） | 1 | **正常返回 Parcel** |
| **对照 B** `service call iphonesubinfo 1`（AIDL 需令牌） | 1 | **正常返回 IMEI** |

**对照证明**：工具与 binder 通路正常、字符串参数可用、拒绝发生在**服务端**（不是 `FAILED_TRANSACTION`、
不是 SELinux、不是工具侧失败）。**穷尽了当时可获得的描述符组合后仍然失败**。

> ⚠️ **本段当时的推断"外层分派在未解出 jar 中 ⇒ 只对 system_uid 开放"已被 §16.8 更正**：
> 外层分派找到了（APEX 内的 `service-wifi.jar`），且**没有任何 uid 判定**——唯一校验是接口描述符字符串。
> 因此"只对 system_uid 开放"这句话不成立，真正的阻断是"描述符还没对上"。

### 16.5 记录两条负知识（本轮自我推翻）

| 我先前的判断 | 实测更正 |
|---|---|
| "全程无 `Permission Denial` ⇒ 拒绝不在授权层" | **错**。厂商可以用 `enforceInterface` 的报文掩盖 uid 门禁；报文类型不能反推门禁类型。 |
| "只差一次正确调用，用真实客户端即可" | **未证且很可能不成立**。所有令牌布局均失败；在拿到外层分派代码前，不得假设再试一次就会通。 |

### 16.6 何时重开这一条

仅两种情形（§7 第 6 条）：
1. 出现**任意 system（uid 1000）上下文的代码执行点** ⇒ 可把本节这条链作为**第二段**接上，直接得到 root 命令执行；
2. 解出 `com.android.server.wifi` 的实现类（外层分派）⇒ 可判定门禁是 uid 还是令牌，但即便如此，
   从 shell 到 system 上下文之间仍缺一环。

**禁止**再用猜事务号的方式试探（236 个服务 × 未知令牌 = 盲试，且已证此路不通）。

### 16.7 复现路径（全部离线，不需要设备）

```bash
python tools/ota_entry_range.py <OTA_URL> vendor        # 列条目区间（vendor.new.dat.br / transfer.list）
python tools/dl_range.py <OTA_URL> <start> <end> out.br 16 ""   # 只取该区间
python tools/rebuild_system.py out.br out.dat            # brotli 流式解压
python tools/sdat2img.py <transfer.list> out.dat vendor.img
# 7z x vendor.img euclid/odm.img  &&  7z x odm.img "bin/hw/vendor.oplus.hardware.wifi@1.1-service"
```

分析脚本：`tools/find_service_reg.py`（dex 内定位服务名/注册点/onTransact 分派，含 androguard hiddenapi 解析绕过）。

### 16.8 追加：外层分派已定位（2026-11-17 19:0x，静态；设备中途断开）

审核意见 v002 的 P0（"找到 wifi Binder 的真实 onTransact 分派"）**已完成静态部分**：

- **Wi-Fi 服务在 APEX 里**，不在 `services.jar`。用 `tools/ext4_find_offset.py` 把镜像内偏移
  `0xf009d7e` 反查回 `/system/apex/com.android.wifi.apex` → `apex_payload.img` → `javalib/service-wifi.jar`。
- `com.android.server.wifi.WifiServiceImpl.onTransact` 只有 **18 条指令**：
  `if (super.onTransact(...)) return true;` 否则
  `((IWifiInjectManager) OplusFeatureCache.getOrCreate(IWifiInjectManager.DEFAULT, ...)).getTransactionHelper().onTransact(code, data, reply, flags)`。
  ⇒ **10069/10070 确实落到 §16.2 那个 helper**，外层没有额外拦截。
- **不存在 uid 门禁**：helper 的 798 条指令里 `getCallingUid()` 只出现 1 次，且仅用于拼日志
  （`"APP enable sta2 in OplusWifiTranscation: ... uid ="`），不参与分支；每个分支只有
  `enforceInterface(常量字符串)` 这一道校验。
- **剩下一跳**：设备重连后补测 5 次（HIDL 描述符、IWifiManager+P2p、前置 i32 等），**全部失败**，累计 16 次探测。
  关键新增对照：`wifi` tx1 对**垃圾令牌**照常返回、越界 code（9999/10999/12000）返回
  `"Not a data message"`（无处理器），只有 10069 **主动抛异常** ⇒ 该 code 确有处理器，
  抛异常动作在其分支内部，**不是全局门禁**。
  ⇒ 动态验证被**调用方 ABI**（`service call` 能表达的 Parcel 构造）卡住，**不是被授权卡住**；
  再往下必须用真实 Java 客户端，而本机无 JDK/d8。

**判定：门禁是"接口描述符"而非 uid（静态证据一致），但"可达"仍记为未证**——没有一次成功调用就不算。
详见 `F16_WIFI_FTM_TRACE.md` §9。

### 16.9 终局：真客户端验证成功，此前"不可达"作废（2026-11-18 09:35）

用 `tools/javaprobe/build.sh` 构建的真 Java 客户端（`app_process` 运行，从 shell uid 2000 发起）：

```
FtmProbe 10069 android.net.wifi.IOplusWifiManager
→ TRANSACT=true ; REPLY 8B ; INT=0
```

对照：`10069`+错误令牌/`GARBAGE` → `enforceInterface` 抛错；越界 `10999` → `TRANSACT=false`。

**结论（推翻 §8 与 §16.4/§16.5）：**
1. **从 shell 完全可达**；此前 16 次 `service call` 失败是**调用方 ABI**（无法复现 `writeInterfaceToken`），
   不是授权，也不是 uid 门禁；
2. 唯一校验是公开的接口描述符字符串；
3. 与 §16.2/§16.3/§16.8 的静态链合并后，
   **"shell → 公开描述符私有事务 → root 上下文 `sh -c`" 全链已闭合到最后一个实验步骤**
   （尚未执行 tx `10070` = `sendFTMCommand`，因为它会真的在 root 上下文执行命令串）。

**这条链取代 GhostLock 成为项目主线索**：不再需要内核地址泄露，也不再需要 KGSL / 两个 binder CVE / FastRPC。
下一步必须先取得明确授权，且只做无副作用探测；详见 `F16_WIFI_FTM_TRACE.md` §11。

### 16.11 撤回：§16.9/§16.10 的"结论翻转"不成立（2026-11-18 09:44）

我在 09:35–09:42 声称"shell → root 命令执行已实锤、项目结论翻转"。**该结论撤回。**

**证据重读**：所有携带 shell 元字符的输入（`myft id > ...`、`myft -h; id`、`myft id | logger`）
服务端均返回 `failed: -3 INVAILD_PARAMETER`，并导致 `_hidl_cb called a second time` 崩溃；
只有格式合法的参数（`myft -h`）返回成功。logcat 中 `entering executeDriverCommand(<s>)`
是**函数入参回显**，我错当成命令执行证据。**没有任何一次回显出 `uid=0(root)`**。

**修正后判定**：
1. 从 shell 可调用私有事务、字符串被 root 服务接收——**仍成立**（§16.9）；
2. 入参可进入 `sh -c` / 可任意命令执行——**不成立，撤回**；
3. 临时 ROOT 实锤——**不成立，撤回**；
4. **整体 no-go 不翻转。**

**实锤标准（留给后续）**：必须①服务端报 `completed successfully`，②命令串含可观察只读副作用，
③**现场回显 `uid=0(root)`** 且调用方仍为 shell。缺一不可。

**用户质疑记录**：本次误判由用户指出——"被拦了那么多次？这个临时 ROOT 有什么用？"，
该质疑成立。误判根因：**把参数回显当作执行证据、把参数校验拒绝归因为 SELinux 文件权限**。

现场已清理：设备探针删除、`/data/local/tmp` 为空、`shell id` 仍为 uid 2000、崩溃的 HAL 已自动重启。
详见 `F16_WIFI_FTM_TRACE.md` §12。

---

## 17. 新对话接手清单（2026-11-18 09:48，交接版 v2.7）

> **从这里开始读。** 前面的章节是证据库，本节是当前状态与下一步。

### 17.1 一句话状态

**整体 no-go。** 四个内核面维持原判定；Wi-Fi 私有事务面经四轮反复后收敛为：
**shell 可调用 → 字符串被 root 服务接收 → 命令串裸拼进 `sh -c` → 唯一的过滤器只覆盖 11 个字符（缺 `\n`/反引号/`<`/`>`）⇒ 静态注入面开放 → 但从未回显 `uid=0`。**
两次"结论翻转/实锤"均为误判，已在 §16.11 撤回；"myftm 非任意命令执行"与"iwpriv 参数被整数化"两处断言已分别在 §20/§22 撤销。**设备终态干净，可随时开新对话继续。**

### 17.2 三个结论层次（后续判断必须严守）

| 层次 | 当前证据 | 状态 |
|---|---|---|
| L1 字符串被 root 服务接收 | logcat `entering executeDriverCommand(<s>)` 逐字回显；服务 rc 为 `user root` | **已证** |
| L2 命令被执行 | 服务端 `completed successfully` + 可观察副作用 | **未证**（`myft -h` 的"成功"仅证明参数格式合法） |
| L3 提权成立 | 现场回显 `uid=0(root)`，调用方仍为 shell uid 2000 | **未证，且多次尝试失败** |

**规则：L1 成立不得推出 L2/L3。** 本次误判就是把 L1 当 L3。

### 17.3 下一步优先级（按推荐顺序）

> **🔴 v2.12 更新（2026-11-18，见 §22）：** 新 P0 的静态部分已收束到"过滤器本身有缺口"——
> 黑名单只含 11 字符，`\n`/反引号/`<`/`>` 可穿越，且 iwpriv 分支不做整数转换；同族另三接口经全镜像
> 检索确认不可达（`runWiFiScript`/`sendSupplicantCommand` 无调用方，`catchSnifferLog` 仅 int 入参）。
> **剩余动作只有一件：授权上机验证 L3**；antirootdialog 仍缺物料。
>
> **🔴 v2.10 复评重排（2026-11-18，来源 `docs_archive/审核意见CHATGPT-v002.txt`，见 §20）：**
> - **P0 = Wi-Fi myftm 分支重开**（静态注入面已证开放，最高优先，纯静态先补过滤路径，不上机）；
> - **P1 = antirootdialog**（补解 odex/vdex，最后 1/7 Binder 缺口）；
> - **P2 = GhostLock 地址泄露**（冻结，除非新泄露证据）；冻结面不变。
> - 复评结论为 **Conditional GO**：项目继续，但只针对 myftm 做定向复审；仍无 ROOT 成功证据。
> - 下方 P0/P1/P2 是 v2.7 原计划，勾选状态**以 §20 为准**。

**~~P0（原） — 静态定性 `-3 INVAILD_PARAMETER`（纯离线）~~ ✅ 已完成，见 §18；但由此衍生的"myftm 安全"断言已在 §20 撤销，Wi-Fi 面以新 P0 重开**

目标：搞清失败发生在哪一层、合法命令格式是什么。步骤：

1. 本地已有两个关键二进制（均在 `.build/`，不入库）：
   - `.build/vendor/x/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service`（native，115,408 B）
   - `artifacts_adb/binder_audit/dex/oppo-wifi-service.dex`（Java 侧 `OplusWifiHalService`）
2. 查 `uD6hk53bOimZNTzE924fVOYf3t8.onValues(int, String)` 里哪个码对应 `INVAILD_PARAMETER`、由哪层写入；
3. 逆向 native slot5 `0x992c`：确认 `0x9a04` 比较 `"myft"` 后的分支，以及 `myft -h` 返回成功的真实含义
   （工具真执行了 vs 仅参数格式合法）；
4. 产出：`-3` 的确定性归因 + 合法命令格式表。

**~~P1（原） — 审固定命令集的实际权限（静态）~~ ⚠️ 部分撤销，见 §20：iwpriv 等分支确为固定模板；
但 myftm 分支 `/vendor/bin/myftm <原始尾串>` 无引号/转义/过滤，注入面静态开放——原"受限 root 工具接口"结论不成立**

`.rodata` 已列 9 类命令：`iwpriv wlan0 setMonChan <int>`、`ftmdaemon`、`myftm`、`wpa_cli`、
`ifconfig wlan0 up`、`tar … && rm -rf`、`con_mode` 写入、`tcpdump_vendor`、`mkdir -m 777`。
逐指令复核（§20）：~~iwpriv 参数经 `to_string(int)`+regex ⇒ 受限~~ ⟵ **§22.3 更正**：iwpriv 分支追加的是
**整条原始入参**、不做整数转换，只靠 11 字符 regex 把关（`to_string`+`setMonChan` 属 `catchSnifferLog`）；
**myftm 尾串经 `append(const char*)` 裸拼进 `sh -c` ⇒ 注入面开放**。二者须分开判定，且两条分支都不可认定安全。

**~~P2（原） — 七个未覆盖私有服务~~ 6/7 完成，见 §19；措辞按 §20 更正**

**六个服务未发现 shell 可达提权路径，第七个（antirootdialog）尚未完成审计**——不得宣称七个已全部排除。
hephaestus 是唯一有 `system(可控串)` 的服务，但 native 层 `getCallingUid()==1000` 硬门禁挡住 shell(2000)，此项否证可靠；
hans/horae/oiface/orms/appdata 无命令执行面或带签名校验；**antirootdialog 实现未解出（odex/vdex）→ 复评为新 P1**。
（原计划：`IAntiRootDialog`/`IHephaestus`/`IHoraeService`/`IOIfaceService`/`IHansComunication`/
`IOppoAppDataService`/`OplusResourceManagerService`，按 §14 atlas 同格式审计。）

**冻结**：KGSL、两个 binder 内核 CVE、FastRPC、GhostLock，无新原语不动。

### 17.4 明确禁止重复的动作

1. **不要再猜令牌 / 用 `service call` 试**——16 次探测已证是调用方 ABI 问题，真客户端已解决；
2. **不要再试已被拒的元字符**——`;` `|` `$` `&` `@` `#` `%` `*` `^` `:` `?` 全部在 native 黑名单内（§22.2），
   重复只会再触发 `-3` 与 HAL 崩溃；**但 `\n`、反引号、`<`、`>` 从未被测试且不在黑名单内**——
   若获授权，应测的正是这一类（§22.6 的最小验证设计），不要被本条的旧措辞误导；
3. **不要用"参数回显"当执行证据**——这是本次误判的直接根因；
4. **不要在 L3 未达时写"实锤""翻转"**——实锤三条件见 §16.11 / §17.2。

### 17.5 工具与物料清单（新对话可直接用）

| 用途 | 路径 |
|---|---|
| 主文档 | `HANDOVER.md`（本文件，唯一权威） |
| Wi-Fi 全证据 | `artifacts_adb/binder_audit/F16_WIFI_FTM_TRACE.md`（§7 静态链 / §9 外层分派 / §11 可达 / §12 撤回）|
| Wi-Fi P0 归因 | `artifacts_adb/binder_audit/WIFI_P0_PARAMETER_TRACE.md`（`-3` 逐层归因 / myftm 前缀更正 / 合法命令格式表）|
| **Wi-Fi P1 九类命令 + 过滤边界** | **`artifacts_adb/binder_audit/WIFI_P1_ROOT_COMMAND_AUDIT.md`**（vtable 槽位全映射 / 黑名单缺口 / 三接口不可达否证 / `getIniVersion` 任意读）；工具 `tools/wifi_slot_audit.py` |
| P2 七服务审计 | `artifacts_adb/binder_audit/P2_SEVEN_SERVICES_AUDIT.md`（宿主/身份/门禁总表 / hephaestus uid 门禁解码 / antirootdialog 缺口）|
| GhostLock 静态 | `artifacts_adb/binder_audit/GHOSTLOCK_NUL_ANALYSIS.md` |
| GhostLock 载体 | `artifacts_adb/binder_audit/GHOSTLOCK_RESCAN.md` |
| Binder 审计 | `artifacts_adb/binder_audit/AUDIT_REPORT.md` |
| 真客户端探针 | `tools/javaprobe/{FtmProbe.java, build.sh, android/os/*.java}`；`bash tools/javaprobe/build.sh` 一键构建 |
| 便携 JDK + D8 | `.build/jdk/jdk-11.0.20+8/` + `.build/jdkpkg/r8.jar`（gitignored，已就绪） |
| OTA 条目定位 | `tools/ota_entry_range.py`；下载 `tools/dl_range.py` |
| 镜像→文件 | `tools/ext4_find_offset.py`（偏移反查路径，找到 APEX 里的 jar 就靠它） |
| dex 定位 | `tools/find_service_reg.py`；反汇编 `artifacts_adb/binder_audit/deep_method.py` |
| NUL 取证 | `tools/gl_nul_analysis.py` |

** Git 状态**：`main` 分支，最新提交 `1b51b4c`（撤回误判），已推送 `origin`。
** 大文件**：`vendor.img`(2.09 GiB)、`euclid/odm.img`(166 MiB)、`system.img` 等全在 `.build/` 与
`artifacts_adb/binder_audit/rootbin/`，均 gitignored。若磁盘紧张可删，可重下（vendor 区间 584 MiB）。

### 17.6 设备与运营约定

- 设备 PCGM00_11_F.16 当前**在线**（`3b883b98`），但多次在长时间空闲后掉线，需物理重插；
- 上机前先 `adb devices`；任何写操作/命令注入都需用户明确授权；
- 判据先登记再运行，运行后原文追加到对应文档；
- 崩溃的 HAL 会自动重启，但每次崩溃都产生 tombstone 噪声，避免重复触发。

---

## 18. 增补：P0 静态定性 `-3 INVAILD_PARAMETER`（2026-11-18，纯离线，§17.3 P0/P1 收束）

> 完整逐指令证据见 `artifacts_adb/binder_audit/WIFI_P0_PARAMETER_TRACE.md`。本轮只分析两个已入库二进制
> （native HAL + `oppo-wifi-service.dex`），**未连设备、无写操作、无重启**。

### 18.1 结论

**`-3` 由 native 侧写入并通过 HIDL 回调透传给 Java；归因是 regex 黑名单校验 + 固定命令模板。
Java 层 `uD6hk53bOimZNTzE924fVOYf3t8` 只是 3 条指令的 lambda 壳，无码表。** 整体 no-go 不翻转。

### 18.2 `-3` 的完整归因链

| 层 | 结论 | 证据 |
|---|---|---|
| Java | `onValues(int,String)` → `setResult(status,value)` 原样转发，无码表；`entering executeDriverCommand(<s>)` 在 **Result 构造函数**里打印 = 入参回显，非执行证据 | dex 反汇编：`uD6hk…` 3 条指令；`isSuccess()` 仅认 status==1 |
| native | `-3` 写入点 `0x9ddc`，伴随字符串 `INVAILD_PARAMETER@0x697b`，经 `blr [vtable+0x30]` 回调 | slot5 `0x992c` 反汇编 |
| 根因 | `sub_9f64 @0x9f64` 构造 `std::regex("[@#$%&*^:;?|]+")`（`0x6dcb`，14 B）对命令串做 `regex_search`，命中返回 false ⇒ `-3` | `0x9fc4`/`0x9fe4`/`0xa024` |

native 状态码表：`0`=命令已拼装执行；`-2`=空参数；**`-3`=regex 命中/参数非法**；`-4`=文件不存在；`-5`=执行失败。

### 18.3 关键更正：myftm 前缀判据（推翻 §7.7 的记录）

`0x9a04/0x9a34` 比较前 4 字节 `"myft"`，`0x9a38/0x9a4c` 比较**第 5 字节 `'m'`**，`0x9a5c cbz` 才进 myftm 分支。
⇒ **进入 myftm 分支的充要条件是前 5 字节恰为 `myftm`**（§7.7 记的"前缀 myft"漏了第 5 字节，已更正）。

**历史 4 次注入串全是 `myft `（第 5 字节空格），从未进 myftm 分支**，实际走 iwpriv 分支
（`0x9a60`：拼 `/odm/bin/iwpriv <整条入参>` + regex 校验）。这解释了全部日志：
`myft -h`（无黑名单字符）→ 命令拼装成功 → status 0；含 `;`/`|` 的串 → regex 命中 → `-3`。

> **⚠️ v2.12 更正（§22.3）**：本段原写 `iwpriv` 分支拼 `/odm/bin/iwpriv wlan0 setMonChan <to_string(int)>`，
> 与逐指令复核不符——该分支是 `c_str()` 后 `append(cmd, len)` 裸追加**整条入参**，无整数转换；
> `setMonChan`+`to_string(u32)`（`0xae58`/`0xae8c`）属于 **slot3 `catchSnifferLog`**。

### 18.4 固定命令模板（P1 并入本轮）—— ⚠️ 部分已被 §20 撤销

> **以下 myftm 相关判断在 v2.10 被外部复评推翻，保留原文仅作历史追溯；以 §20 为准。**

- **iwpriv 分支**（~~仍成立~~ ⟵ **§22.3 更正**）：命中该分支的命令是 `/odm/bin/iwpriv <整条原始入参>`，
  入参**未经整数转换**（`to_string`+`setMonChan` 属 `catchSnifferLog`）；唯一约束是 regex 黑名单拦截元字符，
  而该黑名单只含 11 个字符（§22.2）。
- **myftm 分支**（`0x9b7c`，历史从未走到）：~~命令恒为 `/vendor/bin/myftm` + 入参[5:]，追加在固定路径后；
  **不调 regex**，但同样无法跳出单个 token。~~ ⟵ **§20 撤销**：实为 `/vendor/bin/myftm <入参[5:]>` 裸拼，
  无引号/转义/过滤，`sh -c` 解析 shell 元字符 ⇒ 注入面静态开放。
- 两条分支的 `system()` 都是 `0x95b4` = `execv("/vendor/bin/sh",{sh,-c,cmd})`（此点成立）。
- ~~⇒ 受限 root 工具接口，不是任意命令执行~~ ⟵ **§20 撤销**；L3 仍未证（无 `uid=0` 回显），但分支已重开。

### 18.5 下一步 —— ⚠️ 已被 §20 重排

~~P0/P1 已闭合，不建议上机重试~~ ⟵ **§20 撤销**：myftm 分支注入面静态开放，Wi-Fi P0 重开为最高优先；
先补静态过滤路径（Java/HIDL 传输层 + `/vendor/bin/myftm` 自身），再决定是否申请授权上机。
P2（七个未覆盖私有服务）见 §19，6/7 完成、antirootdialog 升为新 P1（§20）。

---

## 19. 增补：P2 七个未覆盖私有服务审计（2026-11-18，纯离线，§17.3 P2 收束）

> 完整逐项证据见 `artifacts_adb/binder_audit/P2_SEVEN_SERVICES_AUDIT.md`。从 `system.img` 解出 4 个 native
> 二进制 + rc + so（落 `rootbin/_p2/`），结合已入库 apk/jar，按 §14 atlas 同格式审计。**未连设备、无写操作。**

### 19.1 结论

**七服务无一产生 shell 可达的 uid 0 提权路径，整体 no-go 维持。** 覆盖度 6/7 定性，1 个缺口。

### 19.2 关键发现：hephaestus 的 `system()` 被 uid 门禁挡住

- rc 有两个 service：`hephaestus`(user system) 与 `hephaestus_install`(**user root**, oneshot, installd seclabel)。
- 全量反汇编（stripped AArch64，.text 0x908 B）确认 `system@plt=0x2ab0` **仅一处调用 @0x24f0**，
  参数是客户端字符串 `x21`。
- 但 `0x246c getCallingUid()` → `0x2490-0x24b0` 算出 `uid % 100000`，`cmp #0x3e8(1000)`，
  **仅 uid==1000(AID_SYSTEM) 才执行 system()**；shell(2000) → 走 "not apply to this uid" 分支。
- ⇒ 对 shell 是**硬性否证**（native 硬编码门禁，非模板可绕）。再次印证"看到 system() ≠ 可执行注入"。

### 19.3 其余六服务判定

| 服务 | 身份 | 判定 |
|---|---|---|
| hans | system | 无 system/execv/popen 导入；cgroup freezer 用途 |
| horae | system,group root | 无 system；仅 fopen 读配置 |
| oiface | system,group root,SYS_NICE | 无 system；5 处 property_set 全为固定 `persist/debug.oiface.*` |
| orms | 系统 (32bit so + HIDL) | 仅 fopen，无命令执行 |
| appdata | system_app | 无 exec；`deleteFileOrFolder` + 签名校验 `getPackagesForUid`+`checkPackageSignature` 挡 shell |
| **antirootdialog** | 未知 | **缺口**：实现未解出（odex/vdex 剥离，已检索全部已解出 jar/apk 均无），不臆测；闭合需解 odex/vdex |

### 19.4 下一步

v2.9 时记为"P0/P1/P2 全部完成"；**v2.10 复评后已重排——见 §20**：P2 六服务否证仍成立，
但 Wi-Fi myftm 分支重开为最高优先、antirootdialog 升为新 P1。hephaestus uid 门禁否证可靠，不动。
冻结面（KGSL / binder CVE / FastRPC / GhostLock）无新原语，不动。

---

## 20. 增补：外部复评更正 —— myftm 分支重开（2026-11-18，纯离线）

> 来源：`docs_archive/审核意见CHATGPT-v002.txt`（第五次复评）。逐指令复核后**接受其核心批评**。
> 关联证据：`artifacts_adb/binder_audit/WIFI_P0_PARAMETER_TRACE.md` §3.3/§4/§7（已同步重写）。

### 20.1 复评的核心质疑（成立）

v2.9 断言"myftm 分支参数只是固定路径后的一个 token，无法逃离 myftm 命令"——**错误**。
复评指出：这混淆了 shell 的**参数分隔（空格）**与**控制操作符（`;` `|` `&&` `$()` 反引号）**；
后者**不依赖空格**即可被 `sh -c` 解析为命令语法。

### 20.2 逐指令复核结果（全部支持复评）

| 复评要求证明 | 静态复核 | 证据 |
|---|---|---|
| ① `input[5:]` 追加前有无全局过滤 | 本层无：c_str()→append() 间无 `sub_9f64`、无转义循环 | `sub_9f64` 全程序仅 3 调用点 `0x9db0/0xa78c/0xac58`，均不在 myftm 分支 |
| ② `sh -c` 串有无引用/转义/隔离 | **无**：`cmd = "/vendor/bin/myftm " + input[5:]`，无单/双引号、无反斜杠 | SSO 逐字节重建：`sp+0x48`=17B 前缀、`sp+0x30`=`" "`(0x20)、`append(const char*)` 裸追加 |
| ③ shell 控制操作符能否被解释 | **能**：POSIX `sh -c` 整串语法解析 | `0x9cb8`→`execv("/vendor/bin/sh",{sh,-c,cmd})` |

关键更正：`0x9c08 mov w10,#0x22` 是 **libc++ SSO 长度字节（17<<1=34）**，不是引号字符——
真正的命令里没有任何引号。myftm 分支是干净的命令注入面（就本层拼接点而言）。

### 20.3 判定变更

- **撤销** v2.9 的"受限 root 工具接口、非任意命令执行、不建议上机"三项断言（对 myftm 分支）。
- **保留**：`-3` 归因（仅 iwpriv 分支）、myftm 前缀 5 字节更正、P2 六服务否证、hephaestus uid 门禁否证。
- **myftm 分支**：从"已否证"改判为**"静态注入面开放、待授权验证"**；Wi-Fi P0 **重开**，不随 P1 关闭。
- **Conditional GO（复评结论）**：项目继续，但只针对 myftm 做定向复审；**仍无 ROOT 成功证据，整体 no-go 不翻转**。
- **不上机**：复评亦建议先审计清楚再决定；L3 必须经用户明确授权、以现场 `uid=0` 回显为唯一判据（§17.2）。

### 20.4 优先级重排（以本节为准）

| 优先级 | 任务 | 状态 |
|---|---|---|
| **新 P0** | Wi-Fi myftm 分支：补齐静态过滤路径（Java/HIDL 传输层 + `/vendor/bin/myftm` 自身），确认是否别处有统一过滤；再决定是否申请授权上机 | 重开 |
| **新 P1** | antirootdialog：解出 odex/vdex，确认身份/鉴权/敏感操作（最后 1/7 缺口） | 未启动 |
| P2 | GhostLock 地址泄露 | 冻结 |
| 冻结 | KGSL / binder CVE-2023-20938 / binder CVE-2022-20421 / FastRPC | 不动 |

**复评明确**：P0 是研究优先级，不代表已发现可用漏洞；不要新增 CVE、不要急着上机注入。

---

## 21. 增补：执行复评的新 P0 / 新 P1（2026-11-18，纯离线）

> 响应 §20 复评重排的优先级。全程未连设备、无写操作。新解出 `/vendor/bin/myftm` 与
> `OppoExSystemService.{odex,vdex}`（落 `rootbin/_p2/`，gitignored）。

### 21.1 新 P0（Wi-Fi 静态过滤路径）—— 完成，注入面判定不变

**（a）Java/HIDL 传输层：确认全程无过滤**（证据 `WIFI_P0_PARAMETER_TRACE.md` §8.1）
- `OplusWifiTransactionHelper.sendFTMCommand`：`enforceAccessPermission()` = **1 条 return-void 空实现**，串原样下传。
- `OplusWifiHalService.executeDriverCommand`：原样拼日志 + 原样传 HIDL。
- `IOppoWifiService$Proxy.executeDriverCommand`：`writeString` 原样写 Parcel（code=4），回调原样回传。
- ⇒ 复评第①点传输段坐实：**无转义/过滤/引号**，逐字节透传。

**（b）`/vendor/bin/myftm` 本体：第二道约束，但不反驳复评**（证据 §8.2/§8.3）
- 逆向（225,752 B，AArch64 PIE；PLT 经 GOT 精确映射）：导入 `getopt_long`+`atoi`/`strtol`/`sscanf`；
  option spec 为固定 AT 表（`hdi:nb:e:Em:...:rateBw:nss:...`）——高通 Wi-Fi ATE 工厂测试工具。
- main `argc==2` 才继续；**popen(3)/system(5) 命令全为硬编码**：`cat /proc/modules|grep wlan`、
  `rmmod wlan`、`insmod wlan.ko con_mode=5` 等；argv[1] 不进入这些命令。
- **关键自我纠正**：这条约束**不能否证复评**。复评的 `myftm; id` → `/vendor/bin/myftm ; id`
  是在**外层 `sh -c`** 层生效、绕过 myftm 的 getopt。myftm 内部约束只挡"作为其参数 token 传入"的 payload。
- ⇒ **复评"myftm 分支注入面静态开放"维持**；§20 判定不改。L3 未证，不上机。

### 21.2 新 P1（antirootdialog）—— 仍未闭合，新增线索

- 试过：apk classes.dex（只有 appdata）、oat odex/vdex（vdex021，提取内嵌 dex 无该类）、
  system.img 全文搜（2 处游离偏移不在任何文件内）、vendor/odm（仅 SELinux type 名）。**实现未解出**。
- **新增线索**：游离字符串上下文显示它是 **native 守护进程**：
  `/data/oplus/kevent` + `send_pid_to_kernel` + `$$pkgName@@%s`/`,payload@@%s` + `Field "uid" greater than UID...`；
  vendor SELinux 策略中 `anti_root_dialog_service` 是独立 domain。
- ⇒ 它不是纯 Java 服务，而是 **native + SELinux domain + kevent 内核接口**；把 pid/uid 下发内核做 anti-root 判定。
- **不臆测**，覆盖度维持 6/7；闭合需完整 factory 镜像或设备只读拉取（需授权）。

### 21.3 状态与下一步

- **整体 no-go / Conditional GO 不变**；§20 三层次与优先级不变（新 P0 已完成静态部分，新 P1 因物料不足暂停）。
- **不上机**：L3 唯一判据是授权下的 `uid=0` 现场回显；复评亦要求先审清再定。
- 若继续：① 授权上机验证 myftm 分支 L3（用户决策）；② 取完整镜像闭合 antirootdialog（用户决策）。
  冻结面（KGSL / binder CVE / FastRPC / GhostLock）无新原语，不动。

---

## 22. 增补：P1 同族 root 命令接口 + 过滤边界（2026-11-18，纯离线）

> 响应 `docs_archive/审核意见CHATGPT-v0021.txt` 第三节 P1 与第二节第 3 点。**未连设备、无写操作**。
> 完整证据：**`artifacts_adb/binder_audit/WIFI_P1_ROOT_COMMAND_AUDIT.md`**。
> 新工具：`tools/wifi_slot_audit.py`（vtable 枚举 + PLT 解析 + ADRP/ADD 字符串回填 + 全量 exec 扫描）。

### 22.1 九类 HIDL 命令全映射（vtable `@0x1a0a0`，slot2–10 = code1–9）

| 槽 | 地址 | 方法 | 签名 | 命令模板 | 过滤 |
|---|---|---|---|---|---|
| 2 | `0x90a0` | `changeConnectionMode` | `(int)` | `ifconfig wlan0 up` / `insmod … con_mode` | 无（int） |
| 3 | `0xad20` | `catchSnifferLog` | `(int,int)` | `tar … && rm -rf …`、`iwpriv wlan0 setMonChan <u32>` | 无（int） |
| 4 | `0x9684` | `resetConnectionMode` | `()` | 无（`kill`/`waitpid`/`SetProperty`） | — |
| 5 | `0x992c` | **`executeDriverCommand`** | `(String)` | ①`myftm <input[5:]>`（无过滤）②`iwpriv <input>`（regex） | ①无 ②有（不完整） |
| 6 | `0xa0dc` | `setupFTMdaemon` | `()` | `/vendor/bin/ftmdaemon` | 固定串 |
| 7 | `0xa568` | `sendSupplicantCommand` | `(String)` | `/vendor/bin/wpa_cli <input>` | 有（不完整） |
| 8 | `0xa898` | `runWiFiScript` | `(String,String)` | `/vendor/bin/<script> <arg>` | 前缀 + regex |
| 9 | `0xb2ec` | `sendIniContent` | `(String)` | 写固定 `/mnt/vendor/persist/ini_temp.txt` | 路径固定 |
| 10 | `0xb65c` | `getIniVersion` | `(String)` | `fopen(<input>,"r")` 回传内容 | **无** |

命令执行原语：**无 `system`/`popen` 导入**，只有两个 `vfork`+`execv` 包装器
（W1 `0x95b4`，9 个调用点；W2 `0xa390`，2 个），argv 均为 `{"/vendor/bin/sh","-c",cmd,NULL}`。

### 22.2 新发现（重要）：regex 黑名单不完整

`sub_9f64` 模式串 `@0x6dcb` 逐字节读出：`[@#$%&*^:;?|]+`，**仅 11 个字符**。
**缺**：`\n`(0x0A)、`\r`、反引号(0x60)、`<`、`>`、`\`、`"`、`'`、`(`、`)`、`{`、`}`、`!`、`~`。

⇒ 对 `sh -c` 而言 `\n` 是**命令列表分隔符**、反引号是**命令替换**、`>` 是**重定向**——
三者均可穿越校验。**因此注入面不依赖 `myftm` 五字节前缀**：

| 入参 | 组装结果 | 校验 | 预期 |
|---|---|---|---|
| `myft -h; id` | `/odm/bin/iwpriv myft -h; id` | `;` 命中 → `-3` | 拒绝（与历史一致） |
| `x\nid` | `/odm/bin/iwpriv x` ⏎ `id` | **通过** | 两条命令，均 uid 0 |
| `` `id` `` | ``/odm/bin/iwpriv `id` `` | **通过** | 命令替换先执行 |
| `x > /data/local/tmp/o` | 重定向 | **通过** | root 身份写文件 |

**历史 4 次失败实验的失败原因是"只试了 `;` 和 `|`"**，恰好在黑名单内；换行与反引号从未被尝试。
**这是静态推演，未上机**；但它是当前 Wi-Fi 面最强的 L2 表述。

### 22.3 更正：iwpriv 分支不做整数转换

旧 §5 表与 `WIFI_P0_PARAMETER_TRACE.md` §5 写的"iwpriv 分支 `to_string(int)`、模板
`/odm/bin/iwpriv wlan0 setMonChan <int>`"**不成立**：

- 该分支在 `0x9b38 → 0x9d58` 把 `c_str()` 的**整条原始入参**追加到 `/odm/bin/iwpriv ` 之后，无 `atoi/strtol/to_string`；
- `setMonChan <u32>` 模板（`@0x6b6d` + `to_string` ×3）属于 **slot3 `catchSnifferLog`**，此前被混为同一分支。

`-3` 归因不变（regex 命中/参数非法），但"参数被整数化所以安全"的解释从根上不成立。

### 22.4 复评 P1 三接口：全部不构成新攻击面

全 dex 方法体检索 + 全 jar 二进制串检索（`runWiFiScript`/`sendSupplicantCommand` 仅出现在
`oppo-wifi-service.jar` 自身）：

| 接口 | Java 调用方 | 判定 |
|---|---|---|
| `executeDriverCommand` | `helper.sendFTMCommand`（唯一） | **shell 可达**（tx 10070） |
| `catchSnifferLog` | `OplusWiFiSnifferModeManager$1`（`(int,int)`） | 仅 system_server 内部；int 入参，无注入面 |
| `runWiFiScript` | **无** | 死入口 |
| `sendSupplicantCommand` | **无** | 死入口 |
| `sendIniContent`/`getIniVersion` | `OplusWifiNative`（上层无 AIDL） | 不可达 |

⇒ 复评"不能仅凭 myftm 结论认定整个 root HIDL 服务安全"的关切**成立**，但**逐一核实后无新增可利用面**；
真正的风险仍在 `executeDriverCommand` 本身（§22.2）。

### 22.5 潜在项：`getIniVersion` 任意 root 读

`0xb6f4 → 0xb7d8`：入参无前缀校验，直接 `fopen(path,"r")` 并回传文件内容。
当前不可达（无 Java 调用方）；但一旦出现"可调用该 HIDL 的 system 上下文执行点"（§16.6 重开条件），
它会立刻成为**信息泄露**原语——而项目最大阻断点恰是"缺内核地址泄露"。**建议并入 §7 重开条件观察项**。

### 22.6 状态与下一步

- **整体 no-go / Conditional GO 不变**；L1 已证、L2 加强、**L3 未证**（本轮纯离线）。
- **不上机**：L3 唯一判据仍是授权下的 `uid=0` 现场回显（§16.11）。
- 建议的最小验证设计（授权后）：tx 10070 发 `x\nid` → 观察 `uid=0`；失败则改测反引号；
  只写 `/data/local/tmp`，单次调用，不留驻留物。
- 未穷尽项（诚实登记）：`runWiFiScript` 两参数组装顺序按调用序判读未逐字节展开；
  W2 的 argv 未逐字节展开；`framework.dex`/`oplus-framework.dex` 因 androguard hiddenapi 解析失败被跳过
  （已用二进制串检索兜底）；换行/反引号的 shell 行为属静态推演。
- 复评剩余的 antirootdialog（新 P1）仍因物料不足暂停，需完整 factory 镜像或设备只读拉取（授权）。
