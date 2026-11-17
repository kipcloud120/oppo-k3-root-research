# OPPO K3（PCGM00 / C.17）利用 CVE 解锁 Bootloader 可行性分析

> **版本失效声明（2026-11-13，依据实机 ADB 复核）**
> 本文基于 **C.17** 基线（ColorOS 7.1 / Android 10 / 内核 4.9.186 / SPL 2021-05-05）编写。实机 ADB 已确认设备运行 **PCGM00_11_F.16**（ColorOS 11.1 / Android 11 / 内核 4.9.227-perf+ / SPL 2022-04-05，构建 2025-03-26，fingerprint 尾号 `1704167642389`）。
> 本文中的镜像哈希、boot/vbmeta 数值、内核符号与偏移、CVE 补丁窗口，以及任何针对 C.17 的操作指令，**对本机全部作废**，不得用于本机判断；与版本无关的采集命令、分析方法论仍可参考。
> 当前有效基线：`F16_基线_与C17结论失效说明.md`；当前固件镜像：`firmware_F16/`；获取与清理记录：`F16_固件获取与C17清理记录.md`。

- 编制日期：2026-11-12
- 依据：`OPPO_K3_机型代号与ROOT生态调查汇总.md`、`ROOT_实施方案.md`、`github_research.md`、`unpacked_C17/kernel_config.txt`（本机内核配置实测）、联网检索（CVE 数据库 / 安全研究博客 / XDA / 厂商公告）
- 结论等级：**【实】** 已核验一手来源或本机文件；**【推】** 推断；**【源】** 来自公开索引，未逐一核验原文

---

## 0. 结论先行（TL;DR）

1. **近期所有"OPPO 利用 CVE 解锁 BL"的新闻/教程，目标都不是 K3，且没有一个能迁移到 K3。**
   - `CVE-2026-43499`（GhostLock，Futex PI UAF）：**Linux 4.9 在漏洞的"含缺陷代码"理论影响范围内**，且经本机实测 K3 的 4.9.186 内核**确含缺陷代码**（2021 构建不可能含 2026 修复，详见 §3.4）。但实际可被利用的已验证设备全部是天玑 9400 / 骁龙 8 至尊版（SM8750/8845/8850）、GKI 6.6/6.12、ColorOS 15–16；K3 的 4.9 非 GKI 内核因**栈布局 / 编译优化（PGO+LTO）/ 结构体偏移差异**，现有 Exploit **不能直接移植**，需针对 K3 做专属适配。即使成功，也仅提供运行时 root，不等于 BL 解锁。
   - `CVE-2025-21479`（Adreno KGSL）：目标内核 `5.10.198-android12`、ColorOS 新机型。K3 是 Adreno 616 + 内核 4.9，KGSL 代差，不适用。
   - `CVE-2025-20658`（联发科 USB heapb8）：**MTK** 天玑 9400。K3 是高通，不适用。
   - `CVE-2017-5626`（一加 3/3T OxygenOS bootloader oem 命令）：**一加/氧 OS** 专属，非 OPPO ColorOS LK，不适用。
2. **与 K3 同平台（sdm710）或同启动链的 Qualcomm CVE，要么不命中 SoC，要么在 2021 固件里已被修复：**
   - `CVE-2019-2267`（Qualcomm 安全启动加载器越权改锁定的内存）：**命中 sdm710**，但"2020 年 1 月补丁前版本"，C.17 为 2021-05 SPL，已含修复 → 不适用。
   - `CVE-2017-18305`（XBL 安全内存转储 → EL3）：命中列表为 MDM9x/SD210/SD835 等，**不含 sdm710** → 不适用。
   - `CVE-2026-25262`（Qualcomm BootROM Sahara Write-What-Where）：命中 MDM9x07/8909/8916/8952/SDX50 等，**不含 sdm710** → 不适用。
3. **唯一"版本号在范围内"的通用内核 LPE 是 `CVE-2021-22555`（netfilter xt_compat 堆越界写）：K3 内核 `4.9.186 < 修复版 4.9.267`。但本机 `CONFIG_USER_NS` 未开启，标准利用链（依赖非特权 user namespace 取得初始上下文）被阻断；且无公开的非 userns 变体在 Android 4.9 上验证可用。**
4. **最关键的一点——即使拿到临时 root，也仍然解不开 BL。** 临时 root（任何内核 LPE）只能拿到 uid=0 + capabilities，但 K3 的 BL 解锁闸门是写在 `oplusreserve1/reserve1` 分区的、**由 OPPO 服务器私钥签名的令牌**，由 ABL（`abl.img`）在 fastboot 阶段读取并 RSA 校验。没有私钥就无法伪造令牌；2023 年那种"改机型名骗服务器发旧结构令牌"的漏洞在 OPPO/realme 已失效（新结构令牌绑定机型）。

> **综合判定：当前不存在公开的、可靠的、基于 CVE 直接解锁 K3 Bootloader 的方法。** 任何声称"OPPO 用 CVE 解锁"的教程，对 K3 都属误用。

---

## 1. 本机环境基线（判据来源）

| 维度 | 实测值 | 来源 |
|---|---|---|
| SoC | 高通 **sdm710**（骁龙 710） | 汇总 §1.2 |
| 内核 | **`Linux/arm64 4.9.186`**，CONFIG_LOCALVERSION=-perf | `unpacked_C17/kernel_config.txt`【实】 |
| 内核形态 | **非 GKI**（Android 10 时代 4.9 主线，非 5.x/6.x Google GKI） | 推断（版本 + 年代） |
| `CONFIG_USER_NS` | **未设置**（`# CONFIG_USER_NS is not set`） | `kernel_config.txt`【实】 ← CVE-2021-22555 阻断点 |
| `CONFIG_NET_NS` | `=y` | `kernel_config.txt`【实】 |
| `CONFIG_NETFILTER_XTABLES` | `=y`（netfilter 编译进内核，CVE-2021-22555 代码路径存在） | `kernel_config.txt`【实】 |
| 安全补丁级别 | **2021-05-05** | 汇总 §9.3【实】 |
| BL 解锁机制 | 深度测试（Deep Test）→ 服务器发令牌 → 写 `reserve1` 分区 → ABL 校验 | deepwiki `zenfyrdev/bootloader-unlock-wall-of-shame` / XDA【源】 |

---

## 2. CVE 适用性判定总表

| CVE | 类型 / 目标平台 | 是否命中 K3 | 判定 |
|---|---|---|---|
| **CVE-2026-43499** GhostLock | Futex PI UAF；理论影响含 Linux 2.6.39~7.1（含 4.9）；实测利用：SD8 至尊版/Gen4，GKI 6.6/6.12，ColorOS 15–16 | 4.9 在理论范围、且实测 K3 含缺陷代码；但 K3 不在已验证/可行设备，Exploit 需针对 K3 栈布局/偏移专属适配 | ⚠️ 缺陷代码已确认存在；可利用性待专属适配 |
| **CVE-2025-21479** | Adreno KGSL；内核 5.10（android12） | K3=Adreno616+4.9 | ❌ 不适用 |
| **CVE-2025-20658** | MTK USB（天玑 9400） | K3=Qualcomm | ❌ 不适用 |
| **CVE-2017-5626** | 一加 OxygenOS bootloader oem 命令 | 非 OPPO/ColorOS | ❌ 不适用 |
| **CVE-2019-2267** | Qualcomm 安全启动加载器越权；**命中 sdm710** | SoC 命中，但 2021 固件已含 2020-01 修复 | ❌ 已修复，不适用 |
| **CVE-2017-18305** | XBL 内存转储 → EL3；命中 SD835 等 | **不含 sdm710** | ❌ 不适用 |
| **CVE-2026-25262** | BootROM Sahara Write-What-Where；命中 MDM/8xx/SDX50 | **不含 sdm710** | ❌ 不适用 |
| **CVE-2021-22555** | netfilter xt_compat 堆越界写；影响 2.6.19+，修复于 4.9.267 | **版本号在范围内（4.9.186<4.9.267）**，但 `USER_NS=n` 阻断标准利用 | ⚠️ 理论上在范围内，实际上被阻断 |

---

## 3. 逐个分析

### 3.1 近期"OPPO CVE 解锁"系列（看起来相关，实则全不命中）

- **CVE-2026-43499 / GhostLock**【实】：漏洞本身是 Linux `rtmutex` Futex PI 的 UAF（commit `3bfdc63936dd`，主线 7.1 修复）。NVD 把受影响范围写成 `2.6.39 ≤ x < 6.1.175`（**含 4.9 区段**），即 4.9 内核**存在缺陷代码、处于"含缺陷代码"的理论影响范围**；这是代码层面的范围，不等于"现有 Exploit 可直接利用"。
  **K3 是否实际可被利用，取决于两点**：(a) **OPPO 是否在其 4.9.186 内核上反向移植了该修复**——ColorOS 7.1 的 4.9 是厂商长期维护分支，OPPO 可能已 backport，需逐 commit 核验才能下结论（不能仅凭版本号断言"未被修补"）；(b) **现有 Exploit 能否移植**——Sploitus `EF362A0F-7149`、Kitploit `GhostLock-for-OnePlus` 的"已验证设备表"全部是 GKI 6.6/6.12 + SM8750/8845/8850（一加 15/Ace6T、OPPO Pad 4 Pro、小米 17 等），并明确标注"栈布局不兼容 → Not Feasible"；K3 的 4.9 非 GKI 内核在**内核栈布局、编译器优化（PGO+LTO）、`rt_mutex_waiter` 等结构体偏移**上都与这些设备不同，公开 Exploit **不能直接用于 K3**。
  **结论**：目前**没有可靠证据**证明 K3 能够通过现有 GhostLock 方案获得 Root；要确认可行性，必须对 OPPO 的 4.9.186 内核做针对性适配（提取 `pselect6` / `futex PI` 路径偏移、验证栈帧布局），工作量等同于一次独立的漏洞利用开发，而非"下载即用"。
  更重要的一点：**即便成功利用，该漏洞只提供运行时 Root 权限（重启即失），并不意味着 Bootloader 解锁。** 这套方案的完整链条是「内核 UAF 临时 root → 刷修改过的 `lk.img` 强制开 fastboot → `fastboot flashing unlock`」。K3 **本来就有 fastboot**（深度测试进入），它的真正闸门是 reserve1 令牌，不是"fastboot 缺失"，所以即使有 root，也没有 K3 专用的 `lk.img` 和令牌格式可用。

- **CVE-2025-21479**【实】：Adreno KGSL 微码命令越权，目标内核 `5.10.198-android12-9`（OPPO Find X5 Pro）。KGSL 驱动在 4.9 与 5.10 间是不同代际，K3 的 Adreno 616 不在受影响路径。**不适用。**

- **CVE-2025-20658 / heapb8**【源】：联发科 USB 底层协议缺陷（Chimera 工具），目标天玑 9400。**K3 是高通，完全无关。**

- **CVE-2017-5626**【实】：一加 3/3T 氧 OS 的隐藏 `fastboot oem 4F500301/4F500302` 命令可绕过 OEM unlocking 锁 BL。这是一加 ABOOT 专属实现，OPPO/ColorOS 的 LK/ABL 不是同一套。**不适用。**

### 3.2 平台相关（Qualcomm sdm710 / 启动链）CVE

- **CVE-2019-2267**【实】：Qualcomm 安全启动加载器（XBL 类）越权修改锁定内存区域，受影响 SoC **明确含 SDM710**，修复时间为"2020 年 1 月安全补丁前"。K3 固件为 2021-05 SPL，**XBL/ABL 已包含该修复** → 在 C.17 上不可利用。列出它是因为它**是唯一一个 SoC 层面真正命中 K3 的启动链 CVE**，可作为"若你刷的是极老固件"的备注，但对 C.17 无意义。

- **CVE-2017-18305**【实】：XBL 安全内存转储系统调用 → EL3，命中 MDM9206/9607/9650、SD210/212/205、**SD835** 等，**列表不含 sdm710**（K3 是 710）。**不适用。**

- **CVE-2026-25262**【实，Kaspersky ICS CERT / Black Hat Asia 2026】：Qualcomm BootROM（PBL）内 Sahara 协议 `0x13` 状态机 Write-What-Where。命中 **MDM9x07/9x45/9x65、MSM8909/8916/8952、SDX50**，**不含 sdm710**。这是"皇冠上的明珠"级的 BootROM 洞，但 K3 的 SoC 不在受影响系列。**不适用。**

- 补充（架构层面）：FiimeROM 对高通启动链的分析指出，EDL/Sahara 的历史栈溢出（32 位 PBL ROP）在 64 位 SoC（SDM845/SM8150 起）已被 PBL 内 MMU + XN 硬件缓解；而 sdm710 是 64 位，属于被强化的一代。进一步降低 EDL 软件绕过的可行度。

### 3.3 通用内核 LPE（唯一"版本号在范围内"者）

- **CVE-2021-22555**【实】：netfilter `xt_compat_target_from_user` 堆越界写，影响 Linux ≥ 2.6.19，修复于 `4.9.267 / 4.14.231 / 5.4.113 / 5.10.31 / 5.12`。**K3 内核 `4.9.186` 确实早于修复版**，且 `CONFIG_NETFILTER_XTABLES=y` 说明缺陷代码路径存在 → 版本号层面命中。
  **但阻断点**：公开利用（theflow/Google Project Zero 的 writeup、Exploit-DB、Metasploit、Kitploit `letsr00t/cve-2021-22555`）都依赖**非特权 user namespace**（`CLONE_NEWUSER` + `CLONE_NEWNET`）来取得初始 netfilter 操作上下文。本机 `kernel_config.txt` 实测 **`# CONFIG_USER_NS is not set`** → 标准利用链在 K3 上无法 bootstrap。无公开验证的"非 userns"4.9 Android 变体。
   → 判定：**理论上在范围内，实际上被 `USER_NS=n` 阻断**；若要强行利用，需要自行改写出一个不依赖 userns 的触发路径（从 32 位 compat 进程 + 已有 CAP_NET_ADMIN 入手），但锁定的 Android 上无初始特权，工程量与不确定性极高，**不推荐作为可行路线**。

### 3.4 补充实测：K3 的 4.9.186 是否含 CVE-2026-43499 修复（2026-11-12 追加）

为回答 §3.1 留下的"OPPO 是否反向移植了修复"这一开放项，对 `unpacked_C17/kernel.decompressed` 与 `kernel_config.txt` 做了实测核验：

- **内核身份确认**【实】：在二进制中检索到明文 banner `Linux version` 及 `4.9.186`（偏移 18350214 等），并出现设备构建串 `K3`/`K3M`。→ 本镜像确为 K3 的 **4.9.186** 内核，与配置头一致。
- **缺陷代码路径存在**【实】：`kernel_config.txt` 实测 `CONFIG_FUTEX=y`、`CONFIG_RT_MUTEXES=y`、`CONFIG_KALLSYMS=y`、`CONFIG_KALLSYMS_ALL=y`。futex PI 与 rt_mutex 均已编译进内核，CVE-2026-43499 所涉调用链（`futex_requeue` → `rt_mutex_start_proxy_lock` → `remove_waiter` 回滚路径）在 4.9 中天然存在。
- **补丁回溯判定（关键）**【推，依据构建时间线】：修复 commit `3bfdc63936dd`（"rtmutex: Use waiter::task instead of current in remove_waiter()"）于 **2026 年**进入主线 7.1 并向下 backport（6.12.86 / 6.6.140 / 6.1.175 等）。而 K3 固件构建于 **2021-05**（SPL 2021-05-05），比修复早约 5 年，**物理上不可能包含该修复**。故 K3 的 4.9.186 内核**确含缺陷代码、处于"实际缺陷存在"状态**——这正是 NVD 把 4.9 列为受影响区段的原因。

**结论更新**：就 CVE-2026-43499 而言，K3 已从"待定"转为"缺陷代码存在、已确认"；真正剩下的 100% 是**可利用性（Exploit 移植）**——现有 GhostLock Exploit 针对 GKI 6.6/6.12 设备做了偏移与栈布局适配，K3 的 4.9 非 GKI 内核需在 `pselect6` / `futex PI` 路径上重新提取偏移、验证栈帧布局，工作量等同一次独立漏洞利用开发。且**即便成功，仍只是运行时 root，不等于 BL 解锁**（见 §4）。

> 进一步的"代码级"确认（如反编译 `remove_waiter` 比对修复前后差异、解压 kallsyms 表核对符号）可做，但受 2021-vs-2026 时间线约束，结论方向不会变；上述配置 + banner + 时间线已足以高置信判定。

---

## 4. 关键认知：临时 root ≠ 解锁 Bootloader

这一点必须单独强调，因为它决定了所有内核 LPE 的天花板：

1. **OPPO/realme 解锁机制的本质**【源，deepwiki + XDA】：
   - 深度测试 App → 向 OPPO 服务器申请 → 服务器下发**用 OPPO 私钥签名的令牌** → App 把令牌写入 **`(oplus/oppo)reserve1`** 保留分区；
   - 设备进入 fastboot，ABL（`abl.img`）读取 reserve1 的令牌并做 **RSA 校验**；校验通过才放行 `fastboot flashing unlock`。
2. **2023 年的"服务器绕过"已死**【源，XDA 长帖】：
   - 旧方案（turistu 的 Perl 脚本）靠把机型名改成受支持机型、保留真实 IMEI/SN 骗服务器发"旧结构"令牌，ABL 旧校验只比对 IMEI/SN/签名；
   - 2023-05-26 起 OPPO/realme 强制服务器只发"新结构"令牌（**绑定机型**），ABL 切换到新校验（含机型比对），旧脚本彻底失效。
3. **结论**：拿到内核 root 也**伪造不了服务器私钥签名的令牌**，因此无法让 ABL 放行解锁。**任何"临时 root"教程都明确声明它不解 BL**（见 `githubskylh/awesome-android-root` 的临时 root 指南）。K3 的解锁闸门是密码学令牌，不是内核权限。

### 4.1 为什么临时 root 也"改不掉 BL 解锁标识位"

常见误区是把"Linux 内核里的 root"等同于"能控制 Bootloader"。二者是不同执行上下文，解锁状态由 Bootloader（ABL，EL1，先于 Linux 启动并独立运行）掌管，且有层层防护：

1. **执行上下文隔离**：临时 root 是 Linux 内核态（EL1）的权限提升，作用域仅限已启动的 Linux。ABL 在 Linux 之前就已跑完解锁校验；root 既不能"回溯"指挥已经执行过的 ABL，也无法在下次开机时代替 ABL 做裁决。
2. **权威状态在 RPMB / 签名令牌，不在内核可写处**：OPPO/realme 的锁状态权威来源是 `reserve1` 分区里**OPPO 私钥签名的令牌**（ABL 启动时 RSA 校验），型号/IMEI/SN 等敏感信息存于 **RPMB**（Replay Protected Memory Block，出厂写入独立密钥，内核/Linux 拿不到该密钥、无法改写）。你能 `dd` 写普通分区，但①写不出有效的 RSA 签名令牌，②写不了 RPMB。
3. **临时 root 非持久**：GhostLock / CVE-2025-21479 一类是纯内存利用，重启即失。即便某处标志位能写，下次启动 ABL 仍按权威状态重新裁决，root 早已不在。
4. **能"骗"的只是内核自己的视图，不是 Bootloader**：root 可运行时改写内核内存，把 `verifiedbootstate` 伪装成 orange/unlocked、把 `selinux_enforcing` 置 0、内存里关掉 dm-verity——这用于运行时取证/调试，但**不等于 Bootloader 已解锁**，也**不能借此用 fastboot 刷未签名镜像或持久启动自定义 recovery**。
5. **改 ABL 会被安全启动拦下**：唯一"根上"的办法是 root 后 `dd` 写一份"跳过令牌校验"的修改版 `abl` 分区。但 ABL 由 XBL/TrustZone 在启动时做签名校验（Secure Boot），被改动的 ABL 通不过验证、设备无法启动；且 K3 没有公开的、去令牌校验的专用 abl 镜像。

**结论**：在 BBK（OPPO/realme）这套"服务器签名令牌 + ABL 校验"的设计下，本地 root 既不能伪造令牌、也写不了 RPMB、还跨越不了 BL 上下文，因此**无法直接翻转 BL 解锁标识**。这也正是 2023 年后官方把令牌升级为"机型绑定新结构"、彻底堵死"本地改值 / 骗服务器"路径的原因——临时 root 对解锁 K3 的 BL 没有实质推进作用。

### 4.2 深度测试（Deep Test）的机制本质，与"非深度测试"解锁渠道的区别

直接回答"深度测试只有官方渠道，没有其他渠道？"——要把**两种不同问题**分开：

- **问题 A：深度测试（Deep Test）本身有没有非官方渠道？** 没有。深度测试的本质是"OPPO 服务器用 OPPO 私钥签发令牌 → 写入 reserve1 → ABL 校验"。令牌必须由 OPPO 官方服务器用其私钥签发，**不存在"非官方深度测试"**——任何声称"unofficial deep test"的说法，要么是指下面问题 B 的绕过方案，要么就是骗术。2023 年那种"改机型名骗服务器发旧结构令牌"的绕过（turistu 脚本）已被 OPPO/realme 强制"机型绑定新结构令牌"堵死（§4 已述）。所以从机制上，**深度测试 = 只能走 OPPO 官方服务器**，没有平行的非官方深度测试通道。

- **问题 B：解锁 Bootloader 是不是只有深度测试这一条路？** 不是。存在**完全绕过深度测试**的"非官方"解锁渠道，它们不依赖 OPPO 服务器发令牌，而是在更底层动手：
  1. **EDL/9008 + 修改版 ABL/OCDT（"欧加秒解" / 某贼高通工具箱 / Eugas 解锁包）**：经 9008 紧急下载模式刷入跳过 reserve1 令牌 RSA 校验的修改版 `abl_unlock.img`/`ocdt_unlock.img`，从而让 ABL 放行 `fastboot flashing unlock`。XDA 已验证此法适用于**骁龙 778G/782G/865/870/8Gen2** 的 OPPO/真我机型（K9S、Reno7/9/10、K11、Q3S、GT 大师版、Find X2/X3、GT5、Find N3/X6 Pro 等）；ROM乐园亦称第三方可强制解锁 OPPO 骁龙 **865/888/870/8Gen2/8Gen3**（最高到 Find X7U）。**关键：这些清单里都没有 sdm710 / K3**（与 §5.1 的离线工具包核验一致）。
  2. **联发科（MTK）路线**：对 OPPO MTK 机型可用 `mtkclient` / `oppo-mtk-fastboot-unlock` / `lkpatcher` 解锁（改 preloader/boot1 或 SECCFG）。但 K3 是高通 sdm710，**不适用**。
  3. **内核漏洞临时 root → GBL chainload（如 Find X9 Ultra 的 CVE-2026-43499 方案）**：先拿临时内核 root，再 chainload 一个特殊 bootloader 环境去 `fastboot oem oem-unlock-toggle` + `flashing unlock`。此路对 K3 不成立（4.9 非 GKI 不可移植 + 仅临时 root，且需机型专属镜像，见 §3.1/§3.4）。

- **对 K3 的结论**：
  - 深度测试（官方）是**唯一**在"机制上可能仍对 K3 开放"的渠道；
  - 所有"绕过深度测试"的非官方方案（EDL+修改 ABL、MTK 路线、GBL chainload）**都明确不覆盖 sdm710/K3**；
  - 因此 K3 在现实上**实际只剩官方深度测试这一条可能的路**——若它已随官方名单停更而关闭，则 K3 当前无任何可用解锁渠道（官方或非官方均无）。

> **补充（2026 现状交叉核验，修正此前偏保守判断）**：OPPO 深度测试 APK（`com.coloros.deeptesting`）的多个 2026 镜像站（西西/5577/87G/多特等）仍把 **K3（PCGM00，C.07+）列为支持机型**；ROM乐园亦称 OPPO"老机型（Find X3/Reno6 及更早）基本申请即可成功，审核约 1 个月"。即 K3 的深度测试**很可能仍可用**（而非已死），这比 §6 原先"可能仍存在"的措辞更乐观——**强烈建议优先在真机实测**，而非押注已证伪的 CVE 或已排除 sdm710 的灰产 EDL 方案。

---

## 5. EDL / 9008 路径评估（不是 CVE，但是最实在的硬件后门）

- 原理：sdm710 支持 EDL（9008）模式，进入后可经 Sahara + Firehose 协议对 eMMC/UFS 做任意读写，理论上可越过 BL 直接写 `reserve1`、`abl`、`boot` 等分区，甚至改写解锁状态。
- **GitHub 实测检索（2026-11-12，gh API）**【实】：
  - `search/repositories q="OPPO firehose"` → total 1（ncrom1902-dev/ncunlock-services，Xiaomi/Redmi 向，非 OPPO K3）；`q="sdm710 firehose"` → **0**。
  - `search/code q="CPH1955 firehose"` / `q="PCGM00 firehose"` / `filename:prog_ufs_firehose_sdm710 + OPPO` → **全部 0 命中**。
  - 即 **GitHub 上不存在 OPPO K3（CPH1955/PCGM00）专属、或 OPPO 签名的 sdm710 免鉴权 firehose**。
- **现存的 sdm710 firehose 与 K3 不匹配**【源/实】：
  - 通用 `prog_ufs_firehose_sdm710_ddr.elf` 出现在 Chernobylll/FireHouse_UFS、cfirmware.com 等集合——属**通用/他厂签名** loader，**非 OPPO 签名**，在 OPPO 的 SLA 鉴权步骤会被拒。
  - 小米 Mi CC9 / Mi 9 Lite 的 sdm710 "no need auth" firehose 明确是**小米签名**，仅适用小米设备。
  - Chernobylll 集合里另有 `prog_firehose_ddr_fwupdate_cph1853.elf`（CPH1853 = OPPO A3s，**另一款 OPPO 机型**），说明 OPPO firehose 是**按机型签名、鉴权绑定**的；即便能拿到也非 K3 专用，且同样受 SLA 约束。
- **K3 的刷机被 SLA 鉴权锁死**【源，ROMProvider / onfix】：OPPO K3 PCGM00 的 MSM Download Tool 为 **SLA Enable device，必须用授权 OPPO 账号**；onfix 明确写道"OPPO 自 2017 年 6 月左右开始对后续机型刷机工具加密，需要登陆账号刷机，**暂无法破解**"。
- **熔断风险**【汇总 §4.4，不确定项】：OPPO 对部分较新平台（865/870/8Gen）推送"熔断包"使 9008 免授权路径永久锁死；sdm710（K3）是否受影响**未见明确记录**。
- **判定**：**EDL/9008 对 K3 而言被 OPPO firehose SLA 鉴权（及可能的熔断）挡死，GitHub 上没有任何 K3 可用的免鉴权 sdm710 loader 实锤。** 即便能进入 9008 端口，也卡在 Sahara/SLA 鉴权这一步（需 OPPO 私钥签名的 loader 或授权账号）。此路线当前不可行，只能作为"若日后出现 OPPO sdm710 泄漏 loader / 鉴权绕过"的保留项，且属高风险的灰产/维修圈资源，不在公开研究范围内。

### 5.1 离线工具包 REF 实证（2026-11-12 追加）：本地确有 OPPO sdm710 loader，但非"免鉴权"

为回应 §5 开头"GitHub 上是否有 OPPO sdm710 免鉴权 firehose"的追问，本工作区 `REF/` 资料包中出现了相关实物，需单独核验其鉴权属性与对 K3 的可用性：

- **发现：`REF/高通工具箱-2026.9.28-1/bin/tool/qctool/oppo/devprg_710`（693304 字节）**【实】：一个**确为 OPPO 品牌、sdm710 平台的高通 Firehose loader**。`xxd` 头部为 `7f 45 4c 46 02`（ELF64），`e_machine=0xb7`（EM_AARCH64）；二进制内检索到 `QUALCOMM`/`XBL`/`ABL`/`Secure Boot`/`AUTH`/`auth`/`signature` 等字符串 → 标准 Qualcomm firehose programmer，且**内含鉴权/SLA 相关代码路径**。
  - **关键判定——它"免鉴权"吗？否。** 同工具箱 `mi_noauth/` 目录下的 `devprg_710_emmc`(717884B, 2018) / `devprg_710_ufs`(722160B, 2024) 被**显式冠以 `mi_noauth`（小米免鉴权）**标签，是小米签名、无需 SLA 的 loader；而 OPPO 这份放在 `oppo/` 下、**无任何 `noauth` 标签、同目录也无 `sig.dat`/`Digest.mbn`/`conf.xml` 鉴权套件**与之配对（对比 `oplus_8g2/` 的 `Digest.mbn`+`sig.dat`+`conf.xml` 完整签名套件）。OPPO 家族设备（含 K3）走 SLA 在线鉴权，本工具箱 `oplus_test/` 目录的 `说明.txt` 直接记录了 SLA 握手流程（`devprg → digest 挑战 → getsigndata → sig 签名应答 → verify`），证明欧加（OPPO/一加/真我）设备**必须先过 SLA 才能下发命令**。`devprg_710` 只是 OEM 签名的"裸 loader"，它本身仍要在 Sahara/SLA 阶段被设备用 OPPO 根信任校验、并需要授权签名服务应答挑战——**因此不构成"免鉴权 firehose"**。
  - **对 K3 可用性**：即便持有该 loader，K3 为 SLA Enable device（§5 已证），在 9008 下会卡在 SLA 鉴权；而离线 `oppo/` 目录下的裸 loader 没有内置 SLA 应答能力，需依赖灰产远程签名服务（见下"解锁教程.txt"仅为一知乎链接 + 云群聊）。**结论：此 loader 不解决 K3 的 EDL 鉴权闸，仅供"已获 SLA 授权"场景下刷同平台 OPPO 设备，对 K3 无直接可用价值。**

- **"欧加秒解资料包"：ABL/OCDT 修改式解锁，平台覆盖**【实】：
  - 机制：`abl_unlock.img`（1MB，修改版 ABL，跳过 reserve1 令牌 RSA 校验）+ `ocdt_unlock.img`（128KB，修改版 OCDT），经 EDL 刷入以绕过 BL 解锁令牌门。
  - 覆盖平台**逐一核对**：8Gen2（Find N3 / Find X6 Pro / realme GT5）、888（Find N / realme GT/GT2）、865（Find X2/X2Pro/Ace2/Reno5Pro+/X50Pro）、870（Find X3/Reno6Pro+/Pad/Q5Pro/GT Neo2/GT大师探索版）、778G/782G（Reno7/9/10、K9S、K10活力版、K11、Q3S、GT大师版）。**全部为骁龙 8 系 / 7 系新平台，不含 sdm710，也不含 K3/PCGM00**（已用 `grep -iE "710|k3|pcgm00"` 对全目录名核验，0 命中）。
  - **对 K3 可用性**：该资料包的"秒解"方案**完全没有 K3/sdm710 的修改版 ABL/OCDT**。即便能从 SLA 授权拿到 EDL 写入权限，也**没有 K3 专用镜像可刷**；把 8 系/7 系的 `abl_unlock.img` 移植到 sdm710 需要 K3 的 ABL 源码/重建与 reserve1 布局逆向，工程量等同于从零开发，且不在此包内。

- **"解锁教程.txt"本质是灰产服务入口**【实】：内容仅为一行知乎专栏链接（`zhuanlan.zhihu.com/p/1911733731930116121`）+ 一行云湖群聊邀请（`yhfx.jwznb.com/...` 群 ID 317535392）。即该"秒解"并非自助方法，而是**付费/授权的远程解锁服务**——上游由受控的 SLA 签名后端 + 机型专属 abl 镜像支撑，K3 既不在其镜像覆盖、也无公开自助路径。

**REF 分析综合判定**：本工作区离线资料**并未提供 K3 可用的 BL 解锁路径**。`oppo/devprg_710` 的存在只是把"GitHub 上无公开 OPPO sdm710 firehose"这一结论**修正为"公开无、但离线灰产工具包中有 OPPO 签名 sdm710 loader"**——而它**仍受 SLA 鉴权约束、非免鉴权**，故不改变 §5 的核心结论：K3 的 EDL 路线被 SLA 挡死、不存在可用的 no-auth loader；而"欧加秒解"的 ABL/OCDT 修改方案平台覆盖到 8/7 系、**独缺 sdm710/K3**。两条离线线索都指向同一个现实：**K3 的解锁缺口（sdm710 平台 + SLA 锁定 + 无专属修改镜像）未被任何现有资料填补**。

### 5.2 社区 2026 现状汇总（AdaUnlocked 仓库）交叉核验：K3/sdm710 完全未被收录

为回答"2026 年 OPPO 是否仍有可能解锁"这一广义问题，核验了社区维护的《2026 全品牌 BL 解锁与 Root 现状汇总》（`AdaUnlocked/2026-All-Brands-Bootloader-Unlock-Status`，末次更新 2026-10-23，含 4 个历史快照 `README_26_01_16/04_05/06_13/07_14`，已全量下载本地核验）：

- **K3 / sdm710 / PCGM00 在所有快照中零命中**【实】：对全部 5 个 README 变体做 `grep -ainE "710|sdm|骁龙7|K3|PCGM00|K3M"`（已确认 grep 对同文档的 `865`/`870`/`OPPO` 可正常命中），**结果全空**。该指南聚焦 ColorOS 15/16 时代机型（Find X9/X8、Reno 16/14/13/12/11/10、K15/K13、X7U/X6P/N3、Pad 5 Pro 等），**完全未跟踪 2019 年的 K3（ColorOS 7.1 / sdm710）**。
- **OPPO 老机型"免授权 9008"列表明确排除 sdm710**【实，README.md L478】："能免授权的几乎所有 OPPO 老机型，8+、782G、778G、768G、865、870 等，均已推送熔断包"——列出的可免授权 9008 老平台为 **8+/782G/778G/768G/865/870**，**不含 sdm710**。即 K3 不在该指南认定的"免授权 9008 可解老机型"范围内。
- **深度测试解锁仅覆盖"非常老"机型且 a 系列不支持**【实，L479】："部分一加回归时期的老机型可以深度测试解锁……a 系列全系不支持……该方式支持的机型往往非常老"——K3 不在此显式列表，且与其"深度测试名单末次更新 2021-11-22、2026 支持机型极少"的既有结论一致（汇总 §4.4）。
- **OPPO 整体趋势：熔断（永久熔断）愈演愈烈**【实，L445–L478】：865/870 升过 25 年补丁即终身熔断；X7U/X6P/N3 升过 `16.0.3.5xx` 即终身熔断；9400/9500/9300/9200/9000 系更新即熔断无解；连已停更的"老机型"OPPO 也特意推小更新做熔断。**这进一步印证：OPPO 的解锁环境随时间只会更严，K3 在 2019 年关闭的官方深度测试渠道几乎不可能在 2026 重开。**
- **该指南的性质提示**【推】：其"可解"结论高度依赖酷安/某贼生态的灰产工具（上之湖水、悲伤压缩包、AC极光、某贼）与"免授权 9008 / SLA 授权 / 不升级到熔断版本"的脆弱窗口，并非官方合法渠道；且指南明确定义"降级无效的解熔断、依赖付费/特定大牛、无通用工具"均视为"无解"（L643）。即便对指南覆盖的新机型，"可解"也常是限时、限版本、限工具的。

**结论**：该 2026 社区汇总**既未给 K3 任何"可解"路径，也未将其纳入覆盖机型**——从第三方现状视角再次确认：K3（sdm710）在 2026 年既无官方深度测试出口，也无免授权 9008 路径，处于"无解/未被跟踪"状态。这与本报告的 §4–§5 结论完全自洽，且 OPPO 全系"熔断化"趋势使得 K3 的解锁前景只会更差而非更好。

---

## 6. 还有哪些"非 CVE"的微弱可能（按不确定度排序）

1. **确认深度测试 2026 是否仍受理 K3（最该先做的，且大概率仍可用）**：§4.2 已补充核验——OPPO 深度测试 APK 的 2026 镜像站仍把 **K3（PCGM00，C.07+）列为支持机型**，ROM乐园亦称 OPPO 老机型（Find X3/Reno6 及更早）"基本申请即可成功，审核约 1 个月"。即 K3 的深度测试**很可能仍可用**（此前"可能已关闭"的判断偏保守，已修正）。同时 §4.2 明确：所有"绕过深度测试"的非官方方案（EDL+修改 ABL、MTK 路线、GBL chainload）**都不覆盖 sdm710/K3**——因此 K3 现实上只剩官方深度测试这一条可能的路。**优先在真机用深度测试 App（包名 `com.coloros.deeptesting`，降级到 C.07+ 出厂版本）实测申请**，而不是去追 CVE 或已排除 sdm710 的灰产 EDL 方案。
2. **换区（Region Switch）**：用 full-OTA 把固件区域切到支持深度测试的地区（中国/印度）再申请。XDA/GitCode 档案作者**明确声明未验证、不可作为成熟方案**，且 full-OTA 换区本身有风险。
3. **reserve1 / ABL 逆向**：拿到 root（即便难）或 EDL 后，逆向 ABL 对 reserve1 的校验逻辑，尝试本地构造/绕过。这是设备专属、工作量极大的研究，且 OPPO 私钥签名无法伪造 → 真正可行的只能是"让 ABL 跳过校验"，需要 K3 专用修改版 `abl.img`（无公开；REF 中"欧加秒解资料包"虽提供 `abl_unlock.img`/`ocdt_unlock.img`，但平台仅覆盖 8Gen2/888/865/870/778G，**独缺 sdm710/K3**，见 §5.1）。
4. **非 userns 的 CVE-2021-22555 变体**：如前所述，工程量大、成功率低，且即使成功也只是临时 root，不解 BL。

---

## 7. 结论与下一步建议

- **不要**把近期"OPPO CVE 解锁 BL"的教程（GhostLock / CVE-2025-21479 / CVE-2025-20658）套到 K3——它们针对的是天玑 9400 / 骁龙 8 至尊版 / 安卓 15–16 / 内核 5.10–6.12 的新机型，**在 sdm710 + 4.9.186 + ColorOS 7.1 上既不命中也不具备可行性**。
- **唯一"版本号命中"的内核 LPE（CVE-2021-22555）被本机 `CONFIG_USER_NS=n` 阻断**，临时 root 也**解不开 BL**（闸门是服务器签名令牌）。
- **当前没有公开的、可靠的、基于 CVE 直接解锁 K3 Bootloader 的方法。** 这是一个需要直面的结论。
- 建议的优先级：
  1. **第一步永远是在真机实测深度测试是否还能受理 K3**（合法、零成本、可能仍存在）——这决定了整个目标是否还有"官方"出口。
  2. 若官方彻底关闭，现实可行的非官方路线曾被认为是 **EDL/9008 + OPPO sdm710 no-auth firehose**；但经 GitHub 精确检索（§5）确认**该 loader 不存在**，且 K3 为 **SLA 鉴权锁定**（需授权 OPPO 账号），EDL 路线当前不可行。这属于灰产/维修圈资源，**不在本工作区的公开研究范围内**，且变砖/失去保修风险高。
  3. 继续押注内核 CVE 对 K3 而言是低 ROI：相关 CVE 要么不命中 SoC/内核，要么已被 2021 固件修复，要么被 `USER_NS=n` 阻断，且即便成功也只是临时 root。

---

## 8. 证据索引

**CVE / 安全研究**
- CVE-2026-43499：Sploitus `EF362A0F-7149`（GhostLock 设备表/Not Feasible）、Kitploit `GhostLock-for-OnePlus`、CVE Enginsight/acidpeak/govcert.hk 受影响版本范围
- CVE-2025-21479：Sploitus `BA528F54`、ThreatCluster、Kitploit（OPPO Find X5 Pro，内核 5.10.198）
- CVE-2025-20658：ZONE.CI（heapb8 / 天玑 9400 / MTK）
- CVE-2017-5626：CERT/CVE、Anquanke 译文、cvelogic（一加 3/3T OxygenOS）
- CVE-2019-2267：FixTheCVE（**命中 sdm710**，2020-01 补丁）
- CVE-2017-18305：Armis（命中 SD835 等，**不含 sdm710**）
- CVE-2026-25262：Kaspersky ICS CERT / Black Hat Asia 2026（命中 MDM/8xx/SDX50，**不含 sdm710**）
- CVE-2021-22555：Aliyun/Huaweicloud 通告、Vulert、CVE-Security（修复版 4.9.267）、Kitploit `letsr00t/cve-2021-22555`
- Qualcomm 启动链分析：FiimeROM《高通启动链零日漏洞》

**解锁机制**
- deepwiki `zenfyrdev/bootloader-unlock-wall-of-shame` §2.8 OPPO/Realme（reserve1 机制）
- XDA 长帖（2023 服务器旧/新结构令牌、turistu 脚本失效始末）
- GitCode《OPPO/Realme 引导加载程序解锁全解析》、《2024 OPPO 解锁 BL 与 ROOT 深度指南》
- `githubskylh/awesome-android-root` 临时 root 指南（"Does temporary root unlock the bootloader? No."）

**GitHub 检索 / 固件站（§5 EDL 路径）**
- gh API `search/repositories/search/code`：`OPPO firehose` 仓库仅 1（Xiaomi 向）、`sdm710 firehose` 仓库 0、`CPH1955`/`PCGM00`/`sdm710+OPPO` firehose 代码 0 命中
- Chernobylll/FireHouse_UFS：`prog_ufs_firehose_sdm710_ddr.elf`（通用 sdm710）、`prog_firehose_ddr_fwupdate_cph1853.elf`（OPPO A3s，非 K3）
- ROMProvider `pcgm00-oppo-k3-firmware`：K3 为 SLA Enable device，需授权 OPPO 账号
- onfix `K3_PCGM00_11_A.02_190515`："OPPO 自 2017 年 6 月加密刷机工具，需登陆账号，暂无法破解"

**REF 资料包（§5.1 离线实证）**
- `REF/高通工具箱-2026.9.28-1/bin/tool/qctool/oppo/devprg_710`（693304B，ELF64 AArch64，OPPO 签名 sdm710 Firehose loader；含 `AUTH`/`Secure Boot`/`XBL`/`ABL` 字符串 → 非免鉴权）
- 对比样本 `mi_noauth/devprg_710_emmc`(717884B,2018) / `devprg_710_ufs`(722160B,2024)：显式 `noauth` 标签（小米免鉴权）× 反证 OPPO 版非免鉴权
- `oplus_8g2/`：`Digest.mbn`+`sig.dat`+`conf.xml`+`devprg` 完整 SLA 签名套件（8Gen2）；`oplus_test/说明.txt`：记录 SLA 握手（devprg→digest→getsigndata→sig→verify）→ 欧加家族需 SLA 鉴权
- `REF/欧加秒解资料包/`：`abl_unlock.img`(1MB)+`ocdt_unlock.img`(128KB) 修改版 ABL/OCDT；平台覆盖 8Gen2/888/865/870/778G/782G，**不含 sdm710/K3**（`grep -iE "710|k3|pcgm00"` 全目录 0 命中）
- `REF/欧加秒解资料包/解锁教程.txt`：仅知乎专栏链接 + 云湖群聊邀请 → 灰产远程解锁服务入口（非自助）

**社区 2026 现状汇总（§5.2 交叉核验）**
- `AdaUnlocked/2026-All-Brands-Bootloader-Unlock-Status`（末次更新 2026-10-23）：全 5 个 README 快照（含 `README_26_01_16 .md`/`04_05`/`06_13`/`07_14`）经 `grep -ainE "710|sdm|骁龙7|K3|PCGM00|K3M"` 检索，**K3/sdm710/PCGM00 零命中**（已验证 grep 对同文档 `865`/`870`/`OPPO` 可正常命中）
- OPPO 段（README.md L442–L481）：覆盖 Find X9/X8、Reno 16/14/13/12/11/10、K15/K13、X7U/X6P/N3、Pad 5 Pro 等 ColorOS 15/16 机型；"免授权 9008 老机型"列表为 8+/782G/778G/768G/865/870（**不含 sdm710**）；深度测试仅"非常老"机型且 a 系列不支持；其余无解
- OPPO 熔断趋势（L445–L478）：865/870、X7U/X6P/N3、9400/9500/9300/9200/9000 系升特定版本即终身不可逆熔断，连停更老机型也遭针对性熔断包

**深度测试机制与非官方渠道（§4.2 交叉核验）**
- GitCode《OPPO/Realme 引导加载程序解锁全解析》：深度测试申请机制、版本兼容矩阵、非官方绕过路线（mtkclient / lkpatcher / oppo-mtk-fastboot-unlock / 换区 Region Switching）
- TrueSight《权限围墙的裂缝：OPPO 固件底层解构与 BL 解锁突围指南》：EDL/Firehose 寻授权 Programmer、BROM/MTK Client、ISP 物理强刷分级矩阵
- DroidWin《Bootloader Unlock is Now Here for Oppo Find X9 Ultra》：CVE-2026-43499 临时 root → GBL chainload → `oem oem-unlock-toggle` → `flashing unlock`（SM8850 / 内核 6.12.58-android16，**非 K3**）
- ROM乐园《一加真我OPPO全机型深度测试教程》：OPPO 官方深度测试末次更新 2021-11-22、最高到 Find X3/Reno6；老机型"基本申请即可成功，审核约 1 个月"；第三方可强制解锁 OPPO 骁龙 865/888/870/8Gen2/8Gen3（最高 Find X7U）——**不含 sdm710**
- XDA 帖子（Eugas 解锁包 / 某贼高通工具箱）：欧加秒解适用于骁龙 778G/782G/865/870/8Gen2（K9S/Reno7/9/10/K11/Q3S/GT大师版/Find X2/X3/GT5/Find N3/X6 Pro）——**不含 sdm710**
- 深度测试 APK 镜像站（西西/5577/87G/多特，2026）：均列 **K3（PCGM00，C.07+）为支持机型**；包名 `com.coloros.deeptesting`

**本机实测**
- `unpacked_C17/kernel_config.txt`：`Linux/arm64 4.9.186` / `# CONFIG_USER_NS is not set` / `CONFIG_NETFILTER_XTABLES=y` / `CONFIG_NET_NS=y` / `CONFIG_FUTEX=y` / `CONFIG_RT_MUTEXES=y` / `CONFIG_KALLSYMS=y` / `CONFIG_KALLSYMS_ALL=y`
- `unpacked_C17/kernel.decompressed`：grep 命中明文 `Linux version` 与 `4.9.186`（偏移 18350214 等）、构建串 `K3`/`K3M` → 确为 K3 的 4.9.186 内核
- 时间线判定：CVE-2026-43499 修复 commit `3bfdc63936dd` 于 2026 进入主线 7.1；K3 固件构建于 2021-05（SPL 2021-05-05）→ 早于修复约 5 年，不可能含修复 → 缺陷代码存在已确认（§3.4）
- `OPPO_K3_机型代号与ROOT生态调查汇总.md` §1.2（sdm710）、§4.4–4.5（深度测试/EDL/熔断）、§9.3（SPL 2021-05-05）
- `ROOT_实施方案.md` §2.1（BL 解锁前置）、§7（排除路径）
