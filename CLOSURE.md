# 收口判定：PCGM00 F.16 在 BL 锁定条件下「可用 ROOT」为 NO-GO

| | |
|---|---|
| 设备 | OPPO K3 `PCGM00`（`OP4679`，`sdm710`），`PCGM00_11_F.16`，Android 11 |
| 内核 | `4.9.227-perf+`（clang 10.0.7，2025-03-26 构建） |
| 安全补丁 | `2022-04-05` |
| 启动状态 | BL 锁定（`flash.locked=1`）、AVB `green`、dm-verity `enforcing`、A-only |
| 唯一入口 | `uid=2000(shell)` + `u:r:shell:s0`，SELinux Enforcing，`Seccomp: 0` |
| 判定版本 | `HANDOVER.md` v2.24+（含 v006 回归、G-A1 闭合与私有服务面重测，见 §7） |
| 判定范围 | **本机、本固件、不解 BL**。不是"任何条件下不可能"，也不是"任何设备不可能" |

---

## 1. 判定

**在不解 BL 的前提下，这台设备取不到"可用 ROOT"，也取不到"持久 ROOT"。**

**达成的是**：从 shell 让厂商 root 服务以 `uid=0` 在 `u:r:oplus_wifi_service:s0` 域内执行任意命令
（2026-11-18 12:07，两次独立载荷复现，`HANDOVER.md` §23）。

**这为什么不算 ROOT**：该域无 `CAP_DAC_OVERRIDE`；内核能力集被 rc 削到
`NET_ADMIN`+`NET_RAW`+`SYS_MODULE`（`0x13000`，`sys_admin`/`setuid` 连 Bounding 都没有）。
需要区分两层：**SELinux 侧对 `sys_admin`/`sys_module`/`setuid` 是放行的（direct 规则）**，
挡住它们的是内核能力集，不是策略。SELinux 也不给 `mount`/`exec`/域转换。
实测读不到 `/data/system`、`selinuxfs`、`proc_security`、`shell_data_file` ⇒ 装不了 `su`、改不了 `/system`、
拿不到交互式 root shell。

| 层次 | 结果 |
|---|---|
| Root UID 命令执行 | **达成** |
| 可用 root（脱离域限制的系统管理能力） | **NO-GO** |
| 持久 ROOT | **NO-GO**（且按约定全程未做任何持久化写入） |

---

## 2. 四条可能方向的否证方式

每条都不是"没找到"，而是**指明断在哪一层**。

### 2.1 域逃逸（原主线）—— 策略层否证

`HANDOVER.md` §24 / `SELINUX_DOMAIN_AUDIT.md`

| 候选 | 断点 |
|---|---|
| 写文件 → 高权限域执行 | 该域可写的全部文件类型（`wifi_vendor_data_file` / `mnt_vendor_file` / `fuse` / `sdcardfs` / `sysfs_wlan_con_mode` …，共 13 个 file/dir 目标）上，**持有 `execute` 的域数 = 0**（v2.24+ 用修正后的引擎重算，仍为 0） |
| `CAP_SYS_ADMIN` 挂载覆盖 | 策略无 `filesystem mount`（仅 `getattr`）；**SELinux 对 `capability sys_admin` 是放行的**，但内核 `CAP_SYS_ADMIN` 不在 `CapEff` 也不在 Bounding ⇒ 即便将来有 `capset` 也提不上来 |
| 加载自定义模块 | **阻断点不是 SELinux**：`(allow oplus_wifi_service vendor_file (system (module_load)))` 放行、`CAP_SYS_MODULE` 在 `CapEff` 内、`CONFIG_MODULE_SIG_FORCE=y`+`MODULE_SIG_ALL=y`(SHA-512) ⇒ **只有厂商签名的模块能进内核**。v2.24 更正了原表述（原文写"本域对 vendor_file 无写权"，与 `module_load` 的检查对象不符） |
| 属性写 → init 执行 | 只能写 `vendor_oppo_prop`（55 条前缀），命中的 11 条触发器全是 `chmod`/`chown`/`setprop`，**无一条 `start`/`exec`** |
| 域转换 | 唯一可达 `crash_dump`，可读集与可写集**交集为空**（无法注入库），零收益 |

规模（v2.24 新口径）：5 份 CIL 共 24,657 条 allow，本域适用 **347** 条，所属属性 **775** 个，显式目标类型 44 个。
旧数字 307/89 出自有缺陷的闭包实现，已作废（复刻校验与差异归因见 `P1_REGRESSION_FINDINGS.md`）。

### 2.2 内核原语 —— 机制或前提层否证

`HANDOVER.md` §5 / §15

| 面 | 结论 |
|---|---|
| KGSL `CVE-2023-33107` | 源码级 pre-fix，但 `arm_lpae_init_pte()` 的 `BUG_ON(!suppress_map_failures)` 使"命中缺陷"与"panic"是同一事件 |
| GhostLock `CVE-2026-43499` | 机制成立（`-EDEADLK` 10+ 次确定性复现）、栈载体已闭合，但 fake waiter 的 `lock`/rb 链接**必须填非零内核地址**，而本机无任何泄露通道 |
| binder `CVE-2023-20938` | 漏洞未引入（`off_end_offset` 形态落在引入前） |
| binder `CVE-2022-20421` | pre-fix 确证，但本机是 **ticket spinlock**，公开技术依赖 qspinlock，原语退化并带 `wfe` 死等 |
| FastRPC `CVE-2023-33063` | 对 shell 双重封闭：`O_RDWR` 被 SELinux 拒；只读 fd 上 7 个 ioctl 全 `EPERM`。**v2.23 换 uid 0 身份重测：本域对该二类型权限并集为 ∅，open 读/写两向均被拒（`permissive=0`）⇒ 特权域下更封闭**（§32） |

**关键实证**：拿到 uid=0 之后重新测了 19 条探针——`kallsyms`/`kcore`/`dmesg`/`sections` 全被 MAC 拒，
`/proc/modules` 基址恒 `0`，`perf_event_paranoid=3`（§23.9）。**"有 root 就能拿地址"这个直觉是错的。**

同向的第二份证据在设备节点面：对 `/dev/adsprpc-smd`，**shell 能只读 `open`、`ioctl` 可达**（经 `appdomain`），
而 uid 0 的 `oplus_wifi_service` **连 `open` 都被拒**（§32.5）。⇒ **权限按域算，不按 uid 算。**

### 2.3 `/dev/diag` 内核接口 —— 入口层否证

`HANDOVER.md` §25 / `DIAG_DRIVER_AUDIT.md`

42 槽 ioctl 分派表全解（22 有效 / 20 `-EINVAL`）；入口三函数（`ioctl`/`write`/`read`）**逐路径人工复核**；
脚本口径 301 个 `diag*` 符号 / 18 个含拷贝函数 / **55 个拷贝点全部定长或显式封顶**（8 个变长逐个给出上界出处）；
`write()` 三条命令路径的长度门**全部收敛到 `diag_mempools[].item_size`**；**无 `mmap`**（符号不存在）。
形态与上游**修复后** diag 一致：`count>>29` 守卫、内联 `access_ok`、`__check_object_size`。

**范围声明**：这只否证入口层。DCI 内容解析子树未审（G1），但即便那里有缺陷，
**依赖伪造内核指针的利用**仍被"无地址泄露"阻断；非指针型缺陷本项目未评估，属另一类研究。

### 2.4 跨域数据消费 —— 三道门 + 跳板方向层否证

`HANDOVER.md` §26 / §28 / §29 / §30

| 门 | 结果 |
|---|---|
| 连接 | 本域 `unix_stream_socket connectto` 目标只有 `init` |
| 执行 | 两个可写文件类型上持有 `execute` 的域数 = 0（`dlopen` 同样需要 `execute`） |
| 触发 | 唯一的"属性 → root 执行脚本"触发属性属 `system_prop`，本域无 `set` |

**跳板方向这一条在 v2.24+ 被改写**：旧稿写"读这些路径的域**全部没有** `system_server` binder，
唯一持有该通道的是本域"——该前提**不成立**（`hal_wifi_hostapd_default`、`hal_wifi_supplicant_default`、
`fstman` 都持有，经 `(allow hal_*_server hal_*_client (binder (call transfer)))`，而
`hal_*_client` 的成员就是 `system_server`）。

跳板仍需三步，现在**断在第 ② 步**：

| 步 | 判据 | 结果 |
|---|---|---|
| ① 通道 | 消费者能 `binder call system_server` | **成立**（3 个消费者域持有） |
| ② 触发 | 我们能让它读我们写的文件并当配置解析 | **不成立**：`init.svc.hostapd/fstman = []`（§28.2 实测未运行）；supplicant/hostapd 无 `-c <path>`；fstman 带 `-c` 但本域无法触发 |
| ③ 能力 | 其解析器能把配置变成我们能利用的行为 | 未审（G-W1） |

⇒ 结论仍为 DAC 降级，但**承重墙从 ① 换成 ②**。这一点重要：①的失效条件是"策略多一条规则"，
②的失效条件是"rc 改一个参数"，两者重开概率相差一个量级。

**实测校正（v2.18）**：`init.svc.*` 显示 `hostapd`、`fstman`、`triggerwifidump` **本机均未定义**（`[]`），
`ro.hardware=qcom` ⇒ 生效 rc 是 `init.wlan.qcom.rc`。**rc 文本 ≠ 生效集合**，凡"某服务会读/会跑"一律以 `init.svc` 为准。

**唯一实测的"我们写 → root 消费"**：`wifiserver`（`/odm/bin/init.oppo.wifi.sh`，root，开机 oneshot）。
审计结果：读 `persist/bin_version` 只进 `[ -gt ]` 数值比较；`cp persist/…/WCNSS_qcom_cfg.ini → targetFile` 的分支
**源路径实测不存在**，且 `cp` 两端都在本域可写的 `mnt_vendor_file` 内 ⇒ **不提供任何新能力**。

### 2.5 另两条并行线索

- **7 个私有 Binder 服务**：audit 5/5 + 补审 2/2 = **7/7 否证**（§14 / §19 / §24.13 / §33.3 / **§34.3**）。
  两段更正（v2.24）：① `anti_root_dialog_service` 的"shell 零权限"结论**作废**（查询口径错误）——
  修正后 shell 经 `base_typeattr_511` **有 `service_manager:find`**，经 `(allow appdomain appdomain
  (binder (call transfer)))` **有对宿主域 `color_system_service_app` 的 `binder:call`**，设备实测事务送达；
  ② 实现已在 §34.3 定位（混淆类 `com.oplus.exsystemservice.a.b$a`，单一 `int` 事务、无鉴权、
  **无任何危险 sink**）⇒ **可达但无能力，7/7 以更强理由闭合**。
  ⚠️ **范围更正（§35）**：所谓"7 个私有服务"是低估——实测 235 个服务中 shell 能 `find` **228** 个，
  `36/36` 个 OPPO 私有服务全在其中；`binder:call` 经 `appdomain → binderservicedomain` 也通铺。
  **servicemanager 层的 find/call 不是有效门槛，真正的门在每个 `onTransact` 分支**（§35 / `PRIVATE_SERVICE_SURFACE.md`）。
  已做 44 行鉴权/sink 初筛，未确认新路径；`power_monitor` / `usage` 两行已由 §36 的事务级审计闭合。
  **native 面（§37）**：`hans`/`horae`/`oiface` 三个 native 服务的导入 xref 未发现可控数据到内核/文件的已证路径；hans 的 netlink `sendto` 经函数指针调用、调用链未闭合，按"未发现、保留观察"处理。
- **`system_server` Binder 通道**：本域对 AIDL 注册表 `servicemanager` **零规则**（无 `binder call`、无 `service_manager find`）；
  该 HAL 只注册 `IOppoWifiService`、19 个方法无句柄入参、不导入 `readStrongBinder` ⇒ **双向都不通句柄**（§27 / §29）。
  唯一残余是 3 个 `_hidl_cb` 构成的**反向数据通道**，实测在 Java 侧只拼日志 + 存字段，
  该类 28 个方法对 `java.io`/`Runtime`/`ProcessBuilder`/`SystemProperties`/`Intent`/`java.net` **0 命中**（§30）。

---

## 3. 我们没做，且认为不值得做的（清单与理由）

这一节是收口稿的核心：**把"没做"和"不值得做"分开写清楚**，避免读者误以为我们声称穷尽。

| 缺口 | 不做的理由 | 什么条件下才值得做 |
|---|---|---|
| **G1** DCI 内容解析子树（`diag_process_single_dci_pkt` 下游 opcode `0x93/0x94/0x98/0x9a`） | 长度已封顶；剩下的要靠"非指针型"缺陷才可能绕过地址墙，那是另一类研究，非本项目口径 | 出现引用该解析器、且 opcode 集合与本机一致的公开漏洞 |
| **G-W1** 消费端解析器内存安全（supplicant / hostapd / cnss-daemon） | **前置条件不成立**：`hostapd`、`fstman` 本机未定义；supplicant 无 `-c` 配置文件路径 | 本机 rc 出现 `-c <我们可写的路径>` |
| **G-W2** `vendor_oppo_prop` 55 条前缀的值语义 | 策略层已确认无"值被当命令/路径解释"；逐条语义是穷举活，收益近零 | 发现某高权限域把该属性值用于路径或命令位置 |
| **G-W3** `rild`/`self_init` 对 persist 的二进制解析 | 该类路径**禁写**（跨重启持久化），只能静态；脚本侧已证明输入只进数值比较 | 出现可写的 persist 子路径且被高权限域解析 |
| **G-S2b** `getResult()` 的上一跳消费方 | 缺物料（`service-wifi.jar` 的 OPPO 扩展），且性质是**应用层数据流**，不是信任边界 | 出现"该字符串被用于路径/命令/属性"的证据 |
| **G-S3** `engineermode_app` 的 `transfer` 路径 | 只有 `transfer`、没有 `call`；未发现递句柄路径 | 发现它主动把句柄递给本域 |
| **G-W7** `wifisar` 二进制 | 现在可本地解包取到，但该服务**无法触发**（触发属性 `sys.oplus.wlan.sar_idx` 属 `system_prop`） | 该属性变成 `vendor_oppo_prop` 可写 |
| **G4** `diag_dbgfs_*` | debugfs 本域不可达 | 取得 debugfs 或更高域 |
| ~~**G-A1** `anti_root_dialog` 实现~~ | **已闭合（§34.3）**：旧的"无实现 class_def"判断不成立——该 dex 的 `source_file` 为 0/4,068（debug info 被 strip）。改用字符串 xref 定位到混淆类 `com.oplus.exsystemservice.a.b$a`，单事务、无鉴权、**无危险 sink** | 该 App 其他服务出现"外部输入 → 危险 sink"的数据流 |
| ~~**G-P1** `power_monitor` / `usage` 事务级审计~~ | **已闭合（§36）**：两次 xref 定位到 Stub（`com.oplus.os.a$a` / `android.os.a$a`）；二者只做 `enforceInterface`、无调用者鉴权，但可控字符串未流向 sink。`Runtime` 是 `RuntimeException` 假阳性，`SystemProperties.set` 在 `dump()` | 出现可控字符串直达 sink 的方法体，或 OTA 后混淆名变化 |

**同时明确没做的动作**（不是不能，是按约定不做）：未向 `/mnt/vendor/persist/**` 写任何内容；
未做过任何内核 fuzz / 竞态实验（本轮）；未改任何属性触发服务；未安装任何持久化文件。

---

## 4. 这个判定可能错在哪（自我声明）

按对抗性复核的优先级排序：

1. **枚举完备性**。所有"消费者/攻击面"结论都依赖一个枚举集合。若存在一个未被枚举的面
   （例如某条不经过文件、不经过 binder、纯通过内核驱动接口的路径），本文的收口就不成立。
2. **入口层复核的穷尽性**。`diag` 的"入口三函数逐路径复核"是人工的；若漏一条分支，结论 2.3 的强度下降。
3. **"依赖内核指针"这一限定**。它把 §2.2/§2.3 的否证范围收窄了；若有**非指针型**内核缺陷可用，则这两条不覆盖。
4. **rc 与运行态的偏差**。v2.16 曾用 rc 文本推断部署情况，被 v2.18 实测推翻。同类推断若仍残留在未见章节，可能还有错。
5. **策略工具的闭包精度**。这条已经在 v2.24 兑现成实际错误：v2.23 只把问题当成"同名 type/attribute
   被丢弃"，实际是两个独立缺陷（`not` 的补集语义、版本化名字合并）。修正后 `shell` 的属性数由
   131 涨到 752、`oplus_wifi_service` 由 89 涨到 775，并且**直接推翻了 §24.13 的一条否证**（§7.1）。
   教训是：**否证型结论必须由"查询级"证据支撑，不能只靠"全量表里没有这一行"**——
   旧报告正是在"全量表"上得出"shell 对该服务零权限"的。

---

## 5. 如何推翻本文（只接受可复算的反例）

| 不构成推翻 | 构成推翻 |
|---|---|
| "diag 历史上出过漏洞" | 指明本机某 opcode 处理路径的越界点，给出可复算的地址或反汇编片段 |
| "wifi 配置可写很危险" | 指出一个"能读该路径 **且** 能 `binder call` `system_server`/`vold`"的域 |
| "root 应该能做更多" | 给出本域能力集的实测反例（当前 `CapEff=CapBnd=0x13000`） |
| "可能还有别的面" | 指名该面，并给出它在策略 / rc / 二进制中的存在证据 |
| 用其它 SPL/内核的结论外推 | 指明在本机 SPL `2022-04-05` / 内核 `4.9.227-perf+` 下同一路径的差异 |

复现方式：`README.md`「审阅须知」列出了全部离线复算命令（`tools/kfn.py`、`klen_scan.py`、`kcopy.py`
与若干 `grep`）；设备侧只读探针见 `HANDOVER.md` §28.9。

---

## 6. 一句话

**这台机器能给你的上限，是"以 root 身份在别人写好的笼子里跑命令"。**
笼子的四壁（SELinux 域、能力集、内核地址、跨域跳板）我们都量过了，每一面都写清了厚度与断点——
本文的作用是把这四面墙的测量结果封存，而不是宣布墙不存在。


---

## 7. v2.24 更正（审核意见 v006 落地）

| # | 原表述 | 更正后 | 影响 |
|---|---|---|---|
| 7.1 | §2.5「7/7 全部否证；shell 对 anti_root_dialog 零权限」 | 中间态记为 6/7（可达但未知）；**§34.3 已闭合为 7/7**——实现是单事务、无鉴权、无危险 sink，可达但无能力 | 一条**理由**作废、结论保留且更硬。**不改写总体 NO-GO** |
| 7.2 | §2.1「加载自定义模块：`module_load` 只对 `vendor_file` 生效，而本域对其无写权」 | **断点在模块签名**：策略放行、`CAP_SYS_MODULE` 具备、`CONFIG_MODULE_SIG_FORCE=y` 拦截 | 结论不变，**归因与重开条件全变**（签名被绕过即通） |
| 7.3 | §1「`sys_admin` 连 Bounding 都没有」被读成"策略也不给" | 策略**给**（direct 规则含 `sys_admin`/`sys_module`/`setuid`）；墙在内核能力集 | 措辞精度，防误判重开方向 |
| 7.4 | §2.1 规模「307 条 / 89 属性」 | **347 条 / 775 属性** | 量级修正，附复刻校验（旧数字可由 A 口径逐位复算） |
| 7.5 | §4.5 自评「应视为下界」 | 该风险**已兑现为实际错误**（见 7.1），且方向是"旧报告漏算" | 方法论条目改写 |

**没有变的三件事**：Root UID 命令执行仍已达成；可用/持久 ROOT 仍 NO-GO；四条否证方向（域逃逸 /
内核原语 / `/dev/diag` / 跨域消费）的断点位置不变——第 7.1 条影响的是**另一条并行线索**（私有 Binder 服务面），
不是主线。

---

## 8. 配置依赖（不是结论）

以下否定**依赖运行时配置**，不依赖策略文本。它们随时可能因固件变化反转，
因此按"依赖 + 监测点"登记，不计入结论：

| 依赖 | 当前值 | 若变化 | 后果 | 监测点 |
|---|---|---|---|---|
| `CONFIG_MODULE_SIG` / `MODULE_SIG_FORCE` / `MODULE_SIG_ALL` | `y` / `y` / `y`（SHA-512） | `FORCE=n` | 策略已放行 `module_load`（对 `vendor_file`）且 `CAP_SYS_MODULE` 在位 ⇒ **内核任意代码** | `/proc/config.gz` 或 `k3_kernel_config.txt` 重建 |
| `CapEff` / `CapBnd` | `0x13000` | 出现 `CAP_SETUID` / `CAP_SYS_ADMIN` | SELinux 本就放行 `setuid`/`sys_admin`，能力侧门槛一消失即通 | rc 的 `capabilities` 行 + `/proc/PID/status` |
| `ro.hardware` / 生效 rc | `qcom` / `init.wlan.qcom.rc` | 换平台 | `init.svc.*` 集合全变，§28 的"服务未运行"类否定全部作废 | `getprop ro.hardware` + `init.svc.*` |
| SPL / 内核构建 | `2022-04-05` / `4.9.227-perf+` | OTA | 全部偏移、形态、策略作废（§7 第 3 条） | `getprop ro.build.version.security_patch` |

**建议**：关闭系统 OTA；每次接手先跑一遍本表四行。
