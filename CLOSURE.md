# 收口判定：PCGM00 F.16 在 BL 锁定条件下「可用 ROOT」为 NO-GO

| | |
|---|---|
| 设备 | OPPO K3 `PCGM00`（`OP4679`，`sdm710`），`PCGM00_11_F.16`，Android 11 |
| 内核 | `4.9.227-perf+`（clang 10.0.7，2025-03-26 构建） |
| 安全补丁 | `2022-04-05` |
| 启动状态 | BL 锁定（`flash.locked=1`）、AVB `green`、dm-verity `enforcing`、A-only |
| 唯一入口 | `uid=2000(shell)` + `u:r:shell:s0`，SELinux Enforcing，`Seccomp: 0` |
| 判定版本 | `HANDOVER.md` v2.21 |
| 判定范围 | **本机、本固件、不解 BL**。不是"任何条件下不可能"，也不是"任何设备不可能" |

---

## 1. 判定

**在不解 BL 的前提下，这台设备取不到"可用 ROOT"，也取不到"持久 ROOT"。**

**达成的是**：从 shell 让厂商 root 服务以 `uid=0` 在 `u:r:oplus_wifi_service:s0` 域内执行任意命令
（2026-11-18 12:07，两次独立载荷复现，`HANDOVER.md` §23）。

**这为什么不算 ROOT**：该域无 `CAP_DAC_OVERRIDE`（能力集被 rc 削到 `NET_ADMIN`+`NET_RAW`+`SYS_MODULE`，
`0x13000`，`sys_admin` 连 Bounding 都没有），SELinux 也不给 `mount`/`exec`/域转换。
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
| 写文件 → 高权限域执行 | 该域可写的全部文件类型（`wifi_vendor_data_file` / `mnt_vendor_file` / `fuse` / `sdcardfs`）上，**持有 `execute` 的域数 = 0** |
| `CAP_SYS_ADMIN` 挂载覆盖 | 策略无 `mount`/`remount`/`mounton`；能力集里没有 `sys_admin`，Bounding 集也没有 ⇒ 即便将来有 `capset` 也提不上来 |
| 加载自定义模块 | `module_load` 只对 `vendor_file` 生效，而本域对 `vendor_file` 无写权 ⇒ 只能加载既有签名模块 |
| 属性写 → init 执行 | 只能写 `vendor_oppo_prop`（55 条前缀），命中的 11 条触发器全是 `chmod`/`chown`/`setprop`，**无一条 `start`/`exec`** |
| 域转换 | 唯一可达 `crash_dump`，可读集与可写集**交集为空**（无法注入库），零收益 |

规模：5 份 CIL 共 24,657 条 allow，本域适用 307 条，所属属性 89 个，显式目标类型 44 个。

### 2.2 内核原语 —— 机制或前提层否证

`HANDOVER.md` §5 / §15

| 面 | 结论 |
|---|---|
| KGSL `CVE-2023-33107` | 源码级 pre-fix，但 `arm_lpae_init_pte()` 的 `BUG_ON(!suppress_map_failures)` 使"命中缺陷"与"panic"是同一事件 |
| GhostLock `CVE-2026-43499` | 机制成立（`-EDEADLK` 10+ 次确定性复现）、栈载体已闭合，但 fake waiter 的 `lock`/rb 链接**必须填非零内核地址**，而本机无任何泄露通道 |
| binder `CVE-2023-20938` | 漏洞未引入（`off_end_offset` 形态落在引入前） |
| binder `CVE-2022-20421` | pre-fix 确证，但本机是 **ticket spinlock**，公开技术依赖 qspinlock，原语退化并带 `wfe` 死等 |
| FastRPC `CVE-2023-33063` | 对 shell 双重封闭：`O_RDWR` 被 SELinux 拒；只读 fd 上 7 个 ioctl 全 `EPERM` |

**关键实证**：拿到 uid=0 之后重新测了 19 条探针——`kallsyms`/`kcore`/`dmesg`/`sections` 全被 MAC 拒，
`/proc/modules` 基址恒 `0`，`perf_event_paranoid=3`（§23.9）。**"有 root 就能拿地址"这个直觉是错的。**

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

**跳板方向是反的**：读这些路径的域（`hal_wifi_hostapd_default` / `hal_wifi_supplicant_default` /
`wcnss_service` / `fstman` / `vendor_autochmod`）**全部没有 `system_server` binder**；
这批域里唯一持有该通道的是**本域自己**。⇒ 跨域是 DAC 降级（uid 0 → 1010/1000）。

**实测校正（v2.18）**：`init.svc.*` 显示 `hostapd`、`fstman`、`triggerwifidump` **本机均未定义**（`[]`），
`ro.hardware=qcom` ⇒ 生效 rc 是 `init.wlan.qcom.rc`。**rc 文本 ≠ 生效集合**，凡"某服务会读/会跑"一律以 `init.svc` 为准。

**唯一实测的"我们写 → root 消费"**：`wifiserver`（`/odm/bin/init.oppo.wifi.sh`，root，开机 oneshot）。
审计结果：读 `persist/bin_version` 只进 `[ -gt ]` 数值比较；`cp persist/…/WCNSS_qcom_cfg.ini → targetFile` 的分支
**源路径实测不存在**，且 `cp` 两端都在本域可写的 `mnt_vendor_file` 内 ⇒ **不提供任何新能力**。

### 2.5 另两条并行线索

- **7 个私有 Binder 服务**：audit 5/5 + 补审 2/2 = **7/7 全部否证**（§14 / §19 / §24.13）。
  `anti_root_dialog_service` 是 service_manager 类型而非域，全策略只有 `oplus_kevents` 能 call 其宿主域，shell 零权限。
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
