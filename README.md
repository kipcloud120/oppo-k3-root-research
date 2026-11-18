# OPPO K3 临时 ROOT 可行性研究

> **一份负结果加上一次突破的完整记录**：在不解 BL 的前提下，对一台 OPPO K3（`PCGM00` / SDM710 / 内核 `4.9.227` / SPL `2022-04-05`）评估了五个内核候选面与两条服务面线索。**四个内核面判定不可达；GhostLock 阻断在"无内核地址泄露"；但 Wi-Fi 私有事务面在第 5 轮审计 + 外部复评 + 上机验证后被打通——从 shell 可让 root 服务以 `uid=0` 执行任意命令（2026-11-18 12:07，两次复现）。** 该 root 处于 SELinux 域 `oplus_wifi_service` 内、受 MAC 限制，**属"受限 root 命令执行"，尚非可用 root**；剩余缺口已从"内存破坏"变成"域逃逸"。域逃逸静态审计的结论是**该域内无任何可达逃逸路径**（v2.14 / §24）；第七个服务 antirootdialog 已闭合为**不可达**，七服务覆盖 **7/7**；外部复评指出的第六个内核面 `/dev/diag` 已完成入口层审计，**入口层逐路径复核穷尽、55/55 拷贝点判界闭合、无 mmap、post-fix 形态 ⇒ 入口层否证，且与 GhostLock 撞同一面"无内核地址泄露"的墙**（v2.15 / §25）。曾有一次"结论翻转"误判，已撤回（§16.11）；本次 L3 与那次误判无关，用的是从未尝试过的 `\n`/反引号载荷。

| | |
|---|---|
| 目标设备 | OPPO K3 `PCGM00`（`OP4679`，`sdm710`），Android 11，内核 `4.9.227-perf+`（clang 10.0.7，2025-03 构建） |
| 安全补丁 | `2022-04-05` |
| 启动状态 | BL 锁定、AVB `green`、dm-verity `enforcing`、A-only |
| 可用入口 | `uid=2000(shell)` + `u:r:shell:s0`，SELinux Enforcing，**`Seccomp: 0`** |
| 结论 | **受限 root 已达成，可用 root 未达成。** 四个内核候选面不可达；Wi-Fi 私有事务面已打通：从 shell 发 tx 10070、载荷含 `\n` 或反引号即绕过 11 字符黑名单，`sh -c` 以 **`uid=0(root)`**、域 `u:r:oplus_wifi_service:s0` 执行任意命令（2026-11-18 12:07，两次复现）。**但该域受 SELinux 限制**（读不到 `/data/system`、`selinuxfs`、`proc_security`）⇒ 尚非可用 root，缺口是域逃逸。**域逃逸的静态审计已完成（v2.14 / §24）：该域内不存在可达的逃逸路径**——可写路径无任何域持有 `execute`、无 `mount` 权限、`module_load` 只对不可写的 `vendor_file` 生效、属性触发器无 `start`/`exec`、唯一域转换 `crash_dump` 零收益 |
| 私有 Binder 面 | atlas 线索 5/5 闭合、确定否证；**P2 补审 7/7 全部否证**（见 `HANDOVER.md` §19、§24.13）：hephaestus 有 `system()` 面但被 native `uid==1000` 门禁挡住 shell，其余无命令面/带签名校验；**antirootdialog 已闭合**——`anti_root_dialog_service` 是 service_manager 类型而非域，全策略只有 `oplus_kevents` 能 call 其宿主域，shell 零权限 |
| Wi-Fi 私有事务面 | **已利用成功**。路径：`tx10070 → helper(空权限) → HIDL → /odm/bin/iwpriv <载荷> → sh -c`。**v2.12** 证明过滤器只有 11 个字符（缺 `\n`、反引号、`<`、`>`）；**v2.13 上机验证**：载荷 `x\nlog -t P1UID `id`` 回显 `uid=0(root) gid=1010(wifi) … context=u:r:oplus_wifi_service:s0`，两次复现。同族另三接口无 Java 调用方，不增加攻击面。见 §23 / §22。**v2.14 探针**：`CapEff=CapBnd=0x13000`（`sys_admin` 从不在 Permitted/Bounding 内）、`/mnt/vendor/persist/wlan` 实测 `mnt_vendor_file`（`0777`）、`crash_dump` 域转换可判别成立但零收益（§24.9） |
| 设备终态 | 系统未变，**未刷写、未解锁、未改分区、未装持久化文件**；`/data/local/tmp` 已清空；累计 5 次内核重启（均为前期竞态实验，本轮 0 次） |

> **📌 审阅入口（v2.20 · 本轮提交审核）**
> 五份材料：`HANDOVER.md` **§25 / §26 / §27 / §28**、`DIAG_DRIVER_AUDIT.md`、`WIFI_DATA_CONSUMER_AUDIT.md`、`SYSTEM_SERVER_BINDER_AUDIT.md`（均在 `artifacts_adb/binder_audit/`）。
> 结论四条：`/dev/diag` **入口层否证**；Wi-Fi 可写面**消费不构成提权通道**；`system_server` 通道**在"取句柄"处断开**；**root 脚本消费 persist 配置 = 内核面，不是域逃逸**。
> v2.18 用设备实测**闭合了 G-W5** 并重建生效服务集（`ro.hardware=qcom` ⇒ `init.wlan.qcom.rc`；`hostapd`/`fstman`/`triggerwifidump` 本机**均未定义**）；v2.19 用 5 条只读探针**闭合 G-W6**，并把 R1 的"root 消费路径"实测下调；v2.20 **闭合 G-S1** —— 从 HAL 二进制的 `.gnu_debugdata` 解出 19 个方法签名，证明它**不接收任何 binder 句柄**。
> 累计**撤回/收窄自己的判断六处**，见[审阅须知（v2.20）](#审阅须知v220) 的「本轮自我更正」。
> **请重点攻击的五个点、复现命令、推翻口径，见[审阅须知（v2.19）](#审阅须知v219)。**

---

## 结论一览

| 候选面 | 机制是否成立 | 卡在哪一环 | 缺口能否参数化 |
|---|---|---|---|
| **KGSL** `CVE-2023-33107` | 成立（源码级 pre-fix 确定） | `arm_lpae_init_pte()` 的 `BUG_ON(!suppress_map_failures)`：静态变量运行期恒 false ⇒ **进入缺陷路径即 panic**，没有"先命中再利用"的中间态 | 否 |
| **GhostLock** `CVE-2026-43499` | 成立（`-EDEADLK` 10+ 次确定性复现） | **栈载体已闭合、缺信息泄露**：修正扫描器判重 bug 后找到 3 条 xattr 栈覆盖候选（256 B 经 `strncpy_from_user` 写栈）；静态判定"栈槽复用"是几何确定性、NUL 截断不阻断，但 fake waiter 的 `lock` 与 rb 链接必须取**非零内核地址**，本机无泄露通道。**v2.13 实证：新取得的 uid=0 域同样读不到内核地址**（`kallsyms`/`kcore`/`dmesg` 被 MAC 拒，`/proc/modules` 基址恒 0）⇒ 阻断点未变 | 否（缺泄露） |
| **binder** `CVE-2023-20938` | **不成立**（漏洞未引入） | `off_end_offset` 形态处于 `44d8047f1d87 … 32e9f56a96d8` 之间：`is_failure=1 且 failed_at=0` 时清理循环执行 0 次 | — |
| **binder** `CVE-2022-20421` | 成立（pre-fix 形态确证） | 本机是 **ticket spinlock**，公开技术依赖 qspinlock；原语退化为"对两半相等的 4 字节字加 `0x00010001`"，并带 `wfe` 死等风险 | 部分 |
| **FastRPC** `CVE-2023-33063` | 面存在 | 对 shell **双重封闭**：`O_RDWR` 被 SELinux 拒（`EACCES`）；只读 fd 上 7 个已实现 ioctl 全部 `EPERM` | 否 |
| **OPPO Wi-Fi 私有事务**（非内核面） | **成立且已利用**（root 服务、shell 可达、字符串进入 `sh -c`、以 uid=0 执行均已实测） | **卡点已移到 SELinux 域逃逸**：`oplus_wifi_service` 域读不到 `/data/system`、`selinuxfs`、`proc_security`、`shell_data_file` ⇒ 不能装 `su`、改 `/system`、读任意 `/data` | **是**（uid=0 已证；可用 root 未证） |
| **P2 七服务审计**（非内核面） | 不成立（**7/7 全部否证**） | hephaestus 的 `system(可控串)` 被 native `getCallingUid()==1000` 门禁挡住 shell(2000)；其余无命令原语或带签名校验；**antirootdialog 判不可达**（service_manager 类型；全策略仅 `oplus_kevents` 能 call 其宿主域，shell 零权限） |
| **root 脚本消费 persist 配置**（v2.18 提出，v2.19 实测下调） | **无新能力（已实测）** | `wifiserver` = `/odm/bin/init.oppo.wifi.sh`（`user root`，`late_start` oneshot）。它检查 `/mnt/vendor/persist/WCNSS_qcom_cfg.ini`（顶层）——**实测该路径不存在**（真文件在 `persist/wlan/`），分支是死的；即便活着，其 `cp` 的源与目标（`targetFile=/mnt/vendor/persist/wlan/…`）**都在本域可写的 `mnt_vendor_file` 内**，等于在我们自己的两个可写位置之间搬运 ⇒ **不提供新能力**。同一脚本读 `bin_version` 只进 `[ -gt ]` 数值比较（实测两边都是 `200`），**不构成注入** |
| **`system_server` Binder 通道**（v2.17 新增面，v2.20 补全） | **在取句柄处断开（双向）** | ① 本域对 AIDL 注册表 `servicemanager` **零规则**：无 `binder call`、无 `service_manager find`，`domain` 属性也无全局授予；② `binder call` 只对已持有句柄生效；③ **HAL 侧也不递句柄**（v2.20）：该服务只注册 `IOppoWifiService`、19 个方法无句柄入参、不导入 `readStrongBinder`。⇒ 评审列的三类服务层判定（`checkCallingPermission` / uid==1000 / uid==0）**到不了**。残余：3 个 `_hidl_cb` 构成**反向数据通道**（HAL→system_server 回传 status+字符串），风险落在 Java 侧处理器 = G-S2 |
| **Wi-Fi 可写面消费者**（v2.16 新增面） | **不构成提权通道** | 连接门（`connectto` 只有 `init`）、执行门（可写类型 `execute` 域数 = 0）、触发门（触发属性属 `system_prop`）**三道全封**；且消费者域全部无 `system_server` binder，唯一有该通道的是本域 ⇒ 跨域是 DAC 降级（uid 0 → 1010/1000）。本机 supplicant/hostapd 无 `-c`，`fstman` 未部署 |
| **`/dev/diag`**（diagchar，v2.15 新增面） | **入口层无缺陷** | 42 槽 ioctl（22 有效/20 `-EINVAL`）、**入口三函数逐路径复核穷尽、脚本口径 55/55 拷贝点定长或显式封顶**、`write()` 三条路径长度门全收敛到 `diag_mempools[].item_size`、**无 `mmap`**、形态与上游**修复后** diag 一致。余量：DCI 解析子树未穷尽 + 与 GhostLock 同一面"无内核地址泄露"的墙 ⇒ **有 bug 也用不上** |

完整论证、证据与可复算数字见 **[`HANDOVER.md`](HANDOVER.md)**。**新对话请从 §17「接手清单」开始**——当前状态、结论层次、工具路径与禁止重复的动作都在那里；P0/P2 收束在 §18/§19，外部复评与重开在 §20，复评后新 P0/新 P1 的执行结果在 §21，同族九类命令映射与过滤缺口在 §22，**上机取得受限 root（L3）在 §23**，**域逃逸 P0 静态审计（无出口）在 §24**，**`/dev/diag` 入口层审计（否证）在 §25**，**Wi-Fi 可写面消费者审计（不构成提权通道）在 §26**。

---

## 五个值得单独看的结果

### 1. 把"符号不可用"从死路变成可解——问题根本不在镜像

项目前 16 节（v1）花了大量精力论证"镜像节区/函数重排、kallsyms 未同步、地址加减 delta 无效"，并据此放弃精确定位。**这个判断是错的**：真实原因是解析器把 kallsyms 偏移当作 base-relative 处理。

用 [`vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) 从 `kernel.decompressed` 重建 ELF 后，`stext` 反汇编得到的就是 arm64 `head.S` 的真实内容（`bl preserve_boot_args / bl el2_setup / …`），符号空间完全对齐，**123,784 个符号可用**。

> 教训：当一个"不可解"的结论支撑了后续几十页推理时，先怀疑工具，而不是先怀疑目标。

### 2. GhostLock：一个被自己推翻的"穷尽证明"，以及它换来的真实缺口

`rt_mutex_waiter` 在 `do_futex` 帧内的绝对位置由三个独立的 `sub xN, x29, #0xa8` 交叉确认为 `-0x288`；攻击者需要把 72 字节的 fake waiter 完整放进某个 syscall 的**用户可控栈缓冲区**里。判据是纯几何的：

```
d = 0x110 + Σ(调用链帧)          # 到缓冲区的深度
需  d - buf_off ∈ [0x288, 0x2BE]  # 54 字节宽的合格带
```

**第一版结论是"397 个入口全扫 0 命中、近失配 66"**，并据此判死。这个结论后来被一份外部审核推翻：原扫描器用函数名做全局判重，把"同一辅助函数的不同调用路径"当成同一条，18,691 次跳过里有 **18,074 次是不同累计栈帧上下文**；同时拷贝原语前缀表漏了 `strncpy_from_user`。修正后（`tools/gl_carrier_rescan.py`）**从 0 命中变为 3 条满足几何判据的 xattr 栈覆盖候选**：

| 路径 | waiter 在 256 B 栈缓冲内的偏移 | 覆盖整个 waiter 所需串长 |
|---|---|---|
| `SyS_fgetxattr → getxattr` | 0x10 | 84 B |
| `SyS_getxattr → getxattr` | 0x40 | 132 B |
| `SyS_setxattr → path_setxattr → setxattr` | 0x60 | 168 B |

**载体找到之后，剩下的不是"再调一次参数"。** 逐项静态收束（`GHOSTLOCK_NUL_ANALYSIS.md`）后，两个原本列为"待上机验证"的未知量被改写：

- **栈槽复用不是"时机"问题**：同线程、每次异常入口 `sp` 复位到栈顶、路径无 VLA 且帧长定长 ⇒ 复用由构造保证，不需要概率性验证。
- **NUL 截断不阻断**：`strncpy_from_user` 在本机构建上没有 arm64 asm 变体（走 C 实现），终止 NUL 落在 `prio` 第 2 字节时 `zero_bytemask` 会把上位 3 字节置 0，`prio ∈ [1,255]` 全部合法。真正的约束是"到 `prio` 低字节为止共 81/129/161 字节必须**连续非零**"，且"少写一点、靠内核残余补齐"不成立——NUL 恰好清零下一个字段的首字节。

⇒ **新的阻断点**：fake waiter 的 `lock`（0x38）与 `tree_entry` 的三个 rb 链接必须非零，而"干净"取值要么含 `0x00`、要么需要 `RB_EMPTY_NODE` 自引用（等于内核栈地址）。两者都要求**已知一个内核地址**，而本机泄露面为空（`/proc/kallsyms`、`dmesg`、`pstore` 全不可读，KASLR 开启）。**缺的不是载体，是泄露。**

`pselect6` 家族仍然救不回来（`core_sys_select` 单帧 `0x1c0` 把下限钉在 `0x320`，比合格带深 98 字节），这条旧结论未受影响。

### 3. ticket spinlock 把 4 字节 UAF 写降级成一个常数加法

`CVE-2022-20421` 在本机确证为 pre-fix（`binder_inc_ref_for_node` 尾部结构精确等于修复前的 `unlock; if (new_ref && ref != new_ref) kfree(new_ref);`），但公开技术的前提是 qspinlock：一次 lock+unlock 可把目标指针的低 2 位置零，从而破坏对齐、触发类型混淆。

本机没有 `queued_spin_lock_slowpath`，`_raw_spin_lock` 是 `ldaxr` → `+0x10000` → `stxr` → `wfe`，`_raw_spin_unlock` 是低 16 位 `+1`。⇒ 本机原语 = **"对一个两半相等的 4 字节字加 `0x00010001`"**，且不满足"两半相等"时会**挂死而非写入**。整条"对齐破坏 → 类型混淆 → 任意读写"的后续链条无法套用。

这条被记录为 **"pre-fix 但无可用原语"**，不是"不可利用"——两者差别很大。

### 4. 两个"看起来能用、实际一步都走不通"的面

- **KGSL**：同源 4.9 源码里 `arm_lpae_map_sg()` 确实不接 `arm_lpae_init_pte()` 的返回值且无条件 `ms.num_pte++`，符合 RCA 描述。但 `suppress_map_failures` 只在驱动自检期为 true，运行期恒 false ⇒ 一旦 `mmap` 撞上已存在的有效 PTE，执行的是 `BUG_ON()` 而不是返回 `-EEXIST`。三轮实测吻合：300 µs 延时立即掉线，3000/5000 µs 安全。
- **FastRPC**：`/dev/adsprpc-smd` 可 `O_RDONLY` 打开，`ioctl(fd, 0)` 返回 `ENOTTY` 说明请求已穿过 SELinux 钩子进了驱动；但 `O_RDWR` 被策略拒（`EACCES`），而只读 fd 上 7 个已实现 ioctl 全部在参数拷贝前返回 `EPERM`。写通道与调用通道各被封一半。

---

### 5. 一个 root 服务里的 `sh`：从"被拦住"到 `uid=0`（六轮审计的完整弧线）

审计一条线索：`OplusWifiHalService.executeDriverCommand(String)` 有 `system()` 但命令模板硬编码（atlas 同款结论）。这次不同——它不是终点，而是链条中间：

```
Java: android.net.wifi.OplusWifiManager → ServiceManager.getService("wifi")
      → transact(10070 = sendFTMCommand / 10069 = getFTMState)，令牌 android.net.wifi.IOplusWifiManager
服务端: OplusWifiTransactionHelper.onTransact（手写 798 条指令，FTM 分支只有 enforceInterface）
      → HIDL vendor.oplus.hardware.wifi@1.1::IOppoWifiService
      → /odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service    ← init rc: user root
```

`/odm` 曾让四条取数路径全部失败——它不是独立分区，而是**封装在 `vendor.img` 里的 `euclid/odm.img`**。从 OTA 只取 584 MiB 的 `vendor.new.dat.br`，重建后就能把它挖出来。

挖出来之后，这条链的性质变了：服务以 **`user root`** 运行（caps `NET_ADMIN NET_RAW SYS_MODULE`）；二进制不导入 `system`/`popen`，而是手写 `execv("/vendor/bin/sh", {sh,-c,cmd})`，**9 个调用点**；虚表与 HIDL 事务号严格对应，`code 4 = executeDriverCommand = slot5`，函数体里 `hidl_string::c_str()` → 拷入命令缓冲 → 按前缀分支 → `std::string::append` → `sh -c`。

**⇒ "入参字符串被 uid 0 服务接收" 是已证事实；但"进入 `sh -c` 执行任意命令"后经 P0 静态分析否证（见下）。**

可达性曾一度被认为不通。11 次只读探测（`getFTMState`，无参）+ 2 组对照：

| 构造 | 结果 |
|---|---|
| 单令牌 4 种 / 无参 / 双令牌 4 种排列 | 全部 `SecurityException: Binder invocation to an incorrect interface` |
| 对照：`service call wifi 1`（AOSP 事务） | 正常返回 |
| 对照：`service call iphonesubinfo 1`（AIDL 需令牌） | 正常返回 IMEI |

对照证明工具与 binder 通路都正常、拒绝发生在**服务端**。后来把服务实现从 APEX（`/system/apex/com.android.wifi.apex` → `javalib/service-wifi.jar`）里挖出来，确认 `WifiServiceImpl.onTransact` 只有 18 条指令：先跑 AOSP stub，失败就转给 OPPO helper；而 helper 里唯一一处 `getCallingUid()` 只用来**拼日志**——**没有 uid 门禁**，唯一校验是 `enforceInterface(常量字符串)`。也就是说：**不是权限拦住了，是一个字符串还没对上**。随后用真 Java 客户端（`tools/javaprobe/`）验证：**字符串对上后，从 shell 调用成功，`getFTMState()` 返回 0**——此前 16 次 `service call` 失败纯属工具 ABI 问题。随后 tx10070 传入命令串，`logcat` 出现 `entering executeDriverCommand(myft -h)` 与 `completed successfully`——**但这是参数回显，不是执行证据**。所有带 shell 元字符的输入均返回 `failed: -3 INVAILD_PARAMETER` 并使服务崩溃，`id` 一次也没跑出来，没有任何 uid=0 回显。**"临时 ROOT 实锤"是误判，已撤回；项目维持 no-go。** 用户对此的质疑（"被拦了那么多次？有什么用？"）成立。

> 教训（三次自我推翻都记在 `HANDOVER.md` §16）：**报文类型不能反推门禁类型，参数回显不能当执行证据**。"没有 `Permission Denial`" 曾被读成"拒绝不在授权层"；`entering executeDriverCommand(...)` 这条入参回显曾被当成"命令已执行"——两次都错。

**P0 静态定性（§18）**：`-3 INVAILD_PARAMETER` 由 native `0x9ddc` 写入，根因是 `sub_9f64` 的 `std::regex("[@#$%&*^:;?|]+")`；Java 侧 `onValues` 只是 3 指令 lambda 壳、无码表。分支判据更正：进入 myftm 分支需前 5 字节恰为 `myftm`，历史 4 个注入串全是 `myft `（空格），走的是 iwpriv 分支。

> **⚠️ v2.10 外部复评更正（§20，来源 `审核意见CHATGPT-v002.txt`）**：上面"myftm 非任意命令执行"的断言**已撤销**——它混淆了 shell 参数分隔与控制操作符。逐指令重建 SSO 结构证实 myftm 分支命令为 `/vendor/bin/myftm <原始尾串>`，**无引号/转义/过滤**，`sh -c` 会解析 `;` `|` `&&` `$()` 等操作符（`0x9c08` 的 `0x22` 是 SSO 长度字节 17<<1，**不是引号**）。⇒ **myftm 注入面静态开放，Wi-Fi P0 重开、待授权验证 L3；仍无 ROOT 成功证据，整体 no-go 不翻转。** 复评结论为 Conditional GO：只针对 myftm 定向复审，不新增 CVE、不急着上机。

**P2 七服务收束（§19）**：6/7 定性。唯一有 `system(可控串)` 的 hephaestus 被 native `getCallingUid()==1000` 硬门禁挡住 shell(2000)；其余无命令原语或带签名校验；**antirootdialog 未完成（复评为新 P1）**。
> **状态更新（v2.14 / §24.13）**：该缺口已闭合——`anti_root_dialog_service` 是 service_manager 类型而非域，宿主域 `color_system_service_app` 全策略只有 `oplus_kevents` 能 `binder call`，shell 零权限 ⇒ **判不可达，七服务覆盖 7/7**。上句为 v2.11 时的历史状态。

**复评后新 P0/P1 执行（§21）**：新 P0 补齐静态证据——Java/HIDL 传输全程无过滤；`/vendor/bin/myftm` 是 getopt 工厂工具、system 命令硬编码，但**挡不住外层 `sh -c` 的 `;`**，故 myftm 注入面开放判定维持、L3 仍待授权上机。新 P1 解包 antirootdialog 仍未闭合，新增线索表明它是 native 守护进程（`/data/oplus/kevent` + `send_pid_to_kernel` + 独立 SELinux domain）。**整体 no-go / Conditional GO 不变。**
> **两处更正**：① antirootdialog 的"native 守护进程 / 独立域"线索**作废**——实测是 APK 宿主（`com.coloros.exsystemservice`）+ service_manager 类型，判不可达（§24.13）；② "L3 待授权"已完成，2026-11-18 12:07 上机取得 uid=0（§23）。

**同族接口与过滤边界（§22）**：把 vtable 的九个槽位全部落地成一张表后，有两个结论：

1. **过滤器本身有缺口**。`sub_9f64` 的模式串逐字节读出只有 11 个字符：`@ # $ % & * ^ : ; ? |`。它**不拦换行、反引号、`<`、`>`**——而换行对 `sh -c` 就是命令分隔符。所以"regex 校验通过"并不等于"命令串是一个 token"，**注入面也不再依赖 `myftm` 五字节前缀**：入参 `x\nid` 走 iwpriv 分支同样会拼成 `/odm/bin/iwpriv x` ⏎ `id`。历史四次失败实验之所以失败，是因为它们只试了 `;` 和 `|`——恰好都在黑名单里。
2. **同族接口不增加攻击面**。对全镜像做方法级检索：`runWiFiScript` / `sendSupplicantCommand` **没有任何 Java 调用方**（死入口），`catchSnifferLog` 只接受 `(int,int)` 且入口在 system_server 内部，`getIniVersion` 虽是把入参当路径 `fopen` 的任意 root 读、但同样无调用方。真正的风险仍集中在 `executeDriverCommand` 这一条。

同时更正一处旧记录：iwpriv 分支**不做**整数转换（`to_string(int)` 与 `setMonChan` 模板属 `catchSnifferLog`），它是把整条原始入参裸拼后只靠 regex 把关。

> 以上在 v2.12 时是静态推演。**v2.13 已上机证实**：载荷 `x\nlog -t P1UID `id`` 让 `sh -c` 以
> `uid=0(root)`、域 `u:r:oplus_wifi_service:s0` 执行，两次复现；`\n` 与反引号确实穿越了过滤器。
> 但该域被 MAC 限制（读不到 `/data/system`、`selinuxfs`、`proc_security`），**所以这是"受限 root 命令执行"，
> 不是可用 root**。原始日志见 `artifacts_adb/binder_audit/P1_L3_EVIDENCE.txt` 与 `HANDOVER.md` §23。

---

## 为什么这不是"没试够"

| 维度 | 已量化的事实 |
|---|---|
| 覆盖面 | 4 类组件、5 个内核候选面（KGSL / GhostLock / FastRPC / binder ×2 CVE）+ 2 条服务面线索（atlas、Wi-Fi 私有事务），全部有"机制是否成立"的判定 |
| 判据形式 | 全部可证伪：帧深区间 `[0x288, 0x2BE]`、连续非零前缀 `81/129/161 B`、`off_end` 三元式形态、spinlock 指令序列、`EPERM` 实测、**可达性二元探测（含对照组）** |
| 失败可解释 | 每一处失败都能指出"缺哪一环"，而不是"崩了" |
| 工具化 | 帧计算、载体扫描（含自我推翻的修正版）、NUL 语义取证、符号重建、补丁形态比对均已脚本化，可离线复跑 |
| 负知识 | 主动记录 **25 条**曾被自己认定为"确定"、后被实验或外部复审推翻的结论及推翻依据（`HANDOVER.md` §6 / §15.6 / §16.5 / §18 / §19 / §20），含扫描器漏报、"报文类型反推门禁类型"、"参数回显等于执行证据"、以及 v2.10 被外部复评推翻的"myftm 参数无法跳出固定 token" |

---

## 仓库结构

```
HANDOVER.md                 # 主文档：结论页 + 逐面论证 + 关键常数 + 重开条件
README.md                   # 本文件
LICENSE                     # MIT（代码）/ CC BY 4.0（文档）
tools/                      # Python 分析器 + C 实验程序（触发器与零风险探针）
├── gl_frame_calc.py        # 帧几何计算（读 vmlinux.elf，输出 waiter 绝对偏移）
├── gl_carrier_scan.py      # 397 个 syscall 入口的载体扫描（**历史基线，结果已作废**）
├── gl_carrier_rescan.py    # 修正版：按 (name,frames) 判重 + 补齐拷贝原语 → 3 条 xattr 候选
├── gl_nul_analysis.py      # 载体成立之后：NUL 语义 / 栈写区间 / 72B 字节映射
├── find_service_reg.py     # dex 内定位服务名/注册点/onTransact 分派（含 androguard hiddenapi 绕过）
├── ota_entry_range.py      # 只读 OTA ZIP 中央目录，算出任意条目的字节区间（不下整包）
├── ext4_find_offset.py     # 把 image 内字节偏移反查回文件路径（找 APEX 里的 jar 就靠它）
├── f16_rtmux_49_layout.py  # 4.9 rtmutex/futex 结构体布局（离线复算 waiter=72B）
├── f16_layout_v2.py        # task_struct 布局引擎（含 slab 校准）
├── g1_edeadlk.c → g3c_v7.c # 三锁环触发 + 三段式换向 + A′ 活帧对照
├── k3_*.c                  # KGSL 阶段 A/B/C 与竞速实验
└── surface_probe.c / frpc_ioctl_probe.c   # 攻击面普查、ioctl 表枚举
src_ref/                    # 权威源码与补丁（v4.9 tag 的 rtmutex.c/futex.c、修复 diff、RCA）
artifacts_adb/              # 设备原始输出与逐步日志（g_logs/），共 60+ 份
└── binder_audit/           # 审计报告：AUDIT_REPORT（atlas 五轮）、GHOSTLOCK_RESCAN、GHOSTLOCK_NUL_ANALYSIS、F16_WIFI_FTM_TRACE
docs_archive/               # 历史文档存档，见其中 README.md 的状态标注（数值不可引用）
firmware_F16/               # 仅说明文件：如何从自己的固件重建 vmlinux.elf
```

`.gitignore` 排除了厂商固件、内核二进制、厂商 Windows 工具包与第三方完整利用代码，原因见下一节。

---

## 离线复跑（不需要设备）

```bash
# 依赖
python -m pip install pyelftools capstone
#   注意：本机 pip 指向 Python312 而 python 是 3.13，两者不是同一环境，务必用 python -m pip

# 前提：自行重建 vmlinux.elf（步骤见 firmware_F16/README.md）

python tools/gl_frame_calc.py        # 帧大小与 waiter 绝对偏移 → -0x288
python tools/gl_carrier_scan.py      # 历史基线：397 个入口 → 0 命中（**该结果已作废**）
python tools/gl_carrier_rescan.py --mode context --copy-extra strncpy_from_user   # 修正后 → 3 条候选
python tools/gl_nul_analysis.py      # NUL 语义 / prologue 栈写区间 / 72B 字节映射
python tools/f16_rtmux_49_layout.py  # 4.9 结构体布局 → waiter = 72 B（非 80）

# Wi-Fi 私有事务面（§16）：从 OTA 到 vendor 镜像，全程离线
python tools/ota_entry_range.py <OTA_URL> vendor        # 列出 vendor.new.dat.br / transfer.list 的字节区间
python tools/dl_range.py <OTA_URL> <start> <end> out.br 16 ""    # 只取该区间（584 MiB）
python tools/rebuild_system.py out.br out.dat           # brotli 流式解压
python tools/sdat2img.py <transfer.list> out.dat vendor.img
# 7z x vendor.img euclid/odm.img   →   7z x odm.img "bin/hw/vendor.oplus.hardware.wifi@1.1-service"
python tools/find_service_reg.py <dex> wifinl80211      # dex 内定位服务名与分派点
```

设备侧实验（**会触发内核 panic，仅限自有设备**）：

```bash
ZIG=.build/zig-windows-x86_64-0.13.0/zig.exe
$ZIG cc -target aarch64-linux-musl -static -O2 -pthread -o .build/g3c_v7 tools/g3c_v7.c

export MSYS_NO_PATHCONV=1                       # Git Bash 必须关闭路径转换
adb push .build/g3c_v7 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/g3c_v7; timeout 25 /data/local/tmp/g3c_v7"
```

---

## 为什么二进制不在仓库里

1. **厂商固件不是我的版权**。`boot.img`（67 MB）、解压后的 `kernel.decompressed`（33 MB）、由此重建的 `vmlinux.elf`（39 MB）合计约 140 MB，属 OPPO 发行物及其派生二进制，不宜公开再分发。
2. **厂商工具包含授权组件**。`REF/` 内含 OPPO 官方刷机/鉴权程序的 exe/dll，同样不再分发。
3. **厂商二进制与镜像不入库**。`vendor.img`（2.09 GiB）、其内嵌的 `euclid/odm.img`（166 MiB）、
   以及从中提取的 `/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service` 均不随仓库分发；
   文档给出**从官方 OTA 只取 584 MiB 条目**的复现路径（`tools/ota_entry_range.py` + `dl_range.py`）。
4. **第三方完整利用代码不重新分发**。参考的公开 PoC 只在文档中标注出处，读者自行取用。

替代方案已给出：`firmware_F16/README.md` 说明如何从**自己的**固件或设备转储重建四件物料，并附自证方法（`stext` 反汇编应得到 `head.S`）。

**本仓库里没有任何可用于提权的完整利用代码。** `tools/` 下的 C 程序是触发与探针程序，在目标内核上的最好结果是 `-EDEADLK` 或 panic（DoS），不构成提权链。

---

## 责任使用

本项目的目的**只有一个**：判断"在不解 BL 的前提下，这台设备是否存在可行路径"，并把这个判断的依据留在可复核的形式里。

- 全部实验在**作者自有的设备**上进行，未针对任何第三方系统。
- **结论不是单一的"负结果"**：本项目确实取得了一项实证结果——**在 BL 锁定的设备上，从 shell 让厂商 root 服务以 `uid=0` 执行任意命令**（受限 SELinux 域，两次复现，§23）。
  但**"可用 root"与"持久 ROOT"仍判定为否**（域逃逸无路径，§24）。仓库不提供、也不承诺提供一键 root / 解锁能力。
- `tools/` 中的触发程序会使目标内核 **panic 并重启**。仅在你有权处置的设备上运行；不要在他人设备、生产设备或含未备份数据的设备上运行。
- 发布触发程序是因为它们是"机制是否成立"这一判定的唯一硬证据；若你重跑，请自行承担设备风险。
- 本项目包含一条对厂商私有接口的**分析**（`HANDOVER.md` §16–§23：`IOppoWifiService` 以 root 运行、从 shell 可达）。
  ⚠️ **这条链已被实证打通**：入参绕过 11 字符 regex 黑名单后进入 `sh -c`，以 `uid=0` 执行（§23）。
  因此**本仓库不提供、也不会补任何调用样例、命令串、载荷或利用代码**——只记录机制、判定与复现所需的判据。
  若你要在自己的设备上验证，请自行判断风险与合规性；对非自有设备使用等同于攻击。
- 发现本项目中任何**可用于真实攻击且有实际危害**的遗漏，请开 issue 而不是直接扩散。

---

## 审阅须知（v2.20）

本节是给外部复核者的**靶面说明**：列出五条结论、各自的判据强度、累计自我更正、建议优先攻击的点，以及"什么才算推翻"。

### 待审结论与判据强度

| # | 结论 | 判据 | 强度与已知弱点 |
|---|---|---|---|
| 1 | **`/dev/diag` 入口层无可利用缺陷** | 42 槽 ioctl 分派表全解（22 有效/20 `-EINVAL`）；入口三函数（`ioctl`/`write`/`read`）逐路径人工复核；脚本口径 301 符号/55 拷贝点/8 个变长全部给出上界出处；无 `mmap` | **强**（二进制级、可复算）。弱点：脚本只反汇编到首个 `ret`，大函数会被截断（`diagchar_write` 即不在矩阵里）——已用全路径复核补偿，**若复核不完整则是本结论的唯一软肋** |
| 2 | `plat_hwservice_contexts` 读不到是**策略约束**而非遗漏 | 该路径标签 `hwservice_contexts_file`；5 份 CIL 全量核对后只有 `hwservicemanager` 持有 read/getattr | **强**（纯策略文本，可 grep 复算） |
| 3 | **Wi-Fi 可写面消费不构成提权通道** | 三道前置门（连接/执行/触发）逐条封死；消费者域 binder 目标全量核对后**只有本域持有 `system_server`** | **中—强**。弱点在**枚举完备性**：消费者集合取自 §24.5 的读方列表**且依赖"本机导入哪份 rc"（G-W5，未证）**——若漏域或 rc 选错，本结论需重评 |
| 5 | **root 脚本消费 persist 配置 = 无新能力（实测闭合）** | `init.oppo.wifi.sh` 检查 `/mnt/vendor/persist/WCNSS_qcom_cfg.ini`（顶层）→ 实测**不存在**（真文件在 `persist/wlan/`）；且其 `cp` 两端都在本域可写的 `mnt_vendor_file` 内 | **强（已实测）**。连"新能力"都不成立；只剩"内核驱动如何解析该 ini"这个纯内核问题（§25 类），且需动 persist（禁写） |
| 4 | **`system_server` 通道在"取句柄"处断开** | ①本域对 `servicemanager` **零规则**（无 `binder call`、无 `service_manager find`）；②`binder call` 只对已持有句柄生效；③**HAL 侧也不递句柄**——二进制只注册 `IOppoWifiService`、无句柄入参、不导入 `readStrongBinder` | **强**（策略可 grep、二进制可复算）。残余：`_hidl_cb` 反向数据通道（G-S2，Java 侧） |

### 本轮自我更正（v2.17）

主动列出，避免复核者把已撤回的判断当成仍在支撑结论的依据：

| 原判断（v2.16） | 现状 | 触发来源 |
|---|---|---|
| 用 `init.wlan.atoll.rc` 代表本机平台 | **撤回**：本机 SoC 是 SDM710，`atoll` 公开对应 SM7125/720G 一系；应以 `ro.hardware` 决定导入哪份 rc（= G-W5，**尚未验证**） | 评审 v0041 第四节 |
| `fstman`「未部署」（无服务定义、无进程） | **撤回**：`ls -l /vendor/bin/fstman` 返回 *Permission denied* 而非 *No such file*；`vendor.qti.hardware.fstman@1.0-service.rc` 明确有 `fstman`/`fstman_wlan0`。正确表述是**实例存在但本域无法触发**（无 hwservice `find`、无 `binder call`） | 自查 + 评审 |
| 「diag 就算有漏洞也用不上」 | **收窄**：只对**依赖伪造内核指针**的利用链成立；不能推广到所有内存破坏类型 | 评审 v0041 第五节 |
| HANDOVER §25 的拷贝点计数写 56 | **已改 55**（与报告、README、原始矩阵一致） | 评审 v0041 第二节 |
| 用 rc 文本判断"某服务在本机存在/会读" | **纪律作废**：v2.18 实测 `init.svc.*` 显示 `hostapd`/`fstman`/`triggerwifidump` **均未定义**（`[]`），而 rc 文本里有定义 ⇒ **rc 文本 ≠ 生效集合**，一律以 `init.svc.*` 为准 | 设备实测（§28.2） |
| §26 消费者集合 = §24.5 读方列表 | **不完备**：漏了 `wifiserver`（`/odm/bin/init.oppo.wifi.sh`，root，开机跑）与 `wifisar`（root，属性触发） | 设备实测（§28.3） |
| §28.4 "root 脚本把 persist ini 复制成驱动配置 ⇒ R1 升级" | **再降级（同日两次翻转）**：实测该脚本检查的顶层路径**不存在**，且 `cp` 两端都在本域可写的 `mnt_vendor_file` 内 ⇒ **不提供任何新能力** | 授权探针（§28.9） |

### 请重点攻击的四点

1. **§24.5 的读方列表是否完整**（决定结论 3 是否成立）。若存在一个域：能读 `/data/vendor/wifi/**` 或 `/mnt/vendor/persist/**`，**且**能 `binder call` `system_server`/`vold`/`installd`，**且**我们可控其读到的内容 —— 结论 3 即被推翻。
2. **入口三函数的"逐路径复核"是否真穷尽**（决定结论 1）。具体可查：`diagchar_write` 的 `0x40`/`0x80`/`0x400` 三条路径之外，是否存在第四条能进入 `copy_from_user` 的分支；`diag_process_single_dci_pkt` 的 opcode 子集（`0x93/0x94/0x98/0x9a`）是否有上游越界。
3. **"别人递句柄"这一路是否成立**（决定结论 4 的边界）。若 OPPO Wi-Fi HAL 的某个 HIDL 方法接收 system_server 托管的回调对象，则该回调句柄**可能**带一个"显式允许 `ROOT_UID`"的方法（G-S1）。请指名接口与方法。
4. **`init.oppo.wifi.sh` 是否有我们漏掉的命令位置**（决定结论 5 的边界）。全文 1036 行、本地可得；我们只确认 `persist_version` 进的是 `[ -gt ]`。若你能指出它被用在命令位置（或某个 `$(( ))` / `eval` 里），结论 5 即升级为提权候选。
5. **是否还有未被枚举的攻击面**。这是唯一无法由内向外证伪的问题：本项目已覆盖 4 个内核面 + `/dev/diag` + Wi-Fi 私有事务 + 7 个私有 Binder 服务 + 域逃逸 + 可写面消费者 + `system_server` 句柄来源。**若存在第八类面，请指名。**

### 复现（全部离线，不需要设备）

```bash
# 结论 1：diag ioctl 分派表全表
python tools/kfn.py diagchar_ioctl --calls
# 结论 1：拷贝点长度来源全量扫描（输出即 artifacts_adb/binder_audit/diag/copy_matrix.txt）
python tools/klen_scan.py
# 结论 1：单个变长拷贝的判界上下文
python tools/kcopy.py diag_cmd_register_tbl diag_user_process_dci_apps_data diagmem_alloc
# 结论 2：该标签的授权域
grep -hoE "\(allow [a-z_0-9]+ hwservice_contexts_file(_30_0)? \(" .build/sepolicy/*.cil | sort -u
# 结论 3：消费者域的 binder 目标
grep -hoE "\(allow (hal_wifi_hostapd_default|hal_wifi_supplicant_default|wcnss_service|fstman) [a-z_0-9]+ \(binder" .build/sepolicy/*.cil | sort -u
# 结论 4：本域 binder / service_manager / hwservice_manager 权限全量
grep -hoE "\(allow oplus_wifi_service [a-z_0-9]+ \((binder|service_manager|hwservice_manager) \([^)]*\)\)" .build/sepolicy/*.cil | sort -u
# 结论 4：是否存在属性继承的全局 find 授予（应为空）
grep -hoE "\(allow domain [a-z_0-9]+ \(service_manager \([^)]*\)\)" .build/sepolicy/*.cil | sort -u
# 结论 5（只读，需设备）：生效服务集 + 平台
adb shell getprop ro.hardware; adb shell getprop ro.board.platform
adb shell "for s in hostapd fstman wifiserver wifisar triggerwifidump wpa_supplicant; do printf '%-16s [%s]\n' \$s \"\$(getprop init.svc.\$s)\"; done"
# 结论 5：脚本本体（本地 odm 解包，无需设备）
grep -nE "persist|WCNSS_qcom_cfg|insmod|eval|\$\(" .build/vendor/x/odm/bin/init.oppo.wifi.sh
# 结论 5 的实测（需设备；root 域只读，输出走 logcat、不落文件；需先推 ftmprobe.jar）
python tools/wifi_exec.py --tag GW6A --cmd 'log -t GW6A `ls -m /mnt/vendor/persist/`'
python tools/wifi_exec.py --tag GW6E --cmd 'log -t GW6E R-`ls -m /mnt/vendor/persist/wlan/`'
python tools/wifi_exec.py --tag GW6F --cmd 'log -t GW6F R-`ls -m /mnt/vendor/persist/WCNSS_qcom_cfg.ini`'
python tools/wifi_exec.py --tag GW6B --cmd 'log -t GW6B R-`cat /mnt/vendor/persist/bin_version`'
```

> 前置物料（`firmware_F16/vmlinux.elf`、`.build/sepolicy/`）不入库，见 `firmware_F16/README.md` 的本地重建步骤；
> `.build/sepolicy/` 由设备侧 `adb pull` 5 份 CIL + 各分区 contexts 得到（纯读取）。

### 推翻口径（本项目对"反驳"的要求）

沿用本项目一贯纪律：**只接受可复算的反例**，不接受"我觉得还可以试试"。

| 不构成推翻 | 构成推翻 |
|---|---|
| "diag 历史上出过漏洞" | 指明本机 `diag_process_single_dci_pkt` 下游某 opcode 的越界点，并给出可复算的反汇编地址 |
| "wifi 配置可写很危险" | 指出一个"读该路径 + 能呼 `system_server`/`vold`"的域 |
| "可能还有别的面" | 指名该面，并给出它在策略/rc/二进制中的存在证据 |
| 用不同 SPL/内核版本的结论外推 | 指明本机 SPL `2022-04-05` / 内核 `4.9.227-perf+` 下同一路径的差异 |

### 本轮刻意未做的事（避免把"没做"当"做了"）

- **未**做消费端解析器的二进制审计（G-W1）：`DIAG_DRIVER_AUDIT.md` §7 与 `WIFI_DATA_CONSUMER_AUDIT.md` §6 均已登记。
- **未**逐条审计 `vendor_oppo_prop` 55 条前缀的值语义（G-W2）。
- ~~未确认 init rc 的机型匹配~~ **已在 v2.18 闭合（G-W5）**：实测 `ro.hardware=qcom` ⇒ 生效文件 `init.wlan.qcom.rc`；v2.16 的 `atoll` 锚点已在 v2.17 撤回。
- **未**获取 `wifisar` 二进制（G-W7）：其 `getattr` 对 shell 被拒，且该服务我们**无法触发**（`sys.oplus.wlan.sar_idx` 属 `system_prop`）⇒ 属"对不可达路径做分析"，主动不做。
- **未**向 `/mnt/vendor/persist/**` 写任何内容（跨重启持久化，§24 R1 禁令）。

---

## 何时应重开

出现任一条即须重评（详见 `HANDOVER.md` §7）：

1. 出现面向 4.9 / arm64 **ticket spinlock** 的 UAF 原语研究 → binder 线可直接接上（靶点、pre-fix 证据、堆条件已备）。
2. **【GhostLock 现在的阻断点】** 出现**任一可用的内核地址泄露**（`/proc` 侧信道、驱动/binder 泄露、侧信道），
   或出现**不经 NUL 语义**、能把用户数据写到 `[-0x288, -0x240)` 的载体（例如某条路径让 xattr 的 *value* 经
   `__arch_copy_from_user` 落在 waiter 槽）→ GhostLock 立刻重开。**"再跑一次同样的构造"不会改变结论。**
3. 设备 **SPL 或内核构建变化** → 帧几何、binder 形态、全部符号偏移同时失效，须整体重跑（**故建议关闭 OTA**）。
4. 取得 **pstore / dmesg / last_kmsg** 任一 → 可定位 panic 精确点，判断是否为 vendor 差异。
5. GhostLock 上游出现**非栈复用**的利用路线。
6. **【Wi-Fi 命令拼接面·已打通】** ✅ 2026-11-18 12:07 上机达成：
   `\n`/反引号绕过 11 字符黑名单，`sh -c` 以 `uid=0` 执行（§23）。**主缺口转为 SELinux 域逃逸**：
   需要 `allow oplus_wifi_service …:file write` 的落点，或该域可写且被更高权限域消费的路径。
   ⚠️ 仍**不得**表述为"已 root / 可用 root"——域限制已实测（§23.4）。
7. **【Binder·P1，已闭合】** antirootdialog 判**不可达**（§24.13）：`anti_root_dialog_service` 是 **service_manager 类型**而非独立域，宿主为 `com.coloros.exsystemservice`（域 `color_system_service_app`）；全策略中能对该域 `binder call` 的只有 `oplus_kevents`，**shell 零权限**。七服务覆盖度 **7/7**。判定的性质是"策略不给路径"，不是"实现拿不到所以不知道"。
8. **【Wi-Fi 可写面消费者，v2.16 已审计】** 结论 **不构成提权通道**：三条前置门全封死（本域 `connectto` 只有 `init`；可写类型上 `execute` 的域数 = 0；`sys.oplus.wifi.dump.trigger` 属 `system_prop` 无 `set`）；**且跳板方向反了**——读这些路径的 hostapd / supplicant / wcnss_service / fstman / autochmod **全部无 `system_server` binder**，唯一持有该通道的是本域。本机 supplicant 与 hostapd **均无 `-c <config>`**（配置走 ctrl/HIDL），唯一带 `-c` 的 `fstman` **存在但本域无法触发**（无 hwservice `find`、无 `binder call`；v2.17 已撤回"atoll 未部署"的错误表述）。重开条件：出现 `-c` 指向可写路径 / 消费者域获得 `system_server`·`vold` 的 `binder call` / 可写类型获得 `execute` / 消费者解析器出现公开漏洞。详见 `HANDOVER.md` §26。
9. **【`/dev/diag`，v2.15 已审计】** 入口层**未发现可用缺陷**：42 槽 ioctl（22 有效/20 `-EINVAL`）、入口三函数逐路径复核穷尽、55/55 拷贝点定长或显式封顶（8 个变长逐个给出上界出处）、`write()` 三条路径的长度门全收敛到 `diag_mempools[].item_size`、**无 `mmap`**。重开条件：同源源码、或出现影响 `diag_process_single_dci_pkt` 下游（opcode `0x93/0x94/0x98/0x9a`）的公开漏洞、或出现新的内核地址泄露原语。**不重开**：盲目 ioctl 试错、fuzz、竞态实验（期望收益≈0，代价是 panic）。详见 `HANDOVER.md` §25。
10. **【`system_server` 通道，v2.17 已审计】** 结论：**在"取句柄"处断开**——本域对 `servicemanager` 零规则（无 `binder call`、无 `service_manager find`）。重开条件：①本域出现可用的 `servicemanager` 通道；②HAL 接收 system_server 回调且其方法显式允许 `ROOT_UID`；③某进程把 system_server 的**服务句柄**递进本域。详见 `HANDOVER.md` §27。

---

## 致谢

本项目的分析大量依赖以下公开工作：

- [`marin-m/vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) —— 本项目的转折点，把"符号不可用"变成可解。
- [`NebuSec/CyberMeowfia`](https://github.com/NebuSec/CyberMeowfia) —— CVE-2026-43499 的原始研究与 x86 链。
- `JoinChang/ghostlock-oneplus`、`mobilehackinglab/ghostlock-a17` —— arm64 移植与标定旋钮（`PSELECT_SHIFT` / `KPHYS` / `KIMAGE_TEXT_BASE`）。
- `0xkol`，《Racing Against the Lock》—— CVE-2022-20421 的论文级分析。
- Google Project Zero —— CVE-2023-33107 的 RCA（`src_ref/projectzero_33107_rca.md`）。
- Linux 内核 v4.9 源码（GPLv2）—— 全部结构体布局与行号引用的基准。

---

## English summary

**A documented negative result.** On an OPPO K3 (`PCGM00`, SDM710, kernel `4.9.227`, SPL `2022-04-05`, locked bootloader, shell-only access), five kernel-level candidate surfaces plus two service-level leads (the Wi-Fi private transaction and a seven-service audit) were evaluated for a temporary-root path. None is viable, and each one stops at a *nameable* gap rather than an unexplained crash:

- **KGSL `CVE-2023-33107`** — pre-fix in source, but `BUG_ON(!suppress_map_failures)` makes "reaching the bug" and "panicking" the same event. No intermediate state exists.
- **GhostLock `CVE-2026-43499`** — the vulnerability is real and deterministically reachable (`-EDEADLK`, 10+ reproductions), and the repointing primitive was positively proven with a live-frame control. An earlier "397 entries, 0 carriers" claim was **retracted**: the scanner deduplicated by function name and dropped 18,074 distinct stack-frame contexts. After the fix, three xattr paths carry a user-controlled 256-byte stack buffer that lands on the waiter slot. Static closure then shows the surviving gap is **not** the carrier — stack-slot reuse is geometric, and the `strncpy_from_user` NUL terminator is harmless because the masked-word store zeroes `prio`'s upper bytes for you. The gap is that `lock` and the rb-tree links must hold **non-zero kernel addresses**, and this build has no address-disclosure surface (KASLR on; kallsyms/dmesg/pstore unreadable).
- **binder `CVE-2023-20938`** — not introduced in this build (`off_end_offset` sits between `44d8047f1d87` and `32e9f56a96d8`).
- **binder `CVE-2022-20421`** — pre-fix, but this device uses a **ticket spinlock**, so the public qspinlock-based primitive degrades to "add `0x00010001` to a 4-byte word whose halves must be equal".
- **FastRPC `CVE-2023-33063`** — doubly closed for shell: `O_RDWR` denied by SELinux, and all seven implemented ioctls return `EPERM` on a read-only fd.
- **OPPO Wi-Fi private transaction** (non-kernel) — **this one worked.** `executeDriverCommand(String)` reaches `vendor.oplus.hardware.wifi@1.1-service` (init rc: **`user root`**), which ships a hand-rolled `execv("/vendor/bin/sh", {sh,-c,cmd})` with nine call sites. The private transaction is reachable from shell (proved with a real Java client: the only gate is a public descriptor string), and the sole input filter is a **11-character regex class** (`@ # $ % & * ^ : ; ? |`) applied after the raw string is appended to `/odm/bin/iwpriv `. It does not cover **newline, backtick, `<` or `>`** — so a payload such as `x
log -t P1UID `id`` is accepted and `/vendor/bin/sh -c` executes it as **`uid=0(root)`**, `context=u:r:oplus_wifi_service:s0`, reproduced twice on device (2026-11-18 12:07). That domain is MAC-confined (cannot read `/data/system`, `selinuxfs`, `proc_security`), so this is **confined root command execution, not a usable root shell** — the remaining gap is SELinux domain escape, not memory corruption. Raw logs: `artifacts_adb/binder_audit/P1_L3_EVIDENCE.txt`, write-up: `HANDOVER.md` §23.
- **Seven private services** (non-kernel) — P2 audited **7/7, all negatively closed**. The only one with `system(caller_string)` (hephaestus) is gated by a native `getCallingUid()==1000` check that rejects shell (uid 2000); the rest have no command-execution primitive or carry signature checks. `anti_root_dialog_service` turned out to be a *service_manager type*, not a domain: only `oplus_kevents` may `binder call` its host domain (`color_system_service_app`), and shell holds neither `find` nor `call` — **unreachable by policy**, not merely un-extracted. No shell-reachable root path.
- **`/dev/diag` (diagchar)** — a sixth kernel surface raised by review, audited statically against the 4.9.227 binary. **The entry layer is clean**: 42 ioctl slots (22 handled, 20 return `-EINVAL`), **all user-copy sites in the three entry functions are fixed-size or explicitly bounded** (all 8 variable-length ones traced to a concrete upper bound), all three `write()` command classes converge on `diag_mempools[].item_size`, there is **no `mmap`**, and the code carries the post-fix shape (`count >> 29` guard, inline `access_ok`, `__check_object_size`). Remaining depth is the DCI parser sub-tree (opcodes `0x93/0x94/0x98/0x9a`) — and, decisively, **any kernel bug here would still hit the same wall as GhostLock: this domain has no address disclosure**, so even a perfect memory-corruption primitive would have nothing to point at.

The write-up keeps the full evidence chain, the quantifiable gates, the reusable tooling, and — deliberately — **25 previously "certain" conclusions that were later falsified by this project's own experiments or external review** — including several cases where the author's own reasoning (or a too-eager "no-go" closure) was the thing that broke.

Start with [`HANDOVER.md`](HANDOVER.md).

---

## License

- 代码（`tools/`）：**MIT**，见 [`LICENSE`](LICENSE)。
- 文档（`HANDOVER.md`、`README.md`、`docs_archive/`）：**CC BY 4.0**。
- `src_ref/` 内的内核源码与补丁：保留原始许可（GPLv2 及其对应条款）。

分范围的完整说明见 [`NOTICE.md`](NOTICE.md)。
