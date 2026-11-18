# OPPO K3 临时 ROOT 可行性研究

> **一份负结果加上一次突破的完整记录**：在不解 BL 的前提下，对一台 OPPO K3（`PCGM00` / SDM710 / 内核 `4.9.227` / SPL `2022-04-05`）评估了五个内核候选面与两条服务面线索。**四个内核面判定不可达；GhostLock 阻断在"无内核地址泄露"；但 Wi-Fi 私有事务面在第 5 轮审计 + 外部复评 + 上机验证后被打通——从 shell 可让 root 服务以 `uid=0` 执行任意命令（2026-11-18 12:07，两次复现）。** 该 root 处于 SELinux 域 `oplus_wifi_service` 内、受 MAC 限制，**属"受限 root 命令执行"，尚非可用 root**；剩余缺口已从"内存破坏"变成"域逃逸"。七个未覆盖服务审计 6/7（antirootdialog 未完成）。曾有一次"结论翻转"误判，已撤回（§16.11）；本次 L3 与那次误判无关，用的是从未尝试过的 `\n`/反引号载荷。

| | |
|---|---|
| 目标设备 | OPPO K3 `PCGM00`（`OP4679`，`sdm710`），Android 11，内核 `4.9.227-perf+`（clang 10.0.7，2025-03 构建） |
| 安全补丁 | `2022-04-05` |
| 启动状态 | BL 锁定、AVB `green`、dm-verity `enforcing`、A-only |
| 可用入口 | `uid=2000(shell)` + `u:r:shell:s0`，SELinux Enforcing，**`Seccomp: 0`** |
| 结论 | **受限 root 已达成，可用 root 未达成。** 四个内核候选面不可达；Wi-Fi 私有事务面已打通：从 shell 发 tx 10070、载荷含 `\n` 或反引号即绕过 11 字符黑名单，`sh -c` 以 **`uid=0(root)`**、域 `u:r:oplus_wifi_service:s0` 执行任意命令（2026-11-18 12:07，两次复现）。**但该域受 SELinux 限制**（读不到 `/data/system`、`selinuxfs`、`proc_security`）⇒ 尚非可用 root，缺口是域逃逸。**域逃逸的静态审计已完成（v2.14 / §24）：该域内不存在可达的逃逸路径**——可写路径无任何域持有 `execute`、无 `mount` 权限、`module_load` 只对不可写的 `vendor_file` 生效、属性触发器无 `start`/`exec`、唯一域转换 `crash_dump` 零收益 |
| 私有 Binder 面 | atlas 线索 5/5 闭合、确定否证；**P2 补审 6/7**（见 `HANDOVER.md` §19）：hephaestus 有 `system()` 面但被 native `uid==1000` 门禁挡住 shell，其余无命令面/带签名校验；**antirootdialog 未完成**，复评为新 P1 |
| Wi-Fi 私有事务面 | **已利用成功**。路径：`tx10070 → helper(空权限) → HIDL → /odm/bin/iwpriv <载荷> → sh -c`。**v2.12** 证明过滤器只有 11 个字符（缺 `\n`、反引号、`<`、`>`）；**v2.13 上机验证**：载荷 `x\nlog -t P1UID `id`` 回显 `uid=0(root) gid=1010(wifi) … context=u:r:oplus_wifi_service:s0`，两次复现。同族另三接口无 Java 调用方，不增加攻击面。见 §23 / §22 |
| 设备终态 | 系统未变，**未刷写、未解锁、未改分区、未装持久化文件**；`/data/local/tmp` 已清空；累计 5 次内核重启（均为前期竞态实验，本轮 0 次） |

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
| **P2 七服务审计**（非内核面） | 不成立（6/7 定性） | hephaestus 的 `system(可控串)` 被 native `getCallingUid()==1000` 门禁挡住 shell(2000)；其余无命令原语或带签名校验 | 否（antirootdialog 实现未解出） |

完整论证、证据与可复算数字见 **[`HANDOVER.md`](HANDOVER.md)**。**新对话请从 §17「接手清单」开始**——当前状态、结论层次、工具路径与禁止重复的动作都在那里；P0/P2 收束在 §18/§19，外部复评与重开在 §20，复评后新 P0/新 P1 的执行结果在 §21，同族九类命令映射与过滤缺口在 §22，**上机取得受限 root（L3）在 §23**，**域逃逸 P0 静态审计（无出口）在 §24**。

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

**复评后新 P0/P1 执行（§21）**：新 P0 补齐静态证据——Java/HIDL 传输全程无过滤；`/vendor/bin/myftm` 是 getopt 工厂工具、system 命令硬编码，但**挡不住外层 `sh -c` 的 `;`**，故 myftm 注入面开放判定维持、L3 仍待授权上机。新 P1 解包 antirootdialog 仍未闭合，新增线索表明它是 native 守护进程（`/data/oplus/kevent` + `send_pid_to_kernel` + 独立 SELinux domain）。**整体 no-go / Conditional GO 不变。**

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
- 所有结论是**负结果**。仓库不提供、也不承诺提供 root / 解锁能力。
- `tools/` 中的触发程序会使目标内核 **panic 并重启**。仅在你有权处置的设备上运行；不要在他人设备、生产设备或含未备份数据的设备上运行。
- 发布触发程序是因为它们是"机制是否成立"这一判定的唯一硬证据；若你重跑，请自行承担设备风险。
- 本项目包含一条对厂商私有接口的**分析**（`HANDOVER.md` §16/§18：`IOppoWifiService` 以 root 运行、从 shell 可调用，
  但命令面是受限模板 + regex 黑名单，不构成任意命令执行）。
  仓库**只记录结论与复现方法，不提供任何调用样例、命令串或利用代码**。
  若你要在自己的设备上验证，请自行判断风险与合规性。
- 发现本项目中任何**可用于真实攻击且有实际危害**的遗漏，请开 issue 而不是直接扩散。

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
7. **【Binder·新 P1】** antirootdialog 解包仍未闭合（§21）：apk/odex/vdex 均无该类；
   新线索显示它是 **native 守护进程**（`/data/oplus/kevent` + `send_pid_to_kernel` + 独立 SELinux domain）。
   闭合需完整 factory 镜像或设备只读拉取（需授权）。hephaestus 的 `uid==1000` 门禁否证可靠。详见 §19/§20/§21。

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
- **Seven un-audited private services** (non-kernel) — P2 audited 6/7. The only one with `system(caller_string)` (hephaestus) is gated by a native `getCallingUid()==1000` check that rejects shell (uid 2000); the rest have no command-execution primitive or carry signature checks. `IAntiRootDialog`'s implementation remains un-extracted (the sole gap). No shell-reachable root path.

The write-up keeps the full evidence chain, the quantifiable gates, the reusable tooling, and — deliberately — **23 previously "certain" conclusions that were later falsified by this project's own experiments or external review** — including several cases where the author's own reasoning (or a too-eager "no-go" closure) was the thing that broke.

Start with [`HANDOVER.md`](HANDOVER.md).

---

## License

- 代码（`tools/`）：**MIT**，见 [`LICENSE`](LICENSE)。
- 文档（`HANDOVER.md`、`README.md`、`docs_archive/`）：**CC BY 4.0**。
- `src_ref/` 内的内核源码与补丁：保留原始许可（GPLv2 及其对应条款）。

分范围的完整说明见 [`NOTICE.md`](NOTICE.md)。
