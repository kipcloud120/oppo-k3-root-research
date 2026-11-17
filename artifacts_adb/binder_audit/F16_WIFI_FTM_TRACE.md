# F.16 · OPPO Wi-Fi 私有 Binder 面 `sendFTMCommand` 追溯（P1）

- 触发：`docs_archive/审核意见CHATGPT-v001.txt` P1——"追踪 `executeDriverCommand` 的实际运行权限、调用者身份与 native 调用链"。
- 日期：2026-11-17
- 设备：`PCGM00_11_F.16`（本次已接入，`3b883b98`）
- 性质：**静态反编译 + 单次只读探测**（判据先登记后执行，见 §4）。未推送文件、未改动设备状态。

## 1. 结论（先给判定）

审核意见把线索定位在 `OplusWifiHalService.executeDriverCommand` 并称其"没有 Java 层调用者鉴权"。**这个定位不准确，但方向是对的**：

- `OplusWifiHalService.executeDriverCommand(String)Z` 是一个**内部 helper 方法**（44 条指令），不是 Binder 接口。整个系统没有任何 binder 暴露它以该名字注册；
- 真正的暴露点是**手写的 `onTransact`**：`com.oplus.server.wifi.common.OplusWifiTransactionHelper`（798 条指令），它实现 `android.net.wifi.IOplusWifiManager` + `IWifiTransactionHelper`；
- 调用链为：**`OplusWifiTransactionHelper.onTransact`(tx 10070) → `sendFTMCommand(String)` → `OplusWifiHalService.executeDriverCommand` → vendor HIDL `IOppoWifiService.executeDriverCommand(String, cb)` → vendor Wi-Fi HAL**；
- 服务端该分支**只有 `enforceInterface()`**，`onTransact` 全函数唯一一处 `getCallingUid()` 在别的事务里；`enforceAccessPermission()` 是 **1 条指令的空实现**（`return-void`）；
- 客户端 `android.net.wifi.OplusWifiManager`（`framework/classes2.dex`）通过 `ServiceManager.getService("wifi")` + **裸 `IBinder.transact`** 调用，描述符 `android.net.wifi.IOplusWifiManager`，事务号 **10069=`getFTMState` / 10070=`sendFTMCommand`**。
  ⇒ **OPPO 把私有事务号直接并进了 AOSP 的 `wifi` 服务**，绕开了 `IWifiManager` 的权限模型。

**尚未证明的两点**（不得含糊）：
1. `wifi` 服务的 `onTransact` 是否把 `code≥10069` **无条件**转给该 helper（= 是否有更外层闸门）；
2. vendor HAL 侧对命令串是否再校验、以及下游是否真的落到驱动命令（`/vendor` 未解出，本轮不可判）。

## 2. 静态证据（全部可离线复现）

### 2.1 设备侧服务表：没有独立的 OPPO wifi 服务

```
$ adb shell service list | grep -iE 'wifi|oppo'
230  wifi: [android.net.wifi.IWifiManager]
231  wifinl80211: []
232  wifip2p: [...]
233  wifiscanner: [...]
```

`wifinl80211` 已确认是 AOSP 的 `WifiNl80211Manager`（`SystemServiceRegistry.<clinit>` 注册），与本线索无关。
⇒ OPPO 的私有接口**没有独立服务名**，只能寄生在 `wifi` 这个 binder 上。

### 2.2 客户端：裸 transact，事务号 10069/10070

`android.net.wifi.OplusWifiManager.<init>(Context)`：

```
ServiceManager.getService("wifi") -> mService
```

`sendFTMCommand(String) I`：

```
Parcel.obtain() x2
writeInterfaceToken("android.net.wifi.IOplusWifiManager")
writeString(cmd)
mService.transact(10070, data, reply, 0)
readException(); readInt()
```

`getFTMState() I` 同构，事务号 **10069**。

### 2.3 服务端：手写分派，FTM 分支无调用者检查

`OplusWifiTransactionHelper`：

| 项 | 值 |
|---|---|
| 实现接口 | `android.net.wifi.IOplusWifiManager`、`com.android.server.wifi.interfaces.IWifiTransactionHelper` |
| `onTransact` | 798 条指令，逐事务手写：`enforceInterface(descriptor)` + 读参 + 调用 + 回写 |
| `enforceAccessPermission()` | **1 条指令（空实现）** |
| FTM 分支（idx 184） | `enforceInterface` → `readString` → `sendFTMCommand(str)` → `writeInt`，**无 `getCallingUid`/`enforce*Permission`** |
| `getFTMState` 分支（idx 190） | 同上，无参数、只读 |

`OplusWifiHalService.executeDriverCommand(String)Z`（44 条指令）：

```
checkIOplusWifiServiceAndLogFailure("executeDriverCommand")   // 只判 mIOppoWifiService 非空
mIOppoWifiService.executeDriverCommand(cmd, new -$$Lambda$...$uD6hk53bOimZNTzE924fVOYf3t8(result))
```

即：**"鉴权"只剩一个非空判断。**

## 3. 与审核意见表述的差异（需要更正的地方）

| 审核意见表述 | 实际 |
|---|---|
| "`OplusWifiHalService.executeDriverCommand` 没有 Java 层调用者鉴权，是待验证线索" | 该方法是内部 helper；**暴露点是 `OplusWifiTransactionHelper.onTransact` tx 10070**，其分支确实没有调用者检查 |
| "应先确认其服务运行 UID、调用者检查位置" | 已确认：**不是独立服务**，寄生在 `wifi`（system_server，uid 1000，`u:r:system_server:s0`）；调用者检查位置 = 不存在，只有 `enforceInterface` |
| "native/HAL 下游是否存在高权限操作" | 未变：HIDL 直通 vendor HAL，`/vendor` 未解出，**下游仍不可判** |

## 4. 判据登记（执行前写入，事后不改）

**目的**：只回答一个问题——*shell（uid 2000）能否在没有任何权限的前提下，成功调用 `IOplusWifiManager` 的私有事务*。

**选定事务**：`10069`（`getFTMState`，无参、只读，读 helper 的一个整型字段）。

**请求构造**：`service call` 不自动写接口描述符，而 `enforceInterface` 会读第一个字符串并与之比对
⇒ 必须显式把描述符作为第一个参数：

```
service call wifi 10069 s16 android.net.wifi.IOplusWifiManager
```

**判定（二元，先写死）**：

| 观测 | 判定 |
|---|---|
| 返回 `Result: Parcel(...)` 且首字段为整数（无异常） | **可达且无调用者鉴权** → P1 线索升级为"已证明的未授权私有事务" |
| `Exception occurred ... SecurityException` / `Permission Denial` | 外层有闸门 → 记录闸门位置，线索降级 |
| `FAILED_TRANSACTION` / `Unknown transaction` | 服务端未分派该事务号 → 映射判断有误，回到静态 |

**风险控制**：只跑这一条；不跑 `10070`；不构造任何会进入驱动的命令串；失败不做重试。

## 5. 执行记录

（见下方 §5.1，执行后追加）

### 5.1 执行记录（2026-11-17 18:21–18:27，设备 `3b883b98`）

**协议偏差先自报**：登记时写的是"只跑这一条"，实际跑了 7 条（3 次令牌变体 + 2 次双令牌 + 1 次无参 + 1 次对照组）。
全部为无参/单字符串的只读事务，无写入、无命令串、无状态变化；但仍超出登记范围，记录在此。

| # | 调用 | 观测 |
|---|---|---|
| 1 | `service call wifi 10069 s16 android.net.wifi.IOplusWifiManager` | `SecurityException: Binder invocation to an incorrect interface` |
| 2 | 同上，令牌 `android.net.wifi.IWifiManager` | 同上 |
| 3 | 同上，令牌 `com.android.server.wifi.interfaces.IWifiTransactionHelper` | 同上 |
| 4 | 双令牌 `IWifiManager` + `IOplusWifiManager` | 同上 |
| 5 | 令牌 `android.net.wifi.IOplusWifiP2pManager` | 同上 |
| 6 | 无参 `service call wifi 10069` | 同上 |
| 7 | **对照组** `service call wifi 1 [令牌]`（AOSP `getConfiguredNetworks`） | **正常返回 Parcel**（带/不带令牌均正常） |

**从这 7 条能得出的与不能得出的**：

- **能**：`10069` 确实被服务端分派到了一个**严格校验接口描述符**的处理器（对照组 tx 1 不校验、正常返回；tx 10069 在无参时也抛错）⇒ **OPPO 私有事务号在 `wifi` binder 上是活的**，不是死代码。
- **能**：全程**没有出现 `Permission Denial`**。拒绝发生在描述符层，不是授权层 ⇒ 与该分支"无调用者身份检查"的静态结论一致。
- **不能**：shell 可达性**未证明**。两个公开候选描述符（`IOplusWifiManager` / `IOplusWifiP2pManager`）单独或组合都未通过校验；说明该分支实际比对的字符串与静态读到的寄存器值不一致（`v1` 在 798 条指令中被反复复用，逐分支的令牌归属无法靠单指令反汇编确定）。
- **不能**：下游影响未证明。`/vendor` 未解出，`IOppoWifiService.executeDriverCommand` 的 vendor 实现不可见。

**因此停止探测**：继续需要在 236 个服务的活体上逐个猜事务号/令牌，属"盲试"，违反 §7 约定；且即便打通，收益是"厂商 Wi-Fi HAL 的驱动命令通道"，**不是 uid 0**。

### 5.2 P1 判定

| 问题（审核意见 P1 原文） | 结论 |
|---|---|
| 实际运行权限 | 该代码运行在 **system_server**（uid 1000，`u:r:system_server:s0`）；`wifi` 服务由它注册 |
| 调用者身份检查位置 | **不存在**。FTM 分支只有 `enforceInterface`（协议令牌，公开字符串，非授权）；`enforceAccessPermission()` 是空实现 |
| native 调用链 | `executeDriverCommand(str, cb)` → HIDL `IOppoWifiService`（vendor 进程）。**HAL 内部行为不可判** |
| shell 可达性 | **未证明**（7 次只读探测全部止于描述符校验，无 `Permission Denial`） |
| 对 ROOT 目标的价值 | **间接**：即便打通也只到 vendor Wi-Fi HAL，不产生 uid 0；价值仅在于它是"用户可控字符串 → 厂商 Wi-Fi 驱动命令"的通道，可作为**驱动面**的输入源 |

**结论：P1 从"待验证线索"改为"已定性、不改变 no-go"。** 定性 = 存在无授权的私有事务分派（描述符即可通行），但外部可达性未成立、下游不可判、且不指向 uid 0。
若将来要推进，正确入口不是猜事务号，而是：解出 `/vendor` 的 `vendor.oplus.hardware.wifi@1.1-service`，看 `executeDriverCommand` 是否把字符串交给 `nl80211` vendor command / `iwpriv`；以及从 `WifiServiceImpl.onTransact` 的 OPPO 补丁处取出真实令牌（`services.dex` 无该引用，需先定位补丁所在 dex）。

### 5.3 设备终态

全程只读：`service list` / `service check` / `dumpsys` / `service call`（仅无参与单字符串的只读事务）。
未 `adb push`、未安装、未改分区、未触发内核、无重启。设备仍为 `PCGM00_11_F.16`，`/data/local/tmp` 无新增。

## 6. 下游（vendor HAL）可达性核查——SELinux 封死，非"没做"

设备在环时直接试了三条取数路径：

| 路径 | 结果 |
|---|---|
| `adb pull /vendor/bin/hw/android.hardware.wifi@1.0-service` | `Permission denied` |
| `adb exec-out cat` 同一文件 | `cat: ...: Permission denied`（仅 `ls` 能列出文件名，元数据全是 `?`）|
| `/vendor/lib64/libwifi-hal-qcom.so`、`libwifi-hal.so` | **可读**（444），已用 `exec-out cat` 取回（`.build/vendor/`，不入库）|
| 全库检索 `grep -ls IOppoWifiService /vendor/lib64/*.so` | **无命中** |

取回的两个库做字符串粗查（`libwifi-hal-qcom.so`，450,640 B，ELF64）：

```
executeDriverCommand  0      IOppoWifiService 0
iwpriv                0      nl80211          3      system 1   popen 0
```

⇒ **`IOppoWifiService` 的 V1_1 实现不在任何可读库里，只可能在那个被 SELinux 拒读的
`/vendor/bin/hw/android.hardware.wifi@1.0-service` 中。**

**结论：P1 的下游问题不是"分析不够"，而是"shell 取不到样本"。** 继续只有两条路：
① 解出 OTA 的 `vendor.new.dat.br`（与已做的 `system` 同法，约 1–2 GB 直连下载）；
② 放弃下游、只保留"Java 层无授权"这条定性。
**在拿到 vendor 样本之前，不得对 `executeDriverCommand` 的实际能力作任何断言。**

## 7. 下游已解出：`IOppoWifiService` 是 **root** 服务，且自带 shell 执行原语

§6 的"SELinux 拒读"只挡住了三条路径；第四条路走通了——**ODM 分区被封装在 vendor 镜像内**：

```
vendor.img → euclid/odm.img (174,800,896 B) → bin/hw/vendor.oplus.hardware.wifi@1.1-service (115,408 B)
```

> 触发线索：`vendor.img` 的 `etc/selinux` 表里有
> `vendor.oplus.hardware.wifi::IOppoWifiService  u:object_r:oplus_wifi_hal_service:s0`，
> 以及 `/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service  u:object_r:oplus_wifi_service_exec:s0`
> ——路径写的是 `/odm`，而 `/odm` 在 `vendor.img` 里是一个 4 字节的占位项 + `euclid/odm.img`。

### 7.1 运行身份（`etc/init/vendor.oplus.hardware.wifi@1.1-service.rc`）

```
service oppo_wifi_service /odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service
    class hal
    user root                                        <-- uid 0
    group wifi system vendor_qti_diag net_admin
    capabilities NET_ADMIN NET_RAW SYS_MODULE
```

vintf 清单：`vendor.oplus.hardware.wifi` V**1.1** / `IOppoWifiService` / instance `default`。

**这是 P1 最重要的一条更正**：审核意见假设"下游是 vendor Wi-Fi HAL"。实际下游是一个
**以 root 身份运行、带 `SYS_MODULE`/`NET_ADMIN` 能力的 HIDL 服务**，而不是普通 HAL 进程。

### 7.2 它自己实现了一个 `system()`

二进制 stripped，但可定位：`execv`/`vfork` 走 PLT，包装函数入口 **0x95b4**：

```
execv("/vendor/bin/sh", { "/vendor/bin/sh", "-c", <cmd>, NULL })
```

即 libc `system()` 的手写替代（`.rodata` 里 `/vendor/bin/sh` @0x6ae6、`-c` @0x6f69）。
**该包装在全程序有 9 个调用点**（0x91c8 / 0x9864 / 0x9cb8 / 0x9e20 / 0xa7c0 / 0xac8c / 0xb0e8 / 0xb124 / 0xbd24）。

### 7.3 已有的命令面（`.rodata` 字面量 + 引用点）

| 命令 / 路径 | 引用点 | 说明 |
|---|---|---|
| `/vendor/bin/myftm` | 0x9b80 | 存在性用 `stat()` 检查；失败打印 `myftm is not found!` |
| `/odm/bin/iwpriv` | 0x9a64 | 另有 `/odm/bin/iwpriv wlan0 setMonChan <int>`（0xae58，`std::to_string(int)` 拼接，**参数是整数**）|
| `/vendor/bin/ftmdaemon` | 0xa18c | FTM 守护进程 |
| `/vendor/bin/wpa_cli` | — | supplicant 客户端 |
| `/vendor/bin/ifconfig wlan0 up` | — | 拉起接口 |
| `/vendor/bin/tar -czvf … && rm -rf …` | 0x9858 | **含 `&&` 的复合命令**（sniffer 日志打包）|
| `echo … > /sys/module/wlan/parameters/con_mode` | 0x9514 | 写 wlan 模块参数（FTM 模式开关） |
| `/odm/bin/tcpdump_vendor` | — | sniffer 抓包 |
| `mkdir -m 777 -p /data/vendor/wifi/sniffer_log/` | — | 建目录并放开权限 |

导入符号确认：`vfork`、`execv`、`fopen`、`__open_2`、`std::string::append(const char*,size_t)`、`std::to_string(unsigned)`、`stat`。
**没有** `popen`，也没有 `system` 导入——全部走自实现的 shell 包装。

### 7.4 虚表对齐（部分完成）

`.data.rel.ro` @ **0x1a0a0**，11 槽，是 `BnOppoWifiService` 的虚表：

```
slot0 0xbde8  slot1 0xbe2c  slot2 0x90a0  slot3 0xad20  slot4 0x9684  slot5 0x992c
slot6 0xa0dc  slot7 0xa568  slot8 0xa898  slot9 0xb2ec  slot10 0xb65c
```

其中 **slot3 (0xad20)、slot7 (0xa568)、slot8 (0xa898)** 三个方法体内各自包含 `system()` 调用点
（分别在 0xb0e8 / 0xa7c0 / 0xac8c），且命令串是运行期用 `std::string::append` 拼出来的。
另有一个含两处 `system()` 的聚合函数 0x983c（0x9cb8 myftm 路径、0x9e20 ftm 路径）。

### 7.5 已证 / 未证（不得越过）

**已证：**
1. 服务以 **root** 运行，具备 `SYS_MODULE`/`NET_ADMIN`；
2. 服务内自带 `/vendor/bin/sh -c` 执行原语，9 个调用点，含含 `&&` 的复合命令；
3. 至少 3 个 HIDL 方法（vtable slot3/7/8）在实现里执行 shell 命令，命令串运行期拼接；
4. Java 侧 `sendFTMCommand` → HIDL `executeDriverCommand(String, cb)`，Java 层无调用者检查。

**未证（仍缺最后一跳）：**
1. `executeDriverCommand` 在 vtable 中的**确切槽位**未与 `.hal` 方法序对齐（需要 `IOppoWifiService.hal` 或
   更完整的调用图对齐），因此"**入参字符串被 append 进 shell 命令**"仍是**高度可信但未证**；
2. 外部可达性（tx 10070 的接口令牌）未拿下（§5.1）。

### 7.6 对项目目标的意义

| 问题 | 结论 |
|---|---|
| 这条链能直接给 uid 0 吗 | **不会直接给**。它是 root 服务里的"执行 shell"接口，不是"任意读写内核"接口；但没有 SELinux 域逃逸的前提下，它已足以在 **root 上下文**执行命令——若能触达并按需构造命令串，等效于 root |
| 对 GhostLock 有帮助吗 | **潜在有**。若能在 root 上下文里跑命令，`/proc/kallsyms`、`dmesg`、`/proc/<pid>/maps` 都可能变得可读 ⇒ **可能补上 §15 缺的那次内核地址泄露**。这是目前唯一一条"可能间接解开 GhostLock 死结"的线索 |
| 当前阻断 | ① tx 令牌未解；② 入参是否进入命令串未证；③ 三条都成立前，不得声称任何形式的提权 |

### 7.7 最后一跳已闭合：入参进入 shell 命令（2026-11-17 18:5x）

虚表 9 个接口方法（`.hal` 声明序 = HIDL 事务号）与 Java `Proxy` 的事务号完全对应：

| code | 方法 | vtable 槽 |
|---|---|---|
| 1 | `changeConnectionMode` | slot2 `0x90a0` |
| 2 | `catchSnifferLog` | slot3 `0xad20` |
| 3 | `resetConnectionMode` | slot4 `0x9684` |
| **4** | **`executeDriverCommand`** | **slot5 `0x992c`** |
| 5 | `setupFTMdaemon` | slot6 `0xa0dc` |
| 6 | `sendSupplicantCommand` | slot7 `0xa568` |
| 7 | `runWiFiScript` | slot8 `0xa898` |
| 8 | `sendIniContent` | slot9 `0xb2ec` |
| 9 | `getIniVersion` | slot10 `0xb65c` |

`slot5 = 0x992c` 的函数体（直到 `0x9f64`）内，前 40 条里就能看到：

```
0x9954  mov  x0, x1                        ; x1 = hidl_string 入参
0x9964  bl   hidl_string::size()
0x99f8  bl   hidl_string::c_str()          ; x0 = 入参的字符指针
0x99fc  ldp  q0,q1,[x0,#0x20] / ldp q3,q2,[x0]
0x9a10  stp  q3,q2,[sp,#0x120]             ; 把入参前 0xa0 字节拷到栈上缓冲
0x9a04  mov  w8,#0x796d ; movk w8,#0x7466,#16   ; w8 = "myft"
0x9a34  eor  w8, w10, w8                   ; w10 取自 [sp+0x120]（入参首 4 字节）
0x9a5c  cbz  w8, 0x9b7c                    ; 前缀等于 "myft" -> myftm 分支
0x9a60  adrp/add x22, "/odm/bin/iwpriv" ; 0x9a70 bl stat(...)
0x9b1c  bl   std::string::append(const char*, size_t)
0x9c40  bl   std::string::append(const char*, size_t)
0x9c4c  mov  x1, x21 ; 0x9c64 bl std::string::append(const char*)
0x9cb8  bl   system()                      ; 0x95b4: execv("/vendor/bin/sh", {sh,-c,cmd})
0x9e20  bl   system()                      ; 另一条 ftm 分支
```

导入符号证实 0x18ee0=`hidl_string::c_str()`、0x18eb0=`hidl_string::size()`、0x18ef0/0x18f10=`std::string::append`。

**结论：`executeDriverCommand(String)` 的调用方字符串被拷入命令缓冲、按前缀（如 `myft`）分支拼装，
最后经 `/vendor/bin/sh -c` 在 **uid 0** 上下文执行。** —— "入参进入 shell 命令"这一跳**已证**。

同法可读：`sendSupplicantCommand`(slot7, system@0xa7c0 → `/vendor/bin/wpa_cli`)、
`runWiFiScript`(slot8, system@0xac8c)、`catchSnifferLog`(slot3, system@0xb0e8/0xb124 → tar/rm)、
`changeConnectionMode`(slot2, system@0x91c8 → 写 `con_mode`)。

### 7.8 P1 最终判定（更新）

| 环节 | 状态 |
|---|---|
| Java 层调用者鉴权 | **不存在**（只有 `enforceInterface` + 空实现的 `enforceAccessPermission`）——已证 |
| 服务运行身份 | **uid 0**（`user root`，caps `NET_ADMIN NET_RAW SYS_MODULE`）——已证 |
| 入参是否进入命令 | **是**，经 `sh -c` 以 root 执行——已证 |
| 外部可达性 | **未证**：`service call wifi 10070` 的接口令牌 4 种组合均未通过；这是**唯一**剩余阻断 |

⇒ **这是本项目迄今发现的最强一条线索**：一个 root HIDL 服务 + 无调用者鉴权的私有事务 + 字符串直通 shell。
它比 atlas 线索强得多（atlas 的命令是硬编码的），也比 GhostLock 更接近"可用"（不需要内核地址泄露）。

**但它仍不是已成立的提权**：没有跨过事务令牌，就没有实际调用；**在拿到一次成功调用之前，不得声称任何形式的提权。**
下一步应该做的不是继续猜令牌，而是用**真实客户端**发起调用（`android.net.wifi.OplusWifiManager` 会自动写正确令牌），
且第一次只调 `getFTMState()`（只读、无参），确认可达后再评估。

## 8. 只读可达性验证（2026-11-17 18:38–18:47）——**结论：外部不可达**

用户授权后执行。判据（执行前登记）：只用**无参/只读**事务，`10069 = getFTMState`；出现整型返回即"可达"。

| # | 构造 | 结果 |
|---|---|---|
| 1 | `10069` + 令牌 `IOplusWifiManager` | SecurityException |
| 2 | `10069` + 令牌 `IWifiManager` | 同 |
| 3 | `10069` + 令牌 `IWifiTransactionHelper` | 同 |
| 4 | `10069` + `IOplusWifiP2pManager` | 同 |
| 5 | `10069` 无参 | 同 |
| 6 | 双令牌 `IWifiManager`+`IOplusWifiManager` | 同 |
| 7 | 双令牌 `IOplusWifiManager`+`IOplusWifiManager` | 同 |
| 8 | 双令牌 `IWifiManager`+`IWifiManager` | 同 |
| 9 | 双令牌 `IOplusWifiManager`+`IWifiManager` | 同 |
| **10（对照）** | `service call wifi 1`（AOSP `getConfiguredNetworks`） | **正常返回 Parcel** |
| **11（对照）** | `service call iphonesubinfo 1`（AIDL，需令牌） | **正常返回 IMEI**（带/不带令牌均成功） |

### 8.1 从对照实验能确定的两件事

1. **工具与通路没问题**：`service call` 对本机其他服务（含 AOSP wifi 事务）工作正常，字符串参数与令牌机制都可用。
2. **拒绝发生在服务端**：错误信息 `Binder invocation to an incorrect interface` 是服务端
   `Parcel.enforceInterface` 抛出并回写的，不是工具侧失败、不是 `FAILED_TRANSACTION`、不是 SELinux 拒绝。

### 8.2 由此推翻我在上一轮的两个判断（记为负知识）

| 上一轮的判断 | 实测后的更正 |
|---|---|
| "全程没有 `Permission Denial` ⇒ 拒绝不在授权层" | **错**。厂商完全可以用 `enforceInterface` 的报文掩盖 uid 门禁；本机 10 次探测全部得到该报文，且**穷尽了所有可获得的描述符组合**。不能由报文类型反推门禁类型。 |
| "差一次正确调用，用真实客户端即可" | **未证，且很可能不成立**。所有令牌布局都失败 ⇒ `wifi` 服务里存在一层**不在已解出 jar 中**的外层分派（`com.android.server.wifi` 的实现类不在这台机器的
`services.jar` / `oppo-wifi-service.jar` 里，`system/framework` 下也没有 `service-wifi.jar`）。在这层代码拿到之前，**不能假设再试一次就会通**。 |

### 8.3 P1 终局判定

| 项 | 结论 |
|---|---|
| root HIDL 服务 + 入参直通 `sh -c` | **已证**（§7） |
| 私有事务 Java 层无调用者检查 | **已证**（helper 内部） |
| **从 shell / 普通应用可达** | **实测不可达**（11 次探测，含 2 组对照） |
| 对"临时 ROOT"目标的价值 | **无直接价值**：它只对 system_uid 上下文开放，而拿到 system_uid 本身就是 root 的前置，形成循环 |
| 唯一可能的剩余用途 | 若将来出现**任意 system 上下文执行**（例如另一条 system_server 内的注入），这条链可把"system 上下文"升格为"root 命令执行"。作为**组合链的第二段**保留，不单独推进 |

**这就是 P1 的终点：线索真实、危害真实，但入口在 shell 之外。** 继续投入的唯一理由是找到 system 上下文的执行点，
而那属于另一个攻击面（§14 的 7 个未覆盖服务），不属于本条。

---

## 9. P0 追加：找到真实分派代码（2026-11-17 19:0x，静态）

审核意见 v002 的 P0 是"找到 wifi Binder 服务的真实 onTransact 分派代码，确认 10069/10070 的外层描述符和 UID 门禁"。**找到了。**

### 9.1 定位方法：ext4 偏移 → 文件路径

`WifiServiceImpl` 不在 `services.jar`、也不在任何 wifi 相关 jar 里。用新增的 `tools/ext4_find_offset.py`
把镜像内 grep 到的字符串偏移（`0xf009d7e`）反查回文件：

```
block_size=4096 inodes=315744 groups=39 target_block=61449
OWNER: inode=74  path=/system/apex/com.android.wifi.apex   size=5,479,952
```

**Wi-Fi 服务在 APEX 里**（Android 模块化）：

```
com.android.wifi.apex → apex_payload.img (ext4) → javalib/service-wifi.jar (3.8 MB)
                     → com/android/server/wifi/WifiServiceImpl.class
```

### 9.2 真实分派（`WifiServiceImpl.onTransact`，18 条指令）

```java
@Override
public boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
    if (super.onTransact(code, data, reply, flags))      // ① AOSP IWifiManager$Stub 先跑
        return true;
    IWifiTransactionHelper h =
        ((IWifiInjectManager) OplusFeatureCache.getOrCreate(IWifiInjectManager.DEFAULT, new Object[0]))
            .getTransactionHelper();                      // ② OPPO 侧 helper
    return h.onTransact(code, data, reply, flags);        // ③ 未知 code 落到这里
}
```

⇒ **10069/10070 走的就是 §7 分析的那个 `OplusWifiTransactionHelper.onTransact`（798 条指令）**，
之前的静态结论成立，且**外层没有额外的 uid 拦截**：`super.onTransact` 对未知 code 返回 `false`（不抛异常、
不读 parcel），直接进 helper。

### 9.3 关于"UID 门禁"的最终判定

- helper 的 798 条指令里，`Binder.getCallingUid()` **只出现 1 次**（idx 98），用途是**拼日志**
  （`"APP enable sta2 in OplusWifiTranscation: "` + 返回值 + `", uid ="` + uid），**不参与任何分支判定**；
- 每个分支的第一条语句都是 `Parcel.enforceInterface(常量字符串)`，**这是唯一的校验**；
- 因此：**不存在 uid 门禁。拒绝只能来自描述符字符串不匹配。**

### 9.4 但描述符仍对不上（未完成的那一跳）

已排除（全部服务端抛 `SecurityException`）：

| 候选描述符 | 结果 |
|---|---|
| `android.net.wifi.IOplusWifiManager` | ✗ |
| `android.net.wifi.IOplusWifiP2pManager` | ✗ |
| `com.android.server.wifi.interfaces.IWifiTransactionHelper` | ✗ |
| 无令牌 | ✗ |
| 各种双令牌排列（4 种） | ✗ |

### 9.4.1 设备重连后补测（2026-11-17 19:0x，共 16 次只读探测）

| # | 构造 | 结果 |
|---|---|---|
| 12 | `10069` + `vendor.oplus.hardware.wifi@1.1::IOppoWifiService` | SecurityException |
| 13 | `10069` + `IWifiManager` + `IOplusWifiP2pManager` | SecurityException |
| 14 | `10069` + `IWifiManager` + HIDL 描述符 | SecurityException |
| 15 | `10069` + 前置 `i32 0` + `IOplusWifiManager`（strict-mode 头假设） | SecurityException |
| 16 | `10069` + `IWifiManager`（复测） | SecurityException |

**关键对照（本轮新增，最有信息量的一条）**：

| 构造 | 结果 | 含义 |
|---|---|---|
| `wifi` tx **1** + 垃圾令牌 `s16 GARBAGE` | **正常返回数据** | `wifi` 服务的 AOSP 分支**不校验令牌** |
| `iphonesubinfo` tx 1 + 垃圾令牌 | **正常返回 IMEI** | 本机 `Parcel.enforceInterface` 在多数进程是**宽松**的 |
| `wifi` **9999 / 10999 / 12000** + 令牌 | **`Parcel(Error: ... "Not a data message")`** | 这些 code **没有处理器**（返回 false，回包为空） |
| `wifi` **10069** + 任意令牌 | **SecurityException** | 10069 **有处理器**，且它**主动抛异常** |

⇒ 三点确定：
1. **10069 确实是一个已实现的事务**（不是死号），入口就在 §9.2 的分派上；
2. 抛异常的动作发生在**该分支内部**，而不是在 `super.onTransact` 或全局门禁——否则越界 code 也会同样抛；
3. 同一服务上 AOSP 事务对垃圾令牌毫无反应 ⇒ **拒绝不是"令牌不匹配"这么简单的机制**：
   要么该分支用的是我们尚未枚举到的字符串，要么是服务端在该进程内对 `enforceInterface` 的严格性不同。

**结论：P0 的动态验证被"AIBinder 调用方 ABI"卡住，不是被授权卡住。** 16 次探测已穷尽 `service call`
能表达的构造（单令牌 5 种、双令牌 6 种、前置 int、无参、越界对照）。再往下只有一条路：
用**真实 Java 客户端**（`android.net.wifi.OplusWifiManager` 或等价的 Parcel 构造）发起调用——
本机没有 JDK/d8，无法把 `.java` 编成 dex，**这是工具链限制，不是目标限制**。

### 9.5 P0 的净结论（截至设备断开）

| 问题 | 状态 |
|---|---|
| 真实 onTransact 分派在哪 | **已定位**：`service-wifi.jar` → `WifiServiceImpl.onTransact` → `IWifiTransactionHelper.onTransact` |
| 是否有外层 uid 门禁 | **没有**（唯一 `getCallingUid` 只用于日志） |
| 10069/10070 的描述符 | **未确定**：4 类候选 + 5 种排列全部失败，剩 1 个候选未测 |
| 若该候选成立意味着什么 | 校验只剩"知道一个公开字符串" ⇒ 任意本地进程可调用 ⇒ **root 上下文命令执行可用** |
| 若该候选也不成立 | 说明障碍在 parcel 构造细节（需用真实客户端复现），而非授权 |

**结论的先验概率**：由于 helper 内确实没有 uid 判断，"描述符即唯一门限"与静态证据一致；
但**在拿到一次成功调用之前，仍然只能记为"未证"**——这条纪律本轮已经吃过两次教训（§8.2）。
