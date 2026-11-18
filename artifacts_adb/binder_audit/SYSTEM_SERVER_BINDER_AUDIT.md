# `system_server` Binder 通道可达性审计

> 响应 `docs_archive/审核意见CHATGPT-v0041.txt` 第七节 **P0**：
> "一个 UID 0、SELinux domain 为 `oplus_wifi_service` 的进程，究竟能否利用它已经拥有的
> `system_server` Binder 通道，获得超出自身 SELinux 权限的系统管理能力？"
>
> **全程离线**：5 份 CIL + 各分区 contexts。**0 次上机、0 次 Binder 调用。**

---

## 0. 结论（一句话）

**这条通道在"查找"这一步就断了，不需要审计 `system_server` 的任何方法。**

本域对 **AIDL 服务注册表 `servicemanager` 的权限是 0 条规则**——既无 `binder call`、也无 `service_manager find`。
而 `(allow oplus_wifi_service system_server (binder (call transfer)))` 只对**已经持有的句柄**生效：
Binder 的事务模型是 `handle → transact`，句柄要么由 `servicemanager` 按名字查到，要么由别的进程递过来。

⇒ 评审提的三类接口（`checkCallingPermission` 限制的 / 依赖 uid 1000 的 / 以 uid 0 触发管理操作的）
**在当前权限下根本到不了**。剩下的唯一入口是"别人把 system_server 句柄递给我们"，候选只有 HAL 回调（G-S1，未审）。

---

## 1. 权限全量（本域，5 份 CIL 去重）

| 类 | 目标类型 | 权限 | 说明 |
|---|---|---|---|
| `binder` | `system_server_30_0` | **call, transfer** | 评审关注的这条 |
| `binder` | `platform_app_30_0` | call, transfer | 平台应用域 |
| `binder` | `engineermode_app_30_0` | transfer | 只能转交，不能 call |
| `binder` | `hwservicemanager_30_0` | call, transfer | HIDL 注册表 |
| `service_manager` | **（无任何规则）** | — | **关键否定** |
| `hwservice_manager` | `oplus_wifi_hal_service` | add, find | 唯一的 HIDL 名字查找权 |
| `hwservice_manager` | `hidl_base_hwservice_30_0` | add | 只能注册基类名 |

**属性继承核对**：本域所属属性只有 `domain` / `exec_type` / `file_type` / `vendor_file_type`；
`(allow domain <X> (service_manager (find)))` 形式的全局授予在全策略中**不存在**（grep 命中 0）。
⇒ §1 的"无 `service_manager` 规则"不是"我漏看了直接规则"，而是**直接与继承都没有**。

---

## 2. 为什么"有 call 权限"不等于"可用"

Binder 一次调用分三步，SELinux 只管其中两段，且**分属不同对象**：

| 步 | 动作 | 受什么约束 | 本域 |
|---|---|---|---|
| ① 取句柄 | 向 `servicemanager` 发 `FIND_SERVICE` | `(allow <域> servicemanager (binder (call)))` + `(allow <域> <服务类型> (service_manager (find)))` | **两者皆无** ⇒ 无法按名字取任何服务 |
| ② 发事务 | 对已有 handle 调 `transact` | `(allow <域> <目标域> (binder (call)))` | 有（`system_server`） |
| ③ 接收句柄 | 从别的进程收到 flat_binder_object | `(allow <域> <来源域> (binder (transfer)))` | 有 |

⇒ `system_server (binder call)` 只解锁 ②。**没有 ①，② 就无从施加。**
这不是"策略写得宽松但没人用"，而是**授权粒度上的错配**：give call 权限却不给 find 权限，
实际效果等于只能被"喂"句柄。

---

## 3. 句柄来源枚举（穷尽三条）

| # | 来源 | 判定 | 依据 |
|---|---|---|---|
| 1 | 按名字向 `servicemanager` 查 | **不可行** | 无 `servicemanager` binder 权限、无 `service_manager find` 规则 |
| 2 | 由别的进程递来（`transfer` 接收） | **可行但需具体来源**（= G-S1） | 本域被 system_server 调用（HIDL 反向），若 HAL 接口方法带回调参数，则 system_server 会把一个由它托管的 binder 对象递进来 |
| 3 | 自己 `add` 服务再被别人调 | 不产生 system_server 句柄 | `hwservice_manager add` 只对 `oplus_wifi_hal_service` / `hidl_base_hwservice` 生效（§25.9） |

**注意来源 2 的性质**：即便拿到回调句柄，可调用的也只是**那一个接口声明的方法**，
不是"整个 system_server"。评审关心的 `checkCallingPermission` / `uid==1000` / `uid==0` 三类判定，
要在**具体方法**上才有意义。这条路是否值得走，取决于 G-S1 的结果。

---

## 4. 若将来拿到句柄：服务层还有第二道门（评审观点的正确落点）

评审的分层是对的：SELinux 解决"能否通信"，服务层解决"这个调用者能不能做这件事"。本机三种典型形态：

| 服务层形态 | uid=0 的 `oplus_wifi_service` 会怎样 | 备注 |
|---|---|---|
| `enforceCallingPermission("android.permission.X")` | **失败**（我们没有被授予任何 Android 运行时权限） | 最常见 |
| `if (uid == Process.SYSTEM_UID) ...`（=1000） | **失败**（我们是 uid 0，不是 1000） | uid 0 ≠ uid 1000 是本项目的一个关键事实 |
| `if (uid == Process.ROOT_UID \|\| uid == SYSTEM_UID)` | **通过**（=0） | 这类写法才是"uid 0 有额外含义"的地方 |
| `Binder.clearCallingIdentity()` 后的内部调用 | 与我们无关（身份已被清） | — |

⇒ 真正值得查的是**第三类写法**。但它只在 G-S1 成立（我们确实拿到某个 system_server 句柄）之后才有意义；
在此之前投入是**对不可达接口做权限审计**，收益为零。

---

## 5. 缺口与可证伪条件

| # | 缺口 | 闭合方式 |
|---|---|---|
| **G-S1** | HAL 接口是否把 system_server 托管的回调对象递给本进程；若有，其方法集合与鉴权 | 需反汇编 `/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service` 与其 `.so`，枚举 `interface` 中带回调参数的方法（本地未存该二进制，需一次只读 `adb pull`） |
| G-S2 | `platform_app_30_0` 的 `call` 权限同样受"无 find"限制；未枚举哪些 platform_app 会主动连本域 | 同上，需枚举服务注册反向调用 |
| G-S3 | `engineermode_app` 只有 `transfer`，未确认是否存在"递句柄"路径 | 低优先 |

**可证伪条件**（进 §7 主清单）：

1. 发现本域可用的 `servicemanager` 通道（当前为 0 条规则）；
2. 发现 HAL 接口确实接收 system_server 回调，且该回调接口存在"第三类 uid 判定"的方法；
3. 发现任一进程会主动把 system_server 的**服务句柄**（而非回调对象）递进本域。

**不重开**：用 `service call` 盲试（历史 16 次已证明是工具 ABI 问题）；对不可达接口做方法级权限穷举。

---

## 6. 对 v0041 第三节 P0 的逐条回应

| 评审意见 | 处置 |
|---|---|
| "`oplus_wifi_service` 有向 system_server 发 Binder 调用的 SELinux 权限，但不等于审计完接口" | **接受这个区分**，并进一步指出：连"取句柄"这一步都没被授权，所以接口审计尚不具备前提 |
| "需区分只读查询 / `checkCallingPermission` / uid 1000 / uid 0 触发管理操作" | **采纳为 §4 的分类表**；同时指出 uid 0 ≠ uid 1000 是本机关键事实，只有"显式允许 ROOT_UID"的写法才会对我们放行 |
| "登记为独立于文件消费者的待审攻击面" | **已登记**为本报告 + G-S1/G-S2 |
| "v2.16 的消费者分析不等于完成 system_server 全部 Binder 方法审计" | **同意**，但结论方向相反：不需要现在做，因为入口未通 |

---

## 7. 复现

```bash
# 本域的 binder / service_manager 权限全量
grep -hoE "\(allow oplus_wifi_service [a-z_0-9]+ \((binder|service_manager|hwservice_manager) \([^)]*\)\)" .build/sepolicy/*.cil | sort -u
# 属性继承是否有全局 find 授予（应为 0）
grep -hoE "\(allow domain [a-z_0-9]+ \(service_manager \([^)]*\)\)" .build/sepolicy/*.cil | sort -u
# 是否存在 servicemanager 通道（应为空）
grep -h "oplus_wifi_service" .build/sepolicy/*.cil | grep -E "\bservicemanager(_30_0)?\b" | grep -v hwservicemanager
```

---

## 8. G-S1 闭合：HAL 是否把 system_server 的句柄递进本域（2026-11-18）

> **物料全部来自本地**，未上机：`/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service`
> （115,408 B，从 odm 解包得 `.build/vendor/x/odm/bin/hw/`）。
> 关键突破：该 ELF 带 `.gnu_debugdata`（xz 压缩的 mini debug info），解出 **315 个符号**，其中 **92 个 `STT_FUNC`**，
> 含 **`vendor::oplus::hardware::wifi::V1_1::implementation::OppoWifiService` 的全部 19 个方法名与签名**。
> 工具：pyelftools + `lzma`（无 objdump 依赖）。

### 8.1 三条判据（接口面 / 签名面 / 符号面）

| # | 判据 | 结果 |
|---|---|---|
| ① **接口面**：注册了哪个接口 | **只有 `vendor.oplus.hardware.wifi@1.1::IOppoWifiService`**：`registerAsService` 1 处、接口类符号 11 处全为该接口；二进制内**无** `android.hardware.wifi@` 描述符、无 `IWifi` 字样 ⇒ **不实现 AOSP `IWifi`**，因此不存在 `registerEventCallback(IWifiEventCallback)` 这类「客户端把句柄递进来」的方法 |
| ② **签名面**：方法有没有句柄类入参 | **没有**。19 个方法全是 `hidl_string` / 标量 / `std::string` / `const char*`；唯一的句柄类参数是 HIDL base 的 `debug(const hidl_handle&, ...)`，而 `hidl_handle` 是 **fd**、**不是 binder 对象** |
| ③ **符号面**：会不会接收 binder 对象 | 二进制**不导入** `readStrongBinder`（`.dynsym` 与字符串表均无）⇒ 即便有 hidl_handle 参数，也只取 fd，不取 binder |

⇒ **G-S1 对"取句柄"这一问：否。** 三条判据互相独立且都指向同一结论：
该服务只注册 OPPO 私有接口、方法签名里没有回调入参、也不调用 `readStrongBinder`。

### 8.2 但存在一条**反向数据通道**（这才是 §27 真正的残余）

3 个方法的签名带 HIDL 生成的 `_hidl_cb`：

```cpp
getIniVersion       (const hidl_string&, std::function<void(OplusWifiServiceStatus, hidl_string)>)
sendIniContent      (const hidl_string&, std::function<void(OplusWifiServiceStatus, hidl_string)>)
executeDriverCommand(const hidl_string&, std::function<void(OplusWifiServiceStatus, hidl_string)>)
```

HIDL stub 执行该 `std::function` 时，会**从 HAL 进程向调用方（system_server）发起一次 binder 事务**，载荷是
`(status, string)`。这两个值**由我们控制**（我们控制 HAL 的行为与返回串）。

⇒ **数据可以进 system_server，但拿不到可调用的句柄。** 这条通道在 §23 已经实际出现过：
logcat 里 `OplusWifiHalService: … with result = <我们的串>` 就是它。

**风险边界**：回调的**动作是固定的**（把结果交回 Java 侧的异步回调），不是"任意 system_server 方法"。
它能造成什么，取决于 Java 侧怎么处理这个字符串 —— 这是新的缺口 **G-S2**，不在本报告的 SELinux 口径内。

### 8.3 附带产出：19 个方法的全表（首次拿到名字与参数）

| 方法 | 参数 | 尺寸 | 性质 |
|---|---|---|---|
| `executeDriverCommand` | `hidl_string` + `_hidl_cb` | 1592 | **HIDL 导出**（§23 的注入点） |
| `getIniVersion` | `hidl_string` + `_hidl_cb` | 1112 | **HIDL 导出** |
| `sendIniContent` | `hidl_string` + `_hidl_cb` | 796 | **HIDL 导出** |
| `runWiFiScript` | `hidl_string`, `hidl_string` | 1160 | **HIDL 导出** |
| `sendSupplicantCommand` | `hidl_string` | 816 | **HIDL 导出** |
| `catchSnifferLog` | `uint32`, `uint32` | 1484 | **HIDL 导出** |
| `setConMode` | `uint32` | 204 | **HIDL 导出** |
| `changeConnectionMode` | `uint32` | 536 | **HIDL 导出** |
| `isWifiDriverLoaded` / `resetConnectionMode` / `setupFTMdaemon` / `compressedSnifferFile` / `cleanChildDaemonProcess` | `void` | 368/76/692/240/364 | **HIDL 导出**（无参） |
| `executeShellCommand` | **`const char*`** | 208 | **内部辅助**（非 HIDL：HIDL 用 `hidl_string`） |
| `loadDriver` | **`const char*, const char*`** | 192 | **内部辅助** |
| `executeDaemonCommand` | **`const char*`** | 472 | **内部辅助** |
| `filterModuleName` / `checkIfStringSafe` | `std::string` | 304/376 | **内部辅助** |
| `internalSignalHandler` | `int` | 264 | 信号处理 |

**判据**：HIDL 导出方法一律用 `hidl_string`/`hidl_vec`/标量；出现 `const char*` 或 `std::string` 的一定是 C++ 内部函数。
⇒ 真正**可被 binder 调用**的是前 13 个，`executeShellCommand` 等 5 个不在接口上（只能由其它方法内部调用）。

> 与 §22 的对齐：§22 记的是"vtable `@0x1a0a0`，slot2–10 = code1–9"（九类命令）。本节得到 **13 个 HIDL 方法**，
> 两者**不矛盾**（§22 只映射了 Java 侧可达的九类），但**方法与 code 的完整对应尚未建立** —— 登记为待办，不影响 §8.1 的判据。

### 8.4 G-S1 / G-S2 状态

| 缺口 | 状态 |
|---|---|
| **G-S1**（HAL 是否把 system_server 句柄递进本域） | **闭合、否证**：无 `readStrongBinder`、不实现标准 IWifi、方法无回调入参 |
| **G-S2**（Java 侧 `OplusWifiHalService` 如何处理回调里的字符串） | **新登记**。需要 system_server 的 Java 侧代码（`framework.jar` / `services.jar` 的 odex 反编译），本地未存 |
| G-S3（`engineermode_app` 的 transfer 路径） | 低优先，未动 |

**可证伪条件（补进 §7 第 11 条）**：
(a) 发现该服务在任何版本里出现 `readStrongBinder`；
(b) 发现它同时注册了 `android.hardware.wifi@x::IWifi`（那才有 `registerEventCallback` 入参）；
(c) 发现接口里存在 `sp<...Callback>` 型入参。
