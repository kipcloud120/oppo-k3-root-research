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
