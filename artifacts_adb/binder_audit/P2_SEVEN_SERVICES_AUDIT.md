# P2 审计：七个未覆盖私有服务（2026-11-18，纯离线）

> 响应 `HANDOVER.md` §17.3 P2。全程未连设备、无写操作。
> 物料：`system.img` 解出的 4 个 native 二进制 + rc + libresourcemanagerservice.so（落
> `artifacts_adb/binder_audit/rootbin/_p2/`），以及已入库的 `OppoExSystemService.apk`、
> `vendor.oplus.hardware.orms-V1.0-java.jar`。
> 工具：`elf_analyze.py`、capstone 5.0.7（自写 PLT 解析）、androguard 4.1.4（`deep_method.py`）。

---

## 1. 一句话结论

**七个服务按 §14 atlas 同格式审计后，无一产生对"shell 临时 ROOT"可达的新提权路径。
唯一的 `system(可控串)`（hephaestus）被 `getCallingUid()==1000` 门禁挡住 shell(uid 2000)；
其余服务要么无命令执行原语、要么以 system 身份运行且带签名校验。整体 no-go 维持。**

---

## 2. 总表（宿主 / 身份 / 原语 / 门禁 / 判定）

| 服务 | 宿主 | 运行身份 | 命令执行原语 | 门禁 | 对 shell ROOT |
|---|---|---|---|---|---|
| **hephaestus** (`IHephaestus`) | `system_ext/bin/hephaestus` | system；`hephaestus_install` 变体为 **root**(oneshot, installd seclabel) | **`system(argv_str)` @0x24f0** | **`getCallingUid()==1000`** | **否证**：shell=2000 不满足门禁 |
| hans (`IHansComunication`) | `system_ext/bin/hans` | system | 无（无 system/execv/popen 导入） | disabled+property 触发 | 无路径 |
| horae (`IHoraeService`) | `system_ext/bin/horae` | system, `group root` | 无 | disabled+property 触发 | 无路径 |
| oiface (`IOIfaceService`) | `system_ext/bin/oiface` | system, `group root`, `CAP_SYS_NICE` | 仅 `property_set`（5 处，固定 `persist/debug.oiface.*`） | disabled+property 触发 | 无命令注入 |
| orms (`OplusResourceManagerService`) | `system/lib/libresourcemanagerservice.so`(32bit) + `vendor.oplus.hardware.orms` HIDL | 系统 | 无（仅 fopen） | HIDL 框架 | 无路径 |
| appdata (`IOppoAppDataService`) | `OppoExSystemService.apk` | system_app | 无 exec；有 `deleteFileOrFolder` + 设 property | **签名校验** `getPackagesForUid`+`checkPackageSignature` | 否证：签名门禁 |
| antirootdialog (`IAntiRootDialog`) | 未解出（见 §5） | 未知 | 未知 | 未知 | **缺口**：实现未解出 |

---

## 3. 重点：hephaestus 的 `system()` 与 uid 门禁（唯一有 shell 执行原语的服务）

### 3.1 rc 里的两个 service（`self_init_hephaestus.rc`）

```
service hephaestus /system_ext/bin/hephaestus       # user system, seclabel hephaestus
service hephaestus_install /system_ext/bin/hephaestus installd
                                                    # user root, seclabel u:r:installd:s0, oneshot
```

### 3.2 `system()` 调用点与参数来源（全量反汇编 + PLT 解析）

二进制 stripped，AArch64，.text 仅 `0x2000–0x2904`（0x908 B）。PLT 解析（rela.plt GOT 序）确认
`system@plt = 0x2ab0`，全程序**仅一处调用**：

```
0x2438  <fn>(this=x8, str=x1, x2, ...):
0x2468    bl IPCThreadState::self()
0x246c    bl getCallingUid()              ; w22 = 调用者 uid
0x248c    bl __android_log_print("HEPHAESTUS", "calling uid is: %d", w22)
0x2490-0x24ac  w8 = uid - ((uid>>5)*0x0a7c5ac5 >> 39)*100000   ; 等价 uid % 100000
0x24b0    cmp w8, #0x3e8 (1000)
0x24b4    b.ne 0x24fc                     ; 不等 → log "not apply to this uid: %d"
0x24b8    String8 s(x21)                  ; x21 = 入参字符串
0x24e8    log("HEPHAESTUS", "%s to run", x21)
0x24ec    mov x0, x21
0x24f0    bl system                       ; system(入参字符串)
0x24f4    str w0, [x20]                   ; 返回值写出
```

### 3.3 门禁解码（确定性）

魔法数解码：`uid % 100000 == 1000`。对 Android 实际 uid 范围（0–65534）即为 **`uid == 1000`**（AID_SYSTEM）。

| 调用者 | uid | `%100000` | 是否执行 system() |
|---|---|---|---|
| root | 0 | 0 | 否 |
| **system** | 1000 | 1000 | **是** |
| **shell** | 2000 | 2000 | **否**（log "not apply to this uid"） |
| app | 10xxx | 10xxx | 否 |

⇒ **从 shell(uid 2000) 调用被硬性挡住。** 该 `system()` 面只对 uid 1000 的调用方开放；
uid 1000 本身已是 system 特权域，不构成"从 shell 提权"。

### 3.4 与 §14 atlas 的结构对比

atlas：`setEvent` Java 无鉴权 → root 服务 → native `system()`，但命令模板硬编码 ⇒ 否证。
hephaestus：`system(客户端串)` 参数虽可控，但** native 层有 uid==1000 硬门禁** ⇒ 对 shell 否证。
两者都"看到 system()"，但都因各自的约束（模板硬编码 / uid 门禁）不成立。**再次印证"看到 system() ≠ 可执行注入"。**

---

## 4. 其余六个服务（快速判定依据）

- **hans**：rc `user system`，`disabled`，由 `sys.hans.enable` property 触发；无 system/execv/popen 导入。
  功能是 cgroup freezer（`/dev/freezer`）CPU 带宽限制。无命令执行面。
- **horae**：rc `user system`，`group system readproc root`，`disabled`；无 system 导入，仅 `__open_2`/fopen
  读配置（`system_ext/etc/horae/*.conf`）。无命令执行面。
- **oiface**：rc `user system`，`group root`，`CAP_SYS_NICE`；无 system，5 处 `property_set` 全部写
  固定属性名（`persist.sys.oiface.*`、`debug.oiface.trace.switch` 等）。无命令注入。
- **orms**：`vendor.oplus.hardware.orms-V1.0-java.jar` 仅 HIDL 接口 dex；实现在 32 位
  `libresourcemanagerservice.so`（仅 fopen 导入，无命令执行）。资源管理服务，无注入面。
- **appdata**：Stub `onTransact` 只有 `enforceInterface`（符合 §14 方法论），但实现类 `b` 的门禁方法
  `e()` 用 `getPackagesForUid(uid)` + `c.a(context, pkg)` 做**签名校验**；操作为 `deleteFileOrFolder`
  与 `android.hardware.IAppDataManager` transact，改 `oppo.appdataservice.status` property。签名门禁挡住 shell。

---

## 5. 缺口：antirootdialog 实现未解出

`com.oplus.exsystemservice.antirootdialog.IAntiRootDialog` 在 `full_audit_report.txt` 标 `[MISSING]`。
已检索全部已解出 jar/apk（`OppoExSystemService.apk` 仅含 coloros 包的 appdata）、system.img 的
`OppoExSystemService.apk`，均未找到该接口/实现类。推断其 dex 被 AOT 优化进未解出的 odex/vdex，或
宿主为另一个未拉取的 apk。**记为审计缺口，不臆测其行为**；若需闭合，需从 system.img 解出对应
odex/vdex 并用 `vdexExtractor` 之类工具还原 dex（当前物料未含该工具）。

---

## 6. 对 §17.2 三层次的影响与结论

| 层次 | P2 后的状态 |
|---|---|
| L1 字符串被 root 服务接收 | hephaestus 的 root 变体存在，但门禁 uid==1000；shell 不满足 |
| L2 命令被执行 | 仅 hephaestus 有 system(串)，对 shell 因门禁不成立 |
| L3 提权成立 | **七个服务无一提供 shell 可达的 uid 0 命令执行** |

**判定：P2 不改变整体 no-go。** 覆盖度：7 个服务实现中 6 个已审计并定性（hephaestus 为唯一有 system 面者且已否证），
1 个（antirootdialog）记为解包缺口。§17.3 冻结面（KGSL / 两个 binder CVE / FastRPC / GhostLock）无新原语，不动。

**不建议上机**：hephaestus 的 uid 门禁是 native 硬编码，无 §14 所述"模板硬编码但可绕"的余地；
盲试 property 触发只会产生噪声。保持纯静态归档。

---

## 7. 新 P1 尝试：antirootdialog 解包（2026-11-18，纯离线）

> 响应 HANDOVER §20 新 P1。**结论：仍无法闭合，但新增两条确定线索。**

### 7.1 定位过程（全部试过）

| 尝试 | 结果 |
|---|---|
| `OppoExSystemService.apk` 的 classes.dex | 只有 coloros.appdata 的 9 类，**无 antirootdialog** |
| 同 apk 的 oat/arm64 odex + vdex（vdex021） | 提取内嵌 dex 段（`Ljava/lang/ref/Reference;` 等 string_data），**全文无 antirootdialog 字符串** |
| system.img 全文搜 `antirootdialog` | 仅 2 处游离偏移（`0x10e315aad`/`0x1219d5f0e`），ext4 反查**不在任何文件内**（空闲/裁剪残留） |
| vendor.img / odm.img 搜字符串 | 仅 `anti_root_dialog_service`（SELinux type 名，见下），无实现代码 |
| 7z 列文件名 | 无 antiroot/kevent 命名的文件 |

### 7.2 新增确定线索

system.img 游离字符串上下文（`0x10e315aad`）明确显示该服务是**native 守护进程**且走内核通道：

```
/data/oplus/kevent
/data/oplus/kevent/tmp_info.txt
com.oplus.exsystemservice.antirootdialog.IAntiRootDialog
$$pkgName@@%s
Send pid error
,payload@@%s
send_pid_to_kernel err ,ret is %d
Failed to open '%s' (%s)
Field "uid" greater than UID...
```

- vendor.img SELinux 策略（`0xb66394e`）：`anti_root_dialog_service` 是一个独立 SELinux domain/type。
- 第二处偏移（`0x1219d5f0e`）是某 binder 服务接口描述符表，同时含 `IOplusMirageDisplayObserver` /
  `IOplusNecService` / `IOplusPowerMonitor` 等多个 Oplus 服务——说明它注册在某个多服务宿主中。

⇒ antirootdialog 不是纯 Java 服务，而是 **native 服务 + SELinux domain + /data/oplus/kevent 内核接口**。
`send_pid_to_kernel` 提示它把 pid/uid 下发给内核做 anti-root 判定。

### 7.3 判定与缺口

**仍未闭合**：实现二进制/ dex 不在当前镜像物料（system.img 为 OTA 重建、可能裁剪）中。
要继续需：完整 factory system.img（非 OTA 重建），或含该 native 服务的独立分区镜像，或设备上 `/data/oplus/kevent` 相关可执行文件的只读拉取（需授权）。

**不臆测其鉴权/敏感操作**。 §2 总表中 antirootdialog 一行维持"未完成"。
**整体 no-go 不受影响**：本项只是补齐覆盖度，未提供任何新提权路径。

---

## 8. antirootdialog 闭合（2026-11-18 12:3x，设备在环 + 五份策略）

> 触发：核实 §7.2 第三条"`anti_root_dialog_service` 是独立 SELinux 域"时，发现它在
> `vendor_sepolicy.cil` 与 `plat_sepolicy.cil` 中**均为 0 次命中**。顺线索补拉
> `system_ext_sepolicy.cil` / `product_sepolicy.cil`（见 `SELINUX_DOMAIN_AUDIT.md` §13），
> 结论随之改写。**全程只读。**

### 8.1 三处更正

| # | 旧记录（§7.2） | 实际 |
|---|---|---|
| 1 | `anti_root_dialog_service` 是**独立 SELinux domain** | **是 service_manager 类型**（`(type anti_root_dialog_service)` + 属 `system_api_service` 属性），**不是域** |
| 2 | 宿主"未解出，可能在另一 apk" | 宿主是 `/system/system_ext/priv-app/OppoExSystemService/`，包名 `com.coloros.exsystemservice`，`android:persistent="true"` |
| 3 | 实现"不在当前镜像物料中" | 该 APK 的设备实时版本与镜像版本**同一文件**（7,311,019 B，sha256 `7cea0ba8…`）；dex 中有接口描述符 `…antirootdialog.IAntiRootDialog` 与源文件名 `OplusAntiRootDialogService.java`，但**没有实现类的 class_def** |

### 8.2 服务注册与调用方（策略原文）

```
# system_ext_sepolicy.cil
(type anti_root_dialog_service)
(allow color_system_service_app anti_root_dialog_service (service_manager (add find)))
(allow oplus_kevents           anti_root_dialog_service (service_manager (find)))

# 全策略中能 binder call 到 color_system_service_app 的域
oplus_kevents  (binder (call))
```

设备侧对应：

```
$ service list | grep -i antiroot
17  anti_root_dialog: [com.oplus.exsystemservice.antirootdialog.IAntiRootDialog]
```

⇒ 架构为：`com.coloros.exsystemservice`（域 `color_system_service_app`，persistent 系统应用）
注册 `anti_root_dialog`，**唯一调用方是 `oplus_kevents`**（kevent 守护进程，即 §7.2 那些
`/data/oplus/kevent`、`send_pid_to_kernel` 字符串的宿主）。

### 8.3 可达性判定（shell 方向，这是 P1 唯一关心的问题）—— **本小节已于 v2.24 被推翻，见 §9**

| 检查 | 结果（**旧工具口径，已作废**） |
|---|---|
| `shell` 对 `color_system_service_app` 的 `binder` 类权限 | ~~0 条~~ |
| `shell` 对 `anti_root_dialog_service` 的 `service_manager:find` | ~~0 条~~ |
| `oplus_kevents` 之外能 call 该域的域 | ~~无~~ |

⇒ ~~**`IAntiRootDialog` 对 shell 不可达**~~。判定方式与 §7.2 的猜测不同：不是"实现拿不到，所以不知道"，
而是"**策略直接不给 shell 任何一条通往该服务的路径**"。

### 8.4 结论 —— **已撤回，见 §9**

~~**P1 闭合为否证（不可达），覆盖度 7/7。**~~

**遗留说明（诚实登记）**：实现类名未解出——dex 里只有接口名与源文件名，没有对应 class_def。
最可能是被混淆成无意义短名（`IAntiRootDialog` 的实现类），次可能是运行期动态加载。
本轮未继续定位，因为~~它不影响可达性结论~~ —— 该理由在 v2.24 已失效（可达性结论被推翻）。

---

## 9. 撤回 §8（2026-11-18 18:xx，响应审核意见 v006 · P1）

### 9.1 为什么撤

§8.3 的三行"0 条 / 无"来自两处方法错误，都不在数据，而在**判定方式**：

1. **按名字精确匹配，未按属性展开**。策略里通往该服务的两条实际路径都不是以它的名字出现的：

   ```
   (allow shell base_typeattr_511 (service_manager (find)))
   base_typeattr_511 = (and (service_manager_type) (not (apex_service default_android_service
                           dnsresolver_service gatekeeper_service …)))
   ⇒ anti_root_dialog_service ∈ service_manager_type ⇒ shell 有 find

   (allow appdomain appdomain (binder (call transfer)))
   ⇒ shell 与宿主域 color_system_service_app 同属 appdomain ⇒ shell 有 binder call
   ```

   §8.2 里"能 binder call 到 color_system_service_app 的域只有 oplus_kevents"这句，
   查的是**目标名字面等于**该类型的那条规则，漏掉了以属性为目标的规则。

2. **`service_manager:find` 与 `binder:call` 被混为一谈**。即使 find 为 0，也不能据此断言
   "没有任何 Binder 调用路径"；反之，find 为 1 也不等于服务端会放行任何方法。

### 9.2 设备实证（判据先登记）

见 `p1_probes/PROBE_ANTIROOT_CRITERIA.md` 与 `p1_probes/ANTIROOT_PROBE_20261118.txt`：

```
$ service call anti_root_dialog 65535
Result: Parcel(Error: 0xffffffffffffffb6 "Not a data message")
```

越界事务码不触发业务方法，只走 `find` + `call` 两道 LSM 检查。返回的是**对端 parcel 错误**
（事务已送达并收到回包），`logcat` 无 `scontext=u:r:shell:s0` 的 `avc: denied`。
正对照 `service call alarm 65535` 返回同形态错误。

宿主身份实测：`u:r:color_system_service_app:s0 system 2833 com.coloros.exsystemservice`（uid 1000）。

### 9.3 现在的判定

| 层次 | 判定 |
|---|---|
| 策略可达性 | **可达**（find + binder call 均放行） |
| 实现审计 | **未做**（物料里无实现类 class_def，见 §7 / §8.4 遗留说明） |
| 覆盖度 | 先记 **6/7**（本项重开为 G-A1）；**§34.3 已闭合**：实现为混淆类 `com.oplus.exsystemservice.a.b$a`，单 `int` 事务、无鉴权、无危险 sink ⇒ **7/7，理由改为"可达但无能力"** |

**不宣称"存在提权路径"**：可达只说明"策略不挡"，服务端是否对 uid 2000 做鉴权、
是否有危险方法，都还没有证据。要闭合 G-A1，需要拿到完整的 odex/vdex，或对真实事务码做
受控调用——后者属于需要单独授权的动作，本轮未做。
