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
