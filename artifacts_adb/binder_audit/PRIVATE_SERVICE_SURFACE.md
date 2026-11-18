# 私有 Binder 服务面：注册点索引 + 鉴权/sink 初筛（2026-11-18，纯离线）

> 触发：§34.6 遗留项——"其余 27 个 OPPO 私有 `*_service`，shell 现在能 `find` 它们，事务级 sink 未枚举"。
> 工具：`tools/svc_registrar_index.py`、`tools/svc_impl_triage.py`（新增）。
> 全程离线分析；设备侧只做了一次只读 `getprop`/`ps` 复核（见 §7）。

## 0 一句话

**旧稿"七个私有服务"的范围低估了：本机 235 个服务里 shell 能 `find` 228 个，36 个 OPPO 私有服务全部可达。
而且 `find` 之后那道 `binder:call` 对 shell 也是通的（经 `appdomain → binderservicedomain`）——
唯一剩下的门是每个方法自己的鉴权。本轮建立了"服务名 → 注册点"索引并对实现类做了初筛，
没有确认新的提权路径；有 2 行需要按 §34.3 的方式逐个做事务级审计。**

## 1 补上的关键物料：`system_ext_service_contexts`

上一轮 37 个私有服务里只有 1 个能映射到 SELinux 类型，原因不是"没有标签"，而是**我们没拉那份文件**：
`/system_ext/etc/selinux/system_ext_service_contexts`（394 行）此前不在 `.build/sepolicy/`。

> 拉取时踩了一个可复现的坑：Git Bash 把 `adb exec-out cat /system_ext/...` 里的路径转成了
> Windows 路径，实际执行的是本机 `cat`。解法：`MSYS_NO_PATHCONV=1 adb exec-out cat ...`。

补齐后映射率 **235/235**，而不再依赖"名字像不像 `<name>_service`"的猜测。

## 2 可达性重算：228/235，私有服务 36/36

用 `cil_policy.perms('shell', t, 'service_manager')` 逐类型算（不是按名字匹配）：

| 指标 | 值 |
| --- | --- |
| 设备 `service list` 总数 | 235 |
| 能映射到类型的 | **235**（补 contexts 前仅 1/37 私有服务） |
| shell 能 `find` 的 | **228 / 235** |
| 36 个 OPPO 私有服务中能 `find` 的 | **36 / 36** |

第二道门同样是通的：

```
shell ∈ appdomain
(allow appdomain binderservicedomain (binder (call transfer)))
system_server ∈ binderservicedomain
⇒ shell → system_server  binder:call = [call, transfer]
```

这与设备实测一致（`service call alarm 65535` 返回对端 parcel 错误，事务送达）。

⇒ **"find 不到 / call 不到"已经不是服务面的有效屏障**；剩下的是每个 `onTransact` 分支自己的
`checkCallingPermission` / uid 检查。这正是本轮要初筛的对象。

## 3 注册点索引

方法：扫全部可用 dex/jar（约 31 MB）＋ `OppoExSystemService.apk`，对每个方法收集字符串字面量与
`addService` 调用。严格模式（同方法内同时出现）命中 25 次；放宽为纯字符串 xref（覆盖走了
`ColorSystemService.a(String, IBinder)` 这类封装 helper 的注册）命中 **79 次**。

| dex / jar | 类数 | 命中 |
| --- | --- | --- |
| `services.dex` / `services.jar` | 6144 / 6144+3579 | 5+7 |
| `oplus-services.dex` | 1494 | 14 |
| `oppo-wifi-service.dex` | 1905 | 3 |
| `oplus-telephony-common.dex` | 504 | 3 |
| `coloros-internal-services.dex` | 114 | 4 |
| `OppoExSystemService.apk` | 4068 | 13 |

解析出的注册类（节选）：

| 服务 | 注册类 |
| --- | --- |
| `anti_root_dialog` | `com.oplus.exsystemservice.a.b`（§34.3 已审完） |
| `OPPO` | `com.coloros.exsystemservice.additional.i` |
| `OPPOExService` | `com.coloros.exsystemservice.exservice.OppoExService` |
| `color_screenshot` | `com.coloros.exsystemservice.f.b` |
| `engineer` | `com.coloros.exsystemservice.engineer.b` |
| `hephaestus_app_data_service` | `com.coloros.exsystemservice.e.a` |
| `hephaestus`（native） | 上一轮已审（§33.6） |
| `multimediaDaemon` | `com.coloros.exsystemservice.c.b` |
| `networking_control` | `com.oplus.exsystemservice.c.a` |
| `oppo_app_data_service` | `com.coloros.exsystemservice.appdata.b` |
| `power_monitor` | `com.coloros.exsystemservice.powermonitor.l` |
| `usage` | `com.coloros.exsystemservice.h.e` |
| 12 个 | `com.android.server.SystemServer` / `ColorSystemServerEx`（system_server 宿主） |

## 4 鉴权/sink 初筛（44 行）——**这是筛查，不是审计**

对每个注册类及注册方法里 `new-instance` 的实现候选，统计两类 API：

- **鉴权**：`checkCallingPermission` / `enforceCallingPermission` / `getCallingUid` / `AppOpsManager` …
- **危险 sink**：`Runtime.exec` / `ProcessBuilder` / `reboot` / `startService` / `sendBroadcast` /
  `SystemProperties.set` / `Settings.*.put*` / `FileOutputStream` / `deleteFile`

exsystemservice 宿主的服务（去重后节选）：

| 服务 | 实现类 | 鉴权命中 | sink | 判读 |
| --- | --- | --- | --- | --- |
| `OPPOExService` | `exservice.OppoExService` | 4 | 0 | 未见 sink |
| `color_screenshot` | `f.b` | 4 | `startService@a` | 有鉴权，需看触发条件 |
| `engineer` | `engineer.b` | 3 | `Settings$@a/b/c` 等 6 项 | 有鉴权，需看写的是哪些 key |
| `oppo_app_data_service` | `appdata.b` | **6** | `deleteFile@e` | 与 §19.3 的签名校验结论一致 |
| `power_monitor` | `powermonitor.l` | 1 | `FileOutputStream@aC`、`SystemProperties.set` | **需人工看** |
| `usage` | `h.e` | 0 | `SystemProperties.set@a` | **需人工看** |
| `anti_root_dialog` | `oplus.exsystemservice.a.b` | 0 | 0 | §34.3 已完整审完：无 sink |

**两个必须记录的口径问题**：

1. **假阳性已修**：初版把 `Ljava/lang/Runtime` 当模式，结果 `Ljava/lang/RuntimeException` 也命中，
   误报 `power_monitor` 有命令执行。已改为只认 `Ljava/lang/Runtime;->exec`（`svc_impl_triage.py` 第 31 行）。
2. **system_server 的 `(self)` 行全是噪声**：`SystemServer` / `ColorSystemServerEx` 是数万行大类，
   服务名只是 `startOtherServices()` 里的字面量，不能把整个类的 sink 算到某个服务头上。
   表中这些行**只作为"注册点定位"用，不参与风险判读**。

### 人工核查两处

| 服务 | 核查结果 |
| --- | --- |
| `power_monitor` | `Runtime` 是 `RuntimeException`（假阳性，已修）；真实调用是 `SystemProperties.get/getBoolean`（读）、`FileOutputStream` 写自身统计文件（`aC()`）、`SystemProperties.set`（`k()`）；并且在 `a(l$g,String)I` 里**有 `Binder.getCallingUid()`**。未发现可控参数直通 sink，但**未做全类数据流审计** |
| `usage` | `SystemProperties.set` 出现在 `a(FileDescriptor, PrintWriter, String[])`，即 `dump()` 路径，不是事务入口；事务方法 `a(I)V` 里未见危险 API |

## 5 结论

- **没有确认新的提权路径。** 初筛的 44 行里有 2 行需要按 §34.3 的方式做事务级审计
  （`power_monitor`、`usage`），但它们当前**只有"值得看"的证据，没有"可用"的证据**。
- **服务面的性质被改写了**：从"7 个私有服务、find 是门槛"变成"228 个服务 find/call 都通，
  门槛在每个方法"。这不是风险升级，而是**责任位置转移**——以后再谈"某服务不可达"必须给出
  方法级鉴权证据，不能拿 servicemanager 层做挡箭牌。
- **36/36 私有服务可达**这一事实本身不构成漏洞：AOSP 设计上 shell 就能 find/call 大部分服务，
  安全性由服务端权限检查承担。

## 6 缺口

| 缺口 | 性质 | 重开条件 |
| --- | --- | --- |
| `power_monitor` / `usage` 的事务级审计 | 初筛有信号，未做逐方法数据流 | 找到任一事务方法把调用者参数送到 `FileOutputStream` / `SystemProperties.set` / `startService` 的路径 |
| 其余 34 个服务的 `onTransact` 全量枚举 | 本轮只做初筛 | 对任一服务给出"无鉴权 + 危险 sink"的具体方法体 |
| native 注册的服务（hans/horae/oiface/multimediaDaemon） | Java dex 里只有字符串痕迹，实现在 native | 取对应 native 二进制并做 `onTransact` 审计（§19 已审过其中部分） |

## 7 G-W1 触发前提复核（只读，一次）

复核 §34.2 用来支撑"跳板断在触发"的事实：

```
init.svc.hostapd       = (空)
init.svc.fstman        = (空)
init.svc.wpa_supplicant= running
ps -A -o args | grep supplicant:
  wpa_supplicant -O/data/vendor/wifi/wpa/sockets -puse_p2p_group_interface=1 -g@android:vendor_wpa_wlan0
```

⇒ supplicant **在跑**，但命令行里**没有 `-c <config>`**（用 `-g` 全局控制口），
hostapd/fstman 未定义。§26/§34 的"触发门失败"结论**再次被实测确认**。
因此 G-W1（消费者配置解析器内存安全）继续按"前置条件不成立"处理，不启动审计。
