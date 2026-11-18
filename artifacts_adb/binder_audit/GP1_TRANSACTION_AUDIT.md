# G-P1 事务级审计：`power_monitor` 与 `usage`（2026-11-18，纯离线）

> 承接 `PRIVATE_SERVICE_SURFACE.md` §4/§6 的初筛信号。方法沿用 §34.3：
> **服务名字面量 xref → 注册方法 → AIDL 描述符 xref → Stub → 事务实现 → 鉴权/sink**。
> 物料：`_p2/OppoExSystemService.apk` 的 `classes.dex`（4,068 类）。未上机。

## 0 一句话

**两个服务的 Stub 都只做 `enforceInterface`，不做任何调用者身份检查；但它们的事务入口要么不接收字符串、
要么接收的字符串在追踪到的路径上不流向任何危险 sink。⇒ G-P1 按"初筛信号为假阳性/调试路径"闭合，
仍未发现新的提权路径。**

## 1 定位链（可复现）

| 步 | `power_monitor` | `usage` |
| --- | --- | --- |
| 名字字面量命中 | `Lcom/coloros/exsystemservice/powermonitor/l;->b()V` | `Lcom/coloros/exsystemservice/h/e;->b()V` |
| 注册方式 | `a("power_monitor", <IBinder>)`（经 `ColorSystemService.a(String,IBinder)` 封装，故普通 `addService` 索引漏掉） | `a("usage", <IBinder>)`（同） |
| Binder 对象 | 字段 `l.fZ:Landroid/os/IBinder;`，由 `fZ(Z)` 合成访问器赋值 | 字段 `h.e.k:Landroid/os/IBinder;` |
| AIDL 描述符 xref | `Lcom/oplus/os/a$a;->onTransact` → `"com.oplus.os.IOplusPowerMonitor"` | `Landroid/os/a$a;->onTransact` → `"android.os.IOplusUsageService"` |
| Stub 父类 | `android.os.Binder` | `android.os.Binder` |
| 接口定义类 | `Lcom/oplus/os/a;`（方法签名） | `Landroid/os/a;` |
| 实现体 | `com.coloros.exsystemservice.powermonitor.l` | `com.coloros.exsystemservice.h.e` |

## 2 鉴权：两个 Stub 都不查调用者

对两个 `onTransact` 的全部指令扫：

| API | `power_monitor` | `usage` |
| --- | --- | --- |
| `Parcel.enforceInterface` | 有（每个事务码） | 有（每个事务码） |
| `Binder.getCallingUid` | **0** | **0** |
| `checkCallingPermission` / `enforceCallingPermission` / `AppOps` | **0** | **0** |

`enforceInterface` 只校验接口描述符字符串，**不校验调用者身份**。
⇒ 与 `anti_root_dialog` 一样：策略层可达，服务端也不挡 shell。
但与 antirootdialog 不同的是，这里的方法面更大，必须看 sink。

## 3 `power_monitor`：事务面与 sink

`onTransact` 分派的事务方法（节选）：

```
b(J J)List / a(J J)List          // 查询
b/a(OplusWakeLockInfo)V          // 接收 Parcelable
a(OplusAlarmInfo)V
a(Z)V
b() / c() / d()                  // 无参查询
a(I String)V                     // int + 字符串
a()V
```

追踪到实现体 `powermonitor.l` 里唯一带调用者 uid 的方法：

```
a(l$g, String)I:
    Binder.getCallingUid()
    SystemProperties.getBoolean(...)   // 读
    SystemProperties.getBoolean(...)   // 读
```

初筛命中的 sink 出处：

| sink | 所在方法 | 是否事务可达 |
| --- | --- | --- |
| `FileOutputStream`（`aC()V`） | 内部状态写入 | 在追踪的事务方法里**未见调用** |
| `SystemProperties.set`（`k()V`） | 内部状态同步 | 在追踪的事务方法里**未见调用** |
| `Ljava/lang/Runtime` | 实为 `Ljava/lang/RuntimeException`（异常包装） | **假阳性**（`svc_impl_triage.py` 已修） |

⇒ 初筛信号没有一条落到"调用者可控字符串 → sink"的路径上。

## 4 `usage`：事务面与 sink

`onTransact` 分派的方法（节选）：

```
d(String,String,Z)Z / c(String,String,Z)Z / b(String,String,Z)Z / a(String,String,Z)I
d(String)Z / b(String)Z / c(String)I
a(I,String,I,Z,I,[B)I                 // 最强的入口：int + String + byte[]
b(String,I,I)[B
f(I,I)List / r()I / s()String
b(String,String,String)Z
```

接口类 `Landroid/os/a;` 与实现体 `h.e` 的这些字符串入口中：

| API | 命中 |
| --- | --- |
| `getCallingUid` / `checkCalling*` | 0 |
| `SystemProperties.set` | **仅 1 处**，在 `a(FileDescriptor, PrintWriter, String[])` —— 这是 `dump()`，不是事务方法 |
| `Runtime.exec` / `ProcessBuilder` / `startService` / `sendBroadcast` / `FileOutputStream` | 0 |

⇒ 初筛的 `SystemProperties.set` 是**调试转储路径**，不是 Binder 事务入口。

## 5 结论

| 项 | `power_monitor` | `usage` |
| --- | --- | --- |
| 策略可达 | 是 | 是 |
| Stub 鉴权 | 无（只 `enforceInterface`） | 无（只 `enforceInterface`） |
| 调用者可控字符串 | 有（如 `a(I,String)V`） | 有（多个 `(String,…)` 与 `(I,String,I,Z,I,[B)I`） |
| 可控串 → 危险 sink | **未发现** | **未发现** |
| 初筛信号归因 | `RuntimeException` 假阳性；`FileOutputStream`/`set` 在内部状态方法 | `SystemProperties.set` 在 `dump()` |
| 判定 | **闭合，无提权路径** | **闭合，无提权路径** |

**G-P1 从 `CLOSURE.md` §3 的缺口清单中移除。**

## 6 范围限定（不得外推）

1. 本轮只追踪了 **Stub 分派 → 接口方法 → 实现体直接调用**这一层；未对实现体做跨方法/跨类的数据流分析。
   `powermonitor.l` 有约 200 个方法，其中内部状态写入的完整调用图未穷尽。
2. `onTransact` 的事务码到方法名的映射来自反汇编的调用序列；若存在未走 `enforceInterface` 的隐藏分支，
   本报告不覆盖（两个 Stub 的每条分支都出现了 `enforceInterface`，未见例外）。
3. 设备 OTA 后需重做——方法名是混淆的，版本一变全部失效。

## 7 方法论沉淀（与 §33/§34 同族）

**名字 xref 是找实现体的正确入口，但要连做两次**：
第一次用**服务名字面量**找注册点，第二次用**AIDL 接口描述符**找 Stub。
只做第一次会停在"注册类"上（它的父类 `ColorSystemService.a(String,IBinder)` 封装了 `addService`，
普通 `addService` 索引会漏；而它的 sink 统计会把整个大类算进来，产生噪声）。

这一步也解释了 §35 初筛为何把 `SystemServer(self)` 那类行标成噪声：
**注册点、Stub、实现体三者常常不是同一个类**，把它们混在一起统计 sink 必然失真。
