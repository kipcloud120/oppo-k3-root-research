# `anti_root_dialog` 实现审计 —— G-A1 闭合（2026-11-18，纯离线）

> 物料：`_p2/OppoExSystemService.apk`（7,311,019 B，与设备同文件）的 `classes.dex`（4,068 个类）。
> 工具：`androguard` 解析 + 字符串 xref + 指令级输出。**未上机、未调用任何事务码。**
> 前情：§33.4 已证明该服务**对 shell 可达**，但当时判定"实现未审计"（G-A1）。

## 0 一句话

**实现已定位：`com.oplus.exsystemservice.a.b`（混淆名，源码名 `OplusAntiRootDialogService`）
注册 `"anti_root_dialog"`，其 Binder 体是内部类 `a.b$a`，只有一个 `int` 事务。
事务链上没有任何危险 sink（无 `Runtime`/`ProcessBuilder`/`reboot`/`startService`/写文件/写属性），
也不做调用者鉴权。⇒ 可达性翻转为真，但**不产生提权路径**；G-A1 按"无可用能力"结案。**

## 1 为什么上一版说"实现不在物料中"

§8.4 / §19.3 的判断依据是"dex 里没有实现类的 class_def"。本轮复核发现该依据不成立：

| 事实 | 数值 |
| --- | --- |
| dex 中**保留** `source_file`（源文件名）的类 | **0 / 4,068** |
| 类名混淆样例 | `Landroid/a/a;`、`Landroid/a/b;`、`Landroid/app/a;` |
| 字符串池里仍在的源码名 | `OplusAntiRootDialogService.java`、`IAntiRootDialog.java` |

⇒ 这是一个 **strip 掉 debug info 的 release dex**：`source_file` 整体缺失、类名部分混淆。
因此"按类名/source_file 搜不到"**不能推出"实现不存在"**——这是又一次"以名字匹配代替集合求值"。

## 2 定位方法与结果

**方法**：把 `"anti_root_dialog"` 当作字符串 xref 的锚点——注册 Binder 必然要把它传给
`ServiceManager.addService(String, IBinder)`。扫 28,546 个方法，命中 **1 处**：

```
HIT Lcom/oplus/exsystemservice/a/b;->b()V   |   const-string v2, "anti_root_dialog"
```

`b()V` 的完整指令（混淆后的 Java 等价体）：

```java
void b() {
    a("anti_root_dialog", new b$a(this));   // ① 注册 Binder
    this.i = new b$b(this);                 // ② BroadcastReceiver
    Log.d("OplusAntiRootDialogService", "onStart start anti_root_dialog");
}
```

类关系：

| 类 | 父类 | 角色 |
| --- | --- | --- |
| `com.oplus.exsystemservice.a.b` | `com.coloros.exsystemservice.ColorSystemService` | 服务主体（含 Dialog/PowerManager/TelephonyManager 辅助方法） |
| `com.oplus.exsystemservice.a.b$a` | `com.oplus.exsystemservice.a.a$a` | **Binder 实现**，唯一事务方法 `a(I)V` |
| `com.oplus.exsystemservice.a.b$b` | `android.content.BroadcastReceiver` | 监听 `USER_PRESENT` |
| `com.oplus.exsystemservice.a.b$1` | — | 合成的构造器访问桥 |

## 3 事务链逐层

### 3.1 Stub 层

```
Binder.onTransact(int, Parcel, Parcel, int)
  → Parcel.enforceInterface("com.oplus.exsystemservice.antirootdialog.IAntiRootDialog")
  → Parcel.readInt()            // 唯一入参
  → a(I)V                       // 实现
  → Parcel.writeNoException() / writeString(...)
```

- **没有** `Binder.getCallingUid()`、`checkCallingPermission`、`enforceCallingPermission`、
  `AppOpsManager` 任何调用 ⇒ **不鉴权**。
- 入参只有 1 个 `int`，没有字符串、没有 Parcelable、没有文件描述符、没有 Binder 句柄。

### 3.2 实现层 `a(I)V` 的行为

| 动作 | 出处 |
| --- | --- |
| `PowerManager.isInteractive()` | 判断屏幕是否亮 |
| `TelephonyManager.getCallState()` / `listen(PhoneStateListener, 32)` | 判断是否在通话中 |
| `Context.registerReceiver(b$b, IntentFilter("android.intent.action.USER_PRESENT"))` | 等解锁事件后补弹 |
| `Handler.obtainMessage` + `sendMessage` | 切回主线程弹窗 |
| `Window.setType(int)` ×2 | 设置弹窗窗口类型 |
| `OplusThemeStyle.getDialogThemeStyle(int)` | 取主题 |
| `SystemProperties.getBoolean("persist.sys.assert.enable"/".panic", z)` ×2 | 读开关（只读） |
| `ColorSystemService.a(int)` | 基类钩子（无代码体） |
| 字符串 `"displayDialog uid = "` | 日志里记录触发者 uid |

语义很明确：**"检测到 root 时，在合适的时机（亮屏、非通话）给用户弹一个提示框"**。

### 3.3 危险 sink 自检（对外部调用的全量枚举）

对这 4 个类（`b` / `b$a` / `b$b` / `a$a`）的全部指令做外部调用去重，共 32 条，**无**以下任何一类：

| 类别 | 命中 |
| --- | --- |
| 命令执行（`Runtime.exec` / `ProcessBuilder` / `exec*`） | 0 |
| 重启/关机（`PowerManager.reboot` / `shutdown`） | 0 |
| 拉起组件（`startService` / `startActivity` / `sendBroadcast`） | 0 |
| 文件写入（`FileOutputStream` / `File.*` 写） | 0 |
| 属性写入（`SystemProperties.set`） | 0（只有 `getBoolean` 读） |
| 设置写入（`Settings.*.put*`） | 0 |
| 包管理/权限变更（`PackageManager` / `grantRuntimePermission`） | 0 |

## 4 结论与残余

| 项 | 判定 |
| --- | --- |
| 策略可达性 | **可达**（§33.4，find + binder call，设备实测事务送达） |
| 调用者鉴权 | **无**（只有 `enforceInterface`，它只校验接口描述符，不校验身份） |
| 可用能力 | **无危险 sink**：单一 `int` 入参，效果限于"弹一个系统级提示框" |
| 提权价值 | **零** |
| 残余风险 | **未鉴权的 UI 弹窗触发**：任意能 `service call` 的域（含 shell）可用 `int` 触发提示框 ⇒ 骚扰 / 钓鱼诱导，属可用性问题，非提权 |
| 覆盖度 | **6/7 → 7/7**，但理由已从"策略不可达"改为"实现无能力"——后者是更强的闭合形式 |

**范围限定（不得外推）**：
1. 本轮只审到"注册点 → Stub → 事务实现 → 4 个类的回调链"，**未做全 App 数据流分析**；
   `com.oplus.exsystemservice` 的其他服务（如 `atlas_service`、`hans_service` 的宿主侧）不在本报告范围。
2. `SystemProperties.getBoolean("persist.sys.assert.*")` 只读，但"该属性为真时弹窗行为如何变化"
   未逐分支展开——与提权无关。
3. 结论基于**镜像内 APK**；设备实时版本与镜像同文件（§8.1 已核对 sha256），但若 OTA 更换则需重审。

## 5 方法论教训（与 §33 同一族）

| 现象 | 三次同源错误 |
| --- | --- |
| §24.13 | 只查"目标名字面等于 `anti_root_dialog_service`"的规则 ⇒ 漏掉属性目标的 `find` |
| §24.13 | 只查"目标名字面等于 `color_system_service_app`"的规则 ⇒ 漏掉 `appdomain→appdomain` 的 `call` |
| §8.4 / §19.3 | 只查"类名/source_file 等于 `*AntiRootDialog*`"⇒ 漏掉被 strip 的 debug info 之后仍存在的实现 |

⇒ **统一纪律：任何"不存在"的判定，必须先证明"该判定所依赖的索引是完备的"。**
名字索引在 CIL 里会漏属性，在 dex 里会漏 strip/混淆。可执行的替代方案：
策略侧用 `cil_policy.perms()`（集合求值），dex 侧用**字符串 xref**（锚点选注册用的字面量）。
