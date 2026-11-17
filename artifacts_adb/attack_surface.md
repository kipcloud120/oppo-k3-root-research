# shell 域攻击面普查（OPPO K3 / PCGM00_11_F.16）

- 时间：2026-11-17
- 身份：`uid=2000(shell)` / `context=u:r:shell:s0` / SELinux `Enforcing`
- 方法：**只测 `open()`，不 `write()` 任何字节**。`open(path, O_WRONLY)` 会走 DAC + SELinux 写检查，
  成功即代表可写，但不产生任何状态变化。
- 副作用：**零**（未重启、未改动、未向任何驱动发请求）
- 工具：`tools/surface_probe.c`（原始输出 `artifacts_adb/surface_probe_output.txt`）

---

## 1. 设备节点（`/dev`）

跳过 open 本身即有副作用的节点（`watchdog`/`console`/`tty*`/`mem`/`kmem`/`kmsg`/`fb0` 等）后，
共扫描 **198** 个字符/块设备，结果：

| 结果 | 数量 | 明细 |
|---|---|---|
| 可 `O_RDONLY` 打开 | 12 | `uhid` `ion` `zero` `adsprpc-smd` `uinput` `hwbinder` `binder` `ashmem<uuid>` `kgsl-3d0` `null` `urandom` `random` |
| 白名单内**可写**（`O_WRONLY`/`O_RDWR` 成功） | **4** | `binder`（0666）、`hwbinder`（0666）、`ashmem<uuid>`（0666）、`kgsl-3d0`（0666） |

要点：

- **`ion` 只有读权限**（`0664`，shell 属 other）⇒ 本项目早期设想的 ion 喷堆路线，从权限位就不可行。
- **`ashmem27520eec-…` 三种模式全部可开** ⇒ 修正 §1 的旧记录（"`/dev/ashmem` world rw 但 SELinux 拒绝 open"）：
  实际存在的是**按实例命名的 ashmem 节点**，且 shell 可读写。
- `uhid` / `uinput` 只能读，不能写 ⇒ HID 注入类路线关闭。
- `adsprpc-smd` 可读打开但 ioctl 全 `EPERM`（§21.29.12）。

## 2. sysfs / procfs 可写面

| 范围 | 检查项数 | 可写项 |
|---|---|---|
| `/proc/sys`（递归，深度 ≤3） | — | **0** |
| `/sys/module/<mod>/parameters/<param>` | — | **0** |
| 精选高危节点（`kptr_restrict`/`dmesg_restrict`/`perf_event_paranoid`/`drop_caches`/`kgsl force_*`/`power/state`/`sysrq-trigger` 等 16 项） | 16 | 仅 `/sys/kernel/tracing/trace` |
| 合计 | **764** | **1** |

`/sys/kernel/tracing/trace` 可写属正常设计（写 trace 缓冲区），`current_tracer` 仍拒 ⇒ **不构成提权面**。

## 3. 经典本地提权面

| 项 | 结果 |
|---|---|
| SUID 二进制（`/system` `/vendor` `/product` `/odm`，`-xdev -perm -4000`） | **0 个** |
| `run-as` | `-rwxr-x--- root shell`（16000 B）⇒ **SUID 位已移除**，无法切到 app uid |
| `su` | `/system/bin/su`、`/system/xbin/su` 均不存在 |
| `ro.secure` / `ro.debuggable` / `ro.adb.secure` | `1` / `0` / `1` ⇒ production build |

⇒ 传统的"SUID 二进制 / run-as / debuggable"三条路在本机全部关闭（ROM 已做硬化）。

## 4. binder 面（唯一还有实质未知的部分）

`service list` 共 **236** 个服务，其中 **229** 个可 `dumpsys`。OPPO/ColorOS 私有服务占相当比例，节选：

```
  2  OPPO                    android.os.IOplusService
  3  OPPOExService           android.os.IOplusExService
 69  engineer                android.engineer.IOplusEngineerManager
 80  guardelfthermalcontrol  android.os.IOppoGuardElfThermalControl
 84  horae                   com.oppo.horae.IHoraeService
138  oiface                  com.oppo.oiface.IOIfaceService
152 oppo_app_data_service    com.coloros.exsystemservice.appdata.IOppoAppDataService
207 testharness             (无接口描述符)
```

另有 **工程模式处于开启状态**：

```
persist.sys.adb.engineermode      = 1
init.svc.oplus.engineer-1-0       = running
ro.oppo.my_engineering_root       = /my_engineering
```

但 `/my_engineering` 分区实测**近乎空**（仅 `build.prop`、`etc/{NOTICE.xml.gz,key.config,permissions,sysconfig}`），
不含 `su`、daemon 或 apk ⇒ **不是直接的提权入口**。`dumpsys engineer` 无输出。

## 5. 结论

| 面 | 判定 |
|---|---|
| 设备节点可写（binder/hwbinder/ashmem/kgsl） | 均已有明确结论：kgsl 不可利用（§18.11）、ashmem/binder 无已知可用 primitives、要求 ≥SPL 2023 的 CVE 不适用 |
| sysfs / procfs 可写 | **实质为零** |
| SUID / run-as / debuggable | **全部关闭**（ROM 硬化） |
| **OPPO/ColorOS 私有 binder 服务（236 个，含工程模式）** | **未审计** —— 本机唯一还有实质未知的面 |

**判定更新**：§22 的"三面全部不可利用"依然成立；但"该权限模型下所有入口都不行"这一更强结论
**尚不能成立**，因为 binder 面的 236 个服务（尤其 10 余个 OPPO 私有服务）从未被审计。

## 6. 若继续，下一步该做什么（成本与判据）

**不建议**直接 `service call` 盲试事务号 —— 那是对陌生服务发真实调用，可能有副作用且无信息效率。
推荐先做**静态审计**（只读、零风险）：

1. 取 `/system/framework/framework.jar`、`/system/framework/oplus-services.jar`（若存在）、
   `/system_ext`、`/my_*` 下的 jar/apk 清单；
2. 对每个 OPPO 私有 `Stub.onTransact` 分支，检查是否调用
   `enforceCallingOrSelfPermission` / `checkCallingPermission` / `PermissionChecker`；
3. 找出**缺少权限校验且执行高权限操作**（写 `/data`、`chmod`、`exec`、`mount`、`setprop`）的分支，
   再针对性构造最小调用。

**成本**：5–10 人日（需要反编译环境、需要能读到 jar —— `/system/framework` 当前可读性待测）。
**成功率**：不保证；ColorOS 历年来确有此类漏洞，但本机是 2025-03 构建，近年该类问题多已收紧。
**判据**：找到一个"无权限校验 + 高权限操作"的可达分支，且其 uid 为 `system` 或 `root`。
