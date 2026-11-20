# dumpstate 第三主体路径：内核日志文本指针泄露判定（2026-11-20 16:05–16:25）

> **v13.2 更正（2026-11-20，响应审核 v0132 P0-1）**：本文件**头部原来的"当前 boot slide 不可得（boot 边界）"已作废**。该表述只对应 16:05–16:25 首次实验的中间状态（§4 记录的时点缺口）；同日 16:32–16:40 经用户明确授权的一次重启后，§8 已实证取得**当前 boot 的 `.text` KASLR slide = `0x1953600000`**（运行时 `_text = 0xffffff995b680000`），并经跨 boot 预测复现与寄存器族一致性交叉验证。
> **权威台账分工（审核 v0132 明确）**：`KASLR_EVIDENCE.md` 是 slide 的**权威证据台账**（哈希、地址归属、保留边界、成功/失败条件）；**本文件只负责记录该方法的实验过程与原始观察**，不再作为 slide 状态的第一来源。阅读 slide 结论请以 `KASLR_EVIDENCE.md` 为准。
> 状态（现行）：**方法学成立 + 当前 boot slide 已取得（§8）**；§4/§5 的"缺口"表述均为历史中间态，保留作为过程记录。
> 授权：首次执行经用户确认（承接 `IMEM_KASLR_EVIDENCE.md` §5.2 的"dumpstate 第三主体"登记项）；§8 的重启为**单独、逐次授权**。
> 性质：全程只读判定 + 标准 bugreport 流程；无内核写、无 panic 面；第一次实验零重启，§8 的授权重启不计入"路径本身需要重启"——重启只是取得"当前 boot"时点的窗口手段。

## 1. 可达性判定（成立）

- shell 域执行 `setprop ctl.start dumpstate` → `init.svc.dumpstate=running` ⇒ **shell 可经 init 拉起 dumpstate 服务**（`u:r:dumpstate:s0`，第三主体，此前 §53/§54 审计范围外）。
- `dumpstate` 二进制本身 shell 不可执行（`Permission denied`），必须走 init 服务路径；输出经 `bugreportz -p`（socket 流，进度 1.1 协议）产出 zip 至 `/bugreports`（symlink → `/data/user_de/0/com.android.shell/files/bugreports`），**shell 属主可读可拉取**。
- 全流程约 3 分钟（5505/5505），产出 zip 8.6 MB，包含 `KERNEL LOG (dmesg)` 段（8997 行，当前 boot 最近 ~26 分钟 ring）与 **`FS/cache/recovery/last_kmsg` + .1–.10 共 11 份历史 console 全量日志**。

## 2. 指针泄露事实（核心发现）

当前内核 `4.9.227-perf+` 的 printk **未被厂商哈希化**——裸 `%p` 与 `WARN()` 寄存器 dump 的原始指针原样进入 console 日志。每次开机早期存在**两个必现 WARNING**（boot 后 1 秒内）：

| 时间 | WARN 源 | 泄露内容 |
|---|---|---|
| 0.278 s | `sysfs: cannot create duplicate filename '/devices/platform/soc/6.gpio-regulator'` → `WARNING ... sysfs_create_dir_ns+0xb8/0xf0` | `pc : [<runtime_addr>]`、`lr`、`sp : fffffffadfa1f910`（栈）、`x27/x28`（数据段） |
| 0.966 s | `proc_dir_entry 'devinfo/ufs_version' already registered` → `WARNING ... proc_register+0xf8/0x148` | 同上格式 |

**单次 dump 即泄露三类地址**：文本段（pc/lr）、内核栈（sp）、数据段（x27/x28）。

## 3. slide 推导链（可复算，四路交叉一致）

以 `last_kmsg`（旧 boot）为例：

```
pc1 = 0xffffff81722dcb68  = runtime(sysfs_create_dir_ns) + 0xb8
lr1 = 0xffffff81722dcb64  = runtime(sysfs_create_dir_ns) + 0xb4
pc2 = 0xffffff81722ccde8  = runtime(proc_register)        + 0xf8
lr2 = 0xffffff81722ccde4  = runtime(proc_register)        + 0xf4
```

用 `vmlinux.elf` 静态符号表（权威）计算四个独立 slide 候选，**全部一致**：

```
slide = 0x16a000000
运行时 _text = 0xffffff8008080000 + 0x16a000000 = 0xffffff8172080000
```

方法论修正（再次记录）：`firmware_F16/kallsyms_out.txt` 的地址是**文件偏移**而非链接 VA（`_text=0x5b88`），符号-地址换算必须用 `vmlinux.elf`——与 README"五个值得单独看的结果 #1"同源教训的第二实例。

**随 boot 变化确证**：10 份 last_kmsg 副本的 pc 值各不相同（`ffffff81 72…` / `ffffff9c 56…` / `ffffff89 ad…` / …）⇒ 指针真实承载每次开机的独立 KASLR slide，非固定值。

## 4. 当前 boot 边界（本路径的精确缺口）

> **历史中间态（16:05–16:25 首次实验时）**：本节的"当前 boot slide 无法取得"只对应当时未授权重启的条件；**16:32–16:40 的授权重启后已由 §8 补齐**，本节保留作为问题定义与后续 WARN 触发面审计的由来。

- 当前 boot 的两个必现 WARN 打印发生在 `t<1 s`，而当前 dmesg 环形缓冲仅覆盖最近 ~26 分钟（ring 已被 76 h 高频厂商日志覆盖）⇒ **当前 boot 的 slide 无法从现有 ring 取得**。
- `/sys/fs/pstore`/ramoops（`attached 0x400000@0xb7e00000`）同理：pstore 文件只在 boot 时加载**上一次**会话的 console = 与 last_kmsg 同源（旧 slide）。
- last_kmsg.* 全部为历史 boot；slide 每 boot 随机 ⇒ 历史值对本 boot 无效。

**结论**：dumpstate 路径把缺口精确化为——**当前 boot 的 ring 内存在一个原始 pc 打印事件**。达成方式（按项目约束排序）：

1. **运行期可触发的 WARN**（首选，纯离线审计可推进）：找一个从可达主体（shell 或 uid=0 `oplus_wifi_service`，NET_ADMIN/NET_RAW/SYS_MODULE）能触达、必现且无 `BUG()` 升级路径的 `WARN()`，触发后 26 分钟内跑 bugreport 即得当前 slide。审计候选：qcacld（已有未剥符号 `qca_cld3_wlan.ko`）、kgsl、/dev/diag 余量面、vendor 驱动。**约束**：命中即 `BUG()` 的面（如 KGSL CVE-2023-33107）不在候选内。
2. **被动等待真实 WARN**：厂商驱动运行期异常场景的 WARNING 进入 ring 后立即 bugreport；零内核接触但概率不可控。
3. **重启窗口**（本项目边界禁止，仅登记）：任何重启后 26 分钟内 bugreport 即得该 boot slide。

## 5. 与既有四层判定 / 三类地址体系的关系

- 本路径属于 **①-s 类（KASLR slide，`kimage_voffset` 承载）** 的获取面——v008 判"本机无获取原语"的范围是已审接口；dumpstate 第三主体在该范围外，现已在**机制上**取得原语，仅缺当前 boot 的时点。
- 附带泄露的 `sp`（内核栈地址）属 ③ 类方向的旁证信号（当前为 init/swapper 栈，非持锁 W 线程栈），仅登记，不外推。
- GhostLock ②（可控 rt_mutex 堆地址）缺口**不受本路径影响**——slide 不是堆地址。

## 6. 证据与状态

- 本地证据（`.build/bugreport_20261120/`，不入库）：`final.zip`（8.6 MB 完整报告）、`unzipped/bugreport-*.txt`（dmesg 段 35679–44675 行）、`unzipped/FS/cache/recovery/last_kmsg{,.1–.10}`。
- 本轮判定的 slide 推导脚本逻辑：见 §3（纯离线，`python + pyelftools`）。
- 设备终态：`/bugreports` 已清空（zip/tmp/dumpstate_log/dumpstate-stats 均删）；`boot_id` 全程不变（`27520eec-0945-44db-930d-0c0fd61c1eeb`）；uptime 连续（272381 → 274221 s）；零重启。
- 工具层记录：`adb pull/push` 经本环境会出现**目标文件名末字符截断**（`imem_kaslr_probe.s`、`.zi`/`.tx` 两个独立实例），推送/拉取时必须显式完整目标路径并在之后核对文件名完整性。
- `/data/local/tmp` 状态：空（本轮未使用）。

## 7. 下一步（需授权的离线审计候选）

**WARN 触发面静态审计**：在 `qca_cld3_wlan.ko`（14.6 MB 未剥符号）与内核镜像可达 ioctl 路径中枚举 `WARN/WARN_ON` 调用点，过滤条件：(a) 可从 NET_ADMIN/NET_RAW/SYS_MODULE 能力集触达；(b) WARN 后不进入 `BUG()`/panic 路径；(c) 不违反"不重启/不刷写"边界。产出候选清单后经用户授权再做判定型上机。（§8 之后更新：重启窗口路径已按授权实证完成，本条降级为"不重启条件下的替代路线"。）

## 8. 上机判定完成（2026-11-20 16:32–16:40，经用户授权重启一次）——**当前 boot slide 已取得**

### 8.1 执行序列与状态控制

| 时刻 | 动作 | 状态 |
|---|---|---|
| 重启前 | `boot_id=27520eec-0945-44db-930d-0c0fd61c1eeb`，uptime 274539 s；`logcat -b kernel` 通道确认存在（256 KiB） | 基线记录 |
| 16:32:1x | `adb reboot`（授权执行） | boot_id 变更为 `b9f9f06a-2f2c-470f-8887-c9bb004bdaa2` |
| uptime 39 s | 首次探测：klog 缓冲空（logd 内核缓冲未捕获早期 WARN，与预期不同） | 窗口风险显现 |
| uptime 100 s | `ctl.start dumpstate` + `bugreportz -p`（后台，2m45s 完成） | zip 8.1 MB |
| 之后 | 拉取解析：**KERNEL LOG 段含新 boot t=0→0.371 s 的 396 行**，两个 WARN（本次仅 sysfs 一个出现在段内）原始指针在 ring 中 | **命中** |
| 收尾 | `ctl.stop dumpstate`；`/bugreports` 清空；boot_id 不变、uptime 连续 | 设备清洁 |

### 8.2 结果：**当前 boot 的 `.text` KASLR slide = `0x1953600000`**

```
pc1 = 0xffffff995b8dcb68 = runtime(sysfs_create_dir_ns) + 0xb8   → slide = 0x1953600000
lr1 = 0xffffff995b8dcb64 = runtime(sysfs_create_dir_ns) + 0xb4   → slide = 0x1953600000
寄存器族一致性：0xffffff995b8dcb28/24 = runtime(sysfs_create_dir_ns)+0x78/+0x74 ✓
运行时 _text = 0xffffff8008080000 + 0x1953600000（2 MB 对齐 ✓，与 arm64 4.9 KASLR 粒度一致）
```

### 8.3 推导链跨 boot 复现（可证伪预测成立）

- 预测：重启后 `/cache/recovery/last_kmsg` 应为**重启前 boot** 的 console，其早期 WARN 指针应推出重启前 boot 的 slide。
- 实测：post-reboot `last_kmsg` 与重启前 last_kmsg **逐字节同长（353178 B）、pc/lr 指针完全相同**（`ffffff81722dcb68/64`、`ffffff81722ccde8/e4`）⇒ slide = `0x16a000000` 与 §3 一致。**预测命中，链路跨 boot 复现成立。**

### 8.4 开放观察（不影响结论，影响复现窗口评估）

1. 新 boot 的 KERNEL LOG 段仅覆盖 `t=0→0.371 s`（396 行）而非预期的"最近窗口"——机制未定（可能与 OPPO 的 `opmgetdmesg`/crashbox 日志采集、或 ring 在读取时刻的状态有关）。旧 boot（76 h）同段为最近 ~26 分钟窗口。两种形态下 t<1 s 的 WARN 指针：新 boot 在 ring 中存活、旧 boot 已被覆盖 ⇒ **重启后尽早 bugreport 是取得当前 slide 的充分手段**，但内在机制待定性。
2. `logcat -b kernel`（256 KiB logd 缓冲）在两个时点均为空，不能替代 dumpstate 路径。
3. 本次 boot 的第二个 WARN（`proc_register`）未出现在 dmesg 段内（段在 0.371 s 截止，WARN 在 0.966 s）——pc 单点 + lr 同函数 + 寄存器族三重一致已满足判据，未强求。

### 8.5 安全控制与边界

- 本次重启为**用户明确授权**的一次性行为；boot_id 变更（`27520eec…` → `b9f9f06a…`）与 uptime 归零均为授权预期。
- 全程只读判定（bugreport 流程 + 文件删除仅限自身产出）；无内核写、无 panic 面。
- slide 仅对当前 boot（`b9f9f06a…`）有效；再重启即失效，须重走本流程。
- 设备终态：`/bugreports` 空；`/data/local/tmp` 空；本地证据留存 `.build/bugreport_20261120/`（`newboot.zip`、`last_kmsg_postreboot.txt`、`klog_newboot.txt`、首份报告），不入库。

### 8.6 对项目四层判定的意义

**①-s 类（KASLR slide）获取原语在本机成立**：`ctl.start dumpstate → bugreport → 内核日志原始 pc/lr → vmlinux.elf 静态符号 → slide`，四路交叉一致 + 跨 boot 复现。v008"本机无获取 `kimage_voffset` 原语"的表述在已审接口范围内仍然成立，但本路径（dumpstate 第三主体 + 授权重启）在其范围外实证补齐。**注意**：slide ≠ 可用 root——GhostLock ②（可控 rt_mutex 堆地址）/③ 缺口不变；且 slide 依赖"授权重启"这一非默认条件，不应外推为默认可获取。
