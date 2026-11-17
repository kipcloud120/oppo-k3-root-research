# F.16 实机 ADB 取证汇总（运行时攻击面 / 缓解 / 可得性）

- 日期：2026-11-13
- 设备：`<redacted>` / PCGM00 / OP4679 / SDM710（soc_id 360）/ **PCGM00_11_F.16** / Android 11 / 内核 4.9.227
- 方式：`adb shell`（uid 2000，context `u:r:shell:s0`），**全程只读**，未写设备、未重启、未做 ioctl
- 关联：`F16_基线_与C17结论失效说明.md`（版本判定）、`k3_kernel_config.txt`（实机 config.gz）

## 1. 采集产物

| 文件 | 内容 |
|---|---|
| `k3_info.txt` | 第一轮：身份/内核/cmdline(拒)/getprop/proc-mounts/kallsyms(拒)/slabinfo/config.gz/by-name |
| `k3_info2.txt` | 第二轮：全量 getprop、SELinux、模块、CPU、SoC、sysctl、iomem(拒)、dev 节点、debugfs、slab 细节、seccomp、系统包 |
| `k3_info3.txt` | 第三轮：policyvers、debugfs/tracefs 可见性、分区映射、kgsl 打开测试 |
| `k3_info4.txt` | 第四轮：ashmem/ion/kgsl 打开性、tracefs 读、工程模式 App、system_ext 包 |
| `k3_kernel_config.txt` | 实机 `/proc/config.gz` 解压（5622 行） |

## 2. 可达的 kernel 攻击面（shell 权限实测）

| 面 | 节点/路径 | 实测 | 说明 |
|---|---|---|---|
| **Adreno GPU (KGSL)** | `/dev/kgsl-3d0` | `crw-rw-rw-`，**open OK** | **最强候选**：world 可打开；GPU 驱动历史 CVE 多（Adreno 616，4.9.227 / SPL 2022-04） |
| **ION 分配器** | `/dev/ion` | `crw-rw-r--` system，**open OK** | 可打开；ioctl 是否放行未测（4.9 ION 老接口） |
| Binder 系 | `/dev/binder` `/dev/hwbinder` `/dev/vndbinder` `binderfs` | world rw | 经典面，2019 前 CVE 多已修 |
| tracefs | `/sys/kernel/tracing/{trace,tracing_on,buffer_size_kb,trace_marker,trace_clock}` | **部分可读写**：`trace` 可读、`trace_clock` 可读；`current_tracer`/`available_tracers` **拒** | 可读 trace，但无法设 tracer；信息面有限 |
| SELinux access | `/sys/fs/selinux/access` | `-rw-rw-rw-` | 可写访问向量查询节点（受限用途） |

**被 SELinux 挡死（虽 world rw）**：`/dev/ashmem` → open `Permission denied`。
**需 root/被拒**：`/sys/kernel/debug`（debugfs 挂载但 shell 不可进）、`/proc/kallsyms`、`/proc/cmdline`、`/proc/iomem`、`/proc/partitions`、`/proc/sys/kernel/{kptr_restrict,randomize_va_space,dmesg_restrict,unprivileged_bpf_disabled,...}`、`/sys/kernel/slab/<cache>/*`（per-cache）、`dmesg`。

## 3. 已加载模块（`/proc/modules`，地址全部掩码 `0x0`）

大量 audio/wlan dlkm：`wlan`(8.3MB)、`q6_dlkm`、`platform_dlkm`、`machine_dlkm`、`wcd*_dlkm`、`apr_dlkm`、`stub_dlkm` 等。
→ **模块基址不可得**（`/proc/modules` 与 `/sys/module/*/sections` 均掩码/受限）。若走 wlan/audio 驱动漏洞，KASLR 模块基址需另行泄露。

## 4. 运行时缓解与配置（实测）

| 项 | 值 | 影响 |
|---|---|---|
| `kernel.perf_event_paranoid` | **3** | perf 对非特权关闭 → perf 面不可用 |
| `CONFIG_RANDOMIZE_BASE` | y | KASLR 开，符号/模块基址需泄露 |
| `CONFIG_ARM64_PAN` / `UAO` / `UNMAP_KERNEL_AT_EL0` / `SW_TTBR0_PAN` | 全 y | 内核访问用户内存受限 |
| `CONFIG_SLAB_FREELIST_RANDOM` | **not set** | 堆喷更可控 |
| `CONFIG_SLUB_DEBUG` / `SLUB` | y | 配合可读 `/proc/slabinfo`，堆布局可观测 |
| `CONFIG_USER_NS` | **not set** | userns 类提权链阻断（GhostLock 不受影响） |
| `CONFIG_HARDENED_USERCOPY` / `FORTIFY_SOURCE` | y | 常规加固 |
| `CONFIG_BPF_SYSCALL` / `BPF_JIT` | y / not set | 有 bpf 系统调用、无 JIT |
| `CONFIG_KASAN`/`KFENCE`/`KPROBES`/`DEVMEM`/`PROC_KCORE` | 均 not set | 无调试/内核内存接口 |
| SELinux | `Enforcing`，policyvers **30** | 强约束；shell 域受限 |
| AVB | `avb 1.1`、`vbmeta locked`、`verity enforcing`、A-only | 不能改 system（临时 root 也不改） |

**关键 slab 尺寸（`/proc/slabinfo` 实测）**：`cred_jar=192`、`task_struct=3840`、`filp=320`、`kmalloc-256/512/1024`、`vm_area_struct=184`、`dentry=192`。

## 5. 值得注意的 system 侧入口（本地攻击面）

- `com.oppo.engineermode`（`/system/system_ext/app/OppoEngineerMode/OppoEngineerMode.apk`，**userId=1000 系统**，V5.0）：导出服务 `MdSubSystemRestartService` 受 `oppo.permission.OPPO_COMPONENT_SAFE`（signature|privileged）保护 → 普通 App 调不动。
- `com.coloros.logkit`、`com.oplus.onetrace`、`com.oplus.eid`、`com.oplus.crashbox`、`com.coloros.oppoguardelf`：系统侧组件，多数受签名权限保护，**不作为首选面**。
- `deeptesting` **未安装**（深度测试需自行装 APK）。

## 6. 对"临时 root"路线的影响（结论）

1. **候选面重排**（按 shell 可达性 + 历史 CVE 密度）：**KGSL(kgsl-3d0) > ION > Binder > tracefs > futex/GhostLock**。
   - 之前只盯 futex GhostLock；现在实测 **GPU(KGSL) 世界可打开**，对 4.9.227 + SPL 2022-04 的 Adreno 驱动应优先排查未修补 CVE（需 F.16 内核/驱动源码核对补丁窗口）。
2. **仍需 F.16 内核**才能定偏移/补丁：ADB 侧拿不到内核符号、iomem、模块基址。**下一步硬前提仍是取得 F.16 的 boot.img/内核**（见 `F16_基线_与C17结论失效说明.md` Step 0）。
3. **ADB 侧已无更多可挖**：kallsyms/cmdline/iomem/partitions/debugfs/模块地址/dmesg 全部需 root，shell 已到边界。

## 7. 状态

- ADB 采集**完成**，可断开数据线。
- 后续工作不再依赖连机：取 F.16 固件 → 静态提取 4.9.227 符号/驱动 → 选定面（KGSL/ION/GhostLock）做补丁窗口与可移植性判定。
