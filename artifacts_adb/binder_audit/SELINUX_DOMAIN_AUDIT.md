# `oplus_wifi_service` SELinux 域边界审计（P0）

> 响应 `docs_archive/审核意见CHATGPT-v003.txt` 第四节 "P0：SELinux 域权限边界审计"。
> **本轮全程只读**：从设备 `adb pull` 策略文本与 init rc，未 push、未注入、未改属性、未重启、未连内核。
> 策略物料指纹见 §2，工具为 `tools/sepolicy_domain_audit.py` + `tools/prop_trigger_audit.py`（离线可复跑）。
> 结论若与正文不一致，以正文表格中的**原始规则与文件行号**为准。

---

## 1. 结论

**在该域的策略定义范围内，未找到可达的 SELinux 域逃逸路径。** 这不是"还没试出来"，而是四条候选路径各自被策略本身断链：

| 候选逃逸路径 | 判定 | 断链点（策略原文） |
|---|---|---|
| 写入 → 由更高权限域执行 | **不可行** | 该域可写的三类路径（`wifi_vendor_data_file` / `mnt_vendor_file` / `fuse`、`sdcardfs`）在全策略中**没有任何域持有 `execute` 权限** ⇒ 写-执行链从策略层就不存在 |
| 挂载覆盖（`CAP_SYS_ADMIN`） | **不可行（双锁）** | ① 该域对 `filesystem` 类只有 `getattr`，无 `mount`/`remount`；对文件类型无 `mounton`；② 进程实际能力集不含 `CAP_SYS_ADMIN`（rc 只给 3 个，见 §4） |
| 加载自定义内核模块 | **不可行（单向）** | `(allow oplus_wifi_service vendor_file (system (module_load)))` 只对 `vendor_file` 生效，而该域对 `vendor_file` **只有读/执行、没有写** ⇒ 只能加载镜像里既有的、已签名的模块 |
| 属性写 → init 执行为 root | **部分可行、但无害** | 该域只能写 `vendor_oppo_prop`；命中的 11 条 init 触发器动作全是 `chmod`/`chown`/`setprop`，**没有一条 `start` 或 `exec`**；且其中 `ro.*` 运行期不可写 |
| 域转换（`typetransition`） | **唯一一条，但不可控** | 全策略中本域可触发的自动转换只有 `exec crash_dump_exec → crash_dump`（`(typetransition domain crash_dump_exec process crash_dump)`）；见 §7 为何拿不到收益 |

**同时登记 3 项真实风险**（属"越界的写面"，不构成逃逸，但超出"Wi-Fi 自身数据"的合理边界）：

1. **`/mnt/vendor/persist/wlan/WCNSS_qcom_cfg.ini` 可写**：`/mnt/vendor/persist/wlan` 无更细粒度标签，落入 `mnt_vendor_file`，而该域对其有完整写权限；此文件由 init `chmod 0666`，是 WLAN 驱动的配置入口，**写它等于落一个跨重启的持久化改动**——与本项目"不装任何持久化文件"的约定直接冲突，**明确禁止实验**。
2. **属性类型粒度过粗**：`vendor_oppo_prop` 同时覆盖 `vendor.oplus.wifi.*`、`vendor.oppo.camera.*`、`persist.oppo.camera.*`、`persist.odm.dirac.*`、`vendor.vold.serialno`、`vendor.modem_dump_action`。即该 Wi-Fi 域可改写**相机、显示、vold 序列号、modem dump** 的配置属性；`system_server` 是本类型的读方之一（§8）。
3. **`/dev/diag` 全 ioctl 可用**：`(allow oplus_wifi_service diag_device (chr_file (ioctl read write open ...)))` + `root`/`diag` 组。这是**此前 §1.2 五面清单中未登记的一条内核面**（高通 diagchar），属新出现的可达内核攻击面；本轮不评估其可利用性。

**与审核意见的口径一致**：`uid=0` 命令执行已达成，但"可用 root"未达成；本轮进一步把"未达成"的原因从"不知道缺什么"收敛为"**策略明确不给域外可写执行落点**"。

---

## 2. 物料与方法

### 2.1 策略来源（全部 `adb pull`，只读）

| 文件 | 设备路径 | 大小 | SHA256 前 16 位 |
|---|---|---|---|
| `vendor_sepolicy.cil` | `/vendor/etc/selinux/` | 981,335 | `6d1c54a658484e52` |
| `plat_sepolicy.cil` | `/system/etc/selinux/` | 1,579,853 | `5249d8e1eef4db34` |
| **`system_ext_sepolicy.cil`** | `/system_ext/etc/selinux/` | 437,972 | （初版遗漏，见 §13） |
| **`product_sepolicy.cil`** | `/product/etc/selinux/` | 37,176 | （初版遗漏，见 §13） |
| `plat_pub_versioned.cil` | `/vendor/etc/selinux/` | 950,003 | `890e3177b00dfa0c` |
| `precompiled_sepolicy`（二进制，备查） | `/odm/etc/selinux/` | 1,054,954 | `7293d4c33580fb5b` |
| `vendor_file_contexts` | `/vendor/etc/selinux/` | 129,857 | `0b5ca261b452c753` |
| `vendor_property_contexts` | `/vendor/etc/selinux/` | 21,639 | `784d7251c50fea87` |
| `plat_sepolicy_vers.txt` | `/vendor/etc/selinux/` | 5 B | 内容 `30.0` |
| init rc（197 个） | `/vendor|/odm|/system/etc/init/` | 976 KB | 见 `.build/sepolicy/rc/` |

> `vendor_service_contexts` 拉取被拒（`Permission denied`，仅 stat 被拒，不影响本审计：本域不在其中注册 Java 服务）。
> 策略为 **version 30**，故 CIL 中同一类型存在 `X` 与 `X_30_0` 两种写法；工具已归一化去版本后缀，否则目标类型数会被重复计算（首版工具即踩此坑，已修）。

### 2.2 工具

```bash
# 域 allow 全量展开 + 写面 + 消费面（direct / via 属性 分列）
python tools/sepolicy_domain_audit.py --domain oplus_wifi_service \
    --cil .build/sepolicy --json .build/sepolicy/audit_oplus_wifi.json
# 属性写面 × init 触发器 交叉
python tools/prop_trigger_audit.py --cil .build/sepolicy --rc .build/sepolicy/rc \
    --domain oplus_wifi_service
```

工具口径声明：`direct` = 源为域名的规则（厂商显式授予）；`via:X` = 通过属性 `X` 继承。解析告警仅
`typeattributeset(not ...)` 1408 条（`base_typeattr_*` 的补集定义，对"该域能做什么"无影响，因为补集只用于其他域的基线，不作本域授予来源）。

### 2.3 规模

| 指标 | 值 |
|---|---|
| 五份 CIL 的 `allow` 语句总数 | **24,657**（初版只读 3 份：21,011） |
| 对本域适用的 `allow` | **307**（初版 304；多出的 3 条见 §13） |
| 本域所属属性（含嵌套） | **89**（初版 41） |
| 显式以本域为源的规则覆盖的目标类型 | **44**（不变） |
| 可写目标类型（`file`/`dir`/`chr_file`/`sock_file` 等） | 12（不变） |

---

## 3. 域身份

来自 `/odm/etc/init/vendor.oplus.hardware.wifi@1.1-service.rc`（原文）：

```
service oppo_wifi_service /odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service
    class hal
    user root
    group wifi system vendor_qti_diag net_admin
    capabilities NET_ADMIN NET_RAW SYS_MODULE
```

| 维度 | 值 | 说明 |
|---|---|---|
| SELinux 域 | `u:r:oplus_wifi_service:s0` | 与 §23.3 现场 `id` 输出一致 |
| 运行 uid | `0` | `user root` |
| 附加组 | `1010(wifi)`、`1000(system)`、`2901(vendor_qti_diag)`、`3005(net_admin)` | 与 §23.3 一致 |
| 进入方式 | `(typetransition init oplus_wifi_service_exec process oplus_wifi_service)` | **只能由 init 拉起**；从 shell 直接 exec 该二进制不会转换域 |

**关于 DAC 的一个重要更正**：该进程虽然 `uid=0`，但**没有 `CAP_DAC_OVERRIDE` / `CAP_DAC_READ_SEARCH`**（rc 只给 3 个能力，见 §4）。因此 `uid=0` 并不等于"可以读任何文件"：它按**所有者语义**获得 root 拥有的文件的权限，按**组语义**获得 `wifi`/`system`/`vendor_qti_diag`/`net_admin` 四个组的权限。这解释了 §23.4 的观测：能读组内可见的 vendor 文件，但 `ls /data/system` 依旧被 MAC 拒。

---

## 4. 能力面：策略授予 10 个，实际只有 3 个

```
(allow oplus_wifi_service self (capability (chown fowner fsetid net_admin net_raw setgid setuid sys_admin sys_module sys_resource)))
```

| 层 | 能力集合 | 依据 |
|---|---|---|
| SELinux 策略允许 | `chown fowner fsetid net_admin net_raw setgid setuid sys_admin sys_module sys_resource` | 上条规则（`direct`） |
| **进程实际 Permitted** | `NET_ADMIN NET_RAW SYS_MODULE` | rc 的 `capabilities` 行；init 建立 Permitted/Effective/Bounding 后，进程**无法**把 `sys_admin`（`sys_ptrace`、`sys_rawio`、`dac_*`）提上来 |
| **实测（2026-11-18 12:31:30，V1）** | `CapInh/CapPrm/CapEff/CapBnd/CapAmb = 0x13000` | `0x13000` = bit12 `NET_ADMIN` + bit13 `NET_RAW` + bit16 `SYS_MODULE`；bit21 `SYS_ADMIN`(0x200000) **为 0**，且 **Bounding 集同样不含** ⇒ 连 `capset` 也提不上来 |
| 结论 | **策略里的 `sys_admin` 是潜伏授予，运行期不可达** | 两层校验：能力集不含 + `filesystem:mount` 类权限缺失 |

> 实测原文（`p1_probes/20261118T123130_CAPS.log`）：
> `I CAPS : CapInh: 0000000000013000 CapPrm: 0000000000013000 CapEff: 0000000000013000 CapBnd: 0000000000013000 CapAmb: 0000000000013000`
> 这一行同时证明另一件事：该域**能读 `/proc/self/status`**，但读不到 `/proc/kallsyms`（§23.9 的定向策略拒绝），
> 说明拒绝是按文件标签而非按目录，与 §23.9 的判读一致。

⇒ "用 `CAP_SYS_ADMIN` 挂载覆盖"在本机是**双锁**：能力拿不到，SELinux 也不给 `mount`。这条否证与 §1 的第 2 行一致。

---

## 5. 可写面清单（`direct`，即厂商显式授予）

| 类 | 目标类型 | 授予的写类权限 | 落点（file_contexts） |
|---|---|---|---|
| `file` | `wifi_vendor_data_file` | `append create rename setattr unlink write`（+ `read map`） | `/data/vendor/wifi(/.*)?` |
| `dir` | `wifi_vendor_data_file` | `add_name create remove_name rename rmdir reparent setattr write` | 同上 |
| `file` | `mnt_vendor_file` | `append create rename setattr unlink write`（+ `read map`） | `/mnt/vendor(/.*)?`（persist 挂载点整棵树，**含 `persist/wlan`**） |
| `dir` | `mnt_vendor_file` | `add_name create remove_name rename rmdir reparent setattr write` | 同上 |
| `file` | `fuse` | `append create rename setattr unlink write` | **无静态落点**（运行时由挂载指定） |
| `dir` | `fuse` | 同上 + `add_name rmdir` | 同上 |
| `file` | `sdcardfs` | `append create rename setattr unlink write` | 同上 |
| `file` | `sysfs_wlan_con_mode` | `append write` | `/sys/module/wlan/parameters/con_mode`（已用于 `changeConnectionMode`） |
| `file` | `proc_overcommit_memory` | `append write` | `/proc/sys/vm/overcommit_memory`（仅 DoS 面） |
| `chr_file` | `diag_device` | `append ioctl read write open` | `/dev/diag` |
| `sock_file` | `property_socket` | `write` | `/dev/socket/property_service` |
| `property_service` | `vendor_oppo_prop` | `set` | 55 条属性前缀（§8） |

**不在此表但同样重要的读/执行面**：`vendor_file`（`execute`，可跑任意既有 vendor 二进制）、`vendor_shell_exec`（`execute`）、`vendor_toolbox_exec`（`entrypoint execute execute_no_trans`）、`proc_modules`（`read`，地址已掩码）、`vendor_bluetooth_prop`（`read`）、`hwservicemanager_prop`（`read`）。

> `fuse` / `sdcardfs` 在 `plat_file_contexts` 与 `vendor_file_contexts` 中均无路径规则——它们是挂载时由 `context=` 指定的类型。本域对它们的完整写权限**目前无落点可确认**，记为未验证项（§10）。

---

## 6. 消费面：写下去，谁能读？谁能执行？

对 §5 的三类可写路径，逐类查询"全策略中谁对它持有 `execute`"，结果如下（关键否定）：

| 可写目标类型 | 持有 `read` 的域（部分） | **持有 `execute` 的域** |
|---|---|---|
| `wifi_vendor_data_file` | `hal_wifi_hostapd_default`、`hal_wifi_supplicant`、`hal_wigig`、`wcnss_service`、`fstman`、`usage_hidl`、`vendor_autochmod`、`cnd` | **无（0 个域）** |
| `mnt_vendor_file` | `hal_audio_default`、`hal_camera_default`、`hal_health_default`、`rild`、`wcnss_service`、`self_init`、`ueventd`、`qti_init_shell` 等 20+ | **无（0 个域）** |
| `fuse` / `sdcardfs` | — | **无（0 个域）** |
| `vendor_file`（只读，不可写） | 全系统 | `init`、本域、以及大量 `hal_*`（本域只有读/执行，**无写**） |

**这条否定就是域逃逸的断点**：SELinux 的 `execute` 是"能否把该文件作为程序装载"的独立检查，且 `execute` 不会被 `read` 蕴含。既然全策略没有任何域能执行我们可写路径下的文件，那么"写脚本/写 ELF → 等别人执行"的传统链在本机 **从策略层就不成立**，与运行期能否触发无关。

补充：`mnt_vendor_file` 的读方里有 `ueventd`、`rild`、`self_init`、`hal_audio_default` 等**以 root 运行**的服务，它们会读 `persist` 下的配置——但只读，且不存在"读到可执行内容"的语义（详见 §9 的 `WCNSS_qcom_cfg.ini` 风险登记）。

---

## 7. 域转换枚举：只有 `crash_dump` 一条，且拿不到收益

**方法**：先求本域持有 `execute` 的全部文件类型（9 个：`oplus_wifi_service_exec`、`vendor_file`、`vendor_shell_exec`、`vendor_toolbox_exec`、`wcnss_service_exec`、`crash_dump_exec`、`system_lib_file`、`system_linker_exec`、`vndk_sp_file`），再在全策略中找 `typetransition(SRC, 该文件类型, process, NEW)` 且 `SRC` 覆盖本域的条目。

| 文件类型 | 转换目标域 | 转换源属性 | 本域可达 |
|---|---|---|---|
| `crash_dump_exec` | `crash_dump` | `domain`（全局） | **是** |
| `oplus_wifi_service_exec` | `oplus_wifi_service` | `init` | 否（回自身，且需 init 为源） |
| `vendor_shell_exec` | `qti_init_shell` / `vendor_shell` | `init` / `shell` | 否 |
| `wcnss_service_exec` | `wcnss_service` | `init` | 否 |

⇒ **执行 `/vendor/bin/sh` 不会转换域**，这与 §23 实测完全吻合（`sh` 在 audit 日志里带 `scontext=u:r:oplus_wifi_service:s0`）。这条同时解释了"为什么拿到 uid=0 之后仍然是同一个受限域"。

`crash_dump` 是唯一例外，但**不可利用**，三条理由：

1. **无法注入代码**：`crash_dump` 域的可读集合（`exec_type`、`dalvikcache_data_file`、`apk_data_file`、`vendor_file`、`same_process_hal_file`、`system_prop`、`ctl_default_prop`、`domain`）与本域的可写集合（`mnt_vendor_file`、`wifi_vendor_data_file`、`fuse`、`sdcardfs`）**交集为空** ⇒ 不存在用 `LD_PRELOAD`/`LD_LIBRARY_PATH` 把我们的 `.so` 送进该域的落点。
2. **无法控制其行为**：`crash_dump64` 是接收 `--pid` 与"由 init 传入的 tombstone fd"的一次性调试器（AOSP 语义；本机未复现），手工 exec 的结果是"起来即退"，不会给我们一个可交互对象。
3. **没有可用的输出通道**：它把目标进程内存写成 tombstone，目标是**他人的**崩溃现场，不是我们可指定的任意内存。

⇒ 判定：**"可达但零收益"**。这一条应登记为负知识，避免后续把 `crash_dump` 当作候选反复尝试。

**运行期验证（2026-11-18 12:31:41，V3）**：一条事务执行 `/system/bin/crash_dump64`，logcat 原文
（`p1_probes/20261118T123142_CD.log`）：

```
12:31:41.992 31259 31259 F crash_dump64: crash_dump.cpp:243] wrong number of args: 1 (expected 4)
12:31:41.994   792   792 I tombstoned: received crash request for pid -1
12:31:41.996   792   792 W tombstoned: crash socket received short read of length 0 (expected 12)
```

域标签没有直接打印（该二进制不接受"打印自身上下文"这种用法），但**行为可判别**：

| 事实 | 策略依据 | 推论 |
|---|---|---|
| 执行后 2 ms 内 `tombstoned` 收到来自 crash socket 的请求 | `(allow crash_dump tombstoned (unix_stream_socket (connectto)))` 存在 | 有进程连上了 tombstoned |
| 本域 `unix_stream_socket` 的 `connectto` **只有 `init` 一个目标** | 本域 direct 规则全集 | 连 tombstoned 的进程**不可能**是 `oplus_wifi_service` |
| 时间与 PID（31259，父为本域 `sh`）唯一对应 | 日志时序 | ⇒ 该进程已在 `crash_dump` 域 |

⇒ **域转换在运行期成立**（间接证据，非标签直读，故记为"中等置信"）。同时印证 §7 的第 2 条：
它拿到 `--pid`/tombstone fd 之前就因参数不足退出，`tombstoned` 只收到 `short read`，没有任何内存被 dump。
**结论不变：可达、零收益。**

---

## 8. 属性面：55 个前缀、11 条触发器、1 条可用且无下游

**可写属性类型只有一个**：`vendor_oppo_prop`（`(allow oplus_wifi_service vendor_oppo_prop (property_service (set)))`）。它在 `vendor_property_contexts` 中覆盖 **55 条前缀**，其中与本域无关的包括：

```
vendor.oppo.camera.        persist.oppo.camera.      persist.odm.dirac.      odm.dirac.
vendor.vold.serialno       vendor.modem_dump_action  ro.vendor.oppo.*        ro.odm.*
```

把"可写类型"与 354 条 `on property:` 触发器做交叉，命中 **11 条**：

| 触发器 | rc 位置 | init 动作 | 运行期可写？ | 收益 |
|---|---|---|---|---|
| `vendor.oplus.sniffer.on=0/1/2` | `odm/vendor.oplus.hardware.wifi@1.1-service.rc:10/14/18` | `chmod 0777 /data/vendor/wifi`、`chown root system …` | **是** | 无（该目录本就可写；chown/chmod 不改变 SELinux 标签） |
| `persist.vendor.oppo.region=*` | `odm/self-init.rc:35` | `setprop persist.sys.oppo.region ${…}` | **是** | **init 替我们把值写进 `system_prop` 类型的属性**（类型洗白）；但全 rc 中无任何触发器消费 `persist.sys.oppo.region`，链在此终止 |
| `ro.vendor.oplus.regionmark` / `ro.vendor.oplus.operator` | `odm/init.multimedia.rc:13/16/19` | `setprop ro.odm.audio.subtype …` | 否（`ro.*` 一次性） | — |
| `ro.vendor.oppo.radio.multisim.config` | `odm/self-init.rc:33` | `setprop persist.radio.multisim.config …` | 否 | — |
| `ro.vendor.gsi.version_variant` | `odm/self-init.rc:41` | `setprop` + `mount ext4 …` | 否 | — |
| `ro.vendor.oppo.fingerprint` / `ro.vendor.oppo.product.name` | `system/hw/init.rc:1688/1690` | `setprop ro.build.fingerprint` / `ro.product.name` | 否 | — |

**关键否定**：11 条触发器里**没有一条 `start <service>` 或 `exec`**。作为对照，本机确实存在"属性 → root 执行脚本"的现成范式，但触发属性不在本域的可写类型内：

```
# odm/init.vendor.oppo.connectivity.rc
on property:sys.oplus.wifi.dump.trigger=1
    start triggerwifidump            # /vendor/bin/sh /odm/bin/init.vendor.wifi.autochmod.sh "triggerwifidump"
    setprop sys.oplus.wifi.dump.trigger 0
```

`sys.oplus.wifi.dump.*` 属 `system_prop`，本域**没有** `set` 权限；`ctl.start` 属 `ctl_start_prop`，同样没有。⇒ 这条最强的现成范式对本域是关闭的。

`vendor_oppo_prop` 的读方（属性读 = 对该类型 `file:read`）包括 **`system_server`**、`vendor_init`、`cameraserver`、`hal_camera_default`、`hal_wifi_default`、`wcnss_service`、`self_init`、`vendor_pd_mapper` 等。即：我们的属性写入对 `system_server` 可见——但可见 ≠ 可被不安全消费；本轮未找到"消费点把属性值当命令/路径执行"的证据，故**不宣称**。

---

## 9. 风险登记（属越界写面，非逃逸）

| # | 项 | 事实 | 规制 |
|---|---|---|---|
| R1 | `/mnt/vendor/persist/wlan/WCNSS_qcom_cfg.ini` | `/mnt/vendor/persist/wlan` 无专属标签 ⇒ `mnt_vendor_file` ⇒ 本域可写；init 对该文件 `chmod 0666`；它是 WLAN 驱动/firmware 的配置入口 | **禁止实验**（跨重启持久化，违反 §11 约定）；若将来必须验证，只允许读，不允许写 |
| R2 | 属性类型粒度过粗 | `vendor_oppo_prop` 覆盖相机/显示/vold 序列号/modem dump 等非 Wi-Fi 属性；`system_server` 可读 | 视为厂商策略缺陷记录；不据此构造实验 |
| R3 | `/dev/diag` 全 ioctl | root + `diag` 组 + `ioctl`；高通的 diagchar 设备，历史上有多个内存破坏 CVE | **登记为新的内核面**，不纳入当前主线（主线已放弃内核原语）；仅在 §7 重开条件出现新线索时评估 |
| R4 | `vendor_file: module_load` + `SYS_MODULE` | 可对 `/vendor` 下的既有 `.ko` 调 `init_module`；不能加载自定义模块（对 `vendor_file` 无写权） | 与 §5.4 的结论一致：不构成新面 |

---

## 10. 探针结果（2026-11-18 12:31，用户授权后执行；每条一次事务、单变量）

判据均在执行前登记于本文件初版 §10 与 `HANDOVER.md` §24.9，**未事后修改**。原始日志见
`artifacts_adb/binder_audit/p1_probes/`，驱动脚本 `tools/wifi_exec.py`。

| # | 探针 | 载荷 | 结果 | 判据 |
|---|---|---|---|---|
| V1 | 实际能力集 | `x\nlog -t CAPS \`grep Cap /proc/self/status\`` | `CapEff = 0x13000`（`NET_ADMIN`+`NET_RAW`+`SYS_MODULE`），`CapBnd` 同值，`SYS_ADMIN` 缺席 | ✅ 0x200000 位为 0 |
| V2 | `persist/wlan` 标签 | `x\nlog -t LBL \`ls -ldZ /mnt/vendor/persist/wlan\`` | `drwxrwxrwx 2 system system u:object_r:mnt_vendor_file:s0` | ✅ 确为 `mnt_vendor_file`（R1 成立） |
| V3 | `crash_dump` 域转换 | `x\nlog -t CD \`/system/bin/crash_dump64\`` | `F crash_dump64: wrong number of args` + `tombstoned: received crash request for pid -1` | ⚠️ 间接成立（见 §7）；收益仍为零 |

**三点后果**：

1. §4 的"策略 10 个 / 实际 3 个"由推导升级为**实测**；`CapBnd` 同值意味着即便日后有 `capset` 原语也无法提权。
2. R1（`WCNSS_qcom_cfg.ini` 可写）由"策略推导"升级为**实测标签确认**；该目录 `0777`，写它即持久化改动，维持禁用。
3. §7 的"唯一域转换"在运行期被证实可用；同时再次证明**能转换 ≠ 能利用**——`crash_dump` 需要 4 个参数与
   init 传入的 tombstone fd，参数不足时它只会在连上 `tombstoned` 后立即退出。

> 方法论产出：**当一个二进制不打印自身上下文时，用"该进程必然触发的、目标域独有的一次系统调用"反推域**。
> 本例的判别物是 `connectto tombstoned` —— 本域没有这个权限，`crash_dump` 有，于是日志本身成为域标签。

### 10.1 仍然待验证（本轮未做，理由如下）

| 项 | 为何不做 |
|---|---|
| 用 `--pid` 让 `crash_dump` 真实附加到某进程 | 需 ptrace 真实进程；若目标是 `vold` 等被允许对象，会真的挂起该进程。**风险不可接受，放弃** |
| 写 `/mnt/vendor/persist/**` 验证可写性 | 持久化改动，违反 §11 约定 |
| `fuse` / `sdcardfs` 落点枚举 | 需读挂载状态并可能触碰挂载；收益低（§24 已证无域可执行这些路径） |

---

## 11. 可证伪条件

出现任一条，本审计的"无逃逸"结论即须重评：

1. 策略更新后，某个域对 `wifi_vendor_data_file` / `mnt_vendor_file` / `fuse` / `sdcardfs` 获得 `execute`（写-执行链复活）；
2. 本域获得 `filesystem:mount` 或某文件类型的 `mounton`（叠加 `CAP_SYS_ADMIN` 的可行性需重新核算，注意仍需先解决能力集问题）；
3. 本域获得 `ctl_start_prop` / `system_prop` / `hwservice_manager` 的更大写面（属性 → `start` 范式复活）；
4. 出现"读方把可写配置文件内容当命令/路径消费"的**二进制级**证据（本轮未审计被读文件的解析逻辑，见 §12 未穷尽项）；
5. 出现 `oplus_wifi_service_exec` 之外的、能被 shell（非 init）触发的域转换。

---

## 12. 未穷尽项（诚实登记）

1. **只审策略，未审解析逻辑**：`mnt_vendor_file` 的 20+ 个读方（含 `ueventd`、`rild`、`self_init`、`hal_audio_default`）如何**解析**它们读到的内容，本轮未做二进制级审计。§1 的"无逃逸"是**策略层**结论，不是"所有消费逻辑都安全"。
2. `fuse` / `sdcardfs` 无静态落点，其对应用途未确认（未做挂载态枚举，避免触碰 `/proc/mounts` 之外的状态）。
3. `usage_hidl`、`vendor_autochmod`、`fstman`、`wcnss_service`、`hostapd` 与本域**共享** `/data/vendor/wifi` 写权限（同权或更低权域），它们的解析逻辑未审计。
4. `hwservice_manager: hidl_base_hwservice add` 允许本域注册 HIDL 服务名，理论上存在"冒充"面；但每个服务名经 `vendor_hwservice_contexts` 映射到具体类型，本域只能注册 `oplus_wifi_hal_service` / `hidl_base_hwservice` 两类，未发现可冒充更高权限服务的路径（未穷尽，因为 `hwservice_contexts` 的 `plat` 侧部分被 `Permission denied` 拒绝 stat）。

---

## 13. 审计更正：运行期策略是 5 份 CIL，初版只读了 3 份

**发现经过**：核实"`anti_root_dialog_service` 是不是独立 SELinux 域"时，发现它在
`precompiled_sepolicy`（1,054,954 B 的二进制策略）里以**类型名字符串**存在，但在
`vendor_sepolicy.cil` / `plat_sepolicy.cil` 中计数为 0。矛盾指向一个可能：**运行期策略还有别的来源**。

`/odm/etc/selinux/` 下的 `precompiled_sepolicy.*.sha256` 正好列了三项：`plat`、`product`、`system_ext`。
补拉后确认：

| 文件 | 路径 | 大小 | 是否被初版纳入 |
|---|---|---|---|
| `plat_sepolicy.cil` | `/system/etc/selinux/` | 1,579,853 | ✅ |
| `plat_pub_versioned.cil` | `/vendor/etc/selinux/` | 950,003 | ✅ |
| `vendor_sepolicy.cil` | `/vendor/etc/selinux/` | 981,335 | ✅ |
| `system_ext_sepolicy.cil` | `/system_ext/etc/selinux/` | 437,972 | ❌ **初版遗漏** |
| `product_sepolicy.cil` | `/product/etc/selinux/` | 37,176 | ❌ **初版遗漏** |

⇒ **§2–§12 的所有计数都是"3 份策略"口径，已在 §2.3 更新为 5 份。**

### 13.1 重跑后新增的 3 条规则（全部经 `domain` 属性继承，不在本域 direct 集合内）

| 目标 | 类 | 权限 | 影响 |
|---|---|---|---|
| `svelte_log_device` | `chr_file` | `append lock map open write` | 可写一个日志型字符设备，仅"写日志"，不构成面 |
| `vendor_exported_odm_prop` | `file` | `getattr map open read` | 只读属性类型 |
| `vendor_exported_system_prop` | `file` | `getattr map open read` | 只读属性类型 |

### 13.2 关键否定在 5 份策略下重新验证（结论不变）

| 判定 | 3 份口径 | **5 份口径** |
|---|---|---|
| 可写类型上持有 `execute` 的规则数 | 0 | **0**（含属性目标展开） |
| 本域可执行文件类型数 | 9 | **9**（同一集合） |
| 可 exec 类型能触发的域转换 | 仅 `crash_dump` | **仅 `crash_dump`** |
| `filesystem` 类权限 | 仅 `getattr` | **仅 `getattr`** |
| 属性可写类型 | 仅 `vendor_oppo_prop` | **仅 `vendor_oppo_prop`** |

⇒ §1 的"无逃逸"结论**不因补全策略而改变**，但计数、属性数量与"我还漏了什么"的答案变了。

### 13.3 方法论教训

**"策略全集"必须从 `precompiled_sepolicy` 的 sha256 清单反推，而不是从常见路径猜。**
本次是因为一个类型名在 CIL 里查不到、却在二进制策略里查得到，才暴露出缺件；
如果那个类型名恰好与我关心的问题无关，这个缺口会一直沉默。
下一轮凡涉及"某域能做什么"，先 `ls /odm/etc/selinux/*.sha256` 对账。
