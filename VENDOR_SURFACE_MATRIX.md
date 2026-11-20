# VENDOR_SURFACE_MATRIX：vendor 内核模块"按真实加载状态 + 权限可达性"分诊

> 日期：2026-11-20  
> 承接：`docs_archive/审核意见CHATGPT-v0132.txt` 五、P3（"剩余 vendor 模块按可达性挑选，不做无差别逆向"）  
> 目标机：OPPO K3 / PCGM00 / SDM710 / Android 11 / `4.9.227-perf+`  
> 性质：**纯离线**。只用 `vendor.img`（ext4 镜像）、`/proc/modules` 等既存设备取证文本、内核源码树与 SELinux CIL；**未连接设备、未上机、未写设备任何分区、未改 `HANDOVER.md`/`README.md`/`CLOSURE.md`/`HANDOVER_RESUME.md`**。  
> 本文是**分诊**，不含漏洞结论；**不改变四层判定（可用 root / 持久 ROOT = NO-GO）**。  
> 与 WLAN 主线的关系：WLAN 只占一行"仅记录"，不重做 R1，不抢优先级。

---

## 0. 结论先行

1. **实际加载 32 个模块**（`/proc/modules` 32 行，取证级）；`/vendor/lib/modules/` 目录内共 **37** 个 `.ko` ⇒ **5 个在目录里但没加载**（`rdbg`、`llcc_perfmon`、`mpq-adapter`、`mpq-dmx-hw-plugin`、`audio_tfa98xx`）。审核 v0132 提醒的"目录里有文件 ≠ 已加载"在本机成立。
2. **同时满足"真实加载 + 有用户态输入面 + 当前 shell 或受限 UID 0 代理 DAC/SELinux 皆可达"的模块 = 0 个。** 因此本轮 P3 **不产生"可进入 R3 的新面"**，只产生一张"距门槛还有几道门"的观测名单。
3. 最接近门槛的是 **`tfa98xx_v6_dlkm`**：出厂 `.ko` 在 `/proc/<name>-<addr>/` 下建了 **4 个 0666 入口**（`OTC`/`MTPEX`/`TEMP`/`calibrate`，其中 3 个带写 handler），DAC 对全局开放；对我们这两个主体，唯一挡路的是 SELinux 对通用 `proc` 类型**没有给 shell / `oplus_wifi_service` 任何 file allow**（各 0 条；但 `hal_audio_default` 等 21 个域有，见 §5 末注）。
4. 入口"最值钱"的是 **`dspg_dbmdx_dlkm`**：独立字符设备 + `read/write` + sysfs `acoustic_model` 写入（`dbmdx_va_amodel_update`，4.9 KB 解析器）；但节点无 ueventd 条目（默认 0600，推断），只有 uid 0 域过 DAC，仍被 SELinux 单门挡住。
5. **一个必须写进下一轮前提的方法学事实**：`.build/vendor_kernel_full` 的 `tfa98xx.c` **与出厂 `audio_tfa98xx-v6.ko` 不同源**——源码里是 debugfs（`S_IWUGO`），出厂 `.ko` 里**没有 debugfs**（0 个 `debugfs_create_*` 导入、无 `debugfs` 字符串），改成了 `/proc` + `proc_create_data(mode=0666)`。**源码级结论不得直接迁移到 `.ko`。**

---

## 1. 物料、方法与标注体系

### 1.1 物料（全部只读，哈希见附录 A）

| 物料 | 路径 | 用途 | 级别 |
|---|---|---|---|
| 出厂模块 37 个 | `.build/vendor/vendor.img` → `lib/modules/*.ko` | 接口存在性、`file_operations`、`proc_create_data` 的 mode | 取证级（出厂二进制） |
| 启动加载清单 | `vendor_ko/modules.load`（37 行）、`modules.dep` | 与运行态对账 | 取证级 |
| 设备运行态 | `artifacts_adb/k3_info2.txt` §4（`/proc/modules`）、§3（SELinux）、§11（可访问 `/dev`）、§12（debugfs 挂载）；`artifacts_adb/k3_info.txt`（slab）；`artifacts_adb/surface_probe_output.txt`（uid 2000 的 `/dev` 198 项探测） | 谁真的加载了、谁真的能打开 | 取证级 |
| 设备节点权限 | `vendor.img` 根 `ueventd.rc` | 每个 `/dev` 节点的 mode/uid/gid | 取证级 |
| SELinux | `.build/sepolicy/{vendor,plat,plat_pub_versioned,system_ext,product}_sepolicy.cil`、`vendor_file_contexts`、`plat_file_contexts` | `allow` / `genfscon` / 标签 | 取证级 |
| 内核源码 | `.build/vendor_kernel_full/` | 语义参照（**不是**出厂 .ko 的构建源，见 §1.3） | 源码级 |

### 1.2 标注约定

- **取证级**：来自设备运行态取证文本，或来自出厂镜像内的二进制（哈希可复算）；可直接作为事实。
- **源码级**：只能说明"这条代码路径长什么样"，**不能**证明该路径在出厂 `.ko` 里存在（§1.3 已出现反例）。
- **推断**：由 AOSP 默认行为或命名规则推得，未经本机核实；每条都在 §6 列出对应的只读核验动作。

### 1.3 关键方法学警告：源码树 ≠ 出厂二进制

以 `audio_tfa98xx-v6.ko` 为例（三个互相独立的观测）：

| 观测 | 源码树 `sound/soc/codecs/tfa98xx.c` | 出厂 `audio_tfa98xx-v6.ko` |
|---|---|---|
| debugfs | 有：`debugfs_create_dir` + 9 个文件，`S_IWUGO`（源码 878–903 行） | **无**：导入表 0 个 `debugfs_create_*`，全二进制无 `debugfs` 字符串 |
| procfs | 无 | **有**：`proc_mkdir` + `proc_create_data` **×14**（`tfa98xx_i2c_probe`，`.text+0x5944`–`0x5bfc`；其中 1 项仅在 FTM boot 下注册） |
| 符号 | 无 `ftm_mode` 全局 | **有**：`ftm_mode`（`.bss`，`STB_GLOBAL`）+ 导入 `get_boot_mode` |

⇒ 本文所有"入口存在"的判定以 **`.ko` 二进制**为准（取证级），源码只用于解释语义（源码级）。WLAN 之外**没有任何一个模块**能只靠源码定稿。

---

## 2. 实际加载枚举（取证级）

### 2.1 口径

`/proc/modules`（`artifacts_adb/k3_info2.txt:1093–1124`）共 **32 行**，每行都是 `name size refcount deps - Live 0x0 (O)` 形态（`Live` 是"已加载"标记，地址被 kptr_restrict 清零，与可达性无关）。32 个名字全部能在 `modules.load` 37 项中一一对上（映射表 `artifacts_adb/vendor_triage/loaded_map.tsv`，**观测映射而非命名规则**——`audio_machine_sdm710.ko → machine_dlkm` 就是规则外的一例）。

### 2.2 加载 / 未加载

| 状态 | 数量 | 模块 |
|---|---|---|
| **已加载** | **32** | `wlan`, `apr_dlkm`, `wglink_dlkm`, `q6_pdr_dlkm`, `q6_notifier_dlkm`, `adsp_loader_dlkm`, `q6_dlkm`, `usf_dlkm`, `pinctrl_wcd_dlkm`, `pinctrl_lpi_dlkm`, `swr_dlkm`, `wcd_core_dlkm`, `swr_ctrl_dlkm`, `wsa881x_dlkm`, `platform_dlkm`, `cpe_lsm_dlkm`, `hdmi_dlkm`, `stub_dlkm`, `wcd9xxx_dlkm`, `mbhc_dlkm`, `wcd_spi_dlkm`, `wcd_cpe_dlkm`, `wcd9335_dlkm`, `wcd934x_dlkm`, `digital_cdc_dlkm`, `analog_cdc_dlkm`, `msm_sdw_dlkm`, `native_dlkm`, `machine_dlkm`, `tfa98xx_v6_dlkm`, `ak4376_dlkm`, `dspg_dbmdx_dlkm` |
| **目录有、未加载** | **5** | `llcc_perfmon`（sysfs 属性）、`mpq-adapter` / `mpq-dmx-hw-plugin`（DVB 解复用）、`audio_tfa98xx`（被 `-v6` 取代）、`rdbg`（调试字符设备） |

旁证（同一开机）：`/proc/slabinfo` 有 `tfa98xx_cache`（`k3_info.txt:117`）⇒ `tfa98xx_v6_dlkm` 的 probe 真的跑过、真的占了对象，不只是"insmod 成功"。`platform_dlkm` refcount **53**、`q6_dlkm` **11**、`wcd_core_dlkm` **8** ⇒ 音频栈在运行态被高频使用。

### 2.3 版本匹配（一次全量核对）

37 个 `.ko` 的 `vermagic` **全部**为 `4.9.227-perf+ SMP preempt mod_unload modversions aarch64` ⇒ 与运行内核一致，**"版本不符所以加载失败"这一解释被排除**。

5 个未加载的模块**都列在 `modules.load` 里、却不在 `/proc/modules`**：可能是 init 只对清单子集执行 `insmod`、也可能 `insmod` 失败被忽略、也可能加载后被 `rmmod`。**是哪一种，本轮未取证（init 脚本未读），标推断**；`audio_tfa98xx.ko` 与 `audio_tfa98xx-v6.ko` 同时在清单里而只有 `-v6` 在运行态，是这条"清单≠实际加载"的最直接例子（两条 `insmod` 同名符号冲突时会互斥，但未证实）。

### 2.4 本机可达主体（决定后面所有判定）

| 主体 | uid / 域 | capability（实测/策略） | 来源 |
|---|---|---|---|
| shell | 2000 / `u:r:shell:s0` | 常规 shell 集合，无 CAP_SYS_ADMIN / CAP_DAC_OVERRIDE | `k3_info2:1091`；`HANDOVER §60.2` |
| 受限 UID 0 代理 | 0 / `u:r:oplus_wifi_service:s0` | `CapEff=0x13000` = NET_ADMIN + NET_RAW + **SYS_MODULE**（策略另含 sys_admin，但 CapBnd 无 ⇒ 提不上） | `HANDOVER §24.9 V1`；`vendor_sepolicy.cil:5605` |

**判定用的三件事**：DAC（`ueventd.rc` 的 mode/uid/gid + 内核默认）、SELinux（`allow` 是否存在）、capability。三者必须**同时**满足才算"可达"。

---

## 3. 筛选判据（三合一，缺一即淘汰）

模块进入下一轮，必须同时满足：

- **F1 真实加载**：`/proc/modules` 中出现（取证级）。→ **32/37 通过**（含 WLAN）。
- **F2 有用户态输入面**：`file_operations`（字符设备 / procfs / debugfs）、`sysfs` 属性、netlink、netdev ioctl、`ioctl` handler。→ 见 §4。
- **F3 本机可达**：上面两个主体中至少一个，**DAC 能打开** 且 **SELinux 有 allow**（capability 仅对需要 `CAP_NET_ADMIN` 的 wlan0 面起作用）。

**F3 的空集证据**（全部为"0 匹配"式否定，可复算，见附录 B）：

| 类型 | shell | `oplus_wifi_service` |
|---|---|---|
| `audio_device`（`/dev/msm_*`、`/dev/snd`、`/dev/wcd-dsp-glink`） | 0 | 0 |
| `dbmdx_ch_device`（`/dev/dbmdx*`） | 0 | 0 |
| `debugfs`（裸 `debugfs` 类型） | 0（只有 `debugfs_tracing`） | 0（只有 `vendor_debugfs_wlan`，且仅 `dir search`） |
| `proc`（通用 proc 文件） | 0（只有 `filesystem getattr` / `lnk_file getattr`） | 0 |
| `sysfs`（文件写） | 0（只有 `dir` 读 + `search`，`plat_sepolicy.cil:13600`） | 0（只有 `sysfs_wlan_con_mode`，`vendor_sepolicy.cil:5628`） |
| `device`（无标签节点的兜底类型） | 0（只有 `dir getattr`，`plat_sepolicy.cil:13593`） | 0 |

补充：`(allow domain debugfs (dir (search)))`（`plat_sepolicy.cil:6803`）意味着**所有域**都能穿过 `/sys/kernel/debug` 根目录，但仅 `search` 不授予任何 file 权限；裸 `debugfs` 的 `file open/write` 全策略只给 **`init`**（`vendor_sepolicy.cil:5248`，读另给 `dumpstate`）。`oplus_wifi_service` 的 allow 共 **50 条**（`vendor_sepolicy.cil:3941–5640`），逐条看过：除 `sysfs_wlan_con_mode`（写）与 `vendor_debugfs_wlan`（仅 `dir search`）这两个 WLAN 专属面之外，**没有任何**音频 / 字符设备 / 通用 sysfs / 通用 debugfs 的允许。

---

## 4. 分诊矩阵（8 行；判定 ∈ {进入下轮, 仅记录, 关闭}）

> 列 `门` 的读法：`DAC → SELinux → cap`。`✗` 表示该道门不过，并在括号内给出"缺哪一条 allow / 哪个 mode"。  
> 所有行都**不满足 F1+F2+F3 三合一**；本表的目的是记录"还差几道门"。

| # | 模块（加载证据） | 用户态输入面 | 入口函数（符号，来自 `.ko`） | 参数可控性 | 权限门（DAC + SELinux + cap，含 CIL 行） | 判定 |
|---|---|---|---|---|---|---|
| 1 | **`wlan`**（`qca_cld3_wlan.ko`，`k3_info2:1093`，refcount 0） | netdev ioctl `0x89f1`/`0x89fd`；cfg80211；logging chrdev；debugfs wow 图案 | `hdd_ioctl` / `hdd_driver_command` / `wlan_ioctl_ftm_testmode_cmd` | 16 B 结构（`0x89f1`）或 ≤`0x800`（FTM） | shell：无 wlan0 / 无 NET_ADMIN ✗；uid0 代理：**域满足**（NET_ADMIN，`vendor_sepolicy.cil:5605`）；debugfs：`vendor_debugfs_wlan` 仅 `dir search`（`:5637`）✗ | **仅记录**（WLAN 主线已由 `WLAN_IOCTL_CHAIN_AUDIT.md` 接管，本轮不重做、不抢优先级） |
| 2 | **`tfa98xx_v6_dlkm`**（`audio_tfa98xx-v6.ko`，`k3_info2:1097`；slab `tfa98xx_cache`） | **`/proc/<i2c名>-<addr>/`**：`OTC`(0666) `MTPEX`(0666) `TEMP`(0666) `calibrate`(0666) `R`/`range`/`r_aging`/`r_impedance`/`version`/`dsp-state`/`fw-state`/`rpc`(0444) `pga_gain`(0444)；`ftm_tfa98xx`(0644，仅 FTM boot) | `tfa98xx_i2c_probe`（`proc_mkdir` + `proc_create_data`×14）；写：`tfa98xx_dbgfs_start_set`（`calibrate`）、`simple_attr_write`（`OTC`/`TEMP`）；读：`tfa98xx_dbgfs_mtpex_get` 等 | `OTC`/`TEMP`=整型标量（`simple_attr`）；`calibrate`=**长度门 `count-20 ∈ {0,1,2}`**（`sub x11,x19,#0x14; cmp x11,#2; b.hi` 拒绝）+ `__check_object_size` + `copy_from_user` + `strncmp("please calibrate now")`；其余 0444 只读 | **DAC 可写**（0666，目录 0755 root，`k3_info2:1190`；0444 项所有者是 root 且两主体均无 `CAP_DAC_OVERRIDE` ⇒ 只可读）→ **SELinux ✗**：`/proc` 无专属标签（`genfscon proc /`，`plat_sepolicy.cil:272`）⇒ 类型 `proc`；shell 0 条 file allow，`oplus_wifi_service` 0 条。**注意：门不是对所有人关**——持 `proc:file write` 的有 21 个域（`hal_audio_default`、`hal_camera_default`、`hal_fingerprint_oppo`、`init`、`qti_init_shell`、`vendor_autochmod`…），即系统内真实消费者可达，**只是不在本工程的两个主体里**。cap 无关 | **仅记录**（门槛最短；但入口是标量/有界字符串，暂无"可检验内存不变量"） |
| 3 | **`dspg_dbmdx_dlkm`**（`audio_dspg_dbmdx.ko`，`k3_info2:1094`，refcount 0） | 字符设备 `/dev/dbmdx*`（`misc_register`+`cdev_add`+`device_create`）；`read`/`write`（`__kfifo_to_user`）；sysfs `sysfs_create_group`×3（含 `acoustic_model`）；`request_firmware` 语音模型 | `dbmdx_platform_probe` / `dbmdx_register_cdev` / `dbmdx_dev_read` / `dbmdx_dev_write` / `dbmdx_va_amodel_update`(4924 B 解析器) | `write(count,buf)` 直入；sysfs store 走 `dbmdx_va_acoustic_model_store` → 二进制模型解析（**上界未量化，下一轮才谈**） | **DAC 推断 0600 root**（`ueventd.rc` 无 `/dev/dbmdx` 条目 ⇒ AOSP 默认）⇒ shell ✗、uid0 代理 ✓（uid 0）→ **SELinux ✗**：节点标签 `dbmdx_ch_device`（`vendor_file_contexts:582`），全策略只有 `hal_audio_default` 有 `chr_file (read write open)`（`vendor_sepolicy.cil:4166`）；我们两个域 0 条 | **仅记录**（唯一"二级二进制解析器"候选；2 门/1 门，取决于节点是否真存在） |
| 4 | **`platform_dlkm`**（`audio_platform.ko`，`k3_info2:1117`，refcount **53**） | `audio_device` 字符节点族 ioctl：`msm_pcm_ioctl` / `msm_pcm_hwdep_ioctl` / `msm_lsm_ioctl`（+compat） | 同上 | ioctl `cmd` + `arg` 指针，逐 cmd 解析（未量化） | **DAC ✗**：`/dev/msm_*`→`audio_device`（`vendor_file_contexts:579`）、`/dev/snd`→`audio_device`（`plat_file_contexts:82`），`ueventd.rc` 0660 system:audio ⇒ shell(uid2000, gid 2000) 打不开；uid0 ✓ → **SELinux ✗**：`audio_device` 对两个域均 0 条（有 allow 的是 `audiod`(:7328)/`hal_audio_*`/`factory`/`vendor_audioftm`） | **仅记录**（两门；本工程没有 audio 域） |
| 5 | **`native_dlkm`**（`audio_native.ko`，`k3_info2:1116`） | `/dev/msm_aac` 等 PCM 节点 + `audio_in_ioctl` / `aac_in_ioctl` / `audio_aio_ioctl` + debugfs | 同上 | ioctl + mmap 缓冲（未量化） | 同 #4：DAC ✗（0660 system:audio）；SELinux ✗（`audio_device` 0 条） | **仅记录** |
| 6 | **`q6_dlkm`**（`audio_q6.ko`，`k3_info2:1119`，refcount 11） | `audio_cal_ioctl` / `rtac_ioctl` / `avtimer_ioctl`；chrdev+device_create；debugfs | 同上 | ioctl `cmd`+`arg`（校准块/RTAC 结构，未量化） | 同 #4（节点族 `audio_device`） | **仅记录** |
| 7 | **`usf_dlkm`**（`audio_usf.ko`，`k3_info2:1118`） | `/dev/usf1`（`ueventd.rc`：`0660 system system`）+ `usf_ioctl` + input device | `usf_ioctl` / `q6usm_read` / `q6usm_write` | ioctl + read/write（未量化） | **DAC ✗**（0660 system:system，shell 打不开；uid0 ✓）→ **SELinux ✗**：`/dev/usf` 无 `file_contexts` 条目 ⇒ 兜底类型 `device`，两个域 0 条 | **仅记录** |
| 8 | **`rdbg`**（`rdbg.ko`，**未加载**，`modules.load` 有） | `/dev/rdbgctl`（`class_create`+`cdev_add`+`device_create`），`read()` 取各子系统共享内存 dump | `rdbg_open` / `rdbg_read` / `rdbg_init` | `read(count,buf)`，`minor` 选 CPU 子系统 | **未加载**；加载后 DAC 推断 0600（无 ueventd 条目）、SELinux 兜底 `device` 0 条；"可加载"路径存在：`oplus_wifi_service` 有 `vendor_file: module_load`（`vendor_sepolicy.cil:5598`）+ SYS_MODULE（`:5605`），与 `HANDOVER §24.8 R4` 一致 | **关闭**（加载了也打不开；R4 已记录"只能加载既有 .ko"） |

### 4.1 其余 25 个已加载模块（WLAN 已在矩阵第 1 行）：按"输入面类型"归簇（不满足 F2 或直接 2 门）

| 簇 | 模块 | 用户态面 | 为什么只记录 |
|---|---|---|---|
| debugfs-only | `apr_dlkm`、`wcd_core_dlkm`、`wcd9xxx_dlkm`、`wcd_cpe_dlkm`、`wcd_spi_dlkm`、`swr_ctrl_dlkm`、`wcd934x_dlkm`、`wsa881x_dlkm` | `debugfs_create_dir/file`（`wcd9xxx` 还有 `wcdcal_hwdep_ioctl`，经 `/dev/snd/hwC*`） | `debugfs` 文件默认 root 属主 ⇒ shell 不过 DAC、uid0 代理过 DAC；两者都不过 SELinux（裸 `debugfs` 的 `file write/open` 只给 `init`，`vendor_sepolicy.cil:5248`）⇒ shell 侧 2 门 / 代理侧 1 门；hwdep 面同 `audio_device` ⇒ 2 门 |
| `audio_device` 字符节点（非矩阵行） | `wglink_dlkm`（`/dev/wcd-dsp-glink`，`chrdev`+`device_create`） | 只做 GLINK 通道的建节点与转发，无自己的 ioctl 面 | 节点标签 `audio_device`（`vendor_file_contexts:1171`）+ `ueventd.rc` 0660 system:audio ⇒ 与 #4 同两道门 |
| ALSA kcontrol-only | `ak4376_dlkm`、`analog_cdc_dlkm`、`digital_cdc_dlkm`、`hdmi_dlkm`、`msm_sdw_dlkm`、`wcd9335_dlkm`、`stub_dlkm`、`machine_dlkm` | 仅 `snd_soc_register_codec/component`（mixer 控件） | 无独立节点；控件只能经 `/dev/snd/controlC*`（`audio_device`）⇒ `tinyalsa`/`tinymix` 路径，2 门 |
| 控制面/无独立入口 | `q6_pdr_dlkm`、`q6_notifier_dlkm`、`swr_dlkm`、`pinctrl_wcd_dlkm`、`pinctrl_lpi_dlkm`、`mbhc_dlkm`、`cpe_lsm_dlkm` | 无自身 `file_operations`；`cpe_lsm` 的 `msm_cpe_lsm_ioctl` 挂在 LSM 前端（平台侧节点） | 只有"符号"没有"入口"；F2 不成立（`cpe_lsm` 的入口属于 #4 的节点族） |
| sysfs-only | `adsp_loader_dlkm` | sysfs attributes（固件加载状态） | 属性默认 0644 root；SELinux `sysfs` 写对两个域 0 条 |

> 说明：`modules.load` 的 37 项里，`llcc_perfmon`（sysfs group）、`mpq-adapter`（1 个参数）、`mpq-dmx-hw-plugin`（debugfs，12 个参数）、`audio_tfa98xx`（非 v6）同样**未加载**，已并入 §2.2，不再单列。

---

## 5. 门槛距离排序（给下一轮的"观察名单"，不是"进入下轮"）

> "门数"按**最好的主体**计（受限 UID 0 代理）；同一行对 shell 通常多一道 DAC（因为 shell 没有 `CAP_DAC_OVERRIDE`，且不在 `audio`/`system` 组）。

| 距可达 | 模块 | 还差什么 | 若门开了，能做什么 |
|---|---|---|---|
| **1 门（SELinux），入口强** | `dspg_dbmdx_dlkm` | 一条 `(allow <可达域> dbmdx_ch_device (chr_file (open read write)))`；若走 sysfs 则一条 `sysfs` 文件写 | 向语音触发 DSP 投递二进制声学模型（`dbmdx_va_amodel_update` 4.9 KB 解析器）→ 才有"长度/对象身份/生命周期"可审 |
| **1 门（SELinux），入口弱** | `tfa98xx_v6_dlkm` | 一条 `(allow <可达域> proc (file (open read write)))` | 触发功放校准 / 写 `OTC`、`TEMP` 标量 / 打 `calibrate` 魔法串；**不构成内存腐坏面** |
| 2 门（DAC + SELinux） | `platform_dlkm`、`native_dlkm`、`q6_dlkm`、`wcd9xxx_dlkm`、`wcd_core_dlkm`… | 先要有能打开 `0660 system:audio` 的域（本工程没有） | 音频 ioctl 面（最大的一块，`platform_dlkm` refcount 53） |
| 未加载 | `rdbg`、`llcc_perfmon`、`mpq-*` | 先证明"加载"这一步值得（R4 已定"不构成新面"） | rdbg 可读各子系统共享内存 dump；但节点兜底 `device` 类型 0 allow |

**结论**：观察名单 = `dspg_dbmdx_dlkm`（首选）> `tfa98xx_v6_dlkm`（次选）> `audio_device` 簇（记录）。**没有模块进入下一轮**，因为"门"不在模块侧，而在策略侧；在策略不改、域不变的前提下，继续逆向这些模块的解析器**不会产生本机可达结论**。

> **必须同时记住的另一面**：这些门**不是"对所有人关闭"**。`hal_audio_default`（音频 HAL）同时持有 `dbmdx_ch_device:chr_file(read/write/open)`（`vendor_sepolicy.cil:4166`）与 `proc_30_0:file(write)`，即 **DBMDX 字符设备与 tfa98xx 的 0666 `/proc` 项在系统内确有合法消费者**。本工程的"0 个可达"是**我们两个主体**的结论，不是"这些面在本机不存在"的结论。shell → 音频 HAL 的 Binder 间接路径本轮**未评估**，见 §6.1。

---

## 6. 明确未覆盖

### 6.1 没有取证的（本轮不猜）

| 项 | 现状 | 需要什么 |
|---|---|---|
| `/dev/dbmdx*` 是否存在、真实 mode/uid/gid | 只有"`device_create` 在 probe 里"+"`ueventd.rc` 无条目"⇒ 推断 0600 | 上机 `ls -lZ /dev/dbmdx*`（只读） |
| `/proc/<tfa98xx 目录名>` 的真实名字与项 | 目录名 = `<i2c client name>-<addr>`，运行时决定；`i2c->name` 未在本机取证 | 上机 `ls -ldZ /proc/*tfa*`（只读） |
| `/sys/kernel/debug` 下是否有 `apr`/`wcd9xxx` 等目录 | debugfs 已挂载（`k3_info2:1186`），目录未列 | 上机 `ls /sys/kernel/debug`（只读） |
| `/dev/msm_*`、`/dev/snd/*` 的完整清单 | `surface_probe` 只列了"shell 可打开的 12 个"，音频节点**必然不可打开**但"是否存在"未列 | 上机 `ls -l /dev`（只读） |
| `audio_tfa98xx.ko`（非 v6）为何未加载 | 清单有、运行态无；init 脚本未取证 | 读 `/vendor/etc/init/*.rc` 的 insmod 行（离线可做，vendor.img 内） |
| shell → 音频 HAL（`hal_audio_default`）的 Binder 间接路径 | 未评估。该域同时持有 `proc:file write` 与 `dbmdx_ch_device`，是 §4/#2、#3 两个面的**真实消费者** | 若要沿用 WLAN 的"shell → Binder → 受限域"范式，这里是唯一同类候选；需先做 `hwservice_manager` 可达性 + 接口描述符取证（参照 `HANDOVER §11`、`§23`） |

### 6.2 只有符号、没有入口的（F2 不成立）

`q6_pdr_dlkm`、`q6_notifier_dlkm`、`swr_dlkm`、`pinctrl_wcd_dlkm`、`pinctrl_lpi_dlkm`、`mbhc_dlkm`、`machine_dlkm`：`file_operations`/`sysfs`/`netlink` 全无，只有 platform driver 的 probe 与 ALSA 组件注册。**"有符号"不是"有入口"**，本轮不为其排期。

### 6.3 需要上机只读核验的（一次性、零写入，需授权）

1. `ls -lZ /dev/dbmdx* /dev/usf1 /dev/msm_* /dev/snd/*`（确认存在性与 DAC/标签）
2. `ls -ldZ /proc/*tfa*`（确认 tfa98xx proc 目录名与 mode）
3. `ls -l /sys/kernel/debug` + `ls -l /sys/kernel/debug/<名字>`（确认 debugfs 面）
4. `/proc/modules` 复核（确认 32 行的稳定性；本轮用的是 `k3_info2.txt` 既有取证）
5. `cat /proc/cmdline`（确认是否 FTM boot ⇒ 决定 `ftm_tfa98xx` 那 0644 项是否存在）

> 以上 5 条都只读，不写设备、不重载模块；**未获授权前不执行**。

---

## 7. 与项目四层判定 / WLAN 主线的关系

1. **不改变判定**：本文没有产生任何"本机可达新面"，更没有产生新的域或地址源。可用 ROOT / 持久 ROOT 维持 **NO-GO**。
2. **不与 WLAN 抢优先级**：WLAN 主线在 v13.2 已推进到调用链审计——`0x89f1` 的真实用户态消费者是 `wpa_supplicant` 的 `android_priv_cmd` 通道，`/odm/bin/iwpriv` 只走 WEXT 私有区间 `0x8BE0..0x8BFF`（`WLAN_IOCTL_CHAIN_AUDIT.md` §0，对审核 v0132 候选 A 的更正）。本文对 WLAN 只做"已加载 + 主线"的登记，**不复述、不推翻该审计**。
3. **对 R2（模块依赖图）的输入**：37 个模块的加载态与接口簇已表格化（§2.2、§4.1），R2 可直接用 `loaded_map.tsv` + `ko_surface_all.json` 起步，不需要再扫一遍目录。
4. **对审核 v0132 的回应**：P3 的"模块筛选 → 权限判定 → 输入面定位"三步已完成；"安全不变量审计"一步**没有对象可审**（F3 空集），故按"只深入高价值、真实可达的模块"的要求**停在这里**，而不是对所有音频模块做无差别逆向。

---

## 8. 下一轮建议（按成本排序，均需授权）

| 序 | 动作 | 成本 | 产出/停止条件 |
|---|---|---|---|
| 1 | 上机只读核验 §6.3 的 5 条 | 一次只读事务 | 若 `/dev/dbmdx*` 存在且为 0600 ⇒ `dspg_dbmdx` 升为"1 门"；若 tfa98xx 的 `/proc` 目录含 0666 项 ⇒ 与本文一致，判据闭环 |
| 2 | 离线读 `vendor.img` 内 `etc/init/*.rc`，定位 37 个 `.ko` 的 insmod 行与 `chmod/chown` | 纯离线 | 回答"为何 `audio_tfa98xx` 未加载"+"是否有节点被 init 二次 chmod" |
| 3 | **不**建议：对 `audio_device` 簇做解析器审计 | — | 域不存在（无 audio 域可达），审了也不可达 |

---

## 附录 A：物料哈希（SHA-256，均可复算）

```
39bad4dfb6fec4806fdaf53e7f48ac2f9c21759e5b419a50e3bc708f559fbb95  .build/vendor/vendor.img (2,248,146,944 B)
6e19ee92f3204591f638c21146d71c392310048c23217fc85d933baf2e08277c  vendor_ko/modules.load      (与 R1 附录一致)
53047ee9ea9697352deb3a7c88907803c7178933035bce1d53947f63b56e4de4  vendor_ko/modules.dep       (与 R1 附录一致)
f45c1c1cf63281ee5e64c8b6149c42d5e1aaa91142913073668abf1901674d00  vendor_ko/qca_cld3_wlan.ko  (与 R1 附录一致)
fdcc00f6ae92d182e70bcb579ccb735531f7eda20fccb5acef9fd37e3c4581b2  lib/modules/audio_tfa98xx-v6.ko   (374,558 B)
acf6685850e323c80c6b85a0427ec22367744474f760ed09e730dd94227d9a48  lib/modules/audio_dspg_dbmdx.ko   (513,022 B)
af986ceeb634af60b1786b6e15827842dd72283ce133538173ebc3cfa38e915c  lib/modules/audio_apr.ko           (72,814 B)
5b5c30ea36918786516263359f7984a2f6df9c0758c026faa5705d880ab65a0f  lib/modules/rdbg.ko               (24,126 B)
```

37 个 `.ko` 的逐文件大小/哈希/vermagic 见 `artifacts_adb/vendor_triage/ko_hashes.tsv`（本轮生成，全量 24.4 MB）；其中被本文单独引用的 4 个如上。

## 附录 B：复跑命令

```powershell
# 1) 从出厂镜像取模块（7-Zip 直接读 ext4，不挂载）
& 'C:\Program Files\7-Zip\7z.exe' x .build\vendor\vendor.img -oartifacts_adb\vendor_triage\_img 'lib\modules\*.ko' 'ueventd.rc' -y

# 2) 加载态对账（/proc/modules 32 行 vs modules.load 37 行）
python artifacts_adb\vendor_triage\loaded_map.py

# 3) 全模块接口面分类（file_operations / sysfs / debugfs / netlink / proc / input / alsa）
python artifacts_adb\vendor_triage\ko_classify.py

# 4) tfa98xx 的 /proc 注册点（证明 0666 + 项名 + fops）
python artifacts_adb\vendor_triage\dis_win.py artifacts_adb\vendor_triage\_img\lib\modules\audio_tfa98xx-v6.ko 5900 5c20
python artifacts_adb\vendor_triage\fops.py artifacts_adb\vendor_triage\_img\lib\modules\audio_tfa98xx-v6.ko 778 868 958 a48 b38

# 5) 空集证据（各应为 0 行）
Select-String -Path .build\sepolicy\*.cil -Pattern '^\(allow (shell|shell_30_0|oplus_wifi_service) (audio_device|audio_device_30_0|dbmdx_ch_device|debugfs|proc) '
```

## 附录 C：中间产物（本地，勿入库）

| 文件 | 内容 |
|---|---|
| `artifacts_adb/vendor_triage/_img/` | 37 个出厂 `.ko` + `ueventd.rc`（24 MB，厂商二进制） |
| `artifacts_adb/vendor_triage/ko_hashes.tsv` | 37 个 `.ko` 的大小 / SHA-256 / vermagic |
| `artifacts_adb/vendor_triage/loaded_map.tsv` | 32 加载 / 5 未加载的逐行对账 |
| `artifacts_adb/vendor_triage/ko_surface_all.json` | 37 个模块的接口面分类 + init 直接调用 |
| `artifacts_adb/vendor_triage/ko_surface_1.json` / `_2.json` | 8 个候选模块的 init 调用链与名字候选 |
| `artifacts_adb/vendor_triage/{ko_surface,ko_classify,loaded_map,fops,dis_win}.py` | 可复跑脚本（pyelftools + capstone） |

