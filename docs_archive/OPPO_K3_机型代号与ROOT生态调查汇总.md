# OPPO K3 机型代号、官方固件与 ROOT 生态调查汇总

> **版本失效声明（2026-11-13，依据实机 ADB 复核）**
> 本文的机型标识核验、GitHub 生态检索与官方 A/C 分支版本线仍具参考价值；但「国行最终版 = C.17」这一结论**对本机不成立**。实机 ADB 已确认设备运行 **PCGM00_11_F.16**（ColorOS 11.1 / Android 11 / 内核 4.9.227-perf+ / SPL 2022-04-05，构建 2025-03-26），F 分支经官方 `component-ota-cn.allawntech.com/update/v6` 通道下发，未收录于本文依据的官网固件页。
> 本文所有基于 C.17 的 boot/vbmeta 数值、SPL 与 root 路径推断**对本机作废**，仅保留作历史对照。
> 当前有效基线：`F16_基线_与C17结论失效说明.md`；当前固件镜像：`firmware_F16/`；获取与清理记录：`F16_固件获取与C17清理记录.md`。

- 调查日期：2026-11-12
- 调查范围：机型标识核验 → GitHub 全量 ROOT 项目检索 → 官方固件版本线 → 由版本反推 ROOT 可行性
- 证据等级说明：**【实】** 已由一手来源或实际拉取的仓库文件核验；**【源】** 来自公开网页/搜索引擎索引，未获一手核验；**【推】** 基于前述事实的推断，需进一步验证

---

## 0. 结论摘要

1. **机型标识**：国行全网通版 `PCGM00`、移动定制版 `PCGT00`、海外版 `CPH1955`；系统/内核层设备代号 `OP486B`（平台 `sdm710`）；官方宣传昵称「硬核少年」。【实】
2. **最终固件**：国行官方最终版为 **正式版 C.17**（ColorOS 7 / Android 10，2021-10-29），此后官网无更新；海外 CPH1955 最晚可确认构建为 `CPH1955_11_F.13_2021112222502506`（2021-11-22）。【实/源】
3. **GitHub 上「有」ROOT 相关项目，但没有 K3 专属的成熟一键 root 方案**。实质内容是 2019 年的固件 dump / TWRP 设备树 / boot.img 工具链碎片，以及同平台 realme X（RMX1901）的一键 root 与 NetHunter 内核项目。【实】
4. **核心矛盾是版本断层**：GitHub 可得资源全部对应 2019 年 Android 9（A.01–A.04），官方固件最终走到 2021 年 Android 10（C.17），跨一个大版本；对 7 个最终版构建号做 GitHub 代码检索，命中数全部为 0。【实】
5. **第二重矛盾是地域错配**：唯一有官方 BL 解锁资格的是中国大陆版 PCGM00（需「深度测试」APK 审核），而 GitHub 上唯一的 TWRP 设备树却是海外 CPH1955 版，二者无法对接。【源/推】
6. 由此判断：在最终固件 C.17 上获取 root 的可行路径只剩「深度测试解锁 BL → 提取同版本 C.17 的 boot.img → Magisk 补丁 → fastboot 刷入」，且深度测试本身可能要求降级到早期指定版本申请。【推】

---

## 1. 机型标识核验

### 1.1 官方机型编号（Model Number）

| 版本 | 型号 | 依据 |
|---|---|---|
| 国行全网通版 | `PCGM00` | 工信部入网信息、GeekBench 跑分库（型号 OPPO PCGM00，骁龙 710，8GB，Android 9）、人民法院诉讼资产网拍卖公告（「名称 OPPO K3，型号 PCGM00」）、电信天翼终端平台 |
| 国行移动定制版 | `PCGT00` | ROMProvider 国行型号对照表、GSMchoice「其他名称 PCGM00, PCGT00」、GitHub 机型数据库条目 |
| 海外版 | `CPH1955` | GitHub MobileModels 机型表、海外固件站构建号、第三方 ROM 开发组织 `oppo-k3` 命名 |

### 1.2 系统 / 内核层设备代号

- `OP486B`（小写 `op486b`），平台 `sdm710`。【实】
- 固件 `build.prop` 表现：`Device = OP486B`、`Model = CPH1955`、`Product = CPH1955`、`Platform = sdm710`（来源：CPH1955EX_11_A.04 固件 dump 信息，Security Patch 2019-10-05，Firm Date 2019-10-15）。【源】
- DevCheck 设备目录记录 codename `op486b`；Google Play Console 设备目录记录 Device code `OP486B`。【源】
- 该板级代号与 realme X（`RMX1901`）共平台：`oppo-k3/android_device_OPPO_CPH1955` 的 TWRP 树派生自 `mauronofrio/android_device_realme_RMX1901`，因此第三方 ROM / 设备树常互通。【实】

### 1.3 其他口径

- 官方宣传昵称：「硬核少年」（2019 年 5 月发布预热期），属营销称谓而非技术标识。【源】
- DevCheck 页面 URL 中的 `op4679`、GitHub `liuzho/ADN :: names/op4679/pcgt00.json` 中的 `op4679` 为另一套设备索引编号，非机型代号。【源】

### 1.4 现场核验方法

读取 `ro.product.model`（得到 PCGM00 / PCGT00 / CPH1955）与 `ro.product.device` / `ro.product.board`（得到 OP486B），结合 `ro.build.display.id` 判定具体固件版本，避免跨版本刷错镜像。

---

## 2. 官方固件版本线

### 2.1 国行 PCGM00 / PCGT00（权威来源：ColorOS 官网固件页）

- **最新版本：正式版 C.17**
  - ColorOS 版本 V7（ColorOS 7.x）／Android 10
  - 更新时间：2021-10-29，大小 3568.67 MB
  - MD5：`a6f5c1ec0e4b6c57b08f8207d8745a9e`
  - 更新日志：仅「[新增] 桌面增加全局搜索插件，提升搜索服务便捷性」
  - OTA 卡刷包：`PCGM00_11_OTA_2170_all_yu0AtmFTUqOG.ozip`【源】
  - 线刷包：`Oppo_K3_PCGM00_11_C.17_210909_RFT.zip`（4.60 GB，构建日期 2021-09-09，与官网推送日 2021-10-29 不同，属构建日 vs 推送日差异）【源】
- 官网列出 19 个历史版本，C.17 之后无任何条目，即 **截至 2026-11 已停止维护约 5 年**。【实】
- `PCGT00` 移动版无独立固件线，第三方固件站以「PCGM00 / PCGT00」合并包形式分发。【源】

**完整历史版本表（ColorOS 官网）**

| 版本 | 日期 | 大小 | 备注 |
|---|---|---|---|
| 正式版 C.17 | 2021-10-29 | 3568.67 MB | 最终版 |
| 正式版 C.16 | 2021-07-09 | 3540.09 MB | |
| 正式版 C.15 | 2021-04-26 | 3513.53 MB | 集成 Android 2021 年 4 月安全补丁 |
| 正式版 C.14 | 2021-02-04 | 3512.61 MB | |
| 正式版 C.13 | 2021-01-04 | 3484.97 MB | |
| 正式版 C.12 | 2020-11-30 | 3405.00 MB | |
| 正式版 C.11 | 2020-11-02 | 3404.70 MB | |
| 正式版 C.10 | 2020-09-28 | 3404.41 MB | 用户反馈仅含 2020 年 9 月安全补丁 |
| 正式版 C.09 | 2020-09-16 | 3401.72 MB | C 分支起点（Android 10 / ColorOS 7） |
| 正式版 A.18 | 2020-07-10 | 2737.30 MB | |
| 正式版 A.17 | 2020-06-19 | 2737.38 MB | |
| ColorOS 6 正式版 A.15 | 2020-03-28 | 2734 MB | Android 9，集成 2020 年 3 月安全补丁 |
| ColorOS 6 正式版 A.14 | 2020-02-15 | 2714 MB | Android 9 |
| 正式版本 A.08 | 2019-10-28 | 2468 MB | |
| 正式版本 A.07 | 2019-09-07 | 2468 MB | |
| 正式版本 A.06 | 2019-08-22 | 2468 MB | |
| 正式版本 A.04 | 2019-07-06 | 2468 MB | |
| 正式版本 A.03 | 2019-06-07 | 2468 MB | |
| 正式版本 A.02 | 2019-05-27 | 2468 MB | 首发 |

补充构建号（第三方固件库）：`PCGM00_11_A.02_190515`、`A.03_190530`、`A.04_190626`、`A.05_190716`、`A.06_190731`、`A.07_190822`、`A.18_200624`、`C.09_200828`；线刷包 `K3_PCGM00_11_A.02_190515`（高通 9008 / MSM Download Tool）。【源】

### 2.2 海外 CPH1955（无官方版本页，依据第三方固件库）

| 分支 | 最晚构建 | 日期 | 大小 | 备注 |
|---|---|---|---|---|
| F 分支 | `CPH1955_11_F.13_2021112222502506` | 2021-11-22 | 4.27–4.43 GB | 另有 1606 / 1906 / 2206 变体 |
| EX 分支 | `CPH1955EX_11_C.16_210610_ac25cd18` | 2021-06-10 | 6.93 GB | EX 分支最晚 |
| EX 分支历史 | C.15_210401、C.14_210123、C.12_201029、C.11_201016、C.09_200828、C.07_200624、A.11_200411、A.07_200304、A.05_191119 | 2019-11 ~ 2021-06 | 3.0–7.2 GB | 含 OTA 包 `CPH1955EX_11_OTA_2110_all_...ozip` |
| 基础分支 | `CPH1955_11_A.04_191007_f5b263d0`、`CPH1955_11_A.01_190710_d26b6c61` | 2019-07 / 2019-10 | 6.6–7.0 GB | 2019 年社区 dump 对应期 |

### 2.3 命名规则与常见误读

- 文件名中的 `11`（如 `PCGM00_11_C.17`、`CPH1955EX_11_A.04`）是 **OPPO 内部固件分支编号，不是 Android 11**。【实】
- 第三方聚合站元数据存在明显错误：WhatMyDevice 把 `CPH1955_11_A.01_190710` 标为 Android 11，ROMProvider 把 `CPH1955_11_F.13` 标为 Android 9.0，FlashFileFirmware/FileFirmware 把「Updated October 2, 2026」「June 16, 2026」当作固件发布日（实为站点收录日）。**海外 F.13 的 Android 基线无可靠来源，不作断言。**【源】
- ROMProvider 对 CPH1955 F.13 明确标注 `Root access: Not`，即官方固件不含 root。【源】

---

## 3. GitHub ROOT 相关项目全量检索

### 3.1 方法

- 通道：GitHub REST API，认证账号 `kipcloud120`（scopes: repo / read:org / gist）。限额：core 5000/h、search 30/min、code_search 10/min（代码检索按 7 秒节流）。
- 维度：`search/repositories`（限定 `in:name,description,readme`）、`search/code`、`search/issues`，并对候选仓库逐个拉取 README 与 `contents` 核验实际内容。
- 关键词集合：机型词 `OPPO K3`、`PCGM00`、`PCGT00`、`CPH1955`、`OP486B`、`RMX1901`；ROOT 语义词 `root`、`magisk`、`twrp`、`supersu`、`bootloader`、`unlock`、`boot.img`、`edl`、`firehose`、`recovery`。
- 反例剔除：`realme X root` 返回 1157 条、`RMX1901` 返回 109–125 条，绝大多数为通用安卓项目或设备树，已按 README 机型词复现与实际文件内容二次筛选。约 42 次检索。

### 3.2 检索统计（关键查询）

| 类型 | 查询 | 命中 |
|---|---|---|
| 仓库 | `"OPPO K3" in:name,description,readme` | 14 |
| 仓库 | `PCGM00` / `PCGT00` / `CPH1955` / `OP486B`（同上限定） | 3 / 0 / 14 / 3 |
| 仓库 | `RMX1901 in:name,description` | 109 |
| 仓库 | `"OPPO K3" root` / `magisk` / `twrp` | 2 / 0 / 1 |
| 仓库 | `CPH1955 root` / `magisk` / `twrp` | 9 / 0 / 0 |
| 仓库 | `PCGM00 root` / `magisk` / `twrp` / `unlock` / `firehose` | 0 / 0 / 0 / 0 / 0 |
| 仓库 | `OP486B root` / `magisk`、`"OPPO K3" bootloader`、`CPH1955 edl` | 0 / 0 / 0 / 0 |
| 代码 | `PCGM00 magisk` / `PCGM00 root` | 1 / 14 |
| 代码 | `CPH1955 magisk` / `CPH1955 root` / `CPH1955 twrp` | 1 / 51 / 0 |
| 代码 | `OP486B root` / `"OPPO K3" magisk` / `PCGT00` | 4 / 1 / 152 |
| 代码 | `CPH1955 bootloader unlock` / `RMX1901 magisk` | 0 / 20 |
| 代码 | 7 个最终版构建号（见 4.2） | 全部 0 |
| Issues | `PCGM00 root` / `CPH1955 root` / `CPH1955 magisk` / `OP486B root` / `PCGM00 magisk` | 0 / 3 / 1 / 1 / 0 |

### 3.3 分类发现

#### A 类｜K3 直接相关（已核验文件）

| 仓库 | 说明 | ★ | 最后推送 | 核验要点 |
|---|---|---|---|---|
| `oppo-k3/android_device_OPPO_CPH1955` | TWRP Device Tree for Oppo K3 (CPH1955) | 0 | 2019-09-25 | 完整树：`Android.mk`、`AndroidProducts.mk`、`BoardConfig.mk`、`omni_CPH1955.mk`、`recovery.fstab`、`prebuilt/`、`system.prop`；fork 自 realme RMX1901 TWRP 树 |
| `oppo-k3/ota_dumps` | Dump of OTA updates | 0 | 2019-09-27 | `boot.img`、`recovery.img`、`firmware-update/`、`META-INF/`、`system.transfer.list`、`vendor.transfer.list`、`compatibility.zip` |
| `oppo-k3/oppo_op486b_dump` | Dump of 11_A.03 | 0 | 2019-10-07 | `boot.img`、`boot/`、`bootimg/`、`system/`、`vendor/`、`modem/`、`tz.img`、`board-info.txt`；`system/system/build.prop` 中 `ro.build.version.release=9` |
| `oppo-k3/recovery_extract` | Kernel / DTBO / RamDisk from recovery.img | 0 | 2019-09-27 | 含 `root/prop.default` |
| `oppo-k3/system-dump`、`vendor-dump` | OTA system/vendor 镜像 dump | 0 | 2019-09 | 根目录无常规文件（疑似 submodule / LFS） |
| `oppo-k3/device_oppo_OP486B`、`vendor_oppo_OP486B` | CPH1983 的 device / vendor tree | 0 | 2019-10-25 | fork 自 AndroidBlobs |
| `cfig/Android_boot_image_editor` | boot.img / vbmeta.img / payload.bin 解包重打包 | 1334 | 2026-08-06 | `doc/additional_tricks.md` 有 `## K3 (CPH1955)` 专章；Issue #17 含 CPH1955 root / magisk 讨论 |
| `bkerler/oppo_decrypt` | OPPO `.ofp` 固件解密 | — | — | `ofp_qc_decrypt.py` 在 `CPH1955 root` 代码检索中命中；README 无 CPH1955/root 字样，属工具链上游 |
| `Droidspaces/droidspaces-recovery-hack-example` | 改造 stock recovery 启动 Ubuntu 容器 | 6 | 2026-04-20 | README 涉及 CPH1955、root、bootloader、boot.img |
| `cfbrgb/K3-twrp` | 「OPPO k3 twrp」 | 0 | 2022-01-30 | **不可用**：仓库仅一个名为 `rec` 的 1 字节空文件，size 0 KB |
| `L0NE-6/Magisk-DeviceSpoofer` | Magisk 设备指纹伪装模块 | — | — | `update/xj_pcgm00.json`、`update/xj_cph1955.json`，版本 `v2026.10.09.2`，指向 `OPPO K3 (PCGM00)/(CPH1955).zip`；不提供提权 |

`cfig/Android_boot_image_editor` 的衍生/镜像仓库（非独立项目，不逐一列出）：`emtee40/Android_boot_image_editor`、`DawfukFR/BluRaviole_boot_image_editor`、`zoomver/Image-editor(-new)`、`igconitoguy/Android_boot_image_editor`、`osflaky/exp-cfig-Android_boot_image_editor`、`familyboatu1r0ch/a-raina`、`ravindu644/patch-recovery-revived`；`ofp_qc_decrypt.py` 的副本见 `xiaoxindada/SGSI-build-tool`、`ColdWindScholar/TIK`。

**K3 CPH1955 关键技术约束（cfig 文档原文要点）**：从 OTA zip 提取的 `boot.img` 不能正常工作，`recovery.img` 可用；需用 `bspatch boot.img recovery.img system/recovery-from-boot.p` 从 `system/recovery-from-boot.p` 补丁生成 `recovery.img`。【实】

#### B 类｜Magisk / 属性资料（与 root 检测相关，非 root 工具）

- `getActivity/AndroidSystemPropertyCollect :: ColorOS/ColorOS 7.1 Android 10 OPPO K3.txt` — 796 行系统属性快照，39 行含 root/su/verity 等字样，含 `dev.mnt.blk.root=dm-0`。可用于 root 检测规则与设备指纹比对。【实】

#### C 类｜同平台 realme X（RMX1901，sdm710 共板）可参照但不可直接刷入 K3

| 仓库 | 说明 | ★ | 日期 |
|---|---|---|---|
| `monster8d/RMX1901-Flash_Tool` | 「Root Your Device in 1 click」，支持一键 root / 解除 root / 降级 RUI1 / debloat；含 `Flash Tool.bat`、`debloat_list.sh` | 1 | 2022-07-23 |
| `ishashanknigam/kernel-realme-RMX1901` | NetHunter 内核（Linux 4.9.186，Android 10 / ColorOS 7.2），README 含 Magisk / TWRP / NetHunter | 0 | 2026-10-03 |
| `lalblc/kernel_docker_nethunter_realme_sdm710_rmx1901` | Docker / NetHunter 内核，README 注明已停更、删除全部 Releases | 1 | 2023-11-14 |
| `PixelPlusUI-Devices/official_devices_old :: guides/RMX1901.md` | 刷机指南含 Magisk | — | — |
| `pjgowtham/orangefox_device_realme_RMX1901` | OrangeFox recovery 树 | 0 | 2020-07-24 |
| `PitchBlackRecoveryProject/android_device_realme_RMX1901-pbrp` | PBRP 树 | 1 | 2022-06-01 |
| `ij-israfil/recovery_realme_RMX1901`、`th4rv4/recovery_realme_RMX1901` | TWRP recovery 树 | 0 | 2026-08 |
| `H1mJT/kernel_realme_RMX1901`、`negrroo/LawRun_realme_sdm710` | 内核源码 | 5 / 4 | 2024–2025 |

另有约 40 个 `device_realme_RMX1901` / `kernel_realme_RMX1901` 的 fork 与 LineageOS 系设备树（Shravan55555、shravansayz、ij-israfil、raunaqseth、sanyam-taneja 等），均为 0–19 星、2020–2026 年的派生仓库，无 K3 适配。

#### D 类｜机型数据库（PCGT00 代码检索 152 条的主要来源）

`KHwang9883/MobileModels :: brands/oppo_cn.md`、`liuzho/ADN :: names/op4679/pcgt00.json`、`GetTechAPI/TechAPI`、`stevenkang/model-lib`、`KiritoXDone/c001apk`、`yeuban/Flutter-Coolapk` 等，仅含机型名与型号映射，无 root 内容。

### 3.4 明确的零命中项

`"OPPO K3" magisk`、`OP486B magisk`、`"OPPO K3" bootloader`、`PCGM00 twrp/unlock/firehose`、`CPH1955 edl/twrp/bootloader unlock`（仓库维度）；`CPH1955 twrp`、`CPH1955 bootloader unlock`（代码维度）；`PCGM00 root`、`PCGM00 magisk`（Issues 维度）。

即：**未发现 K3 专属的 Magisk 补丁 boot.img、Bootloader 解锁工具、EDL/9008 救砖包或提权漏洞项目。**

### 3.5 检索局限

- GitHub 代码搜索不索引二进制文件；实际流通的 patched boot.img、TWRP `.img`、Magisk 模块 zip 多在论坛 / 网盘 / Telegram，不在可检索范围。
- `in:readme` 依赖索引，长期零星的仓库可能未被收录。
- 除 `cfig/Android_boot_image_editor` 外，K3 相关仓库全部创建于 2019–2022 年、★0–1、长期停更。

---

## 4. 从固件版本反推 ROOT 可行性

### 4.1 版本断层（核心结论）

| | 官方固件 | GitHub 可得 ROOT 资源 |
|---|---|---|
| 时间 | 2019-05 → 2021-10（国行）/ 2021-11（海外） | 2019-07 → 2019-10 |
| 系统 | Android 9 / ColorOS 6 → Android 10 / ColorOS 7 | Android 9（`build.prop` 实证 `release=9`） |
| 证据 | ColorOS 官网 19 个版本 | `oppo-k3` 组织 8 个仓库全部 pushed_at ≤ 2019-10-25 |

跨 Android 大版本后内核、ramdisk、vbmeta、`recovery-from-boot.p` 结构均变化，**GitHub 上 2019 年的 boot.img 不可直接打 Magisk 补丁后刷入 C.17**，否则内核与基带/系统不匹配，存在无法启动风险。【推，但依据充分】

### 4.2 最终版构建号零命中

对以下 7 个构建号做 GitHub 代码检索，`total_count` 全部为 0：`PCGM00_11_C.17`、`PCGM00_11_OTA_2170`、`CPH1955_11_F.13`、`CPH1955EX_11_C.16`、`PCGM00_11_C.15`、`CPH1955EX_11_A.04`、`PCGM00_11_A.03`。【实】

即 GitHub 上不存在针对最终固件的 dump、patched boot.img 或适配代码。这解释了 3.4 的零命中并非检索方法问题。

### 4.3 补丁级别与免解锁 root

- C.15（2021-04-26）明确集成 Android 2021 年 4 月安全补丁；C.16 / C.17 日志未再列补丁项（C.17 仅一项桌面功能），**精确 SPL 未公开**。【源/实】
- 据此，最终固件至少处于 2021-04 补丁级别，2019–2020 年的公开提权漏洞（Binder UAF 一类）已封堵，KingRoot 等免解锁方案基本不可行。【推】
- 官方固件标注 `Root access: Not`。【源】

### 4.4 Bootloader 解锁通道与地域错配

XDA 论坛 `Oppo K3 Rooting` 帖（thread 3991493，开帖 2019-10-26）于 **2025-04-25** 有一条决定性回复（用户 lpf452，附 `OPPO_K3_DeepTesting.apk` 3.4 MB）：【源，来自搜索引擎索引快照；原帖当前 403 拦截，未能核验正文】

- **只有中国大陆销售的 OPPO K3（不含港澳台）能够进入 fastboot 并解锁 bootloader**；
- 常规 `adb reboot bootloader` 或「音量上 + 电源」会快速重启，无法进入 fastboot；
- 需安装 OPPO「深度测试」(Deep Test) APK → 点 Apply 申请 → 审核每月 15 日一次，且需购机满 3 个月 → 查询审核状态显示 Approved → 点「Start Deep Test」（不是 Back），设备才正常进入 fastboot；
- 之后执行 `fastboot flashing unlock`；若提示 access to fastboot is denied，需以管理员权限运行。

**错配点**：唯一有官方解锁资格的是国行 `PCGM00`，而 GitHub 上唯一的 TWRP 设备树 `oppo-k3/android_device_OPPO_CPH1955` 针对海外 `CPH1955`。二者无法直接对接，这是社区适配停留在 2019 年、覆盖不到国行最终版的关键原因。【推】

**深度测试现状（2026 年资料）**：【源】

- OPPO 官方深度测试机型名单「最后一次更新为 2021-11-22」，最高支持到 Find X3 系列 / Reno6，之后新机不再支持官方申请；需在「指定的出厂版本」下载深度测试 APP 在线申请，审核约 1 个月。
- 申请条件：机型上市超 3 个月、近 60 天无申请记录、当前 OPPO 账号在本机连续登录超 60 天、名额未满、非政企/运营商定制版、仅限中国大陆正式发售机型；提交前须切换回系统正式版并升级至支持深度测试的指定版本。
- 深度测试 APK 标注支持 Android 9 与 Android 10 机型，部分 Android 10 版本无法打开即表示当前版本不支持。
- 2026 年 BL 解锁状态汇总资料称 OPPO 深度测试「支持的机型往往非常老、等待时间很长」，并提到 OPPO 对部分较新平台推送「熔断包」导致 9008 免授权路径永久锁死（主要针对 865/870/8Gen 系，K3 为 sdm710，是否受影响未见明确记录）。
- **K3 的具体「指定申请版本」未见公开记录；若指定版本为早期 A 系列（Android 9），则申请解锁需先降级，与「root 最终版 C.17」目标构成第二重矛盾。**【推】

### 4.5 EDL / 9008 路径

第三方固件站提供 OFP 线刷包、MSM Download Tool、Firehose Loader、QCN、UFS dump（如 `PCGM00-11.A.04-0040-201906262314-UFS-DUMP-REPLACE-UNBRICK-REPAIR.rar` 2.3 GB）。但国内固件分发站明确说明：**OPPO 自 2017 年 6 月前后对后续机型刷机工具加密，需要登录授权账号才能刷机**，非公开可用路径。【源】

### 4.6 若实施 root 的约束清单【推】

1. 使用与设备当前系统**完全一致**的 C.17 原版 `boot.img`（来自 `PCGM00_11_OTA_2170` 或 `PCGM00_11_C.17_210909`），禁止复用 GitHub 2019 年镜像。
2. 先通过「深度测试」完成 BL 解锁并确认 `fastboot getvar unlocked`。
3. 在目标机上安装 Magisk → Select and Patch a File → 生成 `magisk_patched_*.img` → `fastboot flash boot`（刷前用 `fastboot getvar current-slot` 确认分区布局，不要默认双槽通刷）。
4. 保留未修改的原版 boot.img 以便回退。
5. 注意 cfig 记录的 K3 (CPH1955) 特例（OTA 提取的 boot.img 不可用、需 bspatch 生成 recovery.img）；该经验来自海外早期 A 分支，在国行 C 分支是否同样适用**未经验证**。
6. 风险：AVB / vbmeta 校验、跨版本镜像变砖、解锁清空数据、失去保修、后续 OTA 中断。

---

## 5. 版本时间线（文字版）

```
2019-05-27  A.02  Android 9 / ColorOS 6   国行首发
2019-07-10  CPH1955_11_A.01              海外首批固件
2019-09-25  GitHub: CPH1955 TWRP 设备树
2019-09-27  GitHub: ota_dumps / recovery_extract
2019-10-07  CPH1955EX_11_A.04 (Android 9, SPL 2019-10-05)
2019-10-07  GitHub: oppo_op486b_dump (11_A.03, build.prop release=9)
2019-10-28  A.08
2020-03-28  A.15  Android 9 最后标注版本，SPL 2020-03
2020-09-16  C.09  Android 10 / ColorOS 7 起点
2020-09-28  C.10  SPL 2020-09
2021-04-26  C.15  SPL 2021-04
2021-06-10  CPH1955EX_11_C.16            EX 分支最晚
2021-10-29  C.17  国行最终版（Android 10 / ColorOS 7）
2021-11-22  CPH1955_11_F.13             海外最晚构建
2021-11-22  OPPO 深度测试机型名单末次更新（同源资料）
2022-01-30  GitHub: cfbrgb/K3-twrp（空仓库）
2026-11     现状：官方固件停更约 5 年；GitHub 无最终版适配
```

---

## 6. 风险、不确定性与待核验项

| 项 | 状态 |
|---|---|
| 海外 CPH1955 F.13 的 Android 基线 | 无可靠来源，第三方站标注互相矛盾（Android 9 / 11） |
| C.17 的精确安全补丁月份 | **已结案（2026-11-12 实测）：2021-05-05**，见第 9 节与《C17_ROOT固件获取与核验记录》；原记录为「官网未披露，仅能确认 ≥ C.15 的 2021-04」 |
| 深度测试服务 2026 年是否仍受理 K3 | 未确认；官方名单末次更新 2021-11-22，2026 年资料称支持机型很少 |
| K3 深度测试的「指定出厂版本」 | 未见公开记录，可能要求降级到早期 A 系列 |
| XDA 解锁细节 | 原帖 403，依据搜索引擎索引快照，未核验正文 |
| 国行 C 分支是否同样需要 bspatch recovery-from-boot.p | 未验证，cfig 经验来自海外 A 分支 |
| `PCGT00` 是否有独立 OTA 通道 | 未见独立固件线，倾向与 PCGM00 共用 |
| GitHub 未索引的二进制 root 包 | 不在本次可检索范围，不能断言「不存在」 |

---

## 7. 可复查附录

### 7.1 主要检索式

```
仓库："OPPO K3"|PCGM00|PCGT00|CPH1955|OP486B|RMX1901  in:name,description,readme
仓库：<机型词> + root|magisk|twrp|bootloader|boot.img|unlock|edl|firehose  in:name,description,readme
代码：PCGM00 magisk / PCGM00 root / CPH1955 magisk / CPH1955 root / CPH1955 twrp
代码：OP486B root / "OPPO K3" magisk / PCGT00 / CPH1955 bootloader unlock / RMX1901 magisk
代码："PCGM00_11_C.17" / "PCGM00_11_OTA_2170" / "CPH1955_11_F.13" / "CPH1955EX_11_C.16" / "PCGM00_11_C.15" / "CPH1955EX_11_A.04" / "PCGM00_11_A.03"
Issues：PCGM00 root / CPH1955 root / CPH1955 magisk / OPPO K3 root / OP486B root / PCGM00 magisk
核验：repos/{owner}/{repo}/readme、/contents、/contents/{path}（base64 解码）
```

### 7.2 关键证据摘录

- `oppo-k3/oppo_op486b_dump/system/system/build.prop`：`ro.build.version.release=9`、`ro.build.version.codename=REL`、`ro.build.version.min_supported_target_sdk=17`。
- `cfig/Android_boot_image_editor/doc/additional_tricks.md`：`## K3 (CPH1955)` — 「`boot.img` extracted from OTA zip file doesn't work properly but `recovery.img` works fine... `bspatch boot.img recovery.img system/recovery-from-boot.p`」。
- `L0NE-6/Magisk-DeviceSpoofer/update/xj_pcgm00.json`：`{"version":"v2026.10.09.2","zipUrl":".../OPPO/OPPO%20K3%20%28PCGM00%29/OPPO%20K3%20%28PCGM00%29.zip"}`（另有 xj_cph1955.json 同构）。
- `monster8d/RMX1901-Flash_Tool/README.md`：`Root Your Device in 1 click` / `Unroot your device in the same way` / `Last tested on RUI2 F.04`。
- `cfbrgb/K3-twrp` 唯一文件 `rec`：1 字节，内容为换行。
- `oppo-k3` 组织仓库清单（8 个，pushed_at 2019-09-22 ~ 2019-10-25）：`android_device_OPPO_CPH1955`、`recovery_extract`、`ota_dumps`、`vendor-dump`、`system-dump`、`oppo_op486b_dump`、`device_oppo_OP486B`、`vendor_oppo_OP486B`。

### 7.3 来源清单

**一手 / 权威**
- ColorOS 官方固件页（K3 PCGM00）：https://www.coloros.com/rom/firmware?id=190
- 人民法院诉讼资产网拍卖公告（型号 PCGM00）：https://www.rmfysszc.gov.cn/statichtml/rm_xmdetail/3587327.shtml 、 https://www.rmfysszc.gov.cn/statichtml/rm_xmdetail/8126605.shtml
- 太平洋电脑网（GeekBench 型号 OPPO PCGM00）：https://g.pconline.com.cn/x/266/12607318.html
- GitHub REST API（仓库 / 代码 / Issues 检索与文件内容核验）
- GitHub 组织：https://github.com/oppo-k3

**固件与机型资料**
- ONFIX C.17：https://onfix.cn/rom/555252 ｜ C.15：https://onfix.cn/rom/447673 ｜ A.02 线刷：https://onfix.cn/rom/54011 ｜ A.15：https://onfix.cn/rom/54009
- ROMProvider 国行型号对照表：https://romprovider.com/oppo-china-model-codename-list/
- ROMProvider CPH1955 固件（含 `Root access: Not`）：https://romprovider.com/cph1955-oppo-k3-firmware-flash-file-support
- MobileModels 海外机型表：https://github.com/KHwang9883/MobileModels/blob/master/brands/oppo_global_en.md
- DevCheck OPPO K3：https://devcheck.app/devices/oppo/op4679 ｜ Soft9 OP486B：https://soft9.us/devices/oppo/OP486B
- Mobifirms CPH1955EX_11_A.04 固件信息：https://www.mobifirms.com/oppo-k3-cph1955-dead-boot-repair
- FirmwareX 国行 / 海外：https://firmwarex.net/oppo-k3-pcgm00-official-firmware 、 https://firmwarex.net/oppo-k3-cph1955-official-firmware
- FirmwareDrive CPH1955：https://firmwaredrive.com/folders/5376 ｜ ROMDevelopers CPH1955：https://romdevelopers.com/index.php?a=downloads&b=folder&id=21559
- AZROM PCGM00/PCGT00/CPH1955 固件汇总：https://azrom.net/tag/stock-rom-oppo-k3-cph1955-pcgm00-pcgt00-official-firmware/
- WhatMyDevice 固件列表（元数据有误，仅作交叉参考）：https://whatmydevice.com/download-rom/oppo-k3
- 中关村在线参数页：https://wap.zol.com.cn/1250/1249492/index.html ｜ GSMchoice：https://www.gsmchoice.com/en/catalogue/oppo/k3/

**ROOT / 解锁**
- XDA「Oppo K3 Rooting」：https://xdaforums.com/t/oppo-k3-rooting.3991493/ （当前 403，依据搜索索引快照）
- AndroidWeblog Magisk 补丁 boot.img 通用流程：https://www.androidweblog.com/?p=30635/
- 2026 年欧加深度测试机型与政策整理：https://openrokid.csdn.net/6acfbe313d0de04db9d47623.html
- 深度测试 APK 申请条件：https://www.arpun.com/game/396913.html 、 https://cr173.com/soft/1299410.html
- 2026 全品牌 BL 解锁状态（熔断 / 9008）：https://gitmemories.com/index.php/AdaUnlocked/2026-All-Brands-Bootloader-Unlock-Status
- 2026 可 root 机型列表（OPPO 章节）：https://www.gizdev.com/rootable-android-phones-complete-list-2026/

---

## 8. 后续可选项

1. 获取官方 C.17 OTA 包（`PCGM00_11_OTA_2170`）做静态分析：`build.prop`、SPL、boot 镜像结构、AVB/vbmeta 状态、是否含 `recovery-from-boot.p`，以确认 Magisk 补丁目标文件。**【已完成，见第 9 节；`build.prop` 位于未下载的 `system.new.dat.br` 内，仍缺】**
2. 核验深度测试 APK 对 K3 / C.17 的实际兼容性与指定申请版本。**【仍开放】**
3. 将版本线与构建号整理为结构化数据（CSV / JSON），便于与工作区内其他取证材料做关联比对。**【部分完成：官方 19 版本 API 原始响应已落盘，见第 9 节】**

---

## 9. 后续执行记录（2026-11-12）

> 本节为 ROM 获取与静态分析的执行阶段增补。第 0–8 节保留首次调查时的状态快照，不作追溯改写；完整过程、原始值与复现方法见同目录 `C17_ROOT固件获取与核验记录.md`。

### 9.1 一手证据链

- 捕获官网 XHR 得到固件接口 `https://www.coloros.com/api/colorOS/business/rom/romList?productId=190`，返回 **19 个版本**的 `fileUrl`、`fileMd5`、完整 `updateLog`。原始响应落盘为 `firmware_C17_root/coloros_romlist_productId190.json`。【实】
- C.17 官方直链：`https://coloroswebsitefs.coloros.com/coloroswebsite-coloros-com/grs_20211029153344/PCGM00_11_OTA_2170_all_yu0AtmFTUqOG.ozip`，3,742,019,949 字节，支持 `Accept-Ranges: bytes`，CDN 头 `x-amz-meta-content-md5 = a6f5c1ec0e4b6c57b08f8207d8745a9e` 与官网一致。**第 2.1 节 OTA 包名由【源】升级为【实】。**【实】
- 识别出 ozip 分块加密结构（头部 `0x1050` 明文；每 `0x4010` 字节 = 16 字节 AES-128-ECB 密文 + `0x4000` 明文），密钥 `ACAC1E13A12531AE4A1B21BB31C13C21`（密钥表标注「Reno, K3」）。因 ECB 块独立，仅用 2 次 Range 请求传输 **13,909,677 字节（13.27 MiB）** 即提取出目标文件，完整包未下载。【实】

### 9.2 交付物

`firmware_C17_root/`：`boot.img`（64 MiB，SHA256 `0015a75c…274e`）、`firmware-update/vbmeta.img`、`META-INF/` 下 3 个元数据文件、`manifest.json`（全部哈希与 Range 明细）、官方 API 原始响应 JSON。复现工具：`tools/ozip_range_extract.py`（已实测 `--list` 与单文件提取）。全部文件通过 ZIP CRC32 + 大小校验。【实】

### 9.3 对第 0–8 节结论的修订

| 位置 | 原记录 | 本轮结果 |
|---|---|---|
| 2.1 ColorOS 版本 | V7 | **V7.1**（OTA metadata `os_version=V7.1`） |
| 2.1 历史版本 MD5 / 直链 | 仅 C.17 有 MD5 | 19 条全部获得 |
| 4.3 | 「C.16 / C.17 日志未再列补丁项」 | **需修正**：C.16 明确「集成 Android 2021 年 5 月安全补丁」；C.17 未列补丁但 SPL 实测为 2021-05-05 |
| 4.6 第 3 条 | 需确认槽位，不要默认双槽通刷 | **已确认 A-only**（updater-script 写 `/dev/block/bootdevice/by-name/boot`，无 `_a/_b`）→ `fastboot flash boot` |
| 4.6 第 6 条 | AVB / vbmeta 校验为风险项 | **已确认启用**：vbmeta `AVB0`、`flags=0`、已签名；boot.img 带 `AVBf` footer |
| 6 | C.17 精确 SPL 未披露 | **已结案：2021-05-05**（metadata `google_patch` 与 boot 头 `os_version=0x14000155` 双证） |
| 6 | 国行 C 分支是否需 bspatch | **仍开放**：确认 235 条目中无 `recovery.img` 与独立 `recovery-from-boot.p`，但 `system.new.dat.br`（2.35 GB）未取，内部内容未验证 |

### 9.4 新增 ROOT 约束与风险点

1. 单槽设备，补丁后刷入 `boot` 而非 `boot_a` / `boot_b`。【实】
2. AVB 启用且 vbmeta 已签名，补丁 boot 可能触发校验失败，需评估禁用验证的 vbmeta 处理；原版 `boot.img` / `vbmeta.img` 已保留用于回退。【实/推】
3. `boot.img` 头 `ramdisk_size=0`、`0x1000` 处为 gzip 内核，推测 ramdisk 内嵌于 kernel initramfs；**Magisk 对无独立 ramdisk 镜像的补丁行为未实测**，为新增待验证风险点。【推】
4. 版本断层（2019 GitHub 资源 vs 2021 C.17）与地域错配（PCGM00 解锁资格 vs CPH1955 设备树）两项核心结论**不变**；深度测试解锁仍是唯一前置条件，其 2026 年可用性未确认。【实/推】

### 9.5 仍开放项

深度测试 2026 年是否受理 K3、K3 的「指定申请版本」、XDA 原帖 403 正文、海外 CPH1955 F.13 的 Android 基线、`PCGT00` 独立 OTA 通道、GitHub 未索引的二进制 root 包、`system.new.dat.br` 内的 `build.prop` 与 `recovery-from-boot.p`。
