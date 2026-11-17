# OPPO K3（PCGM00 / C.17）ROOT 实施方案

> **版本失效声明（2026-11-13，依据实机 ADB 复核）**
> 本文基于 **C.17** 基线（ColorOS 7.1 / Android 10 / 内核 4.9.186 / SPL 2021-05-05）编写。实机 ADB 已确认设备运行 **PCGM00_11_F.16**（ColorOS 11.1 / Android 11 / 内核 4.9.227-perf+ / SPL 2022-04-05，构建 2025-03-26，fingerprint 尾号 `1704167642389`）。
> 本文中的镜像哈希、boot/vbmeta 数值、内核符号与偏移、CVE 补丁窗口，以及任何针对 C.17 的操作指令，**对本机全部作废**，不得用于本机判断；与版本无关的采集命令、分析方法论仍可参考。
> 当前有效基线：`F16_基线_与C17结论失效说明.md`；当前固件镜像：`firmware_F16/`；获取与清理记录：`F16_固件获取与C17清理记录.md`。

- 编制日期：2026-11-12
- 依据：`C17_深度解包与静态分析报告.md`（固件实测）、`github_research.md`（GitHub 一手证据）、`C17_ROOT固件获取与核验记录.md`（原版镜像与来源链）
- 适用对象：**国行 PCGM00、系统版本正式版 C.17（ColorOS 7.1 / Android 10 / SPL 2021-05-05）**
- 本方案是**可执行操作手册**，但本次会话**没有连接实机**（`adb devices` / `fastboot devices` 均为空），因此未执行任何解锁、补丁或刷写；所有刷机动作留待实机阶段

---

## 0. 一页结论

**上一阶段设想的「Magisk 补丁 boot.img → `fastboot flash boot`」不是可靠的主路径。** 深解包证实：C.17 的 `boot.img` 完全没有 ramdisk，rootfs 位于 `system` 分区（Legacy SAR）；按 Magisk 官方分类本机属于 **Type III**（"A-only + Method B"，官方称其 "The worst type of device to ever exist as far as Magisk is concerned"）。

因此 ROOT 的三段式结论是：

1. **必须先解锁 Bootloader**（国行「深度测试」），这是所有路径的共同前置，且 2026 年是否仍受理 K3 未确认。
2. **必须先处理 AVB**：已实测 `sha256(salt || boot[0:16,609,280])` 与签名摘要完全一致，顶层 vbmeta 还有 5 个 chain partition descriptor；不改 vbmeta，任何补丁镜像都会被拒。
3. **镜像路径按决策树走**：优先试「直接 patch C.17 的 boot.img」（同平台 realme X 有 boot 内带 ramdisk 成功启动的实证），失败再退回官方保守的「patch recovery.img + Recovery Mode」。

**最重要的一条结论**：不要继续沿用《汇总》0.6 / 4.6 的单路径假设；也不要把 2019 年 Android 9 的 `oppo-k3` dump / TWRP 树 / bspatch 结果刷进 C.17。

---

## 1. 本机属性判定（决定后续所有分支）

| 维度 | 实测/核验结果 | 证据 |
|---|---|---|
| 机型 / 版本 | PCGM00、C.17、ColorOS 7.1 (V7.1)、Android 10、SPL 2021-05-05 | OTA metadata + boot header `os_version=0x14000155` |
| 槽位 | **A-only 单槽** | updater-script 写 `/dev/block/bootdevice/by-name/boot`，无 `_a/_b` |
| boot ramdisk | **无**（`ramdisk_size=0`、second/recovery_dtbo 全 0、整个内核负载无 cpio magic） | `unpacked_C17/boot_header.json`、`region_map.json` |
| 内核 | `Image.gz` + 16 个追加 DTB；`CONFIG_INITRAMFS_SOURCE=""`；仅 512 B 默认 stub cpio（无 `/init`） | `kernel_config.txt`、`initramfs.cpio` |
| rootfs | **system 分区**，ext4 卷标与挂载点均为 `/`；`/init -> /system/bin/init`；`fstab-at.qcom` 为 `…/system / ext4 ro,barrier=1,discard wait,avb` | `system_prefix.bin`、`ext4_root_report.json`、`system_root/fstab-at.qcom` |
| 启动方式 | **Method B / Legacy SAR** → Magisk **Type III** | `docs/boot.md` 分类表 + 上述事实 |
| AVB | 顶层 `vbmeta.img` SHA256_RSA4096、`flags=0`、5 个 chain descriptor（boot/system/vendor/dtbo/recovery）；boot 内嵌 hash descriptor 已实测摘要绑定 | `vbmeta_header.json`、`boot_embedded_vbmeta.json` |
| 关键 cmdline | 无 `root=`、无 `init=`、无 `skip_initramfs`；但**内核二进制内存在 `skip_initramfs` 字符串**（@解压后 27,253,134），Magisk 的等长 hexpatch 有合法目标 | boot header / DTB / `kernel.decompressed` 扫描 |
| OTA 物料 | 235 条目中**无 `recovery.img`**、无独立 `recovery-from-boot.p`；`system` 根目录 21 项中也未见该 patch | `ota_entries.txt`、`ext4_root_report.json` |

---

## 2. 前置条件（Go / No-Go）

### 2.1 必须先完成：Bootloader 解锁

| 项 | 状态 / 要求 |
|---|---|
| 资格 | 仅**中国大陆正式发售**的 PCGM00（不含港澳台、不含运营商/政企定制版）。海外 CPH1955 无资格 |
| 通道 | OPPO「深度测试」(Deep Test) APP → 申请 → 审核 → 「Start Deep Test」→ 设备进入 fastboot → `fastboot flashing unlock` |
| 2026 现状 | GitHub 一手资料（`zenfyrdev/bootloader-unlock-wall-of-shame`、`awesome-android-root`）确认深度测试仍存在但 **"Very limited model support"、7 天等待、仅国行**；**K3 是否仍在受理名单、是否需要降级到「指定出厂版本」，GitHub 无一手记录** |
| 不可用替代 | `Shocked-Cat/oppo-mtk-fastboot-unlock`、`R0rt1z2/lkpatcher` 均为 **MTK 专用**，K3 是高通 sdm710，不适用；EDL/9008 需 OPPO 授权账号，非公开路径 |

> **No-Go 条件**：若深度测试不再受理 K3，或申请要求降级到 Android 9 的 A 系列，则本次「在 C.17 上 root」目标在当前约束下不可达，需先解决解锁资格问题。

### 2.2 环境检查（实机阶段第一步）

```bash
adb reboot bootloader
fastboot devices
fastboot getvar unlocked            # 必须为 yes
fastboot getvar current-slot        # A-only，预期无 _a/_b
fastboot getvar product
```

### 2.3 备份（刷写前必做）

保留工作区内两份**未修改**原版镜像，并记录哈希用于回退校验：

| 文件 | SHA256 |
|---|---|
| `firmware_C17_root/boot.img` | `0015a75c8bc45a896b750107a73923895616b158fe06ca771b0198b66589274e` |
| `firmware_C17_root/firmware-update/vbmeta.img` | `5a77359c52f2b640143b34b6ec429c76a60662d5033a13d52694c8937767635f` |

另建议在已解锁的 fastboot 下尽量 dump 现有分区（`boot`、`vbmeta`、`recovery`）作为设备侧备份。

> ⚠️ 解锁会**清空用户数据**并失去保修；`fastboot` 改 vbmeta flags 也可能触发数据擦除。先备份数据。

---

## 3. AVB 处理（两条路径共用，必做）

**原理（已核验一手源码）**：`fastboot --disable-verity --disable-verification` 在刷入前把顶层 vbmeta 的 `flags`（偏移 120）由 0 改为 3。`libavb/avb_vbmeta_image.h` 明确 `VERIFICATION_DISABLED` 时 **"verification will be disabled and descriptors will not be parsed"** → 5 个 chain partition descriptor 不再被跟进，boot 内嵌 vbmeta 的签名/摘要校验随之跳过。

**命令**（本机 fastboot 36.0.1 已验证全局参数写法可解析）：

```bash
fastboot --disable-verity --disable-verification flash vbmeta firmware_C17_root/firmware-update/vbmeta.img
```

- Magisk 官方文档写法为 `fastboot flash vbmeta --disable-verity --disable-verification vbmeta.img`；若你的 fastboot 版本报参数错误，改用上面的全局写法。
- **保留原 vbmeta 的 descriptors，只改 flags**：比用 `avbtool --flags 3` 生成"空 vbmeta"更稳妥（空 vbmeta 丢弃 5 个 chain descriptor 与 `os_version` / `security_patch` property，部分 OEM bootloader 会拒绝启动）。
- **该操作可能清空数据**；顺序上可与补丁镜像同一批刷完再重启。
- 风险提示：OPPO LK/ABL 是否严格实现 `VERIFICATION_DISABLED` 语义未实测，属本方案最大不确定点之一。

---

## 4. 决策树

```
解锁成功且 fastboot getvar unlocked = yes
        │
        ├─ 路径 A（优先试）：在「本机」用 Magisk patch C.17 的 boot.img
        │     └─ 刷入 boot + 处理 vbmeta → 开机验证
        │           ├─ 成功启动且 Magisk 显示已安装 → 完成 ✔
        │           └─ 卡开机 / bootloop / Magisk 不生效 → 回退原版 boot，转路径 B
        │
        └─ 路径 B（官方保守）：取得/构造 recovery.img → Recovery Mode patch → 刷 recovery
              └─ 每次用按键组合启动才有 root（正常开机无 root）
```

### 为什么先试路径 A

| 支撑 | 来源 |
|---|---|
| Magisk `boot_patch.sh`（v20.4+，当前 v31.x）在"无 ramdisk"时**不会报错**，而是 `No ramdisk found, create one from scratch`，`magiskboot cpio` 自动新建 cpio 并 `add 0750 init magiskinit` | `topjohnwu/Magisk@master:scripts/boot_patch.sh` + `native/src/boot/cpio.rs` |
| v26.4+ 在 `LEGACYSAR` 时对内核做 `skip_initramfs → want_initramfs` 等长 hexpatch；**本机内核确实含该字符串**，补丁有合法目标 | 同上 + 本次内核扫描 |
| 同平台 realme X / RMX1901（sdm710、Android 10、ColorOS 7.2）2026 年 README 实证：`raw kernel Image + stock 17-DTB container + Magisk root ramdisk = boot image`，TWRP `dd` 刷入后 Android 正常启动且 root context 可用 → **该平台 bootloader 接受 boot 内 ramdisk** | `ishashanknigam/kernel-realme-RMX1901` |
| 本机 boot 头 cmdline 与 16 个 DTB 的 `/chosen` 均**无 `skip_initramfs`** → 若 ABL 也不追加，内核会自然加载新增的 initramfs | 本次静态分析 |

**反证/风险**：`docs/boot.md` 明确 Type III 设备"多数不接受"手工加入的 ramdisk（仅部分小米例外），`Magisk#1801` 有 A-only SAR 设备 "patch boot.img 不工作" 的实证；且 RMX1901 案例用的是自定义 NetHunter 内核 + TWRP + 重签名，并非原厂 ColorOS 内核补 ramdisk。**所以路径 A 必须以实机试为准，不能预设成功。**

---

## 5. 路径 A 详细步骤

1. 把 `firmware_C17_root/boot.img` 传到实机存储（例如 `/sdcard/Download/boot.img`）。
2. 在**同一台设备**安装当前 Magisk App（建议 v31.x / ≥v26.4，以获得 LEGACYSAR hexpatch 与自动新建 ramdisk）。
3. Magisk App → Install → **Select and Patch a File** → 选 `boot.img`（**不要**勾选 Recovery Mode）。
4. `adb pull /sdcard/Download/magisk_patched-*.img` 取回 PC。
5. 回 fastboot，按顺序刷写：

```bash
fastboot flash boot magisk_patched-*.img
fastboot --disable-verity --disable-verification flash vbmeta firmware_C17_root/firmware-update/vbmeta.img
fastboot reboot
```

6. 验证（见第 8 节）。若卡在第一屏 / bootloop：**不要反复重试**，立即按第 9 节回退。

**已知注意点**：
- `docs/install.md` 强制要求 "**ALWAYS** patch boot image **on the same device**"，并禁止刷入他人分享的 patched 镜像 → 本工作区**不能代生成**补丁镜像。
- A-only 单槽，刷 `boot`，不要用 `boot_a`/`boot_b`。
- `LEGACYSAR` 是否被 Magisk 自动置位、ABL 是否动态追加 `skip_initramfs`，静态镜像无法判定，只能实机观察。
- `cfig/Android_boot_image_editor` 可解包/重打包 `ramdisk_size=0` 的 boot（`BootV2.kt` 对 size=0 跳过解压、`pack()` 自动重算 `ramdiskLength`），可作为手工构造 ramdisk 的备选工具；但它会用自带 test key 重签，**原厂 AVB 签名必然失效**，必须配合第 3 节。

---

## 6. 路径 B 详细步骤（A 失败时）

### 6.1 物料问题（必须先解决）

C.17 OTA **不含 `recovery.img`**，也没有独立 `recovery-from-boot.p` 条目。可选来源：

| 来源 | 可行性 |
|---|---|
| `bspatch boot.img recovery.img system/recovery-from-boot.p` | cfig `doc/additional_tricks.md` 的 K3 专章做法；但经 Issue #17 核验，该专章对应 **2019 Android 9 / 海外 CPH1955**，且 C.17 的 `system.new.dat.br` 内是否含该 patch 文件**未验证**（本次 32 MiB 前缀未覆盖；`build.prop` 位于目标块 419,282，需约 1.7 GB 顺序 brotli 解压才能读到） |
| 从设备 dump `recovery` 分区 | 解锁后可用；若路径 A 曾短暂成功获得 root，可直接 `dd if=/dev/block/bootdevice/by-name/recovery of=/sdcard/recovery.img`；也可先临时 `fastboot boot` 一个能启动的镜像再 dump |
| 用 2019 年 `oppo-k3/ota_dumps` 的 `recovery.img` | **不推荐**：Android 9 内核，与 C.17 Android 10 系统不匹配，存在无法启动风险 |
| MSM/OFP 线刷包 | 需 OPPO 授权账号，非公开路径 |

> 若拿不到 C.17 兼容的 recovery 镜像，路径 B 不可执行——这正是路径 A 应优先试的原因之一。

### 6.2 步骤

1. 取得 `recovery.img` 后，Magisk App → Install → Select and Patch a File → **勾选 "Recovery Mode"** → 补丁 recovery.img。
2. 刷写（`fastboot flash recovery magisk_patched-*.img`）+ 第 3 节 vbmeta 处理。
3. 之后**每次要用 Magisk 都必须用 recovery 按键组合启动**：
   - 正常开机 → 系统无 Magisk
   - 按键组合 → 出现 splash → **松开所有按键** → 带 Magisk 的系统
   - 按键组合 → 出现 splash → **长按音量上** → 真正的 recovery 模式
4. 该模式下 **不能用自定义 recovery 安装或升级 Magisk**（`docs/install.md` 明确说明）。

**已知副作用**：`Magisk#1801` 中 Nokia 1 Plus / Infinix / Redmi Note 8 Pro 等 A-only SAR 设备报告 install-to-recovery 后出现无信号 / IMEI 丢失；K3 是否受影响未知，需实测。

---

## 7. 不建议 / 排除的路径

| 路径 | 排除理由 |
|---|---|
| 复用 2019 Android 9 的 boot.img / TWRP 树 / patched 镜像 | 版本断层：跨 Android 大版本，内核、DTB、ramdisk、vbmeta 全变；`oppo-k3` 组织 8 仓库 pushed_at ≤ 2019-10-25，7 个最终版构建号 GitHub code search 全 0 |
| KingRoot / 免解锁提权 | SPL 2021-05-05，2019–2020 公开提权漏洞已封堵；官方固件标注 `Root access: Not` |
| MTK 系解锁工具（lkpatcher / oppo-mtk-fastboot-unlock） | 平台不匹配（K3 = sdm710 高通） |
| `avbtool --flags 3` 生成空 vbmeta | 丢弃全部 chain/property descriptor，OEM bootloader 可能拒绝；优先用"改写原 vbmeta 只动 flags" |
| 刷他人分享的 patched 镜像 / 在别的设备上补丁 | Magisk 官方明确警告，可能需全量擦数据才能恢复 |
| patch system 分区的 `/init` | GitHub 未发现同类可复现方案；且 system 受 `wait,avb` + dm-verity 保护，改动需重写 2.35 GB 镜像并重算 hashtree，代价远高于其它路径 |

---

## 8. 验证清单（刷写后）

```bash
adb wait-for-device
adb shell getprop ro.build.display.id          # 应仍为 PCGM00_11_C.17
adb shell getprop ro.boot.verifiedbootstate     # 期望 orange / unlocked 状态
adb shell getprop sys.boot_completed           # 1
adb shell getprop ro.build.version.security_patch  # 2021-05-05
adb shell id                                   # 需先通过 Magisk 授权 su
adb shell su -c 'id'                          # uid=0(root)
```
并在 Magisk App 首页确认：Installed 版本号、Ramdisk 状态、Zygisk 等。另建议核对 `adb shell getprop ro.boot.slot_suffix` 为空（A-only）。

若路径 B，还需分别在「正常开机」与「recovery 组合键开机」两种状态下验证 Magisk 是否只在后者生效。

---

## 9. 回退方案

**任何异常（卡第一屏 / bootloop / 无信号）都应立即回退，不要反复重试：**

```bash
adb reboot bootloader        # 或长按电源+音量键进 fastboot
fastboot flash boot firmware_C17_root/boot.img
fastboot flash vbmeta firmware_C17_root/firmware-update/vbmeta.img
fastboot reboot
```

- 回退前用 SHA256 校验两个原版文件未被改动（哈希见 2.3）。
- 若回退后仍无法启动，需用 OPPO 官方线刷包做全量恢复（不在本工作区物料范围）。
- 解锁本身不可逆地清空数据、失去保修；回退镜像不能恢复保修状态。
- 后续 OTA 在 root 状态下会中断；如需 OTA，先还原原版镜像。

---

## 10. 风险与未决项

| 项 | 状态 |
|---|---|
| 深度测试 2026 是否受理 K3 / 指定申请版本 | **未确认**，GitHub 无一手记录；是最可能的一票否决项 |
| K3 bootloader 是否接受 boot 内手工加入的 initramfs | **未实测**，决定路径 A 成败 |
| ABL 是否动态追加 `skip_initramfs`（静态镜像不可见） | **未实测**；内核内确有该字符串，Magisk hexpatch 有目标 |
| OPPO LK/ABL 是否严格实现 `VERIFICATION_DISABLED → descriptors not parsed` | **未实测**，决定 vbmeta 处理是否足够 |
| C.17 `system.new.dat.br` 内是否含 `recovery-from-boot.p` | **未验证**（需约 1.7 GB 顺序 brotli 解压）；决定路径 B 物料 |
| `build.prop` 具体属性 | 位于目标块 419,282，本次 32 MiB 前缀未覆盖，**未取得** |
| 国行 C 分支是否同样需要 bspatch 生成 recovery | **仍开放**（cfig 经验来自海外 A 分支 Android 9） |
| GitHub 未索引的二进制 patched boot / TWRP | 不在可检索范围，不能断言"不存在" |
| 无实机连接 | **本次未执行任何刷机/解锁操作**，全部结论止于静态分析 |

---

## 11. 本次交付

**已交付**
- `unpacked_C17/`：boot header / 内核 / 16 DTB / kernel config / initramfs / AVB 全解码 / system 前缀 / ext4 根目录 / 启动脚本 / Magisk 与 AVB 源码摘录，共 40+ 个产物
- `tools/`：5 个可复现解包与分析脚本（`deep_unpack.py`、`fdt_chosen.py`、`system_prefix_probe.py`、`ext4_root_probe.py`、`system_root_files.py`）
- `C17_深度解包与静态分析报告.md`：固件侧全部实测事实与对既有记录的勘误
- `github_research.md`：GitHub 一手资料核验（Magisk 源码/文档/issue、AVB/avbtool/fastboot 源码、cfig K3 专章与 Issue #17、RMX1901 同平台案例、深度测试政策）
- `C17_ROOT固件获取与核验记录.md` 第 11 节：AVB 数值与 ramdisk 解释的勘误

**未交付（且不应在本会话生成）**
- patched boot.img / patched recovery.img —— Magisk 官方要求在**目标设备本机**生成；无实机，且刷入他处生成的镜像有明确变砖警告
- 完整 `system.img` / `build.prop` —— 需顺序解压约 1.7 GB brotli，超出本次"局部下载"成本边界
- BL 解锁、刷写、启动验证 —— 无实机连接

---

## 12. 下一步（按优先级）

1. **确认解锁资格**：在实机上核对 `ro.product.model = PCGM00`、`ro.build.display.id` 为 C.17，安装深度测试 APP 查询审核状态；这一步决定整个目标是否可行。
2. **解锁并 dump**：解锁成功后先 dump `boot` / `vbmeta` / `recovery` 三个分区，补齐 recovery 物料。
3. **执行路径 A**（第 5 节），按第 8 节验证；失败立即回退。
4. 若 A 失败且已取得 recovery.img，执行路径 B（第 6 节）。
5. 若解锁不可行，则本目标在当前约束下判定为**不可达**，需等待/寻找解锁通道，不建议尝试免解锁提权或跨版本镜像。

---

## 13. 证据索引

| 结论 | 一手来源 |
|---|---|
| Magisk Type III / Recovery Mode / 自动新建 ramdisk / LEGACYSAR hexpatch | `topjohnwu/Magisk@master:docs/boot.md`、`docs/install.md`、`scripts/boot_patch.sh`、`scripts/util_functions.sh`、`native/src/boot/cpio.rs`；历史 tag v19.4 / v20.4 / v26.4 |
| A-only SAR 设备 patch boot 失败、改 patch recovery 成功 | `topjohnwu/Magisk#1801`（@bauner, 2019-10-14） |
| install-to-recovery 的基带/IMEI 副作用 | `topjohnwu/Magisk#1801` |
| `VERIFICATION_DISABLED → descriptors not parsed` | `GrapheneOS/platform_external_avb@17:libavb/avb_vbmeta_image.h` |
| fastboot 改写 flags 的实现 | `aosp-mirror/platform_system_core@main:fastboot/fastboot.cpp:rewrite_vbmeta_buffer()` |
| 官方 vbmeta 刷写命令 | `topjohnwu/Magisk@master:docs/install.md` step 6 |
| cfig K3 专章 / bspatch / 工具对 ramdisk_size=0 的处理 / 禁用 AVB | `cfig/Android_boot_image_editor@master:doc/additional_tricks.md`、`issues/17`(22 条评论)、`bbootimg/.../BootV2.kt`、`README.md` |
| 同平台 boot 内带 ramdisk 实测成功 | `ishashanknigam/kernel-realme-RMX1901` README "Packaging and Boot Image" / "Working / Verified Features" |
| 深度测试 2026 政策 | `zenfyrdev/bootloader-unlock-wall-of-shame@brands/oppo/README.md`、`awesome-android-root@docs/rooting-guides/how-to-unlock-bootloader.md` |
| 2021 年后无 C.17 适配仓库 | `github_research.md` §8（7 个最终版构建号 code search 全 0） |

> 完整 URL 与检索统计见 `github_research.md` §10；固件侧原始数值见 `unpacked_C17/*.json` 与 `C17_深度解包与静态分析报告.md`。
