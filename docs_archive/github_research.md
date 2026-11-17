# OPPO K3 (PCGM00 C.17) ROOT：GitHub 一手资料核验报告

- 执行者：github-researcher（研究子代理）
- 日期：2026-11-12
- 输入：主代理已落盘的 C.17 固件静态分析结论（boot header v1 / ramdisk_size=0 / Image.gz+16 DTB / 无 cpio / 无 skip_initramfs / AVB footer / 5 个 chain partition descriptor / ozip 分块加密）
- 方法：`gh api`（账号 kipcloud120，core 5000/h、search 30/min、code search 10/min，已节流）拉取 `contents` / `git/trees` / `issues` / `issues/comments` / tag 历史文件，base64 解码核验**原文**；辅以 `search/repositories`、`search/issues`、`search/code` 定位。
- 本报告**只做研究与写这一个文件**，未修改工作区其它文件，未执行任何刷机/解锁/下载大文件操作。

## 证据等级

| 标记 | 含义 |
|---|---|
| 【实】 | 已拉取一手源码/文档/issue 原文并核验 |
| 【源】 | 仅检索摘要或搜索命中统计，未逐条读原文 |
| 【推】 | 基于【实】的推断，需实测 |

**范围区分**：§2–§5 的 Magisk/AVB 部分多为「通用 Android 机制」（对本机适用但非本机实测）；§6、§7 的 RMX1901、cfig K3 为「同平台/本机近亲已验证经验」；凡 2019 Android 9 资源一律标注版本断层，不作为 C.17 可用方案。

---

## 0. 结论摘要（先读这里）

1. **本机在 Magisk 官方分类里是 Type III 设备**（Legacy SAR + A-only + boot 内无 ramdisk）。判据：出厂 Android 9（LV=28）→ Method B/Legacy SAR，A-only 单槽，运行 Android 10（RV=29），boot 无 ramdisk。Magisk `docs/boot.md` 原话称 Type III 是 **"The worst type of device to ever exist as far as Magisk is concerned"**。【实，§2.2】

2. **Magisk 官方对 Type III 的主路径不是 patch boot.img，而是 patch recovery.img + "Recovery Mode"（install to recovery）**：正常开机无 root，每次须用 recovery 按键组合启动才有 root。【实，§2.2/§2.3】

3. **但 Magisk 的 `boot_patch.sh` 从 v20.4 起在"无 ramdisk"时并不报错，而是自动新建一个 ramdisk**（`magiskboot cpio` 对不存在的 `ramdisk.cpio` 会 `Cpio::new()` 创建空 cpio 再塞入 `magiskinit`）；v26.4 起增加 `LEGACYSAR` 的 `skip_initramfs → want_initramfs` 内核 hexpatch；master 明确注释 "No ramdisk found, create one from scratch"。【实，§2.1】

4. **能否"塞进 boot 就生效"取决于 OEM bootloader**。Magisk 文档明确：部分 Type III 设备 bootloader 仍接受手动塞入 boot 的 initramfs（已知仅部分小米），多数不接受（如三星 S10/Note10），"It solely depends on how the OEM implements its bootloader"。【实，§2.2】

5. **本次检索最有价值的新发现**：同平台 realme X / RMX1901（sdm710、Android 10、ColorOS 7.2）2026 年仓库**实测验证** `boot = raw kernel Image + stock 17-DTB container + Magisk root ramdisk`，经 TWRP `dd` 刷入后 Android 正常启动且 root 可用。这与本机 `Image.gz + 16 DTB` 结构高度同构，**暗示 K3 bootloader 很可能也接受 boot 内 ramdisk**，即"直接 patch C.17 的 boot.img"在本机可能可行。【实（对方平台）/ 推（迁移到 K3），§6.1】

6. **本机两个削弱标准结论的特殊点**：(a) cmdline **无 `skip_initramfs`**，Magisk 的 LEGACYSAR hexpatch 前提在本机不成立，其必要性/有效性存疑；(b) 静态分析确认 C.17 OTA 无独立 `recovery.img` / `recovery-from-boot.p`，官方"patch recovery"路径的物料前提未证实。【推，§9】

7. **AVB**：改 boot 必破坏 hash 校验（主代理已实测 `sha256(salt||boot[0:16609280])` 一致）。官方命令 `fastboot flash vbmeta --disable-verity --disable-verification vbmeta.img` 的原理是 fastboot 在刷入前把 vbmeta 的 flags（偏移 120）改成 3；其中 `VERIFICATION_DISABLED` 使 **"descriptors will not be parsed"**，从而 5 个 chain partition descriptor 不再被跟进，理论上足以绕过 boot 校验。【实，§5】

8. **解锁、物料、社区三方面均无 C.17 现成方案**：GitHub 无 `OPPO_K3_DeepTesting.apk` 仓库、无 2021 后针对 C.17/F.13/ColorOS 7.1 的 patched boot / TWRP / root 脚本（构建号 code search 全 0）；深度测试 2026 年"Very limited model support"、仅国行、7 天等待；K3 的"指定申请版本"未见公开记录。【实/源，§7、§8】

> 第二轮补充（team-lead 追加 A–D，详见 §12）：
9. **recovery.img 来源已打通（§12.A）**：AOSP `MakeRecoveryPatch` 证实 `recovery-from-boot.p` 是 recovery/boot 差分补丁、位于 **system 分区内**、由 `install-recovery.sh` 的 `applypatch` 首次开机生成 recovery；`rmdIX/RealMeRecoveryMaker`（2020，OPPO/realme 系）给出**可迁移到 C.17 .ozip 的完整流程**（ozipdecrypt→brotli→sdat2img→`/system/recovery-from-boot.p`→bspatch）。故"OTA 顶层无该文件"不代表 system 内没有，C.17 是否含补丁仍待 `system.new.dat.br` 解包验证。【实+推】
10. **boot 路径有正例也有反例（§12.B）**：Magisk PR #1102 正文「patch kernel to make it want_initramfs, and add stub ramdisk」+ 红魔 Mars 实测成功，证明 Type III 设备"手工加 ramdisk 刷 boot"确实可生效；但 @vvb2060 明确"非标准的改不了内核就完蛋（EMUI9）"，反例有三星 S10/Note10、Nokia 1 Plus、Redmi Note 8 Pro。**未找到 K3/OnePlus 6/7/realme X 官方固件上的已验证实例**；结合同平台 RMX1901 正例，建议先试 boot 路径、失败转 recovery。【实/推】
11. **AVB 刷 flags=3 顶层 vbmeta 足以全局关闭（§12.C）**：`avb_slot_verify.c:972-990` 证实 VERIFICATION_DISABLED 时直接 `goto out`，5 个 chain partition descriptor 全不解析 → **无需逐分区处理**；`--disable-verity` 单独不够；给 boot 内嵌（chained）vbmeta 设 flags 会触发 `ERROR_INVALID_METADATA`。【实，标准 libavb 语义；OPPO 实现待实测】

---

## 1. 方法与检索覆盖

- 核验的仓库/组织：`topjohnwu/Magisk`（master + 16 个历史 tag）、`cfig/Android_boot_image_editor`、`GrapheneOS/platform_external_avb`@17、`AndroidBootloader/platform_external_avb`@master、`aosp-mirror/platform_system_core`@main、`ishashanknigam/kernel-realme-RMX1901`、`monster8d/RMX1901-Flash_Tool`、`zenfyrdev/bootloader-unlock-wall-of-shame`、`awesome-android-root/awesome-android-root`、`Crazer-Shifter84/OPlus-BootLoader-Unlock`、`Droidspaces/droidspaces-recovery-hack-example`、`Shocked-Cat/oppo-mtk-fastboot-unlock`、`R0rt1z2/lkpatcher`、`Tintarul/oppo-workaround`。
- Issues 命中统计（`search/issues`，`repo:topjohnwu/Magisk ... is:issue`）：`"no ramdisk"`=191、`"legacy SAR"`=46、`"install to recovery"`=164、`"Unable to find ramdisk"`=1（#7159）。已逐条核验 #8297 / #7390 / #1801 / #10006 正文，并全量抓取 `cfig` Issue #17 的 22 条评论。【实】
- 检索式（仓库/代码/Issues）约 30 次；`search/code` 前加 `sleep 7` 节流，未触发限流。

---

## 2. Q1｜Magisk 对「boot.img 没有 ramdisk」到底怎么处理

### 2.1 源码：会「自动新建 ramdisk」，不是报错不支持

**`topjohnwu/Magisk@master:scripts/boot_patch.sh`**（Ramdisk Checks 段，原文）【实】：

```sh
#################
# Ramdisk Checks
#################

unset RAMDISK
for path in ramdisk.cpio vendor_ramdisk/init_boot.cpio vendor_ramdisk/ramdisk.cpio; do
  if [ -e $path ]; then
    RAMDISK=$path
    break
  fi
done

ui_print "- Checking ramdisk status"
if [ -n "$RAMDISK" ]; then
  ./magiskboot cpio $RAMDISK test
  STATUS=$?
  SKIP_BACKUP=""
else
  # No ramdisk found, create one from scratch
  RAMDISK=ramdisk.cpio
  # Could be stock A only legacy SAR, or some Android 13 GKIs
  STATUS=0
  SKIP_BACKUP="#"
fi
```

随后无论有无原 ramdisk，都会执行同一段注入：【实】

```sh
./magiskboot cpio $RAMDISK \
"add 0750 init magiskinit" \
"mkdir 0750 overlay.d" \
"mkdir 0750 overlay.d/sbin" \
"add 0644 overlay.d/sbin/magisk.xz magisk.xz" \
"add 0644 overlay.d/sbin/init-ld.xz init-ld.xz" \
"patch" \
"$SKIP_BACKUP backup ramdisk.cpio.orig" \
"mkdir 000 .backup" \
"add 000 .backup/.magisk config" \
|| abort "! Unable to patch ramdisk"
```

**`magiskboot` 内部坐实「新建」**：`topjohnwu/Magisk@master:native/src/boot/cpio.rs:769-778`【实】：

```rust
pub(crate) fn cpio_commands(file: &Utf8CStr, cmds: &Vec<String>) -> LoggedResult<()> {
    let mut cpio = if file.exists() {
        Cpio::load_from_file(file)?
    } else {
        Cpio::new()          // ← 文件不存在 → 空 cpio
    };

    for cmd in cmds {
        if cmd.starts_with('#') {   // ← 解释 SKIP_BACKUP="#"：以 # 开头的命令被跳过
            continue;
```

即：`ramdisk.cpio` 不存在 → 新建空 cpio → `add 0750 init magiskinit` 写入 `/init`。`SKIP_BACKUP="#"` 把 `backup ramdisk.cpio.orig` 变成注释行跳过（无原 ramdisk 可备份）。

**LEGACYSAR 的内核补丁**（`boot_patch.sh` Binary Patches 段）【实】：

```sh
# Force kernel to load rootfs for legacy SAR devices
# skip_initramfs -> want_initramfs
$LEGACYSAR && ./magiskboot hexpatch kernel \
736B69705F696E697472616D667300 \   # "skip_initramfs\0"
77616E745F696E697472616D667300 \   # "want_initramfs\0"
&& PATCHEDKERNEL=true
```

原理是把内核 `__setup` 注册的 key 字符串由 `skip_initramfs` 原地等长替换为 `want_initramfs`，使内核忽略 bootloader/cmdline 传来的"跳过 initramfs"指令，从而加载 boot 中新建的 Magisk ramdisk。**注意：本机 cmdline 实测无 `skip_initramfs`，此补丁的前提在本机不成立**（详见 §9）。

**脚本头部声明的环境变量**【实】：`KEEPVERITY, KEEPFORCEENCRYPT, PATCHVBMETAFLAG, RECOVERYMODE, LEGACYSAR`。

### 2.2 文档：Type III 的官方定性 → 主路径是 recovery

**`topjohnwu/Magisk@master:docs/boot.md`**【实】——决定本机分类：

> - **Method B - Legacy SAR**: ... The kernel directly mounts the `system` partition as rootdir and exec `/init` to boot.
>   - Devices with `(LV = 28)` ... OnePlus: 6 - 7
> - **Method C - 2SI ramdisk SAR**: ... Devices with `(LV >= 29)`; Devices with `(LV < 28, RV >= 29)`, excluding those that were already using Method B
> - "**Method B devices are stuck with Method B**"

> | **III** | B | A-only | Any | ***N/A*** |
> - **Type III**: Late 2018 - 2019 devices that are A-only. **The worst type of device to ever exist as far as Magisk is concerned.**

> "Further details on Type III devices: Magisk is always installed in the ramdisk of a boot image. For all other device types, because their boot partitions ... have ramdisk included, Magisk can be easily installed by patching the image through the Magisk app. However for Type III devices, they are **limited to installing Magisk into the `recovery` partition**. Magisk will not function when booted normally; instead Type III device owners have to always reboot to recovery to maintain Magisk access."

> "Some Type III devices' bootloader will still accept and provide `initramfs` that was manually added to the `boot` image to the kernel (e.g. some Xiaomi phones), but many devices don't (e.g. Samsung S10, Note 10). **It solely depends on how the OEM implements its bootloader.**"

**本机套用**：K3 2019-05 出厂 Android 9（LV=28）、A-only 单槽、现 RV=29、boot 无 ramdisk → 完全落在 **Type III**（Method B / A-only / ramdisk in boot = N/A）。【实+推】

**`docs/install.md`**【实】：

> "The result of **Ramdisk** determines whether your device has ramdisk in the boot partition. If your device does not have boot ramdisk, read the [Magisk in Recovery](#magisk-in-recovery) section before continuing."
> "_(Unfortunately, there are exceptions as some devices' bootloader accepts ramdisk even if it shouldn't. ... only some Xiaomi devices are known to have this property ...)_"
> "If your device has boot ramdisk, you need to patch the partition image that contains the ramdisk (`boot.img`, `init_boot.img`, or `vendor_boot.img`). **If your device does NOT have boot ramdisk, you need to patch `recovery.img`.**"
> "Patching Images → 2. If you are patching a recovery image, check the **"Recovery Mode"** option"

**「Magisk in Recovery」完整机制**【实】：

> "In the case when your device does not have ramdisk in boot images, Magisk has no choice but to hijack the recovery partition. For these devices, you will have to **reboot to recovery** every time you want Magisk enabled."
> - (Power up normally) → (System with NO Magisk)
> - (Recovery Key Combo) → (Splash screen) → (Release all buttons) → (System with Magisk)
> - (Recovery Key Combo) → (Splash screen) → (Long press volume up) → (Recovery Mode)
> "(Note: You **CANNOT** use custom recoveries to install or upgrade Magisk in this case!!)"

**`docs/details.md`**【实】："On legacy system-as-root devices, `magiskinit` switches root to `/system`." —— magiskinit 对 legacy SAR 的接管方式。

### 2.3 版本演化（逐 tag 核验 `scripts/boot_patch.sh` 原文）【实】

| 版本 | 关键事实 |
|---|---|
| v18.1 | 已有 `# skip_initramfs -> want_initramfs` hexpatch；但 ramdisk 检查直接 `./magiskboot --cpio ramdisk.cpio test`，无"无 ramdisk"分支 |
| v19.0 | 出现 `if [ -e ramdisk.cpio ]; then ...` |
| **v19.4** | 引入 `RECOVERYMODE`（`[ -f recovery_dtbo ] && RECOVERYMODE=true`），头部注释含 `RECOVERYMODE` |
| **v20.4** | `if [ -e ramdisk.cpio ]; then ... else # Stock A only system-as-root; STATUS=0 fi` —— **首次把"boot 无 ramdisk"当作合法 stock 情况，不报错**；后续统一对 `ramdisk.cpio` 执行 `add 0750 init magiskinit`（magiskboot 会自动新建） |
| v21.x–v25.2 | 逻辑延续，注释仍为 "Stock A only system-as-root"；`RECOVERYMODE` 保留 |
| v26.0 | 注释改为 "Stock A only legacy SAR, or some Android 13 GKIs"；仍无 `SKIP_BACKUP` |
| **v26.4** | 新增 `LEGACYSAR` 环境变量、`SKIP_BACKUP=""` / `SKIP_BACKUP="#"`；hexpatch 改为 `$LEGACYSAR && ./magiskboot hexpatch kernel ... skip_initramfs→want_initramfs` |
| v27.0 / v28.0 / v29.0 / v30.0 | 与 v26.4 同构 |
| master (v31.x, pushed 2026-11-10) | 注释明确为 "# No ramdisk found, create one from scratch"，并引入 `RAMDISK` 变量与 `vendor_ramdisk/init_boot.cpio` 探测 |

**结论**：「自动新建 ramdisk / 不报错」自 **v20.4（2020 年初）** 起即具备；「Recovery Mode / install to recovery」自 **v19.4** 起；「LEGACYSAR 内核 hexpatch」自 **v26.4** 起。当前 master（v31.x）三者齐全。【实】

### 2.4 Issues / Discussions 讨论（核验原文）

- `topjohnwu/Magisk#1801`（2019-08-29, closed, 29 评论）**"No signal on MTK A-only SAR with recovery mode Magisk"**【实】：
  - @S190762（2019-08-30）："It is a Nokia 1 Plus running Android 9 Go Edition. It came with Android 9 so has A only system-as-root. **The boot.img doesn't contain a ramdisk and magisk doesn't work if i try to patch the boot.img**" —— A-only SAR 设备直接 patch boot.img 失败的实证。
  - @bauner（2019-10-14）："I used magisk manager to patch the stock boot.img **with the recovery option and dm-verity off** and flashed it with fastboot **to the recovery partition (any other option caused a bootloop)**" —— **可复现的正确做法**，且指出其它选项导致 bootloop。
  - 副作用：该 issue 报告 install-to-recovery 后无信号/无 IMEI（Nokia 1 Plus、Infinix Smart 3 Plus、Redmi Note 8 Pro 均有人跟帖）。对 K3 是风险提示。
- `topjohnwu/Magisk#10006`（2026-08-09, closed）【实】：日志出现 `magiskinit: Legacy SAR Init` / `Cannot find root partition, abort` → 内核 panic bootloop，说明 magiskinit 内确有 Legacy SAR 分支，且 recovery 启动路径对启动标志敏感。
- `topjohnwu/Magisk#7159`（closed）【实】：OnePlus 11 报 `"Unable to patch ramdisk"` / `"No boot image found"` —— 属"无法定位/修补 ramdisk"类错误的实例。
- `#8297`（Nvidia Shield darcy）、`#7390`（A95XF1 Android 13）为通用 patch-boot 后不启动案例，与"无 ramdisk"非直接因果，仅作旁证。【实】

### 2.5 社区指南交叉印证（2026 维护）

`awesome-android-root/awesome-android-root@docs/rooting-guides/magisk-guide.md`【实】：

> "If there is no boot ramdisk, Magisk may need `recovery.img` and a special boot sequence. Read Magisk in Recovery first."
> "Select **Recovery Mode** only when following the recovery-image installation path, not merely because a custom recovery is installed."
> "Custom recovery method ... **cannot** install or upgrade Magisk when Magisk must be installed in recovery."
> "Keep the encryption and **AVB/dm-verity preservation defaults** unless verified device-specific instructions explain a change and its risks."

---

## 3. Q2｜legacy SAR / 无 ramdisk 设备的实际 root 案例

### 3.1 通用做法（对本机适用，非本机实测）【实】

| 做法 | 一手出处 | 要点 |
|---|---|---|
| 新建 ramdisk 塞回 boot | `topjohnwu/Magisk@scripts/boot_patch.sh` + `native/src/boot/cpio.rs` | magiskboot 自动新建 cpio + 注入 magiskinit；`repack` 重建 boot 头补回 `ramdisk_size` |
| 强制内核加载 ramdisk | 同上 `LEGACYSAR` hexpatch | `skip_initramfs`→`want_initramfs`（等长替换，14 字节） |
| 改走 recovery | `docs/install.md` "Magisk in Recovery" + `Magisk#1801` @bauner | 勾选 Recovery Mode + dm-verity off，patch 后刷 **recovery 分区**；每次按键组合启动 |
| 处理 vbmeta | `docs/install.md` step 6（见 §5） | `fastboot flash vbmeta --disable-verity --disable-verification vbmeta.img` |

### 3.2 同平台（sdm710 / Android 10 / ColorOS 7.x）已验证案例【实，最重要的新发现】

`ishashanknigam/kernel-realme-RMX1901`（2026-10-03 创建，NetHunter 内核，Linux 4.9.186 / Android 10 / ColorOS 7.2 / Snapdragon 710）README **"Packaging and Boot Image"** 段：

> "Kernel compilation produces the raw kernel and modules; it does not by itself create a flashable boot image.
> For the documented V3.11 Core validation workflow, packaging used:
> ```
> raw kernel Image
> + stock 17-DTB container
> + Magisk root ramdisk
> = boot image
> ```
> The validated V3.11 Core artifact was then flashed to a live RMX1901 through TWRP using `dd` and boot-tested on Android 10 / ColorOS 7.2."

验证表（"Working / Verified Features"）：Android boot ✅ Verified、`sys.boot_completed=1` ✅、SELinux Enforcing ✅、**Root / NetHunter root context ✅ Verified**、WLAN/BT/MTP/ADB ✅。产物 `out-boot/boot-nethunter-v3-11-core.img`，SHA-256 `3f91d5ff…f5d2`；raw kernel Image 34,168,840 字节。

**对 K3 的意义**【推，依据充分】：
- 该仓库与 K3 共平台：`oppo-k3/android_device_OPPO_CPH1955` TWRP 树派生自 `mauronofrio/android_device_realme_RMX1901`（主代理汇总已核验）。
- 其 "kernel + DTB container + ramdisk" 与本机 `Image.gz + 16 个追加 DTB` 高度同构（对方 17 个 DTB）。
- **它实证了 sdm710/ColorOS 7.2 的 bootloader 接受"boot 分区内带 ramdisk"的镜像** → 直接回应 `docs/boot.md` 对 Type III 的"取决于 OEM bootloader"疑问，**倾向支持"在 K3 上直接 patch boot.img（新建 ramdisk）可行"**，这比官方保守的"必须 patch recovery"更值得先试。
- **限制**：这是自定义 NetHunter 内核 + TWRP + 重签名（自带 `verity_dev_keys.x509`），并非"官方 ColorOS 7.2 原版 boot 直接补 ramdisk"；raw `Image` 未压缩 vs 本机 `Image.gz`。仍需 K3 实测。

### 3.3 OPPO K3 本机的 `recovery-from-boot.p` bspatch 做法【实，但属 2019 Android 9】

`cfig/Android_boot_image_editor@doc/additional_tricks.md` 的 `## K3 (CPH1955)`（详见 §4.1）：用 `bspatch boot.img recovery.img system/recovery-from-boot.p` 从 boot + 差分补丁生成 recovery.img。

- `recovery-from-boot.p` 是 AOSP/厂商 OTA 通用机制（`USES_RECOVERY_AS_BOOT` 相关），`recovery-from-boot.p bspatch` 的 code search 有 79 命中（`jamflux/URTool`、`Pzqqt/Generic_OTA_Package_Generation_Script`、`rajkale99/atools` 等 OTA 工具链），说明做法本身通用。【实/源】
- **但 C.17 上物料前提未证实**：主代理静态分析确认 235 条 OTA 条目中无 `recovery.img` 与独立 `recovery-from-boot.p`，`system.new.dat.br`（2.35 GB）未取、内部未验证。【实，来自主代理汇总 §9.3】

### 3.4 未发现项

- 未发现针对 **OPPO / realme / 一加 ColorOS 7 (Android 10) sdm710** 且"patch system 分区 `/init`"的可复现脚本/issue。Magisk 官方路径是新建 ramdisk 或 patch recovery，不改 system 的 /init。【源：检索未命中】
- 未发现把 `ramdisk_size` 手动补回 header 的独立脚本；但 `magiskboot repack` 与 `cfig pack()` 都会自动重算 header（见 §4.3），无需手工补丁。【实】

---

## 4. Q3｜cfig/Android_boot_image_editor 的 K3 专章与 Issue #17 原文

### 4.1 `doc/additional_tricks.md` 的 K3 段落（全文）【实】

```markdown
## K3 (CPH1955)

`boot.img` extracted from OTA zip file doesn't work properly but `recovery.img` works fine.
In order to obtain `recovery.img`, a `bsdiff` patch from `system/recovery-from-boot.p`
is applied to `boot.img`. Ex: ```bspatch boot.img recovery.img system/recovery-from-boot.p```

This part is contributed by @Surendrajat, thanks!
```

来源：`cfig/Android_boot_image_editor@master:doc/additional_tricks.md`（由 PR #32 加入）。

### 4.2 Issue #17 全量核验（22 条评论）【实】

Issue #17 标题 **"compatibility check: verify as many ROMs and devices as possible"**，cfig 于 2018-05-21 创建，是**兼容性登记帖**，不是 root/magisk 专帖。与 K3 相关的仅 4 条：

| 时间 | 用户 | 原文要点 |
|---|---|---|
| 2019-09-21 | @surendrajat | "Confirmed working with **Oppo K3(CPH1955)** `recovery.img` (with some tricks - to get `recovery.img` out from `boot.img` using a bsdiff patch under system because didn't work with `boot.img`)" |
| 2019-09-22 | @cfig | 表格登记 "K3 (CPH1955) \| OPPO \| Y (recovery.img) \| ??? \| [tricks]"，索要 Android 版本 |
| 2019-09-22 | @surendrajat | **"Absolutely. Pie it is. I will open a PR for tricks about how to get `recovery.img`."** |
| 2019-09-22 | @surendrajat | "@cfig Done #32" |

**关键澄清（纠正背景里"Issue #17 有 CPH1955 root/magisk 讨论"的说法）**：Issue #17 中**没有**针对 CPH1955 的 root/Magisk 讨论。magisk / AVB 相关讨论来自 **2021–2023 年的其它设备**（Topway TS10 车机、Redmi K30 4G、Galaxy S22+ vendor_boot），与本机型无关。其中较有价值的通用讨论：

- @eebssk1（2021-05-28）："**Magisk directly patch the kernel to force load the ramdisk.** It's not very recommended to modify magisk patched image with these tool." —— 印证 §2.1 的 kernel hexpatch。
- @eebssk1（2021-04-10）："Xiaomi Redmi K30 4g ... **boot.img with vbmeta.img modification works**."
- @cfig（2021-05-31）：给出禁用 AVB integrity check 的补丁（把 `Avb.kt` 的 `throw IllegalArgumentException(...failed integrity check...)` 改为 `log.error(...)`），并指出："**magisk patched boot.img can not pass AVB integrity check, but it doesn't matter if bootloader is unlocked, as the bootloader should always load the image for unlocked devices.**" —— 用 cfig 重打包 Magisk 补丁镜像时会撞到 AVB 完整性校验；解锁 BL 后该校验失败通常不阻止启动（通用经验，OEM 实现需实测）。
- @mariodantas（2021-05-28）报 TS10 车机用 magisk patched image 无法启动。

### 4.3 对国行 C.17 是否适用 + 工具能否处理 ramdisk_size=0

**适用性判定**【实+推】：
- **不适用（不能直接套用）**：该专章经 Issue #17 确认是 **Android 9 "Pie"**、`CPH1955` 海外版，2019 年 A 分支；C.17 是国行 `PCGM00`、Android 10、ColorOS 7.1、2021 年 C 分支，跨一个大版本且地域不同。主代理汇总已指出 `oppo-k3` 组织全部资源 ≤ 2019-10、build.prop `release=9`，7 个最终版构建号 GitHub code search 全 0。
- **物料前提待验证（已按 §12.A 修订）**：C.17 OTA 顶层确无 `recovery.img` / 独立 `recovery-from-boot.p`，但按 AOSP `MakeRecoveryPatch` 机制这**属预期行为**——补丁文件位于 `system.new.dat.br` 解包后的 `/system/recovery-from-boot.p`（`rmdIX/RealMeRecoveryMaker` 源码实证），并非 OTA 顶层条目。`system.new.dat.br`（2.35 GB）未取，故 C.17 是否含该补丁**仍未验证**，不能断言缺失。获取路径见 §12.A-4。
- **但方向互相印证**：专章说"boot.img 不能正常工作、recovery.img 可用"，与 Magisk 对 **Type III** 设备"必须 patch recovery"的官方结论一致——即 K3 早期版本就属于无 boot ramdisk 的 Type III 设备。这对判断 C.17 机型属性有参考价值，但**不是**可直接执行的 C.17 root 方案。

**工具能否解包/重打包 `ramdisk_size=0` 的 boot.img**【实，核验源码 `bbootimg/src/main/kotlin/bootimg/v2/BootV2.kt`】：

- 解析（第 143 行）：`if (bh2.ramdiskLength > 0) { theRamdisk.file = File(workDir(), "ramdisk.img").path }` —— 只有 >0 才登记 ramdisk 文件。
- 解包（第 224 行）：`if (this.ramdisk.size > 0) { val fmt = C.dumpRamdisk(...) ... }` —— **size=0 时整段跳过，不会尝试解压空 ramdisk，不会报错**。
- 重打包 `pack()`（第 442–455 行）：`if (this.ramdisk.file.isNullOrBlank()) { ramdisk.file = null; ramdisk.loadOffset = 0 } else { ... this.ramdisk.size = File(this.ramdisk.file!!).length().toInt() }`；构造 header 时 `ramdiskLength = ramdisk.size`（第 418 行）。→ **只要把补好的 cpio 放到 `ramdisk.img.gz`/`root/` 并更新 json，工具会自动重算并写回 `ramdisk_size`、重排 second/dtbo 偏移**（`getSecondBootloaderPosition()` 依赖 `ramdisk.size`），即"把 ramdisk_size 补回去"在工具层面可行。
- README 另支持 "using pre-packed ramdisk.img.gz：place `ramdisk.img.gz` in directory, delete `root/`, program will use it as prebuilt"（`doc/additional_tricks.md`）。

**重打包的 AVB 后果**【实】：cfig README 说明 pack 输出为 `boot.img.signed`、`vbmeta.img.signed`，"**Your boot.img.signed and vbmeta.img.signd will be updated together, then you can flash them to your device**"，且要求镜像遵循 "AOSP verified boot flow, either Boot image signature in VBoot 1.0 or **AVB HASH footer** in VBoot 2.0"。即 cfig 会用自带 test key 重签，**原厂 AVB 签名必然失效**，需配合 §5 的禁用验证。README 还给出专章 **"How to disable AVB verification"**：

> "The idea is to set flag=2 in main vbmeta."
> ```
> rm *.img
> cp <your_vbmeta_image> vbmeta.img
> ./gradlew unpack
> vim -u NONE -N build/unzip_boot/vbmeta.avb.json -c ":19s/0/2/g" -c ":wq"
> ./gradlew pack
> ```
> "Then flash vbmeta.img.signed to your device."

（注：这里用 flag=2 仅 `VERIFICATION_DISABLED`；`fastboot --disable-verity --disable-verification` 得到 flags=3，见 §5。）

---

## 5. Q4｜AVB / vbmeta 处理的一手依据

### 5.1 官方命令（Magisk 文档）【实】

`topjohnwu/Magisk@master:docs/install.md` "Patching Images" step 6：

> "(Optional) If your device has a separate `vbmeta` partition, you can patch the `vbmeta` partition with command:
> `fastboot flash vbmeta --disable-verity --disable-verification vbmeta.img` (note that it may **wipe your data**)"

### 5.2 flags 的权威定义【实】

`GrapheneOS/platform_external_avb@17:libavb/avb_vbmeta_image.h:51-62`：

```c
/* Flags for the vbmeta image.
 *
 * AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED: If this flag is set,
 * hashtree image verification will be disabled.
 *
 * AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED: If this flag is set,
 * verification will be disabled and descriptors will not be parsed.
 */
typedef enum {
  AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED = (1 << 0),
  AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED = (1 << 1)
} AvbVBMetaImageFlags;
```

→ **flags=3 = 1|2**：既禁用 hashtree（dm-verity），又禁用整个 verification 且 **"descriptors will not be parsed"**。
同文件第 174-177 行：`flags` 字段注释 "**This must be set to zero if the vbmeta image is not a top-level image**" —— 解释了本机独立 vbmeta.img（顶层）与 boot 内嵌 vbmeta（被 chain）实测 flags 均为 0。

### 5.3 fastboot 到底做了什么【实】

`aosp-mirror/platform_system_core@main:fastboot/fastboot.cpp`：
- 第 110-111 行：`static bool g_disable_verity / g_disable_verification`。
- 第 637-638 行（usage）：`" --disable-verity  Sets disable-verity when flashing vbmeta."` / `" --disable-verification  Sets disable-verification when flashing vbmeta."`
- 第 1110 行起 `rewrite_vbmeta_buffer()`：**在刷入前本地改写 vbmeta 镜像内容**（不是刷"空 vbmeta"）：

```cpp
// There's a 32-bit big endian |flags| field at offset 120 where
// bit 0 corresponds to disable-verity and bit 1 corresponds to
// disable-verification.
// See external/avb/libavb/avb_vbmeta_image.h for the layout of
// the VBMeta struct.
uint64_t flags_offset = 123 + vbmeta_offset;
if (g_disable_verity)        data[flags_offset] |= 0x01;
if (g_disable_verification)  data[flags_offset] |= 0x02;
```

→ **保留原 vbmeta 的全部 descriptors（含 5 个 chain partition descriptor），只把 flags 从 0 改成 3**（`vbmeta_in_boot=true` 时还会从 boot.img 的 AVB footer 定位 vbmeta 偏移，兼容"vbmeta 内嵌在 boot"的设备）。

### 5.4 chain partition descriptor 的语义与本机额外约束【实】

`GrapheneOS/platform_external_avb@17:README.md`（The VBMeta struct / 链式分区）：

> "This setup allows the bootloader to use the **chain partition descriptor** to find the footer at the end of the partition (using the name in the chain partition descriptor) which in turns helps locate the VBMeta struct and verify that it was signed by `key1` (using `key1_pub` stored in the chain partition descriptor). Crucially, because there's a footer with the offset, the `xyz` partition can be updated without the `vbmeta` partition needing any changes."
> "For a chained partition descriptor its contents is compared against content that needs to be passed in via the `--expected_chain_partition` options. If there is no ... the check fails."
> "If this image has one or more chain partition descriptors, the same logic as the `verify_image` command is used to load files for these ... Once all vbmeta structs have been loaded, the digest is calculated"

`avbtool.py`（同仓库 @17）：
- `make_vbmeta_image` 的 `--chain_partition part_name:rollback_index_location:/path/to/key`（README 第 412 行）。
- `avbtool.py:5090` `sub_parser.add_argument('--flags', help='VBMeta flags', type=parse_number, default=0)`；`5129-5133` 行 `--set_hashtree_disabled_flag` / `--set_verification_disabled_flag` 分别 `args.flags |= AVB_VBMETA_IMAGE_FLAGS_*` → **用 `avbtool make_vbmeta_image --flags 3` 生成空 vbmeta 是一手可查的合法路径**。

**本机（5 个 chain partition descriptor：boot / system / vendor / dtbo / recovery）的约束链条**【实+推】：

1. 校验链：bootloader 读 `vbmeta` 分区 → 解析 5 个 chain descriptor → 对每个被链接分区（含 `boot`）读其尾部 AVB footer → 用 descriptor 内嵌 RSA 公钥验证该分区内嵌 vbmeta 的签名 → 再按内嵌的 hash descriptor 校验整个分区内容。
2. 主代理已实测 `sha256(salt || boot[0:16609280])` 与 boot 内嵌签名摘要**完全一致** → **任何 boot 改动都会破坏这条链**，且因为 chain descriptor 使 boot 自带"就地校验"，**单独改 boot 而不动 vbmeta 必失败**。
3. 刷 `flags=3` 的顶层 vbmeta 后，按 `avb_vbmeta_image.h` 的 `VERIFICATION_DISABLED` 语义，**descriptors will not be parsed** → chain descriptors 不再被跟进 → 理论上不再校验 boot 内嵌 vbmeta → **刷一次（改写 flags 后的）vbmeta 应足够**。【推，基于标准 libavb 语义；OPPO LK/ABL 是否严格遵循需实测】
4. **额外约束/风险**：
   - 若改用 `avbtool --flags 3` 生成**空 vbmeta**（无 descriptors），除 flags 外还丢弃了全部 chain descriptors 与 property descriptors（本机含 `com.android.build.boot.os_version=10`、`security_patch=2021-05-05`）；部分 OEM bootloader 会校验 rollback index / 要求特定 descriptors 存在，可能拒绝启动。**通常不如"改写原 vbmeta 只动 flags"稳妥**。【推】
   - `fastboot` 改写 flags 时若 `has_vbmeta_partition()` 判定存在 vbmeta 分区才生效；本机确有独立 `vbmeta.img`（8192 B）。【实】
   - `docs/install.md` 警告该操作 "may wipe your data"；`docs/install.md` Samsung 章节还警告 "**Never, ever** try to restore either `boot`, `init_boot`, `recovery`, or `vbmeta` partitions back to stock!"（三星专属，但说明 vbmeta 改动有变砖风险）。
   - `cfig` Issue #17 @cfig：解锁 BL 后 "bootloader should always load the image for unlocked devices"（通用经验，非保证）。

---

## 6. Q5｜OPPO K3 深度测试（Deep Test）解锁

### 6.1 零命中项【实】

- `search/repositories`：`OPPO DeepTesting`=0、`OPPO 深度测试`=0、`OPPO_K3_DeepTesting`=0、`deep test OPPO apk`=0、`"OPPO K3" unlock in:name,description,readme`=0。
- `search/code`：`OPPO_K3_DeepTesting`=0。
- 结论：**GitHub 上不存在 `OPPO_K3_DeepTesting.apk` 专门项目/脚本**；XDA 帖附件（主代理汇总 §4.4，`OPPO_K3_DeepTesting.apk` 3.4 MB）不在 GitHub 可检索范围。

### 6.2 2026 年仍有效的一手资料【实】

**`zenfyrdev/bootloader-unlock-wall-of-shame@brands/oppo/README.md`**（★5685，活跃维护）：

> "- Verdict: **🍅 Just terrible!**"
> "There's not much else to say about OPPO. They also offer in-depth testing, **but only for Chinese models**"
> "### Deep Testing — Deep Testing is the application used to request the fastboot key. Internally, it **writes the key to the (oplus/oppo)reserve1 partition**, which is later read by fastboot. Realme and Oppo have different versions of Deep Testing..."
> "**Only 2 versions of Oppo Deep Testing exist: v1.0.1 and v1.1.0.**"
> Realme 侧澄清"指定版本"问题："While Realme's posts make it seem like you need a specific version of DT for each device, this is not true. All devices with RUI 2 and below need to use v1.0.0, all devices with RUI 3 and above need to use v1.0.1 or v1.1.0."
> "Server Exploit (Obsolete): In April-May 2023 you could unlock any Realme phone using this script [rmx3474-rooting], but on May 26th Realme posted this announcement ... they have forced their servers to only return 'new struct' keys ... making the script useless."

**`awesome-android-root/awesome-android-root@docs/rooting-guides/how-to-unlock-bootloader.md`**（2026 维护，解锁指南第 607-610 行）：

> "**OPPO:** - Deep Testing app method - **7-day waiting period** - **Very limited model support**"

**`Crazer-Shifter84/OPlus-BootLoader-Unlock`**（2025-08-22 创建，`docs/oppo.md`）：

> "Many OPPO devices require an **official unlock tool** or **server token**."
> 步骤：Developer Options → OEM Unlocking + USB Debugging → 安装 OPPO 官方解锁 app → `fastboot flashing unlock` → Commit changes
> "Some require: An **official unlock tool/app** from OPPO; A **server-provided unlock token**; Some models are **region or carrier locked**, so unlocking may not be possible at all."

**`Tintarul/oppo-workaround`**（2023-10-10，★5）：README 仅两行 "OTA Updater APK decompiled / Oppo / RealMi / Xiaomi bootloader APK decompiled for bootloader unlock"，无可用内容。【实】

### 6.3 不适用于本机的"非官方解锁"项目【实】

`OPPO bootloader unlock` 仓库检索 19 命中中，两个高星项目都是 **MTK 平台专用**，`zenfyrdev` 文档亦明确标注：

- `Shocked-Cat/oppo-mtk-fastboot-unlock`（★170, 2025-09）："Modifying the factory preloader and writing the preloader via mtkclient to open access to fastboot and unlock the bootloader"
- `R0rt1z2/lkpatcher`（★415, 2023-10）："patch bootloader (LK) images of **MTK** device(s)"

→ K3 是 **高通 sdm710**，这两条路径**不适用**，也不能用来绕过深度测试。

### 6.4 Q5 结论

- 2026 年社区资料一致认为 OPPO 深度测试仍存在，但**仅国行机型**（与 PCGM00 有资格、CPH1955 无资格一致）、"Very limited model support"、需 7 天等待、需官方 app/token。`fastboot flashing unlock` 是最终解锁命令（`Crazer-Shifter84` 与主代理汇总的 XDA 快照一致）。【实】
- **K3 的「指定申请版本」未见 GitHub 公开记录**；`zenfyrdev` 只在 Realme 侧澄清"按 RUI 版本而非每机型指定"。主代理汇总指出 OPPO 官方名单末次更新 2021-11-22、需在"指定的出厂版本"申请，若指定版本为早期 A 系列（Android 9），则解锁需先降级，与 root C.17 目标构成第二重矛盾。【推】
- 深度测试 2026 是否仍受理 K3：**未确认**（GitHub 无一手记录）。【源/推】

---

## 7. Q6｜同平台 realme X / RMX1901 可借鉴项

### 7.1 `ishashanknigam/kernel-realme-RMX1901`【实】

- 元信息：创建 **2026-10-03**，pushed 2026-10-03，默认分支 `nethunter-rmx1901-wcn3998-injection`，size 188010 KB，描述 "Nethunter kernel for Realme X (RMX1901)"。
- 目标设备表：Realme X / RMX1901 / Snapdragon 710 / WCN3998 / **Android 10** / **ColorOS 7.2** / Linux 4.9.186 / ARM64。
- **最有价值内容**（README §"Packaging and Boot Image"，原文见 §3.2）：`raw kernel Image + stock 17-DTB container + Magisk root ramdisk = boot image`，TWRP `dd` 刷入，实测 Android 启动 + root context 可用。
- 构建工具版本：`ARCH=arm64`、`CROSS_COMPILE=.../linaro-aarch64-5.5/bin/aarch64-linux-gnu-`（**Linaro GCC 5.5.0**）、`PYTHON=/usr/bin/python2`、`HOSTCFLAGS="-fcommon"`、`KCFLAGS="-DDISABLE_OPPO_PHOENIX -DCONFIG_VENDOR_REALME"`，`make O=out-nethunter-v3-injection Image dtbs modules`；根目录含 `build-nethunter-v3.sh`、`verity_dev_keys.x509`。
- 配置相关：`CONFIG_WIREGUARD=m`、NetHunter V3.11 Core 九项 `n→m` 模块化改动、V3.11 hard exclusions（含 `CONFIG_DEVTMPFS` 等）。
- **可迁移到 K3 的部分**【推】：
  1. "kernel + DTB 容器 + ramdisk" 的 boot 结构与本机 `Image.gz + 16 DTB` 同构；
  2. 证明该平台 bootloader **接受 boot 内 ramdisk**（→ 支持 patch boot.img 路线，见 §3.2）；
  3. 说明需要 TWRP（或等效 fastboot）刷入、需要重签名/处理 verity。
- **不可直接迁移**：自定义 NetHunter 内核（非 C.17 官方内核）、ColorOS 7.2 ≠ ColorOS 7.1、realme ≠ OPPO 分区/签名、`raw Image` 未压缩、README 未给出 `mkbootimg`/`magiskboot` 的具体打包命令（只给结构公式与 SHA-256），且未记录 Magisk 版本/TWRP 版本。

### 7.2 `monster8d/RMX1901-Flash_Tool`【实】

- 2022-07-23 创建，描述 "Root Your Device in 1 click"，README："Last tested on **RUI2 F.04**"、"Root Your Device in 1 click / Unroot ... / Downgrade to RUI1 / Debloat"。
- 根目录仅 `Flash Tool.bat`、`LICENSE`、`README.md`、`debloat_list.sh`；README 说 "Just replace the Release file (**Flash tool.exe**) in your Directory" —— **核心一键 root 逻辑是 Release 里的 Windows exe，不在仓库源码内，无法核验**。
- 对 K3 价值：低。仅针对 RMX1901、realme UI 2（F.04），不含 boot 结构说明、不含 Magisk/TWRP 版本、不可复现到 K3。【实】

### 7.3 其它 RMX1901 资源

主代理汇总已列约 40 个设备树/内核 fork（OrangeFox、PBRP、TWRP、LineageOS 系），均为 2019–2026 派生仓库，无 K3 适配、无 root 脚本；本次未重复拉取。【源，来自主代理汇总 §3.3】

---

## 8. Q7｜2021 年之后的新仓库补充检索

### 8.1 零命中 / 极稀疏【实】

| 检索式 | total_count | 说明 |
|---|---|---|
| `CPH1955 created:>2021` | 0 | 无 2021 后 CPH1955 新仓库 |
| `"OPPO K3" created:>2021` | 1 | 唯一为 `cfbrgb/K3-twrp`（2022-01-30，空仓库，仅 1 字节 `rec` 文件） |
| `PCGM00 created:>2021` | 0 | |
| `ColorOS 7.1 root` | 0 | |
| `ColorOS 7.1 magisk`（code） | 273 | 全为通用仓库（Sui、AppManager、awesome-android-root 等），无 K3/C.17 内容 |
| 7 个最终版构建号 code search | 全 0 | 主代理汇总 §4.2 已实测（`PCGM00_11_C.17`、`PCGM00_11_OTA_2170`、`CPH1955_11_F.13` 等） |

### 8.2 2021 后"涉及机型"的新仓库（均非 C.17 root 适配）【实/源】

| 仓库 | 创建 | 核验结论 |
|---|---|---|
| `Droidspaces/droidspaces-recovery-hack-example` | 2026-04-20 | cfig 工具的教学/衍生仓库（"A modified Android stock recovery that boots a full Ubuntu container via Droidspaces"）。README 直接复制 cfig 兼容性表，其中 **`| K3 (CPH1955) | OPPO | Y for recovery.img / N for boot.img | Pie | ... |`** —— 明确 boot.img 不兼容、recovery.img 兼容、**Android 9 Pie**。打包流程 `boot.img → ./gradlew unpack → 编辑 rootfs/kernel → ./gradlew pack → boot.img.signed`。**新仓库、旧内容**，不是 C.17 适配。 |
| `L0NE-6/Magisk-DeviceSpoofer` | 2026 | `update/xj_pcgm00.json` / `xj_cph1955.json`，版本 `v2026.10.09.2`，指向 `OPPO K3 (PCGM00)/(CPH1955).zip`——设备指纹伪装模块，**不提供提权**（主代理汇总 §3.3 已核验） |
| `ishashanknigam/kernel-realme-RMX1901` | 2026-10-03 | 见 §7.1，同平台内核，非 K3 专属 |
| `Crazer-Shifter84/OPlus-BootLoader-Unlock` | 2025-08 | 通用解锁指南，见 §6.2 |
| `Droidspaces` 之外 | — | `oppo-k3` 组织 8 个仓库全部 pushed_at ≤ 2019-10-25 |

### 8.3 Q7 结论

**GitHub 上不存在针对 `PCGM00 C.17` / `CPH1955 F.13` / `ColorOS 7.1` 的 patched boot.img、提权类 Magisk 模块、GSI/TWRP 或 root 脚本仓库（2021 年后创建的也没有）**。【实】
局限：GitHub 代码搜索不索引二进制；patched boot.img / TWRP `.img` / Magisk 模块 zip 多在论坛、网盘、Telegram，不在可检索范围，不能断言"全网不存在"（与主代理汇总 §3.5 一致）。

---

## 9. 综合：把研究发现转成对本机 C.17 的可操作判断

> 以下为【推】，供主代理决策；所有刷机动作仍需 BL 解锁与实测。

### 9.1 本机属性的最终判定

| 维度 | 判定 | 依据 |
|---|---|---|
| Magisk 类型 | **Type III（Method B Legacy SAR + A-only + boot 无 ramdisk）** | `docs/boot.md` 分类规则 + 静态分析（LV=28, A-only, ramdisk_size=0） |
| 官方推荐路径 | **patch recovery.img + Recovery Mode**，每次重启到 recovery 才有 root | `docs/install.md` |
| 脚本备选路径 | 直接 patch boot.img 会自动新建 ramdisk（v20.4+），但**能否生效取决于 K3 bootloader** | `boot_patch.sh` + `cpio.rs` + `docs/boot.md` 例外说明 |
| 同平台倾向 | **倾向支持 patch boot.img 可行** | RMX1901 实测 boot 带 ramdisk 可启动（§3.2） |

### 9.2 建议路径排序

**前置（未解决）**：深度测试解锁 BL（2026 是否受理 K3、指定申请版本均未知，见 §6.4）；保留原版 `boot.img` / `vbmeta.img` 回退。

- **路径 A（先试，同平台实证支持）**：用当前 Magisk（≥v26.4，建议 v31.x）在**本机**上 "Select and Patch a File" 直接 patch C.17 的 `boot.img` → `fastboot flash boot magisk_patched-*.img` → `fastboot flash vbmeta --disable-verity --disable-verification vbmeta.img`。
  - 支撑：Magisk 自动新建 ramdisk；RMX1901 同平台证明该结构可启动；A-only 单槽刷 `boot`（主代理汇总 §9.3）。
  - 待验证：K3 bootloader 是否把新增 initramfs 交给内核；`LEGACYSAR` 是否被自动置位及其效果。
- **路径 B（官方保守路径，A 失败再退回）**：取得可用的 `recovery.img`（需先验证 C.17 `system.new.dat.br` 内是否含 `recovery-from-boot.p`，用 cfig `bspatch` 生成）→ Magisk 勾选 **Recovery Mode** patch recovery.img → `fastboot flash recovery` → 每次用按键组合启动。
  - 代价：正常开机无 root；`Magisk#1801` 显示部分 A-only SAR 设备有基带/IMEI 丢失副作用；且 "CANNOT use custom recoveries to install or upgrade Magisk in this case"。
- **两条路径共同**：vbmeta 处理（§5）、不要用别人分享的 patched 镜像（install.md 明确警告）、不要跨版本复用 2019 boot.img。

### 9.3 三个必须标注的不确定点

1. **cmdline 无 `skip_initramfs`**：Magisk 的 LEGACYSAR hexpatch 目标串是 `skip_initramfs\0`（内核 `__setup` key）。本机 boot 头 cmdline、DTB `/chosen` 均无该串（静态分析实测）。虽然内核二进制里可能仍含该字符串（未核验），但"靠 patch 掉 skip 来强制加载 ramdisk"的**前提逻辑在本机不成立**；这既可能意味着 K3 本来就会加载 boot 内 ramdisk（利好路径 A），也可能意味着 K3 用了厂商私有机制绕过 initramfs（需实测）。【推】
2. **C.17 的 recovery 物料未知（已按 §12.A 强化）**：`recovery-from-boot.p` 按 AOSP 机制位于 `system.new.dat.br` 解包后的 `/system/` 内（不在 OTA 顶层），而该文件（2.35 GB）未取 → 是否含补丁仍未验证；可复现获取路径为 ozip 解密 → brotli → `sdat2img.py` → 取 `/system/recovery-from-boot.p` → bspatch（§12.A-2/A-4）。另需注意 `install-recovery.sh` 可能在首次开机覆盖 patched recovery。【实+推】
3. **OPPO bootloader 的 libavb 一致性未实测**：`flags=3` 能否让 5 个 chain descriptor 全部停摆，依赖 OPPO LK/ABL 是否严格实现 "VERIFICATION_DISABLED → descriptors not parsed"。【推】

### 9.4 版本断层复核（呼应主代理汇总）

- cfig K3 专章 / `oppo-k3` 组织全部对应 **2019 Android 9 (Pie)**，Issue #17 里 @surendrajat 明确 "Pie it is."。
- `Droidspaces`（2026 新仓库）复制的兼容性表仍标 "Pie"。
- 唯一 Android 10 / ColorOS 7.x / sdm710 的实测是 **RMX1901 ColorOS 7.2**（非 K3、非 ColorOS 7.1、自定义内核）。
- **不得把 2019 Android 9 的 boot.img / TWRP 树 / bspatch 结果当作 C.17 可用方案。**

---

## 10. 证据索引（URL / owner/repo@path）

**Magisk（默认分支 master，已确认）**
- https://github.com/topjohnwu/Magisk/blob/master/scripts/boot_patch.sh
- https://github.com/topjohnwu/Magisk/blob/v20.4/scripts/boot_patch.sh 、 .../v26.4/... 、 .../v19.4/... （版本演化）
- https://github.com/topjohnwu/Magisk/blob/master/native/src/boot/cpio.rs
- https://github.com/topjohnwu/Magisk/blob/master/docs/boot.md
- https://github.com/topjohnwu/Magisk/blob/master/docs/install.md
- https://github.com/topjohnwu/Magisk/blob/master/docs/details.md
- https://github.com/topjohnwu/Magisk/blob/master/docs/guides.md 、 .../faq.md
- https://github.com/topjohnwu/Magisk/issues/1801 、 /issues/10006 、 /issues/8297 、 /issues/7390 、 /issues/7159

**cfig 工具**
- `cfig/Android_boot_image_editor@master:doc/additional_tricks.md` → https://github.com/cfig/Android_boot_image_editor/blob/master/doc/additional_tricks.md
- https://github.com/cfig/Android_boot_image_editor/issues/17 （22 条评论全量核验）
- `cfig/Android_boot_image_editor@master:bbootimg/src/main/kotlin/bootimg/v2/BootV2.kt`
- `cfig/Android_boot_image_editor@master:README.md`（"How to disable AVB verification"、`boot.img.signed` / `vbmeta.img.signed`）

**AVB / fastboot 一手源码**
- `GrapheneOS/platform_external_avb@17:libavb/avb_vbmeta_image.h` → https://github.com/GrapheneOS/platform_external_avb/blob/17/libavb/avb_vbmeta_image.h
- `GrapheneOS/platform_external_avb@17:README.md` 、 `:avbtool.py`
- `AndroidBootloader/platform_external_avb@master`（备用镜像，含 `avbtool` / 同名文件）
- `aosp-mirror/platform_system_core@main:fastboot/fastboot.cpp` → https://github.com/aosp-mirror/platform_system_core/blob/main/fastboot/fastboot.cpp

**解锁 / 政策**
- `zenfyrdev/bootloader-unlock-wall-of-shame@brands/oppo/README.md` → https://github.com/zenfyrdev/bootloader-unlock-wall-of-shame
- `awesome-android-root/awesome-android-root@docs/rooting-guides/how-to-unlock-bootloader.md` 、 `@docs/rooting-guides/magisk-guide.md` → https://github.com/awesome-android-root/awesome-android-root
- `Crazer-Shifter84/OPlus-BootLoader-Unlock@docs/oppo.md` → https://github.com/Crazer-Shifter84/OPlus-BootLoader-Unlock
- https://github.com/Shocked-Cat/oppo-mtk-fastboot-unlock 、 https://github.com/R0rt1z2/lkpatcher （MTK 专用，不适用本机）
- https://github.com/Tintarul/oppo-workaround

**同平台 / 新仓库**
- https://github.com/ishashanknigam/kernel-realme-RMX1901 （README "Packaging and Boot Image" / "Validation"）
- https://github.com/monster8d/RMX1901-Flash_Tool
- https://github.com/Droidspaces/droidspaces-recovery-hack-example
- https://github.com/oppo-k3 （组织，8 个 2019 仓库，主代理汇总已核验）
- https://github.com/L0NE-6/Magisk-DeviceSpoofer （主代理汇总已核验）

---

## 11. 检索局限

- GitHub 不索引二进制：patched boot.img / TWRP `.img` / Magisk 模块 zip 的实际流通多在 XDA、网盘、Telegram，不可检索。
- `in:readme` 依赖索引，零星老仓库可能未被收录；`search/code` 对大文件/含 `--` 前缀的字符串不敏感（本次 `fastboot.cpp` 的 `--disable-verification` code search 即 0 命中，改为直接抓源码核验）。
- 深度测试 APK、指定申请版本、2026 受理状态：GitHub 无一手记录，依赖 XDA/论坛/官网，主代理汇总已列【源】级资料。
- `ishashanknigam` README 未给出 `mkbootimg`/打包命令的具体参数与 Magisk/TWRP 版本，只给结构公式与验证表，迁移到 K3 仍需自行确定 header/os_patch_level/AVB 重签细节。
- 本报告所有"可行"判断均为静态资料推断，**未在真机上验证**；实际刷机/解锁动作不在本次任务范围。

---

## 12. 补充核验（team-lead 追加 A–D，第二轮）

> 说明：Q1 已由主代理独立核验结案（证据见 `unpacked_C17/github_evidence/`），本节**不重复 Q1**。以下 A–C 为增量的一手核验，D 沿用 §6/§7/§8 结论并补充新增证据。所有结论标注【实/源/推】与 URL。

### 12.A｜stock recovery.img 从哪来（A）

#### A-1 AOSP 机制：`recovery-from-boot.p` + `install-recovery.sh` + `applypatch`【实】

`aosp-mirror/platform_build@main:tools/releasetools/common.py:3792-3799`（`MakeRecoveryPatch`）：

```python
def MakeRecoveryPatch(input_dir, output_sink, recovery_img, boot_img,
                      info_dict=None):
  """Generates the recovery-from-boot patch and writes the script to output.

  Most of the space in the boot and recovery images is just the kernel, which is
  identical for the two, so the resulting patch should be efficient. Add it to
  the output zip, along with a shell script that is run from init.rc on first
  boot to actually do the patching and install the new recovery image.
```

同文件 `:3847-3849`：`d = Difference(recovery_img, boot_img, diff_program=diff_program)` → `_, _, patch = d.ComputePatch()` → `output_sink("recovery-from-boot.p", patch)`。**补丁是 recovery.img 相对 boot.img 的二进制差分**（因两者 kernel 相同，补丁很小），因此 OTA 包**不需要**携带完整 recovery.img。

同文件 `:3883-3893` 生成的 `install-recovery.sh`（首次开机由 init.rc 触发）：

```sh
#!/vendor/bin/sh
if ! applypatch --check %(recovery_type)s:%(recovery_device)s:%(recovery_size)d:%(recovery_sha1)s; then
  applypatch %(bonus_args)s \
          --patch /vendor/recovery-from-boot.p \
          --source %(boot_type)s:%(boot_device)s:%(boot_size)d:%(boot_sha1)s \
          --target %(recovery_type)s:%(recovery_device)s:%(recovery_size)d:%(recovery_sha1)s && \
      log -t recovery "Installing new recovery image: succeeded" || \
      log -t recovery "Installing new recovery image: failed"
else
  log -t recovery "Recovery image already installed"
fi
```

同文件 `:3904-3906`："The install script location moved from /system/etc to /system/bin in the L release. **In the R release it is in VENDOR/bin or SYSTEM/vendor/bin.**" + `sh_location = os.path.join(sh_dir, "install-recovery.sh")`。
`aosp-mirror/platform_build@main:tools/releasetools/make_recovery_patch.py`（独立工具）用 `common.GetBootableImage("recovery.img", ...)` 与 `("boot.img", ...)` 生成补丁。
等价副本亦在 `xiaoxindada/SGSI-build-tool@tool_bin/common.py:2967-3084`（GSI/厨房工具链，已核验同文）。

**机制结论**【实】：OPPO/realme 的 A-only 机型存在独立 `recovery` 分区（与本机 vbmeta 的 recovery chain partition descriptor 一致），但 **OTA 顶层不含 recovery.img**；补丁文件 `recovery-from-boot.p` 位于 **system 分区内部**（`/system/recovery-from-boot.p` 或 `/vendor/recovery-from-boot.p`），首次开机由 `install-recovery.sh` 用 `applypatch` 以 boot 分区为源现场生成并刷入 recovery 分区。cfig 的 `bspatch boot.img recovery.img system/recovery-from-boot.p` 正是在 PC 上离线复现这同一操作。

#### A-2 同系可复现工具：`rmdIX/RealMeRecoveryMaker`【实，A 的最直接答案】

- 元信息：创建 **2020-02-02**，描述 **"Creates recovery image from Realme ROM"**，默认分支 master，JavaFX/Windows GUI。
- 资源清单（`src/main/resources/tools/`）：`ozipdecrypt.py`、`ofp_libextract.py`、`sdat2img.py`、`brotli.exe`、`bspatch.exe`、`bsdiff.exe`、`ImgExtractor.exe`。
- `rmdIX/RealMeRecoveryMaker@master:src/main/java/com/ramdolpix/realmerecoverymaker/Controller.java:73-97` 完整流程（原文）：

```java
logField.appendText("Converting oZip to Zip..." + "\n");
logField.appendText(action.runCommand("python " + tempFolder + "/ozipdecrypt.py " + path2OZipFile));
...
new ZipFile(tempFolder + "/firm.zip").extractFile("boot.img", unpackedFilesFolder);
new ZipFile(tempFolder + "/firm.zip").extractFile("system.new.dat.br", unpackedFilesFolder);
new ZipFile(tempFolder + "/firm.zip").extractFile("system.transfer.list", unpackedFilesFolder);
...
action.runCommand(tempFolder + "/brotli.exe --decompress --in .../system.new.dat.br --out .../system.new.dat");
action.runCommand("python " + tempFolder + "/sdat2img.py .../system.transfer.list .../system.new.dat .../system.img");
action.runCommand(tempFolder + "/ImgExtractor.exe .../system.img " + unpackedSystemFolder);
...
action.moveFile(unpackedSystemFolder + "/system/recovery-from-boot.p", unpackedFilesFolder + "/recovery-from-boot.p");
...
action.runCommand(tempFolder + "/bspatch.exe " + unpackedFilesFolder + "/boot.img "
    + unpackedFilesFolder + "/recovery.img " + unpackedFilesFolder + "/recovery-from-boot.p");
action.moveFile(unpackedFilesFolder + "/recovery.img", System.getProperty("user.home") + "/recovery.img");
```

→ **明确写出 `recovery-from-boot.p` 在解包后的 `system.img` 内 `/system/` 目录**，并用 `bspatch boot.img recovery.img recovery-from-boot.p` 生成 recovery.img。这与 cfig 的 K3 专章完全一致，且是**同一厂商体系（OPPO/realme）、.ozip 固件**的完整可复现实现。

#### A-3 OFP / MSM 线刷包路径【实/源】

- `bkerler/oppo_decrypt@master:README.md`："Oppo .ofp and Oneplus .ops Firmware decrypter"；`ofp_qc_decrypt.py`（**高通 .ofp**）、`ofp_mtk_decrypt.py`（MTK）、`opscrypto.py`（一加 .ops）、`backdoor.py`（hidden "readback"）。用法 `python3 ofp_qc_decrypt.py [myops.ofp] [directory to extract]`。→ K3 是高通 sdm710，若有 OFP/MSM 线刷包（主代理汇总 §2.1 列 `Oppo_K3_PCGM00_11_C.17_210909_RFT.zip`，§4.5 列 OFP 资源），`ofp_qc_decrypt.py` 是另一条 recovery 来源路径。
- `bkerler/oppo_ozip_decrypt@master:README.md`："For extraction of **libpatchapply.so or /sbin/recovery**, use: `./ofp_libextract.py [your_ofp_file]`"、"If you're getting a **recovery.cpio.7z** file, extract using 7z to get the /sbin/recovery file." → 说明 OPPO OFP 内含 recovery ramdisk 物料。
- **诚实校正**【实】：`bkerler/oppo_ozip_decrypt` 当前根目录**只有** `README.md` / `ozipdecrypt.py` / `requirements.txt`，**没有** `ofp_libextract.py`；`bkerler/oppo_decrypt` 根目录也无此文件。README 提及的脚本，其副本存在于 `xiaoxindada/SGSI-build-tool::oppo_ozip/ofp_libextract.py`、`rmdIX/RealMeRecoveryMaker::src/main/resources/tools/python/ofp_libextract.py`、`tahirtaous/ozip2zip::ofp_libextract.py` 等（`search/code q=ofp_libextract` total=19）。即 README 说明可信但工具文件需从镜像仓库取得。

#### A-4 cfig K3 专章 / Issue #17 对国行 C.17 的适用性（复核 §4）【实+推】

- 专章原文与 Issue #17 原文见 §4.1 / §4.2：由 @Surendrajat 于 2019-09-21 提交，`## K3 (CPH1955)` + `bspatch boot.img recovery.img system/recovery-from-boot.p`；@surendrajat 在 Issue #17 明确 **"Absolutely. Pie it is."**（Android 9），PR #32 即该段落。
- **修订 §4.3 的表述**：主代理静态分析"235 条目中无 `recovery.img` 与独立 `recovery-from-boot.p`"与 AOSP 机制**完全一致的预期行为**（补丁在 system 分区内，不在 OTA 顶层），**不能据此断言 C.17 不含该补丁文件**。C.17 的 `system.new.dat.br`（2.35 GB）未取，内部是否有 `/system/recovery-from-boot.p` **仍未验证**。【实+推】
- **对 C.17 的可复现获取路径（迁移 RealMeRecoveryMaker）**【推】：C.17 是 `.ozip`（主代理已实测分块加密、密钥 `ACAC1E13A12531AE4A1B21BB31C13C21`）→ 解密得 zip → 取 `system.new.dat.br` + `system.transfer.list` → `brotli -d` → `sdat2img.py` → 解包 `system.img` → 取 `/system/recovery-from-boot.p` → `bspatch boot.img recovery.img recovery-from-boot.p`。工具链全部开源可得（`ozipdecrypt.py` / `sdat2img.py` / `bspatch` / `ImgExtractor` 或 `cfig/Android_boot_image_editor` 的 `pack`）。
- **版本断层警示**：cfig K3 专章（2019 / CPH1955 / Pie）、RealMeRecoveryMaker（2020 / realme）均**未在 C.17（Android 10 / ColorOS 7.1 / PCGM00）上验证**；AOSP R 版本仍保留 `install-recovery.sh` 机制（路径移至 `/vendor/bin`），但 OPPO 是否沿用需实测。【推】
- **Recovery Mode 的已知坑**【推，源自 AOSP `applypatch --check` 逻辑】：`install-recovery.sh` 每次开机用 `applypatch --check` 校验 recovery 分区 sha1，若不符会**重新生成并覆盖** recovery 分区。若把 Magisk patched recovery 刷入 recovery 分区，后续首次开机可能被 `install-recovery.sh` 覆盖回原版 → 需关注该脚本是否被禁用/删除。

### 12.B｜Type III 设备「手工加 ramdisk 的 boot.img」刷进 boot 的正例/反例（B）

#### B-1 一手正例：Magisk PR #1102「Support Aonly&System-as-root devices」【实】

`topjohnwu/Magisk#1102`（2019-02-19, closed, **PR=true**）正文原文：

> "Partition layout: https://source.android.com/devices/bootloader/system-as-root#about-system-as-root
> In `boot.img`, we **patch kernel to make it want_initramfs , and add stub ramdisk. There are only `init` in the stub ramdisk.**
> magiskinit already supports system-as-root devices."

评论（中文原文）：
- @vvb2060（2019-02-20）："刷入时注意看提示，应该是 Only kernel stock boot image detected，或者 Magisk stub boot image detected。另外，**这个 PR 支持的是 AOSP 文档中 system-as-root 布局的标准方式，非标准的改不了内核就完蛋（应该不会再出一个 EMUI9 吧）**。"
- @youyim（2019-02-20，红魔 Mars / 努比亚 / 骁龙 845 / A-only SAR）：**"在红魔 Mars 上正常工作，感谢"** → **Type III（A-only SAR）设备把"patch kernel 强制 want_initramfs + 新建只含 init 的 stub ramdisk"的 boot.img 刷进 boot 并成功 root 的已验证正例**。这正是 Magisk v20.4+ 内建的 "create one from scratch" + LEGACYSAR hexpatch 的原型（§2.1/§2.3）。
- @vvb2060（2019-02-24）："Now, only the script has changed. You can use the official Magisk with this script."

**关键约束**【实】：@vvb2060 明确指出该方案只支持 **AOSP 标准 system-as-root 布局**；"非标准的改不了内核就完蛋"（点名 EMUI9 为反例）。这与 `docs/boot.md` 的 "It solely depends on how the OEM implements its bootloader" 一致。

#### B-2 官方例外与反例【实】

- 主代理已核（§0/§2.2）：`docs/boot.md` "Some Type III devices' bootloader will still accept and provide `initramfs` that was manually added to the `boot` image to the kernel (**e.g. some Xiaomi phones**), but many devices don't (**e.g. Samsung S10, Note 10**). It solely depends on how the OEM implements its bootloader."；`docs/install.md` "only some Xiaomi devices are known to have this property"。
- `topjohnwu/Magisk#1801`（§2.4 已核）：@S190762（Nokia 1 Plus, A-only SAR）"**The boot.img doesn't contain a ramdisk and magisk doesn't work if i try to patch the boot.img**"；@bauner（Redmi Note 8 Pro）"I used magisk manager to patch the stock boot.img with the recovery option and dm-verity off and flashed it with fastboot to the **recovery partition (any other option caused a bootloop)**"。
- `topjohnwu/Magisk#6566`（2023-01-25, closed）**Oppo A83 CPH1729 - bootloop**【实】："I tried to root this old device using **patch boot image technique but ended up bootlooping**"，勾选 "Preserve force encryption"、"**Patch vbmeta in boot image**"；设备 Android 7.1.1、Magisk 25.2、**Ramdisk: Yes**、A/B: No。→ 属 OPPO 设备上 patch boot 失败的实例，但**该机有 boot ramdisk（不是无 ramdisk 的 Type III）**，故只能作为「OPPO + vbmeta/AVB 处理不当导致 bootloop」的旁证，**不能**当作"无 ramdisk 设备手工加 ramdisk"的反例。
- `repo:topjohnwu/Magisk "want_initramfs"` issues 共 9 命中，其余为 #4307（a21s `skip_initramfs` 误判）、#5971（SAR 设备 mount init.rc 失败）、#6786（FP3 bootloop）等，均为通用 SAR/检测问题，无 OPPO K3 专属结论。【实】

#### B-3 `skip_initramfs` 来源的新线索：`topjohnwu/Magisk#4307`【实】

PR #4307（2021-05-03, "a21s: whitelist exynos850 to work around incorrect detection as skip_initramfs"）正文 magiskinit 日志：`magiskinit: skip_initramfs=[1]`、`magiskinit: SARInit`、`Early mount system_root`。评论：
- @jameskdev："**hex-editing the boot.img-dtb prior to patching/flashing (changing skip_initramfs to want_initramfs) also solves the problem. Magisk does this automatically for some devices, but not for the A21S.**"
- @osm0sis："the real issue here is that the **skip_initramfs -> want_initramfs patch isn't working on the device's kernel when unpacked**"、并指出 "**the skip_initramfs commandline was coming from the dtb**"。

→ `skip_initramfs` 可能来自 **DTB 的 bootargs 而非 boot header cmdline**；magiskinit 以 `skip_initramfs` 作为进入 Legacy SAR Init 的判据之一。**对本机**【推】：主代理静态分析已实测 boot header cmdline 与 DTB `/chosen` **均无 `skip_initramfs`**（`/chosen` 仅 `rcupdate.rcu_expedited=1 core_ctl_disable_cpumask=6-7`），因此 (a) Magisk 的 LEGACYSAR hexpatch 前提在本机不成立；(b) 若 OPPO 通过 bootloader 动态注入或私有机制实现 SAR，则静态 boot.img 里看不到该参数，须实机抓取 `/proc/cmdline` 确认。这是 §9.3 不确定点 1 的一手佐证。

#### B-4 同平台正例（§3.2/§7.1 汇总）【实/推】

`ishashanknigam/kernel-realme-RMX1901`（sdm710 / Android 10 / ColorOS 7.2）：README 实测 `raw kernel Image + stock 17-DTB container + Magisk root ramdisk = boot image`，TWRP `dd` 刷入后 Android 启动、root context 均 ✅ Verified → 支持"该平台 bootloader 接受 boot 内 ramdisk"。

#### B-5 B 的结论

1. **正例确实存在**【实】：红魔 Mars（A-only SAR，PR #1102，2019）、RMX1901（同平台 sdm710 / Android 10，2026）均通过"patch kernel 强制加载 + 新建 stub ramdisk 刷 boot"成功。Magisk 官方 `install.md` 也承认"部分小米"属此例外。
2. **反例同样明确**【实】：三星 S10/Note10（docs/boot.md）、Nokia 1 Plus / Redmi Note 8 Pro（#1801）、EMUI9 一类"非标准 SAR"（PR #1102 @vvb2060）。
3. **未找到**【实/源】：`OPPO K3 / PCGM00 C.17`、`realme X 官方 ColorOS 7.x`、`OnePlus 6/7 官方 OOS` 上"手工加 ramdisk 的 boot.img 刷进 boot 并生效"的已验证实例。`"realme X" magisk boot ramdisk` issues = 0；`repo:topjohnwu/Magisk "OnePlus 6"` = 88 命中但全为通用问题（OOS10/11 app freeze、addon.d、Nord CE2 等），无 ramdisk 结构结论；`"OPPO" "no ramdisk" magisk` = 11 命中，无 K3。
4. **决策建议**【推】：`docs/boot.md` 的"取决于 OEM bootloader"仍是准绳，K3 无法确定归类。鉴于 (a) 同平台 RMX1901 正例、(b) boot 路径成本低且失败可用原版 boot.img 回退、(c) recovery 路径的物料前提（§12.A）尚未证实且每次必须重启到 recovery，建议 BL 解锁后**优先实测路径 A（patch boot）**，失败再转路径 B（patch recovery）。两条路径均须配合 §12.C 的 vbmeta 处理。

### 12.C｜5 个 chain partition descriptor 下，刷 flags=3 vbmeta 是否足以「全局」关闭校验（C）

#### C-1 标准 libavb 的决定性源码【实】

`GrapheneOS/platform_external_avb@17:libavb/avb_slot_verify.c`（`load_and_verify_vbmeta`，第 972-990 行）：

```c
/* If verification has been disabled by setting a bit in the image,
 * we're done... except that we need to load the entirety of the
 * requested partitions.
 */
if (vbmeta_header.flags & AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED) {
    AvbSlotVerifyResult sub_ret;
    avb_debug(full_partition_name, ": VERIFICATION_DISABLED bit is set.\n");
    /* If load_requested_partitions() fail it is always a fatal
     * failure ... rather than recoverable ... */
    sub_ret = load_requested_partitions(
        ops, requested_partitions, ab_suffix, slot_data);
    if (sub_ret != AVB_SLOT_VERIFY_RESULT_OK) {
      ret = sub_ret;
    }
    goto out;      /* ← 直接返回，跳过下面整个 descriptor 遍历循环 */
}
```

后续第 1016 行起才是 `for` 遍历 descriptors 的 `switch (desc.tag)`，其中：
- `case AVB_DESCRIPTOR_TAG_HASH:` → `load_and_verify_hash_partition(...)`（第 1017-1031 行）；
- `case AVB_DESCRIPTOR_TAG_CHAIN_PARTITION:`（第 1033-1089 行）→ 校验 `rollback_index_location`、取 `chain_public_key`，递归 `load_and_verify_vbmeta(..., chain_public_key, ...)` 去加载并验证被链接分区的内嵌 vbmeta；并注明 "**Only allow CHAIN_PARTITION descriptors in the main vbmeta image.**"

即 **5 个 chain partition descriptor 只有在 descriptor 循环被执行时才会被跟进**；顶层 `VERIFICATION_DISABLED` 一置位，循环根本不会进入。

补充同源证据：
- 第 839-848 行：`if (is_main_vbmeta) { toplevel_vbmeta_flags = (AvbVBMetaImageFlags)vbmeta_header.flags; } else { if (vbmeta_header.flags != 0) { ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA; avb_error(..., ": chained vbmeta image has non-zero flags\n"); goto out; } }` → **被 chain 的分区 vbmeta（如 boot 内嵌 vbmeta）flags 非 0 会直接判为非法元数据**。
- 第 1127-1138 行：`toplevel_vbmeta_flags & AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED` **仅**用于选择 kernel cmdline descriptor 的 dm-verity 片段（`USE_ONLY_IF_HASHTREE_NOT_DISABLED` / `..._DISABLED`），与 hash/chain descriptor 的解析校验无关。
- 第 315-324 行（`load_and_verify_hash_partition`）："Don't bother loading or validating unless the partition was requested in the first place." → hash 校验只针对 `requested_partitions`。
- `avb_vbmeta_image.h:51-62`（§5.2 已核）：`VERIFICATION_DISABLED` 注释 "**verification will be disabled and descriptors will not be parsed**"；flags=3 = HASHTREE_DISABLED(1) | VERIFICATION_DISABLED(2)。

#### C-2 C 的直接回答【实+推】

1. **足以"全局"关闭，不需要逐分区处理**：把**顶层** `vbmeta` 分区刷成 flags 含 `VERIFICATION_DISABLED`（flags=2 或 3）后，`avb_slot_verify` 在顶层即 `goto out`，**5 个 chain partition descriptor（boot/system/vendor/dtbo/recovery）一个都不被解析/跟进**，boot 分区尾部的 AVB footer 与内嵌 vbmeta（hash descriptor + property descriptors）都不会被读取或校验 → 主代理实测的 `sha256(salt||boot[0:16609280])` 一致性链条被整体跳过。【实，标准 libavb 语义】
2. **必须带 `--disable-verification`**：仅 `--disable-verity`（bit0 HASHTREE_DISABLED）**不够**——它只切换 dm-verity 的 kernel cmdline 片段，hash/chain descriptor 仍照常解析，boot 改动仍会触发校验失败。`fastboot flash vbmeta --disable-verity --disable-verification vbmeta.img` 得到 flags=3 才完整。【实】
3. **"逐分区处理"在标准 libavb 下既不可行也无必要**：给 boot 内嵌（chained）vbmeta 设 flags 会触发 `chained vbmeta image has non-zero flags` → `ERROR_INVALID_METADATA` 直接失败（第 843-847 行）。正确做法只有改顶层 vbmeta 的 flags。【实】
4. **两种生成方式对比**【实+推】：
   - `fastboot --disable-verity --disable-verification`（`aosp-mirror/platform_system_core@main:fastboot/fastboot.cpp:1110+` 的 `rewrite_vbmeta_buffer`，§5.3 已核）：**保留原 vbmeta 的全部 descriptors，只把 flags 字段（偏移 120）改成 3**。优点是保留 `os_version=10` / `security_patch=2021-05-05` 等 property descriptors 与 chain 公钥、rollback index，OEM 兼容性最好 → **推荐**。
   - `avbtool make_vbmeta_image --flags 3`（`avbtool.py:5090`，§5.4 已核）或 cfig README "How to disable AVB verification"（设 main vbmeta flag=2 后 `./gradlew pack` 重签，§4.3 已核）：生成/改写空 vbmeta。标准 libavb 下同样有效，但会丢弃全部 descriptors 与 rollback index，部分 OEM bootloader 可能依赖其存在 → 次选。
5. **残留风险**【推】：以上为**标准 libavb（userspace 参考实现）**语义；OPPO LK/ABL 是否严格调用 `avb_slot_verify`、是否存在独立于 libavb 的 boot 分区校验（例如 bootloader 自行读取 boot footer 并用 chain 公钥验签），**未在 K3 上实测**。另 `load_requested_partitions` 仍会把 requested partitions 内容读入 `slot_data`（但**不校验**），供后续 cmdline/挂载使用。
6. 旁证【实】：`cfig/Android_boot_image_editor#17` @cfig（2021-05-31）："magisk patched boot.img can not pass AVB integrity check, **but it doesn't matter if bootloader is unlocked, as the bootloader should always load the image for unlocked devices**" —— 社区经验与"解锁后 AVB 失败通常不阻止启动"一致，但仍属通用经验而非本机保证。

### 12.D｜Q5 / Q6 / Q7 沿用结论与新增证据（D）

- **Q5 深度测试**：沿用 §6 —— GitHub 无 `OPPO_K3_DeepTesting.apk` 仓库（`search/repositories`/`search/code` 均 0）；2026 一手资料 `zenfyrdev/bootloader-unlock-wall-of-shame@brands/oppo/README.md`（仅国行、Deep Testing 写 key 到 `reserve1` 分区、OPPO 仅 v1.0.1/v1.1.0）、`awesome-android-root@how-to-unlock-bootloader.md`（Deep Testing app / 7-day / **Very limited model support**）、`Crazer-Shifter84/OPlus-BootLoader-Unlock`（2025，需官方 app/server token）；MTK 专用 `Shocked-Cat/oppo-mtk-fastboot-unlock` / `R0rt1z2/lkpatcher` **不适用于 sdm710**。K3 指定申请版本未见公开记录，2026 是否受理未确认。【实/源】
- **Q6 同平台**：沿用 §7 —— `ishashanknigam/kernel-realme-RMX1901`（2026-10-03，Android 10/ColorOS 7.2/sdm710）实测 `kernel + 17 DTB + Magisk ramdisk` 可启动+root（见 §12.B-4）；`monster8d/RMX1901-Flash_Tool`（2022）核心 exe 不在仓库、RUI2 F.04，不可迁移。【实】
- **Q7 新仓库**：沿用 §8 —— `CPH1955 created:>2021`=0、`"OPPO K3" created:>2021`=1（空仓库 `cfbrgb/K3-twrp`）、`PCGM00 created:>2021`=0、`ColorOS 7.1 root`=0、7 个最终版构建号 code search 全 0；`Droidspaces/droidspaces-recovery-hack-example`（2026-04）复制 cfig 兼容性表且 K3 行仍标 "Pie / Y for recovery.img, N for boot.img"；`L0NE-6/Magisk-DeviceSpoofer`（2026）仅指纹伪装不提权。**GitHub 上不存在 2021 后针对 C.17/F.13/ColorOS 7.1 的 patched boot / TWRP / root 脚本**。【实】
- **D 新增的工具链仓库**（均为 2019–2020 创建，**不是** C.17 root 适配，不改变 Q7 结论）：`rmdIX/RealMeRecoveryMaker`（2020-02，realme/OPPO 系 recovery 制作，见 §12.A-2）、`bkerler/oppo_decrypt`（OFP/.ops 解密）、`bkerler/oppo_ozip_decrypt`（.ozip 解密）、`xiaoxindada/SGSI-build-tool`（AOSP releasetools 派生 + `oppo_ozip/ofp_libextract.py`）、`tahirtaous/ozip2zip`、`aosp-mirror/platform_build`（`MakeRecoveryPatch` 权威源）。【实】

### 12.E｜对既有章节的修订

1. **§4.3「物料前提缺失」**：原表述"C.17 OTA 已确认无 `recovery.img` / 独立 `recovery-from-boot.p`"按 §12.A-1 应修正为——**OTA 顶层无这两个文件是 AOSP 机制的预期行为**；`recovery-from-boot.p` 位于 `system.new.dat.br` 解包后的 `/system/` 目录（RealMeRecoveryMaker 源码实证），该文件未取，故 C.17 是否含补丁**仍未验证**，不能断言缺失。
2. **§9.2 路径 B**：物料获取具体化为 §12.A-4 的 ozip→brotli→sdat2img→`/system/recovery-from-boot.p`→bspatch 流程；并新增"注意 `install-recovery.sh` 可能覆盖 patched recovery"的坑（§12.A-4 末）。
3. **§9.2 路径 A / §9.3 不确定点 1**：补入 §12.B-1（红魔 Mars 正例 + "非标准 SAR 就完蛋"约束）与 §12.B-3（`skip_initramfs` 可来自 DTB、magiskinit 以其为 SAR 判据）作为一手支撑。
4. **§5 / §9.2 的 AVB 结论**：按 §12.C 强化为"顶层 flags=3 足以全局关闭、无需逐分区、`--disable-verity` 单独不够、chained vbmeta 设 flags 非法"。

### 12.F｜新增证据索引（URL / owner/repo@path）

**A（recovery 来源）**
- `aosp-mirror/platform_build@main:tools/releasetools/common.py`（`MakeRecoveryPatch`）→ https://github.com/aosp-mirror/platform_build/blob/main/tools/releasetools/common.py
- `aosp-mirror/platform_build@main:tools/releasetools/make_recovery_patch.py`
- `xiaoxindada/SGSI-build-tool@tool_bin/common.py:2967-3084`（等价副本）→ https://github.com/xiaoxindada/SGSI-build-tool
- `rmdIX/RealMeRecoveryMaker@master:src/main/java/com/ramdolpix/realmerecoverymaker/Controller.java` → https://github.com/rmdIX/RealMeRecoveryMaker
- `bkerler/oppo_decrypt@master:README.md` → https://github.com/bkerler/oppo_decrypt
- `bkerler/oppo_ozip_decrypt@master:README.md` → https://github.com/bkerler/oppo_ozip_decrypt
- `cfig/Android_boot_image_editor@master:doc/additional_tricks.md`、`/issues/17`（见 §10）

**B（boot 路径正反例）**
- `topjohnwu/Magisk#1102`（PR，Support Aonly&System-as-root devices）→ https://github.com/topjohnwu/Magisk/pull/1102
- `topjohnwu/Magisk#4307` → https://github.com/topjohnwu/Magisk/pull/4307
- `topjohnwu/Magisk#6566`（Oppo A83 CPH1729 bootloop）→ https://github.com/topjohnwu/Magisk/issues/6566
- `topjohnwu/Magisk#1801`（见 §10）

**C（AVB 链分区）**
- `GrapheneOS/platform_external_avb@17:libavb/avb_slot_verify.c` → https://github.com/GrapheneOS/platform_external_avb/blob/17/libavb/avb_slot_verify.c
- `GrapheneOS/platform_external_avb@17:libavb/avb_vbmeta_image.h`、`@17:avbtool.py`（见 §10）
- `aosp-mirror/platform_system_core@main:fastboot/fastboot.cpp`（见 §10）
- `cfig/Android_boot_image_editor#17` @cfig 2021-05-31 评论（见 §4.2）

