# K3（PCGM00 / C.17）ADB 信息采集清单（供另开会话执行）

> **版本失效声明（2026-11-13，依据实机 ADB 复核）**
> 本文基于 **C.17** 基线（ColorOS 7.1 / Android 10 / 内核 4.9.186 / SPL 2021-05-05）编写。实机 ADB 已确认设备运行 **PCGM00_11_F.16**（ColorOS 11.1 / Android 11 / 内核 4.9.227-perf+ / SPL 2022-04-05，构建 2025-03-26，fingerprint 尾号 `1704167642389`）。
> 本文中的镜像哈希、boot/vbmeta 数值、内核符号与偏移、CVE 补丁窗口，以及任何针对 C.17 的操作指令，**对本机全部作废**，不得用于本机判断；与版本无关的采集命令、分析方法论仍可参考。
> 当前有效基线：`F16_基线_与C17结论失效说明.md`；当前固件镜像：`firmware_F16/`；获取与清理记录：`F16_固件获取与C17清理记录.md`。

- 编制：2026-11-13
- 用途：在**不解 BL、无 root** 的前提下，用 ADB（shell / uid 2000）采集"判定下一步是否值得做 + 运行时约束"所需信息
- 关联：`临时ROOT_GhostLock_移植性评估.md`（临时 root 路线）、`K3_CVE解锁可行性分析.md`（解锁路线）

---

## 0. 先看这段（决定你要不要花时间）

当前设备状态推定：**BL 锁定、user 版本、SELinux Enforcing**。因此：

| 想读的东西 | shell 权限能否读到 | 说明 |
|---|---|---|
| 型号/版本/补丁/启动状态 | ✅ 能 | `getprop` 全部可读 |
| `/proc/version`、`/proc/cmdline`、`/proc/cpuinfo` | ✅ 能 | 判定内核与启动参数 |
| `getenforce`、`id` | ✅ 能 | 确认权限模型 |
| `/proc/kallsyms` 真实地址 | ❌ 不能 | 预期全 0（`kptr_restrict`+SELinux）→ **利用必须运行时泄露** |
| `/proc/slabinfo` | ❌ 大概率拒绝 | SLUB 布局无法据此精调（且非必需） |
| `dmesg` 内核日志 | ❌ Android 10 起基本拒绝 | 不要指望 |
| `adb root` | ❌ 必失败 | production build |
| 内核内存 / 分区裸设备 | ❌ | 需 root |

**结论**：连机能可靠回答的是"**运行内核 = 我们分析的那个 C.17 镜像吗**"和"**运行时有没有可利用的松口（SELinux 模式、kptr、cmdline 无 skip_initramfs 等）**"；**拿不到**利用素材。结构体偏移我们已从镜像静态提取，不依赖连机。

> 建议：**值得连一次**——10 分钟，用来把"镜像假设"钉成"实机事实"，避免后面白做。但不连也不影响报告结论。

---

## 1. 连接准备

1. 手机：设置 → 关于手机 → 连点"版本号"7 次开开发者选项 → 开发者选项 → 打开 **USB 调试**（不要动 OEM 解锁开关，避免触发不可逆动作）。
2. 数据线连电脑，手机弹窗勾选"**始终允许**"+确定。
3. 电脑端 adb（任选其一）：
   - PATH 里已有：`adb`（实测 `/d/platform-tools/adb`，1.0.41 / 36.0.1）
   - 或工作区内：`scrcpy-win64-v3.3.4/adb.exe`
4. 校验：`adb devices` 应看到 `device`（不是 `unauthorized` / `offline`）。

---

## 2. 一键采集脚本（另开会话直接整段粘贴）

在 git bash 里执行。会把结果写到手机 `/sdcard/k3_info.txt` 再拉回当前目录。**全部只读**。

```bash
ADB="adb"          # 如不在 PATH：ADB="/d/AI_tools/AI_Workspace/WBK_OPK_RT_CRA/scrcpy-win64-v3.3.4/adb.exe"
$ADB devices
$ADB shell '{
  echo "########## ID ##########"; id; echo
  echo "########## UNAME ##########"; uname -a; echo
  echo "########## /proc/version ##########"; cat /proc/version; echo
  echo "########## /proc/cmdline ##########"; cat /proc/cmdline; echo
  echo "########## cpuinfo(head) ##########"; head -30 /proc/cpuinfo; echo
  echo "########## SELINUX ##########"; getenforce; echo
  echo "########## getprop(K3关键项) ##########"
  for k in ro.product.model ro.product.device ro.product.board \
           ro.build.display.id ro.build.version.release ro.build.version.security_patch \
           ro.build.fingerprint ro.build.type ro.debuggable ro.secure \
           ro.boot.verifiedbootstate ro.boot.flash.locked ro.boot.veritymode \
           ro.boot.slot_suffix ro.boot.hardware ro.boot.bootloader ro.boot.baseband; do
    printf "%s = " "$k"; getprop "$k";
  done; echo
  echo "########## /proc/mounts(verity/dm) ##########"; grep -E "dm-|verity|/system|/vendor|/data" /proc/mounts; echo
  echo "########## kallsyms 可读性 ##########"; head -5 /proc/kallsyms; echo
  echo "########## kptr ##########"; cat /proc/sys/kernel/kptr_restrict 2>&1; echo
  echo "########## slabinfo 可读性 ##########"; head -5 /proc/slabinfo 2>&1; echo
  echo "########## dmesg 可读性 ##########"; dmesg 2>&1 | tail -5; echo
  echo "########## 深度测试APP是否在装 ##########"; pm list packages 2>/dev/null | grep -i -E "deep|deeptest|coloros.deeptesting"; echo
  echo "########## /proc/config.gz ##########"; ls -l /proc/config.gz 2>&1; echo
  echo "########## block by-name(A-only?) ##########"; ls -l /dev/block/by-name/ 2>&1 | head -30; echo
} > /sdcard/k3_info.txt 2>&1'
$ADB pull /sdcard/k3_info.txt ./k3_info.txt
```

再单独跑一条（会明确报失败，用于留证）：
```bash
$ADB root 2>&1
```

---

## 3. 逐项清单与判读（若想自己一条条来）

### A. 必读（决定这盘棋怎么下）

| # | 命令 | 预期 / 判读 |
|---|---|---|
| A1 | `adb shell getprop ro.product.model` | `PCGM00`=国行全网通；`PCGT00`=移动定制（深度测试资格可能受限）；其它=海外/改版 |
| A2 | `adb shell getprop ro.build.display.id` | 应为 `PCGM00_11_C.17`；**与镜像不一致则我们分析的镜像作废** |
| A3 | `adb shell getprop ro.build.version.security_patch` | 应为 `2021-05-05`（与镜像一致 → 同一构建） |
| A4 | `adb shell getprop ro.build.version.release` | `10` |
| A5 | `adb shell getprop ro.boot.verifiedbootstate` | `green`=已校验(锁)；`orange`=已解锁。**orange 则整份临时 root 分析可跳过，直接走 Magisk** |
| A6 | `adb shell getprop ro.boot.flash.locked` | `1`=锁定（预期） |
| A7 | `adb shell getprop ro.boot.veritymode` | `enforcing`（预期，影响能否改 system） |
| A8 | `adb shell getprop ro.debuggable` / `ro.secure` | `0` / `1`（预期，故 adb root 必失败） |
| A9 | `adb shell getenforce` | `Enforcing`（预期）；若 `Permissive` 是重大松口，需记录 |
| A10 | `adb shell id` | `uid=2000(shell)`（预期） |
| A11 | `adb shell cat /proc/version` + `uname -a` | 应含 `4.9.186`；**版本不符则镜像作废** |
| A12 | `adb shell cat /proc/cmdline` | 关键看：**有无 `skip_initramfs`**（有则影响 boot ramdisk 路径）；KASLR 相关参数 |
| A13 | `adb shell getprop ro.boot.slot_suffix` | 空 = A-only（与镜像 updater-script 结论一致则相互印证） |

### B. 选读（补充约束，能读就读）

| # | 命令 | 判读 |
|---|---|---|
| B1 | `adb shell head -5 /proc/kallsyms` | 预期全 `0000000000000000` → 确认"提权前读不到符号，KASLR 必须运行时泄露" |
| B2 | `adb shell cat /proc/sys/kernel/kptr_restrict` | 预期 `1` 或 `2`；若 `0` 且 kallsyms 可读则是松口 |
| B3 | `adb shell head -5 /proc/slabinfo` | 预期 `Permission denied` |
| B4 | `adb shell dmesg \| tail` | 预期拒绝；若可读，看有无 KASAN/锁dep 线索（不太可能） |
| B5 | `adb shell pm list packages \| grep -i deep` | 若已装 `com.coloros.deeptesting` → 深度测试路径可直接试 |
| B6 | `adb shell grep -E "dm-\|verity" /proc/mounts` | 确认 system/vendor 走 dm-verity |
| B7 | `adb shell ls -l /dev/block/by-name/` | 看分区布局（A-only 无 `_a/_b`） |

### C. 不必读（读了也白读，别浪费时间）

- 任何 `/proc/pid/mem`、`/dev/kmem`、`/dev/block/mmcblk0` 裸读（需 root）
- `adb shell su`（无 su）
- `/data/` 其它用户目录（无权限，且涉及隐私，**不要碰**）

---

## 4. 回传格式（给后续会话用）

把 `k3_info.txt` 整份贴回，或至少回传这几行结论：

```
model=
display.id=
security_patch=
release=
verifiedbootstate=
flash.locked=
veritymode=
debuggable=/secure=
getenforce=
uname(kernel)=
cmdline has skip_initramfs? (Y/N)
kallsyms readable? (全0/有值)
deeptesting installed? (Y/N)
```

判读要点一句话：
- **A2/A3/A11 与镜像不一致** → 我们分析的不是这台机器，镜像我方结论作废，需重取。
- **A5=orange** → 别做临时 root，直接走 Magisk（省 3 周）。
- **B1 全 0** → 确认利用需运行时泄露，工作量按报告 §5 计。
- **B5 有 deeptesting** → 优先评估官方解锁，可能一步到位拿持久 root。

---

## 5. 安全禁忌（务必遵守）

1. **只读**：上面全部命令只读；**不要**执行 `adb reboot bootloader`、`fastboot flash`、`fastboot oem`、`adb shell rm/dd`、`pm uninstall`、改 `settings` 等写操作。
2. **不要动 OEM 解锁开关**：部分机型切换会触发熔断/清数据。
3. **不要装来源不明的 root/深度测试 APK**：先核验签名与来源。
4. 拔线前先 `adb kill-server` 可选，不影响。
