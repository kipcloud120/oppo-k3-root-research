# F.16 用户态二进制 net_device 私有 ioctl 常量盘点（0x89f1 / 0x89fd）

> 范围：**离线**静态盘点 F.16 官方固件物料中「哪些随固件发布的用户态 ELF 会把
> `SIOCDEVPRIVATE+1 (0x89f1)` / `SIOCDEVPRIVATE+13 (0x89fd)` 作为 `ioctl(2)` 的
> 第 2 个参数发出去」，并把 `wpa_supplicant` 的 4 处 0x89f1 归属到函数/命令。
> 全程未连接设备、未动态运行、未联网；不修改 `HANDOVER.md` / `README.md` /
> `CLOSURE.md` / `HANDOVER_RESUME.md` / `GHOSTLOCK_ADDRESS_SOURCE_MATRIX.md`。
>
> **边界**：本文只回答“谁发这个 ioctl、从哪条路径发”。**不**推断漏洞、**不**讨论
> 提权、**不**判断该 ioctl 的参数校验是否充分。kernel 侧（`hdd_ioctl` /
> `hdd_driver_command` / FTM `con_mode==5`）不在本文展开。

---

## 0. 结论摘要

| 结论 | 内容 |
|---|---|
| 扫描规模 | 2063 个文件（vendor.img 的 `bin\`+`bin\hw\`+`lib64\`+`lib\` 共 2025 个；odm.img 的 `bin\` 38 个）；其中 ELF 1964 个（AArch64 1157 / ARM 807），另有 99 个非 ELF 或非 ARM/QDSP6 |
| 指令级确认的调用点 | **20 条 CONFIRMED**（7 个文件），另有 **5 条 WEAK（仅常量，未构成 ioctl 调用）** |
| 能向 **WLAN netdev** 发 0x89f1 的 | `wpa_supplicant`(4)、`hostapd`(4)、`sigma_dut`(1)、`lowi-server`(1) |
| 能向 **WLAN netdev** 发 0x89fd 的 | **无（0 条）**。`ftmdaemon` / `myftm` / `ftmtest` / `ftm_flows_test` / `libwifi-hal-qcom.so` / `libwigig_ftm_flows.so` 中**连 0x89fd 常量都不存在** |
| 0x89fd 的 10 条命中 | 全部是 **RMNET** 私有 ioctl（`netmgrd` 6、`qti` 3、`adpl` 1），作用于 `rmnet_mhi0/1`、`usb_rmnet0` 等 rmnet netdev；与 wlan 的 FTM 语义无关 |
| `wpa_cli` | 只走控制 socket：**不导入 `ioctl` 符号、无 0x89f1/0x89fd 常量**；`DRIVER <cmd>` 由 `sendto/select/recvfrom` 发到 wpa_supplicant 的 ctrl socket |
| `iwpriv` / `iwpriv_vendor` | 无 0x89f1/0x89fd 常量、无命中（与既有结论一致） |
| `qca_cld3_wlan.ko` | 4 处常量，均为**内核侧受理方**（WEAK，无 ioctl 调用），不是调用方 |

一句话：**F.16 里真正会发 wlan 私有 0x89f1 的随固件二进制是
`wpa_supplicant`、`hostapd`、`sigma_dut`、`lowi-server`；0x89fd 在用户态没有任何
wlan 调用方，命中 0x89fd 的 netmgrd/qti/adpl 是 RMNET 的私有 ioctl。**

---

## 1. 物料与解压

| 项 | 结果 |
|---|---|
| 磁盘余量（解压前 `Get-PSDrive D`） | Free ≈ 39.0 GB |
| `vendor.img` | 2,248,146,944 B ext4；顶层 2699 文件/126 目录 |
| 选择性解压 | `7z x vendor.img -o.build\vendor_bins\vendor "bin\*" "lib64\*" "lib\*"` |
| `odm.img` | 174,800,896 B，`/odm`；解压 `bin\*` → `.build\vendor_bins\odm` |
| 落地文件 | vendor：bin 363 + lib 885 + lib64 777 = 2025；odm：38；合计 2063 |
| 符号链接 | 本目录内 184 个 symlink 条目在无特权下无法建链；按镜像内相对目标复制实体 73 个，其余 111 个解压结果本身已有实体内容；最终 **0 个 0 字节文件**，与 `list.txt` 名单对比 **2025/2025 命中、0 缺失** |
| 未解目录 | `etc\`、`app\`、`firmware\`、`radio\`、`rfs\`、`overlay\`、`dsp\` 等不在本次范围（任务只要 bin/lib/lib64）；`etc\wifi\*` 仅用于交叉核对，未参与扫描 |

> 说明：`bin\` 下大量 13 B 文件是 toybox/vendor toybox 的符号链接；已按目标
> 复制成实体，扫描器按 `\x7fELF` 魔数判定，不会把它们当 ELF。

---

## 2. 工具与判定标准（`tools/scan_ioctl_bin.py`）

新增可复跑工具，核心不是“全文件搜字节”，而是**节区级反汇编 + 指令级确认**：

1. 只反汇编带 `SHF_EXECINSTR` 的节区（`.text` 等），避免 `.rodata`/`.dynsym`/字符串里的同值字节误报。
2. **常量站点**：AArch64 上识别 `mov/movz/movk/orr/add/...` 立即数 == 目标值，以及
   `ldr wN, [pc, #imm]` 从字面量池加载到目标值；ARM 上识别 `movw/mov` + PC 相对 `ldr`。
3. **指令级确认**：从常量站点向前做 ≤96 条指令的短程寄存器数据流，跟踪 `w1/x1`
   是否仍持有该值；只有遇到 `bl <ioctl>` 且 `w1 == cmd` 才记 **CONFIRMED**。
   中途 `ret`、无关 `bl`（清 caller-saved）、`w1` 被覆盖、间接 `blr` 都判不成立。
4. **PLT 解析**：`.rela.plt` 顺序 == PLT stub 顺序；stub 几何用 `reloc[0]` 的 GOT 槽
   反推校验（AArch64 为 `.plt+0x20+i*0x10`），并有 symtab/dynsym 直接符号回退。
5. 输出：文件 / 节区 / 文件偏移 / 指令地址 / 指令 / `ioctl` 调用点 / 解析到的导入符号 /
   `CONFIRMED|WEAK`，可 `--json` 落全量记录。

**二次校验**：对每个 CONFIRMED 命中，独立解码 `bl` 目标，验证其等于
`.plt+0x20+index_of("ioctl")*0x10`。20/20 全部相等（见 §3 表），排除 PLT 错位导致的假阳性。

复跑：

```powershell
python tools\scan_ioctl_bin.py .build\vendor_bins --jobs 8 --max-insn 96 `
    --json .build\ioctl_scan_all.json --text .build\ioctl_scan_all.txt
```

---

## 3. 全量命中表（20 CONFIRMED + 5 WEAK）

> 下述二进制均来自 `.build\vendor_bins\`；`off` = 文件内偏移，`va` = 指令虚拟地址
> （本批 ELF 的 `.text` 两者相等）。`ioctl@` 为 `bl` 指令地址，导入符号均为 `ioctl`。
> “归属函数”由函数边界 + 函数内 `__func__`/日志字符串 + 调用者交叉确认。

### 3.1 WLAN 域（qca_cld3_wlan netdev）——0x89f1，共 10 条

| 二进制 | cmd | off | va | 指令 | ioctl@ | 归属函数（起始 VA） |
|---|---|---|---|---|---|---|
| `vendor\bin\hw\wpa_supplicant` | 0x89f1 | 0x2a22f4 | 0x2a22f4 | `mov w1, #0x89f1` | 0x2a22fc | `android_priv_cmd` (0x2a21d4) |
| `vendor\bin\hw\wpa_supplicant` | 0x89f1 | 0x2ac688 | 0x2ac688 | `mov w1, #0x89f1` | 0x2ac690 | `ops->sched_scan` (0x2ac40c) |
| `vendor\bin\hw\wpa_supplicant` | 0x89f1 | 0x2c2a14 | 0x2c2a14 | `mov w1, #0x89f1` | 0x2c2a1c | `wpa_driver_nl80211_driver_cmd` 通用透传 (0x2c2174) |
| `vendor\bin\hw\wpa_supplicant` | 0x89f1 | 0x2c2edc | 0x2c2edc | `mov w1, #0x89f1` | 0x2c2ee4 | `GETCOUNTRYREV` helper (0x2c2e44) |
| `vendor\bin\hw\hostapd` | 0x89f1 | 0xb71ec | 0xb71ec | `mov w1, #0x89f1` | 0xb71f4 | `android_priv_cmd` (0xb70c8) |
| `vendor\bin\hw\hostapd` | 0x89f1 | 0xc12a4 | 0xc12a4 | `mov w1, #0x89f1` | 0xc12ac | `sched_scan/PNO` (0xc1028) |
| `vendor\bin\hw\hostapd` | 0x89f1 | 0x105824 | 0x105824 | `mov w1, #0x89f1` | 0x10582c | `wpa_driver_nl80211_driver_cmd` (0x104f84) |
| `vendor\bin\hw\hostapd` | 0x89f1 | 0x105cec | 0x105cec | `mov w1, #0x89f1` | 0x105cf4 | `wpa_driver_ioctl` (0x105ab4) |
| `vendor\bin\sigma_dut` | 0x89f1 | 0x4dbc8 | 0x4dbc8 | `mov w1, #0x89f1` | 0x4dbd8 | `sendDrvCmd` helper (0x4db40) |
| `vendor\bin\lowi-server` | 0x89f1 | 0x9ff5c | 0x9ff5c | `mov w1, #0x89f1` | 0x9ff68 | `LOWIWifiDriverUtils::sendDriverCmd` (0x9fe64) |

### 3.2 RMNET 域（rmnet netdev）——0x89fd 共 10 条 + 1 条 0x89f1 WEAK

> 这些函数的日志字符串明确写 `RMNET_IOCTL_*`、设备名 `rmnet_mhi0/1`、`usb_rmnet0`，
> 属于 **rmnet 驱动的私有 ioctl 编号空间**，不是 wlan0 的 FTM。

| 二进制 | cmd | off | va | 指令 | ioctl@ | 归属函数 |
|---|---|---|---|---|---|---|
| `vendor\bin\netmgrd` | 0x89fd | 0x74194 | 0x74194 | `mov w1, #0x89fd` | 0x741a8 | `netmgr_kif_ifioctl_change_sleep_state`（RMNET_IOCTL_SET_SLEEP_STATE） |
| `vendor\bin\netmgrd` | 0x89fd | 0x74dd0 | 0x74dd0 | `mov w1, #0x89fd` | 0x74ddc | `netmgr_kif_extended_ioctl` |
| `vendor\bin\netmgrd` | 0x89fd | 0x763cc | 0x763cc | `mov w1, #0x89fd` | 0x763e8 | `netmgr_kif_ifioctl_get_ep_pair`（GET_EP_PAIR） |
| `vendor\bin\netmgrd` | 0x89fd | 0x772e4 | 0x772e4 | `mov w1, #0x89fd` | 0x77300 | `netmgr_kif_ifioctl_get_epid`（GET_EPID） |
| `vendor\bin\netmgrd` | 0x89fd | 0x94508 | 0x94508 | `mov w1, #0x89fd` | 0x94524 | `netmgr_kif_get_qos_header_format` |
| `vendor\bin\netmgrd` | 0x89fd | 0x9579c | 0x9579c | `mov w1, #0x89fd` | 0x957b0 | `netmgr_kif_ifioctl_set_qos_version` |
| `vendor\bin\netmgrd` | 0x89f1 | 0x7ba6c | 0x7ba6c | `mov w8, #0x89f1` → `cinc w21,w8,ne` | 0x7baa0 | `netmgr_kif_ifioctl_set_llpmode`（**WEAK**：实际 cmd 为 0x89f1 或 0x89f2，取决于 LLP 模式） |
| `vendor\bin\qti` | 0x89fd | 0xee3c | 0xee3c | `mov w1, #0x89fd` | 0xee50 | `qti_rmnet_ph_set_mru`（dev `usb_rmnet0`） |
| `vendor\bin\qti` | 0x89fd | 0x126ac | 0x126ac | `mov w1, #0x89fd` | 0x126c0 | `qti_rmnet_modem_set_mru`（dev `rmnet_mhi0`） |
| `vendor\bin\qti` | 0x89fd | 0x12a50 | 0x12a50 | `mov w1, #0x89fd` | 0x12a64 | `qti_rmnet_modem_change_sleep_state`（dev `rmnet_mhi0`） |
| `vendor\bin\adpl` | 0x89fd | 0xa13c | 0xa13c | `mov w1, #0x89fd` | 0xa150 | `adpl_modem_set_mru`（dev `rmnet_mhi1`） |

### 3.3 内核受理侧（非调用方，WEAK）

| 二进制 | cmd | off | va | 指令 | 判定 |
|---|---|---|---|---|---|
| `vendor\lib\modules\qca_cld3_wlan.ko` | 0x89fd | 0x38178 | 0x38138 | `mov w8, #0x89fd` | WEAK：`hdd_ioctl` 的 cmd 分发，随后走 `b` 比较，不是在用户态调 ioctl |
| `vendor\lib\modules\qca_cld3_wlan.ko` | 0x89f1 | 0x38250 | 0x38210 | `mov w8, #0x89f1` | WEAK：同上 |
| `vendor\lib\modules\qca_cld3_wlan.ko` | 0x89f1 | 0x2da0d8 | 0x2da098 | `mov w8, #0x89f1` | WEAK：ret 前仅常量 |
| `vendor\lib\modules\qca_cld3_wlan.ko` | 0x89f1 | 0x2da104 | 0x2da0c4 | `mov w4, #0x89f1` | WEAK：ret 前仅常量 |

> 这正是“常量出现 ≠ 调用”的对照：同一常量在 .ko 里是**受理方**的 cmd 比较，
> 工具不会把它算成调用方。

---

## 4. `wpa_supplicant` 的 4 处 0x89f1（重点）

物料：`.build\vendor_bins\vendor\bin\hw\wpa_supplicant`（3,364,080 B，AArch64，
`.text @ 0xc9000, size 0x24cd3c`；`.plt @ 0x315d40`；无 `.symtab`，只有 `.dynsym`）。

四处共同形态（完全一致的三指令尾巴）：

```asm
mov  w1, #0x89f1          ; ioctl request = SIOCDEVPRIVATE+1
ldr  w0, [x8, #0x4c]      ; x8 = bss/drv → ioctl_sock
bl   ioctl                ; .plt+0x20+idx*0x10  (wpa_supplicant 中为 0x316e20)
```

`w1` 前一条是 `sub/add x2, <&ifreq>`，`ifreq.ifr_name` 来自驱动对象的 `ifname`
（`drv+0x20` / `bss+0x20`），`ifr_ifru.ifru_data` 指向栈上的 `android_priv_cmd`
（`{char *buf; int used_len; int total_len;}`）。因此 4 处都是
**AF_INET socket + `ioctl(sock, 0x89f1, &ifreq)`**，不是别的 ioctl。

### 4.1 归属

| # | VA | 所在函数（起始 VA） | 函数角色 | 触发路径 |
|---|---|---|---|---|
| 1 | 0x2a22f4 | `android_priv_cmd`（0x2a21d4） | nl80211 的通用「发私有命令」helper：`android_priv_cmd(bss, cmd)`，`ifname` 取自 `bss+0x20`，`priv_cmd.buf` 指向函数内 0xf8 字节命令缓冲 | 本 build 仅 2 个调用者，且都是固定子命令：0x2ac6ac 传 `"PNOFORCE 1"`、0x2acb80 尾调用传 `"PNOFORCE 0"`（PNO 调度扫描启动/停止） |
| 2 | 0x2ac688 | `ops->sched_scan`（0x2ac40c；ops 表偏移 **0x340**） | 组装 PNO 调度扫描计划（`"PNOSETUP "` + 计划/SSID/频率），直接 ioctl 下发；失败日志 `ioctl[SIOCSIWPRIV] (pnosetup): %d` | wpa_supplicant 内部 PNO/sched_scan 流程（非控制通道 DRIVER） |
| 3 | 0x2c2a14 | `wpa_driver_nl80211_driver_cmd`（0x2c2174；ops 表偏移 **0x308**） | **通用 else 分支**：先把 `cmd` 拷进调用者的 `buf`，`priv_cmd.buf=buf/used_len=total_len=buf_len`，再 ioctl；返回后按响应内容后处理 `SETBAND` / `LINKSPEED` / `RSSI` / `GET` | **`wpa_cli DRIVER <cmd>` 控制通道**（见 §4.2）；命中所有未被前面特殊分支/OEM 回调拦截的任意子命令 |
| 4 | 0x2c2edc | `GETCOUNTRYREV` helper（0x2c2e44） | 固定子命令：把 `"GETCOUNTRYREV"` 写入调用者缓冲，ioctl 后打印 `"Response: %s"` | 被 `wpa_driver_nl80211_driver_cmd` 的 `GETSTATSBSSINFO` 分支调用（0x2c2344 比较 → 0x2c2358 `cbz` → 0x2c25dc → 0x2c260c `bl 0x2c2e44`），另在 0x2c3f88 的 station 信息 helper 中再调用一次 |

**证据摘录（文件偏移 = VA）**

```
0x2a22f4: 2a22f0 sub x2, x29, #0x30
          2a22f4 mov w1, #0x89f1
          2a22f8 ldr w0, [x8, #0x4c]
          2a22fc bl  0x316e20        ; PLT ioctl
          2a2320 add x1, ... ; "%s: failed to issue private commands"
          2a2324 add x2, ... ; "android_priv_cmd"        ← __func__

0x2ac688: 2ac684 sub x2, x29, #0x40
          2ac688 mov w1, #0x89f1
          2ac68c ldr w0, [x8, #0x4c]
          2ac690 bl  0x316e20
          2ac750 add x1, ... ; "ioctl[SIOCSIWPRIV] (pnosetup): %d"
          2ac6a0 add x1, ... ; "PNOFORCE 1"  → bl android_priv_cmd

0x2c2a14: 2c2a10 add x2, sp, #0x30
          2c2a14 mov w1, #0x89f1
          2c2a18 ldr w0, [x8, #0x4c]
          2c2a1c bl  0x316e20
          2c2a2c add x1, ... ; "SETBAND"（ioctl 之后按响应后处理）

0x2c2edc: 2c2ed8 add x2, sp, #0x10
          2c2edc mov w1, #0x89f1
          2c2ee0 ldr w0, [x8, #0x4c]
          2c2ee4 bl  0x316e20
          2c2eec add x1, ... ; "Response: %s"
          2c2e6c add x24, ...; "GETCOUNTRYREV"
```

### 4.2 控制通道：是不是 wpa_cli 的 `DRIVER <cmd>`？——是

`wpa_supplicant` 侧完整链路（全部为静态证据）：

```
ctrl_iface 分发函数（起始 0x212ae8）
  0x213bdc  adrp/add x1 → "DRIVER "   ; 比较前缀，长度 7
  0x213be0  ...  bl os_strncmp
  0x213bf0  cbz w0 → 0x226748
0x226748  handler:
  x0 = wpa_s, x1 = cmd+7（跳过 "DRIVER "）, x2 = reply buf, w3 = 0x1000
  0x22675c  bl 0x212924
0x212924  wpa_drv_driver_cmd:
  0x212948  ldr x8, [x0, #0x298]     ; wpa_s->driver（ops）
  0x21294c  ldr x8, [x8, #0x308]     ; ops->driver_cmd
  0x212984  blr x8                   ; 间接调用
ops 表 @0x31e970：name="nl80211", desc="Linux nl80211/cfg80211"
  ops+0x308 (0x31ec78) = 0x314510   ; veneer: b #0x2c2174
  → 0x2c2174 wpa_driver_nl80211_driver_cmd
      → §4.1 site 3 的通用 else → ioctl(fd, 0x89f1, &ifreq)
```

补充事实：

* 0x212954–0x212970 把 `ops->driver_cmd` 与 `0x314510`（nl80211 版本的 veneer）
  做比较（`adrp/add x9,#0x314510` 后 `cmp x8,x9`）；相等走一条“少打一条日志”的
  路径，不等则先打一条日志（0x212a50）再回到 0x212974。两条路径最终都 `blr x8`，
  不影响调用链结论。
* **本 build 只有 nl80211 一张 driver ops 表**（`.data.rel.ro` 中 name 指针仅
  `"nl80211"`；没有 `"wext"` ops 表），也**没有** `wpa_driver_wext_driver_cmd`
  的 `__func__` 字符串（只有 `"wpa_driver_nl80211_driver_cmd"` @0x75447）。
  因此 4 处都**不属于** `wpa_driver_wext_driver_cmd`；site 3 直接属于
  `wpa_driver_nl80211_driver_cmd`，其余 3 处是同一 nl80211 driver 模块内的函数。
* 该 dispatcher 开头会 `dlopen("/vendor/lib64/libwpa_drv_oem.so")` 并尝试
  `oem_generic_cb_table` 回调；**镜像中不存在这个 .so**（已核对 `vendor.img`
  `lib64\` 列表与解压结果），所以 OEM 分支在 F.16 上不会命中，`DRIVER <cmd>`
  最终落到 site 3 的通用 ioctl 透传。
* `wpa_cli` 侧：控制命令表项 `"DRIVER"`（0x1464c 附近，带 `w2=1` 参数个数），
  0x1f8c0–0x1f8dc 以 `"%s"` + `"DRIVER"` 组装 `"DRIVER <cmd>"`，0x1f994 调
  0x21a0c → 0x255f8（静态链接的 `wpa_ctrl_request`），后者内部
  `sendto` / `select` / `recvfrom`（PLT 符号已核对）。`wpa_cli` 的 `.dynsym`
  **没有 `ioctl`**，全文件也没有 0x89f1/0x89fd 常量。

> 注意：`wpa_cli DRIVER <cmd>` 只保证把命令送到 site 3 的通用透传；
> site 1/2/4 是 wpa_supplicant 内部流程（PNO / GETCOUNTRYREV）另行触发的，
> 不经过 `DRIVER` 控制命令。

### 4.3 4 处的差异（固定子命令 vs 通用透传）

| # | 命令来源 | 固定/透传 | 说明 |
|---|---|---|---|
| 1 | `android_priv_cmd(bss, cmd)` 的 `cmd` 参数 | **固定**（本 build 只有 `PNOFORCE 0/1`） | 通用 helper，但调用点固定为 PNO 强制开关；`priv_cmd.buf` 是函数内 0xf8 缓冲，`used_len=total_len=0xf8` |
| 2 | 函数内构造 `"PNOSETUP "` + 计划 | **固定前缀 + 动态计划内容** | 只服务 PNO `sched_scan`；`ops+0x340`，不是控制通道 |
| 3 | 调用者传入的 `cmd`/`buf`/`buf_len` | **通用透传** | `DRIVER <cmd>` 的主体；除特殊分支（`START`/`MACADDR`/`SET_TXPOWER`/`GETSTATSBSSINFO`/`GETSTATSSTAINFO`/`SETCELLSWITCHMODE`/`SET_ANI_LEVEL`/`GET_THERMAL_INFO`）外都走这里 |
| 4 | 函数内固定 `"GETCOUNTRYREV"` | **固定子命令** | 查询国家码版本；被 `GETSTATSBSSINFO` 分支与 station helper 复用 |

---

## 5. 其它 WLAN 相关二进制

### 5.1 `hostapd`（`vendor\bin\hw\hostapd`，1,155,376 B）

4 处 0x89f1，结构与 wpa_supplicant 同源（同一套 Android/QCA driver 代码）：

| VA | 归属 |
|---|---|
| 0xb71ec | `android_priv_cmd`（0xb70c8，`__func__` = "android_priv_cmd"） |
| 0xc12a4 | `sched_scan/PNO`（0xc1028，`ioctl[SIOCSIWPRIV] (pnosetup)`） |
| 0x105824 | `wpa_driver_nl80211_driver_cmd`（0x104f84；`__func__` = "wpa_driver_nl80211_driver_cmd"） |
| 0x105cec | `wpa_driver_ioctl`（0x105ab4；同函数含 `P2P_DEV_ADDR`/`P2P_SET_NOA`/`P2P_SET_PS`） |

### 5.2 `sigma_dut`（`vendor\bin\sigma_dut`）

* 0x4dbc8 `mov w1,#0x89f1` → 0x4dbd8 `bl ioctl`。
* 函数 0x4db40 是 `sendDrvCmd(ifname, cmd)`：`socket(AF_INET, SOCK_DGRAM, 0)`、
  16 字节 `ifr_name`、`priv_cmd{buf=cmd, len}`、`ioctl(fd,0x89f1,&ifreq)`。
* 调用点 0x5e15c 传入的命令由 0x5e13c 的 `"FASTREASSOC %s %d"` 格式化而来，
  调用方函数（0x5dc98 起）同时引用 `CTRL-EVENT-SCAN-RESULTS`、`bssid` 等 Wi-Fi
  字符串，二进制内含 `wlan0` 字符串——DUT 的 Wi-Fi 测试路径。

### 5.3 `lowi-server`（`vendor\bin\lowi-server`）

* 0x9ff5c `mov w1,#0x89f1` → 0x9ff68 `bl ioctl`。
* 函数 0x9fe64（`LOWIWifiDriverUtils::sendDriverCmd`）内字符串：
  `"ioctl(SIOCDEVPRIVATE + 1) returned %d"`、`"sendDriverCmd: socket(ioctlSock) returned: %d"`、
  `"wifi.interface is %s"` —— 明确是 WLAN 私有命令。

### 5.4 `iwpriv` / `iwpriv_vendor`（odm `bin\`）

两者均：ELF 解析成功、`consts=0`、`hits=0`、`weak=0`。即**全文中不存在**
0x89f1/0x89fd 立即数，更不存在对应 ioctl 调用；与“iwpriv 只发 SIOCGIFCONF /
SIOCGIWNAME / SIOCGIWRANGE / SIOCGIWPRIV / 0x8954 / SIOCGIFHWADDR / SIOCGIFADDR”
的既有结论一致。

### 5.5 FTM / 0x89fd 专项

| 二进制 | 0x89fd 常量 | 说明 |
|---|---|---|
| `vendor\bin\ftmdaemon` | 无（全文件 0 字节匹配） | 由 `bin\wififtm` 脚本设 `con_mode=5` 后启动，但自身不发 0x89fd |
| `vendor\bin\myftm` | 无 | 同上 |
| `vendor\bin\ftmtest` | 无 | 同上 |
| `vendor\bin\ftm_flows_test` | 无 | 同上 |
| `vendor\lib64\libwifi-hal-qcom.so` / `lib\...` | 无 | 32/64 位均无 |
| `vendor\lib64\libwigig_ftm_flows.so` / `lib\...` | 无 | 同上 |
| `vendor\bin\wifihwftm` | 非 ELF（217 B shell） | 脚本，不是调用方 |
| `vendor\bin\wpa_supplicant` | 无 | 只有 4×0x89f1 |

> 结论：在 F.16 的 vendor 用户态物料里，**没有找到任何向 wlan netdev 发 0x89fd
> 的二进制**；`hdd_ioctl` 的 0x89fd/FTM 分支在用户态没有静态可见的调用方。
> （若存在通过 `iwpriv` 动态取号或经厂商私有库转发的情形，属于本文方法学盲区，
> 见 §7；但就“立即数 + ioctl 同函数”这一层，结论为 0。）

---

## 6. 未取得 / 解压失败 / 非 ELF 清单

### 6.1 未解压（按任务范围省略）

`vendor.img` 顶层除 `bin\`、`lib\`、`lib64\` 外的目录未解：`etc\`(591)、`rfs\`(88)、
`app\`(36)、`firmware\`(32)、`radio\`(12)、`overlay\`(3)、`euclid\`(3)、`dsp\`、
`lost+found\`、`firmware_mnt\`、`bt_firmware\`，以及根下 `build.prop`/`default.prop`/
`ueventd.rc`/`recovery-from-boot.p`。这些目录不含用户态 ELF 调用方（`etc\` 只有配置）。

### 6.2 解压失败 / 缺失

* 184 个 symlink 条目无法在 Windows 无特权下建链；已全部按镜像内相对目标复制为
  实体文件（73 个现复制，111 个解压结果本身已有实体内容），**0 个 0 字节文件**；
  与 `7z l` 名单对比 2025/2025，**无缺失路径**。
* odm.img `bin\`：38/38 全部落地。

### 6.3 非 ELF（62 个，按魔数判定，均按设计不参与扫描）

```
odm\bin\engineer_vendor_shell.sh        odm\bin\init.oplus.bsp_debug.sh
odm\bin\init.oplus.bsp_us_dump.sh       odm\bin\init.oppo.fingerprints.sh
odm\bin\init.oppo.wifi.sh               odm\bin\init.vendor.wifi.autochmod.sh
odm\bin\vendor.autochmod.sh
vendor\bin\init.at.class_main.sh        vendor\bin\init.at.post_boot.sh
vendor\bin\init.class_main.sh           vendor\bin\init.crda.sh
vendor\bin\init.mdm.sh                  vendor\bin\init.qcom.class_core.sh
vendor\bin\init.qcom.coex.sh            vendor\bin\init.qcom.early_boot.sh
vendor\bin\init.qcom.efs.sync.sh        vendor\bin\init.qcom.post_boot.sh
vendor\bin\init.qcom.sdio.sh            vendor\bin\init.qcom.sensors.sh
vendor\bin\init.qcom.sh                 vendor\bin\init.qcom.usb.sh
vendor\bin\init.qti.chg_policy.sh       vendor\bin\init.qti.qcv.sh
vendor\bin\install-recovery.sh          vendor\bin\qca6234-service.sh
vendor\bin\qtigetprop                   vendor\bin\qtisetprop
vendor\bin\wififtm                      vendor\bin\wififtmtest
vendor\bin\wifihwftm                    vendor\bin\wifisar
vendor\bin\wifistopftmtest
vendor\lib64\camera\com.qti.sensormodule.ofilm_imx519.bin
vendor\lib64\camera\com.qti.sensormodule.shine_gc2375.bin
vendor\lib64\camera\com.qti.sensormodule.truly_imx471.bin
vendor\lib64\camera\com.qti.sensormodule.trulyi2c20_imx471.bin
vendor\lib64\camera\com.qti.tuned.default_full_iq.bin
vendor\lib64\camera\com.qti.tuned.ofilm_18041_imx519.bin
vendor\lib64\camera\com.qti.tuned.shine_gc2375.bin
vendor\lib64\camera\com.qti.tuned.truly_imx471.bin
vendor\lib64\camera\data.zip
vendor\lib64\camera\fdconfigpreview.bin
vendor\lib64\camera\fdconfigpreviewlite.bin
vendor\lib64\camera\fdconfigvideo.bin
vendor\lib64\camera\fdconfigvideolite.bin
vendor\lib\camera\com.qti.sensormodule.ofilm_imx519.bin
vendor\lib\camera\com.qti.sensormodule.shine_gc2375.bin
vendor\lib\camera\com.qti.sensormodule.truly_imx471.bin
vendor\lib\camera\com.qti.sensormodule.trulyi2c20_imx471.bin
vendor\lib\camera\com.qti.tuned.default_full_iq.bin
vendor\lib\camera\com.qti.tuned.ofilm_18041_imx519.bin
vendor\lib\camera\com.qti.tuned.shine_gc2375.bin
vendor\lib\camera\com.qti.tuned.truly_imx471.bin
vendor\lib\camera\fdconfigpreview.bin
vendor\lib\camera\fdconfigpreviewlite.bin
vendor\lib\camera\fdconfigvideo.bin
vendor\lib\camera\fdconfigvideolite.bin
vendor\lib\modules\modules.alias               vendor\lib\modules\modules.dep
vendor\lib\modules\modules.load                vendor\lib\modules\modules.softdep
vendor\lib\voc.dat.zip
```

### 6.4 架构不支持（37 个，`EM_QDSP6`/Hexagon DSP，不可能发 Linux ioctl）

`vendor\lib\rfsa\adsp\` 与 `vendor\lib64\rfsa\adsp\` 下：
`libdsp_streamer_add_constant.so`、`libdsp_streamer_skel.so`、
`libsns_device_mode_skel.so`、`libsns_low_lat_stream_skel.so`、
`capi_v2_aptX_Classic.so`、`capi_v2_aptX_HD.so`、`libBeautyShot_skel.so`、
`libVC1Dec.so`、`libVC1DecDsp_skel.so`、`libVDHexagonBlurless_skel.so`、
`libVDHexagonBlurless_v2_skel.so`、`libVDHexagonSuperPhoto_skel.so`、
`libapps_mem_heap.so`、`libarcsoft_dualcam_refocus_skel.so`、
`libarcsoft_hdrplus_hvx_skel.so`、`libc++.so.1`、`libc++abi.so.1`、
`libcamera_nn_skel.so`、`libdepthmap_skel.so`、`libdspCV_skel.so`、
`libfastcvadsp.so`、`libfastcvdsp_skel.so`、`libhexagon_nn_skel.so`、
`libktvdrc.so`、`libktveffect.so`、`libktveq.so`、`libktvns.so`、
`libktvpitchshift.so`、`libktvreverb.so`、`libktvvolume.so`、`libproxy_skel.so`、
`libscveObjectSegmentation_skel.so`、`libscveT2T_skel.so`、
`libsnpe_dsp_v65_domains_v2_skel.so`、`libsns_device_mode_skel.so`、
`libsns_low_lat_stream_skel.so`、`libthread_blur_skel.so`。

---

## 7. 方法学与局限（影响结论强度的点）

1. **只认同一函数内的数据流**。若某个 helper 把 `cmd` 当参数、内部再 `ioctl(fd, cmd, …)`，
   调用方只会留下常量站点（WEAK）或漏报；本次 20 条 CONFIRMED 全部是
   `mov wN, #imm` 与 `bl ioctl` 同函数，无跨函数传递。
2. **只扫可执行节区**。`.rodata`/`.data` 中出现 0x89f1 不算调用（本报告不收录）。
3. **ARM 32 位为尽力而为**：`movw/mov` + PC 相对 `ldr` + PLT 几何探测；807 个 ARM ELF
   扫描后 0 命中。AArch64 为完整实现。
4. **不判断 fd 一定指向 wlan0**。WLAN 组按 `ifname`/`wifi.interface`/`wlan0` 字符串与
   结构布局判定；RMNET 组按函数名、`rmnet_mhi*`/`usb_rmnet0` 设备名与
   `RMNET_IOCTL_*` 日志判定。两组**数值相同但 netdev 私有 ioctl 命名空间不同**。
5. 未做反编译级别名分析；未追踪通过函数指针表间接调用 `ioctl`（如 `blr`）的路径——
   遇到时工具记 WEAK/停止，不会误判为 CONFIRMED。

---

## 8. 产物

| 路径 | 说明 |
|---|---|
| `tools/scan_ioctl_bin.py` | 可复跑扫描器（目录/文件列表 → 文本表 + JSON） |
| `.build/vendor_bins/vendor/{bin,lib,lib64}` | vendor.img 选择性解压结果（2025 文件） |
| `.build/vendor_bins/odm/bin` | odm.img `bin\` 解压结果（38 文件） |
| `.build/ioctl_scan_all.json` / `.txt` | 本次全量扫描原始输出（2063 文件） |
| `artifacts_adb/r1_wlan_reach/ioctl_const_inventory.md` | 本文 |

复跑命令：

```powershell
python tools\scan_ioctl_bin.py .build\vendor_bins --jobs 8 --max-insn 96 `
    --json .build\ioctl_scan_all.json --text .build\ioctl_scan_all.txt
```

---

## 9. 最终结论（一段话）

在 F.16 官方 vendor/odm 用户态物料（2063 个文件、1964 个 ARM/AArch64 ELF）中，
带**指令级 `ioctl` 证据**的 `0x89f1` 调用点共 10 处，全部位于 WLAN 域：
`wpa_supplicant` 4 处（`android_priv_cmd`、`ops->sched_scan`、`wpa_driver_nl80211_driver_cmd`
通用透传、固定 `GETCOUNTRYREV` helper）、`hostapd` 4 处（同源四角色）、`sigma_dut` 1 处
（`FASTREASSOC` 等 DUT 命令）、`lowi-server` 1 处（`sendDriverCmd`）。`wpa_cli` 不直接
ioctl，只把 `DRIVER <cmd>` 经控制 socket 送给 `wpa_supplicant`，后者经
`ctrl_iface` 的 `"DRIVER "` 分发 → `wpa_drv_driver_cmd` → `ops->driver_cmd`
（唯一 nl80211 ops 表，`ops+0x308`）→ `wpa_driver_nl80211_driver_cmd`，最终由
site 3 的通用透传发出 `ioctl(fd, 0x89f1, &ifreq)`；镜像中无 `libwpa_drv_oem.so`，
OEM 回调分支不会拦截。`0x89fd` 在用户态**没有任何 wlan 调用方**：`ftmdaemon`/
`myftm`/`ftmtest`/`libwifi-hal-qcom.so` 等连常量都没有；命中的 10 处 `0x89fd`
全部是 `netmgrd`/`qti`/`adpl` 对 `rmnet_mhi*`/`usb_rmnet0` 的 RMNET 私有 ioctl，
与 qca wlan 的 FTM 语义无关。`iwpriv`/`iwpriv_vendor` 无 0x89f1/0x89fd；
`qca_cld3_wlan.ko` 的 4 处只是内核受理侧常量。本文只做“谁发这个 ioctl”，
不涉及漏洞或提权推断。
