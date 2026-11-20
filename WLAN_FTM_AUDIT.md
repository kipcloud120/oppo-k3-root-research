# WLAN FTM testmode（`net_device` ioctl `0x89fd`）纯离线可达性审计

- 目标：OPPO K3（PCGM00，SDM710，Android 11，内核 `4.9.227-perf+`，SPL 2022-04-05）
- 物料范围（结论仅对此范围有效，换构建即作废）：
  - `vendor_ko/qca_cld3_wlan.ko`，ET_REL，SHA256 `F45C1C1CF63281EE5E64C8B6149C42D5E1AAA91142913073668ABF1901674D00`
  - F.16 固件物料：`.build/vendor/x/`（vendor/odm 解包）、`.build/vendor_bins/`（vendor.img 解包）、`.build/odm_bin/`
  - SELinux：`.build/sepolicy/{vendor,plat,system_ext}_sepolicy.cil`、同名 `*_file_contexts`、`*_property_contexts`
- 方法：pyelftools + capstone 对 ET_REL 做符号/重定位级反汇编；固件侧只做文件/字符串/ELF 常量静态盘点。**未连接设备、未动态运行、未联网。**

---

## 1. 入口与门（指令级）

### 1.1 `hdd_ioctl`（符号真值 `0x38050`，size 716）

| 地址 | 指令 | 作用 |
|---|---|---|
| `0x38134` | `bl hdd_get_conparam` | 取 conparam（**读 `.bss+0x270`**，见 §2） |
| `0x38138` | `mov w8, #0x89fd` | 常量 |
| `0x3813c` | `cmp w21, w8` | `w21` = `cmd`（入口 `0x3808c mov w21,w2`） |
| `0x38140` | `b.ne 0x381fc` | cmd≠0x89fd → 通用路径 |
| `0x38144` | `cmp w0, #5` | **FTM con_mode 门** |
| `0x38148` | `b.ne 0x381fc` | conparam≠5 → 通用路径 |
| `0x3814c`–`0x38154` | `bl wlan_hdd_qcmbr_unified_ioctl` | 唯一调用点（`x0=vdev ctx`、`x1=ifreq`） |

通用路径 `0x381fc`：`__wlan_hdd_validate_context` → 仅特判 `0x89f1`（`0x38210/0x38214`，含两条 copy_from_user 变体：`0x38254` 16 字节 / `0x382b0` 12 字节），其余 cmd 落到 `0x38264`→`0x38280`→共用 trace 尾部并返回 `-0x16`（`0x38188 mov w24,#-0x16`，-EINVAL）。
**即：`0x89fd` 是 `hdd_ioctl` 里唯一不进通用路径的私有 cmd，但必须先过 `conparam==5`。**

### 1.2 `wlan_hdd_qcmbr_unified_ioctl`（符号真值 `0x2b730`，size 284）

> R1 文档写的 `0x2b740` 是函数内第 5 条指令（`mov x20,x1`），不是符号值。

| 地址 | 指令/调用 | 作用 |
|---|---|---|
| `0x2b73c` | `ldr x19,[x0,#0x18]` | 取 hdd ctx |
| `0x2b758` | `bl __wlan_hdd_validate_context` | 上下文校验，失败即返回 |
| `0x2b760` | `ldr x11,[x20,#0x10]` | `ifreq.ifr_ifru.ifru_data`（用户指针） |
| `0x2b770`–`0x2b780` | `adds/sbcs/cset` + `0x2b7e8 ldr w1,[x10]` | 内联 `get_user`：从用户指针取 **4 字节子命令**（`w1`） |
| `0x2b834`–`0x2b83c` | `ldr x0,[x19,#8]; add x2,x8,#4; bl wlan_ioctl_ftm_testmode_cmd` | `(pdev, subcmd, ptr+4)` |

失败分支：越界/取数失败 → `0x2b824 mov w0,#0x10`（QDF_STATUS_E_INVAL）。
**该函数在本构建里已退化为「FTM testmode 专用转发器」**：除 FTM 外没有任何其它分派（无 QCMBR 其它子命令）。

### 1.3 `wlan_ioctl_ftm_testmode_cmd`（符号真值 `0x1e60c0`，size 644）

> R1 写的 `0x1e60d4` 是 `mov w21,w1`（函数内 +0x14），不是入口。

| 地址 | 指令/调用 | 作用 |
|---|---|---|
| `0x1e60e4` | `bl wlan_objmgr_pdev_get_comp_private_obj(..,#0x17)` | 取 FTM pdev 私有对象；为 NULL → `0x1e6184 mov w0,#0x10` |
| `0x1e60f4/0x1e60fc` | `cmp w21,#0x1001; b.eq 0x1e618c` | **子命令 0x1001 = 取回包** |
| `0x1e6190`–`0x1e61a4` | `mov w0,#0x804; bl __qdf_mem_malloc` | 分配 0x804 回包缓冲 |
| `0x1e61b8` | `bl ucfg_wlan_ftm_testmode_rsp` | 填回包 |
| `0x1e62cc`–`0x1e62d4` | `mov w2,#0x804; bl __arch_copy_to_user` | 回包 `copy_to_user 0x804` |
| `0x1e6100/0x1e6104` | `cmp w21,#0x1000; b.ne 0x1e61c8` | **子命令 0x1000 = 下发命令**；其它 → `0x1e61c8 mov w23,#0xb` |
| `0x1e61e0` | `ldr w21,[x9]` | 内联 `get_user`：用户缓冲区**首 4 字节 = 长度** |
| `0x1e6220`–`0x1e6228` | `cbnz w10,..; cmp w21,#0x800; b.gt 0x1e6310` | **长度门：`≤0x800`(2048)**，超出 → 错误 `0x10` |
| `0x1e6248` | `bl __qdf_mem_malloc(x23=sxtw(len))` | 分配 len |
| `0x1e625c/0x1e6260` | `add x20,x20,#4; bl __check_object_size` | 数据从 `ptr+4` 起 |
| `0x1e6290` | `bl __arch_copy_from_user(buf, ptr+4, len)` | 拷贝 |
| `0x1e62fc`–`0x1e6300` | `bl ucfg_wlan_ftm_testmode_cmd(pdev, buf, len)` | 下送 |

**审计观察（非本次结论）**：`0x1e6224 cmp w21,#0x800` 后接 `b.gt` 是**有符号**比较，长度为负（bit31=1）时可通过该门；但 `0x1e6230 sxtw x23,w21` 会把负值符号扩展成巨大值，`__qdf_mem_malloc` 随即失败返回 `2`，故不构成越界；属防御纵深不一致，建议记一笔。

### 1.4 下送链

- `ucfg_wlan_ftm_testmode_cmd` 符号真值 `0x1e57a8`（size 88）→ 调 `wlan_ftm_cmd_send`（调用点 `0x1e57e4`）。**R1 写的 `0x1e6300` 是上文调用点，不是该函数地址。**
- `ucfg_wlan_ftm_testmode_rsp` 符号真值 `0x1e58f0`（size 88）→ `qdf_mem_copy(user+4, comp+8, len)`。

---

## 2. 正常运行时 FTM 是否启用

### 2.1 驱动参数线（关键新发现）

| 符号 | 位置 | 说明 |
|---|---|---|
| `curr_con_mode` | `.bss+0x270` | **`hdd_get_conparam` 实际读的就是它**（`0x495d8 ldr w0,[x8]`，重定位 `.bss+0x270`） |
| `con_mode` | `.bss+0x2b0` | `module_param(con_mode)`，`__param_con_mode`(`__param+0x0`) → `con_mode_ops`(`.rodata+0x3af8`) → `con_mode_handler`(`0x616a0`)，perm `0x1a4`=0644 |
| `con_mode_ftm` | `.bss+0x2b4` | `__param_con_mode_ftm`(`__param+0x28`) → `con_mode_handler_ftm`(`0x617c8`) |
| `con_mode_epping` | `.bss+0x12c` | 同上，与 FTM 无关 |

- **默认值 = 0**：`.bss` 零初始化，无 `.data` 初值；`init_module` `0x5e288`–`0x5e2e4` 做 `ldr w8,[con_mode]; str w8,[curr_con_mode]`，即 **insmod 时 `curr_con_mode := con_mode`**。无参数 insmod ⇒ conparam=0 = mission mode ⇒ `0x38144 cmp w0,#5` 永不成立。
- **运行时改 `con_mode` 不是改一个变量**：`con_mode_handler`(`0x616a0`) 解析后 `0x61780 blr x8`，其中 `hdd_set_con_mode_cb`(`.data+0x728`) 在 `init_module` `0x5e4e0`–`0x5e504` 被赋为 **`hdd_driver_mode_change`(`0x60fb8`)**。该函数执行整驱动模式切换：`hdd_stop_all_adapters`(`0x6126c`)、`hdd_deinit_all_adapters`(`0x61278`)、`pld_idle_shutdown`(`0x612b4`)、`epping_disable`(`0x613a4`)、`rtnl_lock`(`0x61458`)、`hdd_start_adapter`(`0x61528`) 等，并在 `0x61168` 处访问 `curr_con_mode`。
  ⇒ **`echo 5 > /sys/module/wlan/parameters/con_mode` 会强制拆掉 Wi-Fi 再把驱动重启进 FTM**，与正常 Wi-Fi 服务天然不能并存。
- `con_mode_ftm` 路径更窄：`0x617e4` 读回 `con_mode_ftm`，`==5` 才把 5 同时写进 `curr_con_mode` 与 `con_mode`；否则 `0x61834 printk` 并返回 `-0x20c`。

### 2.2 固件脚本/rc 线

| 证据 | 内容 | 含义 |
|---|---|---|
| `init.wlan.target.rc:119`（`on boot`） | `insmod /vendor/lib/modules/qca_cld3_wlan.ko` | **无 `con_mode` 参数 → 默认 0** |
| `init.wlan.target.rc:148-149` | 两条 `modprobe ... qca_cld3_wlan` 均被注释 | 无第二加载路径 |
| `init.wlan.qcom.rc:555-564` | `service wififtm /vendor/bin/wififtm`，`user root`，**`disabled` + `oneshot`**，仅 `on property:oppo.wifi.ftm=1` 启动 | FTM 需显式属性触发 |
| `init.wlan.qcom.rc:541-550` | `service wifi_ftm /system/bin/wififtmtest`，`disabled`+`oneshot`，仅 `on property:oppo.wifi.ftmtest=1` | 同上 |
| `init.wlan.qcom.rc:569-580` | `service wifihwftm /vendor/bin/wifihwftm`，仅 `oppo.wifi.hwtest=1` / `vendor.wifi.hwtest=1` 触发 | 同上 |
| `init.wlan.qcom.rc:717-722` | `service ftmd ... ftmdaemon`，`disabled`+`oneshot` | 无常规启动触发点 |
| `init.wlan.qcom.rc:903-904` | `on property:vendor.wifi.ftmd.load=true` → `insmod /system/lib/modules/pronto/pronto_wlan.ko con_mode=5` | **legacy 死路径**：本机无 pronto 模块（该路径属旧平台） |
| `vendor/bin/wififtm`（194 B） | `#svc wifi disable`（**已注释**）；`sleep 10`；`insmod vendor/lib/modules/qca_cld3_wlan.ko`；`ifconfig wlan0 up`；`echo 5 > /sys/module/wlan/parameters/con_mode`；`ftmdaemon -n -dd` | **全固件唯一写 5 的脚本**；先 insmod/拉起 wlan0 再切模式 |
| `vendor/bin/wififtmtest`（30 B） | `ftmdaemon -n` | 只起守护进程，不设模式 |
| `vendor/bin/wifihwftm` | `insmod` + `echo 5` + `ftmdaemon` | 同类产线脚本 |
| `vendor/bin/wifistopftmtest` | `echo 0 > .../con_mode` | 退出 FTM |
| `odm/bin/init.oppo.wifi.sh` | 无 `con_mode`/`ftm`/`insmod` 字样（全文检索 0 命中） | 正常 Wi-Fi 初始化不碰 FTM |
| `odm/bin/init.vendor.wifi.autochmod.sh` | 仅 wifi dump 采集（`iwpriv_vendor wlan0 crash_inject`） | 与 FTM 无关 |

**小结（源码/文件级）**：正常启动链（`on boot` → `insmod` 无参数 → conparam=0）**没有任何一处把 con_mode 设为 5**；进入 FTM 只有「属性触发 `wififtm` 脚本」或「有权限的域直接写 sysfs」两条显式路径，且都会先停用/重载驱动。

---

## 3. 用户态调用方（二进制证据）

对全部 FTM/Wi-Fi 相关可执行文件做「立即数 + 32 位字面量」双路扫描（`artifacts_adb/r1_wlan_reach/scan_imm89fd.py`，同时匹配 `movz/movk/movn #0x89fd` 六种编码与 `.data/.rodata` 里的 `0x000089fd`）：

| 二进制 | 导入 `ioctl` | 出现的 ioctl 请求码 | 含 `0x89fd` |
|---|---|---|---|
| `/vendor/bin/ftmdaemon`（163632 B） | 是 | `0x707`、`0x4004e901`/`0x4004e909`/`0x4004ea01` 族（`0xd4fc`、`0xdf30`、`0xe858`、`0x10540` 等调用点） | **否** |
| `/vendor/bin/myftm`（225752 B） | **否**（98 个导入里无 ioctl，只有 open/socket/genl） | — | **否** |
| `/odm/bin/iwpriv`、`/odm/bin/iwpriv_vendor` | 是 | WEXT：`0x8912`、`0x8b01`、`0x8b0b`、`0x8b0d`、`0x8927`、`0x8915`、`0x8954`（`0x2f38`、`0x325c`、`0x3298`、`0x36b4`、`0x3a24` 等） | **否** |
| `/vendor/bin/ftmtest`、`ftm_flows_test` | 否（纯 nl80211/genl） | — | **否** |
| `/vendor/bin/hw/wpa_supplicant`、`/odm/bin/wpa_supplicant` | 是 | nl80211 为主 | **否** |
| `vendor.oplus.hardware.wifi@1.1-service`（115408 B，见 §3.1） | — | — | **否** |

结论（指令级/字面量级）：**出货固件里没有任何二进制把 `0x89fd` 作为请求码**；`iwpriv` 走的是 `hdd_driver_command` 那条 WEXT 私有路（且该函数在 `0x38380` 先 `hdd_get_conparam`，`==5` 时直接 `0x383b0 mov w23,#-0x16` 拒绝），`myftm` 连 `ioctl` 符号都不导入。**`0x89fd` 分支在 F.16 物料内没有调用方。**

### 3.1 真正“注册/调用 FTM”的是 OPLUS Wi-Fi HAL（字符串级，未做函数级确认）

`vendor.oplus.hardware.wifi@1.1-service`（`/odm/bin/hw/`）内含：

| 偏移 | 字符串 |
|---|---|
| `0x6a0f` | `/sys/module/wlan/parameters/con_mode` |
| `0x6a97` | `failed to excute myftm command:   %s ` |
| `0x6b30` | `/vendor/bin/ftmdaemon` |
| `0x6be5` | `failed to excute ftm command!` |
| `0x6d05` / `0x6d77` | `/vendor/lib/modules/qca_cld3_wlan.ko`、`.../qca_cld3/qca_cld3_wlan.ko` |
| `0x6f6c` | `/vendor/bin/myftm` |
| `0x6da5` / `0x6f7e` | `ftmdaemon is not found!`、`myftm is not found!` |

即：**HAL 是 FTM 的“代理”**——能 insmod 驱动、写 `con_mode`、exec `myftm`/`ftmdaemon`。这正好对应 §4 里 `oplus_wifi_service` 被授予的 `sys_module`/`net_admin`/`sysfs_wlan_con_mode` 写/`wcnss_service_exec` 执行权。
**未决**：HAL 的 HIDL 方法是否对调用方做签名/权限门（谁能通过 binder 让它执行上述动作），需对 115 KB HAL 做函数级反汇编；本轮未做。

---

## 4. SELinux / 权限

`genfscon sysfs /module/wlan/parameters/con_mode → u:object_r:sysfs_wlan_con_mode`（`vendor_sepolicy.cil:183`）。对该节点的写权限（`vendor_sepolicy.cil`）：

| 域 | 规则 | 行 |
|---|---|---|
| `oplus_wifi_service` | `allow ... sysfs_wlan_con_mode (file (ioctl read write getattr lock append map open ...))` | 5628 |
| `wcnss_service` | 同上 | 7086 |
| `wifi_diag` | 同上 | 7132 |
| `engcommand_hidl` / `engineer_vendor_daemon` | 同上 | 3594 / 3773 |
| **`shell`** | **无任何 `allow shell sysfs_wlan_con_mode`** | — |
| **`wifi_ftm`** | **无**（只能读不到、写不了 con_mode） | — |

能力/执行权：

| 主体 | 关键授权 | 含义 |
|---|---|---|
| `oplus_wifi_service` | `self (capability (chown fowner fsetid setgid setuid net_admin net_raw sys_module sys_admin sys_resource))`（5605）；`wcnss_service_exec` `execute_no_trans`（5595）；`vendor_file` `execute`（5599）；`vendor_shell_exec`（5597）；`hwservice_manager` add/find（5585-5586）；`engineermode_app`/`platform_app`/`system_server` 可 binder call（3940-3942、5572-5583） | **UID 0 级代理：可改 con_mode、可 insmod、可 exec wififtm/myftm、可 ioctl wlan0（net_admin）** |
| `wcnss_service`（`/vendor/bin/wififtm` 的落地域，`vendor_file_contexts:85` 把该文件标为 `wcnss_service_exec`） | `sysfs_wlan_con_mode` 写（7086） | 能完成 `echo 5` |
| `wifi_ftm`（`/system/bin/wififtmtest` → `wifi_ftm_exec`，`system_ext_file_contexts:173`） | `self (capability (net_admin net_raw))`（7167）、`netlink_generic_socket`（7168）、`diag_device`（7163） | **能对 wlan0 发私有 ioctl（有 CAP_NET_ADMIN）**，但**不能改 con_mode** |
| `shell`（uid 2000） | **无 `sysfs_wlan_con_mode` 写**；**无 `net_admin`**（全文仅 `qti_init_shell` 有 `net_admin`，9099） | 既不能改 con_mode，也不能对 wlan0 发 `SIOCDEVPRIVATE` 类 ioctl |
| `/dev/wlan`（`wlan_device`，`vendor_file_contexts:1100`） | 仅 `hal_wifi`（8766）、`system_server`（11003）可 open/ioctl | FTM 不走这个字符设备 |

**区分**：`oplus_wifi_service` / `wcnss_service` 属于「有权限改 con_mode」；`wifi_ftm` 属于「有权限发 ioctl 但没权限改 con_mode」；`shell` 两者皆无。**「改完驱动是否可用」不由 SELinux 决定**——`hdd_driver_mode_change` 会先拆掉所有 adapter 再重启，写 5 成功后 wlan0 会以 FTM 形态重建，正常 Wi-Fi 连接必然中断（源码级推断，见 §2.1）。

---

## 5. 结论

**判定：(b) 条件性关闭** —— 正常运行时 0x89fd 分支不可达；只有在“显式授权 + Wi-Fi 停机/驱动重载”之后才可达，且出货固件内没有调用方，实际接近 (a)。

判据（逐条对应上文）：

1. **双门串联**：`0x3813c`（cmd==0x89fd）与 `0x38144`（conparam==5）缺一不可，`0x38148 b.ne` 直接落到通用路径。
2. **正常启动 conparam=0**：`init.wlan.target.rc:119` 无参数 insmod → `init_module 0x5e2e4` 把 `con_mode`(默认 0) 抄进 `curr_con_mode`，门 `cmp #5` 永不成立。
3. **无任何启动期写 5**：全部 rc/脚本中，唯一写 5 的是 `vendor/bin/wififtm`（以及同类 `wifihwftm`），而它们对应的 init service 均为 `disabled` + `oneshot`，只能由 `oppo.wifi.ftm` / `oppo.wifi.hwtest` 属性触发；`pronto_wlan.ko con_mode=5` 是 legacy 死路径。
4. **改 con_mode = 驱动模式重启**：`echo 5` → `con_mode_handler`(`0x616a0`) → `hdd_driver_mode_change`(`0x60fb8`) → stop/deinit/idle-shutdown 全部 adapter 后重启，**不能与正常 Wi-Fi 并存**。
5. **无出货调用方**：全物料二进制均不含 `0x89fd` 立即数或字面量；`myftm` 不导入 `ioctl`，`ftmdaemon` 的 ioctl 码是 `0x707`/`0x4004e9xx` 族，`iwpriv` 是 WEXT 码且 `hdd_driver_command` 在 conparam==5 时主动拒绝。
6. **权限面收敛**：`shell` 无 `sysfs_wlan_con_mode` 写、无 `net_admin`；能同时“改 con_mode + ioctl wlan0”的只有 `oplus_wifi_service`、`wcnss_service`、`wifi_diag` 等 root 级域。

**未决（需最小授权实验/额外静态工作）**：

- **U1**：`vendor.oplus.hardware.wifi@1.1-service` 的 HIDL 方法是否对调用方（`platform_app` / `engineermode_app` / `system_server`）做权限校验。若某个方法可在无签名门槛下写 `con_mode=5` 并 exec `myftm`，则存在“应用→HAL→FTM”的**升级为 (c)** 的路径。所需最小工作：对该 115 KB HAL 做函数级反汇编 + 定位 `0x6a0f`/`0x6f6c` 字符串的 xref（纯离线，不需设备）。
- **U2**：`myftm`/`ftmdaemon` 究竟用 nl80211 vendor 命令还是别的通道完成 FTM 业务（二者均无 `0x89fd`）。若确认走 nl80211，则 `0x89fd` 分支在本构建里就是**完全无调用方的遗留接口**，可把结论收紧为 (a)。
- **U3**（动态，需最小授权实验）：在 conparam=5 且 `wlan0` 已 up 的 FTM 形态下，`ioctl(wlan0, 0x89fd, &ifreq{ptr})` 的实际返回与 `copy_to_user 0x804` 行为。若要做，最小实验=一台同 SPL 的 K3 + root shell + 一个只调用该 ioctl 的静态程序（不接触其它接口），仅观察返回值/回包长度。
- **U4**：`ucfg_wlan_ftm_testmode_cmd` → `wlan_ftm_cmd_send` → `target_if_ftm_cmd_send` 的下游是否还有独立状态机门（FTM psoc 是否 attach）。本轮只到 `0x1e57e4` 调用点，未展开。

---

## 6. 不外推声明

本结论仅适用于 `qca_cld3_wlan.ko` SHA256 `F45C1C1C…674D00` + 本文列出的 F.16 vendor/odm/SELinux 物料。任何 OTA、换版驱动、换 vendor.img、换 sepolicy 均使本结论作废；R1 文档中的三个地址（`0x2b740`、`0x1e60d4`、`0x1e6300`）应按下文勘误更新。

### 附：对 R1 地址的勘误

| 对象 | R1 写法 | 实测符号真值 | 说明 |
|---|---|---|---|
| `hdd_ioctl` | `0x38050` | `0x38050` ✅ | 一致 |
| `wlan_hdd_qcmbr_unified_ioctl` | `0x2b740` | **`0x2b730`** | `0x2b740` 是函数内 `mov x20,x1` |
| `wlan_ioctl_ftm_testmode_cmd` | `0x1e60d4` | **`0x1e60c0`** | `0x1e60d4` 是函数内 `mov w21,w1` |
| `ucfg_wlan_ftm_testmode_cmd` | `0x1e6300` | **`0x1e57a8`** | `0x1e6300` 是调用点 |
| `ucfg_wlan_ftm_testmode_rsp` | — | `0x1e58f0` | 回包填充（`0x804`） |

### 附：中间产物（`artifacts_adb/r1_wlan_reach/`）

- `hdd_qcmbr_unified.full.txt` — `wlan_hdd_qcmbr_unified_ioctl` 全量反汇编（含重定位注释）
- `cil_query.py` — CIL 定向查询工具（跳过超长 `typeattributeset` 行）
- `scan_imm89fd.py` — 0x89fd 指令编码 + 字面量双路扫描器
