# WLAN ioctl 调用链审计（v13.2 P1-A / P1-C / P1-D）

> 日期：2026-11-20（v13.2）
> 承接：`docs_archive/审核意见CHATGPT-v0132.txt` §三（P1：完成 `hdd_driver_command` 调用链审计）
> 性质：**纯离线**。物料 = F.16 固件（`vendor.img` / `odm.img`）+ `qca_cld3_wlan.ko` + 厂商内核源码 + SELinux CIL；**未连接设备、未上机、未做任何动态输入**。
> 判定语义：本文**不改变**四层判定（受限 UID 0 命令执行已达成；可用 ROOT / 持久 ROOT 仍 NO-GO）。本文只回答"用户态调用方 → 系统调用 → 驱动 ioctl 分派 → 哪个 handler"这条连接是否成立。
> 权威物料哈希：`qca_cld3_wlan.ko` = `f45c1c1cf63281ee5e64c8b6149c42d5e1aaa91142913073668abf1901674d00`；`vendor.img` = 见 `KASLR_EVIDENCE.md` 物料台账（F.16，2025-03-26 构建）。换构建即作废。

---

## 0. 结论先行（含对审核 v0132 候选 A 的更正）

审核 v0132 把 `0x89f1 → hdd_driver_command` 列为 P1 第一主线，并要求回答"`/odm/bin/iwpriv` 或 `executeDriverCommand` 是否真的经过 `hdd_driver_command`"。

**本轮答案是否定的，且给出了真正的连接：**

1. **`/odm/bin/iwpriv` 不会发 `0x89f1`，也不会发 `0x89fd`。** 它是标准 wireless-tools 30~pre9：`SIOCGIWPRIV(0x8B0D)` 取驱动私有表 → 对命中的名字，若表项 `cmd < SIOCDEVPRIVATE`，按 `(set_args,get_args)` 匹配 **name 为空** 的父项，实际 `ioctl(父项 cmd)`；父项全在 **`0x8BE0..0x8BFF`**（WEXT 私有区间）。反汇编中固定 ioctl 常量只有 `0x8912/0x8B01/0x8B0B/0x8B0D/0x8927/0x8915/0x8954`，其余来自表项。**`0x89f1` 在 `iwpriv`/`iwpriv_vendor` 中零出现。**
2. **`0x89f1` 的真实用户态消费者是 `wpa_supplicant`**（Android `driver_nl80211` 的 `android_priv_cmd` 通道，4 处 `mov w1,#0x89f1` + `ioctl`），由 wpa 控制通道的 `DRIVER <cmd>` 命令驱动；它携带的字符串正是 `hdd_drv_cmds` 98 项白名单（`SETBAND`/`RSSI`/`LINKSPEED`/`RXFILTER-ADD`/`BTCOEXMODE`/…）。
3. **`hdd_driver_command` 因此确实有完整的"用户态 → 内核"连接**，但连接的主语是 **wpa_supplicant**，不是 `iwpriv`、也不是 OPPO HAL 的 `executeDriverCommand` 的 iwpriv 分支。审核担忧的"仅凭同名/同常量推定"在该路径上被排除。
4. **`executeDriverCommand` 的真正内核落点是 WEXT 私有面**（`0x8BE0..0x8BFF`，32 个 handler / 223 条私有参数），不是 `hdd_driver_command`。这条链的每一环都有本机物证：HAL 裸拼 `/odm/bin/iwpriv <入参>`（`WIFI_P1_ROOT_COMMAND_AUDIT.md` §2 + §7.2 两次真机回显 uid=0）→ `iwpriv` 发 WEXT 私有 ioctl → `we_handler_def` → `we_private[]` handler。
5. **P1-C 的独立安全价值判定**：`0x89f1` 98 项命令表面向 wpa_supplicant（系统自身进程），受限 UID 0 代理**打不到**（见 §4.2：无 wpa 控制 socket 权限）；`executeDriverCommand` 可达的 WEXT 私有面才是代理主体真正能驱动的驱动状态面。**这修正了 R1 的候选方向，而不推翻 R1 的"候选 A 值得审"结论**——只是候选 A 的正确内核端点是 WEXT 私有 handler。
6. **四层判定不变**：以上均发生在"受限 UID 0 域内的驱动状态影响"层，不产生域逃逸、不提供内核地址、不改变可用 ROOT = NO-GO。**不做任何动态输入验证**（审核 v0132 §三 P1-C 明文）。

---

## 1. 方法与可复算命令

| 环节 | 物料 | 工具 / 命令 |
|---|---|---|
| 用户态二进制 | `.build/odm_bin/iwpriv`、`iwpriv_vendor`、`wpa_supplicant`、`wpa_cli`（从 `odm.img`/`vendor.img` 离线解出） | `python tools/disasm_user.py <elf> --out ...`；`python tools/scan_ioctl_const.py <elf> --vals 0x89f0,0x89f1,0x89fd`；`python tools/fn_around.py <elf> <addr>` |
| 驱动模块 | `vendor_ko/qca_cld3_wlan.ko`（ET_REL） | `python tools/ko_fn.py hdd_ioctl`；`python tools/wlan_cmd_table.py`（98 项）；`python tools/wlan_wext_table.py`（32 handler + 223 参数） |
| 内核分派 | `.build/vendor_kernel_full`（OPPO sdm710 Android 11 树） | `net/socket.c`、`net/core/dev_ioctl.c`、`net/wireless/wext-core.c` |
| SELinux | `.build/sepolicy/*.cil` + `*_file_contexts` | `Select-String` 精确 grep（本文引用行内容） |

复算入口（全部离线）：

```bash
cd "D:/AI_tools/AI_Workspace/WBK_OPK_RT_CRA"
python tools/wlan_cmd_table.py                 # 98 项 hdd_drv_cmds
python tools/wlan_wext_table.py                # we_private 32 handler + we_private_args 223 条
python tools/ko_fn.py hdd_ioctl                # 0x89f1/0x89fd 两个 case
python tools/ko_fn.py hdd_driver_command       # 长度门/NUL/白名单/释放
python tools/scan_ioctl_const.py .build/odm_bin/iwpriv --vals 0x89f0,0x89f1,0x89fd
python tools/scan_ioctl_const.py .build/odm_bin/wpa_supplicant --vals 0x89f0,0x89f1,0x89fd
```

---

## 2. 用户态调用方盘点（P1-A 第一段）

### 2.1 `/odm/bin/iwpriv`（与 `iwpriv_vendor`）：负结果，证据闭合

- 二进制：`/odm/bin/iwpriv` 20,488 B，ET_DYN/AArch64；`/odm/bin/iwpriv_vendor` 20,312 B。二者字符串与代码结构一致（标准 wireless-tools）。
- 固定 ioctl 常量（全部命中点）：

| 地址 | 值 | 含义 |
|---|---|---|
| `0x2f38` | `0x8912` | `SIOCGIFCONF`（枚举接口） |
| `0x325c` | `0x8B01` | `SIOCGIWNAME` |
| `0x3298` | `0x8B0B` | `SIOCGIWRANGE` |
| `0x33c0` | `0x8B0D` | `SIOCGIWPRIV`（取驱动私有表） |
| `0x3600` | `0x8927` | `SIOCGIFHWADDR` |
| `0x36b4` | `0x8915` | `SIOCGIFADDR` |
| `0x3a24` | `0x8954` | 非标准常量（iwpriv 内部查询，非驱动命令面；未判定用途，**不外推**） |
| `0x2a24` | `w1 = [x22]`（表项 `cmd`） | **唯一的"驱动私有命令"调用点** |

- 私有表调用语义（与 `wireless-tools 30~pre9` `iwpriv.c: set_private_cmd` 一致，逐指令核对 `0x2700–0x2a28`）：
  - `priv[k].cmd < SIOCDEVPRIVATE` ⇒ 子命令：找同名参数的**空名父项**（`0x8BE0..0x8BFF`），`subcmd = priv[k].cmd`，`ioctl(父项 cmd)`，子命令号写入 `wrq.u.mode`；
  - 否则 `ioctl(priv[k].cmd)`。
- 本机 `we_private_args` 的父项共 23 条，全部在 `0x8BE0..0x8BFF`（`tools/wlan_wext_table.py`），例如 `0x8BE0`、`0x8BE7`、`0x8BF2`、`0x8BF4`、`0x8BF5`、`0x8BF6`、`0x8BF7`、`0x8BF8`、`0x8BF9`、`0x8BFC`、`0x8BFE`、`0x8BFF`。
- **结论**：`iwpriv` 可发出的 ioctl 集合 = `{0x8912, 0x8B01, 0x8B0B, 0x8B0D, 0x8927, 0x8915, 0x8954} ∪ {0x8BE0..0x8BFF 父项}`。**`0x89f1`、`0x89fd` 不在其中**（`grep` 反汇编全文 0 命中，且唯一 ioctl 调用点用表项 cmd）。
- 这一负结果**直接否证**了"`executeDriverCommand → /odm/bin/iwpriv → hdd_driver_command`"的假设；也否证了 `catchSnifferLog` 的 `iwpriv wlan0 setMonChan` 会落到 `0x89f1`（它落到 `0x8BFC` 的 `setMonChan` 子命令，子命令号 23）。

### 2.2 `wpa_supplicant`：正结果（`0x89f1` 的真实消费者）

- 二进制：`/vendor/bin/hw/wpa_supplicant` 3,364,080 B（从 `vendor.img` 离线解出，路径 `bin/hw/wpa_supplicant`）。
- 4 处 `mov w1,#0x89f1` + `bl ioctl`（`tools/scan_ioctl_const.py`）：

| # | 指令地址 | 结构/语义 | 归属（调用链 + 字符串） |
|---|---|---|---|
| 1 | `0x2a22f4` | `android_priv_cmd`：`{char *buf; int len; int total_len}`，`buf` 指向 248 B 命令缓冲，`len/total_len=0xF8`；`ifr_name` 由接口名（≤15 B）填充；失败日志 `"%s: failed to issue private commands"`、`"CTRL-EVENT-DRIVER-STATE HANGED"` | **PNOFORCE 路径**（由 `PNOFORCE 0/1` 触发；见 `ioctl_const_inventory.md`） |
| 2 | `0x2ac688` | 同结构，位于 PNO/sched_scan 构造函数（字符串 `"PNOSETUP "`、`"For PNO Scan"`、`"nl80211: Invalid number of sched scan plans: %u"`） | **`ops->sched_scan`（`"PNOSETUP "`）** |
| 3 | `0x2c2a14` | 同 `android_priv_cmd` 结构 | **`wpa_driver_nl80211_driver_cmd` 通用 else 透传**（ctrl `"DRIVER "` → `wpa_drv_driver_cmd` → `ops+0x308` → `0x314510` → `0x2c2174`）——**这是 98 项白名单的主入口** |
| 4 | `0x2c2edc` | 同结构 | 固定 `GETCOUNTRYREV` helper（由 DRIVER 的 `GETSTATSBSSINFO` 分支调用） |
- 结构一致性：内核 `hdd_ioctl` 只读 `[arg+0]=buf` 与 `[arg+0xc]=len`（见 §3.1），与 `android_priv_cmd` 的 `buf@0` / `total_len@0xc` 完全对应；`hdd_driver_command` 的长度上界 `0x2000` 在该通道实际被 wpa_supplicant 侧 `0xF8` 先行约束。
- 同一 inventory 还发现 `hostapd`（4 处）、`lowi-server`（1 处）、`sigma_dut`（1 处）也发 `0x89f1`；`netmgrd` / `qti` / `adpl` 发 `0x89fd`（见 `ioctl_const_inventory.md`）——**`0x89f1` 是 QCA 驱动的通用 vendor 命令通道，不是 iwpriv 私有接口**。
- 命令字符串交叉核对（同一二进制内，**只作佐证，不作连接判据**）：98 项表名中有 **17 项**在 `wpa_supplicant` 中可检出字面量——`SETBAND`（0x423d8）、`BTCOEXMODE`、`RSSI`、`LINKSPEED`、`RXFILTER-ADD/REMOVE/START/STOP`、`STOP`、`P2P_DEV_ADDR/SET_NOA/SET_PS`、`COUNTRY`、`GETCOUNTRYREV`、`CHANNEL_SWITCH`、`BTCOEXSCAN-START/STOP` 等；其余 81 项未检出字面量（可能为历史/当前框架未用，可能由上层拼接）。**连接判据是"wpa_supplicant 逐指令向 `0x89f1` 传任意字符串"，不是"名字逐项命中"**；反过来，`"PNOSETUP"` 这类不在 98 表中的字符串也会被送入 `hdd_driver_command` 并得到 `ENOTSUPP`，这正说明通道是通用字符串通道。
- 触发链（用户态，v13.2 已逐跳核对）：`wpa_cli driver "<cmd>"` → 控制 socket → wpa_supplicant 控制接口比较 `"DRIVER "`（`0x213bdc`）→ `wpa_supplicant_ctrl_iface_driver`（`0x226748`）→ `wpa_drv_driver_cmd()`（`0x212924`）→ `ops+0x308`（`0x314510`，本 build **只有 nl80211 ops 表**，无 wext ops）→ `0x2c2174` → 通用透传 `0x2c2a14` → `ioctl(0x89f1)`。
  `wpa_cli` 自身不直接 ioctl（它只写控制 socket；`wpa_cli` 二进制**不导入 ioctl**，见 `ioctl_const_inventory.md`）。

### 2.3 OPPO HAL（`vendor.oplus.hardware.wifi@1.1-service`）：两条分支的真实落点

| HAL 方法 | 组装命令 | 实际落点 | 证据 |
|---|---|---|---|
| `executeDriverCommand`（HIDL code 4） | `/odm/bin/iwpriv ` + 整条入参（裸拼，regex 黑名单只挡 11 字符） | `iwpriv` → **WEXT 私有 ioctl**（§2.1） | `WIFI_P1_ROOT_COMMAND_AUDIT.md` §2；§7.2 两次真机 `uid=0` 回显证明 `sh -c` 已执行；本文 §2.1 证明 iwpriv 不发 0x89f1 |
| `executeDriverCommand` 的 `myftm` 分支 | `/vendor/bin/myftm ` + `input[5:]` | `myftm`（FTM 工具，见 `WLAN_FTM_AUDIT.md`） | 同上 §2.3 |
| `catchSnifferLog`（HIDL code 2） | `/odm/bin/iwpriv wlan0 setMonChan <to_string(int)>` | `setMonChan` 子命令 23 → 父项 `0x8BFC` → `iw_set_two_ints_getnone` | 同上 §1 表；`we_private_args` 表（`tools/wlan_wext_table.py`） |
| `sendSupplicantCommand`（HIDL code 6） | `/vendor/bin/wpa_cli <input>` | wpa 控制 socket → 若 socket 可达则可到 `0x89f1` | 但**无 Java 调用方**（死入口），且域无 socket 权限（§4.2） |

---

## 3. 内核分派路径（P1-A 第二段，逐指令/源码）

### 3.1 `0x89f1` 路径：`sock_ioctl → dev_ioctl → dev_ifsioc → hdd_ioctl → hdd_driver_command`

内核源码（本机厂商树）：

- `net/socket.c:953`：`if (cmd >= SIOCDEVPRIVATE && cmd <= (SIOCDEVPRIVATE + 15)) err = dev_ioctl(net, cmd, argp);`
- `net/core/dev_ioctl.c:549-561`（default 分支）：`SIOCDEVPRIVATE..+15` → `dev_load` → `rtnl_lock` → `dev_ifsioc` → `rtnl_unlock`；**该分支没有 `CAP_NET_ADMIN` 检查**（对比 `:478/:501/:526` 的其它 cmd 分支）。
- `net/core/dev_ioctl.c:319-344`：`dev_ifsioc` 对 `SIOCDEVPRIVATE..+15` 走 `ops->ndo_do_ioctl(dev, ifr, cmd)`（`netif_device_present` 为真时）。

驱动侧（`qca_cld3_wlan.ko`，`tools/ko_fn.py hdd_ioctl`）：

| 地址 | 指令/行为 |
|---|---|
| `0x38050` | `hdd_ioctl`（net_device ndo_do_ioctl） |
| `0x38138` | `cmp w21,#0x89fd`；`0x38144 cmp w0,#5`（`hdd_get_conparam()==5`）才走 FTM |
| `0x38210` | `cmp w21,#0x89f1` |
| `0x3821c-0x38248` | `mrs x8,sp_el0; ldr x9,[x8]; tbnz w9,#0x16`（`PF_KTHREAD`）：内核线程走 12 B 结构；用户进程走 16 B |
| `0x3824c-0x38254` | `add x0,sp,#8; mov w2,#0x10; bl __arch_copy_from_user`（从 `ifr->ifr_data` 拷 **16 B**） |
| `0x383f4` | `ldrsw x5,[x22,#0xc]`（用户结构 `len` 字段 @+0xc） |
| `0x383fc-0x38400` | `sub w8,w5,#1; cmp w8,#2,lsl#12` ⇒ **`1 ≤ len ≤ 0x2000`** |
| `0x38430-0x3843c` | `add x0,x5,#1; bl __qdf_mem_malloc` |
| `0x38458-0x3848c` | `__check_object_size` + `__arch_copy_from_user(x20, x24, x23)` |
| `0x384ec` | `strb wzr,[x20,x8]`（**显式 NUL**） |
| `0x38510` | `strchrnul(buf,' ')`（切命令名/参数） |
| `0x38530-0x38544` | `x28 = 表基址 + 0x10`；`cmp x27,#0x62`（**98 项**） |
| `0x3854c-0x38574` | `strlen(name)` 相等 + `strncasecmp`（大小写不敏感） |
| `0x385a8` | `blr x8`（handler 间接调用，参数 `(adapter,hdd_ctx,buf,name_len,arg_struct)`） |
| `0x385ec-0x38640` | 未匹配 `qdf_trace_msg` + 返回 `-0x20c`（ENOTSUPP） |
| `0x38648` | `__qdf_mem_free`（所有退出路径） |

> 复核：以上与 R1 §6.1–6.2 一致；本文补充了 `dev_ioctl` 的 **无 CAP_NET_ADMIN 门**这一内核层事实（R1 当时写"需 CAP_NET_ADMIN"，对 `0x89f1` 不准确；对 WEXT SET 才准确，见 §3.2）。

### 3.2 WEXT 私有路径：`sock_ioctl → dev_ioctl → wext_handle_ioctl → we_private[]`

- `net/socket.c:957`：`SIOCIWFIRST..SIOCIWLAST` → `dev_ioctl`。
- `net/core/dev_ioctl.c:564-565`：`if (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST) return wext_handle_ioctl(...)`。
- `net/wireless/wext-core.c:970-978`：`wext_permission_check()` —— `IW_IS_SET(cmd)`（偶数命令）或 `SIOCGIWENCODE*` 要求 **`CAP_NET_ADMIN`**，否则 `-EPERM`。
- `net/wireless/wext-core.c:943-945`：`SIOCGIWPRIV` 走 `iw_handler_get_private`（把 `we_private_args` 原样回给 iwpriv；GET，奇数，**无需 CAP**）。
- `net/wireless/wext-core.c:952-963`：`get_handler(dev,cmd)` → 私有区间用 `descr->private[cmd - SIOCIWFIRSTPRIV]`。

驱动侧表（`tools/wlan_wext_table.py`，符号 + 重定位双证）：

| 项 | 地址/值 | 含义 |
|---|---|---|
| `we_handler_def` | `.rodata+0x6258` | `num_private=32`，`private=we_private`，`num_private_args=223`，`private_args=we_private_args` |
| `we_private` | `.rodata+0x4c70`（32×8 B） | `[0]=iw_setint_getnone`、`[3]=iw_setchar_getnone`、`[4]=iw_set_three_ints_getnone`、`[7]=iw_hdd_set_var_ints_getnone`、`[8]=hdd_fips_test`、`[18]=iw_set_host_offload`、`[20]=iw_set_fties`、`[21]=iw_get_statistics`、`[22]=iw_set_keepalive_params`、`[23]=iw_set_packet_filter_params`、`[24]=iw_set_pno`、`[25]=iw_set_band_config`、`[26]=iw_set_dynamic_mcbc_filter`、`[28]=iw_set_two_ints_getnone`、`[30]=iw_set_dot11p_channel_sched`、`[31]=iw_get_linkspeed`、`[9/11/13]=iw_add/del/get_tspec` 等（`python tools/wlan_wext_table.py`，节感知重定位：具名函数符号取 `st_value+addend`） |
| `we_private_args` | `.rodata+0x4d70`（223×0x18） | 23 个父项（真实 ioctl，`0x8BE0..0x8BFF`）+ 200 个子命令（id→name→父项，见 `tools/wlan_wext_table.py` 输出） |
| 例：`setMonChan` | id=23，`set=0x4802`，父项 `0x8BFC` | `catchSnifferLog` 的实际落点 |
| 例：`setpno` | `0x8BF8`，`set=0x27FF`（CHAR \| 2047） | 变长字符串面；核心层 `wext-priv.c` 会校验 `iwp->length > (set_args & 0x7FF)` → `-E2BIG` |
| 例：`setPktFilter` | `0x8BF7`，`set=0x1067`（BYTE \| 103） | 定长二进制面；handler 内 `length == 3+20*buf[2]` 精确校验（`WLAN_WEXT_HANDLER_AUDIT.md`） |
| 例：`setHostOffload` | `0x8BF2`，`set=0x1018`（BYTE \| 24） | 定长结构体面 |

> 详细 handler 审计见 `WLAN_WEXT_HANDLER_AUDIT.md`（本轮并行交付）；98 项 `hdd_driver_command` handler 审计见 `WLAN_HANDLER_AUDIT.md`。

### 3.3 WEXT 核心的"长度归一化"（决定 WEXT 面审计的基线）

`net/wireless/wext-priv.c` 在进入驱动 handler 之前已经做了长度归一化，这一点直接影响 P1-B 的判定口径：

- `get_priv_descr_and_size()`（`:93-134`）：按 `descr->set_args` 计算 `extra_size = get_priv_size(set_args)`（类型宽度 × 参数个数）；对 `FIXED` 且 `extra_size + offset <= IFNAMSIZ(16)` 的项走 `&iwr->u` 内联路径（`extra_size = 0`，不分配）。
- `ioctl_private_iw_point()`（`:137-161`）：
  - `if (iwp->length > (descr->set_args & IW_PRIV_SIZE_MASK)) return -E2BIG;`（只设上界）；
  - `extra = kzalloc(extra_size, GFP_KERNEL);`（**按声明尺寸分配，零填充**）；
  - `copy_from_user(extra, iwp->pointer, extra_size);`（**按声明尺寸拷贝**，不是按用户给的 `length`）。
- 因此：对"定长结构体"类 handler（如 `iw_set_host_offload` 24 B、`iw_set_packet_filter_params` 103 B），用户传入任意小的 `length` 也只会让核心拒绝（`length==0`）或忽略，**handler 拿到的始终是 `kzalloc` 的定长零填充缓冲**——"用户长度小于结构体 ⇒ 堆越界读"这一朴素假设在 4.9 wext 核心上**不成立**。
- 对"变长"类（`CHAR | 0x7FF` 等），核心按 2047 B 分配/拷贝，用户指针必须可读满 2047 B，否则 `copy_from_user` 失败返回 `-EFAULT`。
- 结论：WEXT 私有面的安全属性主要取决于**各 handler 对已归一化缓冲的字段/索引校验**（例如 `iw_set_packet_filter_params` 的 `length == 3+20*buf[2]` 精确校验、`iw_set_two_ints_getnone` 的子命令跳表是否越界），而不是"copy_from_user 长度"本身。详见 `WLAN_WEXT_HANDLER_AUDIT.md`。

---

## 4. 可达性判定（P1-D：两个主体、两栏记录）

审核 v0132 明确要求区分"域满足"与"实际调用"。下表把两个可达主体分开，**不使用"域满足"代替"调用链闭合"**。

### 4.1 `shell`（uid 2000，`u:r:shell:s0`）

| 面 | SELinux / 能力事实 | 判定 |
|---|---|---|
| 执行 `/odm/bin/iwpriv`、`/vendor/bin/wpa_cli` | `*_file_contexts`：两者均为 `wcnss_service_exec`；`oplus_wifi_service` 有 `execute_no_trans`，**`shell` 无该规则** | **不可执行**（不出现在 `(allow shell ...)` 中） |
| WEXT 私有 SET（`0x8BE0..0x8BFF` 偶数） | `wext_permission_check` 要求 `CAP_NET_ADMIN`；shell `CapEff=0x13000`（无 NET_ADMIN） | **不可达** |
| WEXT GET（`SIOCGIWPRIV 0x8B0D`、`SIOCGIWNAME` 等） | 无 CAP 要求；shell ∈ `netdomain`，`(allow netdomain self (udp_socket ...))` 允许建 socket | 可达（只读枚举） |
| `0x89f1` 直接 socket ioctl | 内核 `dev_ioctl` **无 CAP 检查**（§3.1）；SELinux 层：`plat_sepolicy.cil` 有 `neverallowx shell domain (ioctl udp_socket (... 0x89e0 0x89ff))`，且本机内核树只有 `file_ioctl` 钩子、无 `socket_ioctl` 钩子（`security/selinux/hooks.c`、`include/linux/lsm_hooks.h` 逐项 grep） | **未决**：策略层明确"不得授予"，但内核层 xperm 检查是否作用于 socket fd 静态不能定论；**不做动态验证** |

> 这一栏修正了 R1 §2 的"shell 需 wlan0/CAP_NET_ADMIN"对 `0x89f1` 的表述：`0x89f1` 在内核层**不需要** CAP_NET_ADMIN。但 shell 缺少可执行载体（不能跑 iwpriv/wpa_cli），直接 socket 路径又被策略的 neverallowx 覆盖 ⇒ **静态上不能宣告 shell 可达**。

### 4.2 受限 UID 0 代理（`u:r:oplus_wifi_service:s0`，`tx10070 → sh -c`，uid 0）

| 面 | 事实 | 判定 |
|---|---|---|
| 执行 `/odm/bin/iwpriv` | `(allow oplus_wifi_service wcnss_service_exec (file (ioctl read getattr lock map execute open watch watch_reads execute_no_trans)))` | **可执行**（留在本域，无域转换） |
| 能力 | `(allow oplus_wifi_service self (capability (chown fowner fsetid setgid setuid net_admin net_raw sys_module sys_admin sys_resource)))` | **有 NET_ADMIN** |
| WEXT 私有 SET | 上述两条 + `wext_permission_check` | **可达**（`iwpriv` 的 SET/父项命令） |
| `0x89f1` 直接 ioctl | 同 §4.1 的 neverallowx 只约束 `shell`；`oplus_wifi_service` 无 `ioctl udp_socket` 的 neverallowx 行，但也没有 `allowxperm` 证据 | **未决**（理论上内核无 CAP 门；SELinux xperm 行为未定） |
| wpa 控制 socket（`/data/vendor/wifi/sockets`，`wifi_vendor_wpa_socket`） | `oplus_wifi_service` **没有** `wifi_vendor_wpa_socket` / `wpa_socket` / `hal_wifi_supplicant` 的任何 allow（CIL 精确 grep 为空）；`file_contexts` 该路径不落 `wifi_vendor_data_file` | **不可达** ⇒ `wpa_cli` 即使能执行也连不上 supplicant；因此 **`0x89f1` 的 wpa_supplicant 通道对代理关闭** |
| 直接跑 `wpa_supplicant` | 可执行（`hal_wifi_supplicant_default_exec` 属 `vendor_file_type`，`allow ... vendor_file ... execute_no_trans`），但 wlan0 已由系统 supplicant 持有，二次初始化在 `nl80211` 层即失败；**静态不能证明**其能走到 `0x89f1` | **未决/不采信**（不构成已闭合链） |

**P1-D 的准确表述**：
- **已闭合**：代理 → `iwpriv` → WEXT 私有面。这是"域满足"升级为"可执行 + 能力 + 驱动表存在"三重条件，但**"iwpriv 实际能成功完成 ioctl"仍缺一次动态日志**（`SIOCGIWPRIV` 返回、`ioctl` 返回值）；按纪律不做。
- **未闭合**：代理 → `0x89f1 → hdd_driver_command`。缺的是"能发 `0x89f1` 的载体 + 能拿到 wpa 控制 socket"两者之一；现有物料下**没有**这样的载体。
- 因此审核 v0132 的"P1-A 连接点未证"在本轮得到**有方向的否证**：**不是"iwpriv 还没绑定上"，而是"iwpriv 根本不走这条 ioctl"**。

---

## 5. P1-C：独立安全价值判定

按审核 v0132 的三种可能结论：

1. **调用链不存在 ⇒ 关闭该调用路径。** 适用于 `executeDriverCommand → hdd_driver_command`：**不成立，关闭**。
2. **调用链存在，但参数/生命周期符合预期 ⇒ 关闭候选。** 适用于 `wpa_supplicant → 0x89f1 → hdd_driver_command`：连接**存在且完整**（本文 §2.2 + §3.1），但（a）输入长度被 `wpa_supplicant` 侧 `0xF8` 与驱动侧 `0x2000` 双重约束，（b）98 handler 的逐项审计见 `WLAN_HANDLER_AUDIT.md`（本轮并行交付）。若该审计未发现具体反例，则此路在"可达主体"层面也不构成新能力——因为**代理打不到它**。
3. **存在明确的静态安全缺陷 ⇒ 独立报告。** 若 `WLAN_WEXT_HANDLER_AUDIT.md` 报告长度未校验/结构体越界读，则缺陷属于**受限 UID 0 域内的 WEXT 私有面**，影响边界是"驱动状态与内核内存读"，不是"首次 uid 0"（该域命令执行已由 §23 达成）。

**价值排序（本轮结论）**：
- 候选 A 的正确内核端点 = **WEXT 私有面**（`0x8BE0..0x8BFF`，223 条参数/32 handler），而非 `hdd_driver_command`；
- `hdd_driver_command` 98 项表的正确主语 = **wpa_supplicant DRIVER 通道**，对本项目的可达主体**不构成新面**（除非未来证明代理能拿到 wpa socket，或 shell 的 neverallowx 在内核层不生效）；
- 因此下一轮深审优先级应改为：**WEXT 私有 handler（代理可达）> 98 handler（wpa 可达，但代理不可达）> FTM（需 con_mode=5）**。

---

## 6. 证据表（地址级）

| # | 结论 | 证据 |
|---|---|---|
| 1 | `iwpriv` 不发 `0x89f1/0x89fd` | `iwpriv.dis.txt` 全文 grep 0 命中；唯一私有 ioctl 点 `0x2a24` 用 `ldr w1,[x22]`（表项 cmd）；固定常量仅 7 个（§2.1 表） |
| 2 | `iwpriv` 私有命令落 `0x8BE0..0x8BFF` | `we_private_args` 23 个父项（`tools/wlan_wext_table.py`）；`wireless-tools iwpriv.c` 子命令→父项语义（源码级 + 反汇编 `0x2700–0x2a28`） |
| 3 | `wpa_supplicant` 发 `0x89f1` | 4 处 `mov w1,#0x89f1`（`0x2a22f4/0x2ac688/0x2c2a14/0x2c2edc`）+ `bl ioctl`；`android_priv_cmd` 字符串；`"failed to issue private commands"`；4 字节命令字符串族（`SETBAND` 等） |
| 4 | 内核 `0x89f1` 无 CAP 门 | `net/core/dev_ioctl.c:549-561`（default 分支无 `ns_capable`）；`net/socket.c:953` |
| 5 | WEXT SET 需 CAP_NET_ADMIN | `net/wireless/wext-core.c:970-978` |
| 6 | 驱动侧 98 项表/长度门/NUL/释放 | `hdd_ioctl@0x38050`、`hdd_driver_command@0x38320` 逐指令（§3.1 表） |
| 7 | 代理可执行 iwpriv + 有 net_admin | `vendor_sepolicy.cil` 两条 allow（§4.2 表）；`vendor_file_contexts` `/odm/bin/iwpriv → wcnss_service_exec` |
| 8 | 代理无 wpa 控制 socket 权限 | `vendor_sepolicy.cil` 精确 grep：`oplus_wifi_service` 无 `wifi_vendor_wpa_socket`/`wpa_socket`/`hal_wifi_supplicant` allow；`vendor_file_contexts` `/data/vendor/wifi/sockets → wifi_vendor_wpa_socket` |
| 9 | shell 不可执行 iwpriv/wpa_cli | `vendor_sepolicy.cil` 无 `(allow shell wcnss_service_exec ...)`；`(allow shell ...)` 全集 grep |

---

## 7. 未覆盖 / 未决（不得外推）

1. **offline 未做动态验证**：`iwpriv` 在代理域内是否真能完成 `SIOCGIWPRIV` 与私有 ioctl（`SIOCGIWPRIV` 需要 `dev->wireless_handlers` 已注册；`hdd_register_wext` 在模块初始化路径上的实际调用时机未逐行核到）。**未决**，需要一次只读动态（`iwpriv wlan0 -a` 之类的只读枚举）并有独立授权。
2. **SELinux xperm 对 socket fd 的生效性**：本机内核树无 `socket_ioctl` 钩子，`file_ioctl` 对 socket inode 的 `sclass` 处理未逐行定论；`neverallowx` 是策略层证据，不等于运行时拒绝。**未决**。
3. **`wpa_supplicant` 第 3/4 处 `0x89f1` 的具体命令族**：本轮只逐指令确认了结构一致与 1/2 处语义；3/4 处的命令字符串未全部还原。**不影响"连接存在"的结论**，但影响"哪些 DRIVER 子命令能打到 98 表"的完备枚举。
4. **`/odm/bin/iwpriv_vendor`**：与 iwpriv 结构同源，本文按同版处理；未逐字节 diff。
5. **FTM `0x89fd`**：不在本文范围，见 `WLAN_FTM_AUDIT.md`。
6. **厂商源码缺失**：qcacld-3.0 完整源码未取得；所有驱动侧结论为**本机 .ko 反汇编 + 厂商 WEXT 表结构**，不外推到"源码里没有校验"。

---

## 8. 对 R1 / 审核 v0132 的口径更正汇总

| 旧口径 | 更正 | 依据 |
|---|---|---|
| "`/odm/bin/iwpriv` 是 `0x89f1` 的候选用户态调用方"（R1 §5/§6.3） | **否**：iwpriv 只发 WEXT 私有（`0x8BE0..0x8BFF`），不发 `0x89f1` | §2.1 |
| "shell 无 wlan0/CAP_NET_ADMIN ⇒ 候选 A 不可达"（R1 §2 行 A） | 对 **WEXT SET** 成立；对 **`0x89f1`** 内核层**不需要** CAP_NET_ADMIN（`dev_ioctl` 无检查） | §3.1/§3.2 |
| "候选 A = `0x89f1 → hdd_driver_command`"（R1 §6） | 候选 A 的**代理可达部分**是 **WEXT 私有面**；`0x89f1` 属 wpa_supplicant 通道，代理不可达 | §2/§4 |
| "连接点未证，需补 iwpriv ↔ `0x89f1` 绑定"（R1 §5） | **绑定不存在**（负结果）；需补的是"代理能否驱动 WEXT 私有面"的只读动态确认 | §7.1 |

---

## 附录：可复跑命令

```bash
cd "D:/AI_tools/AI_Workspace/WBK_OPK_RT_CRA"
# 98 项命令表
python tools/wlan_cmd_table.py --csv
# WEXT 私有表（32 handler + 223 参数 + 父子映射）
python tools/wlan_wext_table.py
# 用户态常量扫描
python tools/scan_ioctl_const.py .build/odm_bin/iwpriv --vals 0x89f0,0x89f1,0x89fd
python tools/scan_ioctl_const.py .build/odm_bin/wpa_supplicant --vals 0x89f0,0x89f1,0x89fd
# 反汇编落盘
python tools/disasm_user.py .build/odm_bin/iwpriv --out artifacts_adb/r1_wlan_reach/iwpriv.dis.txt
python tools/fn_around.py .build/odm_bin/wpa_supplicant 0x2a22f4
```
