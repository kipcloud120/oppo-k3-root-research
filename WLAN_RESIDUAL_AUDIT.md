# WLAN_RESIDUAL_AUDIT — OPPO K3（PCGM00 / SDM710 / Android 11）v13.2 遗留三组小项收口

> **性质：纯离线。** 未连接设备、未动态运行、未联网、未重载驱动、未执行任何 ioctl 或 HIDL 调用。
> 全部结论由本机物料的反汇编/重定位/字符串静态推导，逐条带指令地址或字面量偏移。
>
> **证据等级标注**（与项目既有口径一致）：
> - **【指令级】** = 本机物料反汇编可逐条复核（含重定位解析）；
> - **【源码级】** = 由固件内的脚本/rc/策略文本直接读出；
> - **【未决】** = 静态不可判定，或缺少必要物料（明确写出缺什么）。
>
> **本文只写以下文件**：本文件、`artifacts_adb/r1_wlan_reach/residual_audit.csv`、
> `artifacts_adb/r1_wlan_reach/residual/**`（中间产物）、`tools/wlan_residual_scan.py`、
> `tools/hal_perm_gate.py`、`tools/ftm_tool_surface.py`。
> **未修改** `HANDOVER.md` / `README.md` / `CLOSURE.md` / `HANDOVER_RESUME.md` /
> `WLAN_HANDLER_AUDIT.md` / `WLAN_FTM_AUDIT.md` / `HANDOVER_G5_T3_2026-11-20.md`，也未运行任何 git 命令。

### 物料与哈希

| 物料 | 大小 | 标识 |
|---|---|---|
| `vendor_ko/qca_cld3_wlan.ko` | 14,601,726 B | SHA-256 `f45c1c1c…74d00`，ET_REL/EM_AARCH64，vermagic `4.9.227-perf+` |
| `.build/vendor/x/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service` | 115,408 B | ET_DYN/EM_AARCH64，build-id `828f85aa2715c0d23592356e67791585` |
| `.build/hal_debugdata.elf` | 18,184 B | 上述 HAL 的 `.gnu_debugdata`（LZMA，段 0xD60 B）解压结果，**build-id 逐字节相同** |
| `.build/vendor_bins/vendor/bin/myftm` | 225,752 B | ET_DYN/EM_AARCH64 |
| `.build/vendor_bins/vendor/bin/ftmdaemon` | 163,632 B | ET_DYN/EM_AARCH64 |
| `.build/vendor_bins/vendor/bin/ftmtest` | 29,952 B | ET_DYN/EM_AARCH64（对照组） |
| `.build/odm_bin/iwpriv` | 20,488 B | ET_DYN/EM_AARCH64（对照组） |
| `.build/sepolicy/vendor_sepolicy.cil` | 981,335 B | SELinux 策略（CIL 反编译） |

**换任意一项物料，本文结论即作废。**

---

## §0 结论摘要

### 0.1 A 组：98 项 handler 的 5 个残留项（全部收口）

| 项 | 上一轮状态 | 本轮结论 | 依据 |
|---|---|---|---|
| **A1** `MAXTXPOWER`(#74) `drv_cmd_max_tx_power` | 【未决】扫描器 `no-check`，但人工看到 `cmp w8,#0xc8` | **有界**：`w8 = w20 + 0x64`，`w20 = ldr [sp,#0x14]`（解析槽），值域 **[-100, 100]**；门**确实覆盖解析结果** | **【指令级】** `0x3fb90 / 0x3fb94 / 0x3fb98 / 0x3fb9c` |
| **A2-1** `CCXBEACONREQ`(#70) | 【未决】`FMT-UNRESOLVED` | **有界**：`"%31s "` @ `.rodata.str1.1+0x12a09` | **【指令级】** `x25` 装载 `0x3ecf4..0x3ed08`，用于 `0x3ed0c→0x3ed10`、`0x3ee10→0x3ee14` |
| **A2-2** `CCXPLMREQ`(#71) | 【未决】`FMT-UNRESOLVED`×10 | **有界**：`"%31s "`（同一常量） | **【指令级】** `x22` 装载 `0x3f214..0x3f228`，11 个调用点见 §2.2 |
| **A2-3** `SET_DISABLE_CHANNEL_LIST`(#90) | 【未决】`FMT-UNRESOLVED` | **有界**：`"%d "` @ `.rodata.str1.1+0x14f4d` | **【指令级】** `x23` 装载 `0x412e8..0x412fc`，用于 `0x41304`、`0x4153c` |
| **A2-4** `GET_ANI_LEVEL`(#92) | 【未决】`FMT-UNRESOLVED` | **有界**：`"%d "`（同一常量） | **【指令级】** `x25` 装载 `0x41c98..0x41cac`，用于 `0x41cb4`、`0x41df0` |

- **A 组没有新增内存破坏反例。** 全部 4 个 `FMT-UNRESOLVED` 的格式串解出后均为 `%31s` / `%d`，
  **无裸 `%s`、无 `%[`、无 `%c`、无 `%n`**。
- **全量复算**：对 98 个 handler 重跑同一套跨 `bl` 数据流，得到 **27 处 `sscanf` / 14 个 handler /
  `unresolved=0` / `unbounded=0`**（`%31s `×18、`%d`×4、`%d `×4、`%u %u`×1）。**处数与上一轮记录的 27 处一致**；
  handler 计数由 13 变 14 是分类口径差（上一轮把 `FMT-UNRESOLVED` 的 handler 排除在"可解析"计数外，
  本轮按"含直接 `bl sscanf` 的 handler"计）。
- **新增否定性发现 H2**（唯一新反例，**不是**内存安全漏洞）：
  `MAXTXPOWER` 的 `kstrtoint` **返回值未检查**，且目标槽 `sp+0x14` **在调用前从未被写** ⇒ 解析失败时
  读未初始化栈并把该值当作 max tx power 消费（受 [-100,100] 值域门约束）。见 §2.1。

### 0.2 B 组：FTM U1 —— HAL HIDL 方法权限门（已证：**不存在方法级门**）

| 项 | 结论 | 依据 |
|---|---|---|
| 9 个 HIDL 方法是否检查调用方身份/权限 | **全部为"空权限直通"：一个都不检查** | **【指令级】** 89 个 PLT 导入中**没有** `IPCThreadState`/`getCallingUid`/`getCallingPid`/`checkCallingPermission`/`getuid`/`geteuid`/`getpid`/`selinux_*`/`audit_*`；9 个方法体内**没有**任何此类调用；`.text` 内 **0 条 `svc`**；`.rodata/.dynstr` 内 **0 条** permission/uid/caller 文案 |
| 两个"可疑"导入的定性 | `syscall` = **finit_module(273)**；`prctl` = **PR_SET_PDEATHSIG(1)/SIGKILL(9)** | **【指令级】** 逐调用点核参：`0x9484` args=(273,…)；`0xa548` args=(1,9) |
| 服务如何注册 | `registerAsService("default")`，**单参重载，无权限参数** | **【指令级】** `main` `0x18c78` |
| **真正的门在哪** | **SELinux 域级**：`oplus_wifi_hal_service` 的 `hwservice_manager find` 只给 3 个外部域 + 服务自身；`oplus_wifi_service` 的 `binder call` 同样只给 3 个域 | **【源码级】** `vendor_sepolicy.cil` L3943 / L5588 / L5589 / L5585（find）；L3940 / L5572 / L5575（call） |
| 若受限 UID 0 域（`oplus_wifi_service`）或 shell 拿到 HIDL 句柄，是否有方法级门 | **没有。** 一旦能 `find`+`call`，HIDL 侧**不做任何身份判断** | **【指令级】** 同上 |

**附带得到的更强一击（与 FTM 直接相关）**：`changeConnectionMode(int32)`（HIDL code 1）的唯一入参检查是
`cmp w20,#5 ; b.hi <invalid>`，随后把**调用方给的整数原样**写进
`/sys/module/wlan/parameters/con_mode`（`0x9190 mov w1,w20 → 0x9194 bl setConMode`；
`setConMode` 内 `fopen(con_mode,"w+")` + `fwrite("%d")`）。
⇒ **`changeConnectionMode(5)` 一次调用即可把驱动切进 FTM**，不需要脚本、不需要 `insmod`、不需要直接写 sysfs。
**【指令级】** `0x90ec / 0x9190 / 0x9194 / 0x9508–0x9560`。

### 0.3 C 组：FTM U2 —— `myftm` / `ftmdaemon` 的 ioctl 面（已证：**0x89fd 无调用方**）

| 二进制 | 通道 | 证据 | 是否可能发 0x89fd |
|---|---|---|---|
| `myftm`（225,752 B） | **nl80211 netlink** | **不导入 `ioctl`（0/95 PLT）**；`DT_NEEDED` 含 `libnl.so`；导入 `genl_connect`/`nl_send_auto_complete`/`nl_socket_alloc`；字符串 `nl80211`、`failed to join testmode group!`、`qca6174*` 命令族 | **不可能**（无 ioctl 符号；`0x89fd`/`0x89f1` 立即数与字面量均 0 命中）**【指令级】** |
| `ftmdaemon`（163,632 B） | **netlink（WLAN 面）+ 字符设备 ioctl（NFC/BT/tty 面）** | 导入 `ioctl`（32 个调用点），`DT_NEEDED` 含 `libnl.so`/`libdiag.so`/`libbtnv.so`；已解请求码为 `0x707`、`0x4004e901/02/09`、`0x4004ea01`、`0xbfac`、`0xc008561c`、`0xc0205648`、`0xc054561d`、`0x402c5639`；设备串 `/dev/ese`（NFC）、`/dev/btpower`、`/dev/ttyHS0`、`/dev/smd3|5`、`/dev/nq-nci`、`/dev/i2c-4` | **不可能**（**无 `0x89fd`/`0x89f1`**，无 `SIOCDEVPRIVATE(0x89f0)` 家族；`0x8bxx` WEXT 也不出现）**【指令级】** |
| `ftmtest`（29,952 B，对照） | nl80211 netlink | 不导入 `ioctl`；`libnl` + `genl_connect` | 不可能 |
| `iwpriv`（20,488 B，对照） | WEXT `ioctl` | 8 个调用点：`0x8912/0x8b01/0x8b0b/0x8b0d/0x8927/0x8915/0x8954` | 不可能（**无 `0x89f1`**，与 `ioctl_const_inventory.md` 一致） |

⇒ **U2 收紧为 (a)：本构建内 `0x89fd` 分支没有任何用户态调用方。** 两个 FTM 工具的 WLAN 业务全部走
`nl80211`（`ftmdaemon` 的 ioctl 全部落在 NFC/BT/tty 字符设备上，与 WLAN 无关）。

### 0.4 反例清单（本轮全部，含地址）

| 编号 | 对象 | 地址 | 性质 | 是否内存安全漏洞 |
|---|---|---|---|---|
| **H2** | `drv_cmd_max_tx_power`：`kstrtoint` 返回值未检查 + 槽未预置 ⇒ 未初始化栈读 | `0x3fb8c`（call）/ `0x3fb90`（`ldr w20,[sp,#0x14]`，无 `cbnz w0`） | 健壮性 + 未初始化读 | **否**（值域门把消费值限定在 [-100,100]；不越界、不破坏） |
| H1（沿用上一轮） | `drv_cmd_set_mc_rate`：`kstrtouint` 返回值未检查 | `0x3fa8c` | 同上，但槽已预置 0 | 否 |

**A 组 0 项内存破坏；B 组 0 项反例（是"缺失的门"）；C 组 0 项反例。**

### 0.5 与四层判定（CLOSURE §1.1 口径）

**不变**：① Root UID 命令执行 = 达成（受限域）；② 可用 root = **NO-GO**；③ 持久 ROOT = **NO-GO**；
④ GhostLock ①已闭合 / ②③未闭合（冻结）。**本文不改变四层判定。** 详见 §5。

---

## §1 方法与可复算命令

### 1.1 三个新工具（均在 `tools/`，均带 `--selftest`）

| 工具 | 用途 | 关键实现 |
|---|---|---|
| `tools/wlan_residual_scan.py` | A 组：偏置值域门 + 跨 `bl` 格式串解析 + 全 98 项复算 + 反汇编转储 | ①`gate_scan()` 用"派生寄存器 + 偏置"重对槽位；②`FmtResolver` 在**函数内 CFG** 上做前向数据流，按 AAPCS64 只在 `bl` 处失效 `x0..x18`、**保留 `x19..x28`** |
| `tools/hal_perm_gate.py` | B 组：HAL 方法级权限门 | 校验 `.gnu_debugdata` build-id 同源 → 读 vtable@`0x1a0a0` 槽 2..10 → 逐方法解析 `BL→PLT/内部符号` → 全 `.text` 的 `svc`/`mrs tpidr_el0`/`blr` 统计 → `prctl`/`syscall` 逐点核参 |
| `tools/ftm_tool_surface.py` | C 组：FTM 工具的通道判定 | `DT_NEEDED` + `.dynsym` UND 分类；`bl ioctl@plt` 逐点求 `x1`（request，含 `movk` 的 `lsl #16`）与 `x0`；`/dev` 串 → 引用函数 → 该函数是否含 ioctl；`0x89fd/0x89f1` 立即数 + 字面量双路 |

### 1.2 复算命令（全部只读物料）

```powershell
cd "D:\AI_tools\AI_Workspace\WBK_OPK_RT_CRA"
Get-FileHash vendor_ko\qca_cld3_wlan.ko -Algorithm SHA256        # f45c1c1c…74d00

# A 组
python tools\wlan_residual_scan.py --selftest                     # 9 ok / 0 fail
python tools\wlan_residual_scan.py                                # A1 + A2 逐条
python tools\wlan_residual_scan.py --all                          # 全 98 项：27 处 sscanf / unresolved=0 / unbounded=0
python tools\wlan_residual_scan.py --dump artifacts_adb\r1_wlan_reach\residual\handlers

# B 组
python tools\hal_perm_gate.py --selftest                          # 11 ok / 0 fail
python tools\hal_perm_gate.py                                     # 9 方法 + 导入面 + 特权原语
python tools\hal_perm_gate.py --dump 90a0:218                     # changeConnectionMode 带字符串注释

# C 组
python tools\ftm_tool_surface.py --selftest                       # 6 ok / 0 fail
python tools\ftm_tool_surface.py --verbose                        # 32 个 ioctl 调用点逐点窗口

# 交付 CSV（三组同表头，顺序拼接）
$csv='artifacts_adb\r1_wlan_reach\residual_audit.csv'
python tools\wlan_residual_scan.py --csv $csv
python tools\hal_perm_gate.py     --csv $csv --append
python tools\ftm_tool_surface.py  --csv $csv --append
```

`residual_audit.csv` 表头：`group,item,object,addr,evidence,verdict,level,note`（72 条数据行 = A18 + B10 + C44）。

### 1.3 数据流模型与边界（**不得外推**）

1. **A 组的格式串解析是"函数内 CFG 前向数据流 + 常量格"**，join 取"相同才保留"，因此只会**漏解**、不会**错解**；
   跨函数的 `sscanf` 包装（若有）不在模型内 —— 本模块的 27 处全部是直接 `bl sscanf`。
2. **只对 `bl`（R_AARCH64_CALL26）视为调用**；`blr` 处一律失效 caller-saved。本模块 4 个 handler 内无 `blr` 影响格式串。
3. **A1 的"槽未预置"判定**只覆盖 `sp`/`x29` 相对写；不含"上一帧残留"（那正是未初始化的定义）。
4. **B 组的"无方法级门"是二进制内否定**：`BnOppoWifiService::onTransact` 分发层位于
   `vendor.oplus.hardware.wifi@1.1.so`（`DT_NEEDED`），**该 `.so` 未在物料中，未取得**；
   但分发层若要查身份，必须调用上述导入符号之一（本二进制一个都没有，且分发层在另一个 `.so` 中，
   不改变"方法体不查身份"这一结论）。此边界在 §3.6 单列。
5. **C 组请求码求解是逐调用点 24 条窗口的局部追踪**，遇到 `bl` 清空；因此 **4 处请求码仍"未解出"**（§4.2），
   但"是否出现 `0x89fd`"由**立即数 + 字面量双路全量扫描**回答，不依赖该追踪。

---

## §2 A 组逐 handler

### 2.1 A1 `MAXTXPOWER`（#74）`drv_cmd_max_tx_power` @`0x3fad0`（684 B，帧 `0x90`）

#### 指令序列（`0x3fb40`–`0x3fc48` 节选；`…` 处为 trace 参数装配，不影响判定）

```
0x3fb40  bl    strlen             ; len = strlen(cmd)
0x3fb44  mov   x1, x0             ; 第 2 参数 = count（注意 `strnchr` 原型是 (s, count, c)）
0x3fb48  mov   x0, x20            ; 第 1 参数 = cmd
0x3fb4c  mov   w2, #0x20          ; 第 3 参数 = 空格（不是 memchr 的 (s,c,n) 顺序）
0x3fb50  bl    strnchr            ; 在 cmd 前 len 字节内找第一个空格
0x3fb84  mov   w1, #0xa           ; 基数 10
0x3fb88  add   x2, sp, #0x14       ; 目标槽 = sp+0x14
0x3fb8c  bl    kstrtoint
0x3fb90  ldr   w20, [sp, #0x14]    ; ★ 无条件重载（无 cbnz/tbnz w0）
0x3fb94  add   w8, w20, #0x64      ; ★ 偏置 +100（把有符号区间折成无符号比较）
0x3fb98  cmp   w8, #0xc8
0x3fb9c  b.ls  0x3fc14             ; (unsigned)(v+100) <= 200  ⇒  成功臂
0x3fba0  …     qdf_trace_msg("… Invalid MAXTXPOWER command")
0x3fbd0  mov   w0, #-0x16          ; -EINVAL
0x3fc14  …     qdf_trace_msg("… SETMAXTXPOWER: %d")   ; w5 = w20
0x3fc48  …     hdd_get_front_adapter / sme_set_max_tx_power(w20) 循环下发
```

#### 判定

- **`w8` 是否自解析槽重载？是（隔一层）**：`w8 = w20 + 0x64`，`w20 = ldr [sp,#0x14]`，
  而 `sp+0x14` 正是 `0x3fb88` 交给 `kstrtoint` 的槽。**门覆盖解析结果**。「指令级」
- **值域**：`b.ls` 成立 ⇔ `(uint32)(v + 100) ≤ 200`。取 `v ∈ [-100, 100]` 时该式与
  `0 ≤ v+100 ≤ 200` 等价 ⇒ **接受区间 `[-100, 100]`**（单位 dBm 量级，语义自洽）。
  区间外走 `0x3fba0` 打 "Invalid MAXTXPOWER command" 并返回 `-EINVAL`。**有界**。「指令级」
- **扫描器为什么漏**：`scan_checks()` 只认"`ldr wT,[sp,#slot]` 之后 `cmp wT,#imm`"，
  不建模 `add wT2, wT, #imm` 的偏置形态 ⇒ 报 `no-check`。**这是扫描器的形态盲区，不是缺陷。**

#### 新增反例 H2（同类但比 H1 强）

```
0x3fb8c  bl   kstrtoint          ; 失败时 kstrtoint 不写 *res（内核 kstrtox 语义）
0x3fb90  ldr  w20, [sp, #0x14]  ; ← 该槽在 0x3fb8c 之前【从未被写】
```

- **槽位预置核查**（`_slot_preinit`）：函数入口 `0x3fad0`–`0x3fb8c` 的**唯一可达路径**上，写过的 `sp` 偏移只有
  `+0x18 / +0x1c / +0x20 / +0x24 / +0x08` 与 `x29−8 / −0x10 / −0xc`；**`sp+0x14` 无任何写**。
  「指令级」
- 因此输入 `MAXTXPOWER abc`（空格后非数字）时：`strnchr` 找到空格 → 跳过空格 → 非 NUL →`kstrtoint` 失败 →
  **读上一帧残留**作为功率值。若该残留恰好落在 `[-100,100]`，则通过门并被 `sme_set_max_tx_power` 消费。
- **对比 H1**：`SETMCRATE` 在 `0x3fa84` 有 `str wzr,[sp,#4]` 预置，所以 H1 仅是"静默降级"；
  **H2 多了一条"未初始化栈读"**，但仍**不构成越界/破坏/信息泄露**（值不回传用户）。
- **不外推**：不据此声称提权，不据此改四层判定。若要验证，最小实验是构造一个 `MAXTXPOWER` + 非数字后缀的
  ioctl 入参并观察 dmesg 的 `SETMAXTXPOWER: %d` 输出 —— 属**动态**，本轮不做。

### 2.2 A2 四个 `FMT-UNRESOLVED`：格式串逐条解出

**为什么上一轮解不出**：这 4 个 handler 的格式串都被编译器**提升到 callee-saved 寄存器**（`x22/x23/x25`），
在函数序言里只装一次，之后每个调用点用 `mov x1, xN` 复用。上一轮的 `ptr_arg_target()`
**遇到 `bl` 就 break**，而装载点与调用点之间隔着若干 `bl`，于是全部 `FMT-UNRESOLVED`。

本轮按 AAPCS64 语义（callee-saved 跨 `bl` 保值）做 CFG 前向数据流，全部解出：

| # | 命令 | handler | sscanf 调用点 | `x1` 来源 | 格式串 | 常量地址 | 输出槽 / 宽度 | 判定 |
|---|---|---|---|---|---|---|---|---|
| 70 | `CCXBEACONREQ` | `drv_cmd_ccx_beacon_req` @`0x3ebf8` | `0x3ed10`、`0x3ee14` | `x25`（`mov x1,x25` @`0x3ed0c` / `0x3ee10`） | `"%31s "` | `.rodata.str1.1+0x12a09`（`movz/movk` 组 `0x3ecf4/0x3ecfc/0x3ed04/0x3ed08`） | `sp+0xb0` / 32 B | **有界** |
| 71 | `CCXPLMREQ` | `drv_cmd_ccx_plm_req` @`0x3f170` | `0x3f230`、`0x3f29c`、`0x3f328`、`0x3f400`、`0x3f480`、`0x3f504`、`0x3f588`、`0x3f60c`、`0x3f694`、`0x3f720`、`0x3f7d0`（11 处） | `x22`（`mov x1,x22` @`0x3f22c` 等） | `"%31s "` | 同上 `+0x12a09`（`0x3f214/0x3f21c/0x3f224/0x3f228`） | `sp+0x8` / 32 B | **有界** |
| 90 | `SET_DISABLE_CHANNEL_LIST` | `drv_cmd_set_disable_chan_list` @`0x41268` | `0x41304`、`0x4153c` | `x23`（`mov x1,x23` @`0x41300` / `0x41538`） | `"%d "` | `.rodata.str1.1+0x14f4d`（`0x412e8/0x412f0/0x412f8/0x412fc`） | `sp+0x14` / 4 B | **有界** |
| 92 | `GET_ANI_LEVEL` | `drv_cmd_get_ani_level` @`0x41be0` | `0x41cb4`、`0x41df0` | `x25`（`mov x1,x25` @`0x41cb0` / `0x41dec`） | `"%d "` | 同上 `+0x14f4d`（`0x41c98/0x41ca0/0x41ca8/0x41cac`） | `sp+0x1c` / 4 B | **有界** |

**格式串字节级复核**（直接读段，不经工具）：

```
.rodata.str1.1+0x12a09 : 25 33 31 73 20 00        = "%31s "
.rodata.str1.1+0x14f4d : 25 64 20 00              = "%d "
```

**"callee-saved 未被中途覆盖"的独立复核**（防止数据流把别处的常量错接过来）：

| handler | 寄存器 | 函数内**全部**写点 | 结论 |
|---|---|---|---|
| `ccx_beacon_req` | `x25` | `0x3ecf4/0x3ecfc/0x3ed04/0x3ed08`（装载 `"%31s "`）、`0x3ef14`（`mov w25,#0x33`，**在两个调用点之后**） | 两个调用点用的都是 `"%31s "` |
| `ccx_plm_req` | `x22` | `0x3f1b0`（形参 `mov x22,x2`）、`0x3f214..0x3f228`（装载）、`0x3f894`（`ldp` 恢复，**在全部调用点之后**） | 11 个调用点都是 `"%31s "` |
| `set_disable_chan_list` | `x23` | `0x412e8..0x412fc`（装载）、`0x41610` 起（`ldr w23,[sp,#4]` 等，**晚于 `0x4153c`**） | 两个调用点都是 `"%d "` |
| `get_ani_level` | `x25` | `0x41c98..0x41cac`（装载）、`0x41f68`（`mov x25,xzr`，**晚于两个调用点**） | 两个调用点都是 `"%d "` |

**槽位边界**（写区间不覆盖下一个独立对象）：`%31s` 最坏 31+1 = 32 B。

| handler | 写区间 | 下一个独立 `sp` 偏移 | 是否重叠 |
|---|---|---|---|
| `ccx_beacon_req` | `[0xb0, 0xd0)` | `0xe0`（`0xa8` 在前） | 否 |
| `ccx_plm_req` | `[0x08, 0x28)` | `0x30`（`0x04` 在前） | 否 |
| `set_disable_chan_list` | `[0x14, 0x18)` | `0x18` | 否（恰好贴合） |
| `get_ani_level` | `[0x1c, 0x20)` | `0x20` | 否（恰好贴合） |

**同 handler 内相邻不变量（顺带核过，不属本轮任务，但可减少复核成本）**：

- `SET_DISABLE_CHANNEL_LIST`：`0x41310 ldr w5,[sp,#0x14] ; 0x41314 cmp w5,#0x62 ; 0x41318 b.lo 0x413e4`
  ⇒ 通道数 **< 98** 才进成功臂（`0x413e4` 打 "Number of channel to disable are: %d"）。**上界存在**。「指令级」
- `GET_ANI_LEVEL`：`0x41cc0 ldr w5,[sp,#0x1c] ; 0x41cc4 cmp w5,#0x15 ; 0x41cc8 b.lo 0x41d54`
  ⇒ 频点数 **≤ 20**；栈上 `channel_freq[]` 基址 `x29-0x60 = sp+0xc0`（`0x41dc4`），
  20×4 B = `0x50` ⇒ 末字节 `0x10f`，而栈保护字在 `x29-0x10 = sp+0x110`：**恰好贴合，不覆盖**。「指令级」

### 2.3 全量复算（98 项）

```
== 全量复算：14 个 handler / 27 处 sscanf / unresolved=0 / unbounded=0
   fmt='%31s '     18 处
   fmt='%d'        4 处
   fmt='%d '       4 处
   fmt='%u %u'     1 处
```

⇒ 上一轮"所有 `%s` 全部带 `%31s` 宽度"的结论，**在补上 4 个 handler 后仍然成立且更强**：
27 处全部可解、全部有宽度、无 `%[`。

### 2.4 A 组小结

| 项 | 判定 | 等级 |
|---|---|---|
| A1 `MAXTXPOWER` 值域门 | **有界 [-100,100]**（"w8 是否自槽重载"= 是，隔一层 `add`） | 指令级 |
| A1 返回值门 / 槽初值 | **缺失**（H2：未初始化栈读） | 指令级 |
| A2 ×4 格式串 | **有界**（`%31s` / `%d`，无裸 `%s`/`%[`） | 指令级 |
| 98 项 handler 内存破坏反例 | **仍为 0** | 指令级（有界窗口数据流 + 人工复核） |

---

## §3 B 组：HAL HIDL 方法权限门（FTM U1）

### 3.1 符号来源与同源校验

HAL 的 `.gnu_debugdata` 段只有 `0xD60` B（LZMA 压缩）。`.build/hal_debugdata.elf` 是解压后的 mini 调试信息：

- **build-id 逐字节相同**：`828f85aa2715c0d23592356e67791585`
  （`.note.gnu.build-id` 原始数据 `04000000 10000000 03000000 474e5500 828f85aa…`，前 12 B 是 note 头）；
- 289 个符号（含 `STT_FUNC` 92 个带 size），可把 vtable 槽位与 `OppoWifiService` 的方法名一一对上
  （如 `0x90a0` = `…15OppoWifiService20changeConnectionModeEj`）。

**这条校验很关键**：本节的"方法身份"不是靠"符号存在"猜的，而是"同一 build-id 的调试符号 + vtable 指针 + 方法体"三方对齐。

### 3.2 vtable@`0x1a0a0` → 9 个 HIDL 方法（与既有审计一致）

| slot | HIDL code | 方法 | 入口 | size | 权限/身份调用 |
|---|---|---|---|---|---|
| 2 | 1 | `changeConnectionMode(uint32)` | `0x90a0` | 536 | **NONE** |
| 3 | 2 | `catchSnifferLog(uint32,uint32)` | `0xad20` | 1484 | **NONE** |
| 4 | 3 | `resetConnectionMode()` | `0x9684` | 76 | **NONE** |
| 5 | 4 | `executeDriverCommand(string)` | `0x992c` | 1592 | **NONE** |
| 6 | 5 | `setupFTMdaemon()` | `0xa0dc` | 692 | **NONE** |
| 7 | 6 | `sendSupplicantCommand(string)` | `0xa568` | 816 | **NONE** |
| 8 | 7 | `runWiFiScript(string,string)` | `0xa898` | 1160 | **NONE** |
| 9 | 8 | `sendIniContent(string)` | `0xb2ec` | 796 | **NONE** |
| 10 | 9 | `getIniVersion(string)` | `0xb65c` | 1112 | **NONE** |

> 槽位↔code 的对应与 `WIFI_P1_ROOT_COMMAND_AUDIT.md` §1 完全一致（该文由 dex 侧 `const/4` 事务号独立得出），
> 本轮用 build-id 同源的调试符号再独立确认一次。

### 3.3 导入面：89 个 PLT 符号，**0 个**身份/权限 API【指令级】

`DT_NEEDED`：`liblog libutils libcutils libhidlbase libbase vendor.oplus.hardware.wifi@1.1.so libc++ libc libm libdl`。

89 个导入的**完整**语义分类里，**没有任何**下列符号（任一缺失即不可能做方法级 uid 检查）：

```
IPCThreadState::getCallingUid / getCallingPid / checkCallingPermission /
checkCallingOrSelfPermission / getuid / geteuid / getgid / getegid / getpid /
gettid / selinux_* / audit_* / capget / capset / setuid / setresuid
```

**两个"看起来可疑"的导入，逐点核参后排除**：

| 导入 | 调用点 | 参数 | 定性 |
|---|---|---|---|
| `syscall` | `0x9484` | `args = (273, fd, buf, 0)` ⇒ `__NR_finit_module` | `loadDriver()` 的模块装载，**非** uid 读取 |
| `prctl` | `0xa548` | `args = (1, 9)` ⇒ `PR_SET_PDEATHSIG, SIGKILL` | `executeDaemonCommand()` 的子进程死亡信号，**非**权限门 |

其余旁证：

- **`.text` 内 `svc` 指令 = 0 条** ⇒ 不存在"绕过 libc 直接取 uid"的路径；
- 49 条 `mrs xN, tpidr_el0` 全是 bionic TLS（栈保护字 / `errno`），非权限；
- 89 条 `blr` 全是 `std::function` 回调 / 虚调用；
- `.rodata/.dynstr` 中 **0 条** 含 `permission` / `uid` / `caller` / `checkCalling` / `selinux` 的文案。

### 3.4 逐方法的"无门直通"证据【指令级】

| code | 方法 | 方法体内**直通**的特权原语（调用点） |
|---|---|---|
| 1 | `changeConnectionMode` | `setConMode`@`0x9194`（写 `con_mode`）、`loadDriver`@`0x926c`（`finit_module`）、`executeShellCommand`@`0x91c8`（`/vendor/bin/ifconfig wlan0 up`）、`stat`@`0x9238` |
| 2 | `catchSnifferLog` | `executeShellCommand`@`0xb0e8`/`0xb124`、`executeDaemonCommand`@`0xb1dc`、`chown`@`0xb13c`、`SetProperty`@`0xb230`、`stat`@`0xb0fc` |
| 3 | `resetConnectionMode` | `cleanChildDaemonProcess`@`0x9698`、`compressedSnifferFile`@`0x96ac` |
| 4 | `executeDriverCommand` | `stat`@`0x9a70`/`0x9b8c`、`checkIfStringSafe`@`0x9db0`（regex 黑名单）、`executeShellCommand`@`0x9cb8`/`0x9e20`、`blr`×6（回调） |
| 5 | `setupFTMdaemon` | `stat`@`0xa1ac`、`filterModuleName`@`0xa13c`、`executeDaemonCommand`@`0xa2e4`（`/vendor/bin/ftmdaemon`） |
| 6 | `sendSupplicantCommand` | `stat`@`0xa5c8`、`checkIfStringSafe`@`0xa78c`、`executeShellCommand`@`0xa7c0`（`wpa_cli`） |
| 7 | `runWiFiScript` | `checkIfStringSafe`@`0xac58`、`executeShellCommand`@`0xac8c` |
| 8 | `sendIniContent` | `fopen`@`0xb474`（固定路径写） |
| 9 | `getIniVersion` | `fopen`@`0xb7dc`（**入参当路径**，任意 root 读） |

**逐方法唯一的 `blr` 用途**：code4 的 6 条 `blr`、code8/9 的 5/6 条 `blr` 分别是 `std::function` 回调
（HIDL 的 `_hidl_cb`）与 STL 内部虚调用；**没有一条是 `blr` 到某个"权限检查函数指针"**——
判据是：方法级 uid 检查在 AArch64 上必然要么 `bl` 到 libbinder/libhwbinder 的导入符号（本二进制 0 个），
要么 `svc #0` 直接系统调用（本二进制 0 条），两条路都被否掉。

### 3.5 `changeConnectionMode`：一次 HIDL 调用即可进 FTM（FTM 面最强的单点证据）

```
0x90ec  cmp   w20, #5
0x90f0  b.hi  0x9140                ; mode > 5 ⇒ 打 "inVaild connection mode or running in MTK platform"，返回 -1
0x9184  bl    isWifiDriverLoaded
0x9188  tbz   w0, #0, 0x9210        ; 驱动未加载 ⇒ 先 loadDriver(finit_module)
0x9190  mov   w1, w20               ; ★ 调用方给的 mode，原样
0x9194  bl    setConMode            ; setConMode(mode)
         └ 0x9508  adrp x0,#0x6000 ; 0x9514 add x0,x0,#0xa0f  ⇒ "/sys/module/wlan/parameters/con_mode"
           0x951c  adrp x1,#0x6000 ; 0x9518 add x1,x1,#0xf92  ⇒ "w+"
           0x9524  bl    fopen
           0x9530  mov   x0, sp      ; buf（0x9520 已清零 32 B）
           0x9534  mov   w4, w20     ; mode 作为变参
           0x9538  bl    0xbc38      ; 本地特化 snprintf 包装
                   └ 0xbc9c  adrp x2,#0x6000 ; 0xbca0 add x2,x2,#0x850 ⇒ "%d"
                     0xbca8  mov  w1, #0x20              ; 硬编码长度 0x20
                     0xbcb0  bl   vsnprintf(buf, 0x20, "%d", ap)
           0x9544  bl    __strlen_chk ; strlen(buf)（object size 0x20）
           0x9560  bl    __fwrite_chk ; fwrite(buf, 1, len, fp)
0x91c8  bl    executeShellCommand("/vendor/bin/ifconfig wlan0 up")
```

> 注：`0xbc38` 的符号是 `_ZL8snprintfPcU17pass_object_size1mPKcz`，但编译器把它**特化**成了
> "`buf` + 一个变参"的本地包装：长度 `0x20` 与格式串 `"%d"@0x6850` 都在包装体内硬编码（`0xbc9c`/`0xbca8`），
> 因此调用点只出现 `x0=buf`、`w4=mode` 是正常的，不是漏参。

- **接受域是 `mode ∈ [0, 5]`，`5` = FTM**（与驱动 `hdd_ioctl` 的 `cmp w0,#5` 同一个枚举）。
- **没有第二道门**：`setConMode` 里没有"值必须是 0/1"之类的白名单，直接 `"%d"` 落盘。
- ⇒ **对 FTM 的 U1，答案是：不是"是否能写 con_mode=5"的问题，而是"谁能发 code1"**。而"谁能发"由 §3.6 的
  SELinux 决定，HIDL 方法体内**没有任何门**。

### 3.6 真正的门：SELinux 域级（【源码级】`vendor_sepolicy.cil`）

| 能力 | 主体 | 行 |
|---|---|---|
| `hwservice_manager find` on `oplus_wifi_hal_service` | `engineermode_app_30_0` | L3943 |
| 同上 | `platform_app_30_0` | L5588 |
| 同上 | `system_server_30_0` | L5589 |
| 同上（含 `add`） | `oplus_wifi_service`（服务自身） | L5585 |
| `binder call` to `oplus_wifi_service` | `engineermode_app_30_0` | L3940 |
| 同上 | `platform_app_30_0` | L5572 |
| 同上 | `system_server_30_0` | L5575 |

- **`shell` / `untrusted_app` / `priv_app` / `wifi_ftm` / `wcnss_service` 对上述两个标签的 `find`/`call`：全文 0 命中。**
  ⇒ shell **不能**自己拿到 HIDL 句柄（这与 `WIFI_P1` §4.3 的 tx10070 实测一致：从 shell 侧只到得了 Java AIDL，
  且 Java 层 `enforceAccessPermission()` 是空实现）。
- 服务的 init 描述：`.build/vendor/x/odm/etc/init/vendor.oplus.hardware.wifi@1.1-service.rc`
  —— `user root`、`group wifi system vendor_qti_diag net_admin`、`capabilities NET_ADMIN NET_RAW SYS_MODULE`。「源码级」

**⇒ U1 结论（收紧）**

> 受限 UID 0 域（`oplus_wifi_service` 自身）若已持有句柄，**不存在任何方法级权限门**；
> 外部域只要过得了 SELinux 的 `find`+`call`（`engineermode_app` / `platform_app` / `system_server` 三类），
> 同样**不存在方法级门**，可直接调用 code1(arg=5) 切 FTM、或 code4 执行 `sh -c`。
> **反过来**：`shell` 与普通应用域既无 `find` 也无 `call`，所以"拿到 HIDL 句柄"这件事本身在本构建里**没有静态路径**。

### 3.7 B 组未决 / 未取得（诚实登记）

1. **`vendor.oplus.hardware.wifi@1.1.so` 未取得**（HAL 的 `DT_NEEDED`，`BnOppoWifiService::onTransact` 分发层在其中）。
   本文的"无方法级门"是对**方法体**的完整否定 + 对**整个服务二进制**的导入面否定；
   分发层若有门，只能通过上述导入符号实现（本二进制 0 个），但**该 `.so` 本身未做指令级核查** ⇒ 标 **未决（物料缺失）**。
2. `lshal debug -E vendor.oplus.hardware.wifi@1.1::IOppoWifiService/default` 在既有 bugreport 中**失败（exit 128）**，
   因此没有 HIDL 侧的 interface dump 可对照方法序（本轮改用 vtable + 同源调试符号，已足够）。
3. Java/AIDL 层"哪一条事务最终落到 code1"，本文**未复核**（属 `WIFI_P1` / `WIFI_P0` 的范围），
   本文只回答"HAL 方法体是否有门"。

---

## §4 C 组：`myftm` / `ftmdaemon` 的 ioctl 面（FTM U2）

### 4.1 `myftm`（`.build/vendor_bins/vendor/bin/myftm`，225,752 B）—— **纯 netlink，无 ioctl**

| 检查 | 结果 |
|---|---|
| `ioctl` 导入 | **无**（`.dynsym` UND 里没有；PLT 95 项中 0 项） |
| `DT_NEEDED` | `libcutils libz **libnl** libc++ libc libm libdl` |
| netlink 相关导入 | `socket`、`bind`、`genl_connect`、`genl_ctrl_alloc_cache`、`genl_ctrl_search_by_name`、`genl_family_get_id`、`genlmsg_put`、`nl_socket_alloc`、`nl_socket_add_membership`、`nl_send_auto_complete` |
| 通道字符串 | `nl80211`、`nl80211 not found.`、`couldn't init nl80211!: %s`、`nl80211: sending message`、`nl80211: waiting for response` |
| 业务字符串 | `failed to join testmode group!`、`testmode`、`qca6174CmdRegRead/Write`、`qca6174TxCommand`、`qca6174SetAntenna`、`qca6174CmdSAR`、`qca6174_eeprom_block_read`、`myftm_wlan_bdf_read/write` … |
| 支持性常量 | `mov w?,#0x67`@`0x1c828`（= `NL80211_CMD_VENDOR`）、`mov w?,#0xc2`@`0x159d4`（= `NL80211_ATTR_VENDOR_ID`）——**单条常量，未串联调用点，仅作旁证** |
| `0x89fd` / `0x89f1` | **立即数 0 命中、字面量 0 命中** |

**判定**：`myftm` 的 WLAN/FTM 业务走 **nl80211 generic netlink（vendor 命令）**，**不碰** `0x89fd`、也不碰任何
WEXT 私有 ioctl。**【指令级】**

### 4.2 `ftmdaemon`（`.build/vendor_bins/vendor/bin/ftmdaemon`，163,632 B）—— netlink(WLAN) + 字符设备 ioctl(NFC/BT/tty)

| 检查 | 结果 |
|---|---|
| `ioctl` 导入 | **有**，`bl ioctl@plt` 共 **32 个调用点** |
| `DT_NEEDED` | `**libnl** libbt-hidlclient **libdiag** libcutils liblog libhardware **libbtnv** libc++ libc libm libdl` |
| netlink 相关导入 | `genl_connect`、`genl_ctrl_alloc_cache`、`genl_ctrl_search_by_name`、`genlmsg_put`、`nl_socket_alloc`、`nl_send_auto_complete`（与 `myftm` 同源） |
| 通道字符串 | `nl80211`、`couldn't init nl80211!: %s`、`nl80211: sending message`（WLAN 面）；`/dev/ese`、`/dev/btpower`、`/dev/ttyHS0`、`/dev/smd3`、`/dev/smd5`、`/dev/nq-nci`、`/dev/i2c-4`（非 WLAN 面） |
| 业务字符串 | `libpn548ad_fw.so`、`libpn553_fw.so`、`gphDnldNfc_DlSeq`（NXP NFC 固件下载）、`Failed to stop Transmit PS/RT` |
| `0x89fd` / `0x89f1` / `0x89f0` | **全部 0 命中**（立即数 + 字面量） |

**32 个 ioctl 调用点的请求码（静态可解部分）**：

| request | 调用点 | 所属函数 | 该函数的字符串证据 | 归属 |
|---|---|---|---|---|
| `0x707` | `0xd4fc`、`0xd5a4` | `0xd450`、`0xd538` | 函数内未解析出字符串引用；调用形态为"命令字节 + 载荷 + 3×u16 + 指针"的私有包（`0xd4b8`–`0xd4f4`） | 非 WLAN（私有字符设备通道）**【未决：设备名】** |
| `0x4004e901` | `0xdf30`、`0xdf78`、`0xdfb8`、`0xe9a8`、`0xfd50`、`0x10088` | `0xdf0c` 等 | `libpn548ad_fw.so`、`libpn553_fw.so`、`gphDnldNfc_DlSeq` | **NFC**（`_IOW(0xe9,1,4)`） |
| `0x4004e902` | `0x10c00` | `0x10bf0` | — | NFC |
| `0x4004e909` | `0xe858` | `0xe83c` | — | NFC |
| `0x4004ea01` | `0x10568` | `0x1043c` | `/dev/ese` | **NFC eSE** |
| `0xbfac` | `0x12600` | `0x12584` | `/dev/btpower` | **BT 电源** |
| `0xc008561c` | `0x174f4`、`0x1751c`、`0x17548`、`0x17664`、`0x17750`、`0x17770`、`0x1784c`、`0x17eb0`、`0x17f10`、`0x185d0`、`0x18668` | `0x17490`、`0x17618`、`0x176b8`、`0x17800`、`0x17e08`、`0x17ed4`、`0x18590`、`0x18624` | `Failed to stop Transmit PS` | `_IOWR('V',0x1c,8)` 族（BT/UART 侧） |
| `0xc0205648` | `0x1758c`、`0x17788`、`0x188e8` | 同上 | — | 同上 |
| `0xc054561d` | `0x17f4c` | `0x17f2c` | `Failed to stop Transmit RT` | 同上 |
| `0x402c5639` | `0x17fd4` | `0x17fc4` | — | 同上 |
| 未解出 | `0xfb9c`、`0x10540`、`0x10578`、`0x109d0` | — | — | **未决（4 处，见 §4.4）** |

**设备节点 → 引用函数 → 该函数是否含 ioctl**（`/dev` 串 xref）：

```
/dev/ttyHS0    xref@0x013420 func=0x0133d0 ioctl_in_func=N
/dev/i2c-4     xref@0x01156c func=0x01133c ioctl_in_func=N
/dev/smd5      xref@0x01a304 func=0x01a2f0 ioctl_in_func=N
/dev/ese       xref@0x010508 func=0x01043c ioctl_in_func=Y   ← NFC
/dev/smd3      xref@0x01341c func=0x0133d0 ioctl_in_func=N
/dev/nq-nci    xref@0x00def0 func=0x00dee4 ioctl_in_func=N
/dev/nq-nci    xref@0x00ea0c func=0x00e9cc ioctl_in_func=N
/dev/nq-nci    xref@0x00eb0c func=0x00eb08 ioctl_in_func=N
/dev/btpower   xref@0x0125dc func=0x012584 ioctl_in_func=Y   ← BT
```

**判定**：`ftmdaemon` 的 ioctl **全部**落在 NFC / BT 电源 / UART 字符设备上；**没有一个落在 `wlan0`
或 WLAN 私有码上**（`0x89xx` 家族 0 命中）。其 WLAN 面与 `myftm` 共用同一套 nl80211 客户端代码。**【指令级】**

### 4.3 对照组

| 二进制 | 通道 | 关键事实 |
|---|---|---|
| `ftmtest`（29,952 B） | nl80211 netlink | 不导入 `ioctl`；`libnl`+`genl_connect`；立即数 `0x1374`（QCA OUI `00:13:74`）5 处（`0x3594`/`0x3960`/`0x416c`/`0x4e60`/`0x5530`），与 `NL80211_CMD_VENDOR` 的 OUI 用法一致 |
| `iwpriv`（20,488 B） | WEXT `ioctl`（8 点） | `0x8912`/`0x8927`/`0x8915`/`0x8954`（标准 net 设备 ioctl 段）+ `0x8b01`/`0x8b0b`/`0x8b0d`（标准 WEXT 段，`SIOCIWFIRST = 0x8B00`）；**无 `0x89f1`**（`SIOCDEVPRIVATE = 0x89F0`） |

> **与 v13.2 WEXT 审计的交叉核对（本轮独立复算，结论一致）**：`iwpriv` 的 8 个 ioctl 调用点中，7 个是固定常量
> （`0x8912`/`0x8b01`/`0x8b0b`/`0x8b0d`/`0x8927`/`0x8915`/`0x8954`，即 `WLAN_WEXT_HANDLER_AUDIT.md` 所说的
> "7 个固定常量"），第 8 个在 `0x2a24`，其请求码来自**表驱动**：`0x2a14 madd x22,x23,#0x18,x21` →
> `0x2a18 ldr w1,[x22]`（按命令号索引每项 0x18 字节的私有表）。这与"`iwpriv` 的私有面走
> `0x8BE0..0x8BFF`（`SIOCIWFIRSTPRIV`）+ 表驱动"一致；**`0x89f1` 不在其中**（`ioctl_const_inventory.md` 里
> `0x89f1` 的调用方是 `wpa_supplicant`/`hostapd`/`sigma_dut`/`lowi-server`，不是 `iwpriv`）。
> 本轮把 `iwpriv` 仅作 C 组对照，不重复 WEXT 审计的结论。

### 4.4 U2 结论与残留

**结论（收紧为 (a)）**：

> 出货固件里的两个 FTM 工具**都不使用 `0x89fd`**：`myftm` 连 `ioctl` 符号都不导入（纯 nl80211）；
> `ftmdaemon` 虽有 32 个 ioctl 调用点，但请求码全部属于 NFC（`_IOW(0xe9, …)` / `_IOW(0xea, …)`）/BT/`V` 族，
> 设备面是 `/dev/ese`、`/dev/btpower`、`/dev/ttyHS0` 等，**没有 WLAN 私有码、没有 `0x89fd`**。
> 结合上一轮对全物料 2,063 个文件的扫描（`0x89fd` 仅命中 `adpl`/`netmgrd`/`qti` 等 RMNET 面），
> **`0x89fd`（`hdd_ioctl` FTM testmode）在本构建内无调用方。**

**残留（4 处请求码未解出）**：`0xfb9c`、`0x10540`、`0x10578`、`0x109d0`。这 4 处不影响结论——
"是否出现 `0x89fd`"由**立即数 + 字面量双路全量扫描**回答（0 命中），而不是由这 4 处推断。
若将来要把 C 组做到"逐点闭口"，需把这 4 处的人工回溯补上（标 **未决**）。

---

## §5 与四层判定的关系（**不改变 NO-GO**）

按 `CLOSURE.md` §1.1 的口径逐层对照：

| 层次 | 本文前 | 本文后 | 变化 |
|---|---|---|---|
| ① Root UID 命令执行（受限域） | 达成 | 达成 | **不变**（本文不做动态验证，不新增执行路径） |
| ② 可用 root（域逃逸） | NO-GO | NO-GO | **不变**（B 组只说明"HAL 方法体无门"，域逃逸面未触及） |
| ③ 持久 ROOT | NO-GO | NO-GO | **不变** |
| ④ GhostLock（①闭合 / ②③未闭合，冻结） | 冻结 | 冻结 | **不变**（本文不产出任何内核地址泄露原语） |

**本文带来的净变化（都是"把未决清零"，不是能力提升）**：

1. **A 组未决清零**：`MAXTXPOWER` 从"未决"变为"有界"（并新增低危 H2）；4 个 `FMT-UNRESOLVED` 全部解出为
   `%31s`/`%d`，`98 项 handler` 的"无内存破坏反例"结论**从"98 项中含 4 项未决"变为"98/98 已判"**。
2. **FTM U1 从"未决"变为"已证无方法级门"**，同时把 FTM 的进入路径描述**细化为一条**：
   `HIDL code1(arg=5) → setConMode(5) → con_mode=5`，不需要脚本/`insmod`/直接写 sysfs。
   这**细化**了 `WLAN_FTM_AUDIT.md` §5 的"(b) 条件性关闭"表述，但**不改变**判定等级：
   因为能发 code1 的域只有 `engineermode_app` / `platform_app` / `system_server`（+ 服务自身），
   `shell` 无 `find`/`call`。
3. **FTM U2 从"未决"变为"无调用方"**，因此 `WLAN_FTM_AUDIT.md` 的"(b) 条件性关闭，实际接近 (a)"
   现在可以**正式收紧为 (a)**（限定：仅对 `0x89fd` 这一条 ioctl 面；不涉及其它 FTM 通道）。

**不得外推（三条硬边界）**：

1. **B 组不证明"shell 能调到 HIDL"**：SELinux 明确不给 shell `find`/`call`；本文只证"若有句柄则无方法级门"。
2. **C 组不证明时序**：`myftm`/`ftmdaemon` 何时被拉起、是否与 `con_mode=5` 竞态，本轮不做。
3. **A 组不覆盖下游**：`sme_set_max_tx_power` / `wlan_hdd_get_ani_level` / `wlan_hdd_disable_channels`
   内部是否有二次校验，仍属"handler 边界之外"，本轮不涉及。

---

## §6 复算产物

| 文件 | 说明 |
|---|---|
| `tools/wlan_residual_scan.py` | A 组：偏置值域门 + 跨 `bl` 格式串数据流 + 98 项全量复算 + 反汇编转储（`--selftest` 9/9） |
| `tools/hal_perm_gate.py` | B 组：build-id 同源校验 + vtable 方法表 + 导入面/`svc`/`prctl`/`syscall` 核参（`--selftest` 11/11） |
| `tools/ftm_tool_surface.py` | C 组：`DT_NEEDED`+UND 分类 + 32 个 ioctl 调用点请求码 + `/dev` xref + `0x89fd` 双路扫描（`--selftest` 6/6） |
| `artifacts_adb/r1_wlan_reach/residual_audit.csv` | 72 条数据行（A18 + B10 + C44），表头 7 列 |
| `artifacts_adb/r1_wlan_reach/residual/A_group.txt` | A 组工具完整输出（含全量复算） |
| `artifacts_adb/r1_wlan_reach/residual/B_group.txt` | B 组工具完整输出 |
| `artifacts_adb/r1_wlan_reach/residual/C_group.txt` | C 组工具完整输出（`--verbose`，含每个 ioctl 的指令窗口） |
| `artifacts_adb/r1_wlan_reach/residual/hal_key_functions.txt` | HAL 关键函数带字符串/调用注释的反汇编（`0x90a0`/`0x94e8`/`0x9428`/`0xa0dc`/`0x18be4`/`0xa390`） |
| `artifacts_adb/r1_wlan_reach/residual/handlers/*.txt` | 5 个 A 组 handler 的带重定位注释反汇编 |

> 注：`tools/` 下 `wlan_handler_scan.py`（上一轮）的 `--dump-dir` 存在一处崩溃
> （`%x` 格式化 `off=None`），本轮**未修改该文件**，改由 `wlan_residual_scan.py --dump` 提供等价能力。

---

## §7 最值得复核的 3 点

1. **H2（A1）——`0x3fb90` 的未初始化栈读**。
   `MAXTXPOWER` 是"值域门存在（[-100,100]）但返回值门缺失 + 槽未预置"的组合，与 H1 不同：
   H1 的槽被 `str wzr` 预置过，H2 没有。**这是本轮唯一新增的反例**，也是最容易被"扫描器说 no-check、
   人工又看到 `cmp`"这种半对半错的状态掩盖的一处。复核方式：确认 `sp+0x14` 在 `0x3fad0`–`0x3fb8c`
   之间确实无写（本文已逐条列出所有被写的 `sp` 偏移），并确认 `kstrtoint` 失败不写目标槽。

2. **B 组 §3.5：`changeConnectionMode(5)` 一次调用进 FTM**（`0x90ec` / `0x9190` / `0x9194` / `0x9524–0x9560`）。
   这条把 FTM 的"进入代价"从"写 sysfs + 脚本 + insmod"降到"一次 HIDL 调用"，且方法体内**没有任何门**。
   需要复核的是**上游**：`engineermode_app` / `platform_app` / `system_server` 三者中，哪些真切能发到 code1
   （Java/AIDL 侧的事务号与权限），以及 `mode ≤ 5` 之外是否还有 AIDL 侧的取值限制。本文只否证了 HAL 方法体。

3. **C 组 §4.2：`ftmdaemon` 的 4 处未解出请求码**（`0xfb9c`、`0x10540`、`0x10578`、`0x109d0`）。
   它们**不可能**是 `0x89fd`（立即数/字面量双路 0 命中），但"逐点闭口"还差这 4 处；
   同时 `0x707` 与 `0xbfac` 两个私有码的**设备归属**也只在函数级定位（`/dev/btpower`），未做到"fd 数据流级"。
   若 C 组要继续做，正确方向是补这 6 个点的 fd 溯源，而不是重扫 `0x89fd`。
