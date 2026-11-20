# WLAN WEXT 私有 ioctl Handler 静态审计（qcacld / OPPO K3 PCGM00）

> 对象：`vendor_ko/qca_cld3_wlan.ko`（ET_REL/AArch64，SHA-256 `f45c1c1c…74d00`，内核 4.9.227-perf+）
> 方法：纯离线反汇编 + 符号/重定位复算；**未连接设备、未动态运行、未联网**。
> 可达链（主代理已确证，本文直接采用）：`oplus_wifi_service`(uid 0, net_admin) → `/vendor/bin/sh -c "/odm/bin/iwpriv wlan0 <name> <args>"` → `ioctl(0x8BE0..0x8BFF)` → `wext_handle_ioctl`/`ioctl_private_call` → `we_private[i]`。
> 本文只回答一个问题：**用户可控的 `length`/指针能否让某个 handler 越界读/写。** 符号存在、厂商源码没写检查，都不单独构成结论。

---

## §0 结论摘要

**总体：在本轮逐指令核完的 8 个 handler 中，未发现"长度未校验导致固定结构体越界"的可确认反例。** 原因是本机 .ko 的实际形态与"经典 qcacld 缺陷形态"不同：内核侧 `wext-priv.c` 已经按 `we_private_args[].set_args` 声明尺寸分配并拷贝，且多数 0x8BE0.. 父项因 `IW_PRIV_SIZE_FIXED` 且 ≤16B 而走 `&iwr->u`（16B union）**免拷贝路径——用户指针根本到不了驱动**。

| ioctl | handler | 判定 |
|---|---|---|
| 0x8BE0 | `iw_setint_getnone` | **有界**（union 16B；sub_cmd ≤0x64 经跳表校验） |
| 0x8BE7 | `iw_hdd_set_var_ints_getnone` | **有界**（count=min(len,11)，44B 栈缓冲） |
| 0x8BF2 | `iw_set_host_offload` | **有界**（读 0..23，恰好 24B 声明尺寸） |
| 0x8BF6 | `iw_set_keepalive_params` | **有界**（`length == 0x20` 精确门） |
| 0x8BF7 | `iw_set_packet_filter_params` | **有界**（`length >= 3` 且 `length == 3+20*buf[2]`） |
| 0x8BF8 | `iw_set_pno` | **有界**（`malloc(len+1)`；文本解析自带 SSID 1..16 / 信道 <98 校验） |
| 0x8BFC | `iw_set_two_ints_getnone` | **有界**（sub_cmd 1..0x17 跳表；只读 12B） |
| 0x8BFA | `iw_set_dynamic_mcbc_filter` | **无功能**（恒返回 -EINVAL，`0x8e360`） |
| 其余 15 个父项 | — | **未决**（内核侧分配/长度门已知；handler 体内字段偏移未逐指令核完） |

已确认的**结构性负结果**（比逐条"未发现"更有价值）：

1. **无用户指针的 handler 集合**（core `extra_size==0`，走 16B union）：0x8BE0、0x8BE1、0x8BE4、0x8BEF、0x8BE6、0x8BEB（SET）、0x8BED（GET）、0x8BF9、0x8BFA、0x8BFC。这些 handler 收到的 `extra == &iwr->u`，`iwr` 是 `wext_handle_ioctl` 的**内核栈**变量、长度固定 16B。即使 handler 读满 16B 也不越界；风险只剩"越过 16B 读栈"。
2. **`mem_alloc_copy_from_user_helper` 只有 2 个调用者**：`iw_setchar_getnone`(0x8BE3) 与 `iw_set_packet_filter_params`(0x8BF7)。前者**未核**，是本面唯一残留的"经典形态"嫌疑点（见 §4）。
3. **0x8BE4 / 0x8BE8 的真名**：`iw_set_three_ints_getnone` / `hdd_fips_test`。任务背景里的 `hdd_conn_set_connection_state` 是误解析——旧脚本用重定位 addend 直接当函数地址、没有加 `st_value`，而 `hdd_conn_set_connection_state` 恰好位于 `.text+0x0`。**该符号确实是 `hdd_conn_is_connected` 等函数的真实代码邻居，但不在这两个槽位。**

---

## §1 方法与复算命令

### 1.1 工具修正（重要）

`tools/ko_fn.py` 的注解在本 .ko 上**双重失效**：

- 该 .ko 的 `.rela.text` 只有 `CALL26=283` 与 `MOVW_UABS_G0_NC..G3_NC=264/266/268/269`，**没有** `ADR_PREL_PG_HI21(275)`/`ADD_ABS_LO12_NC(277)`。编译器全部用 `movz/movk` 绝对地址链引用 `.rodata`，所以 `ko_fn.py` 的 adrp+add 字符串解析永远命中不了。
- `.exit.text` 的符号 `st_value` 也是 0，`func_at()` 若不按节过滤，会把 `.text` 前 `0x388` 字节全标成 `cleanup_module`。
- 指针表项解析必须 `S + A`（符号值 + addend），不能只用 addend。

为此新增可复用工具 **`tools/wlan_wext_scan.py`**（节感知、全重定位、指针表、注解反汇编）。

### 1.2 复算命令

```powershell
# 32 个 handler 指针（ioctl 0x8BE0+i）
python tools/wlan_wext_scan.py --handlers

# 223 条 {cmd,set_args,get_args,name} 父子表（原工具，仍可用）
python tools/wlan_wext_table.py

# 0x8BE0 的 ~100 项子命令分派表（.rodata+0x6280，101 项）
python tools/wlan_wext_scan.py --table .rodata+0x6280+101

# 单函数带注解反汇编 / 只看重定位 / 看调用者
python tools/wlan_wext_scan.py --fn iw_set_packet_filter_params
python tools/wlan_wext_scan.py --relocs iw_set_two_ints_getnone
python tools/wlan_wext_scan.py --callers mem_alloc_copy_from_user_helper
```

内核侧语义以 `HANDOFF` 提供的内核树 `.build/vendor_kernel_full/net/wireless/wext-priv.c` 为准（GPL 通用代码，非厂商驱动；驱动结论一律用 .ko 反汇编，不用源码）。

### 1.3 内核侧门（`wext-priv.c`，行号为该树）

`get_priv_descr_and_size()`（:105-139）：

```
extra_size = (set_args & 0x07FF) * type_size;   // IW_PRIV_SIZE_MASK=0x07FF, FIXED=0x0800
if (SET) offset = (descr->name[0]=='\0') ? 4 : 0;   // 空名父项=子命令，预留 1 个 int
if (FIXED && extra_size + offset <= IFNAMSIZ(16)) extra_size = 0;   // → 走 &iwr->u
```

`ioctl_private_iw_point()`（:141-190）：

```
if (SET) { if (!ptr && len) -EFAULT;  if (len > (set_args & 0x07FF)) return -E2BIG; }
extra = kzalloc(extra_size);
if (SET && len) copy_from_user(extra, ptr, extra_size);   // 注意：拷 extra_size，不是 len
handler(dev, info, (union iwreq_data*)iwp, extra);
// GET: copy_to_user(ptr, extra, min(iwp->length, max)*type_size)
```

**结论：对 SET，`length` 的硬上限永远是声明尺寸（≤2047），且 `extra` 总是恰好 `extra_size` 字节的 kzalloc 缓冲。** 因此"驱动按用户 length 重新分配再强转固定结构"才是唯一可出问题的地方——本机只有 2 个这样的点。

### 1.4 关键 helper

| 地址 | 函数 | 语义 |
|---|---|---|
| `0x085680` | `hdd_priv_get_data` | 原生：`memcpy(dst, wrqu, 0x10)` → `{ptr@0, len@+8, flags@+0xa}`；compat：`is_compat_task()`(`tbnz w8,#0x16` = TIF_32BIT) 时按 32 位 `compat_iw_point` 取 `{ptr@0, len@+4, flags@+6}`。**无长度校验，只取指针+长度。** 本 .ko 中已被内联，`--callers` 为 0。 |
| `0x085520` | `mem_alloc_copy_from_user_helper(ptr, len)` | `cmp x1,#0x1000; b.ls` → **`len > 4096` 直接返回 NULL**；否则 `__qdf_mem_malloc(len+1)`、`copy_from_user(extra,ptr,len)`、`strb wzr,[buf,len]` 补 NUL。**只保证 ≤4096，不保证 ≥sizeof(struct)。** |
| `0x1b6aa0` | `__qdf_mem_malloc` | `__kmalloc(size, flags)`，flags 含 `__GFP_ZERO(0x8000)`（`0x2088020`/`0x24080c0`），>4096 走 `wcnss_prealloc_get`+`memset` ⇒ **分配即清零**。 |

---

## §2 逐 handler 审计

格式：入口 → 用户参数来源 → 长度门 → 拷贝 → 结构体/字段 → 下游 → 错误出口。

### 2.1 `0x8BE0 iw_setint_getnone`（`0x088d28`，576B）——**有界**

- **参数来源**：`set_args=0x4801` = INT|FIXED|1，`name==''` ⇒ `extra_size = 4+4 = 8 ≤16` ⇒ **`extra_size=0`，走 `&iwr->u`，无用户指针**。
- **读取**：`0x088d8c ldp w22,w24,[x20]`（x20=x3=extra）→ `sub_cmd = *(u32*)(extra+0)`（即 `wrq->u.mode`）、`arg = *(u32*)(extra+4)`。**共 8B / 16B**。
- **索引门**：`0x088e54 cmp w22,#0x64; b.hi 0x8eac` ⇒ `sub_cmd` **必须 ≤0x64(100)**（`b.hi` 为无符号，负数也拒绝）。
- **分派**：`0x088e6c ldr x8,[table + x22*8]`，表在 **`.rodata+0x6280`，101 项**（已全量转储：0..100，`[2]/[8]/[54]/[60]/[61]/[73]/[90]/[97]/[98]` 为 NULL）。空项 `cbz x8` → `-EINVAL`。
- **下游**：`add x0,x21,#0x900`（adapter）+ `w1 = arg`，`blr x8`。即每个子命令 handler 形如 `f(adapter, value)`。**value 是纯标量，未参与任何内存索引**（抽查 `hdd_we_set_ch_width`/`hdd_we_set_tx_chainmask` 等均为 `wma_cli_set_command` 常量下发布）。
- **判定**：结构上不可能越界读（≤8B）、不可能越界写。**有界。**

### 2.2 `0x8BE7 iw_hdd_set_var_ints_getnone`（`0x08b5f0`，576B）——**有界**

- **参数来源**：内联 `hdd_priv_get_data`：`0x08b648 cbz x22`→`-EINVAL`；`0x08b658 memcpy(sp+8, wrqu, 0x10)`；compat 分支 `0x08b758 ldp w21,w8,[x22]`。
- **长度门（关键）**：`0x08b670 ldrh w8,[sp,#0x10]`（len）→ `0x08b674 mov w9,#0xb` → `0x08b680 cmp w8,#0xb` → `0x08b684 csel w8,w8,w9,lo` → `0x08b688 lsl w22,w8,#2`。即 **`n = min(len, 11)`，拷贝 `4*n ≤ 44` 字节**。
- **拷贝**：`0x08b6b4 add x0,sp,#0x18; 0x08b6c0 __arch_copy_from_user` → 目标为**栈上 44B 缓冲**（`sp+0x18..0x43`），另有 `0x08b7f0 memset` 补齐尾部。
- **下游**：`0x08b704 bl 0x876e8`（`__iw_set_var_ints_getnone`，静态局部函数，`(dev, info, priv_data, ints[11])`）。
- **判定**：count 显式 clamp 到 11，栈缓冲 44B 与上限一致。**有界**（`len=0` 时 `n=0`，也只拷 0 字节）。

### 2.3 `0x8BF2 iw_set_host_offload`（`0x08c280`，1020B）——**有界**

- **参数来源**：`set_args=0x1018` = BYTE|24（非 FIXED）⇒ core `extra_size=24`，`len≤24`，`extra` 为 24B kzalloc；handler 直接用 `x22=x3=extra`，**无 `hdd_priv_get_data`、无用户指针**。
- **字段读取**：`0x08c3b8 ldrb [x22]`（type）、`0x08c3ec ldrb [x22,#1]`（enable）、`0x08c4fc/0x8c564 add x5,x22,#2`（IP，16B/max）、`0x08c59c add x1,x22,#2` + `0x8c5a4 mov w2,#0x10`（16B→栈）、`0x08c5a8 ldrh [x22],#0x12`（u16@0）、`0x08c5b4 mov x1,x22`（=extra+0x12）+ `0x8c5bc mov w2,#6`（MAC 6B）。
- **最大偏移**：`0x12 + 6 - 1 = 0x17 = 23` ⇒ **恰好覆盖 24B，零越界**。
- **下游**：`sme_set_host_offload(ctx, device_mode, &stack_struct)`（`0x08c5d0`），栈结构 `qdf_mem_set(sp+8, 0x20, 0)` 先清零。
- **判定**：声明尺寸 = 读取尺寸 = 24。**有界。**

### 2.4 `0x8BF6 iw_set_keepalive_params`（`0x08cd70`，1000B）——**有界**

- **参数来源**：`x25=wrqu`、`x21=x3=extra`（core `extra_size=32`，BYTE|32）。
- **长度门（精确）**：`0x08cee8 ldrh w5,[x25,#8]` → `0x08ceec cmp w5,#0x20` → `0x08cef0 b.ne 0x8cf30`（"Invalid length %d" → `-EINVAL`）。**必须 `length == 32`。**
- **值校验**：`0x08cef4 ldr w5,[x21,#4]; 0x08cef8 cmp w5,#0x3e9; b.lo`（timePeriod < 1001）。
- **字段**：`[x21]`(u8 type)、`[x21,#4]`(period)、`[x21,#8..0xb]`(host IP)、`[x21,#0xc..0xf]`(dest IP)、`[x21,#0x10]`（MAC 6B，`%pM`）⇒ 最大 0x15 < 32。
- **下游**：`sme_set_keep_alive(ctx, device_mode, extra)`（`0x08d0f4`）。
- **判定**：精确 32B 门 + 读 ≤0x15。**有界。**

### 2.5 `0x8BF7 iw_set_packet_filter_params`（`0x08d158`，1152B）——**有界**（本面最值得注意的"看似缺陷实为有校验"点）

- **权限**：`0x08d1c0 bl capable`，`w0=0xc`(`CAP_NET_ADMIN`)；`0x08d1c4 tbz w0,#0 → -1`。**handler 自带 CAP_NET_ADMIN 复核**（与 wext-core 的 `wext_permission_check` 双重）。
- **参数来源**：内联 `hdd_priv_get_data`：`0x08d30c cbz x23`、`0x08d31c memcpy(sp+8,x23,0x10)`；compat `0x08d360`。取 `ptr=[sp+8]`、`len=[sp+0x10]`。
- **门 1**：`0x08d36c ldrh w6,[sp,#0x10]`；`0x08d370 cbz x5`（ptr）或 `0x08d374 cbz w6`（len）→ `-EINVAL`。
- **门 2**：`0x08d378 ldr w5,[x21,#0x9a8]` = 连接态；必须非 0 才继续（否则 "Packet filter not supported in this mode/disconnected state"）。
- **拷贝**：`0x08d428 ldr x0,[sp,#8]; 0x08d42c ldrh w1,[sp,#0x10]; 0x08d430 bl mem_alloc_copy_from_user_helper` ⇒ `malloc(len+1)`，`copy_from_user(len)`。失败 `-ENOMEM`（`0x8d4c4 mov w25,#-0xc`）。
- **门 3（长度下界）**：`0x08d438 ldrh w8,[sp,#0x10]`；`0x08d440 cmp x8,#2`；`0x08d444 b.hi 0x8d4cc`。**`len <= 2` 直接报 "Less than minimum number of arguments needed" → `-EINVAL`；即 `len >= 3`。**
- **门 4（长度精确式）**：`0x08d4cc ldrb w9,[x23,#2]`（`num_params`）；`0x08d4d4 add x9,x9,x9,lsl#2`（×5）；`0x08d4d8 bfi x10,x9,#2,#0xb`（`x10 = 3 + 20*n`）；`0x08d4dc cmp x10,x8; 0x08d4e0 b.ne` → "Arguments do not match…" `-EINVAL`。**即 `len == 3 + 20*num_params`。**
- **字段**：`[x23]`(action)、`[x23,#1]`(id)、`[x23,#2]`(num) —— 全部在 `len>=3` 内。
- **下游**：`wlan_hdd_set_filter(ctx, buf, device_mode)`（`0x8d59c`），随后 `__qdf_mem_free`。下游按 `3+20n` 解释，与校验一致。
- **判定**：`len>=3` 保证 `buf[2]` 可读；精确式保证不超出 `3+20n`。**有界。**

### 2.6 `0x8BF8 iw_set_pno`（`0x08d5d8`，2916B）——**有界**（文本协议解析）

- **参数来源**：`x23=wrqu`、`x25=x3=extra`（core `extra_size=2047`，CHAR|2047）；`0x08d76c ldrh w27,[x23,#8]` = len。
- **拷贝**：`0x08d77c add x26,x27,#1` → `0x08d784 __qdf_mem_malloc(len+1)`（**清零**）→ `0x08d79c qdf_mem_copy(dst, extra, len)`。**无固定结构体强转**；此后全部是 `sscanf("%hhu %n"/"%u %n"/"%d %n"/" %u %u %hhu %n")` 文本解析。
- **解析内建边界**：
  - SSID 个数：`0x08d9ac sub w8,w5,#1; 0x08d9b0 cmp w8,#0x10; b.lo` ⇒ **`1..16`**；越界 "Network count %d invalid"。
  - 每 SSID 记录 stride `0x1bc`：`0x08da30 mov w28,#0x1bc; 0x08da54 madd x27,x26,x28,x23`。
  - 信道个数：`0x08db38 ldrb w8,[x26]; 0x08db3c cmp w8,#0x62; b.hs` ⇒ **`< 98`**；写 `str w0,[x27,x23,lsl#2]`，循环 `0x08db7c cmp x23,x9; b.hs`。
  - 网络类型：`0x08dc04 cmp w5,#3; b.hs`；某枚举：`0x08da7c cmp w8,#0x20; b.hs`。
- **目标缓冲**：全局 `__iw_set_pno.req` @ `.bss+0x1010`，**size `0x1c88`**。最坏写偏移 `0x1bc*15 + 0x70 + 96*4 + 3 = 0x1bf7 < 0x1c88` ⇒ **不溢出全局对象**（但 record 间存在 stride 0x1bc 与字段 +0x1f4 的结构性重叠，属功能问题，非内存安全，见 §4）。
- **判定**：长度维度无固定结构体越界；计数维度有显式校验且最坏偏移仍在对象内。**有界**。

### 2.7 `0x8BFC iw_set_two_ints_getnone`（`0x08e370`，1996B）——**有界**（任务点名的 `setMonChan` 不是越界）

- **参数来源**：`set_args=0x4802` = INT|FIXED|2，`name==''` ⇒ `8+4=12 ≤16` ⇒ **`extra_size=0`，union 路径**。`0x08e3f0 ldr w25,[x20]` = `sub_cmd = u.mode`。
- **索引门**：`0x08e4f0 sub w8,w25,#1; 0x08e4f4 cmp w8,#0x16; 0x08e4f8 b.hi` ⇒ **`sub_cmd ∈ [1,0x17]`（23）**；`0x08e518 ldrb w11,[.rodata+0x4c38 + w8]; 0x08e51c add x10,x10,w11,lsl#2; br x10`（23 字节跳表，已全量解出）。
- **读取**：`ldp w5,w6,[x20,#4]`、`ldp w8,w9,[x20,#4]`、`ldr/ldrh [x20,#4]`、`[x20,#8]` ⇒ **最大 12B / 16B union**。
- **`setMonChan = sub_cmd 23`**：`0x08e7dc ldr w1,[x20,#4]; 0x08e7e0 cmp w1,#0x101; 0x08e7e4 b.lt 0x8e854`：
  - `arg1 < 0x101`：`0x08e854 wlan_reg_legacy_chan_to_freq(ctx, arg1)` → `w1=freq`；
  - 否则 `w1 = arg1` 直接当频率；
  - 再 `0x08e7e8 ldr w2,[x20,#8]`，`0x08e868 wlan_hdd_set_mon_chan(adapter, w1, w2)`。
  - **两个 int 都只是"值"，不参与数组索引、不参与长度**。任务假设的"未校验索引"在此不成立。
- **判定**：**有界**；`setMonChan` 的残余风险仅为下游 `wlan_hdd_set_mon_chan` 的**取值域**校验（未核，非内存长度问题）。

### 2.8 `0x8BFA iw_set_dynamic_mcbc_filter`（`0x08e328`，68B）——**无功能**

```
0x08e32c mov x29,sp
0x08e330..0x8e358  qdf_trace_msg(... "iw_set_dynamic_mcbc_filter" ...)
0x08e360 mov w0,#-0x16        ; -EINVAL
0x08e364 ldp x29,x30,[sp],#0x10
0x08e368 ret
```
- 完全未读取 `wrqu`/`extra`，**无条件 `-EINVAL`**。表项 `set_args=get_args=0`。**不构成攻击面。**

### 2.9 其余父项（未逐指令核完）

只确证了内核侧分配尺寸与路径（`extra_size`），handler 体内字段偏移未核：

| ioctl | handler | core `extra_size` / 路径 | 说明 |
|---|---|---|---|
| 0x8BE1 | `iw_setnone_getint` | GET, FIXED 4 ≤16 → **union 16B** | 只回传，取 `extra` |
| 0x8BE3 | `iw_setchar_getnone` | CHAR 512 → **512B kzalloc** | **同时调用 `mem_alloc_copy_from_user_helper`（`+0x1fc`）** |
| 0x8BE4 | `iw_set_three_ints_getnone` | INT FIXED 3 =12，空名 +4 =16 ≤16 → **union 16B** | 读 3 个 int |
| 0x8BE5 | `iw_get_char_setnone` | GET CHAR 2047 → 2047B | `copy_to_user` 长度由 `min(user_len,2047)` 决定 |
| 0x8BE6 | `iw_setnone_getnone` | 0/0 → **union 16B** | 无参 |
| 0x8BE8 | `hdd_fips_test` | CHAR 2047（set/get 同） | 名字 `fips_test` |
| 0x8BE9 | `iw_add_tspec` | INT FIXED 19 =76 → **76B** | 非空名，无子命令偏移 |
| 0x8BEB | `iw_del_tspec` | INT FIXED 1 =4（非空名）→ **union 16B** | 读 1 个 int |
| 0x8BED | `iw_get_tspec` | GET INT FIXED 1 =4 → **union 16B** | — |
| 0x8BEF | `iw_setnone_get_threeint` | GET INT FIXED 3 =12 → **union 16B** | 回传 3 个 int |
| 0x8BF4 | `iw_set_fties` | CHAR 384 → **384B** | — |
| 0x8BF5 | `iw_get_statistics` | GET CHAR 2047 → 2047B | `copy_to_user` 长度 `min(user_len,2047)` |
| 0x8BF9 | `iw_set_band_config` | INT FIXED 1 =4（非空名）→ **union 16B** | 已见 `capable(0xc)` 复核（`0x8e1dc`） |
| 0x8BFE | `iw_set_dot11p_channel_sched` | BYTE 208 → **208B** | 208B 结构 + 可能子命令，**优先复核** |
| 0x8BFF | `iw_get_linkspeed` | SET CHAR 18 → **18B** | 名字 `getLinkSpeed`，`set_args=0x2012` |

---

## §3 具体反例

**本轮未发现可确认的"长度未校验 → 固定结构体越界"反例。**

以下是*已排除*的三个候选，写明排除依据，供主代理复核：

1. **`iw_set_packet_filter_params`（0x8BF7）"先用用户 length 分配再强转"**
   - 看似违反不变量：`mem_alloc_copy_from_user_helper(ptr, len)` 分配 `len+1`，随后读 `buf[0..2]` 并按 20B/参数解释。
   - 实际不变量成立：`0x8d440 cmp x8,#2 / b.hi` 强制 `len>=3`；`0x8d4b8 bfi x10,x9,#2,#0xb` + `0x8d4dc cmp x10,x8 / b.ne` 强制 `len == 3+20*buf[2]`。
   - 边界：`buf[2]` 是 u8，理论上可到 255 ⇒ `3+20*255=5103`，但 core 已把 `len` 锁在 `≤103`（`set_args=0x1067`），到达此处必 `buf[2] ≤ 5`。

2. **`iw_set_two_ints_getnone` 的 `setMonChan`（子命令 23）"未校验索引"**
   - 实际不变量成立：`0x8e4f4 cmp w8,#0x16 / b.hi` 把 `sub_cmd` 锁在 `[1,23]`；跳表 23 项；只读 12B union。
   - `setMonChan` 的 `arg1/arg2` 只作频率/带宽标量传入 `wlan_hdd_set_mon_chan`，**不做内存索引**。

3. **`iw_setint_getnone`（0x8BE0）"~200 子命令大 switch"**
   - 实际不变量成立：`0x8e54 cmp w22,#0x64 / b.hi` 锁 `sub_cmd ≤100`；分派表 `.rodata+0x6280` 恰 101 项，NULL 项有 `cbz` 保护；每个子 handler 签名 `f(adapter, u32)`，第二参不参与寻址。

> 结论口径：以上属"静态上界成立"，不等于"下游语义安全"。下游
> `wlan_hdd_set_filter` / `wlan_hdd_set_mon_chan` / `wma_cli_set_command` / `sme_set_*` 的取值域与二次解释未在本轮展开（见 §4）。

---

## §4 未覆盖 / 未决

按复核优先级：

1. **`iw_setchar_getnone`（0x8BE3，`0x089d98`）— 最高优先级。** 它是本面**唯一未核的 `mem_alloc_copy_from_user_helper` 调用者**（调用点 `+0x1fc`）。若它把 `len+1` 的缓冲强转成固定 `struct`（qcacld 经典形态），则存在 `len < sizeof(struct)` 的内核堆越界读。**必须逐指令核 `0x8be3` 内 `len` 的比较与强转字段偏移。**
2. **`iw_set_dot11p_channel_sched`（0x8BFE，208B）与 `iw_add_tspec`（0x8BE9，76B）**：均为"定长大结构 + 内部子命令/数组计数"形态，最可能出现未校验的元素数（如 tspec 的 `num_tspec`）。未核。
3. **GET 侧回传长度**：`iw_get_statistics`(0x8BF5)、`iw_get_char_setnone`(0x8BE5)、`iw_setnone_get_threeint`(0x8BEF)、`iw_get_linkspeed`(0x8BFF)。core 用 `adjust_priv_size()` = `min(iwp->length, max)*type_size` 做 `copy_to_user`，**长度与用户 `length` 同源但被 max 夹住**；需确认 handler 是否把 `iwp->length` 写得比 `extra_size` 大（会被 max 夹住，安全）或写小于实际填充（信息泄露方向）。
4. **`hdd_fips_test`（0x8BE8）**：`set_args=get_args=0x17FF` 同源，既是 SET 又是 GET，语义可疑（IOCTL 号 0x8BE8 为偶数=GET 方向，但表项给了 set_args），未核。
5. **PNO record 布局**：`iw_set_pno` 的 stride `0x1bc` 与字段 `+0x1f4`（rssi）/信道数组 `+0x70..0x1f3` 存在 record 间重叠；最坏写仍在 `__iw_set_pno.req`(0x1c88) 内，**非内存安全**，但需功能侧确认是否掩盖了别的问题。
6. **指针可达性未做数据流闭合**：本文默认"`/odm/bin/iwpriv` 能按 name 命中表项即可达"。`hdd_check_wext_control` 对部分 ioctl 有运行时开关（`0x8be6`/`0x20f0` 状态机），本轮未枚举哪些 ioctl 被默认禁用；若被禁用则实际不可达，只会让结论更保守。
7. **未审计 `wext_handle_ioctl` 本体的权限/长度处理**：以主代理已确证的 `wext_permission_check()`(`CAP_NET_ADMIN`) 为前提；本 .ko 内另有 `capable(0xc)` 复核（0x8BF7、0x8BF9），说明厂商做了二次加固。

---

## §5 与项目四层判定的关系

- **不改变 NO-GO。** 本面即便出现"长度未校验"，其影响域也只是**受限 UID 0 域内（`oplus_wifi_service`，已持 `net_admin`）对 qcacld 驱动状态的操控**：`mac80211`/`cfg80211` 之外的一条私有 ioctl，用户态入口被 SELinux 限定在 `oplus_wifi_service` 的 `execute` 代理链上，shell 无 `net_admin` 无法直达。
- 本面的真实价值是**"受限 UID 0 域内的驱动状态影响"**：
  - 若 `iw_setchar_getnone` 等确认越界读，可形成**内核堆信息泄露**（经 GET 回传或日志），把"UID 0 代理域"提升到"内核指针/堆布局知情"，为后续 GhostLock 类原语提供信息面；
  - 若存在越界写，才是"代理域 → 内核"的实质跨越，但本轮**未发现**。
- 因此本报告的定位是：**缩小**而非扩大攻击面——把 23 个可达父项里 7 个判为有界、1 个判为死代码，把复核火力集中到 `iw_setchar_getnone` / `iw_set_dot11p_channel_sched` / `iw_add_tspec` 三个点。

---

## 附：产物清单

| 路径 | 内容 |
|---|---|
| `WLAN_WEXT_HANDLER_AUDIT.md` | 本文件 |
| `artifacts_adb/r1_wlan_reach/wext_audit.csv` | 23 个父项逐行判定 |
| `artifacts_adb/r1_wlan_reach/_wext_dump_*.txt` | 已核 handler 的带注解反汇编原文（twoints / hostoffload / keepalive / pktfilter / pno） |
| `tools/wlan_wext_scan.py` | 节感知全重定位扫描器（新增） |
| `tools/wlan_wext_table.py` | 原 32+223 表复算工具（沿用，注意其 handler 名解析有 addend-only 缺陷） |
