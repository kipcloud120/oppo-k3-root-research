# WLAN WEXT 私有 ioctl Handler 静态审计（第二轮 · 收口）

> 对象：`vendor_ko/qca_cld3_wlan.ko`（ET_REL/AArch64，SHA-256 `f45c1c1cf63281ee5e64c8b6149c42d5e1aaa91142913073668abf1901674d00`，内核 `4.9.227-perf+`，OPPO K3 PCGM00 / SDM710 / Android 11）。
> 方法：**纯离线**反汇编（capstone 5.0.7）+ 节感知全重定位复算；未连接设备、未动态运行、未联网。
> 前提（主代理已确证，本文直接采用）：`oplus_wifi_service`(uid 0, net_admin) → `/vendor/bin/sh -c "/odm/bin/iwpriv wlan0 <name> <args>"` → `ioctl(0x8BE0..0x8BFF)` → `wext_handle_ioctl`/`ioctl_private_call` → `we_private[i]`。
> 本文只回答一个问题：**用户可控的 `length`/指针/整数值能否让某个 handler 越界读或越界写。** 符号存在、厂商源码没写检查，都不单独构成结论。

---

## §0 结论摘要

### 0.1 逐项判定（23 个可达父项，全部收口）

**本轮把上一轮剩下的 15 个"未决"全部核完：21 个判定为有界，2 个判定为无功能，0 个未决。**

| ioctl | handler（符号@地址/尺寸） | 方向 | core `extra` | 长度门（指令地址） | 判定 | 证据级别 |
|---|---|---|---|---|---|---|
| 0x8BE0 | `iw_setint_getnone` @0x88d28/576 | SET | 0 → 16B union | `sub_cmd<=0x64` @0x88e54；子命令只收 (adapter,u32) | **有界** | 指令级 |
| 0x8BE1 | `iw_setnone_getint` @0x88f68/3628 | **GET** | 0 → 16B union | `sub_cmd-1<=0x3c` @0x89100 ⇒ `sub_cmd∈[1,0x3d]`（61 路，表 `.rodata+0x4b02`）；全部访问仅 `[extra+0]` 4B | **有界** | 指令级 |
| 0x8BE3 | `iw_setchar_getnone` @0x89d98/1320 | **GET** | 0 → 16B union（**无 core 拷贝**） | `len>=1`@0x89f8c + helper `len<=4096`@0x85534 | **有界** | 指令级 |
| 0x8BE4 | `iw_set_three_ints_getnone` @0x87148/1228 | SET | 0 → 16B union | 读 `[extra+0x4..0xf]` 恰好 16B；`sub_cmd 1..0x15` @0x87304 | **有界** | 指令级 |
| 0x8BE5 | `iw_get_char_setnone` @0x8a2c0/4068 | **GET** | 2047 | `sub_cmd(flags) 1..17`@0x8a3f8；输出全部显式传 `0x7ff`/`0x400` | **有界** | 指令级 |
| 0x8BE6 | `iw_setnone_getnone` @0x8b2a8/836 | SET | 0 → 16B union | **完全不访问 extra**；`sub_cmd(u16@wrqu+0xa) 8..0x13`@0x8b3f4 | **有界** | 指令级 |
| 0x8BE7 | `iw_hdd_set_var_ints_getnone` @0x8b5f0/576 | **GET** | 0 → 16B union | `n=min(len,11)`@0x8b684，拷 `4n<=44` 到 44B 栈 | **有界** | 指令级 |
| 0x8BE8 | `hdd_fips_test` @0x9fcc8/1148 | SET | 2047 | `len>=0x30`@0x9fd88 + `key_len∈{16,32}` + `data_len==len-0x30`@0x9fde4 | **有界** | 指令级 |
| 0x8BE9 | `iw_add_tspec` @0x8b830/1008 | **GET** | 0 → 16B union | `len==0x13`@0x8ba54 + `access_ok(ptr,76)`@0x8ba74 | **有界** | 指令级 |
| 0x8BEB | `iw_del_tspec` @0x8bc20/544 | **GET** | 0 → 16B union | 读 4B tsid / 写 4B status | **有界** | 指令级 |
| 0x8BED | `iw_get_tspec` @0x8be40/524 | **GET** | 0 → 16B union | 读 4B / 写 4B | **有界** | 指令级 |
| 0x8BEF | `iw_setnone_get_threeint` @0x8c050/560 | **GET** | 0 → 16B union | 读 4B；下游只写 `extra+0/4/8`（12B） | **有界** | 指令级 |
| 0x8BF2 | `iw_set_host_offload` @0x8c280/1020 | SET | 24 | 读 0..0x17，恰好 24B | **有界**（r1 已核） | 指令级 |
| 0x8BF4 | `iw_set_fties` @0x8c680/732 | SET | 384 | core `len<=384`；`len!=0`@0x8c7fc；以 `(extra,len)` 传下游 | **有界** | 指令级 |
| 0x8BF5 | `iw_get_statistics` @0x8c960/1040 | **GET** | 2047 | 固定 TLV 写 174B，回填 `iwp->length=0xae`@0x8cd10 | **有界** | 指令级 |
| 0x8BF6 | `iw_set_keepalive_params` @0x8cd70/1000 | SET | 32 | `len==0x20` 精确门 | **有界**（r1 已核） | 指令级 |
| 0x8BF7 | `iw_set_packet_filter_params` @0x8d158/1152 | **GET** | 0 → 16B union | `len>=3`@0x8d440 且 `len==3+20*buf[2]`@0x8d4dc | **有界**（r1 结论对，理由需更正） | 指令级 |
| 0x8BF8 | `iw_set_pno` @0x8d5d8/2916 | SET | 2047 | `malloc(len+1)` 文本解析，计数内建校验 | **有界**（r1 已核） | 指令级 |
| 0x8BF9 | `iw_set_band_config` @0x8e140/484 | **GET** | 0 → 16B union | `capable(0xc)`@0x8e1dc；读 `extra+0` 4B | **有界** | 指令级 |
| 0x8BFA | `iw_set_dynamic_mcbc_filter` @0x8e328/68 | SET | 0 | 无读取，恒 `-EINVAL`@0x8e360 | **无功能**（r1 已判） | 指令级 |
| 0x8BFC | `iw_set_two_ints_getnone` @0x8e370/1996 | SET | 0 → 16B union | `sub_cmd 1..0x17` 跳表；只读 12B | **有界**（r1 已核） | 指令级 |
| 0x8BFE | `iw_set_dot11p_channel_sched` @0x8eb40/**8** | SET | 208 | **空桩**：`mov w0,wzr; ret` | **无功能**（r1 误标"高优先未决"） | 指令级 |
| 0x8BFF | `iw_get_linkspeed` @0x8eb48/600 | **GET** | **5** | `snprintf(extra,5)`@0x8ecf8 + 回填 `iwp->length=5`@0x8ecf4 | **有界**（r1 把尺寸记成 18，错） | 指令级 |

**统计：有界 21 / 无功能 2 / 未决 0**（r1：有界 7 / 无功能 1 / 未决 15）。

### 0.2 三个推翻或更正 r1 的结论（本轮最重要的产出）

**(1) r1 没有应用 ioctl 号的奇偶方向，导致 12 个父项的"core 分配尺寸 / 长度门"记错 —— 这直接改变了"长度门在哪里"的分析。**

`include/uapi/linux/wireless.h:353`：`#define IW_IS_SET(cmd) (!((cmd) & 0x1))`，即**奇数是 GET、偶数是 SET**。`wext-priv.c:93 get_priv_descr_and_size()` 与 `:146/:160/:171 ioctl_private_iw_point()` 全部按 `cmd` 的奇偶分支，**与表里 `set_args`/`get_args` 的声明无关**。

按 `we_private_args` 实测（`python tools/wlan_wext_subcmd.py --args`）：

* **11 个偶数（SET）**：0x8BE0、0x8BE4、0x8BE6、0x8BE8、0x8BF2、0x8BF4、0x8BF6、0x8BF8、0x8BFA、0x8BFC、0x8BFE。
* **12 个奇数（GET）**：0x8BE1、0x8BE3、0x8BE5、0x8BE7、0x8BE9、0x8BEB、0x8BED、0x8BEF、0x8BF5、0x8BF7、0x8BF9、0x8BFF。

后果：

* 对 12 个奇数项，**core 的 `iwp->length > (set_args & 0x7FF)` → `-E2BIG` 这一句根本不执行**；`kzalloc(extra_size)`/`copy_from_user` 也只在 `extra_size != 0` 时才走 `ioctl_private_iw_point()`（`wext-priv.c:197`）。所以在奇数项上"core 把长度夹在声明尺寸内"是**不成立**的。
* 例：r1 认为 0x8BE3 的 `len` 被 core 夹在 512（`set_args=0x2200`），0x8BF7 被夹在 103（`set_args=0x1067`）。**实际都不存在**：0x8BE3 的 `extra_size` 是 0（`get_args=0`→`get_priv_size(0)==0`），handler 自己从 `iwr->u.data` 里取 `pointer/length`；真正的长度门只剩 `mem_alloc_copy_from_user_helper` 的 **4096** 上限。结论（有界）不变，但**余量放大 8 倍，而且安全性完全落在 helper 的 NUL 补字节与下游字符串解析器上**（见 §2.1）。
* 例：0x8BFF 的 `core extra_size` 是 **5**（`get_args=0x2005`），不是 r1 写的 18（18 是 `set_args=0x2012`，对奇数 cmd 永远用不到）。这个差别是关键：handler 拿到的是 **5 字节** kzalloc，而不是 18 字节——见 §2.7。
* 例：0x8BE9 `iw_add_tspec` 的 `76B` 不是 core 分配的（`get_args=0x4801,FIXED`→`extra_size=0`），而是 handler 在**自己的栈上**按 `len==19` 拷 76B。

**(2) 0x8BFE `iw_set_dot11p_channel_sched` 是 8 字节空桩，不是"208B 结构未核"。**

```
0x08eb40  mov w0, wzr      ; return 0
0x08eb44  ret
```
下一项 0x8BFF `iw_get_linkspeed` 从 0x8eb48 开始，二者紧邻 ⇒ 本函数尺寸恰为 8。**它不读 `wrqu`、不读 `extra`，无条件返回 0。** 表里声明的 208B（`set_args=0x10D0`）只被 core 白白 kzalloc+copy 一次，无人消费。判定：**无功能**，从"高优先复核"名单里移除。

**(3) `iw_get_linkspeed`（0x8BFF）的堆缓冲只有 5 字节，且写入零冗余。**

```
0x08eccc  bl   wlan_hdd_get_link_speed(adapter, &u32@x29-0xc)
0x08ecd0  cbnz w0, <err>
0x08ecf4  strh w1, [x22, #8]        ; w1=5 → iwp->length = 5
0x08ecf8  snprintf(x21 /*extra*/, 5, "%u", speed)
0x08ecfc  cmp  w0, #5
0x08ed00  b.lo <ok>
0x08ed28  mov  w25, #-5             ; -EIO
```
core 的 `adjust_priv_size(0x2005, iwp) = min(iwp->length=5, max=5) × 1 = 5`，`copy_to_user(ptr, extra, 5)` —— 与 `snprintf` 的 `size=5`、`kzalloc(5)` 三者严格相等。**有界，但零冗余**：若将来 `size` 改成 6 就是 1 字节内核堆溢出。

### 0.3 0x8BE0 子命令面（101 项）分类计数

`iw_setint_getnone` 的 `sub_cmd = *(u32*)extra`，门 `cmp w22,#0x64 / b.hi`（0x88e54）→ 跳 `.rodata+0x6280`，**101 项，全部解开**（`python tools/wlan_wext_subcmd.py --subcmd`）：

| 类别 | 数量 | 说明 |
|---|---|---|
| NULL 表项（父项 `cbz x8` → `-EINVAL`） | **11** | id 0,2,8,44,54,60,61,73,90,97,98 |
| 有界 —— `value` 作 `wma_cli_set_command(vdev,cmd,value)` 标量 | **51** | 见 CSV |
| 有界 —— `value` 作第 4 参传给 `hdd_we_packet_power_save`（→ 仍进 `wma_cli_set_command`） | **10** | id 45–53、83（`hdd_we_pps_*`，44B 叶） |
| 有界 —— `value` 作**跳表索引**，三处都带 `b.hi` 上界 | **3** | id 3 / 85 / 86，见下表 |
| 有界(本层) —— 只收 `(adapter, u32 value)`，无用户指针/长度，下游取值域未展开 | **26** | 见 CSV |
| 合计 | **101** | |

三处"`value` 当索引"逐条核过，**全部有上界校验**：

| sub_id | 目标 | 门（指令） | 跳表 | 判定 |
|---|---|---|---|---|
| 3 | `hdd_we_set_power` @0x8ee60 | `sub w8,w1,#1; cmp w8,#3; b.hi` @0x8ee80-84 → `-EINVAL` | `.rodata+0x4c5b`，4×u8 | 有界 |
| 85 | `hdd_wlan_dump_stats` @0x85b88 | `sub w8,w19,#2; cmp w8,#0x17; b.hi` @0x85bdc-0x85be4 | `.rodata+0x4a30`，24×u8 | 有界 |
| 86 | `hdd_we_clear_stats` @0x91da8 | `cmp w19,#9; b.hi` @0x91df8-0x91dfc | `.rodata+0x4c5f`，10×u8 | 有界 |

**结构性负结果（比逐条"未发现"更强）**：父项只把 **adapter 指针 (`dev+0x900`) 与一个 32 位标量 (`w1`)** 传给子 handler（`0x88e6c ldr x8,[x8,x22,lsl#3]` → `0x88e74 add x0,x21,#0x900` → `0x88e78 mov w1,w24` → `0x88e7c blr x8`）。**子 handler 拿不到任何用户缓冲区指针，也拿不到 length**，因此这 101 项在本层不可能出现"长度未校验的越界"。风险只可能转移到下游（`wma_cli_set_command`/`sme_*` 对 value 的取值域解释），这是 §4 的未决项，不是长度/内存问题。

### 0.4 与 r1 的差异一览

| 项 | r1 | r2（本轮） | 依据 |
|---|---|---|---|
| 0x8BE1 | 未决 | 有界 | 全部访问仅 `[extra+0]` 4B（`str/ldr wX,[x22]`），`sub_cmd-1<=0x3c`（61 路） |
| 0x8BE3 | **NOT_VERIFIED_HIGH** | 有界（但长度门=4096，非 512） | §2.1 |
| 0x8BE4 | 未决 | 有界 | 读 `[extra+0x4/0x8/0xc]`，最大到 +0xf |
| 0x8BE5 | 未决 | 有界 | 17 路子命令全部显式传 `0x7ff`；`length=strlen+1` |
| 0x8BE6 | 未决 | 有界 | 完全不读 extra |
| 0x8BE8 | 未决（"set=get 同源可疑"） | 有界 | `len>=0x30`+`data_len==len-0x30`；"set=get"无害（偶数=SET，`get_args` 永不被读） |
| 0x8BE9 | 未决（"76B 结构"） | 有界 | extra_size=0；76B 是 handler 自己按 `len==19` 拷到栈上 |
| 0x8BEB/0x8BED | 未决 | 有界 | 4B 进 4B 出 |
| 0x8BEF | 未决 | 有界 | 12B 写进 16B union |
| 0x8BF4 | 未决 | 有界 | core 384 门 + `(extra,len)` 直传 |
| 0x8BF5 | 未决 | 有界 | TLV 写 174B，回填 length=0xae |
| 0x8BF9 | 未决 | 有界 | 读 4B |
| 0x8BFE | **NOT_VERIFIED_HIGH** | **无功能** | 8 字节空桩 |
| 0x8BFF | 未决（extra=18） | 有界（extra=**5**） | 奇数=GET → `get_args=0x2005` |
| 0x8BF7 | 有界，理由记为"core 锁 len<=103" | 有界，理由改为"`len==3+20n` 自洽 + helper 4096" | 奇数=GET，core 不锁长度 |

---

## §1 方法与复算命令

### 1.1 只读事实（本机 .ko，指令级）

| 事实 | 值 | 来源 |
|---|---|---|
| `.ko` SHA-256 | `f45c1c1c…74d00` | `Get-FileHash` |
| `we_private` | `.rodata+0x4c70`，32 项 | `--handlers` |
| `we_private_args` | `.rodata+0x4d70`，223 × 0x18 | `--args` |
| 0x8BE0 子命令表 | `.rodata+0x6280`，101 项 | `--subcmd` |
| `mem_alloc_copy_from_user_helper` | 0x85520/0x15c；`0x85534 cmp x1,#(1<<12)` → `b.ls` 才继续 | 指令级 |
| `IW_IS_SET(cmd)` | `!((cmd)&1)` | 内核树 `include/uapi/linux/wireless.h:353`（AOSP/GPL 公共代码，非厂商驱动源码） |

`wext-priv.c`（`.build/vendor_kernel_full/`）关键行（**源码级**，仅用于解释内核侧门，不用于推断驱动行为）：
`:65 adjust_priv_size`（`num=min(iwp->length,max)`）、`:93 get_priv_descr_and_size`（`IW_IS_SET` 分支、`FIXED && size+offset<=16 → extra_size=0`）、`:150` SET 的 `-E2BIG`、`:155 kzalloc(extra_size)`、`:161 copy_from_user(extra,ptr,extra_size)`、`:171-179` GET 的 `adjust_priv_size` + `copy_to_user`、`:197` `extra_size==0` 时**绕开** `ioctl_private_iw_point`。

### 1.2 工具（本轮新增/修正）

| 工具 | 作用 |
|---|---|
| `tools/wlan_wext_scan.py`（沿用） | `--handlers` / `--fn` / `--relocs` / `--callers` / `--table` |
| **`tools/wlan_wext_subcmd.py`（新增）** | `--args`（算 core `extra_size`，含奇偶方向）、`--subcmd`（101 项 + 危险调用分类）、`--clusters`、`--at 0xADDR --len N`（绕开同名符号按地址反汇编）、`--audit-csv PATH`（直接生成本轮 CSV） |

**工具坑（必须记住）**：本 .ko 有**同名不同地址**的函数（`iw_get_char_setnone` 同时存在于 0x8a2c0/4068B 和 0x96270/392B）。任何"按名字查 size"的写法都会拿到错的那个（r1 的 `--handlers` 就把 0x8BE5 的尺寸印成 392）。新工具一律用 `k.funcs` 列表按地址求覆盖区间。

### 1.3 复算命令

```powershell
cd D:\AI_tools\AI_Workspace\WBK_OPK_RT_CRA

# 父项方向 + core extra_size（奇偶修正后的表）
python tools/wlan_wext_subcmd.py --args

# 101 项子命令表 + 分类计数
python tools/wlan_wext_subcmd.py --subcmd

# 任意地址反汇编（绕开同名符号；本例 = iw_get_char_setnone 真身）
python tools/wlan_wext_subcmd.py --at 0x8a2c0 --len 0xfe4

# 生成审计 CSV
python tools/wlan_wext_subcmd.py --audit-csv artifacts_adb/r1_wlan_reach/wext_audit_2.csv

# 单函数带注解反汇编 / 重定位
python tools/wlan_wext_scan.py --fn iw_setchar_getnone
python tools/wlan_wext_scan.py --fn mem_alloc_copy_from_user_helper
```

反汇编原文（本轮新增，`artifacts_adb/r1_wlan_reach/`）：`_wext_dump_setchar.txt`、`_wext_dump_getchar_real.txt`、`_wext_dump_getchar_body.txt`、`_wext_dump_iw_*.txt`、`_wext_dump_hdd_fips_test.txt`、`_wext_dump_wowl_add.txt`、`_wext_dump_wowl_del.txt`、`_wext_dump_memalloc.txt`、`_wext_sub_*.txt`。

### 1.4 证据级别与限制

* 每条结论都标 **指令级**（`.ko` 反汇编地址）或 **未决**。文中出现的 `wext-priv.c` 行号属 **源码级**，只说明内核侧门，不代替驱动自身的指令级证据。
* 反汇编是**静态**的：寄存器别名/跳表已手工闭合，但**调用图下游**（`sme_*`/`wma_*`/`ucfg_*`）只在"是否被当长度/索引"这一层核，未展开其内部取值域。
* 所有"有界"都是**上界成立**的意思，不等于"下游语义安全"。

---

## §2 逐 handler

格式：入口 → 用户参数来源 → 长度门 → 拷贝/结构体 → 下游 → 错误出口。

### 2.1 `0x8BE3 iw_setchar_getnone`（0x89d98/1320）——**有界**（本轮最高优先项）

**（a）入口与权限。** `0x89e44 bl capable`，`w0=0xc`（`CAP_NET_ADMIN`）；`tbz w0,#0 → 0x89eb4`（"permission check failed" → `-1`）。随后 `__wlan_hdd_validate_context`。

**（b）core 侧到底给的是什么。** `we_private_args[144] = {cmd=0x8BE3, set=0x2200, get=0x0000, name=""}`。`0x8BE3` 是**奇数 ⇒ GET** ⇒ `get_priv_descr_and_size()` 走 else 分支，`get_priv_size(0)=0`，且 `get_args` 未置 `IW_PRIV_SIZE_FIXED`——`extra_size` 仍然是 **0**。于是 `ioctl_private_call()` 走 `wext-priv.c:197` 的"无额外参数"分支：`handler(dev, info, &iwr->u, (char*)&iwr->u)`。
**⇒ 没有 `-E2BIG`、没有 `kzalloc`、没有 `copy_from_user`、返回时也没有 `copy_to_user`。`extra` 是 16B 的内核栈 union（本 handler 从不使用 x3）。**

**（c）用户参数来源 = handler 自己内联的 `hdd_priv_get_data`。**

```
0x89f4c  cbz  x21, <EINVAL>          ; wrqu == NULL
0x89f50  mrs  x8, sp_el0             ; current_thread_info
0x89f58  tbnz w8, #0x16, 0x89f74     ; TIF_32BIT → compat 路径
0x89f5c  memcpy(sp+0x30, wrqu, 0x10) ; native: struct iw_point{ptr,len,flags}
0x89f6c  ldr  x0, [sp, #0x30]        ; ptr
0x89f74  ldp  w0, w8, [x21]          ; compat: u32 ptr @0 / u16 len @4 / u16 flags @6
0x89f80  cbz  x0, <EINVAL>           ; ptr == NULL
0x89f84  ldrh w1, [sp, #0x38]        ; len
0x89f8c  cbz  w1, <EINVAL>           ; len == 0
0x89f90  ldrh w24, [sp, #0x3a]       ; flags  ← 注意：sub-command 在 flags，不在 len
```

**（d）长度门。** handler **自己没有**任何 `len` 上界比较。唯一的门在 `mem_alloc_copy_from_user_helper`（0x85520）：

```
0x85534  cmp x1, #1, lsl #12    ; 4096
0x85538  b.ls  0x8557c          ; len<=4096 才继续
0x8553c  ... "Invalid length: %zu max: %u" → return NULL
0x85588  add x0, x20, #1        ; malloc(len+1)
0x855ec  __arch_copy_from_user(buf, ptr, len)
0x855f8  strb wzr, [x21, x20]   ; buf[len] = 0  ← 后面所有解析都靠这个
```
**⇒ 用户可控 `len` 的真实范围是 `[1, 4096]`（不是 512）。** 失败返回 NULL → `0x89f98 cbz x0` → `-ENOMEM`（`0x8a0a8`），不 free（未分配）。

**（e）`len+1` 缓冲如何被消费。** 先打一条日志 `"%s: %d: Received length: %d data: %s"`（`0x89fc8`，`%s` 读的就是 NUL 结尾的 buf，安全）。然后按 `flags-1` 分派：

```
0x89fcc  sub  w8, w24, #1
0x89fd0  cmp  w8, #5
0x89fd4  b.hi 0x8a0ec            ; 越界 → "Invalid sub command %d" → -EINVAL
0x89ff4  ldrb w11, [.rodata+0x4b7c + w8]
0x89ff8  add  x10, x10, w11, lsl #2
0x89ffc  br   x10
```
6 项全部解出（`.rodata+0x4b7c`）：

| flags | 目标 | 行为 |
|---|---|---|
| 1 | 0x8a000 | `hdd_add_wowl_ptrn(dev+0x900, buf)` |
| 2 | 0x8a0b0 | `hdd_del_wowl_ptrn(dev+0x900, buf)` |
| 3 | 0x8a118 | RRM 邻居报告请求（见 g） |
| 4 | 0x8a238 | `WE_SET_AP_WPS_IE` → 只打日志 "won't process"，返回 0 |
| 5 | 0x8a0ec | "Invalid sub command" 日志 → `-EINVAL` |
| 6 | 0x8a28c | 直接跳到 free + 返回 `-EOPNOTSUPP`（`w25=#-0x5f` 于 0x89fe4） |

**（f）`hdd_add_wowl_ptrn`（0x84930/0x4e4）——把 buf 当 `"off:mask:pat"` 文本解析，全程有界。**

```
0x849a8..0x849c8  seglen = strcspn(buf, "\0;")      ; 依赖 buf[len]=0
0x849c8  cmp  w8, #0xb ; b.lt → "Invalid length specified. Skip!"
0x84ad0  ldrb [buf+2] == ':'  &&  [buf+5] == ':'   ; 格式
0x84ae8  hex_to_bin(buf[0..1])  → offset
0x84b08  hex_to_bin(buf[3..4])  → plen
0x84b2c  cmp  w9, #0x92 ; b.hi → skip      ; offset <= 146
0x84b34  and  w10, w8, #0xff
0x84b38  cmp  w10, #0x14 ; b.lo → 继续解析  ; plen <= 19（>=20 落进 "Invalid length"）
0x84bbc  x11 = 2*offset + 6
0x84bc4  cmp  w11, w25 ; b.ge → skip       ; 2*offset+6 <  seglen
0x84bcc  ldrb w12, [buf, x11] == ':'        ; 越界前先判 x11 < seglen
0x84bd8  w10 = 2*offset+6 + 2*plen ; orr #1
0x84be0  cmp  w10, w25 ; b.ne → skip        ; 精确等式 2*offset+6+2*plen|1 == seglen
0x84c20  strb → sp+0x3b .. sp+0xcc          ; offset<=146 ⇒ 最高 sp+0xcc
0x84c70  strb → sp+0xce .. sp+0xe0          ; plen<=19   ⇒ 最高 sp+0xe0
0x84c90  malloc(seglen+1) ; 0x84cac memcpy(dst,seg,seglen) ; 0x84cb8 dst[seglen]=0
0x84ccc  ucfg_pmo_add_wow_user_pattern(req, &stack_struct)
```
栈帧 0x1d0、`x29=sp+0x170`；两处写入上界 `sp+0xe0 < sp+0x170`。**offset 的上界与目标字段尺寸严格相等（146），零冗余；plen 的上界 19 比字段 20 少 1。** 所有 `ldrb` 的索引都被 `x11 < seglen` 或精确等式先夹住，`seglen <= strlen(buf) <= len`。

**（g）RRM 分支（flags=3，0x8a118…0x8a22c）——第二处 `len` 派生长度。**

```
0x8a130  ldrh w24, [sp, #0x38]     ; w24 改存 len
0x8a150  cmp  w24, #1 ; cset w5,eq ; ssid_present = (len == 1)
0x8a168  cmp  w24, #1 ; b.eq → 跳过拷贝   ; len==1 时无 SSID
0x8a170  w8  = len
0x8a178  w9  = len - 1
0x8a17c  cmp w8, #0x21
0x8a180  w8  = 0x20
0x8a184  csel w8, w9, w8, lo        ; count = min(len-1, 32)
0x8a18c  dst = (x29-0x30) | 2       ; sp+0x42
0x8a190  w2  = count & 0xff
0x8a198  qdf_mem_copy(dst, buf, count)
0x8a22c  sme_neighbor_report_request(...)
```
`count <= 32` 且目标 32B 字段 `sp+0x42..0x61`，`count <= len-1 < len`（源侧安全）。**有界。**

**（h）错误出口是否释放。** 统一出口 `0x8a28c mov x0,x21; bl __qdf_mem_free`；三条"未分配"的错误路径（0x8a034/0x8a07c/0x8a0a8）都直接 `b 0x89edc`，不经过 free。`hdd_add_wowl_ptrn`/`hdd_del_wowl_ptrn` 内部对各自的分配也有 `__qdf_mem_free`（0x84d04/0x85040）。**无泄漏、无 double free。**

**（i）判定：有界。** 用户可控的只有 `ptr/len/flags`；`len ∈ [1,4096]` 由 helper 夹住，缓冲必以 NUL 结尾；两个消费方（wowl 文本解析、RRM SSID 截断）都有独立上界且与目标尺寸严格相等；无固定结构体强转，无 `len` 当数组长度/索引。

### 2.2 `0x8BFE iw_set_dot11p_channel_sched`（0x8eb40/**8**）——**无功能**

```
0x08eb40  mov w0, wzr
0x08eb44  ret
```
不读 `wrqu`（x2）、不读 `extra`（x3）。表项 `set_args=0x10D0` ⇒ core（偶数=SET）仍会 `kzalloc(208)` + `copy_from_user(208)`，但 208B 缓冲无人消费。**208B 结构体不存在，字段偏移问题不存在，无元素计数/索引。**

### 2.3 `0x8BF4 iw_set_fties`（0x8c680/732）——**有界**

* **方向**：偶数 ⇒ SET ⇒ core `extra_size = get_priv_size(0x2180) = 384`（未置 FIXED），`len>384` 直接 `-E2BIG`；`kzalloc(384)`；`len!=0` 时 `copy_from_user(extra, ptr, 384)`。
* **参数来源**：`x22=wrqu`、`x21=x3=extra`（`0x8c6bc/0x8c6d0`）。
* **门**：`0x8c7f8 ldrh w5,[x22,#8]; cbz w5` → 0 长度 `-EINVAL`（"called with 0 length IEs"）；`0x8c800 ldr x8,[x22]; cbz x8` → 指针 NULL `-EINVAL`。
* **拷贝/结构体**：**没有固定结构体强转**。下游直接把 core 拷好的 `extra` 与用户 `len` 一起传下去：
  `0x8c890 ldr x0,[x24,#0x10]; 0x8c898 ldrb w1,[x23,#0x998]; 0x8c894 mov x2,x21; 0x8c89c ldrh w3,[x22,#8]; 0x8c8a0 bl sme_set_ft_ies`
  ⇒ `(extra, len)`，`len <= 384 = sizeof(extra)`。
* **"IE 长度字段是否被当拷贝长度"**：驱动层没有；`sme_set_ft_ies` 内部的 IE 解析未展开（§4）。缓冲上界成立。
* **错误出口**：`-EINVAL` / `-EOPNOTSUPP`(0x20c) 前都会 `__osif_vdev_sync_op_stop`；无分配。

### 2.4 `0x8BE9 iw_add_tspec`（0x8b830/1008）——**有界**

* **方向**：奇数 ⇒ **GET** ⇒ `get_args=0x4801,FIXED` ⇒ `extra_size=0` ⇒ handler 拿到 16B union，**76B 不是 core 分配的**。
* **权限/模式**：`0x8b9b4 capable(0xc)`；`0x8b9c0 ldr w8,[dev+0xb194]; cmp #2`（必须 station 模式）。
* **参数来源**：`0x8b9cc cbz x23`（wrqu）；native `0x8b9e8 memcpy(sp+0x10, wrqu, 0x10)`；compat `0x8ba3c ldp w1,w8,[x23]`（ptr@0,len@4,flags@6）。
* **长度门（关键）**：`0x8ba4c ldrh w8,[sp,#0x18]; cmp w8,#0x13; b.ne` ⇒ **`len` 必须精确等于 19**（19×4 = 76）。
* **指针门**：`0x8ba58-0x8ba74` 是内联的 `access_ok(ptr, 76)`（`ptr+0x4c` 与 `current_thread_info()->addr_limit` 比较，`cset x9,ls` + `cbz`），失败走 `0x8bad4`（`-EIO`）。
* **拷贝**：`0x8ba80 __arch_copy_from_user(x29-0x54 = sp+0x6c, ptr, 0x4c)` ⇒ **76B → 76B 栈缓冲**；随后 `0x8ba94 memset(sp+0x20, 0, 0x4c)` 建一个 76B 输出结构。
* **字段边界**：读 `[x29-0x54]`(tsid)、`-0x50`(up)、`-0x4c`(dir)、`-0x48/-0x44`(si/…)、`-0x40..-0x10`，**全部在 76B 内**；`up<8`@0x8baa8、`up<9`@0x8bb1c（"***ts_info.up out of bounds***"）、`dir∈{0,1,2}`@0x8bb10。
* **写回**：`0x8bb14 str w8,[x20]`（错误码 5）、`0x8bbe8 str w0,[x20]`（`hdd_wmm_addts` 状态）⇒ 只写 4B 到 16B union；GET 返回路径 core 不拷贝（`extra_size==0`）。
* **判定：有界**。`len==19` 是硬门，76B 读取由 `access_ok` 保障。

### 2.5 `0x8BF5 iw_get_statistics`（0x8c960/1040）——**有界**（GET 侧信息泄露方向已排除）

* **方向**：奇数 ⇒ GET ⇒ `get_args=0x17FF` ⇒ `extra_size=2047`，`kzalloc(2047)`（清零）。
* **参数来源**：`x20=wrqu`、`x21=x3=extra`（`0x8c99c/0x8c9b0`）。
* **写入**：固定偏移 TLV 记录，`strh` 头 + `memcpy` 定长（0x10 或 4）：
  `[x21+0x00]..[x21+0x0d]`、`+0x12..+0x23`、`+0x24..+0x35`、`+0x36..+0x3d`… 最后一条 `0x8cce4 strh w8,[x21,#0xa8]` + `0x8cce8 memcpy(x21+0xaa, …, 4)` ⇒ **最高写到 `extra+0xad`，共 174B**。
* **回填长度**：`0x8ccf0 mov w8,#0xae` → `0x8cd10 strh w8,[x20,#8]` ⇒ **`iwp->length = 0xAE = 174`，与实际写入字节数精确相等**。非 station 路径 `0x8cd24 strh wzr,[x20,#8]` ⇒ length=0。
* **core 侧**：`adjust_priv_size(0x17FF, iwp) = min(174, 2047)×1 = 174` ⇒ `copy_to_user(ptr, extra, 174)`。
* **信息泄露方向**：`extra` 由 `kzalloc` **清零**，回填长度 = 实际写入长度 ⇒ **不存在"把未初始化内核内存回传"的路径**。
* **判定：有界。**

### 2.6 `0x8BE5 iw_get_char_setnone`（0x8a2c0/**4068**）——**有界**

> 注意：`--fn iw_get_char_setnone` 会命中 0x96270 的同名 392B 版本（`hdd_check_private_wext_control` 变体，不是 we_private 用的那个）。本节数据来自 `--at 0x8a2c0 --len 0xfe4`。

* **方向**：奇数 ⇒ GET ⇒ `get_args=0x27FF` ⇒ `extra_size=2047`（kzalloc 清零），`iwp->pointer` 必须非 NULL（`wext-priv.c:152`）。
* **参数**：`x21=wrqu`、`x22=x3=extra`（`0x8a300/0x8a314`）。`0x8a348 ldrh w27,[x21,#0xa]` = **`iwp->flags` = sub-command**。
* **门**：`0x8a3f4 sub w8,w27,#1; cmp w8,#0x10; b.hi` ⇒ **flags ∈ [1,17]**，越界 "Invalid IOCTL command %d"；跳表 `.rodata+0x4b82`，**17 个 u16 偏移**（`0x8a430 ldrh w11,[x9,x8,lsl#1]`）。
* **17 路输出的共同形态**：全部把 `extra` 与一个**显式尺寸**交给格式化函数，尺寸常量只有 `0x7ff`(2047) 和 `0x400`(1024)：
  * `hdd_wlan_get_version(ctx, 0x7ff, extra)` @0x8a448，返回长度 `0x8a450 strh w0,[x21,#8]`
  * `hdd_wlan_get_stats(…, wrqu+8, extra, 0x7ff)` @0x8a4d4
  * `hdd_cfg_get_global_config(…, extra, 0x400)` @0x8a510
  * `snprintf(extra, 0x7ff, fmt, …)` @0x8a5c4 等多处
  * `iw_get_channel_list_with_cc(dev, info, wrqu, extra)` @0x8a5e4
  * `wlan_hdd_get_rssi` + `snprintf(…, "rssi=%d")` @0x8a600
* **回填长度**：`0x8af90 bl strlen; 0x8af94 add w8,w0,#1; 0x8af9c strh w8,[x21,#8]` ⇒ `iwp->length = strlen(extra)+1 ≤ 2047`。
* **core 侧**：`adjust_priv_size(0x27FF, iwp) = min(len,2047)×1` ⇒ 拷贝量 ≤ 2047 = sizeof(extra)。
* **信息泄露方向**：`extra` kzalloc 清零；长度 = `strlen+1` 或格式化函数返回值，都被 core 的 2047 夹住。**未发现泄露路径。**
* **残留风险（§4）**：17 路下游（尤其 `hdd_wlan_get_stats` 与 `iw_get_channel_list_with_cc`）是否**内部**严格按传入的 `0x7ff` 截断，本轮未逐函数核。若其中某个用 `sprintf`，会溢出 2047B 堆缓冲 —— 这是本面现在唯一还值得抽样的点。

### 2.7 `0x8BFF iw_get_linkspeed`（0x8eb48/600）——**有界（零冗余）**

见 §0.2(3)。补充：
* 方向：奇数 ⇒ GET ⇒ `get_args=0x2005` ⇒ `extra_size = (0x005 & 0x7FF) × 1 = 5`，**kzalloc 5 字节**（未置 FIXED，所以不走 `&iwr->u`）。
* `0x8ebe4 stur wzr,[x29,#-0xc]` 先清零局部 u32；`0x8eccc wlan_hdd_get_link_speed(adapter, &local)`。
* `0x8ecf4 strh w1,[x22,#8]`（length=5）**发生在** `snprintf` 之前；`0x8ecfc cmp w0,#5 / b.lo` 要求 `snprintf` 返回 <5（"Unable to encode link speed" 否则 `-EIO`）。
* `0x8ec88 ldr x21,[x8]` 会覆盖 x21（=extra）——但只在 `wext_control==0` 的拒绝分支里，之后不再使用 extra。
* core 侧 `copy_to_user(ptr, extra, min(5,5)) = 5`。

### 2.8 `0x8BE8 hdd_fips_test`（0x9fcc8/1148）——**有界**（本轮新发现：唯一自带 `copy_to_user` 的 SET handler）

* **方向**：偶数 ⇒ SET ⇒ `set_args=0x17FF` ⇒ `extra_size=2047`，`iwp->length>2047` 直接 `-E2BIG`；`copy_from_user(extra, ptr, 2047)`（`len!=0` 时）。表项 `get_args` 也是 `0x17FF`，但因为 cmd 是偶数，**`get_args` 永远不会被读** ⇒ r1 记的 "set=get 同源可疑" 不成立。
* **没有 `wext_control` 门**：本函数体内没有 `hdd_ctx->config+0x20f0` 的载入（其它 handler 都有）。
* **参数**：`x23=wrqu`、`x22=x3=extra`（`0x9fd08/0x9fd14`）。
* **校验链（全部指令级）**：
  ```
  0x9fd80  ldrh w6, [x23, #8]        ; len = iwp->length
  0x9fd84  cmp  w6, #0x2f
  0x9fd88  b.hi 0x9fdc0              ; len >= 48 否则 "Request len %u is too small" → -EINVAL
  0x9fdc4  ldr  w5, [x22, #8]        ; key_len   ∈ {16,32}  (0x9fdc8/0x9fdcc/0x9fdd4)
  0x9fdd8  ldr  w5, [x22, #0x2c]     ; data_len
  0x9fddc  sub  w8, w6, #0x30
  0x9fde0  cmp  w8, w5
  0x9fde4  b.ne 0x9feb8              ; data_len 必须 == len-0x30
  0x9fde8  ldr  w5, [x22, #4]  ; mode < 2
  0x9fdf4  ldr  w5, [x22]      ; op   < 2
  ```
  ⇒ `data_len ∈ [0, 2047-48] = [0,1999]`，`key_len ∈ {16,32}`。
* **请求体**：`0x9fe20 add x8,x22,#0xc`（key 指针 = extra+12）、`0x9fe34 add x8,x22,#0x30`（data 指针 = extra+48）、`0x9fe3c str w9,[x0,#0x10]`(key_len)、`0x9fe48 str w8,[x0,#0x20]`(data_len) → `sme_fips_request`。**key 区 [12,12+32)=[12,44)、data 区 [48,48+1999] ⊆ [48,2047) —— 恰好贴合 2047B 缓冲。**
* **回复回写（本面唯一的 SET handler 自带 `copy_to_user`）**：
  ```
  0xa007c  ldr w5,[resp,#0x38] ; ldr w6,[resp,#0x20]
  0xa0084  cmp w5, w6 ; b.ne "Data length mismatch" → -EINVAL
  0xa008c  str wzr,[x22]         ; extra[0..3] = 0 状态
  0xa0098  str w8,[x22,#4]       ; extra[4..7] = resp->data_len
  0xa009c  ldr x1,[resp,#0x40] ; qdf_mem_copy(extra+8, resp->data, resp->data_len)
  0xa00b8  w8 = data_len + 8 ; 0xa00c4 strh w8,[x23,#8]   ; iwp->length = data_len+8
  0xa00fc  __arch_copy_to_user(iwp->pointer, extra, data_len+8)
  ```
  `resp->data_len` 被强制等于请求 `data_len = len-48 ≤ 1999` ⇒ `qdf_mem_copy` 写 `extra[8..2006]`（≤2047）、`copy_to_user` 读 `data_len+8 ≤ 2007` 字节（≤2047）。**两头都在界内**。
* **判定：有界。** 这是"差一条指令就出事"的形态：如果 `0x9fd84 cmp w6,#0x2f / b.hi` 这一句不存在，`len<0x30` 会让 `len-0x30` 回绕成 `0xFFFFFFD0+`，`data_len` 即可被设成 40 亿级，接着 `sme_fips_request`/`qdf_mem_copy` 就会从 2047B 缓冲里越界读数 GB。**建议主代理把这一句作为回归基线记录。**

### 2.9 快速收口的 7 个父项

**0x8BE1 `iw_setnone_getint`（0x88f68/3628，GET，extra=16B union）**
`0x088fb0 mov x22,x3`；`0x890f4 ldr w5,[x22]` 取 sub_cmd，`0x890fc sub w8,w5,#1; 0x89100 cmp w8,#0x3c; 0x89104 b.hi` ⇒ **`sub_cmd ∈ [1,0x3d]`（61 路）**，跳表 `.rodata+0x4b02`。全部对 extra 的访问只有 `0x890f4 ldr w5,[x22]`、`0x892f8 ldr w8,[x22]`、`0x89304 ldr w5,[x22]` 和 9 处 `str wX,[x22]` ⇒ **一律 4 字节、偏移 0**。写回不经过 core（`extra_size==0`），走 `dev_ioctl` 的 ifreq 回拷（16B union 之内）。**有界。**

**0x8BE4 `iw_set_three_ints_getnone`（0x87148/1228，SET，extra=16B union）**
`0x871c8 ldr w23,[x21]`(sub_cmd)、`0x8732c ldp w2,w8,[x21,#8]`、`0x87330 ldr w1,[x21,#4]`、`0x87348 ldr w2,[x21,#0xc]`、`0x8738c ldp w24,w21,[x21,#8]` ⇒ **最大访问 `[extra+0xf]`，恰好 16B**。子命令门 `0x87300 cmp w8,#0x14; b.hi`（`sub_cmd ∈ [1,0x15]`），跳表 `.rodata+0x4a76`。**有界。**

**0x8BE6 `iw_setnone_getnone`（0x8b2a8/836，SET，extra=16B union）**
**完全不访问 extra**。`0x8b3d0-0x8b3e4` 先判 `TIF_32BIT`（`tst x8,#0x400000`），native 从 `wrqu+0x0a`、compat 从 `wrqu+0x06` 取 u16 sub_cmd；`0x8b3ec sub w8,w5,#8; cmp w8,#0xb; b.hi` ⇒ `sub_cmd ∈ [8,0x13]`，跳表 `.rodata+0x4c2c`。子命令里做的是 `wlan_reg_freq_to_chan`/`sme_get_modify_profile_fields`/`qdf_mem_copy(.., dev+0xb198, 6)`/`wma_cli_set_command`/`sme_ht40_stop_obss_scan`/`sme_roam_reassoc`，**无用户数据参与长度**。**有界。**

**0x8BEB `iw_del_tspec`（0x8bc20/544，GET）**：`capable(0xc)`@0x8bd98；`0x8bda0 ldr w1,[x20]` = tsid（4B）；`tsid==-1` → `str w8(=5),[x20]`；否则 `hdd_wmm_delts` → `0x8bdb4 str w0,[x20]`。**4B 进 4B 出。有界。**

**0x8BED `iw_get_tspec`（0x8be40/524，GET）**：同上形态，`hdd_wmm_checkts`，`ldr w1,[x20]` / `str w0,[x20]`。**有界。**

**0x8BEF `iw_setnone_get_threeint`（0x8c050/560，GET）**：`0x8c1c8 ldr w5,[x20]` = cmd；`cmp w5,#1 / b.ne` → "Invalid IOCTL get_value command"；`0x8c1fc hdd_indicate_tsf(adapter, x1=x20=extra, w2=3)`。`hdd_indicate_tsf` 只写 `[x19]`、`[x19,#4]`、`[x19,#8]`（0xa6810/0xa6874/0xa687c）⇒ **12B ≤ 16B union。有界。**

**0x8BF9 `iw_set_band_config`（0x8e140/484，GET）**：`0x8e1dc capable(0xc)`；`0x8e184 mov x21,x3`；`0x8e288 ldr w1,[x21]` = band（4B）→ `hdd_reg_set_band(dev, band)`。注意 `0x8e204` 处 `x21` 被改写成 `.bss+0xfc8`，但那条分支只通向拒绝返回。**读 4B、无写。有界。**

### 2.10 `0x8BE0 iw_setint_getnone` 的子命令面

父项（r1 已核，本轮复核）：`set_args=0x4801` + 空名 ⇒ `extra_size = 4+4 = 8 ≤ 16` ⇒ union 路径；`0x88d8c ldp w22,w24,[x20]`（sub_cmd+arg 共 8B）；`0x88e54 cmp w22,#0x64; b.hi`；`0x88e6c ldr x8,[.rodata+0x6280 + x22*8]`；空项 `cbz` → `-EINVAL`；`add x0,x21,#0x900; mov w1,w24; blr x8`。

**本轮把 101 项全量解开并分类（明细见 `wext_audit_2.csv` 的 101 行子命令段）：11 项 NULL（无功能）、90 个唯一目标函数（无复用）。**
90 项里：**没有一个**调用 `memcpy/copy_from_user/strlen/strscpy/sscanf/snprintf` 这类长度或字符串解析原语（自动扫描全部 90 个目标的重定位）；**没有一个**接收用户缓冲指针或 length——签名固定 `f(adapter, u32 value)`。
`sanity` 小结：**在这 101 × 1 个 32 位输入上，本层不存在"长度未校验 → 越界读/写"。**

唯一需要单独点名的是 **三处把 `value` 当跳表索引**，全部有上界（见 §0.3 表）。抽样给出 sub 3 的完整形态：

```
hdd_we_set_power @0x8ee60
0x8ee74  cbz  x19, <EINVAL>
0x8ee78  mov  w5, w1                ; value
0x8ee7c  sub  w8, w1, #1
0x8ee80  cmp  w8, #3
0x8ee84  b.hi 0x8eecc               ; → "Invalid value %d" → -EINVAL
0x8eea0  ldrb w11, [.rodata+0x4c5b + w8]
0x8eea4  add  x10, x10, w11, lsl #2
0x8eea8  br   x10                   ; 4 个 case: sme_save_usr_ps_cfg / sme_ps_enable_disable / sme_ps_uapsd_enable / sme_ps_uapsd_disable
```

`hdd_we_clear_stats`（sub 86）与 `hdd_wlan_dump_stats`（sub 85）同形，门分别是 `cmp w19,#9; b.hi` 与 `sub w8,w19,#2; cmp w8,#0x17; b.hi`。

---

## §3 具体反例

**本轮未发现可确认的越界读 / 越界写反例。** 23 个父项、101 个子命令全部给出"有界 / 无功能"的可判定结论。

下面 4 个是**"零冗余"边界**——当前指令序列成立，但只要上游常量或一条 `b.hi` 变化就会破。列出它们作为回归基线，不含利用步骤：

1. **0x8BE3 → `hdd_add_wowl_ptrn` 的 offset 上界与目标字段尺寸严格相等。**
   不变量：`offset ≤ 0x92 (146)`（`0x84b2c cmp w9,#0x92 / b.hi`），目标 `sp+0x3b..sp+0xcc`（146B）。**余量 0 字节**：`offset=146` 时最后一次 `strb` 落在 `sp+0xcc`，而 `sp+0xcd` 正是紧邻的 `plen` 字段。上界放松 1 就会踩到 `plen`（仍是同帧栈内，但会污染第二段拷贝的长度）。`plen` 侧上界 19、字段 20 字节，余量 1。
   另：`0x84bbc-0x84be4` 用 `2*offset+6+2*plen|1 == seglen` 的**精确等式**把两段十六进制解析的读取范围钉在 `seglen` 内；这条等式是"读不越界"的唯一依据。

2. **0x8BE8 `hdd_fips_test`：`len >= 0x30` 只由一条 `b.hi` 保证。**
   `0x9fd84 cmp w6,#0x2f / 0x9fd88 b.hi`。若缺失，`0x9fddc sub w8,w6,#0x30` 会回绕，`data_len` 与 `len-0x30` 的等式就变成"两个用户可控值相等"，`data_len` 可达 `0xFFFFFFD0`，随后 `sme_fips_request` 与 `0xa00a4 qdf_mem_copy(extra+8, resp->data, resp->data_len)` 会从 2047B 堆缓冲越界读。当前该句存在 ⇒ 上界 1999。

3. **0x8BFF：`extra` 只有 5B，`snprintf` 的 size 也是 5。**
   `kzalloc(5)`（core，`get_args=0x2005`）／`snprintf(...,5,...)`@0x8ecf8／`iwp->length=5`@0x8ecf4 三者相等。任一变大 1 字节即为堆溢出。

4. **0x8BEF：`hdd_indicate_tsf` 写 12B 进 16B union。**
   余量 4B。若将来把"3 个 int"改成 5 个，就会越过 `iwr->u` 打到 `struct ifreq` 之后的栈。

---

## §4 仍未决与原因

按复核价值排序：

1. **`wext_control` 门（可影响"是否可达"，不影响"是否有界"）。** 除 0x8BE8（无此门）与 0x8BFE（8B 空桩，什么都不读）外，每个 handler 都在 `__wlan_hdd_validate_context` 之后读 `hdd_ctx->config + 0x20f0` 的一个 u32 并做 0/1/2 状态机：
   * `==1` → 打 `"Using deprecated ioctl %x"` 后**放行**；
   * `==2` → 直接放行；
   * `==0` → **拒绝**，返回 `-0x20c`（"Rejecting disabled ioctl %x"，并按 `last/jiffies` 做 ≤50 jiffies 的日志限流）。
   这个字段来自 INI 配置，**默认值无法离线确定**（`.ko` 里只有代码，没有配置值）。若默认为 0，则除 0x8BE8 外全部不可达——只会让结论更保守。0x8BE8 `hdd_fips_test` 体内**没有**这个门。
2. **0x8BE5 的 17 路输出函数的内部截断。** `hdd_wlan_get_version` / `hdd_wlan_get_stats` / `hdd_cfg_get_global_config` / `iw_get_channel_list_with_cc` 都拿到了 `extra` 与显式上限（0x7ff / 0x400），但"是否真的按上限截断"未逐函数核。若某个内部用 `sprintf`/`strcat`，就会溢出 2047B 堆缓冲。**这是本面现在最值得抽样复核的点（信息泄露/堆溢出的方向）。**
3. **下游取值域（"有界"只到本层）。** `wma_cli_set_command` / `sme_cli_set_command` / `hdd_wmm_addts` / `hdd_wmm_delts` / `hdd_wmm_checkts` / `sme_neighbor_report_request` / `sme_set_ft_ies` / `wlan_hdd_set_filter` / `sme_fips_request` 内部对 value 与长度的二次解释未展开。特别地：0x8BE0 的 101 个子命令把 `value` 直接塞进 WMI 命令参数，若某条 WMI TLV 在固件侧把它当长度，问题会出在固件而不是驱动。
4. **0x8BE1 的 61 路（`sub_cmd` 1..0x3d）子命令语义未逐个展开。** 本层已证明"只有 4B 读 + 4B 写"，但每一路指向哪个 `hdd_we_*` 函数、其 value 域是否有约束，未列表。
5. **0x8BE3 → `hdd_add_wowl_ptrn` 的全局 pattern 数组索引。** `0x84c94 str x0,[x20, w21, sxtw #3]`，`w21` 来自"找一个空槽"的循环，上界是 `ucfg_pmo_get_num_wow_filters()` 的返回值；`x20 = .bss+0xed8` 这个全局指针数组的**实际元素个数**本轮未核（配置驱动，通常是 8）。若配置值大于数组长度，则是 8 字节指针数组越界写。
6. **compat 路径只在 3 个 handler 里核过**（0x8BE3 / 0x8BE6 / 0x8BE9）。`compat_iw_point` 的布局是 `{u32 ptr; u16 len; u16 flags}`，与非 compat 的 `{ptr; u16 len; u16 flags}` 不同；本机 `oplus_wifi_service` 是 64 位，实际走 native，所以 compat 分支只是完备性核对。
7. **PNO record 布局**（r1 §4 第 5 条，沿用）：`iw_set_pno` 的 stride `0x1bc` 与字段 `+0x1f4` 存在 record 间重叠，最坏写仍在 `__iw_set_pno.req`(0x1c88) 内。功能问题，非内存安全，本轮未再投入。

---

## §5 与项目四层判定的关系

* **不改变 NO-GO。** 本面 23 个父项、101 个子命令现在**全部可判定**，没有任何一条能证明"用户可控长度/索引越过内核对象边界"。因此本面既不提供新的原语，也不推翻任何已有判定。
* **本面的真实价值是"受限 UID 0 域内的驱动状态/信息面"，而且本轮把它压小了：**
  * 可达链要求 `oplus_wifi_service`（uid 0，已持 `net_admin`）。普通 shell 无 `net_admin`，无法直达 `0x8BE0..0x8BFF`。
  * **信息泄露方向已关闭**：三个 GET/char 类 handler（0x8BE5 / 0x8BF5 / 0x8BFF）的 `extra` 全部来自 `kzalloc`（清零），且回填的 `iwp->length` 分别等于 `strlen+1` / 174 / 5，与 `copy_to_user` 的夹取上限一致 ⇒ 不存在"把未初始化内核内存回传"的路径。它们回传的是驱动统计、版本串、INI 配置文本——**不含内核指针**。
  * **写入方向未发现**：唯一的"用户长度直接决定拷贝量"的点是 0x8BE3 的 `mem_alloc_copy_from_user_helper`（≤4096）与 0x8BE8 的 `data_len == len-0x30`，两者的落地写入目标都是**驱动自己的栈或内核堆分配**，且上界与目标尺寸相等或更小。
* **相对 r1，本轮把"未决"从 15 降到 0，并下调了两个"高优先嫌疑"**（0x8BFE 是空桩；0x8BFF 的堆缓冲只有 5B 但恰好自洽）。对主代理的实际收益是：**本面可以从"待核清单"移出**，只留 §4 的第 2、3、5 条作为"下游/配置"级的抽样项，而这三条都不在 wext handler 这一层。

---

## 附：产物清单

| 路径 | 内容 |
|---|---|
| `WLAN_WEXT_HANDLER_AUDIT_2.md` | 本文件（第二轮收口报告） |
| `artifacts_adb/r1_wlan_reach/wext_audit_2.csv` | 124 条记录 + 表头：23 个父项 + 101 个子命令，含方向、长度门、目标尺寸、判定、证据地址 |
| `artifacts_adb/r1_wlan_reach/_wext_dump_setchar.txt` | `iw_setchar_getnone` 全量带注解反汇编 |
| `artifacts_adb/r1_wlan_reach/_wext_dump_getchar_real.txt` / `_getchar_body.txt` | `iw_get_char_setnone`（0x8a2c0 真身）与 17 路 switch 体 |
| `artifacts_adb/r1_wlan_reach/_wext_dump_iw_*.txt` | 其余 handler 反汇编（get_linkspeed / get_statistics / set_fties / add_tspec / del_tspec / get_tspec / setnone_get_threeint / set_band_config / set_three_ints / setnone_getint / setnone_getnone / dot11p） |
| `artifacts_adb/r1_wlan_reach/_wext_dump_hdd_fips_test.txt` / `_wowl_add.txt` / `_wowl_del.txt` / `_memalloc.txt` / `_hdd_indicate_tsf.txt` | 关键下游/helper 反汇编 |
| `artifacts_adb/r1_wlan_reach/_wext_sub_*.txt` | 三处"value 作跳表索引"的子命令全量反汇编 |
| `artifacts_adb/r1_wlan_reach/_wext_subcmd_8be0.txt` / `_wext_core_extra.txt` / `_wext_subval.txt` | 101 项子命令表、core extra_size 复算、`value` 用途摘要（`_wext_probe_subval.py` 生成） |
| `tools/wlan_wext_subcmd.py` | 新增：`--args` / `--subcmd` / `--clusters` / `--at` / `--audit-csv` |
| `tools/wlan_wext_scan.py` | 沿用（节感知全重定位扫描器） |
