# WLAN_HANDLER_AUDIT — qcacld `hdd_driver_command` 98 个命令 handler 的离线静态审计

> 目标物料：`vendor_ko/qca_cld3_wlan.ko`
> （ET_REL / EM_AARCH64，14,601,726 B，SHA-256 `f45c1c1cf63281ee5e64c8b6149c42d5e1aaa91142913073668abf1901674d00`，vermagic `4.9.227-perf+`）
> 目标机型：OPPO K3 / PCGM00 / SDM710 / Android 11
> 性质：**纯离线**。未连接设备、未执行任何驱动命令、未联网。
> 上游：`docs_archive/R1_WLAN非配置输入可达性矩阵_2026-11-20.md` §6（候选 A 首轮）。
> 本文只写 3 个文件：本文件、`tools/wlan_handler_scan.py`、`artifacts_adb/r1_wlan_reach/handler_audit.csv`；
> **未改动** `HANDOVER.md` / `README.md` / `CLOSURE.md` / `HANDOVER_RESUME.md` / `GHOSTLOCK_ADDRESS_SOURCE_MATRIX.md`。
>
> 证据等级标注：**【指令级】** = 本机 `.ko` 反汇编可复核；**【推断】** = 由指令模式推出但未逐条人工确认；**【未决】** = 静态不可判定。

---

## §0 结论摘要

按审计纪律分三类，**不凑漏洞数量**。

### 0.1 已确认有界（指令级）

对 98 个 handler 逐项扫描后，**未发现**下列任一类可证伪的不变量破坏：

| 朴素假设 | 结果 | 依据 |
|---|---|---|
| 无界 `%s` 写入定长栈数组 | **不成立** | 27 处 `sscanf`（13 个 handler）中，所有 `%s` 转换**全部带 `%31s` 字段宽度**；未见裸 `%s`/`%[`。可达的最坏写入 = 31+1 = 32 B，且各调用点的槽位边界检查通过（如 `SETANTENNAMODE`：`sp+0x8`，`%31s`，下一独立槽位 `sp+0x30`）**【指令级】** |
| 解析后未校验直接做数组下标 | **未观察到** | 所有标量解析点后均出现 `ldr wN,[sp,#slot]` + `cmp wN,#imm` + 条件分支，或使用 `kstrtou8/u16` 的天然位宽约束；逐点地址见 `handler_audit.csv` 的 `range_check` 列**【指令级】** |
| 输入长度流入 `memcpy/qdf_mem_copy` | **未观察到** | 全部 `memcpy`/`qdf_mem_copy` 的长度参数均为编译期常量（CSV `copy_ops` 列 `len=%#x`）；无 `len=reg` 项**【指令级】** |
| 输出格式化溢出 | **不成立** | 所有 `scnprintf` 的长度参数均为常量（`limit=%#x`，典型 `0x800`），见 `copy_ops`**【指令级】** |
| 栈槽被相邻对象覆盖 | **未发现** | 逐解析点比较 `slot + need <= next_used_slot`，**SLOT-OVERLAP = 0 项**；方法见 §1.3【推断】 |
| 生命周期/错误路径 | **未发现泄漏** | 6 个 handler 使用 `__qdf_mem_malloc`/`__qdf_mem_free`，全部在出口前释放；`hdd_driver_command` 本体全路径 `__qdf_mem_free`（R1 §6 已证）【指令级】 |

### 0.2 需人工复核（少量、具体、可定位）

| i | 命令 | handler | 观察 | 等级 |
|---|---|---|---|---|
| 73 | `SETMCRATE` | `drv_cmd_set_mc_rate` | `kstrtouint` 返回值**未检查**、无值域门，解析结果直接送入 `wlan_hdd_set_mc_rate` | 【指令级】 |
| 74 | `MAXTXPOWER` | `drv_cmd_max_tx_power` | 扫描器报 `no-check`；但紧邻 `0x3fb98 cmp w8,#0xc8 / b.ls`，值域门**疑似存在**，需人工确认 `w8` 是否自 `sp+0x14` 重载 | 【未决】 |
| 70/71/90/92 | `CCXBEACONREQ`/`CCXPLMREQ`/`SET_DISABLE_CHANNEL_LIST`/`GET_ANI_LEVEL` | 同名函数 | 各含 1–4 处 `sscanf`，其格式串由 callee-saved 寄存器跨调用传递，**静态未解析**（`FMT-UNRESOLVED`）。已知可解析的同类格式串均为 `%d`/`%31s`，未见裸 `%s` | 【未决】 |
| 69 | `SETCCKMIE` | `drv_cmd_set_cckm_ie` | `hex_to_bin` 为**标量返回**函数（`int hex_to_bin(char)`），无内存目标槽；扫描器 `slot?` 为形态误报，非缺陷 | 【指令级】 |

### 0.3 发现的具体反例（严格意义上只有 1 个，且**不是**内存安全漏洞）

**反例 H1 — `SETMCRATE`（第 73 项）违反"解析失败必须中止"不变量**

```
0x3fa84  str  wzr, [sp, #4]        ; 槽位预置 0（因此不产生未初始化栈值读取）
0x3fa88  bl   kstrtouint           ; x2 = sp+4
0x3fa8c  ldr  w1, [sp, #4]         ; ← 直接取值，无 cbnz w0 / tbnz w0,#31
0x3fa90  mov  x0, x19
0x3fa94  bl   wlan_hdd_set_mc_rate ; 值被无条件消费
```

- **违反的不变量**：`kstrtouint()` 失败时不得使用其输出。
- **实际影响（诚实评估）**：因为 `0x3fa84` 已把槽位清零，失败路径上送入的是 `0`，**不构成未初始化栈读取、不构成越界、不构成内存破坏**。可表述为"非法输入被静默降级为 rate=0 而非返回 `-EINVAL`"，属**健壮性/逻辑级缺陷**。
- **不外推**：不据此声称提权、不据此改四层判定。

---

## §1 方法与可复算命令

### 1.1 步骤

1. **命令表复算**：`.rela.rodata` 的 `R_AARCH64_ABS64`(257) 绑定 `hdd_drv_cmds`（`.rodata+0x2bb8`，98×0x18）；名称 = 段符号 + addend 指向 `.rodata.str1.1`。**98/98 解析成功，0 未解析**。
2. **符号边界**：`.symtab` 的 `STT_FUNC` + `st_size`；98 个 handler 全部命中独立符号。
3. **调用解析**：`.rela.text` 的 `R_AARCH64_CALL26`(283)/`JUMP26`(282) → 被调符号名。全模块 76,299 条 CALL26。
4. **字面量解析**：本模块用 **large code model**，地址由 `movz #:abs_g0_nc` + 3×`movk`（重定位 264/266/268/269）装载；命任一段即由 `(节, 符号值+addend)` 唯一确定字面量。**`.rela.text` 中不存在 ADR_PREL/ADD_ABS 重定位**，故 R1 §4 第 3 条"未解析 `MOVW_UABS_G*`"的局限在本轮已消除【指令级】。
5. **capstone 逐指令**：帧大小、解析目标槽、返回值门、值域门、拷贝调用及常量长度、锁/等待。

### 1.2 密码学口径

```powershell
cd "D:\AI_tools\AI_Workspace\WBK_OPK_RT_CRA"
Get-FileHash vendor_ko\qca_cld3_wlan.ko -Algorithm SHA256     # f45c1c1c…74d00
python tools\wlan_cmd_table.py                                 # 98 项，unresolved=0
python tools\wlan_handler_scan.py --selftest                    # 8 ok / 0 fail
python tools\wlan_handler_scan.py                               # 人读摘要 + 分类计数
python tools\wlan_handler_scan.py --csv --out artifacts_adb\r1_wlan_reach\handler_audit.csv
python tools\wlan_handler_scan.py --json --out artifacts_adb\r1_wlan_reach\handler_audit.json
python tools\wlan_handler_scan.py --dump-dir artifacts_adb\r1_wlan_reach\handlers
python tools\wlan_handler_scan.py --handler drv_cmd_set_dwell_time --disasm
```

### 1.3 已知局限（**不得外推**）

1. **数据流是有界窗口的轻量扫描，不是 SSA**。寄存器追踪只做单层 `xN <- sp/x29 + imm` 与 ≤3 跳 `mov xD,xS`；跨基本块/phi 不建模。
2. **"成功臂/失败臂"判定是启发式**：以 `mov w0,#0` vs `mov w0,#-N` 判路径极性（`_success_path`），只跟随无条件 `b`；复杂错误汇聚点可能判为 `None`（表现为区间只给一侧）。
3. **栈槽边界用"下一个被独立使用的 sp 偏移"近似**，不含编译器填充与 `x29` 之外的自定义帧指针；`SLOT-OVERLAP=0` 是**正面证据**，但"无重叠"不等于"语义正确"。
4. **`sscanf` 格式串必须能静态解出**；`FMT-UNRESOLVED` 的 4 个 handler 未纳入"已确认有界"。
5. **不做语义等价证明**：不判断状态机是否正确、不判断是否存在逻辑竞态、不判断命令权限是否应授予该域。
6. **换物料即作废**：结论仅对上述 SHA-256 的 `.ko` 成立。

---

## §2 98 行一览表（按 R1 的 5 类分组）

> 数据由 `tools/wlan_handler_scan.py --csv` 直接生成，逐行可复算；本表为压缩记录，指令地址见 CSV 的 `parse_evidence` / `copy_evidence` 列。

> 每行字段：**入口 → 参数来源/解析 → 长度与值域约束 → 对象生命周期 → 状态变化 → 错误出口**。

### 参数解析（24 项）

| i | 命令 | handler | 帧 | 解析 → 约束（指令级） | 拷贝/输出 | 备注 |
|---|---|---|---|---|---|---|
| 3 | SETBAND | drv_cmd_set_band | 0x30 | kstrtou8@0x38814[sp+0x4/1B] **⇒** ret:cbz w0@0x38818->fail? slot1B<=+0x8 | — |  |
| 5 | COUNTRY | drv_cmd_country | 0x20 | — **⇒**  | — | no-parse-no-copy |
| 6 | SETCOUNTRYREV | drv_cmd_country | 0x20 | — **⇒**  | — | no-parse-no-copy |
| 10 | SETROAMTRIGGER | drv_cmd_set_roam_trigger | 0x50 | kstrtos8@0x38cbc[sp+0x4/1B] **⇒** ret:tbnz w0@0x38cc0->ok slot1B<=+0x8 | — |  |
| 14 | SETROAMSCANREFRESHPERIOD | drv_cmd_set_roam_scan_refresh_period | 0x20 | kstrtou8@0x39310[sp+0x4/1B] **⇒** ret:tbnz w0@0x39314->ok slot1B<=+0x8 | — |  |
| 18 | SETROAMDELTA | drv_cmd_set_roam_delta | 0x40 | kstrtou8@0x397fc[sp+0x4/1B] **⇒** ret:tbnz w0@0x39800->ok val[0x0,0x64]@cmp#0x65;b.hs slot1B<=+0x8 | — |  |
| 27 | SETROAMSCANCHANNELMINTIME | drv_cmd_set_roam_scan_channel_min_time | 0x40 | kstrtou8@0x3a88c[sp+0x4/1B] **⇒** ret:tbnz w0@0x3a890->ok slot1B<=+0x8 | — |  |
| 30 | SETSCANCHANNELTIME | drv_cmd_set_scan_channel_time | 0x40 | kstrtou16@0x3afd4[sp+0x4/2B] **⇒** ret:tbnz w0@0x3afd8->ok slot2B<=+0x8 | — |  |
| 32 | SETSCANHOMETIME | drv_cmd_set_scan_home_time | 0x40 | kstrtou16@0x3b274[sp+0x4/2B] **⇒** ret:tbnz w0@0x3b278->ok slot2B<=+0x8 | — |  |
| 34 | SETROAMINTRABAND | drv_cmd_set_roam_intra_band | 0x30 | kstrtou8@0x3b508[sp+0x4/1B] **⇒** ret:tbnz w0@0x3b50c->ok slot1B<=+0x8 | — |  |
| 36 | SETSCANNPROBES | drv_cmd_set_scan_n_probes | 0x40 | kstrtou8@0x3b764[sp+0x4/1B] **⇒** ret:tbnz w0@0x3b768->ok slot1B<=+0x8 | — |  |
| 38 | SETSCANHOMEAWAYTIME | drv_cmd_set_scan_home_away_time | 0x40 | kstrtou16@0x3ba40[sp+0x4/2B] **⇒** ret:tbnz w0@0x3ba44->ok val[0x0,0x12c]@cmp#0x12d;b.hs slot2B<=+0x8 | — |  |
| 41 | SETWESMODE | drv_cmd_set_wes_mode | 0x40 | kstrtou8@0x3bef8[sp+0x4/1B] **⇒** ret:tbnz w0@0x3befc->ok slot1B<=+0x8 | — |  |
| 43 | SETOPPORTUNISTICRSSIDIFF | drv_cmd_set_opportunistic_rssi_diff | 0x40 | kstrtou8@0x3c148[sp+0x4/1B] **⇒** ret:tbnz w0@0x3c14c->ok slot1B<=+0x8 | — |  |
| 45 | SETROAMRESCANRSSIDIFF | drv_cmd_set_roam_rescan_rssi_diff | 0x40 | kstrtou8@0x3c38c[sp+0x4/1B] **⇒** ret:tbnz w0@0x3c390->ok slot1B<=+0x8 | — |  |
| 48 | SETFASTTRANSITION | drv_cmd_set_fast_transition | 0x30 | kstrtou8@0x3c6f4[sp+0x4/1B] **⇒** ret:tbnz w0@0x3c6f8->ok slot1B<=+0x8 | — |  |
| 50 | SETROAMSCANCONTROL | drv_cmd_set_roam_scan_control | 0x40 | kstrtou8@0x3caf8[sp+0x4/1B] **⇒** ret:tbnz w0@0x3cafc->ok slot1B<=+0x8 | — |  |
| 51 | SETOKCMODE | drv_cmd_set_okc_mode | 0x50 | kstrtouint@0x3cccc[sp+0x14/4B] **⇒** ret:tbnz w0@0x3ccd0->ok val[0x2,..]@cmp#0x2;b.lo slot4B<=+0x18 | — |  |
| 56 | CONCSETDWELLTIME | drv_cmd_conc_set_dwell_time | 0x30 | kstrtouint@0x3d0f4[sp+0x4/4B];kstrtouint@0x3d138[sp+0x4/4B] **⇒** ret:cbnz w0@0x3d0fc->ok val[0x0,0x2710]@cmp#0x2711;b.hs slot4B<=+0x8;ret:cbnz w0@0x3d140->ok val[0x0,0x2710]@cmp#0x2711… | — |  |
| 58 | SETDWELLTIME | drv_cmd_set_dwell_time | 0x30 | kstrtouint@0x3d5a8[sp+0x4/4B];kstrtouint@0x3d66c[sp+0x4/4B];kstrtouint@0x3d6a8[sp+0x4/4B];kstrtouint@0x3d6e4[sp+0x4/4B] **⇒** ret:cbnz w0@0x3d5ac->ok val[0x0,0x2710]@cmp#0x2711;b.lo slot4B<=+0x8;ret:cbnz w0@0x3d670->ok val[0x0,0x2710]@cmp#0x2711… | — |  |
| 61 | SETRMCENABLE | drv_cmd_set_rmc_enable | 0x70 | sscanf@0x3dba8[%s(31)] fmt=\'%31s \' out=sp+0x8;kstrtoint@0x3dbc0[sp+0x4/4B] **⇒** ret:cmp#0x1;b.ne@0x3dbac slot32B<=+0x28;ret:tbnz w0@0x3dbc4->ok slot4B<=+0x28 | — |  |
| 72 | SETCCXMODE | drv_cmd_set_ccx_mode | 0x40 | kstrtou8@0x3f970[sp+0x4/1B] **⇒** ret:tbnz w0@0x3f974->ok slot1B<=+0x8 | — |  |
| 73 | SETMCRATE | drv_cmd_set_mc_rate | 0x30 | kstrtouint@0x3fa88[sp+0x4/4B] **⇒** no-check slot4B<=+0x8 | — | PARSE-NO-CHECK |
| 86 | SET_FCC_CHANNEL | drv_cmd_set_fcc_channel | 0x40 | kstrtos8@0x40a10[sp+0x4/1B] **⇒** ret:cbz w0@0x40a14->ok slot1B<=+0x8 | — |  |

### 内存管理（32 项）

| i | 命令 | handler | 帧 | 解析 → 约束（指令级） | 拷贝/输出 | 备注 |
|---|---|---|---|---|---|---|
| 0 | P2P_DEV_ADDR | drv_cmd_p2p_dev_addr | 0x30 | — **⇒**  | __check_object_size@0x3870c;__arch_copy_to_user@0x38740 |  |
| 7 | GETCOUNTRYREV | drv_cmd_get_country | 0x60 | — **⇒**  | qdf_mem_copy(len=0x2)@0x38984;scnprintf(limit=0x14)@0x389b8;__check_object_size@0x38a1c;_… | OUT-FMT-HAS-S |
| 11 | GETROAMTRIGGER | drv_cmd_get_roam_trigger | 0x60 | — **⇒**  | scnprintf(limit=0x20)@0x38f08;__check_object_size@0x38f2c;__arch_copy_to_user@0x38f60 | OUT-FMT-HAS-S |
| 13 | GETROAMSCANPERIOD | drv_cmd_get_roam_scan_period | 0x60 | — **⇒**  | scnprintf(limit=0x20)@0x3920c;__check_object_size@0x39230;__arch_copy_to_user@0x39264 | OUT-FMT-HAS-S |
| 15 | GETROAMSCANREFRESHPERIOD | drv_cmd_get_roam_scan_refresh_period | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x39438;__check_object_size@0x3945c;__arch_copy_to_user@0x39490 | OUT-FMT-HAS-S |
| 17 | GETROAMMODE | drv_cmd_get_roam_mode | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x396dc;__check_object_size@0x39700;__arch_copy_to_user@0x39734 | OUT-FMT-HAS-S |
| 19 | GETROAMDELTA | drv_cmd_get_roam_delta | 0x70 | — **⇒**  | scnprintf(limit=0x20)@0x399e0;__check_object_size@0x39a04;__arch_copy_to_user@0x39a38 | OUT-FMT-HAS-S |
| 20 | GETBAND | drv_cmd_get_band | 0x60 | — **⇒**  | scnprintf(limit=0x20)@0x39b90;__check_object_size@0x39bb4;__arch_copy_to_user@0x39be8 | OUT-FMT-HAS-S |
| 22 | GETROAMSCANCHANNELS | drv_cmd_get_roam_scan_channels | 0x280 | — **⇒**  | memset@0x3a0bc;scnprintf(limit=0x80)@0x3a134;scnprintf@0x3a190;__check_object_size@0x3a1d… | FMT-LIMIT-REG;OUT-FMT-HAS-S |
| 23 | GETCCXMODE | drv_cmd_get_ccx_mode | 0x60 | — **⇒**  | scnprintf(limit=0x20)@0x3a360;__check_object_size@0x3a384;__arch_copy_to_user@0x3a3b8 | OUT-FMT-HAS-S |
| 24 | GETOKCMODE | drv_cmd_get_okc_mode | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3a4fc;__check_object_size@0x3a520;__arch_copy_to_user@0x3a554 | OUT-FMT-HAS-S |
| 25 | GETFASTROAM | drv_cmd_get_fast_roam | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3a630;__check_object_size@0x3a654;__arch_copy_to_user@0x3a688 | OUT-FMT-HAS-S |
| 26 | GETFASTTRANSITION | drv_cmd_get_fast_transition | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3a768;__check_object_size@0x3a78c;__arch_copy_to_user@0x3a7c0 | OUT-FMT-HAS-S |
| 28 | SENDACTIONFRAME | drv_cmd_send_action_frame | 0xa0 | mac_pton@0x3aba4[sp+0x10/0B];sscanf@0x3ac38[%s(31)] fmt=\'%31s \' out=sp+0x18;kstrtoint@0x3ac50[sp+0x4/4B];hex_to_bin@0… **⇒** ret:tbz w0@0x3aba8->ok;ret:cmp#0x1;b.ne@0x3ac3c slot32B<=+0x38;no-check slot4B<=+0x8 | __qdf_mem_free@0x3ab3c;__qdf_mem_malloc@0x3ad30 |  |
| 29 | GETROAMSCANCHANNELMINTIME | drv_cmd_get_roam_scan_channel_min_time | 0x60 | — **⇒**  | scnprintf(limit=0x20)@0x3ae98;__check_object_size@0x3aed4;__arch_copy_to_user@0x3af08 | OUT-FMT-HAS-S |
| 31 | GETSCANCHANNELTIME | drv_cmd_get_scan_channel_time | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3b150;__check_object_size@0x3b174;__arch_copy_to_user@0x3b1a8 | OUT-FMT-HAS-S |
| 33 | GETSCANHOMETIME | drv_cmd_get_scan_home_time | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3b3f0;__check_object_size@0x3b414;__arch_copy_to_user@0x3b448 | OUT-FMT-HAS-S |
| 35 | GETROAMINTRABAND | drv_cmd_get_roam_intra_band | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3b640;__check_object_size@0x3b664;__arch_copy_to_user@0x3b698 | OUT-FMT-HAS-S |
| 37 | GETSCANNPROBES | drv_cmd_get_scan_n_probes | 0x60 | — **⇒**  | scnprintf(limit=0x20)@0x3b928;__check_object_size@0x3b94c;__arch_copy_to_user@0x3b980 | OUT-FMT-HAS-S |
| 39 | GETSCANHOMEAWAYTIME | drv_cmd_get_scan_home_away_time | 0x60 | — **⇒**  | scnprintf(limit=0x20)@0x3bc10;__check_object_size@0x3bc34;__arch_copy_to_user@0x3bc68 | OUT-FMT-HAS-S |
| 42 | GETWESMODE | drv_cmd_get_wes_mode | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3c028;__check_object_size@0x3c04c;__arch_copy_to_user@0x3c080 | OUT-FMT-HAS-S |
| 44 | GETOPPORTUNISTICRSSIDIFF | drv_cmd_get_opportunistic_rssi_diff | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3c268;__check_object_size@0x3c28c;__arch_copy_to_user@0x3c2c0 | OUT-FMT-HAS-S |
| 46 | GETROAMRESCANRSSIDIFF | drv_cmd_get_roam_rescan_rssi_diff | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3c4a8;__check_object_size@0x3c4cc;__arch_copy_to_user@0x3c500 | OUT-FMT-HAS-S |
| 52 | GETROAMSCANCONTROL | drv_cmd_get_roam_scan_control | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3ce68;__check_object_size@0x3ce8c;__arch_copy_to_user@0x3cec0 | OUT-FMT-HAS-S |
| 57 | GETDWELLTIME | drv_cmd_get_dwell_time | 0x60 | — **⇒**  | memset@0x3d2a4;scnprintf(limit=0x20)@0x3d400;__check_object_size@0x3d428;__arch_copy_to_u… |  |
| 69 | SETCCKMIE | drv_cmd_set_cckm_ie | 0x50 | hex_to_bin@0x3ead8[slot?];hex_to_bin@0x3eae8[slot?] **⇒** none | __qdf_mem_malloc@0x3eab8;__qdf_mem_free@0x3eb50;__qdf_mem_free@0x3ebec | PARSE-NO-CHECK |
| 71 | CCXPLMREQ | drv_cmd_ccx_plm_req | 0x90 | sscanf@0x3f230[%s(31)] fmt=\'%31s \' out=sp+0x8;kstrtoint@0x3f248[sp+0x4/4B];sscanf@0x3f29c[fmt-unresolved] out=sp+0x8;… **⇒** ret:cmp#0x1;b.ne@0x3f234 slot32B<=+0x28;ret:tbnz w0@0x3f24c->fail? val@cmp#0x0;? slot4B<=+0x28;ret:cmp#0x1;b.ne@0x3f2a0… | __qdf_mem_malloc@0x3f1cc;__qdf_mem_free@0x3f85c | FMT-UNRESOLVED;FMT-UNRESOLVED;FMT-UNRES… |
| 76 | GETDFSSCANMODE | drv_cmd_get_dfs_scan_mode | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x3ff78;__check_object_size@0x3ff9c;__arch_copy_to_user@0x3ffd0 | OUT-FMT-HAS-S |
| 82 | RSSI | drv_cmd_get_rssi | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x40784;__check_object_size@0x407a8;__arch_copy_to_user@0x407dc | OUT-FMT-HAS-S |
| 83 | LINKSPEED | drv_cmd_get_linkspeed | 0x50 | — **⇒**  | scnprintf(limit=0x20)@0x408b8;__check_object_size@0x408dc;__arch_copy_to_user@0x40910 | OUT-FMT-HAS-S |
| 89 | GETANTENNAMODE | drv_cmd_get_antenna_mode | 0x60 | — **⇒**  | scnprintf(limit=0x20)@0x4115c;__check_object_size@0x41180;__arch_copy_to_user@0x411b4 | OUT-FMT-HAS-S |
| 92 | GET_ANI_LEVEL | drv_cmd_get_ani_level | 0x180 | sscanf@0x41cb4[%d] fmt=\'%d \' out=sp+0x1c;sscanf@0x41df0[fmt-unresolved] out=sp+0x1c **⇒** ret:cmp#0x1;b.ne@0x41cb8 val[0x15,..]@cmp#0x15;b.lo slot4B<=+0x20;ret:cmp#0x1;b.ne@0x41df4 | qdf_mem_set@0x41e98;__qdf_mem_malloc@0x41f08;scnprintf@0x41fa8;__check_object_size@0x4207… | FMT-UNRESOLVED;FMT-LIMIT-REG |

### 状态管理（15 项）

| i | 命令 | handler | 帧 | 解析 → 约束（指令级） | 拷贝/输出 | 备注 |
|---|---|---|---|---|---|---|
| 9 | SET_AP_WPS_P2P_IE | drv_cmd_dummy | 0x10 | — **⇒**  | — | no-parse-no-copy |
| 53 | BTCOEXMODE | drv_cmd_bt_coex_mode | 0x30 | — **⇒**  | — | no-parse-no-copy |
| 54 | SCAN-ACTIVE | drv_cmd_scan_active | 0x0 | — **⇒**  | — | no-parse-no-copy |
| 55 | SCAN-PASSIVE | drv_cmd_scan_passive | 0x0 | — **⇒**  | — | no-parse-no-copy |
| 60 | SETIBSSBEACONOUIDATA | drv_cmd_set_ibss_beacon_oui_data | 0x0 | — **⇒**  | — | no-parse-no-copy |
| 64 | GETIBSSPEERINFOALL | drv_cmd_get_ibss_peer_info_all | 0x0 | — **⇒**  | — | no-parse-no-copy |
| 65 | GETIBSSPEERINFO | drv_cmd_get_ibss_peer_info | 0x0 | — **⇒**  | — | no-parse-no-copy |
| 66 | SETIBSSTXFAILEVENT | drv_cmd_set_ibss_tx_fail_event | 0x0 | — **⇒**  | — | no-parse-no-copy |
| 84 | RXFILTER-REMOVE | drv_cmd_rx_filter_remove | 0x10 | — **⇒**  | — | no-parse-no-copy |
| 85 | RXFILTER-ADD | drv_cmd_rx_filter_add | 0x10 | — **⇒**  | — | no-parse-no-copy |
| 93 | STOP | drv_cmd_dummy | 0x10 | — **⇒**  | — | no-parse-no-copy |
| 94 | RXFILTER-START | drv_cmd_dummy | 0x10 | — **⇒**  | — | no-parse-no-copy |
| 95 | RXFILTER-STOP | drv_cmd_dummy | 0x10 | — **⇒**  | — | no-parse-no-copy |
| 96 | BTCOEXSCAN-START | drv_cmd_dummy | 0x10 | — **⇒**  | — | no-parse-no-copy |
| 97 | BTCOEXSCAN-STOP | drv_cmd_dummy | 0x10 | — **⇒**  | — | no-parse-no-copy |

### 并发管理（4 项）

| i | 命令 | handler | 帧 | 解析 → 约束（指令级） | 拷贝/输出 | 备注 |
|---|---|---|---|---|---|---|
| 68 | GETTSMSTATS | drv_cmd_get_tsm_stats | 0x140 | kstrtou8@0x3e53c[sp+0x4c/1B] **⇒** ret:tbnz w0@0x3e540->ok val[0x10,..]@cmp#0x10;b.lo slot1B<=+0x50 | osif_request_alloc@0x3e69c;osif_request_put@0x3e724;osif_request_put@0x3e808;osif_request… | locks;FMT-LIMIT-REG;OUT-FMT-HAS-S |
| 77 | GETLINKSTATUS | drv_cmd_get_link_status | 0x70 | — **⇒**  | osif_request_alloc@0x400d0;scnprintf(limit=0x20)@0x40194;__check_object_size@0x401b8;__ar… | locks;OUT-FMT-HAS-S |
| 90 | SET_DISABLE_CHANNEL_LIST | drv_cmd_set_disable_chan_list | 0x220 | sscanf@0x41304[%d] fmt=\'%d \' out=sp+0x14;sscanf@0x4153c[fmt-unresolved] out=sp+0x14 **⇒** ret:cmp#0x1;b.ne@0x41308 val[0x62,..]@cmp#0x62;b.lo slot4B<=+0x18;ret:cmp#0x1;b.ne@0x41540 val[0xf,..]@cmp#0xf;b.lo | __qdf_mem_malloc@0x41484;__qdf_mem_malloc@0x414ac;__qdf_mem_free@0x41718 | FMT-UNRESOLVED;locks |
| 91 | GET_DISABLE_CHANNEL_LIST | drv_cmd_get_disable_chan_list | 0x280 | — **⇒**  | memset@0x41998;scnprintf@0x41a30;scnprintf@0x41a8c;__check_object_size@0x41ad0;__arch_cop… | locks;FMT-LIMIT-REG;OUT-FMT-HAS-S |

### 外部交互（23 项）

| i | 命令 | handler | 帧 | 解析 → 约束（指令级） | 拷贝/输出 | 备注 |
|---|---|---|---|---|---|---|
| 1 | P2P_SET_NOA | drv_cmd_p2p_set_noa | 0x10 | — **⇒**  | — | no-parse-no-copy |
| 2 | P2P_SET_PS | drv_cmd_p2p_set_ps | 0x10 | — **⇒**  | — | no-parse-no-copy |
| 4 | SETWMMPS | drv_cmd_set_wmmps | 0x10 | — **⇒**  | — | no-parse-no-copy |
| 8 | SETSUSPENDMODE | drv_cmd_set_suspend_mode | 0x30 | kstrtou8@0x38b40[sp+0x4/1B] **⇒** ret:tbnz w0@0x38b44->ok slot1B<=+0x8 | — |  |
| 12 | SETROAMSCANPERIOD | drv_cmd_set_roam_scan_period | 0x50 | kstrtou8@0x39024[sp+0x4/1B] **⇒** ret:tbnz w0@0x39028->ok slot1B<=+0x8 | — |  |
| 16 | SETROAMMODE | drv_cmd_set_roam_mode | 0x40 | kstrtou8@0x39554[sp+0x4/1B] **⇒** ret:tbnz w0@0x39558->ok slot1B<=+0x8 | — |  |
| 21 | SETROAMSCANCHANNELS | drv_cmd_set_roam_scan_channels | 0x1f0 | — **⇒**  | memset@0x39d08;memset@0x39d60 |  |
| 40 | REASSOC | drv_cmd_reassoc | 0x50 | mac_pton@0x3bdf4[sp+0x8/0B] **⇒** ret:tbz w0@0x3bdf8->ok | memcpy(len=0x18)@0x3bde8 |  |
| 47 | SETFASTROAM | drv_cmd_set_fast_roam | 0x40 | kstrtou8@0x3c5c8[sp+0x4/1B] **⇒** ret:tbnz w0@0x3c5cc->ok slot1B<=+0x8 | — |  |
| 49 | FASTREASSOC | drv_cmd_fast_reassoc | 0x70 | — **⇒**  | qdf_mem_copy(len=0x6)@0x3c9a4;qdf_mem_copy(len=0x6)@0x3ca20;qdf_mem_copy(len=0x6)@0x3ca60 |  |
| 59 | MIRACAST | drv_cmd_miracast | 0x40 | kstrtou8@0x3d8e8[sp+0x4/1B] **⇒** ret:tbnz w0@0x3d8ec->ok val[0x3,..]@cmp#0x3;b.lo slot1B<=+0x8 | — |  |
| 62 | SETRMCACTIONPERIOD | drv_cmd_set_rmc_action_period | 0x70 | sscanf@0x3de80[%s(31)] fmt=\'%31s \' out=sp+0x8;kstrtoint@0x3de98[sp+0x4/4B] **⇒** ret:cmp#0x1;b.ne@0x3de84 slot32B<=+0x28;ret:tbnz w0@0x3de9c->ok slot4B<=+0x28 | — |  |
| 63 | SETRMCTXRATE | drv_cmd_set_rmc_tx_rate | 0xa0 | sscanf@0x3e0bc[%s(31)] fmt=\'%31s \' out=sp+0x38;kstrtoint@0x3e0d4[sp+0xc/4B] **⇒** ret:cmp#0x1;b.ne@0x3e0c0 slot32B<=+0x58;ret:tbnz w0@0x3e0d8->ok val[0x0,0x48]@cmp#0x48;b.hi slot4B<=+0x10 | memcpy(len=0x6)@0x3e1e4 |  |
| 67 | SETCCXROAMSCANCHANNELS | drv_cmd_set_ccx_roam_scan_channels | 0x1d0 | — **⇒**  | memset@0x3e304 |  |
| 70 | CCXBEACONREQ | drv_cmd_ccx_beacon_req | 0x140 | sscanf@0x3ed10[%s(31)] fmt=\'%31s \' out=sp+0xb0;kstrtou8@0x3ed28[sp+0x44/1B];sscanf@0x3ee14[fmt-unresolved] out=sp+0xb… **⇒** ret:cmp#0x1;b.ne@0x3ed14 slot32B<=+0xd0;ret:tbnz w0@0x3ed2c->ok val@cmp#0x8;? slot1B<=+0x48;ret:cmp#0x1;b.ne@0x3ee18;re… | — | FMT-UNRESOLVED |
| 74 | MAXTXPOWER | drv_cmd_max_tx_power | 0x90 | kstrtoint@0x3fb8c[sp+0x14/4B] **⇒** no-check slot4B<=+0x18 | — | PARSE-NO-CHECK |
| 75 | SETDFSSCANMODE | drv_cmd_set_dfs_scan_mode | 0x40 | kstrtou8@0x3fdc8[sp+0x4/1B] **⇒** ret:tbnz w0@0x3fdcc->ok val[0x0,0x2]@cmp#0x3;b.hs slot1B<=+0x8 | — |  |
| 78 | TDLSSECONDARYCHANNELOFFSET | drv_cmd_tdls_secondary_channel_offset | 0x30 | sscanf@0x403c0[%d] fmt=\'%d\' out=sp+0x4 **⇒** ret:cmp#0x1;b.ne@0x403c4 slot4B<=+0x8 | — |  |
| 79 | TDLSOFFCHANNELMODE | drv_cmd_tdls_off_channel_mode | 0x30 | sscanf@0x40498[%d] fmt=\'%d\' out=sp+0x4 **⇒** ret:cmp#0x1;b.ne@0x4049c slot4B<=+0x8 | — |  |
| 80 | TDLSOFFCHANNEL | drv_cmd_tdls_off_channel | 0x30 | sscanf@0x40570[%d] fmt=\'%d\' out=sp+0x4 **⇒** ret:cmp#0x1;b.ne@0x40574 slot4B<=+0x8 | — |  |
| 81 | TDLSSCAN | drv_cmd_tdls_scan | 0x30 | sscanf@0x4069c[%d] fmt=\'%d\' out=sp+0x4 **⇒** ret:cmp#0x1;b.ne@0x406a0 slot4B<=+0x8 | — |  |
| 87 | CHANNEL_SWITCH | drv_cmd_set_channel_switch | 0x50 | sscanf@0x40cac[%u+%u] fmt=\'%u %u\' out=sp+0x4,sp+0x0 **⇒** ret:cmp#0x2;b.ne@0x40cb0 slot4B<=+0x8 | — |  |
| 88 | SETANTENNAMODE | drv_cmd_set_antenna_mode | 0x60 | sscanf@0x40f78[%s(31)] fmt=\'%31s \' out=sp+0x8;kstrtoint@0x40f90[sp+0x4/4B] **⇒** ret:cmp#0x1;b.ne@0x40f7c slot32B<=+0x28;ret:tbnz w0@0x40f94->ok slot4B<=+0x28 | — |  |

### §2.A 全量 CSV 快照（79 列宽的压缩版：前 10 列原文）

```
i,name,handler,handler_size,frame_size,parse_funcs,range_check,in_short,copy_ops,notes
0,P2P_DEV_ADDR,drv_cmd_p2p_dev_addr,224,48,,,1,__check_object_size@0x3870c;__arch_copy_to_user@0x38740,
1,P2P_SET_NOA,drv_cmd_p2p_set_noa,28,16,,,1,,no-parse-no-copy
2,P2P_SET_PS,drv_cmd_p2p_set_ps,28,16,,,1,,no-parse-no-copy
3,SETBAND,drv_cmd_set_band,212,48,kstrtou8@0x38814[sp+0x4/1B],ret:cbz w0@0x38818->fail? slot1B<=+0x8,1,,
4,SETWMMPS,drv_cmd_set_wmmps,24,16,,,1,,no-parse-no-copy
5,COUNTRY,drv_cmd_country,116,32,,,1,,no-parse-no-copy
6,SETCOUNTRYREV,drv_cmd_country,116,32,,,1,,no-parse-no-copy
7,GETCOUNTRYREV,drv_cmd_get_country,388,96,,,1,qdf_mem_copy(len=0x2)@0x38984;scnprintf(limit=0x14)@0x389b8;__check_object_size@0x38a1c;__arch_copy_to_user@0x38a50,OUT-FMT-HAS-S
8,SETSUSPENDMODE,drv_cmd_set_suspend_mode,340,48,kstrtou8@0x38b40[sp+0x4/1B],ret:tbnz w0@0x38b44->ok slot1B<=+0x8,1,,
9,SET_AP_WPS_P2P_IE,drv_cmd_dummy,76,16,,,1,,no-parse-no-copy
10,SETROAMTRIGGER,drv_cmd_set_roam_trigger,456,80,kstrtos8@0x38cbc[sp+0x4/1B],ret:tbnz w0@0x38cc0->ok slot1B<=+0x8,1,,
11,GETROAMTRIGGER,drv_cmd_get_roam_trigger,412,96,,,1,scnprintf(limit=0x20)@0x38f08;__check_object_size@0x38f2c;__arch_copy_to_user@0x38f60,OUT-FMT-HAS-S
12,SETROAMSCANPERIOD,drv_cmd_set_roam_scan_period,336,80,kstrtou8@0x39024[sp+0x4/1B],ret:tbnz w0@0x39028->ok slot1B<=+0x8,1,,
13,GETROAMSCANPERIOD,drv_cmd_get_roam_scan_period,432,96,,,1,scnprintf(limit=0x20)@0x3920c;__check_object_size@0x39230;__arch_copy_to_user@0x39264,OUT-FMT-HAS-S
14,SETROAMSCANREFRESHPERIOD,drv_cmd_set_roam_scan_refresh_period,236,32,kstrtou8@0x39310[sp+0x4/1B],ret:tbnz w0@0x39314->ok slot1B<=+0x8,1,,
15,GETROAMSCANREFRESHPERIOD,drv_cmd_get_roam_scan_refresh_period,324,80,,,1,scnprintf(limit=0x20)@0x39438;__check_object_size@0x3945c;__arch_copy_to_user@0x39490,OUT-FMT-HAS-S
16,SETROAMMODE,drv_cmd_set_roam_mode,368,64,kstrtou8@0x39554[sp+0x4/1B],ret:tbnz w0@0x39558->ok slot1B<=+0x8,1,,
17,GETROAMMODE,drv_cmd_get_roam_mode,304,80,,,1,scnprintf(limit=0x20)@0x396dc;__check_object_size@0x39700;__arch_copy_to_user@0x39734,OUT-FMT-HAS-S
18,SETROAMDELTA,drv_cmd_set_roam_delta,348,64,kstrtou8@0x397fc[sp+0x4/1B],ret:tbnz w0@0x39800->ok val[0x0,0x64]@cmp#0x65;b.hs slot1B<=+0x8,1,,
19,GETROAMDELTA,drv_cmd_get_roam_delta,416,112,,,1,scnprintf(limit=0x20)@0x399e0;__check_object_size@0x39a04;__arch_copy_to_user@0x39a38,OUT-FMT-HAS-S
20,GETBAND,drv_cmd_get_band,440,96,,,1,scnprintf(limit=0x20)@0x39b90;__check_object_size@0x39bb4;__arch_copy_to_user@0x39be8,OUT-FMT-HAS-S
21,SETROAMSCANCHANNELS,drv_cmd_set_roam_scan_channels,1024,496,,,1,memset@0x39d08;memset@0x39d60,
22,GETROAMSCANCHANNELS,drv_cmd_get_roam_scan_channels,552,640,,,1,memset@0x3a0bc;scnprintf(limit=0x80)@0x3a134;scnprintf@0x3a190;__check_object_size@0x3a1d0;__arch_copy_to_user@0x3a204,FMT-LIMIT-REG;OUT-FMT-HAS-S
23,GETCCXMODE,drv_cmd_get_ccx_mode,424,96,,,1,scnprintf(limit=0x20)@0x3a360;__check_object_size@0x3a384;__arch_copy_to_user@0x3a3b8,OUT-FMT-HAS-S
24,GETOKCMODE,drv_cmd_get_okc_mode,408,80,,,1,scnprintf(limit=0x20)@0x3a4fc;__check_object_size@0x3a520;__arch_copy_to_user@0x3a554,OUT-FMT-HAS-S
25,GETFASTROAM,drv_cmd_get_fast_roam,308,80,,,1,scnprintf(limit=0x20)@0x3a630;__check_object_size@0x3a654;__arch_copy_to_user@0x3a688,OUT-FMT-HAS-S
26,GETFASTTRANSITION,drv_cmd_get_fast_transition,308,80,,,1,scnprintf(limit=0x20)@0x3a768;__check_object_size@0x3a78c;__arch_copy_to_user@0x3a7c0,OUT-FMT-HAS-S
27,SETROAMSCANCHANNELMINTIME,drv_cmd_set_roam_scan_channel_min_time,384,64,kstrtou8@0x3a88c[sp+0x4/1B],ret:tbnz w0@0x3a890->ok slot1B<=+0x8,1,,
28,SENDACTIONFRAME,drv_cmd_send_action_frame,1128,160,mac_pton@0x3aba4[sp+0x10/0B];sscanf@0x3ac38[%s(31)] fmt=\'%31s \' out=sp+0x18;kstrtoint@0x3ac50[sp+0x4/4B];hex_to_bin@0x3ad84[slot?];hex_to_bin@0x3ada0[slot?],ret:tbz w0@0x3aba8->ok;ret:cmp#0x1;b.ne@0x3ac3c slot32B<=+0x38;no-check slot4B<=+0x8,1,__qdf_mem_free@0x3ab3c;__qdf_mem_malloc@0x3ad30,
29,GETROAMSCANCHANNELMINTIME,drv_cmd_get_roam_scan_channel_min_time,352,96,,,1,scnprintf(limit=0x20)@0x3ae98;__check_object_size@0x3aed4;__arch_copy_to_user@0x3af08,OUT-FMT-HAS-S
30,SETSCANCHANNELTIME,drv_cmd_set_scan_channel_time,352,64,kstrtou16@0x3afd4[sp+0x4/2B],ret:tbnz w0@0x3afd8->ok slot2B<=+0x8,1,,
31,GETSCANCHANNELTIME,drv_cmd_get_scan_channel_time,316,80,,,1,scnprintf(limit=0x20)@0x3b150;__check_object_size@0x3b174;__arch_copy_to_user@0x3b1a8,OUT-FMT-HAS-S
32,SETSCANHOMETIME,drv_cmd_set_scan_home_time,352,64,kstrtou16@0x3b274[sp+0x4/2B],ret:tbnz w0@0x3b278->ok slot2B<=+0x8,1,,
33,GETSCANHOMETIME,drv_cmd_get_scan_home_time,316,80,,,1,scnprintf(limit=0x20)@0x3b3f0;__check_object_size@0x3b414;__arch_copy_to_user@0x3b448,OUT-FMT-HAS-S
34,SETROAMINTRABAND,drv_cmd_set_roam_intra_band,280,48,kstrtou8@0x3b508[sp+0x4/1B],ret:tbnz w0@0x3b50c->ok slot1B<=+0x8,1,,
35,GETROAMINTRABAND,drv_cmd_get_roam_intra_band,308,80,,,1,scnprintf(limit=0x20)@0x3b640;__check_object_size@0x3b664;__arch_copy_to_user@0x3b698,OUT-FMT-HAS-S
36,SETSCANNPROBES,drv_cmd_set_scan_n_probes,352,64,kstrtou8@0x3b764[sp+0x4/1B],ret:tbnz w0@0x3b768->ok slot1B<=+0x8,1,,
37,GETSCANNPROBES,drv_cmd_get_scan_n_probes,380,96,,,1,scnprintf(limit=0x20)@0x3b928;__check_object_size@0x3b94c;__arch_copy_to_user@0x3b980,OUT-FMT-HAS-S
38,SETSCANHOMEAWAYTIME,drv_cmd_set_scan_home_away_time,348,64,kstrtou16@0x3ba40[sp+0x4/2B],ret:tbnz w0@0x3ba44->ok val[0x0,0x12c]@cmp#0x12d;b.hs slot2B<=+0x8,1,,
39,GETSCANHOMEAWAYTIME,drv_cmd_get_scan_home_away_time,388,96,,,1,scnprintf(limit=0x20)@0x3bc10;__check_object_size@0x3bc34;__arch_copy_to_user@0x3bc68,OUT-FMT-HAS-S
40,REASSOC,drv_cmd_reassoc,464,80,mac_pton@0x3bdf4[sp+0x8/0B],ret:tbz w0@0x3bdf8->ok,1,memcpy(len=0x18)@0x3bde8,
41,SETWESMODE,drv_cmd_set_wes_mode,284,64,kstrtou8@0x3bef8[sp+0x4/1B],ret:tbnz w0@0x3befc->ok slot1B<=+0x8,1,,
42,GETWESMODE,drv_cmd_get_wes_mode,300,80,,,1,scnprintf(limit=0x20)@0x3c028;__check_object_size@0x3c04c;__arch_copy_to_user@0x3c080,OUT-FMT-HAS-S
43,SETOPPORTUNISTICRSSIDIFF,drv_cmd_set_opportunistic_rssi_diff,268,64,kstrtou8@0x3c148[sp+0x4/1B],ret:tbnz w0@0x3c14c->ok slot1B<=+0x8,1,,
44,GETOPPORTUNISTICRSSIDIFF,drv_cmd_get_opportunistic_rssi_diff,300,80,,,1,scnprintf(limit=0x20)@0x3c268;__check_object_size@0x3c28c;__arch_copy_to_user@0x3c2c0,OUT-FMT-HAS-S
45,SETROAMRESCANRSSIDIFF,drv_cmd_set_roam_rescan_rssi_diff,272,64,kstrtou8@0x3c38c[sp+0x4/1B],ret:tbnz w0@0x3c390->ok slot1B<=+0x8,1,,
46,GETROAMRESCANRSSIDIFF,drv_cmd_get_roam_rescan_rssi_diff,300,80,,,1,scnprintf(limit=0x20)@0x3c4a8;__check_object_size@0x3c4cc;__arch_copy_to_user@0x3c500,OUT-FMT-HAS-S
47,SETFASTROAM,drv_cmd_set_fast_roam,304,64,kstrtou8@0x3c5c8[sp+0x4/1B],ret:tbnz w0@0x3c5cc->ok slot1B<=+0x8,1,,
48,SETFASTTRANSITION,drv_cmd_set_fast_transition,272,48,kstrtou8@0x3c6f4[sp+0x4/1B],ret:tbnz w0@0x3c6f8->ok slot1B<=+0x8,1,,
49,FASTREASSOC,drv_cmd_fast_reassoc,752,112,,,1,qdf_mem_copy(len=0x6)@0x3c9a4;qdf_mem_copy(len=0x6)@0x3ca20;qdf_mem_copy(len=0x6)@0x3ca60,
50,SETROAMSCANCONTROL,drv_cmd_set_roam_scan_control,284,64,kstrtou8@0x3caf8[sp+0x4/1B],ret:tbnz w0@0x3cafc->ok slot1B<=+0x8,1,,
51,SETOKCMODE,drv_cmd_set_okc_mode,576,80,kstrtouint@0x3cccc[sp+0x14/4B],ret:tbnz w0@0x3ccd0->ok val[0x2,..]@cmp#0x2;b.lo slot4B<=+0x18,1,,
52,GETROAMSCANCONTROL,drv_cmd_get_roam_scan_control,300,80,,,1,scnprintf(limit=0x20)@0x3ce68;__check_object_size@0x3ce8c;__arch_copy_to_user@0x3cec0,OUT-FMT-HAS-S
53,BTCOEXMODE,drv_cmd_bt_coex_mode,256,48,,,1,,no-parse-no-copy
54,SCAN-ACTIVE,drv_cmd_scan_active,16,0,,,1,,no-parse-no-copy
55,SCAN-PASSIVE,drv_cmd_scan_passive,12,0,,,1,,no-parse-no-copy
56,CONCSETDWELLTIME,drv_cmd_conc_set_dwell_time,508,48,kstrtouint@0x3d0f4[sp+0x4/4B];kstrtouint@0x3d138[sp+0x4/4B],ret:cbnz w0@0x3d0fc->ok val[0x0,0x2710]@cmp#0x2711;b.hs slot4B<=+0x8;ret:cbnz w0@0x3d140->ok val[0x0,0x2710]@cmp#0x2711;b.hs slot4B<=+0x8,1,,
57,GETDWELLTIME,drv_cmd_get_dwell_time,632,96,,,1,memset@0x3d2a4;scnprintf(limit=0x20)@0x3d400;__check_object_size@0x3d428;__arch_copy_to_user@0x3d45c,
58,SETDWELLTIME,drv_cmd_set_dwell_time,924,48,kstrtouint@0x3d5a8[sp+0x4/4B];kstrtouint@0x3d66c[sp+0x4/4B];kstrtouint@0x3d6a8[sp+0x4/4B];kstrtouint@0x3d6e4[sp+0x4/4B],ret:cbnz w0@0x3d5ac->ok val[0x0,0x2710]@cmp#0x2711;b.lo slot4B<=+0x8;ret:cbnz w0@0x3d670->ok val[0x0,0x2710]@cmp#0x2711;b.hs slot4B<=+0x8;ret:cbnz w0@0x3d6ac->ok val[0x0,0x2710]@cmp#0x2711;b.hs slot4B<=+0x8;ret:cbnz w0@0x3d6e8->ok val[0x0,0x2710]@cmp#0x2711;b.hs slot4B<=+0x8,1,,
59,MIRACAST,drv_cmd_miracast,408,64,kstrtou8@0x3d8e8[sp+0x4/1B],ret:tbnz w0@0x3d8ec->ok val[0x3,..]@cmp#0x3;b.lo slot1B<=+0x8,1,,
60,SETIBSSBEACONOUIDATA,drv_cmd_set_ibss_beacon_oui_data,8,0,,,1,,no-parse-no-copy
61,SETRMCENABLE,drv_cmd_set_rmc_enable,744,112,sscanf@0x3dba8[%s(31)] fmt=\'%31s \' out=sp+0x8;kstrtoint@0x3dbc0[sp+0x4/4B],ret:cmp#0x1;b.ne@0x3dbac slot32B<=+0x28;ret:tbnz w0@0x3dbc4->ok slot4B<=+0x28,1,,
62,SETRMCACTIONPERIOD,drv_cmd_set_rmc_action_period,660,112,sscanf@0x3de80[%s(31)] fmt=\'%31s \' out=sp+0x8;kstrtoint@0x3de98[sp+0x4/4B],ret:cmp#0x1;b.ne@0x3de84 slot32B<=+0x28;ret:tbnz w0@0x3de9c->ok slot4B<=+0x28,1,,
63,SETRMCTXRATE,drv_cmd_set_rmc_tx_rate,784,160,sscanf@0x3e0bc[%s(31)] fmt=\'%31s \' out=sp+0x38;kstrtoint@0x3e0d4[sp+0xc/4B],ret:cmp#0x1;b.ne@0x3e0c0 slot32B<=+0x58;ret:tbnz w0@0x3e0d8->ok val[0x0,0x48]@cmp#0x48;b.hi slot4B<=+0x10,1,memcpy(len=0x6)@0x3e1e4,
64,GETIBSSPEERINFOALL,drv_cmd_get_ibss_peer_info_all,8,0,,,1,,no-parse-no-copy
65,GETIBSSPEERINFO,drv_cmd_get_ibss_peer_info,8,0,,,1,,no-parse-no-copy
66,SETIBSSTXFAILEVENT,drv_cmd_set_ibss_tx_fail_event,8,0,,,1,,no-parse-no-copy
67,SETCCXROAMSCANCHANNELS,drv_cmd_set_ccx_roam_scan_channels,480,464,,,1,memset@0x3e304,
68,GETTSMSTATS,drv_cmd_get_tsm_stats,1380,320,kstrtou8@0x3e53c[sp+0x4c/1B],ret:tbnz w0@0x3e540->ok val[0x10,..]@cmp#0x10;b.lo slot1B<=+0x50,1,osif_request_alloc@0x3e69c;osif_request_put@0x3e724;osif_request_put@0x3e808;osif_request_put@0x3e8b8;scnprintf@0x3e964;__check_object_size@0x3e98c;__arch_copy_to_user@0x3e9c0,locks;FMT-LIMIT-REG;OUT-FMT-HAS-S
69,SETCCKMIE,drv_cmd_set_cckm_ie,496,80,hex_to_bin@0x3ead8[slot?];hex_to_bin@0x3eae8[slot?],none,1,__qdf_mem_malloc@0x3eab8;__qdf_mem_free@0x3eb50;__qdf_mem_free@0x3ebec,PARSE-NO-CHECK
70,CCXBEACONREQ,drv_cmd_ccx_beacon_req,1396,320,sscanf@0x3ed10[%s(31)] fmt=\'%31s \' out=sp+0xb0;kstrtou8@0x3ed28[sp+0x44/1B];sscanf@0x3ee14[fmt-unresolved] out=sp+0xb0;kstrtouint@0x3ee2c[sp+0x40/4B],ret:cmp#0x1;b.ne@0x3ed14 slot32B<=+0xd0;ret:tbnz w0@0x3ed2c->ok val@cmp#0x8;? slot1B<=+0x48;ret:cmp#0x1;b.ne@0x3ee18;ret:tbnz w0@0x3ee30->ok slot4B<=+0x44,0,,FMT-UNRESOLVED
71,CCXPLMREQ,drv_cmd_ccx_plm_req,1860,144,sscanf@0x3f230[%s(31)] fmt=\'%31s \' out=sp+0x8;kstrtoint@0x3f248[sp+0x4/4B];sscanf@0x3f29c[fmt-unresolved] out=sp+0x8;kstrtoint@0x3f2b4[sp+0x4/4B];sscanf@0x3f328[fmt-unresolved] out=sp+0x8;kstrtoint@0x3f340[sp+0x4/4B];sscanf@0x3f400[fmt-unresolved] out=sp+0x8;kstrtoint@0x3f418[sp+0x4/4B];sscanf@0x3f4,ret:cmp#0x1;b.ne@0x3f234 slot32B<=+0x28;ret:tbnz w0@0x3f24c->fail? val@cmp#0x0;? slot4B<=+0x28;ret:cmp#0x1;b.ne@0x3f2a0;ret:tbnz w0@0x3f2b8->fail? slot4B<=+0x28;ret:cmp#0x1;b.ne@0x3f32c;ret:tbnz w0@0x3f344->fail? slot4B<=+0x28;ret:cmp#0x1;b.ne@0x3f404;no-check slot4B<=+0x28;ret:cmp#0x1;b.ne@0x3f484;,0,__qdf_mem_malloc@0x3f1cc;__qdf_mem_free@0x3f85c,FMT-UNRESOLVED;FMT-UNRESOLVED;FMT-UNRESOLVED;FMT-UNRESOLVED;FMT-UNRESOLVED;FMT-UNRESOLVED;FMT-UNRESOLVED;FMT-UNRESOLVED;FMT-UNRESOLVED;FMT-UNRESOLVED
72,SETCCXMODE,drv_cmd_set_ccx_mode,396,64,kstrtou8@0x3f970[sp+0x4/1B],ret:tbnz w0@0x3f974->ok slot1B<=+0x8,1,,
73,SETMCRATE,drv_cmd_set_mc_rate,132,48,kstrtouint@0x3fa88[sp+0x4/4B],no-check slot4B<=+0x8,1,,PARSE-NO-CHECK
74,MAXTXPOWER,drv_cmd_max_tx_power,684,144,kstrtoint@0x3fb8c[sp+0x14/4B],no-check slot4B<=+0x18,1,,PARSE-NO-CHECK
75,SETDFSSCANMODE,drv_cmd_set_dfs_scan_mode,416,64,kstrtou8@0x3fdc8[sp+0x4/1B],ret:tbnz w0@0x3fdcc->ok val[0x0,0x2]@cmp#0x3;b.hs slot1B<=+0x8,1,,
76,GETDFSSCANMODE,drv_cmd_get_dfs_scan_mode,300,80,,,1,scnprintf(limit=0x20)@0x3ff78;__check_object_size@0x3ff9c;__arch_copy_to_user@0x3ffd0,OUT-FMT-HAS-S
77,GETLINKSTATUS,drv_cmd_get_link_status,804,112,,,1,osif_request_alloc@0x400d0;scnprintf(limit=0x20)@0x40194;__check_object_size@0x401b8;__arch_copy_to_user@0x401ec;osif_request_put@0x40350,locks;OUT-FMT-HAS-S
78,TDLSSECONDARYCHANNELOFFSET,drv_cmd_tdls_secondary_channel_offset,212,48,sscanf@0x403c0[%d] fmt=\'%d\' out=sp+0x4,ret:cmp#0x1;b.ne@0x403c4 slot4B<=+0x8,1,,
79,TDLSOFFCHANNELMODE,drv_cmd_tdls_off_channel_mode,212,48,sscanf@0x40498[%d] fmt=\'%d\' out=sp+0x4,ret:cmp#0x1;b.ne@0x4049c slot4B<=+0x8,1,,
80,TDLSOFFCHANNEL,drv_cmd_tdls_off_channel,304,48,sscanf@0x40570[%d] fmt=\'%d\' out=sp+0x4,ret:cmp#0x1;b.ne@0x40574 slot4B<=+0x8,1,,
81,TDLSSCAN,drv_cmd_tdls_scan,204,48,sscanf@0x4069c[%d] fmt=\'%d\' out=sp+0x4,ret:cmp#0x1;b.ne@0x406a0 slot4B<=+0x8,1,,
82,RSSI,drv_cmd_get_rssi,304,80,,,1,scnprintf(limit=0x20)@0x40784;__check_object_size@0x407a8;__arch_copy_to_user@0x407dc,OUT-FMT-HAS-S
83,LINKSPEED,drv_cmd_get_linkspeed,308,80,,,1,scnprintf(limit=0x20)@0x408b8;__check_object_size@0x408dc;__arch_copy_to_user@0x40910,OUT-FMT-HAS-S
84,RXFILTER-REMOVE,drv_cmd_rx_filter_remove,32,16,,,1,,no-parse-no-copy
85,RXFILTER-ADD,drv_cmd_rx_filter_add,32,16,,,1,,no-parse-no-copy
86,SET_FCC_CHANNEL,drv_cmd_set_fcc_channel,372,64,kstrtos8@0x40a10[sp+0x4/1B],ret:cbz w0@0x40a14->ok slot1B<=+0x8,1,,
87,CHANNEL_SWITCH,drv_cmd_set_channel_switch,800,80,sscanf@0x40cac[%u+%u] fmt=\'%u %u\' out=sp+0x4,sp+0x0,ret:cmp#0x2;b.ne@0x40cb0 slot4B<=+0x8,1,,
88,SETANTENNAMODE,drv_cmd_set_antenna_mode,592,96,sscanf@0x40f78[%s(31)] fmt=\'%31s \' out=sp+0x8;kstrtoint@0x40f90[sp+0x4/4B],ret:cmp#0x1;b.ne@0x40f7c slot32B<=+0x28;ret:tbnz w0@0x40f94->ok slot4B<=+0x28,1,,
89,GETANTENNAMODE,drv_cmd_get_antenna_mode,432,96,,,1,scnprintf(limit=0x20)@0x4115c;__check_object_size@0x41180;__arch_copy_to_user@0x411b4,OUT-FMT-HAS-S
90,SET_DISABLE_CHANNEL_LIST,drv_cmd_set_disable_chan_list,1756,544,sscanf@0x41304[%d] fmt=\'%d \' out=sp+0x14;sscanf@0x4153c[fmt-unresolved] out=sp+0x14,ret:cmp#0x1;b.ne@0x41308 val[0x62,..]@cmp#0x62;b.lo slot4B<=+0x18;ret:cmp#0x1;b.ne@0x41540 val[0xf,..]@cmp#0xf;b.lo,0,__qdf_mem_malloc@0x41484;__qdf_mem_malloc@0x414ac;__qdf_mem_free@0x41718,FMT-UNRESOLVED;locks
91,GET_DISABLE_CHANNEL_LIST,drv_cmd_get_disable_chan_list,664,640,,,1,memset@0x41998;scnprintf@0x41a30;scnprintf@0x41a8c;__check_object_size@0x41ad0;__arch_copy_to_user@0x41b04,locks;FMT-LIMIT-REG;OUT-FMT-HAS-S
92,GET_ANI_LEVEL,drv_cmd_get_ani_level,1348,384,sscanf@0x41cb4[%d] fmt=\'%d \' out=sp+0x1c;sscanf@0x41df0[fmt-unresolved] out=sp+0x1c,ret:cmp#0x1;b.ne@0x41cb8 val[0x15,..]@cmp#0x15;b.lo slot4B<=+0x20;ret:cmp#0x1;b.ne@0x41df4,0,qdf_mem_set@0x41e98;__qdf_mem_malloc@0x41f08;scnprintf@0x41fa8;__check_object_size@0x42078;__arch_copy_to_user@0x420ac;__qdf_mem_free@0x42110,FMT-UNRESOLVED;FMT-LIMIT-REG
93,STOP,drv_cmd_dummy,76,16,,,1,,no-parse-no-copy
94,RXFILTER-START,drv_cmd_dummy,76,16,,,1,,no-parse-no-copy
95,RXFILTER-STOP,drv_cmd_dummy,76,16,,,1,,no-parse-no-copy
96,BTCOEXSCAN-START,drv_cmd_dummy,76,16,,,1,,no-parse-no-copy
97,BTCOEXSCAN-STOP,drv_cmd_dummy,76,16,,,1,,no-parse-no-copy
```


## §3 逐 handler 深审（高风险子集，指令地址级）

### 3.1 `drv_cmd_set_dwell_time`（第 58 项，924 B，帧 `0x30`）—— 作为"有界"的正样本

4 个 `kstrtouint`，目标均为 `sp+4`（4 B），每个都完整具备"返回值门 + 值域门"：

```
0x3d5a8  bl   kstrtouint
0x3d5ac  cbnz w0, 0x3d5c0          ; 解析失败 → 错误出口
0x3d5b0  ldr  w1, [sp, #4]
0x3d5b4  mov  w8, #0x2711
0x3d5b8  cmp  w1, w8
0x3d5bc  b.lo 0x3d684              ; < 0x2711 ⇒ 成功臂（bl wlan_scan_cfg_set_active_dwelltime）
```

- 接受区间：`[0, 0x2710]`（0–10000），三条支路（ACTIVE / PASSIVE / 2G）同构，`b.hs` 版本跳失败臂。
- 槽位 `sp+4`、宽 4 B，`next_used = sp+8`（栈保护字），`4+4 <= 8` ⇒ 不越界。
- **判定：有界【指令级】**。

### 3.2 `drv_cmd_set_mc_rate`（第 73 项）—— 反例 H1

见 §0.3。附加事实：`0x3fa84 str wzr,[sp,#4]` 使槽位确定初始化 ⇒ 影响限于"静默降级"。

### 3.3 `drv_cmd_set_antenna_mode`（第 88 项）—— `%31s` 边界正样本

```
0x40f78  bl   sscanf(fmt="%31s ", out=sp+8)   ; 最坏写 32 B
0x40f90  bl   kstrtoint(sp+4)
```
`sp+8` 起 32 B，下一独立槽位 `sp+0x30` ⇒ `8+32 = 0x28 <= 0x30`，不覆盖相邻对象。**【指令级】有界**。

### 3.4 `drv_cmd_set_okc_mode`（第 51 项）—— `x29` 相对槽 + `tbnz` 返回门

```
0x3ccbc  sub  x2, x29, #0xc        ; x29 = sp+0x20 ⇒ 槽 = sp+0x14
0x3cccc  bl   kstrtouint
0x3ccd0  tbnz w0, #0x1f, 0x3cd18   ; bit31=负 ⇒ 失败臂
0x3ccd4  ldur w5, [x29, #-0xc]
0x3ccd8  cmp  w5, #2
0x3ccdc  b.lo 0x3cd50              ; < 2 ⇒ 成功
```
接受区间 `[0,1]`。**【指令级】有界**。

### 3.5 `SETCCKMIE`（第 69 项）—— `hex_to_bin` 形态澄清

`hex_to_bin` 原型为 `int hex_to_bin(char ch)`（**标量返回**，无目标指针）。两次连续调用是把两个十六进制字符合成 1 字节写进 `__qdf_mem_malloc` 的堆缓冲（`0x3eab8` 分配，`cbz x0` 检查）。扫描器的 `slot?` 是**形态误报**，非缺陷。**【指令级】**

---

## §4 明确未覆盖范围

1. **未做动态验证**：不连接设备、不发 ioctl、不重载 WLAN、不构造危险状态。
2. **未审计 handler 的下游**（`sme_*`/`ucfg_*`/`wlan_hdd_*` 内部）：本文只到 handler 的调用边界；下游是否有越界不在范围内。
3. **`FMT-UNRESOLVED` 的 4 个 handler**（70/71/90/92）：其跨调用的 `sscanf` 格式串未静态解析，不能声称"已确认有界"，标 **未决**。
4. **`MAXTXPOWER`（74）**：扫描器 `no-check` 与人工看到的 `cmp w8,#0xc8` 存在不一致，标 **未决**，需一次人工逐指令确认。
5. **并发面仅做符号级归集**：仅确认 `qdf_mutex_acquire/release`、`osif_request_wait_for_response` 的出现位置（4 个 handler），**未做锁序/生命周期/竞态分析**。
6. **不覆盖可达性**：本文不证明 `/odm/bin/iwpriv` → ioctl `0x89f1` 的调用链已闭合（R1 §6.3 的"连接点未证"继续有效）。
7. **不覆盖配置解析链**（`cfg_parse`/`sscanf`/`WCNSS_qcom_cfg.ini`），已由 §56 关闭。

---

## §5 与项目结论的关系

- **不改变四层判定**。可用 ROOT / 持久 ROOT 仍 **NO-GO**；§23 的"受限 UID 0 命令执行"仍是**已达成**且**未扩展**。
- 本审计的价值是**扩展受控面**而非"首次 uid 0"：把 R1 候选 A（`ioctl 0x89f1 → hdd_driver_command`）从"有界分发器"推进到"逐 handler 的参数字面量级证据"，即把 R1 §6.3 的待办 ② 做完、把待办 ① 的解析能力补齐（`MOVW_UABS_G*` 已解）。
- **唯一新增的否定性发现**是 H1（`SETMCRATE` 未检查 `kstrtouint` 返回值），且因其槽位预清零而**不构成内存安全漏洞**，故**不足以**把候选 A 提升为 R3。
- 若要继续，正确的下一步仍是 R1 §6.3 待办 ③（只读核验 wlan0 节点权限与 iwpriv 的 ioctl 号），而非继续在 handler 内找"更多反例"。

---

## §6 复算产物

| 文件 | 说明 |
|---|---|
| `tools/wlan_handler_scan.py` | 本审计的可复跑脚本（含 `--selftest`） |
| `artifacts_adb/r1_wlan_reach/handler_audit.csv` | 98 行 + 表头；前 10 列 = 要求列 |
| `artifacts_adb/r1_wlan_reach/cmd_table.csv` | 98 项命令表（`wlan_cmd_table.py --csv`） |
| `artifacts_adb/r1_wlan_reach/handler_audit.json` | 完整结构化事实（可选） |
| `artifacts_adb/r1_wlan_reach/handlers/*.txt` | 98 份逐 handler 反汇编（带重定位注释，可选） |
