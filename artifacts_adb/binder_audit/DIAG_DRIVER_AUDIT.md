# `/dev/diag`（diagchar）内核接口静态审计

> 响应 `docs_archive/审核意见CHATGPT-v004.txt` 第七节 **P0**。
> **全程离线**：只用 `firmware_F16/vmlinux.elf`（4.9.227-perf+，与本机同源）+ 反汇编工具；
> **未上机、未对设备做任何 ioctl 实验、未写任何文件到设备**。
> 工具：`tools/kfn.py`（函数级反汇编）、`tools/kcopy.py`（拷贝点上下文）、`tools/klen_scan.py`（全量扫长度来源）。
> 原始矩阵：`diag/copy_matrix.txt`。

---

## 0. 结论（一句话）

**没有找到可用缺陷。** 入口层（`open` / `read` / `write` / `ioctl` / `compat_ioctl`）三个主函数的**逐路径全量复核**显示：
每一次用户态拷贝都是**定长**或**有显式上界**，且前置 `access_ok`、后置 `__check_object_size`；`/dev/diag` **没有 mmap**。
该驱动的形态与上游 diag 系列**修复后**版本一致（下节列出 5 条形态判据）。
⇒ R3 从"新攻击面、未审计"降级为"**入口层已否证、解析子树未穷尽**"。

**更重要的判读（第二层）**：即便将来在 diag 找到内存破坏，本项目也**用不上**——
它能给的是内核读写，但我们连"内核地址"都拿不到（§23.9 已实证：本域 `kallsyms`/`kcore`/`dmesg` 全被 MAC 拒、
`/proc/modules` 基址恒 0、`perf_event_paranoid=3`）。任何需要伪造内核指针的利用都停在同一个墙前。
**diag 路线因此是"双重封闭"：入口层硬化 + 缺泄露原语。** 这正是把它继续冻结、而不是重开主线的依据。

---

## 1. 物料与方法

| 项 | 值 |
|---|---|
| 反汇编源 | `firmware_F16/vmlinux.elf`（`vmlinux-to-elf` 重建，`.kernel` + `.kernel2` 两段，符号空间对齐） |
| 符号数 | 123,784；其中 `diag*` 函数 **301** 个（本审计的扫描域） |
| 工具口径 | 符号地址一律取 ELF `.symtab`；**不用** `kallsyms_out.txt`（偏移在 futex/binder 区有 0x6–0x9 万字节偏差，见 `HANDOVER.md` §0 三条硬规则之第 1 条） |
| 判据 | ①每条 `bl __arch_copy_from_user/__arch_copy_to_user` 前 20 条内回溯 w2/x2 的最后一次写；`mov w2,#imm` 记 CONST，其余记 REG 并人工复核 ②分派表按 `adrp+add+ldrh+adr+add+br` 形态解出 |

**方法说明（避免"抽查当穷尽"，也避免"脚本当权威"）**：`klen_scan.py` 对**全部 301 个** `diag*` 符号逐函数反汇编，
共命中 **18 个含拷贝的函数 / 55 个拷贝点**，其中 **8 个**长度来自寄存器（需人工判界），其余 47 个为常量。
本报告对这 8 个逐个给出上界出处，**没有留"未看"的**。

**口径限制（必须一起读）**：脚本对每个符号**只反汇编到首个 `ret`**。含多返回路径的大函数会被截断——
典型反例：**`diagchar_write` 根本没出现在矩阵里**（它在 `+0x80` 处就有一条错误返回）。
因此矩阵是**必要不充分**证据，不能单独支撑"入口层无遗漏"。
补偿办法：对入口三个主函数做**逐路径人工复核**（不依赖脚本）——
`diagchar_ioctl`（42 槽全表，§3）、`diagchar_write`（4 字节头 + 三条命令路径，§5）、
`diagchar_read`（13 个 `copy_to_user`：12 定长 + 1 内部长度）。**这三处的覆盖是穷尽的；其余 diag* 函数为脚本口径。**

---

## 2. 文件操作表（`file_operations`）

| 操作 | 符号 | 存在 | 判据 |
|---|---|---|---|
| `open` | `diagchar_open` | ✅ | **无 capability 门禁**：任何能过 SELinux 的打开者都被接受；客户端表上限 0x31（49），超出返回 `-ENOMEM` |
| `read` | `diagchar_read` | ✅ | 13 处 `copy_to_user`，12 处定长（4/1 字节），1 处变长（内部缓冲长度，见 §4-⑧） |
| `write` | `diagchar_write` | ✅ | 4 字节命令头 + 载荷，见 §5 |
| `ioctl` | `diagchar_ioctl` | ✅ | 42 槽分派表，见 §3 |
| `compat_ioctl` | `diagchar_compat_ioctl` | ✅ | 10 个拷贝点，**全部定长**（0x28/0x14/4/0xe/4/4/2/4/0x14/0xc），与原生路径结构体尺寸镜像 |
| **`mmap`** | — | **❌ 符号不存在** | 排除"把驱动缓冲直接映射进用户态"这一整类原语 |

> `mmap` 缺席是本次最省事的一条负结果：diag 在部分高通平台提供 `diagchar_mmap`，
> 那会把"用户态直接读写内核环形缓冲"变成默认能力。**本机没有这个入口。**

---

## 3. `diagchar_ioctl` 分派全表（42 槽）

**分派形态**（`0xffffff80085ff5a0`）：

```
cmp w1, #0x29          ; cmd > 41 → 默认分支
b.hi  default
ldrh w11, [table + cmd*2]   ; 16 位偏移表 @0xffffff800926f18a
adr  x10, case0
add  x10, x10, w11, lsl #2  ; 目标 = case0 + 偏移*4
br   x10
```

- 表内**有效槽 22 个**，**其余 20 个**（2–6、10–20、24、30、31、40）全部指向 `+0x63c`，即
  `mov w20, #-0x16` → **`-EINVAL`**。默认分支不触碰任何用户指针。
- 每个有效 case 的**结构体尺寸是编译期常量**，且**每条拷贝前都有内联 `access_ok`**
  （`mrs sp_el0; ldr [x8,#0x40]` = `current_thread_info()->addr_limit`，随后 `adds/csinv/sbcs/cset` 判界），
  失败路径统一 `memset` 清零栈缓冲残留（`sub x8,x8,x2; add x0,x8,#len` 形态）。

| cmd | 结构体 | 长度 | 处理函数 | 备注 |
|---|---|---|---|---|
| 0 | 0x30 | 定长 | `diag_cmd_register_tbl` | 命令注册表，见 §4-① |
| 1 | — | 无拷贝 | `diag_cmd_remove_reg_by_pid(current->tgid)` | 只按 pid 摘链 |
| 7 | 0x14 | 定长 | `diag_switch_logging` + `diag_switch_logging_clear_mask` | 有 mutex |
| 8 | — | 入参无拷贝、出参 2 字节 | 内联（无外部调用） | 取 u16 字段 `+0x2f0` 作 DCI 客户端号（`0xffff`=满），回写 2 字节 |
| 9 | — | 无拷贝 | `diag_ioctl_lsm_deinit` | — |
| 21 | 4 | 定长 | `diag_dci_get_client_entry` + `diag_dci_deinit_client` | 按 client_id 查表 |
| 22 | 指针直传 | 子函数 | `diag_ioctl_dci_support` | 6 字节 in/out |
| 23 | 0xe | 定长 | `diag_dci_register_client` | — |
| 25 | 指针直传 | 子函数 | `diag_ioctl_dci_health_stats` | 0x1c 字节 in/out |
| 26 | 指针直传 | 子函数 | `diag_ioctl_dci_log_status` | 0xa 字节 in/out |
| 27 | 指针直传 | 子函数 | `diag_ioctl_dci_event_status` | 0xa 字节 in/out |
| 28 | 4 | 定长 | `diag_dci_clear_log_mask` | — |
| 29 | 4 | 定长 | `diag_dci_clear_event_mask` | — |
| 32 | 2 | 定长 out | 内联 | `copy_to_user` 写 2 字节 |
| 33 | 指针直传 | 子函数 | `diag_ioctl_vote_real_time` | 7 字节 in |
| 34 | 指针直传 | 子函数 | `diag_ioctl_get_real_time` | 8 字节 in/out |
| 35 | 指针直传 | 子函数 | `diag_ioctl_set_buffering_mode` | 4 字节 in |
| 36 | 指针直传 | 子函数 | `diag_ioctl_peripheral_drain_immediate` | 1 字节 in |
| 37 | 4 | 定长 | 内联 `printk` | 4 字节值只作 `printk` **参数**（格式串是常量，无格式化字符串问题）；随后返回 `-EINVAL`，未观察到写入任何结构 |
| 38 | 指针直传 | 子函数 | `diag_ioctl_hdlc_toggle` | 1 字节 in |
| 39 | 0x14 | 定长 | `diag_ioctl_query_pd_logging` | — |
| 41 | 0xc | 定长 | `diag_ioctl_query_session_pid` | 0xc in + 0xc out，两次 `access_ok` |

> cmd 22/25/26/27/33/34/35/36/38 是"把用户指针直接交给子函数"的形态——**它们的长度校验在子函数里**，
> 已逐个反汇编确认（§4末尾）。这是审计上最容易漏的一类转手。

---

## 4. 八个变长拷贝的逐一判界

| # | 位置 | 方向 | 长度来源 | 上界出处 | 判定 |
|---|---|---|---|---|---|
| ① | `diag_cmd_register_tbl` `+0xbc` | FROM | `x20 = count * 8` | **`ubfx x8, w22, #0x1d, #3` + `cbz`**：count 的 bit29–31 必须为 0 ⇒ `count < 2^29` ⇒ `count*8` 不会回绕；`kmalloc(count*8)` 与 `copy(count*8)` **同源同值** | ✅ 安全 |
| ② | `diag_md_copy_to_user` `+0x1bc` | TO | `x23` | 由 `diag_md_session_*` 维护的会话缓冲长度，只回拷本端已写入的数据 | ✅ 不看外部输入 |
| ③ | `diag_md_copy_to_user` `+0x3f0` | TO | `x23` | 同上 | ✅ |
| ④ | `diag_user_process_dci_apps_data` `+0xa0` | FROM | `x23 = len` | 三重：`len ≥ 1` → **`len ≤ diag_mempools[0].item_size`**（`/0x24`） → `access_ok` + `__check_object_size`；随后 `diagmem_alloc(driver,len,0)` 内部**再判一次** `size ≤ item_size` | ✅ 安全 |
| ⑤ | `diag_copy_to_user_msg_mask` | TO | `w25 = 0xc + entry->num*4` | 复制前 `cmp w22, [entry+0x18]`（容量域）必须 `≤`；再判累计偏移 `off + w22 + 4 ≤ 用户给的 buf_len`；源指针是内核已登记表项 | ✅ 双向判界 |
| ⑥ | `diag_copy_to_user_log_mask` | TO | `w27 = 5 + ceil(bits/8)` | 同上形态（`cmp w23, [entry+0x18]`） | ✅ |
| ⑦ | `diag_dbgfs_write_debug` | FROM | `x20` | debugfs 写路径；**本域无 debugfs 访问权**（open 即被 MAC 拒），且需 root 挂载 | ⚠️ 不可达 |
| ⑧ | `diagchar_read` `+0x75c` | TO | `x23` | 内部响应缓冲的已填充长度（`read_index - read_ptr`），不来自用户参数 | ✅ |

**子函数逐个复核（cmd 22/25/26/27/33/34/35/36/38）**：全部为**单一常量长度**——
`diag_ioctl_dci_support` 6、`dci_health_stats` 0x1c、`dci_log_status` 0xa、`dci_event_status` 0xa、
`vote_real_time` 7、`get_real_time` 8、`set_buffering_mode` 4、`peripheral_drain_immediate` 1、`hdlc_toggle` 1。
**没有一个是 `*size` 或 `arg` 派生**。

---

## 5. `diagchar_write` 命令分派

**入口判据**：`cmp x2, #3; b.hi` ⇒ `count ≤ 3` 直接 `-EBADMSG`（`-0x4a`）；前 4 字节是命令字，`w19 = count - 4` 是载荷长。

| 命令字 | 路径 | 长度门 | 拷贝 |
|---|---|---|---|
| `0x40` | DCI 事件/日志写 | `len ≥ 1` 且 `len ≤ diag_mempools[2].item_size`（`+0x8c`） | `diag_dci_get_buffer` → `__check_object_size` → `access_ok` → `copy(len)` |
| `0x80` | DCI 控制包 | `len ≤ 0x4004` **且** `diagmem_alloc` 内 `size ≤ item_size` | 同上 |
| `0x400` | DCI apps 数据 | `len ≥ 1` 且 `len ≤ diag_mempools[0].item_size` | `diag_user_process_dci_apps_data(ptr, len, 0x400)` |
| `0x100/0x200/0x300` | `tst w20,#0x300` 命中 | 同上（走 `0x400` 同一函数，命令类别作参） | 同上 |
| 其它 | 落 `0xffffff8008601d2c` 后续分支或错误返回 | — | — |

**`diagmem_alloc(driver, size, pool)` 的判界（关键）**：

```
pool 选择：比较 arg 与 5 个 0x34 步长表项的 id 域（偏移 0 / 0x34 / 0x68 / 0x9c / 0xd0）
取表项：  x22 = diag_mempools + pool*0x34
          ldr x8,[x22,#0x1c]!   ; 空闲链头，为空 ⇒ "pool not initialized"
          cbz w19 / ldr w8,[x8+0x24] / cmp w8,w19 / b.hs
⇒ if (size != 0 && size > item_size) 拒绝
```

⇒ **`write()` 的三个长度门都收敛到 `item_size`**，与池缓冲区实际尺寸同源。没有"用户给长度、驱动按固定缓冲拷"的错配。

---

## 6. 与上游修复状态的形态对照

以下 5 条是**代码形态判据**，不是 commit 号比对（本机镜像无 git 元数据，凡涉及具体 CVE 编号的断言本报告一律不给）：

| # | 形态 | 位置 | 含义 |
|---|---|---|---|
| 1 | `count` 高位检查 `ubfx #0x1d,#3` + `cbz` | `diag_cmd_register_tbl` | diag 命令注册表历史上的整数溢出/超大分配就死在这一句上；**本机有这句** |
| 2 | 每条拷贝前内联 `access_ok` | 全部 55 处（脚本口径） | 无一遗漏（无 `->addr_limit` 判据缺失的裸拷贝） |
| 3 | 拷贝前 `__check_object_size` | 池缓冲/`kmalloc` 路径 | FORTIFY 形态；说明该内核 diag 是**较新分支**，不是 2016 年的旧实现 |
| 4 | `size ≤ item_size` 双判（调用方 + `diagmem_alloc`） | §4-④ / §5 | 防御性冗余 |
| 5 | **无 `mmap`** | `file_operations` | 无"用户态直映内核缓冲"原语 |

**判读**：把"diag 有全 ioctl 权限"直接当成"diag 可提权"是**把一个前提当结论**。
本机 diag 的入口层已经按修复后形态编写，缺的正是"能利用的那个 bug"——而那是 0day，不在静态审计的可判范围内。

---

## 7. 覆盖度缺口（诚实登记，禁止外推为"穷尽"）

| # | 未审内容 | 为什么不影响 §0 的结论 | 何时必须回来 |
|---|---|---|---|
| G1 | **DCI 报文解析子树**：`diag_process_apps_dci_read_data` → `diag_process_single_dci_pkt`（按首字节 0x93/0x94/0x98/0x9a 再分派）及其下游 | 该层解析的是**内容**而非长度；长度已在 §4-④ 处封顶。**这是唯一可能存在逻辑/解析缺陷的地方** | 若出现"引用该解析器"的公开漏洞，或拿到固件源码 |
| G2 | mask 表的 **set/get 配对不变量** | get 侧（⑤⑥）双向判界已覆盖；set 侧 `diag_cmd_set_msg_mask` 亦有容量与区间重叠校验（`log_code ≥ 8`、`num_items ≥ 1`、`±0xc8` 区间冲突检查） | 若发现 set 侧绕过上述三门的路径 |
| G3 | `diag_md_*`（多设备会话）完整生命周期 | 只用了 `copy_to_user`，方向为内核→用户，且长度为本端写入量 | 若出现"用户可指定会话缓冲长度"的路径 |
| G4 | `diag_dbgfs_*` 全部 | debugfs 未挂载/本域不可达 | 若取得 debugfs 或更高域 |

---

## 8. 判定与可证伪条件

### 8.1 判定

| 问题 | 答案 |
|---|---|
| `/dev/diag` 可访问吗？ | **可以**（策略 + 身份已确证，§24.4 R3） |
| ioctl 权限存在吗？ | **可以**（44 个目标类型中含 `diag_device` 全 ioctl） |
| 入口层有内存破坏吗？ | **未发现**（入口三函数逐路径复核穷尽；其余 diag* 为脚本口径 55/55 判界闭合，见 §1 口径限制） |
| 解析子树有缺陷吗？ | **未审**（G1），既不能证实也不能否证 |
| 能拿到任意内核读写吗？ | **不能**——即使拿到 bug，仍需内核地址；本域无泄露口（§23.9） |
| 能绕过 SELinux 吗？ | 需要内核 R/W + 泄露 + KASLR，三缺二 ⇒ **当前不成立** |

**评级**：`/dev/diag` 从「新发现、未审计」→ **「入口层否证；余量为解析子树 + 与 GhostLock 相同的泄露墙」**。

### 8.2 可证伪条件（写进 §7，与其它面同规格）

满足**任一条**才重开 diag：

1. 拿到与本机同源的 diag 源码（`msm-4.9` 分支，且确认 `diagchar_core.c`/`diagfwd_*.c` 与二进制对得上），可做逐行对照；
2. 出现影响 `diag_process_single_dci_pkt` 下游的公开漏洞，且 opcode 集合与本机一致（0x93/0x94/0x98/0x9a）；
3. 出现**新的内核地址泄露原语**（本域或更低域），使"有 bug 也用不上"这一条失效。

**不重开**：盲目发 ioctl 试错误码、fuzz 驱动、竞态实验。理由：入口层长度门已闭合，随机 fuzz 的期望收益接近 0，而代价是内核 panic（历史 5 次重启全来自竞态实验）。

---

## 9. 对审核意见 v004 的逐条回应

| 审核意见 | 本轮处置 |
|---|---|
| 第七节 P0：以匹配 4.9.227-perf+ 的驱动源码审计 ioctl 分派、用户数据复制、长度验证、权限边界 | **完成（二进制级）**：§3 分派全表、§4 八个变长拷贝判界、§5 write 路径、§2 权限边界。**源码不可得**，故以 `vmlinux.elf` 反汇编为权威源，并在 §6 说明形态判据的效力边界 |
| "其他 Qualcomm 设备上的 diag 漏洞不能直接移植到 K3" | **接受并落实**：§6 只做形态对照，不给任何移植性断言；未引用任何具体 CVE 编号 |
| "不建议未经分析就进行设备侧 ioctl 实验" | **遵守**：本轮 0 次上机、0 次 ioctl |
| 第八节：若 diag 无问题且消费者无缺陷，可正式 NO-GO | **部分支持**：diag 入口层已否证，但 G1（解析子树）+ 消费面 P1 未穷尽 ⇒ 现在下"整体 NO-GO"仍早一步，建议按 §8.2 的三条条件收口后再定 |

---

## 10. 复现路径（全部离线）

```bash
# 分派表
python tools/kfn.py diagchar_ioctl --calls

# 单函数反汇编
python tools/kfn.py diag_cmd_register_tbl

# 拷贝点上下文（±10 条）
python tools/kcopy.py diag_user_process_dci_apps_data diagmem_alloc

# 全量：301 个 diag* 符号 / 55 个拷贝点 / 常量 vs 寄存器
python tools/klen_scan.py > artifacts_adb/binder_audit/diag/copy_matrix.txt
```
