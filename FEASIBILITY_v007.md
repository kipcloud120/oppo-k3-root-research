# 可行性评估：v007 提出的"内核地址泄露"三条路线（2026-11-19，纯离线）

> 响应 `docs_archive/审核意见CHATGPT-v007.txt`。**全程只读**：仅解析 `firmware_F16/vmlinux.elf`、`kallsyms_out.txt`、`kernel_appended.dtb` 与已归档的 config / slabinfo，并克隆公开参考项目 `yijiacloud/GhostLock-OPPO-PCKM00` 到 `ref_pc/km00` 做源码级比对；未连接设备、未修改任何现有代码、未产出任何 PoC。
> 本文回答的是"能不能做"，不是"怎么做"。上与下：方向层面评估见上一轮对话；本文是其证据支撑与逐项判定。
>
> **v2 更新（同日，第 9–13 节）**：拿到 PCKM00 实际源码后，逐行核对了 boot_id / KernelSnitch / ashmem 的真实实现。**多处结论被修正**——最重要的是：① PCKM00 的 boot_id 回读确证为"GhostLock 写原语的后置步骤"（原判定成立且获源码铁证）；② KernelSnitch 的候选验证是**纯离线哈希计算**而非时序猜测，采样量可控、hashsize 自动覆盖，我上一轮"KPTI/HZ 使其输出精度未知"的担忧**部分作废**；③ KernelSnitch 在 PCKM00 里服务于 pipe 物理页定位，与本机的 xattr 载体需求**不同构**。阅读结论请以第 13 节的修正版为准。

---

## 0. 结论先行

| 路线（按 v007 优先级） | 本机可行性 | 决定性理由 |
|---|---|---|
| ① boot_id 指针回读 | **不成立（前提缺失）** | 该技术要求"先用内核写原语篡改 boot_id 底层数据块"，而本机恰恰没有写原语。符号存在 ≠ 可利用 |
| ② KernelSnitch futex 侧信道 | **条件成立，优先级最高** | 物理基础齐备（动态哈希表 1024 桶、mm_struct 896B、SLUB 可读），但 KPTI+PAN+UAO+HZ=100 使其输出精度未知，且给的是线性映射地址而非 text slide |
| ③ ashmem_fops 交叉验证 | **不成立（前提缺失）** | 交叉验证是"已有一个候选地址后的校验器"，不是地址来源；本机 ashmem 节点虽可读写，但读不到 fops 里的函数指针值 |
| ④ 物理布局锚定（v007 的 P0） | **部分成立** | DTB 保留区证明 PHYS_OFFSET=0x80000000、线性映射关系成立；但 runtime slide 仍未知，锚定解决不了 KASLR |

**净判定**：v007 的方向成立（补"运行时地址"缺口），但它推荐的第一优先级 boot_id 是**条件性后置技术**，不能当起手式。三条路线里只有 KernelSnitch 具备"独立产生地址候选"的潜力，且必须先在离线侧回答其输出精度问题。**没有任何一条路线能绕过"先有一个可信内核地址锚点"这一根本缺口**——这正是交接 §15.4 / §23.9 的既定结论，本轮评估未推翻它。

---

## 1. 评估方法与证据口径

沿用交接文档的三条硬规则：反汇编只用 `vmlinux.elf`；`kallsyms_out.txt` 只查名字；不连设备。所有符号地址、结构尺寸、配置值均可离线复算：

```bash
python tools/kfn.py --list 'futex|ashmem|configfs|nfulnl'     # 函数符号
python tools/kfn.py futex_wait_setup                          # 哈希桶计算路径
python tools/kfn.py futex_init                                # 哈希表分配参数
python tools/kfn.py proc_do_uuid --calls                      # boot_id 写路径
grep -iE 'bootid|nfulnl|ashmem_fops' firmware_F16/kallsyms_out.txt
grep -iE '^CONFIG_(UNMAP_KERNEL_AT_EL0|ARM64_PAN|ARM64_UAO|CONFIGFS_FS|ASHMEM)' artifacts_adb/k3_kernel_config.txt
```

---

## 2. 路线①：boot_id 指针回读 —— 不成立（前提缺失）

### 2.1 符号与通道层面：真实存在

| 检查项 | 结果 |
|---|---|
| `sysctl_bootid` | 存在，数据符号 `0x020c9d3c`（`kallsyms` 相对偏移）；`proc_do_uuid.bootid_spinlock @0x020c9d78` |
| `proc_do_uuid` | 存在，`0xffffff80085f7b58`；反汇编含 `generate_random_uuid` + `proc_dostring` ⇒ **写路径开放**（sysctl write=1） |
| `CONFIG_PROC_SYSCTL` / `CONFIG_SYSCTL` | 均为 `y` |
| `nfulnl` 族 | 完整存在：`nfulnl_logger @0x01d9bb88`、`nfulnl_log_packet @0x00e81008`、`nfulnl_recv_config @0x00e81210`、`nfnetlink_rcv` 等 |

结论：v007 的 P0 问题"F.16 是否包含 `nfulnl_loggers` / `sysctl_bootid` 符号"——**答案是包含**（符号名精确形态为 `nfulnl_logger` 单数、`sysctl_bootid`）。这一项 v007 判断正确。

### 2.2 但机制层面：前提错配

PCKM00 的 boot_id 技巧不是"读 boot_id 会泄露内核指针"，而是（v007 第 56–60 行自述）：

> 1. 通过**已经建立的内核内存操作能力**，控制内核数据结构所产生的写入效果。
> 2. 让一个已知内核地址的信息反映到 boot_id 的底层数据中。
> 3. 从 procfs 读到这些字节，恢复运行时基址。

即：它的输入是"受控内核写原语"，输出才是"地址"。本机状态：

- 唯一已证的写能力是 Wi-Fi 私有事务的 `uid=0` 命令执行（§23），但域为 `u:r:oplus_wifi_service:s0`，**读不到 boot_id 之外的内核数据块、无 `devmem`、无 `/proc/kcore`、能力集仅 `0x13000`**（§24/§23.9）。
- GhostLock 若要提供内核写，fake waiter 的 `lock`/rb 链接**必须先有非零内核地址**（§15.4）——这正是 boot_id 想产出的东西。

⇒ **循环依赖**：boot_id 需要写原语，写原语（GhostLock）需要地址，地址要靠 boot_id。v007 自己也承认"不是可脱离 GhostLock 利用原语单独移植的技巧"（第 33 行），但随后仍把它列为"第一优先级"，属于排序与前提自相矛盾。

**判定：不成立。** 可作"拿到第一个地址/写原语之后的 KASLR 校验步骤"，不可作信息泄露起点。

---

## 3. 路线②：KernelSnitch futex 侧信道 —— 条件成立，优先级最高

这是三条路线里唯一**不需要前置内核写原语**的候选：它是纯用户态时序侧信道，输入是 futex 调用与时钟测量，输出是对象地址候选。

### 3.1 物理基础：齐备（本机实测/反汇编确证）

| 要素 | 本机事实 | 来源 |
|---|---|---|
| futex 动态哈希表 | `__futex_data.0 @0xffffff8009e0e150`（`futex_htable` 指针）、`__futex_data.1 @0xffffff8009e0e160`（`hashsize`）；`futex_init` 调 `alloc_large_system_hash` | `kfn.py futex_init` |
| 桶结构尺寸 | `futex_wait_setup` 中 `add x28,x9,x8,lsl #7` ⇒ 每桶 **128 B**（`futex_hash_bucket`）；`and x8,x10,x8` 用 `hashsize-1` 取模 | `kfn.py futex_wait_setup` |
| 初始桶数 | `futex_init` 中 `__sw_hweight64(nr_cpu_ids)<<8` 后向上取 2 的幂；本机 **4 核** ⇒ `next_pow2(256×4)=1024` 桶 | config / DTB / 反汇编 |
| 哈希函数 | mainline 4.9 `hash_long()`（Jenkins 混合，`0xdeadbeef` 种子，多轮 ror/sub/eor），key 含 mm/inode 指针 | `get_futex_key` / `futex_wait_setup` |
| mm_struct 尺寸 | slabinfo 实测 `mm_struct 336/378/896`（每对象 896 B） | `k3_info.txt:413` |
| SLUB 布局 | `CONFIG_SLUB=y`，无 `SLAB_FREELIST_RANDOM`/`HARDENED`；kmalloc 仅 2 的幂 cache | §2.2 / §2.4 |
| 时钟原语 | `Seccomp:0`，用户态 `clock_gettime` 可用 | §2.1 |

⇒ **v007 指出的物理基础在本机全部存在**，且 4.9 与 4.14 的 futex 哈希表实现同源（都是 mainline 动态哈希表 + `hash_long`），移植不像偏移那样需整体重做。

### 3.2 但三个硬约束使输出精度未知

1. **KPTI + PAN + UAO 全开**（`CONFIG_UNMAP_KERNEL_AT_EL0=y` / `ARM64_PAN=y` / `ARM64_UAO=y`）：PCKM00 的 KernelSnitch 适配 4.14.180，侧信道特征（尤其是跨页表切换的时序）在 KPTI 开启的 4.9 上会显著改变。交接 §2.2 已明确"KPTI 开启削弱 prefetch 侧信道"。
2. **`CONFIG_HZ=100`**：调度tick 10ms 粒度，futex 哈希桶碰撞的时序差可能落在 tick 噪声内，需要大量采样才能拉出信噪比——采样量是可行性成本的核心未知数。
3. **输出类型不匹配**：KernelSnitch 给的是**线性映射区的 mm_struct 地址**，不是 KASLR text slide（v007 第 88–92 行自认）。而 GhostLock fake waiter 需要的是 `rt_mutex` / `pi_state`（`kmalloc-128`）的内核地址（§15.4）。从 mm_struct 地址到可用 fake waiter 地址之间，还差"线性映射基址 → 目标 slab 对象地址"的推导链，这一步在本机**未被证明**。

### 3.3 判定

**条件成立，列为第一优先级。** 但"条件"是：必须先在离线侧回答"KPTI/HZ=100 下能否以可接受采样量得到稳定地址候选"，以及"mm_struct 线性地址能否推导到 fake waiter 可用的对象地址"。这两个问题回答之前，不构成对 §7 第 2 条 (a) 重开条件的触发——**候选地址不等于可信地址**（§15.5：无独立 oracle 的猜测必然 panic，且 panic 文本不可读）。

---

## 4. 路线③：ashmem_fops 交叉验证 —— 不成立（前提缺失）

### 4.1 通道层面：本机条件甚至优于 PCKM00

| 检查项 | 结果 |
|---|---|
| `ashmem_fops` | 存在，数据符号 `0x012afa10` |
| `ashmem_*` 函数族 | 完整：`ashmem_open/mmap/ioctl/read/release/llseek/shrink_*` 全部存在 |
| `CONFIG_ASHMEM` | `y` |
| 用户态可达性 | `ashmem<uuid>` 节点（0666）shell 三种模式全可开、可读写（`attack_surface.md:25`）⇒ 修正了旧记录"ashmem 被 SELinux 拒绝 open" |
| `CONFIG_CONFIGFS_FS` | `y`；configfs 函数族齐全（`configfs_attach_*`、`__configfs_open_file` 等），但通用 bin 属性是否注册到可达 interface 未在本机确认 |

### 4.2 但它是校验器，不是地址源

`ashmem_fops` 交叉验证的逻辑是：若已从别处得到一个"疑似内核基址"，检查 `fops` 里 `open/ioctl/mmap/release` 多个函数指针是否**共同指向同一基址 + 已知偏移**，以排除偶然命中。其输入是"候选地址"，输出是"真/假"。

要在运行时读到 `ashmem_fops` 里的函数指针值，需要：① 知道 `ashmem_fops` 的运行时地址（它本身就在 KASLR 后的 `.data`/`.rodata`，`0x012afa10` 只是静态偏移）；或 ② 有内核读原语从该地址取值。两者都回到"先有地址/读原语"。

**判定：不成立（作为地址来源）。** 定位为"路线②产出候选地址之后的交叉校验器"，与 boot_id 同级后置。

---

## 5. 路线④：物理布局锚定 —— 部分成立

### 5.1 本轮新证据

解析 `kernel_appended.dtb`（7 个 DTB 拼接，首个 `totsize=0x5dafb`）的保留内存区，得到明确的物理地址锚点：

```
hyp_region@85700000      xbl_region@85e00000     removed_region@85fc0000
camera_region@8ab00000   modem_region@8b000000   wlan_msa_region@94B00000
gpu_region@0x98a15000    qseecom_region@0x9e400000
ramoops@0x0xB7E00000     cont_splash_region@9c000000
```

`/memory` 节点的 `reg` 为全 0（高通 bootloader 运行时填充），但保留区地址确凿证明物理地址空间从 **0x80000000** 段开始 ⇒ 交接 §8.3 的候选 `PHYS_OFFSET=0x80000000` 得到独立佐证，`0x40000000` 候选可排除。

结合静态链接基址 `0xffffff8008080000`（`PAGE_OFFSET=0xffffff8000000000`），arm64 线性映射关系 `virt = 0xffffff8000000000 + (phys - 0x80000000)` 在本机成立。

### 5.2 但仍解决不了 KASLR

线性映射只能把**已知物理地址**转成虚拟地址；`RANDOMIZE_BASE=y` 下 text/`.data` 的 runtime slide 仍未知（§2.2 / §8.3）。DTB 给的物理布局不能泄露 slide。

**判定：部分成立。** 可作为"把 KernelSnitch 产出的线性映射物理地址转成虚拟地址"的配套参数，不能单独作为地址源。

---

## 6. 与项目纪律的一致性核对

| 约束 | 本评估的态度 |
|---|---|
| 不上机跑完整 PoC（v007 自报 ~97% panic） | **维持拒绝**。本机 `dmesg`/`pstore`/`last_kmsg` 全不可读（§2.3），panic 拿不到文本，既不能证真也不能证伪（§15.5） |
| 不做持久化写入、不刷机、不解 BL | 维持 |
| 累计 5 次重启额度 | 不动用；本轮全部离线 |
| §7 第 2 条 (a)"任一可用内核地址泄露"触发 GhostLock 重开 | **尚未触发**：KernelSnitch 只产出"候选地址"，未满足"可用"判据（缺独立 oracle，§15.5） |
| 关闭 OTA | 维持建议 |

---

## 7. 建议的下一步（需单独授权才执行；均离线、零设备副作用）

1. **KernelSnitch 输出精度预研（最高优先）**：取 PCKM00 `kernelsnitch/` 源码，与本机的 `get_futex_key`/`futex_wait_setup`/`__futex_data` 布局做 4.14→4.9 差异表；用离线模型估算 KPTI+HZ=100 下桶碰撞时序差的可观测性。回答"1024 桶、10ms tick 下，需要多少次采样才能稳定区分 mm_struct 地址"。
2. **线性映射推导链验证**：从 `mm_struct`（896B，`kmalloc-1k`）地址推导到 `pi_state`（88B，`kmalloc-128`）地址的可行性——这一步若不成立，KernelSnitch 即使成功也无助于 GhostLock。
3. **boot_id / ashmem 后置脚本化**：仅在 1+2 成立、拿到第一个可信地址后，再把 boot_id 回读与 ashmem_fops 交叉验证作为 KASLR 校验步骤实现——现在不做。

**不建议**：现在就重排主线去追物理布局（已基本完成，边际收益低）；直接上机试跑任何 PCKM00 代码；把候选地址当作重开条件已满足。

---

## 8. 一句话

v007 找对了缺口（运行时地址），但推荐错了入口：boot_id 和 ashmem_fops 都是"拿到地址之后"的工具；唯一可能独立产生地址候选的 KernelSnitch，在本机物理基础齐备却被 KPTI+HZ=100 与"输出类型不匹配"两道未知挡住。**本机符号层面已就位，缺的仍是第一个可信地址——本轮评估未改变这一根本判定。**

> ⚠️ 本节（第 8 节）的结论在第 9–13 节的源码级预研后有修正，请以第 13 节为准。保留原文是为了记录评估的演进。

---

# 第二部分：源码级预研（v2，2026-11-19）

## 9. 参考项目实际实现（铁证）

克隆 `yijiacloud/GhostLock-OPPO-PCKM00`（HEAD `fe149a6`）到 `ref_pc/km00/`，逐行核对了三条路线的真实代码。

### 9.1 完整利用链（README 自述）

```
futex requeue-pi UAF
  └─> pselect fd_set 栈覆盖 (fake rt_mutex_waiter / fake task)
        └─> arbitrary write
              └─> 覆写 ashmem_fops -> configfs bin read/write
                    └─> pipe_buffer 页改写 (物理 RW)
                          └─> patch cred -> root
```

**这条链直接证实**：ashmem_fops / configfs 是 GhostLock **成功之后**建立内核读写的中继，boot_id 回读是同一阶段用于定 KASLR 的步骤——三者都不是"地址来源"。第 0 节对 boot_id / ashmem 的判定获得源码铁证。

### 9.2 boot_id 回读的真实机制（`slide.c`）

`slide_leak_kernel_base()` → `slide_child_leak_stext()` → `slide_read_stext()`，链路为：

1. `prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE)` —— 先用 GhostLock UAF 建立写原语（**前置条件**）；
2. 子进程跑三线程 requeue-pi（`slide_waiter/owner/consumer`），通过 UAF 把 `nfulnl_logger` 的指针值写到 boot_id 底层数据块；
3. `open("/proc/sys/kernel/random/boot_id")` 读回 16 字节 → 得到 `nfulnl_logger` 的运行时指针（校验 `leaked >> 48 == 0xffff`）；
4. `stext = leaked - p0_alias_image_offset(SLIDE_NFULNL_LOGGER)` 恢复基址。

⇒ **boot_id 的输入是 GhostLock 写原语，输出才是地址**。它不是独立信息泄露，排序在 GhostLock 之后。v007 第 33 行的自我限定与源码完全一致。

### 9.3 KernelSnitch 的真实角色（`pipe.c` / `util.c`）

- `setup_kernelsnitch(MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS=4, 1, 0)`；
- 输出 `leaked = cleanup_kernelsnitch()`，随后 `base = leaked & ~(ORDER3_SIZE-1)`（`ORDER3_SIZE=32KB`）；
- 用途：定位 **mm_struct 所在的 order-3 物理页**，进而找 pipe_buffer 页做物理 RW —— 服务于 GhostLock 成功**之后**的提权阶段。

⇒ KernelSnitch 给的是线性映射对象地址，与第 0 节判断一致；但它在 PCKM00 里的用途是 pipe 页定位，不是 KASLR 基址（KASLR 走 boot_id）。

## 10. futex 哈希表 4.14 → 4.9 差异表

| 要素 | PCKM00 (4.14.180) | K3 本机 (4.9.227) | 可移植性 |
|---|---|---|---|
| 哈希表实现 | `alloc_large_system_hash` 动态表 | **同**（反汇编 `futex_init` 确证） | ✅ 同源 |
| 哈希函数 | jhash，`JHASH_INITVAL=0xdeadbeef` | **同**（`futex_wait_setup` 见 `0xdeadbeef` + ror/sub/eor 序列） | ✅ 完全一致 |
| 桶结构 | `futex_hash_bucket` 128B | **同**（`add x28,x9,x8,lsl #7`） | ✅ 完全一致 |
| 桶数 | `256×8=2048` | `256×4=1024`（4 核） | ⚠ 需按 `sysconf(_SC_NPROCESSORS_ONLN)` 自动算，源码已如此 |
| hashsize 未知时 | bruteforce 遍历 `h_sizes[]=256…65536` | **同机制** | ✅ 本机 1024 被自动覆盖 |
| mm_struct 尺寸 | `0x3a8`=936B | `896B`（slabinfo 实测） | ⚠ 需改 `MM_STRUCT_SZ` 常量 |
| mm slab | order-3 (32KB) | slabinfo：896B×18/页 ⇒ order-2(16KB) 或 order-3 | ⚠ 需重定 `MM_ORDER` |
| 计时原语 | `mrs cntvct_el0`（用户态） | `CONFIG_ARM_ARCH_TIMER=y`；`clock_gettime` 基于 cntvct | ⚠ `VCT_ACCESS not set` 存疑，但 arm64 默认开 `EL0VCTEN`（见 §11 更正） |
| 用户 futex 地址 | `mmap` 64GB PROT_NONE + 1GB 页 | 同接口可用（Seccomp=0） | ✅ |

**净结论**：4.9 与 4.14 的 futex 哈希表**机制同源**，KernelSnitch 的碰撞逻辑可继承；需改的只是三个常量（`MM_STRUCT_SZ`、`MM_ORDER`、核数驱动的桶数），且后两者源码已参数化或自动推导。**我上一轮"4.14→4.9 需整体重做"的担忧作废。**

## 11. 采样量估算（推翻上一轮的"精度未知"）

### 11.1 关于 `VCT_ACCESS not set` 的更正

Web 核查（Arm ARM / FlushTime 论文 / arm64 timer 文档）确认：`CONFIG_ARM_ARCH_TIMER_VCT_ACCESS` **不等于** `CNTKCTL_EL1.EL0VCTEN`。arm64 Linux 默认设置 `EL0VCTEN=1` 使用户态可读 `cntvct_el0`（`clock_gettime` 就基于它）；config 未设置通常只影响"trap 模拟"路径。⇒ 我上一轮据此判定"计时不可用"是**误判**，予以更正。是否真的可读，仍需一条设备侧只读指令确认（`mrs x0,cntvct_el0`），但**不构成离线阶段的阻断**。

### 11.2 三阶段采样量（离线可算）

| 阶段 | 性质 | PCKM00 | K3 本机 | 风险 |
|---|---|---|---|---|
| ① 碰撞发现 `find_collisions` | 用户态计时 | 32768 futex × 128 次 ≈ 419 万次 `FUTEX_WAKE_PRIVATE` | 16384 × 128 ≈ **210 万次** | 无 panic；纯用户态 |
| ② mm_struct bruteforce | **纯离线哈希计算** | 8GB/936 ≈ 57 万候选 ×3×9 | 8GB/896 ≈ **60 万候选** | 无计时、无内核交互 |
| ③ boot_id 回读 | 需 GhostLock 写原语 | — | **本机不具备前置** | 见 §9.2 |

关键：阶段 ② 不是时序猜测，而是对每个候选地址做多个 hash size 的碰撞一致性验证（`h_sizes[]` 覆盖 256…65536）。**hashsize 未知不构成障碍，KPTI/HZ=100 对阶段 ② 完全无关**。阶段 ① 的计时即使噪声较大，也有 `THRESHOLD_MULT=10`（10 倍阈值）+ `REPEAT_MEASUREMENT=128` 次中位数滤波兜底。

⇒ **上一轮"KPTI+HZ=100 使 KernelSnitch 输出精度未知"的判定部分作废**：采样量可控（秒到分钟级）、无 panic 风险。真正的未知收窄为"阶段 ① 的 10 倍阈值在 4.9 上是否仍能稳定区分碰撞桶"这一单点。

## 12. mm_struct → pi_state 推导链验证（关键否定）

这是本轮最重要的**否定**发现，它限制了 KernelSnitch 对 K3 的价值：

1. **KernelSnitch 输出的用途不同构**：PCKM00 用 `leaked & ~(32KB-1)` 定位 mm_struct 所在物理页，服务于 pipe_buffer 物理 RW（GhostLock 之后的阶段）。K3 的缺口是 fake waiter 的 `lock`/rb 链接需要非零内核地址（§15.4），需求不同。
2. **fake waiter 的 `lock` 语义不同**：PCKM00 的 `fake_lock = payload_base + LOCK_OFF`（util.c:452）是**用户态可控页地址**——因为它的载体是 pselect fd_set，waiter 从用户栈整体拷入，`lock` 可指向用户态伪造对象。K3 的载体是 xattr 经 `strncpy_from_user` 写到内核栈，`lock` 在 `rt_mutex_adjust_prio_chain` 链走查中会被当 `rt_mutex*` 解引用，**必须内核可访问**。
3. **推导链断裂**：KernelSnitch 给出的是某个 mm_struct 的线性映射地址。§15.4 要求 `lock` 指向 `pi_state`（kmalloc-128，本机 slabinfo 确认存在，249056 对象）或 rb 自引用需**内核栈地址**。从"一个 mm_struct 地址"推不到"pi_state 地址"或"当前内核栈地址"——它们是不同 slab、不同分配序的对象。

⇒ **判定：推导链不成立。** KernelSnitch 即使成功，其输出也不能直接填进 K3 的 fake waiter。它能提供的是"一个可信的线性映射锚点"，用于通过 `virt = PAGE_OFFSET + (phys-PHYS_OFFSET)` 反推物理布局（§12.1），但 fake waiter 所需的那个具体地址仍缺。

### 12.1 意外收获：两机布局常量完全相同

PCKM00 的 `target.h` 与本机反推值完全一致：

```
KIMAGE_TEXT_BASE   = 0xffffff8008080000   [两机相同]
PAGE_OFFSET        = 0xffffff8000000000   [两机相同]
PHYS_OFFSET        = 0x80000000           [本机 DTB 佐证]
__pa(_text)        = 0x88080000 = PHYS + 0x8080000
```

⇒ 线性映射锚点 `PAGE_OFFSET`/`PHYS_OFFSET` 可从 PCKM00 直接继承（已由本机 DTB 独立验证）。若 KernelSnitch 给出任一线性映射地址，即可反推 slide（`__pa(_text)+slide` 的线性别名）。这是 KernelSnitch 对 K3 的**真正价值**：定 KASLR slide，而不是填 fake waiter。

## 13. 修正后的最终判定

| 项 | 上一轮判定 | 源码预研后 | 依据 |
|---|---|---|---|
| boot_id 是否前提缺失 | 不成立（前提缺失） | **维持** | §9.2 源码铁证 |
| ashmem_fops 是否地址源 | 不成立 | **维持** | §9.1 利用链铁证 |
| KernelSnitch 4.14→4.9 | 需整体重做 | **推翻：机制同源，改 3 个常量即可** | §10 差异表 |
| KernelSnitch 采样量/精度 | KPTI+HZ 使精度未知 | **部分推翻：采样量可控、hashsize 自动覆盖、计时大概率可用** | §11 |
| KernelSnitch 输出能否填 fake waiter | （未明确） | **不能：推导链断裂** | §12 |
| 线性映射锚点能否继承 | 部分成立 | **成立：两机常量完全相同且本机 DTB 佐证** | §12.1 |

**净判定（修正版）**：v007 的三条技术里，KernelSnitch 的**可实现性**比我上一轮估计的高（易移植、采样可控），但它的**用途**被我上一轮高估了——它解决的是"得到线性映射锚点 / KASLR slide"，而 K3 GhostLock 当前卡的"fake waiter 的 lock/rb 内核地址"仍未解决（§12 推导链断裂）。boot_id 与 ashmem 依旧是后置技术。

**因此，对 GhostLock 重开条件（§7 第 2 条 a）的判定不变：尚未触发。** KernelSnitch 能给"可信线性映射锚点"，却给不了"fake waiter 可用的那个具体内核地址"——**本机缺的仍是第一个正确的地址，本轮的结论从"精度未知"收紧为"能定 slide、定不了 waiter"。**

## 14. 建议的下一步（修正版，仍需单独授权）

1. **[高优先，纯离线]** 把 PCKM00 的 `kernelsnitch/` 移植到本机参数（`MM_STRUCT_SZ=896`、`MM_ORDER` 重定、`cpu=4`），在 PCKM00 源码基础上做编译期适配——不产出可运行 PoC，只验证碰撞一致性逻辑在本机参数下自洽。
2. **[高优先，纯离线]** 重新审视 §15.4 的 fake waiter 约束：如果 `lock` 可用"内核栈自引用地址"，那么问题的关键变成"能否泄露当前内核栈地址"——KernelSnitch 给的是 mm_struct（堆），不是栈。评估是否有别的侧信道能给栈地址（这是 §7 第 2 条 a 的真正内容）。
3. **[中优先，单条只读指令待授权]** 设备侧只读确认 `cntvct_el0` 用户态可读性（一条 `mrs`），以关闭 §11.1 的最后不确定性——需用户明确授权才执行。
4. **[不做]** boot_id / ashmem 的后置实现（前置写原语不存在）；任何上机 PoC（97% panic + 无 panic 文本）。

**一句话（修正版）**：PCKM00 源码把上一轮的两个"未知"变确定了——KernelSnitch 好移植、采样可控，但它给的是 mm_struct 线性地址，填不进 K3 的 fake waiter；**"能定 slide、定不了 waiter"是本轮把缺口收紧到的新精度。**
