# 审核意见 v008 响应：三类地址的独立关系、oracle/唯一性分离与离线研究重排（2026-11-19）

> 响应 `docs_archive/审核意见CHATGPT-v008.txt` 第 4/5/6 条。**全程离线**：只读 `firmware_F16/vmlinux.elf`、`kallsyms_out.txt`、`k3_kernel_config.txt`、`kernel_appended.dtb` 的分析结论，以及 `ref_pc/km00` 参考源码；未连接设备、未改任何既有结论的正文、未产出 PoC。
> 结论与数字以 `HANDOVER.md` 为唯一权威；本文是 v008 引起的**口径收紧 + 新离线审计**，不改动 v3.0 的四层判定。

---

## 0. 结论先行

| v008 审核点 | 处置 | 结果 |
|---|---|---|
| §4 把 `mm_struct 线性地址 / KASLR slide / DPM 基址` 并列为"端到端可得"混淆了不同概念 | **接受并更正** | 三者分属两套独立映射：DPM 地址定位（R1）、物理地址换算（R2）、内核镜像 slide（R3）。**KernelSnitch 只给 R1，R2 是确定换算、无秘密，R3 拿不到**（§1） |
| §4 `FEASIBILITY_v007.md §12.1` 的推导有未补证步骤 | **接受并指出具体错误** | §12.1"任一线性映射地址即可反推 slide"与本文 §1.3 的反汇编证据冲突，且与同文 §9.2（slide 来自 boot_id 的镜像 VA 泄露）**自相矛盾**；已加更正块（§1.4） |
| §4 110× 信号与 N=4 唯一性是两件事 | **接受并形式化** | 拆成两道独立的门 G1（真机时序 oracle）与 G2（离线唯一性数学），互不蕴含；并据此把"全链端到端可行"降级（§2） |
| §5 对 ROOT 状态的影响 | **确认** | 四层判定不变，GhostLock 仍是"研究路径重开"而非"接近 ROOT 成功"（§3） |
| §6 下一阶段优先级 | **接受并重排** | P1 堆地址路线可行性边界（新审计见 §4.1）；P2 `!VMAP_STACK` 栈泄露面重审（§4.2）；P3 收紧口径（§1）；不做 boot_id/ashmem（§4.4） |

**一句话**：v008 的核心意见成立且可落到二进制——KernelSnitch 泄露的是**线性映射里一个 slab 对象的物理位置**（R1），到物理地址是**无秘密的确定性换算**（R2），而 `.text` 的 KASLR slide 由**另一套映射**（`kimage_vaddr/kimage_voffset`）在启动时单独确定（R3），**不能由一个 mm 地址反推**。这不会推翻"侧信道真机可用"，但会把 v3 表述中"端到端可得 KASLR slide"这句夸大撤回。

---

## 1. 三类地址的严格分离（响应 v008 §4）

### 1.0 为什么必须分开：本机存在两套互相独立的地址映射

| 映射 | 参数 | 性质 | 二进制/config 证据 |
|---|---|---|---|
| **线性映射（DPM / physmap）** | `PAGE_OFFSET=0xffffff8000000000`、`PHYS_OFFSET=0x80000000` | **编译期固定**，无运行时变量、无 slide | `CONFIG_ARM64_VA_BITS_39=y`；`kfn.py --list 'page_offset_base\|phys_base'` **无结果**——本机不像 x86-64 有可被 KASLR 随机化的 `page_offset_base`；DTB 保留区 `hyp_region@85700000` 等独立佐证 `PHYS_OFFSET=0x80000000` |
| **内核镜像映射** | `kimage_vaddr` / `kimage_voffset` | **启动期计算**，承载 KASLR slide | `CONFIG_RANDOMIZE_BASE=y`、`CONFIG_RELOCATABLE=y`；`kimage_voffset` ELF 符号 @ `0xffffff8009852508`（STT_OBJECT）；`kimage_vaddr` @ `0xffffff8009127000` |

> 这正是 v008 所述的两套映射："线性映射使用 PAGE_OFFSET/PHYS_OFFSET 做虚拟↔物理换算；内核镜像映射使用 kimage_vaddr/kimage_voffset，KASLR offset 由镜像虚拟地址相对固定基址计算。"二者**不共享秘密**。

### 1.1 R1 — DPM 线性映射地址定位（KernelSnitch 的**真实且唯一**输出）

- 输出：`mm_va`，落在 `[PAGE_OFFSET, PAGE_OFFSET+8GB)`、按 896 B（`mm_struct` 尺寸）对齐的候选网格上。
- 获取：真机 futex 桶碰撞计时（G1）→ 离线全窗口哈希枚举（G2），候选数 `9,586,981 ≈ 2^23.19`。
- **这是有价值的内核地址泄露**：它给出某个 `mm_struct` slab 页在线性映射中的位置（等价于该页的物理帧）。v008 对此的肯定成立——"泄露 mm_struct 线性映射地址，确实是有价值的内核地址泄露，能帮助确定相应线性映射区域的内存位置"。
- 但它**只是 DPM 中的一个堆点**：既不指向栈，也不定位任何特定 `pi_state`（`WAITER_ADDRESS_ANALYSIS.md` §5.5 已证 futex key 不含栈地址）。

### 1.2 R2 — 物理地址换算（确定、无秘密）

```
pa = mm_va - PAGE_OFFSET + PHYS_OFFSET
   = mm_va - 0xffffff8000000000 + 0x80000000
```

实测代入 `mm_va=0xffffff8041eed880`（`tools/KSNITCH_LOCAL_CHECK.md` §3 的构造目标）：

```
0xffffff8041eed880 - 0xffffff8000000000 = 0x41eed880
0x41eed880 + 0x80000000                = 0xc1eed880   ← 该 mm_struct 所在页的物理地址
```

- **关键点**：两个常量均为编译期固定值，换算式中**不含任何运行时秘密**。泄露 `mm_va` 只暴露"这一个 slab 页的物理位置"，**不暴露关于线性映射布局随机化的任何信息**——因为本机线性映射根本没有可随机化的基址。
- 因此"DPM 基址可得"的正确含义是：**固定常量已知**，而不是"泄露了一个秘密基址"。这一区分正是 v008 要求的口径收紧。

### 1.3 R3 — 内核镜像 KASLR slide（**需要独立的镜像虚拟地址泄露**）

- 链接期基址：`_text @ 0xffffff8008080000`（ELF 符号）。
- 运行时 slide = 镜像运行虚拟基址 − 链接期基址；它体现在 `kimage_voffset` 中。
- **启动期反汇编铁证**（`kfn.py __primary_switched --n 0xc0`，函数 @ `0xffffff8009a00184`）：

```
0xffffff8009a001b8  adrp x4, #0xffffff8009127000   ; kimage_vaddr 符号地址
0xffffff8009a001bc  ldr  x4, [x4]                  ; 取链接期镜像虚拟基址
0xffffff8009a001c0  sub  x4, x4, x0                ; 减去启动传入的物理装载基址 x0
0xffffff8009a001c4  adrp x5, #0xffffff8009852000
0xffffff8009a001c8  str  x4, [x5, #0x508]          ; → 0xffffff8009852508 = kimage_voffset 槽位
```

  `0xffffff8009852508` 与 ELF 符号 `kimage_voffset` 地址**精确吻合**。arm64 内核镜像地址换算走 `__pa(v) = v − kimage_voffset`，与 §1.2 的线性映射公式是**两条独立路径**。

- **结论**：要恢复 slide，必须拿到一个**运行时内核镜像虚拟地址**（如某个 `.data` 函数指针）再减去链接期偏移。参考项目的 boot_id 回读正是这种机制（泄露 `nfulnl_logger` 指针 → `stext = leaked − offset`，见 `FEASIBILITY_v007.md` §9.2），而它**需要先有 GhostLock 写原语**——循环依赖，当前不具备。

> ⇒ **R1/R2 推不出 R3**：`mm_struct` 是 slab 对象（页面来自 buddy/SLUB 分配），其线性地址与该 boot-fill 的 `kimage_voffset` 之间没有任何固定数学关系。"一个 mm 地址 ⇒ KASLR slide 已恢复"是把一种内核地址泄露夸大成另一种——v008 §4 的批评成立。

### 1.4 `FEASIBILITY_v007.md §12.1` 的更正与文档内部矛盾

- **原文 §12.1**："若 KernelSnitch 给出任一线性映射地址，即可反推 slide（`__pa(_text)+slide` 的线性别名）。"
- **错在**：假设"任一线性地址"与"镜像虚拟基址"之间存在可反解关系。由 §1.2/§1.3，线性地址只含固定常量换算；`kimage_voffset` 是启动期独立写入的值，二者不共享秘密。"`__pa(_text)+slide` 的线性别名"确实存在（镜像物理页在线性映射中有别名），但**知道一个 mm 页的线性地址并不能定位镜像的线性别名**。
- **同文自相矛盾**：`FEASIBILITY_v007.md` §9.2 已正确指出 slide 来自 boot_id 回读的内核镜像 VA 泄露（且需写原语前置）；§12.1 却说任意线性地址即可反推 slide。两种机制互斥。按 §1.3 的反汇编证据，**§9.2 正确、§12.1 应撤回**。
- **处置**：在 `FEASIBILITY_v007.md` §12.1 就地加更正块（保留原文，符合项目的"负知识"惯例），并在 §13 判定表加注；本文是权威更正来源。

---

## 2. 时序 oracle 与唯一性是两道独立的门（响应 v008 §4 后半）

v008："真机探针的 110× 信号证明时序 oracle 存在，但还应与这一唯一性问题分别看待。"——接受，形式化为两个互不蕴含的判据：

| 门 | 命题 | 证据域 | 当前状态 | 失败后果 |
|---|---|---|---|---|
| **G1 时序 oracle** | 用户态能用计时识别与堆积桶同哈希的 futex 地址 | **真机**（物理/时序） | ✅ 成立：空桶 9 tick vs 堆积桶 992 tick（**110×**）；512 候选中命中 1 个真实碰撞（`live_probe/LIVE_PROBE_RESULT.md` §2） | 拿不到碰撞集合，无从恢复 |
| **G2 唯一性** | 给定 N 个碰撞，能在 ~9.6M 候选中唯一确定目标 `mm_struct` | **离线数学**（哈希 OR 语义） | ⚠ 边缘：N=4 误报期望 **0.65**（被 `h_sizes[]` 的最小 256 桶主导）；N≥5 或单用 1024 桶判定可降到 `2.4e-3` / `8.9e-6`（`tools/KSNITCH_LOCAL_CHECK.md` §4） | 多个候选无法区分 → 猜错即 panic |

- **独立性**：G1 的信噪比（256 线程探针 vs 参考 4096）只决定"能否采到足够多的**真**碰撞"；G2 决定"这些碰撞在数学上是否**够用**"。110× 再高也不会改变 N=4 的误报期望；把 N 提到 5 也不会改善真机计时。**v008 的"分别看待"成立**。
- **额外收紧（主动，同属 v008 精神）**：`LIVE_PROBE_RESULT.md` §3 的"KernelSnitch 全链（观测+离线恢复）端到端可行"表述偏强——真机只做了 G1，G2 是在**合成目标**上离线验证算法自洽，二者**没有在真机上串成一次对未知 mm 的完整恢复**；R3（slide）根本没有获取。已在 §5 记入文件变更，相关文档加更正注记。
- **净判定**：G1 真机成立、G2 数学边缘（可控到稳固）、**G1∧G2 的端到端组合未演示、R3 未获取**。表述统一降级为"两个子环节分别验证，端到端恢复与 slide 获取未实机演示"。

---

## 3. 对 ROOT 状态的影响（响应 v008 §5）

v008 §5 的结论与 v3 四层判定一致，逐项确认：

| 研究方向 | v3 后状态 | 本文确认 |
|---|---|---|
| Wi-Fi 私有 Binder UID 0 | 已达成受限 root | 不变，非完整 ROOT |
| SELinux 域逃逸 | 静态审计无可达路径 | 冻结 |
| GhostLock 触发与栈载体 | 已有证据 | 不再是主要缺口 |
| KernelSnitch futex 侧信道 | 真机信号成立 | 不变（G1 ✅） |
| fake waiter 所需的受控 `rt_mutex` 地址 | 未解决 | **当前主要阻断**（②/③） |
| W 线程内核栈地址泄露 | 未解决 | 替代研究方向（P2） |
| 完整可用临时 ROOT / 持久 ROOT | 未达成 | **NO-GO，不变** |

**确认 v008 的判断**："没有改变最终 ROOT 结论，但改变了 GhostLock 的研究优先级"；"是实质性进步，而不是换个说法继续 NO-GO"。本文不把任何 NO-GO 改成 GO。

---

## 4. 离线研究优先级重排（响应 v008 §6）

### 4.1 P1 — 堆地址路线可行性边界审计（新增离线审计）

v008："重点不是重复验证 futex 计时，而是审计 K3 是否已经具备可控的内核堆对象分配与生命周期条件。PCKM00 的 AF_UNIX skb 路线是对照案例，但不能直接假定 K3 的内核分配器行为相同。"

**本机能确认的（符号/config 级）**：

| 条件 | K3 状态 | 证据 |
|---|---|---|
| AF_UNIX skb 喷射的**分配接口** | **存在** | `CONFIG_UNIX=y`；`__alloc_skb @0xffffff8008e8fdd8`、`sock_alloc_send_pskb @0xffffff8008e8db28`、`unix_stream_sendmsg @0xffffff8008fad5e8` |
| 可控大小的内核堆缓存 | **存在** | `kmalloc-128`：249056 对象；`mm_struct` 896 B / order-2（slabinfo）；无 `SLAB_FREELIST_RANDOM` |
| memfd（参考用于布局） | **存在** | `sys_memfd_create @0xffffff80081f4828` |
| msg_msg（System V IPC）路线 | **不存在** | `# CONFIG_SYSVIPC is not set` |
| userfaultfd（分配时序控制） | **不存在** | `# CONFIG_USERFAULTFD is not set` |
| setxattr 作为喷射原语 | **实测失败** | 2000 次仅 33 次成功、`kmalloc-128` delta=0（`HANDOVER.md:323`） |

**仍未确认、且是真正边界的**：参考项目靠 **AF_UNIX skb 喷射 + KernelSnitch mm 页 + 固定 delta**（`SKB_DATA_DELTA=-0xe80`、`ORDER3_SIZE=PAGE_SIZE<<3`）把 payload 落到**已知内核地址**。K3 上这条链缺的不是"能否分配"，而是：
1. **地址可知性**：即使能喷 skb，也需知道喷射页的落点；参考的落点推导依赖 `MM_ORDER=3`，本机为 `pages/slab=4`（order-2），delta 与布局**不能直接继承**（`KSNITCH_LOCAL_CHECK.md` §6 阻挡项）。
2. **生命周期可控性**：无 uffd/msg_msg 时，能否稳定地"分配—停留—释放—重占"以把受控对象放到目标页，属设备行为，**纯离线不可判定**。

⇒ P1 的封闭判据（可证伪）：给出 K3 上"**受控内容 → 已知内核虚拟地址**"的完整推导（含 order-2 下的新 delta），并说明如何填进 fake waiter 的 `lock`/rb。否则维持 ② 未闭合。

### 4.2 P2 — `!VMAP_STACK` 下栈地址泄露面重审（新增离线审计）

v008："确认 `!VMAP_STACK` 设备上有哪些与栈页位置有关、又能从低权限观察到的机制。已有 futex 哈希侧信道不包含栈地址，不能重复用它来论证栈地址可得。"

| 候选机制 | 本机状态 | 判定 |
|---|---|---|
| futex 哈希侧信道（KernelSnitch） | 可用（G1 ✅），但 key = `{用户地址, mm/inode, offset}`，**栈地址不进 hash** | ❌ 不可用（源码层确认，`futex.c:391-396`） |
| USENIX'25 TLB 栈侧信道 | 依赖 `CONFIG_VMAP_STACK`；本机 `# CONFIG_HAVE_ARCH_VMAP_STACK is not set`，栈退回 DPM 的 order-2 大页背景 | ❌ 不适用（粒度前提缺失） |
| `perf_event_open` 栈采样 | 符号存在（`sys_perf_event_open @0xffffff80081c3900`、`CONFIG_PERF_EVENTS=y`），但 Android 的 `perf_event_paranoid` 对 uid 2000 的限制**未在本机读取** | ⚠ 未定，**需授权只读确认**，本文不据此下结论 |
| `/proc/self/*`、pagemap 类 | 只暴露用户态映射；读物理帧需 `CAP_SYS_ADMIN`（当前 `CapEff=0x13000`） | ❌ 不可达 |

- 栈几何本身**已静态解决**（16 KB 对齐、waiter 偏移固定），缺的是"获得持有 stale waiter 的 W 线程**当前栈基址**的 oracle"——`WAITER_ADDRESS_ANALYSIS.md` §5.5.2 的结论维持。
- **可证伪条件维持**：出现"以内核栈地址（`thread_info`/`task_struct.stack`）为键、用户可观测"的新原语 ⇒ 直接闭合 ③。不得以"栈与 mm 同处 DPM"作为替代论证。

### 4.3 P3 — 收紧地址泄露结论

即本文 §1：所有入口文档统一改为"R1 可得 / R2 确定换算无秘密 / R3 未获取"，删去"端到端可得 KASLR slide"的并列表述。

### 4.4 明确不做（与 v008 §6 一致）

- **boot_id 回读**：依赖既有内核写原语，是后置 KASLR 校验步骤，不是当前缺口起点（§9.2 铁证）。
- **ashmem_fops 地址源**：用于验证已获得的地址，不是地址来源（§9.1 利用链铁证）。
- **GhostLock 端到端 PoC**：参考自报 ~97% panic、本机 panic 文本不可读。
- 任何设备上机动作（本文全程离线）；如 P2 的 perf 只读确认需要设备，单独申请授权。

---

## 5. 判定可能错在哪（自我声明）

1. **x86 直觉迁移**："线性地址泄露 ⇒ DPM 基址泄露 ⇒ slide"在 x86-64（有 `page_offset_base`）上可能成立，但本机 arm64 无该变量（§1.0 已查符号表）。若未来固件引入随机化线性映射的机制，§1 的 R2/R3 关系须重算。
2. **反汇编解读**：`kimage_voffset = kimage_vaddr − x0` 中 x0 为启动传入的物理装载基址，取自标准 arm64 `__primary_switched` 序列；指令字节已核对，但未在真机 dump 运行时 `kimage_voffset` 值（属设备上机，未授权）。
3. **P1/P2 边界**：堆喷射与 perf 限制属设备行为，纯离线只能确认"接口存在/不存在"，不能确认"低权限下可控"。已显式标注未定项，未把"未试出"写成"不可能"。

## 6. 如何推翻本文（只接受可复算反例）

| 不构成推翻 | 构成推翻 |
|---|---|
| "侧信道能拿地址 ⇒ 拿到 slide" | 给出从 `mm_va` 到 `kimage_voffset` 的**可复算数学关系 + 反汇编**，并说明为何与 §1.3 的两套映射不冲突 |
| "110× 说明全链端到端" | 给出一次真机对**未知** mm 的完整 G1+G2 恢复记录，以及 R3 获取结果 |
| "参考项目有 skb 喷射，K3 也能" | 给出 K3 order-2 布局下受控内容 → 已知内核地址的新 delta 推导 |
| "栈与 mm 同处 DPM" | 给出以栈地址为键的用户可观测侧信道原语（并说明 `!VMAP_STACK` 下粒度来源） |

---

## 7. 本轮文件变更

| 文件 | 变更 |
|---|---|
| `FEASIBILITY_v008.md` | **新增**：本文（v008 响应主文档） |
| `FEASIBILITY_v007.md` | §12.1 就地加更正块；§13 判定表加注 |
| `HANDOVER.md` | 新增 §43（v008 响应），头部口径说明 |
| `README.md` / `HANDOVER_RESUME.md` / `CLOSURE.md` | 收紧"端到端可得 KASLR slide"表述为 R1/R2/R3 三分 |
| `DUAL_TRACK_RESULT.md` / `live_probe/LIVE_PROBE_RESULT.md` | 加"G1/G2 分离、端到端未演示"更正注记 |
| `docs_archive/README.md` | 登记 v008 已响应 |
| 设备 | **未连接、零副作用** |

## 8. 一句话

**v008 抓到了 v3 最容易被误读的一处：KernelSnitch 给的是线性映射里一个堆页的物理位置（R1→R2 确定换算、无秘密），不是 `.text` 的 KASLR slide（R3 需独立镜像 VA 泄露，本机拿不到）；110× 只证明时序 oracle 存在，与 N=4 唯一性是两道独立的门。ROOT 判定不变，GhostLock 的研究优先级按"堆地址边界 → 栈泄露面 → 口径收紧"重排，boot_id/ashmem 维持不做。**
