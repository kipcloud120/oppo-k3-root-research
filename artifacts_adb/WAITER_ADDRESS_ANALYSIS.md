# Fake waiter 的"内核地址"约束精确化分析

- 任务来源：team-lead 分派（ghost-hoock / CVE-2026-43499 研究项目）
- 日期：2026-11-19
- 性质：**纯源码 / 文档分析**。未连接设备、未修改任何既有文件、未产出 PoC。
- 唯一新增文件：本文（`artifacts_adb/WAITER_ADDRESS_ANALYSIS.md`）。
- **2026-11-19 增补（方向 B 复核）**：team-lead 实测本机 `CONFIG_THREAD_INFO_IN_TASK=y`、
  `# CONFIG_HAVE_ARCH_VMAP_STACK is not set`（VMAP_STACK 未启用），栈由 order-2 页分配于 DPM
  线性映射区。据此新增 **§5.5**，专门回答"栈与 mm 同区能否让 KernelSnitch 泄露栈地址"。

## 0. 引用口径与一处路径更正

- 任务书写的权威源路径 `src_ref/kernel_49_mainline/kernel/rtmutex.c` **不存在**；实际权威文件为
  `src_ref/kernel_49_mainline/rtmutex.c`（1763 行）。本文所有 `:NNN` 均指该文件，除非另注。
- 项目内另有 `src_ref/futex_4.9/rtmutex.c`（1788 行），按任务要求**不采用**。
- 结构体偏移以 `HANDOVER.md` §8.1（588–598 行）为准：`rt_mutex_waiter` = 72 B (0x48)，
  `tree_entry=0x00 / pi_tree_entry=0x18 / task=0x30 / lock=0x38 / prio=0x40`，**无 `deadline` 字段**。
  参考实现 ref_pc/km00 针对 4.14（waiter 0x50、deadline 0x48，见 `slide.c:103-105`），
  与本机 4.9 布局不同，但被读取的五个字段偏移一致（`HANDOVER.md:598` 已确认）。

## 1. 结论速览

| 问题 | 结论 | 置信度 |
|---|---|---|
| 1. `lock` 仅比较还是解引用 | **会被解引用**（trylock 写 + owner/top_waiter/dequeue/enqueue 反复解引用）；`lock==orig_lock` 只是其中一次比较 | 确认 |
| 1. `task` 是否被解引用 | 主路径（`prio≥0`）**不**解引用；只需 8 字节全非零 | 确认 |
| 2. `RB_EMPTY_NODE` 自引用能否让 dequeue 直接返回 | **能**，但自引用值必须精确等于 `&waiter->tree_entry`（当前内核栈地址） | 确认 |
| 2. 该自引用是否必须精确栈地址 | **是**（在"自引用干净通过 dequeue"这条构造下） | 确认 |
| 3. 真正硬门槛 | **"至少一个指向受控、可写、结构合法 `rt_mutex` 的内核虚拟地址"**；K3 载体下具体化为**当前内核栈地址**（a），pi_state 堆地址（b）是替代路径；任意非零线性地址（c）**不够** | 确认 + 推断 |
| 4. KernelSnitch 对 K3 fake waiter | **仅能定 slide（DPM 基址）**；对硬门槛本身**无关**——既不给栈地址，也不定位特定 pi_state | 确认 + 推断 |
| 4. 本机 !VMAP_STACK 是否改判方向 B | **不改判**。栈确在 DPM 同区，但 futex 碰撞 key 的输入只有 `mm_struct`/inode，**栈地址不进 hash** ⇒ 无法以栈为目标碰撞探测；栈地址侧信道（USENIX'25 TLB）依赖 VMAP_STACK，本机恰好关闭 ⇒ 更不利 | 确认（hash 源码层）+ 推断 |
| 4. 若已知某栈基址能否推 fake waiter 精确地址 | **能**（几何可行：栈 16KB 对齐 + waiter 相对 sp 偏移固定，见 §5.5.2），但前提"拿到当前线程栈基址"本身无 oracle | 确认（几何）+ 未定（前提） |
| 5. §7 第2条(a) 是否需细分 | **需要**。"任一内核地址泄露"过宽，应按地址类型分三档 | 建议 |

---

## 2. 问题 1：fake waiter 各字段在 4.9 的读取 / 解引用逐行核对

调用链入口：`rt_mutex_adjust_prio()` 在 `rtmutex.c:1141-1153` 读 `waiter->prio`、`waiter->lock`
（`next_lock = waiter->lock`，`:1146`），随后进入 `rt_mutex_adjust_prio_chain()`（`:490-819`）。
`waiter = task->pi_blocked_on` 于 `:549` 取得。

### 2.1 `lock`（0x38）——**被解引用，是主要硬门槛来源**

| 行 | 动作 | 性质 |
|---|---|---|
| `:422-425` | `task_blocked_on_lock(p) = p->pi_blocked_on->lock` | 从 waiter 读 lock（守卫 `next_lock` 的同源） |
| `:579` | `if (next_lock != waiter->lock)` | **纯指针比较**，无解引用；`next_lock` 由 `:1146` 从同一字段读出 ⇒ 守卫退化恒等（与 `GHOSTLOCK_NUL_ANALYSIS.md:106` 一致） |
| `:621` | `lock = waiter->lock` | 赋给局部，开始解引用链 |
| `:627` | `raw_spin_trylock(&lock->wait_lock)` | **内核对 fake 对象的第一次写**：`lock+0x00`，arm64 ticket lock 要求两半相等（`NUL 分析 §5:109`） |
| `:642` | `lock == orig_lock \|\| rt_mutex_owner(lock) == top_task` | 一次指针比较 **+ 一次解引用**（读 `lock+0x18` owner） |
| `:666/:672/:721/:734` | `rt_mutex_owner(lock)` | 反复解引用 owner |
| `:703/:727/:787` | `rt_mutex_top_waiter(lock)` | 经 `rtmutex_common.h:46-56`：`:51` 读 `lock->waiters_leftmost`(0x10)，`:53` `BUG_ON(w->lock != lock)` 再读一次 waiter->lock |
| `:706` | `rt_mutex_dequeue(lock, waiter)` | 读 `lock->waiters`(0x08) 并写（rbtree 操作） |
| `:708` | `rt_mutex_enqueue(lock, waiter)` | 读写 `lock->waiters / waiters_leftmost` |

> **判定（确认）**：`lock` 绝非"只做 `lock==orig_lock` 比较"。它在 `:627` 被原子写、在 `:642/666/721/734`
> 读 owner、在 `:703/727/787` 读 waiters 树、在 `:706/708` 被 rbtree 改写。`lock` 必须指向一个
> **可写、结构合法的 `rt_mutex`**。`PAN/UAO` 开启时内核不能直接用用户态地址做这些访问
> （`HANDOVER.md:321`），所以 `lock` 必须指向**内核虚拟地址**。

### 2.2 `tree_entry`（0x00）

| 行 | 动作 |
|---|---|
| `:274` | `if (RB_EMPTY_NODE(&waiter->tree_entry)) return;` —— 读 `__rb_parent_color`，与 `&waiter->tree_entry` 比较 |
| `:277-278` | `lock->waiters_leftmost == &waiter->tree_entry` → `rb_next(&waiter->tree_entry)` |
| `:280-281` | `rb_erase(&waiter->tree_entry, &lock->waiters)` + `RB_CLEAR_NODE` |
| `:267-268` | enqueue 写 `left/right/parent_color`（内核自己按真实地址写，不需攻击者给址） |
| `:226-240` | `rt_mutex_waiter_less()` 读 `left->prio`(0x40)；**仅 `dl_prio(prio)` 时**读 `left->task->dl.deadline`（4.9 waiter 无 deadline 字段，故 `prio≥0` 时不读） |

### 2.3 `pi_tree_entry`（0x18）

| 行 | 动作 |
|---|---|
| `:313` | `rt_mutex_dequeue_pi()` 内 `RB_EMPTY_NODE(&waiter->pi_tree_entry)` —— 同样需要自引用 = `&waiter->pi_tree_entry`（栈地址） |
| `:316-320` | leftmost / `rb_next` / `rb_erase` / `RB_CLEAR_NODE` |
| `:306-307` | enqueue_pi 写 |
| `:746-747 / :761-763` | 在 `:739` 或 `:750` 的 top-waiter 分支间接调用（只有 fake waiter 成为 top 才走到） |

### 2.4 `task`（0x30）——**主路径不解引用（确认）**

- 全文件仅 `:975` 赋值 `waiter->task = task`、`:1067` `wake_q_add(wake_q, waiter->task)`（唤醒路径）；
- `:728` `wake_up_process(rt_mutex_top_waiter(lock)->task)` 需 `!rt_mutex_owner(lock)`（`:721`）且 top_waiter 为 fake；
- `rt_mutex_waiter_less()` 的 `:239-240` 只在 `dl_prio(prio)` 为真时读 `task->dl.deadline`；本机 4.9 `prio≥0` 时不成立。
- ⇒ 与 `HANDOVER.md:886-887`、`NUL 分析 §5:116` 一致：**`task` 只需 8 字节全非零**。

### 2.5 `prio`（0x40）

- `:611` `if (waiter->prio == task->prio)` 读比较；相等则（依 detect_deadlock）早退或令 `requeue=false`，**写原语消失**；
- `:707` `waiter->prio = task->prio` 自写；`:229` 在 `waiter_less` 中读。
- ⇒ 需合法非零且 `≠ task->prio`（普通任务 120，取 130 一类；`NUL 分析 §4:96`）。

---

## 3. 问题 2：`RB_EMPTY_NODE` 自引用与 rb 链接

### 3.1 自引用能否让 dequeue 直接返回 —— 能（确认）

`rt_mutex_dequeue()`（`:271-282`）首句即：

```c
if (RB_EMPTY_NODE(&waiter->tree_entry))
        return;
```

Linux 4.9 的宏定义为 `(node)->__rb_parent_color == (unsigned long)(node)`；因此只要
`waiter->tree_entry.__rb_parent_color` 填成 `&waiter->tree_entry` 的数值，`:274` 立即返回，
跳过 `:280` 的 `rb_erase`（即跳过"按攻击者给的 rb 链接派生写地址"的危险路径）。

### 3.2 自引用值是否必须精确等于栈上实际地址 —— 是（确认）

- fake waiter 由 xattr 经 `strncpy_from_user` 写到**内核栈**（`HANDOVER.md:327-329`、更正块 `:336-344`）；
- 宏比较的是 `&waiter->tree_entry` 这个**运行期虚拟地址**，不是"某个常量"。地址填错 ⇒ 比较失败 ⇒ 走进
  `rb_erase`，按错误链接派生写地址 ⇒ 写乱内存 / panic（`HANDOVER.md:917-918`：`rb_parent()` 清低 2 位，"随便填非零垃圾必然把写打到不可控地址"）。
- ⇒ **这条构造下必须知道"当前内核栈地址"**（更精确：`waiter->tree_entry` 在栈上的绝对虚拟地址）。

### 3.3 重要限定：自引用不是唯一走法（推断，有源码证据）

参考实现 ref_pc/km00 **并不使用自引用**，而是把 rb 链接指向已知内核全局符号以制造可控写：

- `slide.c:115-120`：`tree_pc=SLIDE_LOGGERS_0_1`、`tree_right=0`、`tree_left=SLIDE_RANDOM_BOOT_ID_DATA`；
- `util.c:502-504`：`pi_tree_entry` 填 `write_pc / write_right / write_left`（`write_pc=fake_fops`，`:468`）；
- 即由 `rb_erase` 把写导向 `fake_fops` / boot_id data 等**已知内核 data 地址**。

⇒ **修正一个常见混淆**：若目标是"制造写原语"，所需的是**已知内核 data/text 地址（slide）**，不一定是栈地址；
"必须知道当前栈地址"只在"用自引用让 dequeue 干净返回"或"lock 指向栈上 payload"这两种**与栈强绑定**的构造下成立。
这一点直接决定问题 3 与问题 4 的答案。

---

## 4. 问题 3：硬门槛精确化 —— 到底是哪一类地址

### 4.1 三类逐一判定

| 类别 | 是否硬门槛 | 理由 |
|---|---|---|
| **(c) 任意内核线性映射地址（只需非零、能通过比较）** | **否，且不够**（确认） | `lock` 在 `:627` 被 trylock 写、`:642/721/734` 读 owner、`:703` 读 waiters、`BUG_ON(w->lock!=lock)`(`rtmutex_common.h:53`) 校验；随便一个非零地址无法通过解引用与结构合法性要求。`HANDOVER.md:917-918` 亦指出乱填必打不可控地址 |
| **(b) kmalloc-128 堆地址（pi_state）** | **是一条可行路径，但非唯一**（确认+推断） | `futex_pi_state` 内嵌 `pi_mutex`（`HANDOVER.md:594`），天然是可写合法 `rt_mutex`；若已知其地址可令 `lock` 指向它。但分配序与 KASLR 使其地址未知（`HANDOVER.md:896`），且 K3 无本机 kmalloc-128 喷堆原语（`:321`、`setxattr 2000 次仅 33 次成功且 delta=0`） |
| **(a) 当前内核栈地址** | **K3 载体下的现实硬门槛**（确认+推断） | 见 4.2 |

### 4.2 K3 为什么把 (a) 顶到硬门槛位（核心推断链）

K3 与 ref_pc/km00 的**根本差异在载体位置**：

- ref_pc/km00：pselect `fd_set` 载体在**用户态**，payload 经 AF_UNIX skb 喷射落到**内核线性映射的可控页**，
  `fake_lock = payload_base + LOCK_OFF`（`util.c:450-452`，其中 `payload_base = base + SKB_DATA_DELTA`，
  `base` 来自 KernelSnitch 泄露的 mm_struct 地址，见 `util.c:604-605`）。
  ⇒ lock 指向**内核堆上的受控 rt_mutex**，栈地址从未被需要。
- K3：xattr `strncpy_from_user` 写到**内核栈**（`HANDOVER.md:327-329`）。`lock` 字段要指向一个内核态可写、
  结构合法的 `rt_mutex`，候选只有：
  1. 用户态地址 —— PAN 挡（`HANDOVER.md:321`）；
  2. 现成 `pi_state.pi_mutex` —— 地址未知（即 (b)）；
  3. **栈上另一处由 payload 伪造的 rt_mutex** —— 能写，但 `lock` 字段必须填成那处栈地址（即 (a)）；
  4. 内核堆喷射页 —— K3 **无此原语**（同上）。

⇒ **精确化结论（确认 + 推断）**：真正的硬门槛是

> **至少要有一个"攻击者可控、内核可写、结构合法 `rt_mutex`"的内核虚拟地址。**

在 K3 当前载体下，由于唯一可控内存是内核栈，这一门槛**具体化为 (a) 当前内核栈地址**
（用于让 `lock` 指向栈上伪造 rt_mutex，和/或 `tree_entry` 自引用）。(b) 是等价替代路径
（若某日能泄露/喷射 pi_state），但同样要求一次内核地址泄露。(c) 单独不成立。

> 注：`HANDOVER.md:889-899` 与 `NUL 分析 §6:118-128` 把约束写成"必须知道至少一个内核地址"
> 是正确的，但未区分类型；本文即是对它的精确化。

---

## 5. 问题 4：KernelSnitch 侧信道可达性

### 5.1 KernelSnitch 到底给什么（确认，web 来源）

- **NDSS 2025 KernelSnitch 论文**（`https://www.ndss-symposium.org/wp-content/uploads/2025-223-paper.pdf`，
  另见 TU Graz 镜像 `.../ndss25-kernelsnitch.pdf`）：通过 futex 哈希桶的时序侧信道检测
  `futex_hash(uaddr, mm_struct)` 碰撞，离线枚举直接物理映射（DPM/physmap）窗口，
  搜索空间约 `2^35.5`，**泄露的是 `mm_struct` 的堆地址**，即 DPM 中的对象地址；
  "kernel heap is directly accessed via the Direct Physical Mapping (DPM)"。
- 公开实现（ghost-hoock，`https://kitploit.com/zh/tools/github/deaurity/ghost-hoock`）明确：
  KernelSnitch 恢复"我们自己的 `mm_struct` 地址——即我们后续所需喷射页的基址"。
  与 ref_pc/km00 的 `util.c:604-605` 用途一致。

⇒ KernelSnitch 提供的是**DPM 线性映射中的堆地址 / slide 信息**，不是栈地址，也不是任意指定对象的地址。

### 5.2 对 (a) 栈地址 —— 无关（确认 + 推断）

- KernelSnitch 泄露的是 mm_struct slab 对象，栈不在 mm_struct slab；
- 已知的**栈地址**侧信道：TU Graz "When Good Kernel Defenses Go Bad"（USENIX 2025，
  `http://gruss.cc/files/usenix25-tlbsidechannel.pdf`；Black Hat USA 2025 同题报告）用
  prefetch + Evict+Reload TLB 侧信道以 4KB 精度泄露**内核栈**、msg_msg、cred、页表等地址，
  评估于 5.15/6.5/6.8（Intel/AMD/ARM）。但该攻击**明确依赖**
  `CONFIG_VMAP_STACK`（栈移入 vmalloc、4KB 页）、`CONFIG_SLAB_VIRTUAL` 或 strict module RWX
  造成的 2MB→4KB 拆分来形成细粒度 TLB 模式（来源：USENIX'25 论文摘要 + Black Hat 报告页
  `http://talksintel.ai/cybersecurity/conferences/blackhat-usa-2025/...`）。
- **本机 4.9**：`CONFIG_SLAB_VIRTUAL` 不存在；`CONFIG_VMAP_STACK` 在 4.9 时代为实验性、arm64 默认关闭
  （Kermes NDSS'27 `https://yancomm.net/papers/2027%20-%20NDSS%20-%20Kermes.pdf` 说明
  VMAP_STACK 默认开启是后来的事）⇒ 该栈侧信道在 4.9 上**不适用**（推断；最终以本机 `.config` 为准）。
- **未定**：未检索到专门针对 4.9、非 VMAP_STACK 内核栈地址的成熟公开侧信道。
  即使栈在 DPM 的 thread_stack slab 内，KernelSnitch 原语只针对 mm_struct，不能平移到栈。

### 5.3 对 (b) pi_state 堆地址 —— 仅间接（确认 + 推断）

- KernelSnitch 的 hash 输入是 `mm_struct` 指针，**不能直接给出 pi_state 地址**；
- 它能定 `page_offset_base` / DPM 窗口（slide），但 pi_state 的具体槽位取决于分配序（本机不可控，
  `HANDOVER.md:896、321`）；
- 更关键：即使拿到堆 slide，K3 **没有把 payload 放到该堆地址处的喷射原语**
  （ref_pc 靠 AF_UNIX skb 喷射，`util.c:447-465`；K3 无）⇒ slide 无法转成可用的受控 rt_mutex 地址。

### 5.4 判定

> **KernelSnitch 对 K3 fake waiter 是"仅能定 slide"，对当前硬门槛本身"无关"。**
> 它给了 DPM 基址，但既不给栈地址（a），也不定位特定 pi_state（b），且 K3 缺少把 slide 兑现为
> 受控 rt_mutex 地址的堆喷原语。只有当"存在可控堆喷射"这一前提成立时（K3 当前不成立），
> KernelSnitch 类泄露才等价于可用地址。

旁证（可靠性）：MT6985 适配失败日志（`https://kitploit.com/en/tools/github/233laoliu/mt6985-cve-2026-43499`）
记录 KernelSnitch 在 `CONFIG_KASAN_HW_TAGS`（MTE 标签指针参与 hash）下暴力匹配失效；
本项目本机是否具备该配置**未定**，但说明该侧信道并非普适。

### 5.5 增补：!VMAP_STACK + 同处 DPM 能否让 KernelSnitch 泄露"栈地址"

> 触发：team-lead 实测本机 `CONFIG_THREAD_INFO_IN_TASK=y`、`CONFIG_HAVE_ARCH_VMAP_STACK` 未设置。
> 4.9 arm64 在 `VMAP_STACK=n` 时走 `alloc_pages_node(node, THREADINFO_GFP, THREAD_SIZE_ORDER)`
> 再 `page_address(page)`（`THREAD_SIZE_ORDER=2` ⇒ 16 KB，4 个连续物理页），栈因而落在 DPM
> `[0xffffff8000000000, +8GB)`、按 16 KB 对齐，`current_thread_info = sp & ~(THREAD_SIZE-1)`。
> 该事实属实且重要；以下逐条回答它对方向 B 的影响。

#### 5.5.1 问题 1：碰撞机制能否从"定位 mm_struct"扩展到"定位栈基址" —— 不能（确认，源码层）

KernelSnitch 的 oracle 本质是：观测 `hash(uaddr, SECRET_PTR)` 的桶占用碰撞，反推那个"秘密内核指针"。
要让它以栈为目标，**栈地址必须作为某个 hash key 的输入**。本地 4.9 源码给出否定答案：

- `hash_futex()`（`futex.c:391-396`）：`jhash2((u32*)&key->both.word, (sizeof(word)+sizeof(ptr))/4, offset)`。
  整个 key 只有 3 类输入：
  1. `key->both.word` —— 用户态 futex 地址（**用户可控，非内核地址**）；
  2. `key->both.ptr` —— private futex 下由 `futex_get_mm()`（`futex.c:339`）填的 **`mm_struct*`**，
     shared futex 下是 inode 指针（`FUT_OFF_INODE`，`futex.c:435`）；**这是唯一的秘密内核指针**；
  3. `key->both.offset` —— `FUT_OFF_*` 小标志位。
- **内核栈地址从未进入 `union futex_key`**，因此不进入 `jhash2`。⇒ 无论怎样改变栈基址，桶占用都不变，
  没有可观测的碰撞信号可供反推 ⇒ **栈地址不是 KernelSnitch 的有效目标**。
- 能否"顺便"从泄露的 mm_struct 地址推出栈？不能：mm_struct 来自 slab（对象级、cache 对齐步进），
  栈来自 buddy order-2 页（16 KB），**两个独立分配域、无固定偏移**。mm 地址已知 ⇒ 只能定 DPM 中
  "一个点"，不能锚定任何特定线程的栈页。
- 换用 KernelSnitch 论文里其它数据结构（radix tree / rbtree，见 4hou 报道）也一样：oracle 要求目标
  对象的**地址本身作为哈希/树键**，而内核栈不是任何此类可观测结构的键。

#### 5.5.2 问题 2：若已知某栈基址，能否推出 fake waiter 精确地址 —— 几何上能，前提无 oracle（确认 + 未定）

- **几何部分（确认）**：若已知当前线程栈基址 `BASE = sp & ~(THREAD_SIZE-1)`（16 KB 对齐），
  则 fake waiter 中 `&waiter->tree_entry` 的精确地址可由 BASE + 固定偏移算出：
  waiter 起点相对 sp 的偏移由 `GHOSTLOCK_NUL_ANALYSIS.md §2.3`（`:60-71` 的 boff 表，
  fgetxattr `boff=0x10`）与 §3（`:75-88`：sp 复位、定长帧、无 VLA）静态确定；
  `tree_entry` 即 waiter 起点（偏移 0）。即"栈基址 → 自引用值"这一环**不是障碍**。
- **前提部分（未定/否定）**：障碍在于"拿到 BASE"本身。KernelSnitch 给的是 mm_struct 地址，
  不是任何线程的栈基址；mm 与栈无确定偏移（见 5.5.1）。且即便将来有某种栈泄露，它也必须是
  **持有 stale waiter 的那个线程 W 的栈**（waiter 写在 W 的栈上，`NUL 分析 §3:79`），
  而不是任意线程的栈——同一 mm 下多线程各有独立 16 KB 栈。
- ⇒ 精确化：真正缺的不是"从栈基址算 waiter 偏移"（这已静态解决），而是
  **"获得 W 线程当前栈基址"这一 oracle**，本机没有。

#### 5.5.3 问题 3：!VMAP_STACK + KernelSnitch 是否"就近在咫尺" —— 否，且 !VMAP_STACK 反而更不利（确认 + 推断）

- team-lead 的几何观察正确：栈与 mm_struct **同处 DPM 线性映射区**，KernelSnitch 的扫描窗口
  `0xffffff8000000000 ~ +8GB` 也覆盖栈。但"同区"不等于"可互相推导"：
  - mm_struct 是 slab 对象（细粒度、cache 对齐）；
  - 栈是 buddy order-2 页（16 KB 粗粒度），分配序、物理帧与 mm 无耦合；
  - oracle 的输入只有 mm_struct（5.5.1），栈地址不参与任何可观测哈希/树键。
  ⇒ **不构成针对栈地址的泄露组合**，§7 第2条(a) 不因本发现而放宽。
- 更关键的反直觉点：**对本目标而言 !VMAP_STACK 是减分项**。USENIX'25 的 TLB 栈泄露之所以能以
  4 KB 精度定位栈，正是**依赖 `CONFIG_VMAP_STACK`** 把栈移入 vmalloc 区、形成细粒度 TLB 冲突模式
  （见 5.2 引用）。本机 VMAP_STACK 关闭 ⇒ 栈退回 DPM 的 2 MB 大页背景，缺少该细粒度信号；
  该攻击在本机形态上**不适用**。故"栈落在 KernelSnitch 扫描窗口"带来的想象空间，被
  "失去唯一已知栈侧信道的粒度前提"抵消且有余。
- **净判定（方向 B 维持原结论，理由精确化）**：
  > KernelSnitch 仍只给 DPM 中的一个堆点（slide / mm_struct 地址），不给栈基址；
  > 本机 !VMAP_STACK 只说明"栈在 DPM"，并未提供"观测栈物理帧"的 oracle。
  > 因此它对 K3 fake waiter 依旧是**"仅能定 slide、对硬门槛无关"**，不存在"近在咫尺"的重开。

- **唯一可能改变判定的未定项**：若未来出现"以内核栈地址（或 `thread_info`/`task_struct.stack`）为键、
  用户可观测"的碰撞/时序原语（当前 4.9 源码与公开检索均未见），才可能把 KernelSnitch 方法平移到栈。
  这是可证伪条件，应登记为新的重开项，而非当前结论。

---

## 6. 问题 5：`HANDOVER.md` §7 第2条(a) 的精确化建议

原文（`:523-525`）："(a) **任一可用的内核地址泄露** ⇒ fake waiter 的 `lock` 与 rb 链接才有可填的值"。
按本文结论，此表述过宽 —— "任一地址"会把只给 slide 的 KernelSnitch 误判为可重开条件。

**建议改写为（三档）**：

> (a) 出现能定位**一个攻击者可控、内核可写、结构合法 `rt_mutex` 的内核虚拟地址**的信息泄露：
> - (a1) **当前内核栈地址**（K3 当前 xattr 栈载体下最直接：用于让 `lock` 指向栈上伪造 rt_mutex，
>   或让 `tree_entry/pi_tree_entry` 自引用）；
> - (a2) **某个可控 rt_mutex 的堆地址**（如 pi_state / skb 喷射页，等价于 ref_pc 的 `payload_base`）；
> - (a3) **仅有 KASLR text/data slide 或 DPM 基址（KernelSnitch 类）不足以单独重开**——
>   除非同时存在"能把 payload 写到该已知地址处"的可控堆喷射 / 写原语（本机当前无）。
> - (a4) **【!VMAP_STACK 增补后明确排除】** "栈与 mm 同处 DPM + KernelSnitch 扫描窗口覆盖栈"
>   **不构成栈地址泄露**：futex key 不含栈地址（`futex.c:391-396`，§5.5.1），且本机关闭 VMAP_STACK
>   使唯一已知的 4 KB 粒度 TLB 栈侧信道失效（§5.2/§5.5.3）。除非出现"以栈地址为键的用户可观测侧
>   信道"这一新原语，否则不得据此放宽 (a1)。

这条细分与 `NUL 分析 §7:143`、`HANDOVER.md:909` 的"等泄露原语"方向一致，只是把"泄露"限定到真正能
闭合 fake waiter 的地址类型上，避免把"仅定 slide"或"同处 DPM"误当作直接解药。

---

## 7. 标注汇总

| 结论 | 标注 | 依据 |
|---|---|---|
| `lock` 会被解引用（非仅比较） | **确认** | `rtmutex.c:627/642/666/672/703/706/708/721/734/787`；`rtmutex_common.h:51-53` |
| `task`/`prio` 约束 | **确认** | `rtmutex.c:611/707/975/1067/728`、`:226-240`；`HANDOVER.md:886-887` |
| 自引用使 dequeue 直接返回、且需精确栈地址 | **确认** | `rtmutex.c:274`；`HANDOVER.md:894`、`NUL 分析 §5:112 / §6:124` |
| "可控 rt_mutex 内核地址"是真正硬门槛 | **确认（定义层）+ 推断（K3 具体化为栈地址）** | `util.c:450-452`（ref_pc 反证）；`HANDOVER.md:321/896` |
| KernelSnitch = DPM 堆地址/slide | **确认** | NDSS'25 KernelSnitch 论文；`util.c:604-605`；ghost-hoock 描述 |
| KernelSnitch 对 K3 = 仅定 slide / 无关 | **确认（不给栈/pi_state）+ 推断（无法兑现为受控对象）** | 同上 + `HANDOVER.md:321/896` |
| futex 碰撞不能以栈地址为目标 | **确认（源码层）** | `futex.c:391-396`（key=`word`用户地址+`ptr`mm/inode+`offset`标志，无栈）；`futex.c:339/435` |
| 已知栈基址 → 可算 fake waiter 自引用地址 | **确认（几何）+ 未定（能否拿到 W 线程栈基址）** | `NUL 分析 §2.3:60-71 / §3:75-88`；本文 §5.5.2 |
| !VMAP_STACK + 同处 DPM ≠ 栈泄露 | **确认（机制）+ 推断（无其它栈 oracle）** | `futex.c` key 分析 + USENIX'25 TLB 依赖 VMAP_STACK；本文 §5.5 |
| §7 第2条(a) 应按类型细分（含明确排除"同处 DPM"） | **建议** | `HANDOVER.md:523-525` + 本文 §4–§6 |

## 8. 外部来源清单（web，均在 2026-11-19 检索）

1. KernelSnitch: Side-Channel Attacks on Kernel Data Structures — NDSS 2025，
   `https://www.ndss-symposium.org/wp-content/uploads/2025-223-paper.pdf`
2. When Good Kernel Defenses Go Bad: Reliable and Stable Kernel Exploits via Defense-Amplified
   TLB Side-Channel Leaks — USENIX 2025，`http://gruss.cc/files/usenix25-tlbsidechannel.pdf`
3. Black Hat USA 2025 同题报告摘要（栈/堆/页表 4KB 精度泄露，依赖 VMAP_STACK/SLAB_VIRTUAL），
   `http://talksintel.ai/cybersecurity/conferences/blackhat-usa-2025/derandomizing-the-location-of-security-critical-kernel-objects`
4. Kermes: Systematically Unveiling Kernel Memory Region Exploitation Potential — NDSS 2027，
   `https://yancomm.net/papers/2027%20-%20NDSS%20-%20Kermes.pdf`
5. ghost-hoock（CVE-2026-43499 公开利用描述，KernelSnitch 喷射页基址用途），
   `https://kitploit.com/zh/tools/github/deaurity/ghost-hoock`
6. MT6985 适配失败日志（KernelSnitch 在 MTE 下的可靠性旁证），
   `https://kitploit.com/en/tools/github/233laoliu/mt6985-cve-2026-43499`
7. Pixel 7 移植复盘（mm_struct slab 步进按 CWG 对齐而非结构大小；栈喷伪造 waiter 被读到但红黑树写未发生），
   `https://bbs.kanxue.com/thread-292846.htm`
8. 4.9 arm64 `VMAP_STACK=n` 时栈走 `alloc_pages_node(...THREAD_SIZE_ORDER)`+`page_address()` 的源码分析，
   `https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/grsec-code-analysis/kstack.md`

> 所有 web 结论仅作旁证；核心判定均来自本地源码逐行核对（`src_ref/kernel_49_mainline/rtmutex.c`、
> `rtmutex_common.h`、`futex.c`）与项目文档（`HANDOVER.md`、`GHOSTLOCK_NUL_ANALYSIS.md`、`ref_pc/km00`）。
> team-lead 提供的本机 config 事实（`THREAD_INFO_IN_TASK=y`、`!VMAP_STACK`）作为 §5.5 的前提采纳，
> 未在本分析中重新上机验证（本任务禁止连设备）。

> ⚠️ **v008 术语更正（权威见 `FEASIBILITY_v008.md` §1）**：本文多处"仅能定 slide（DPM 基址）"把两个概念并列，措辞过宽。精确表述为：KernelSnitch 给的是 **DPM 线性映射中一个 mm_struct 堆页的物理位置**（R1，+无秘密的物理换算 R2）；它**给不了 `.text` 的 KASLR slide**（R3 由启动期 `kimage_voffset` 独立承载，不能由线性地址反推）。**本文的核心判定（fake waiter 需要"可控 rt_mutex 内核地址"、KernelSnitch 对硬门槛无关）不受此术语更正影响，维持。**
