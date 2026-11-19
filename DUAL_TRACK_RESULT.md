# 双方向预研综合结论（2026-11-19；含用户授权的真机实测）

> 响应用户"两个方向都做"。方向 A = KernelSnitch 本机参数适配验证；方向 B = fake waiter 字段约束精确化。
> 预研阶段全程离线；**2026-11-19 用户授权后补做真机实测**，仅用户态 futex 计时探针、零重启、临时文件已清空。未改任何既有代码、未产出 PoC。
> 分项详情见 `tools/KSNITCH_LOCAL_CHECK.md`（方向 A）、`artifacts_adb/WAITER_ADDRESS_ANALYSIS.md`（方向 B）、`live_probe/LIVE_PROBE_RESULT.md`（真机实测）；本文是综合判定。

---

## 0. 一句话结论

**两个方向都得到了确定答案，且它们拼在一起指向同一件事：** KernelSnitch 好移植、采样可控、哈希已逐字节验证兼容（方向 A 全部成立）；但它的输出是 mm_struct 线性地址，**填不进 K3 的 fake waiter**——方向 B 证明真正的硬门槛是"一个可控、内核可写、结构合法 rt_mutex 的内核地址"，在 K3 的 xattr 栈载体下具体化为**当前内核栈地址**。KernelSnitch 给不了栈地址，也缺配合的堆喷原语。**缺口从"精度未知"最终收紧为"能拿 mm 线性地址、定不了 waiter"，且差的那一块是栈地址泄露 + 堆喷原语。**

> ⚠️ **v008 更正（权威见 `FEASIBILITY_v008.md`）**：原句"能定 slide"撤回——slide 由 `kimage_voffset` 独立承载，不能由 mm 线性地址推出（反汇编铁证见该文 §1.3）。另：本文"全链端到端"相关表述应读作"G1 真机 oracle + G2 离线唯一性**分别**验证"，二者未在真机串成对未知 mm 的完整恢复，R3（slide）未获取。四层判定不变。

---

## 1. 方向 A：KernelSnitch 本机适配 —— 全部成立

脚本 `tools/ksnitch_local_check.py`（可独立运行，已实测通过）+ 文档 `tools/KSNITCH_LOCAL_CHECK.md`。

| 验证项 | 结果 |
|---|---|
| 本机 hash 函数 | **`jhash2`（按 u32 字）**。`futex_wait_setup@0xffffff80081622f8` 内联 mix 用 ror 28/26/24/16/13/28、final 用 ror 18/21/7/16/28/18/8 ≡ 标准 `__jhash_mix` 的 rol 4/6/8/16/19/4 与 `__jhash_final` 的 rol 14/11/25/16/4/14/24（编译器把 rol 优化成 ror(32−n)）。种子 `w22=0xdeadbeff = 0xdeadbeef+16`（length=4<<2 折叠），与 `jhash2(k,4,offset)` 初值吻合。源码 `futex.c:391-395` 确认 |
| 与参考实现兼容 | **逐字节一致（反汇编铁证）**：key 布局经 `get_futex_key` 反汇编确证为 `key[+0]=current->mm`、`key[+8]=address`、`key[+0x10]=offset`；hash 输入 `[mm_lo,mm_hi,addr_lo,addr_hi]`、initval=offset，与参考项目复现完全相同。脚本新增 `kernel_hash_from_disasm()` 逐指令复现语义，200 组随机向量逐位比对一致 |
| 碰撞闭环 | 正确 mm 地址可被全 8GB 窗口 bruteforce **唯一找回，误报 0** |
| **真机实测（2026-11-19）** | **阶段①碰撞观测真机成立**：`cntvct_el0` EL0 可读（19.2 MHz），堆积桶 992 tick vs 空桶 9 tick（**110×**），512 候选中命中 1 个真实碰撞。零重启、临时文件已清空。详见 `live_probe/LIVE_PROBE_RESULT.md` |
| hashsize 覆盖 | 本机桶数 1024 被 `h_sizes[]=256…65536` 覆盖；OR 语义下最小 256 已命中，对桶数不确定鲁棒 |
| 唯一性量化 | **关键洞察**：`h_sizes[]` 的 OR 语义（任一 hsz 命中即 found）退化为"最小 hsz=256 必要条件"，误报率由 256 而非 1024 主导。误报期望：N=2→7.5e4、N=3→195、**N=4→0.65（边缘）**、N=5→0.0024、N=16→≈0。**建议：单用 1024 判定（期望 8.9e-6）或把碰撞数提到 N≥5**；绝不可低于 N=4 |
| 成本 | 8GB/896 ≈ 2^23.19 候选；原样 1.73 亿次 jhash → 8 线程 C ~1.1 秒、纯 Python ~554 秒。bruteforce 秒级，非瓶颈；无 panic 风险 |
| 需改常量 | `MM_STRUCT_SZ` 936→896（0x3a8→0x380，必须改）；`MM_ORDER` 3→本机 pages/slab=4 推算 **order=2**（对哈希闭环无影响，但影响 spray 数量与 slab 基址计算，**属主要待设备确认项**）；桶数 2048→1024（`futex_init` 按 4 核自动算，`h_sizes` 已含 1024，无需手改） |

**源码级确认（非臆测）**：`__futex_hash_from` 签名为 `(addr, mm, hsz)`（地址在前，`futex_hash.h:203`）；private futex key 前 16B = `[mm_lo, mm_hi, page(addr)_lo, page(addr)_hi]`，jhash2 length=4、initval=`addr & 0xfff`（L187-193）；bruteforce 步长是 `mm_struct_sz`，MM_ORDER 不参与哈希（`kernelsnitch.h:206/219`）。

> ⚠️ **避坑（本轮踩到并排除）**：本地 `src_ref/futex_4.9/futex.h` 写的是**旧 key 布局** `{address, mm, offset}`——该文件实为 ~v4.20 代码（HANDOVER.md 已警告其不可用于行号/尺寸引用）。若按它复现，字序相反、哈希全错。本机 vmlinux **真实二进制**用新布局 `{mm, address, offset}`（反汇编 `stp x23,x20,[x19]` 中 mm 在 +0），与参考项目一致。**一切以 `firmware_F16/vmlinux.elf` 二进制为准，不以本地 4.9 目录的头文件为准。**

**结论**：KernelSnitch 的哈希与碰撞逻辑在 K3 参数下**闭环自洽、可直接适配，无哈希层致命阻挡**。我上一轮"4.14→4.9 需整体重做、输出精度未知"的担忧全部作废。落地前需：设备确认 `MM_ORDER(=2)` 与线性窗口范围、加固唯一性判定（单用 1024 或 N≥5）。

---

## 2. 方向 B：fake waiter 硬门槛精确化 —— 缺口是栈地址

详情见 `artifacts_adb/WAITER_ADDRESS_ANALYSIS.md`（逐行源码核对，带行号引用）。

### 2.1 `lock` 字段会被解引用（不是只比较）

`rtmutex.c:627` trylock 写 `lock+0`、`:642/666/721/734` 读 owner、`:703/727/787` 读 waiters 树、`:706/708` rbtree 改写、`BUG_ON(w->lock!=lock)` 校验。PAN/UAO 开启 ⇒ `lock` **必须指向内核虚拟地址**，且是可写、结构合法的 `rt_mutex`。

### 2.2 真正硬门槛（精确化）

> **至少要有一个"攻击者可控、内核可写、结构合法 `rt_mutex`"的内核虚拟地址。**

三档判定：
- (c) 任意非零线性地址：**不够**（过不了解引用与合法性校验）；
- (b) pi_state（kmalloc-128）堆地址：理论可行，但地址未知且 K3 无堆喷原语；
- (a) **当前内核栈地址**：K3 xattr 栈载体下的现实硬门槛——让 `lock` 指向栈上伪造 rt_mutex，或让 `tree_entry/pi_tree_entry` 做 `RB_EMPTY_NODE` 自引用（该宏要求 `__rb_parent_color == &waiter->tree_entry`，即精确的栈上地址）。

### 2.3 为什么 ref_pc 能成功而 K3 卡住（关键反证）

- ref_pc/km00：`fake_lock = payload_base + LOCK_OFF`，`payload_base` 来自 **KernelSnitch 泄露的 mm_struct 地址 + AF_UNIX skb 喷射落到内核堆的可控页** ⇒ lock 指向内核堆上的受控 rt_mutex，**从头到尾不需要栈地址**。
- K3：唯一可控内存是**内核栈**（xattr `strncpy_from_user`），没有 skb 堆喷原语（§15.4：`setxattr` 2000 次仅 33 次成功、kmalloc-128 delta=0；无 SYSVIPC）。⇒ 只能走 (a) 栈地址。

### 2.4 KernelSnitch 对 fake waiter 的判定

KernelSnitch 泄露的是 **mm_struct 线性地址（DPM 堆对象）**。源码 `futex.c:498-530` 确认私有 futex key = `{页内offset, private.mm, private.address}`，hash 只吃 mm_struct 指针与用户态地址——**不含内核栈地址**，故无法平移到栈。它只能定 slide / DPM 基址；即使给了 slide，K3 也缺"把 payload 写到该已知地址"的堆喷原语来兑现。**判定：对 fake waiter 硬门槛"无关"（仅定 slide）。**

---

## 3. 两个方向拼起来的新发现：本机栈在线性映射区（重要，需精确化）

我做了一项 agent 报告未充分展开的独立核查：

- 本机 config 实测：`CONFIG_THREAD_INFO_IN_TASK=y`，**`# CONFIG_HAVE_ARCH_VMAP_STACK is not set`**（VMAP_STACK 未启用）。
- Linux 4.9 arm64 在 `!VMAP_STACK` 时，内核线程栈由 `alloc_pages_node(THREAD_SIZE_ORDER=2)` 分配 **4 个连续物理页（16KB）**，`page_address()` 返回**线性映射虚拟地址** ⇒ **内核栈位于 `[0xffffff8000000000, +8GB)` 线性映射区，按 16KB 对齐**。
- KernelSnitch 的扫描窗口恰好是这段线性映射区。

**双刃剑的精确判读**：
1. 好消息：栈与 mm_struct 同处线性映射区，物理上在 KernelSnitch 窗口内。
2. 坏消息（决定性）：KernelSnitch 的 futex hash 输入**没有栈地址**，所以"栈在窗口内"≠"能被它探测"。要探测栈，需要栈地址参与某个可观测哈希——futex key 不满足。
3. 已知的栈地址侧信道（USENIX'25 TLB 侧信道，4KB 精度）**依赖 VMAP_STACK / SLAB_VIRTUAL** 来制造细粒度 TLB 模式；本机 `!VMAP_STACK`（16KB 连续页、无细粒度拆分）**反而不适用**。

⇒ **净结论**：`!VMAP_STACK` 让栈落进 KernelSnitch 窗口，但既没有可用的哈希输入、也没有适用的细粒度侧信道——**栈地址仍然泄露不出来**。这一条把方向 B 的结论钉死：不是"也许能凑合"，而是"机制上够不着"。

**进一步精确化（方向 B §5.5.2，重要）**：缺的不是"从栈基址算 waiter 偏移"——这一环**几何上已静态解决**（栈 16KB 对齐 + waiter 相对 sp 的固定偏移，`NUL 分析 §2.3/§3`）。真正缺的是 **"获得持有 stale waiter 的 W 线程当前栈基址"这一 oracle**：
- KernelSnitch 给的是 mm_struct 地址，mm 来自 slab、栈来自 buddy order-2 页（16KB），**两个独立分配域、无固定偏移**，从 mm 推不到栈；
- 必须是 W 线程的栈（waiter 写在 W 栈上），不是同 mm 下任意线程的栈（各有独立 16KB 栈）。

⇒ 缺口最终表述：**不是"不知道 waiter 在栈上的偏移"，而是"不知道 W 线程的栈基址"，且没有 oracle。**

---

## 4. 对 §7 第 2 条 (a) 重开条件的精确化建议

原文"(a) 任一可用的内核地址泄露"过宽，会把只给 slide 的 KernelSnitch 误判为可重开。建议改为三档：

> (a) 出现能定位**一个攻击者可控、内核可写、结构合法 rt_mutex 的内核虚拟地址**的信息泄露：
> - **(a1) 当前内核栈地址**（K3 xattr 栈载体最直接：让 `lock` 指向栈上伪造 rt_mutex，或 `tree_entry` 自引用）；
> - **(a2) 某个可控 rt_mutex 的堆地址**（pi_state / skb 喷射页，等价 ref_pc 的 `payload_base`）；
> - **(a3) 仅有 KASLR slide / DPM 基址（KernelSnitch 类）不足以单独重开**——除非同时存在"能把 payload 写到该已知地址"的可控堆喷原语（本机当前无）。

---

## 5. 最终判定与下一步

**GhostLock 重开条件（§7 第 2 条 a）仍未触发。** 两个方向合起来的净结果：

| 缺口 | 状态 |
|---|---|
| KernelSnitch 哈希/采样/适配 | ✅ 已解决（方向 A 全部成立） |
| slide / DPM 基址 | ✅ KernelSnitch 可得 |
| **可控 rt_mutex 内核地址（栈地址）** | ❌ 仍缺——机制上够不着（方向 B + §3） |
| **内核堆喷原语（把 payload 放到已知地址）** | ❌ 仍缺（K3 无 skb/setxattr 喷堆） |

**下一步候选（均需单独授权）**：
1. **[高优先，纯离线]** 若要走 (a2) 堆路径：寻找 K3 上能把可控数据写到已知内核地址的原语（这是把 slide 兑现为可用地址的前提）——这是比"再找泄露"更本质的缺口。
2. **[高优先，纯离线]** 若要走 (a1) 栈路径：调研 4.9 / `!VMAP_STACK` 内核是否有任何针对 order-2 连续页栈地址的泄露面（本轮已确认 futex 哈希侧信道不行）。
3. **[已完成，2026-11-19]** 真机实测确认 `cntvct_el0` EL0 可读 + futex 碰撞侧信道成立（110× 信号）——见 `live_probe/LIVE_PROBE_RESULT.md`。① 类地址端到端可行已坐实，净判定不变。
4. **[不做]** boot_id / ashmem 后置实现（前置写原语不存在）；任何 GhostLock 端到端 PoC（97% panic）。

**一句话**：两个方向都做完了——方向 A 证明 KernelSnitch 能用，方向 B 证明它给了也用不上；**最本质的缺口不是"泄露不够准"，而是 K3 既泄露不出栈地址、也没有把 slide 兑现成可控 rt_mutex 地址的堆喷原语。**
