# v4 真机实测报告：P1/P2 闭合 + KernelSnitch G1 桶索引性证伪调查（2026-11-19，用户授权）

> 接续 `LIVE_PROBE_RESULT.md`（v3 §41）与 `FEASIBILITY_v008.md`。本轮在用户授权下重新连接真机，
> 执行 v008 §4.4 预留的两项"需单独授权"工作（P2 perf 限制、P1 设备行为缺口），并尝试 v008 §6
> 判据二（G1∧G2 真机端到端）。**安全边界不变**：全部探针为纯用户态（mmap/futex/cntvct_el0），
> 未触发 UAF、未写内核、未碰 /proc、无持久化。全程 `/data/local/tmp` 临时文件。
> **设备状态**：基线核验通过（SPL/内核/指纹与 F.16 一致，零重启，uptime 165435s 起算）；
> 会话中后段设备被用户取走断连，`/data/local/tmp` 清理**未完成**，见 §7 待办。

---

## 0. 结论先行

| 项 | v3/v008 状态 | 本轮结果 |
|---|---|---|
| P2 perf 栈采样（③ 类地址唯一"未定"项） | ⚠ 未定 | **闭合：排除**。`perf_event_paranoid=3`，uid 2000 下 4 种配置全部 EPERM（§2） |
| P1 skb 生命周期可控性（设备行为缺口） | ⚠ 纯离线不可判定 | **闭合：可控**。5+3 轮分配-停留-释放-重占零偏差（§3） |
| G1∧G2 真机端到端（对未知 mm 完整恢复） | 未演示 | **未达成**。G2 全窗口零命中（§4）；且发现 G1 信号的**桶索引性存疑**（§5） |
| 线性映射窗口 | `0xffffff8000000000` +8GB | **更正**：PAGE_OFFSET=`0xffffffc000000000`（铁证 §4.2）；旧窗口实为 modules+image+vmalloc |
| 四层 ROOT 判定 | NO-GO | **不变**。但 GhostLock ① 类地址泄露的可信度**下调**（§6） |

**一句话**：P2 与 P1 的两个缺口按 v008 口径正式闭合（结论分别是"排除"与"可控"）；但端到端恢复
实验失败，且失败模式指向一个此前未被质疑的前提——**真机上 futex 计时信号可能根本不是桶索引的**。
在迁移实验证伪或证实之前，v3 §41 的"G1 真机成立（110×）"应降级为"存在 100× 计时信号，其语义未验证"。

---

## 1. 基线核验（只读，✅ 通过）

SPL `2022-04-05`、内核 `4.9.227-perf+`（构建 2025-03-26）、指纹
`OPPO/PCGM00/OP4679:11/RKQ1.201217.002/1704167642389`、Enforcing、uid 2000(shell)——与 F.16 基线逐字一致，
无 OTA 漂移。会话起始 uptime 165435s（连续运行，零重启）。
**新读数**：`nproc=6`（在线 CPU 6 个）——与 `KSNITCH_LOCAL_CHECK.md` "4 核 → hashsize=1024" 的口径冲突，
真实 hashsize 应为 `roundup_pow2(256×num_possible_cpus)`，num_possible 需真机读 `/sys/devices/system/cpu/possible`，
未及读取（设备断连）。该差异影响 G2 唯一性建议（"单用 1024 判定"应改为"单用实际 hashsize 判定"），
但不影响本轮任何负结果（见 §4.4，判据已放宽到 mask-8）。

---

## 2. P2：perf_event_paranoid 与栈采样限制实测（✅ 闭合：排除）

| 项 | 实测值 |
|---|---|
| `/proc/sys/kernel/perf_event_paranoid` | **3**（拒绝一切非特权 perf_event_open，含纯用户态采样） |
| `/proc/sys/kernel/perf_cpu_time_max_percent` | 25 |
| `perf_event_max_stack` | 文件不存在 |

探针 `live_probe/perf_probe.c`（aarch64 静态编译，4 种配置 × `perf_event_open(pid=self)`）：

| 配置 | 结果 |
|---|---|
| HW cpu-cycles, exclude_kernel=1 | **EPERM (13)** |
| HW cpu-cycles, exclude_kernel=0 | **EPERM (13)** |
| SW task-clock, exclude_kernel=1 | **EPERM (13)** |
| SW cpu-clock + PERF_SAMPLE_CALLCHAIN, exclude_kernel=1 | **EPERM (13)** |

⇒ v008 §4.2 唯一"未定"项落定：**uid 2000 下 perf 栈采样不可达，③ 类地址经 perf 泄露的候选正式排除**。
③ 的可证伪条件维持不变（需"以内核栈地址为键、用户可观测"的新原语）。

---

## 3. P1：AF_UNIX skb 喷射生命周期可控性实测（✅ 闭合：可控）

探针 `live_probe/spray_probe.c`。尺寸推导（4KB 页、`SKB_DATA_ALIGN=64`、`sizeof(skb_shared_info)≈320`）：
payload 16064 → data alloc 16384 = **order-2**（K3 mm slab 同阶）；payload 32128 → **order-3**（PCKM00 对照阶）。

| 组 | 轮次 | 每轮分配数 | 失败数 | 喷射耗时 | 释放耗时 |
|---|---|---|---|---|---|
| order-2（16KB） | 5 | **3072 恒定** | 256 | 22–43ms | ~250ms |
| order-3（32KB） | 2 | **1792 恒定** | 256 | 35–41ms | ~244ms |
| order-2 背靠背重占 | 3 | **3072 恒定** | — | — | — |

**确定性 spread = 0.00%**（8 轮无任何偏差）。设备 MemAvailable≈2.9GB，单轮喷射 ≤192MB，无 OOM 副作用。

⇒ v008 §4.1 的"生命周期可控性"（分配—停留—释放—重占，uid 2000）**闭合为可控**，
且速率 ~50MB/s 足以支撑秒级时序窗口。**P1 剩余缺口收窄为唯一一项：地址可知性**
（"受控内容 → 已知内核虚拟地址"的落点推导，order-2 下 delta 未知，且无只读 oracle 可交叉验证）。

---

## 4. G1∧G2 真机端到端：未达成（负结果，证据链完整）

探针 `live_probe/e2e_probe.c`：本进程 256 线程堆积 `inc_futex`（region+128）→ 扫描候选地址找碰撞 →
**暂停校验**（堆积线程整体撤出 futex，真碰撞应变冷）→ 设备端 G2 枚举 → 用恢复 mm 预测"必然同桶"
地址做命中率验证（兼测 futex_hashsize）。

### 4.1 G1 观测侧（复现良好）

两次运行均为：基线 16–20 ticks，堆积桶 389–819 ticks（~40×），扫描 20000 候选得 **12 个
">10× 基线" hit（1136–2288 ticks，~125×）**，暂停校验 **12/12 变冷**（16–17 ticks）——
表面看与 v3 §41 的 110× 信号一致且更强。

### 4.2 G2 离线/设备端枚举：全组合零命中

对 12 个 hit（互相"同桶"为必要条件）做了穷举式模型扫描（全部 numpy 向量化，`tools/debug_g2_*.py`）：

| 扫描 | 窗口 | 网格 | 判据 | 结果 |
|---|---|---|---|---|
| 结构性网格 | 旧窗口 0xffffff8000000000+8GB | 16384 对齐 + 896×j (j<18) | mask-256 | **0** |
| 全 32 字节网格 ×5 模型 | 旧窗口 | 268,435,456 候选 | mask-256 | **0** |
| 结构性网格 | **修正窗口 0xffffffc000000000+8GB** | 16384 对齐 + 896×j | mask-256 | **0** |
| 全 32 字节网格 ×5 模型 | 修正窗口 | 268,435,456 候选 | mask-256 | **0** |
| 结构性网格，双窗口 | 两个窗口 | 16384+896×j | **mask-64/32/16/8** | **0** |

五个模型变体（词序/页对齐/initval 组合）与 mask-8（仅要求 3 位哈希位相等——对任意
pow2≥8 的 hashsize 都是必要条件）下均无幸存者。**误报期望在 12 hit、mask-8 下 ≈ 0.002，
零命中在数学上排除了"12 hit 同桶 + mm 在窗口内 + 模型正确"三者的合取。**

### 4.3 模型与窗口的独立复核（全部指令级确认，非转写）

- `get_futex_key`（`0xffffff8008161d08`）逐指令复核：`and w8,w0,#0xfff`（offset@key+0x10）、
  `sub x20,x0,x8`（页基址）、`cbz w1→1f24`（私有路径）`stp x23,x20,[x19]`（mm@+0, 页基址@+8）✓
- `futex_wait_setup`（`0xffffff80081622f8`）哈希内联：`w22=0xdeadbeff`（=INIT+16，length=4）→
  标准 jhash_mix（ror 28,26,24,16,13,28）→ `a+=addr_hi` → jhash_final（ror 18,21,7,16,28,18,8）→
  `hash & (hashsize-1)`，桶步长 128B ✓ —— 与 `tools/ksnitch_local_check.py` 的复现逐字一致
- `futex_wake`（`0xffffff800815de00`）哈希内联同构（同种子、同词布局）✓
- **PAGE_OFFSET 铁证**：`is_vmalloc_addr`（`0xffffff821d858`）内嵌 vmalloc 区界
  `[0xFFFFFF8008000000, 0xFFFFFFBEBFFF0000)`；后者精确等于
  `PAGE_OFFSET(0xFFFFFFC000000000) − VMEMMAP_SIZE(4GB) − SZ_64K`，且与 4.9 arm64
  `PAGE_OFFSET = ~0UL << (VA_BITS-1)`（VA_BITS=39 → 0xffffffc000000000）、
  `_text=0xffffff8008080000 = MODULES_END + 0x80000` 的模块区布局三方自洽。
  **⇒ 线性映射区 = [0xffffffc000000000, +RAM)，旧扫描窗口（0xffffff80…）实为 modules+镜像+vmalloc。**

### 4.4 逻辑结论

模型（指令级）× 窗口（指令级常量反解）× 网格（全超集）× 判据（mask-8 必要条件）四层全部成立，
而零命中 ⇒ **唯一可能崩塌的前提是观测侧："hit 的热量 = 与堆积桶同桶的全链遍历"。**
§5 的机制实验证实了这一怀疑。

---

## 5. 机制调查：G1 信号的桶索引性证伪（本轮最重要发现）

### 5.1 标定实验（`live_probe/calib_probe.c`，WAKE(0) 与 WAKE(1) 对照）

反常数据（全部可复算）：

| 操作 | inc_futex 计时变化 | 桶模型预期 |
|---|---|---|
| 256 waiter 堆积在 inc 自身（T0） | 819 | 同左 |
| **再加 64 waiter 到 inc 自身** | **528（变冷！）** | 应更热（320 项链长） |
| +64 waiter 到 hit1（推测同桶） | 1352（1.65×） | ~1.25× |
| hit1 摘除 64 waiter 后复测 | hit1=6278（**仍热**） | 应回落 ~1900 |
| +64 waiter 到任意冷地址 Y1/Y2/Y3 | 1120 / 1197 / 1337（**跨桶升温**） | 不变 |
| 实验结束（仅剩原 256 crowd） | 1375（较 T0 漂移 +68%） | 不变 |

跨桶升温 + 同桶加料变冷 + 热量粘滞 ⇒ 计时**不是**桶链长的单调函数。

### 5.2 源码级解释（4.9 `futex_wake`，`src_ref/futex_4.9/futex.c:1436-1451`）

```c
plist_for_each_entry_safe(this, next, &hb->plist, list) {
    if (match_futex (&this->key, &key)) {
        mark_wake_futex(&wake_q, this);       /* ← 先标记 */
        if (++ret >= nr_wake) break;          /* ← 后判断 */
    }
}
```

两个此前未被文档记录的语义：

1. **`WAKE(0)` 并非"纯遍历"**：`mark_wake_futex` 在 `nr_wake` 判断之前执行，
   `WAKE(0)` 也会唤醒**首个匹配项**（参考实现 `__measure` 用 val=0，其"纯遍历"假设同样不成立）。
   空桶走 `hb_waiters_pending` 快速退出（基线 16 ticks 的来源）。
2. **匹配地址的计时 = "走到 plist 中首个匹配项的位置"**，非匹配地址 = 全链遍历。
   计时取决于 **plist 内序与缓存状态**，而非桶总长——这解释了 §5.1 的全部反常
   （同桶加料改变首匹配位置 → 变冷；实验进程的反复 WAKE 改变 plist 顺序 → 热量漂移/粘滞）。

### 5.3 迁移实验（`live_probe/transfer_probe.c`）——决定性但未终审

将 256 堆积线程整体从 A 迁到 B（不同页、不同 key，桶不同为大概率事件）后复测：

- **6/6 旧 hit 仍高温**（1219–1403 ticks）；
- 新扫描的 6 个 hit 与旧集合 **100% 重合**；
- 旧地址 A 仍 600 ticks（无明显回落）。

若机制为桶索引，新旧 hit 集重合要求 `hash(A)==hash(B)`，先验概率 1/2048——单次实验无法区分
"1/2048 巧合"与"机制非桶索引"。**已编写 `transfer2_probe.c`**（修复迁移竞态：先改指针再 WAKE 旧地址；
加入 pause→A→B→C→A 完整序列与远距 B/C），**因设备断连未执行**。

### 5.4 判定影响（口径更正）

- v3 §41 "**G1 真机成立（110× 信号）**" → 降级为：**"存在 ~100–125× 的用户态 futex 计时信号，
  但其是否为桶索引 oracle 未被证实；在 transfer2 终审前，不得据其构造 G2 碰撞方程。"**
- v008 §6 判据二（真机端到端恢复）**维持未达成**，且失败原因比"未演示"更实质：
  观测前提本身待验证。
- 对四层 ROOT 判定**无影响**（NO-GO 不变）；对 GhostLock ① 类地址泄露的可信度**下调**：
  KernelSnitch 路线从"研究路径重开（G1 ✅）"回到"**观测机制未验证**"。

---

## 6. 既有文档更正清单（本轮实证触发）

| 文档 | 原表述 | 更正 |
|---|---|---|
| `KSNITCH_LOCAL_CHECK.md` §五.5 | "步长 896 的扫描是真实地址集合的超集" | **错误**。16384 mod 896=256、gcd(256,896)=32，真实 mm VA 集合是 32 的倍数网格；正确结构性枚举 = 16384 对齐 slab 页基址 + 896×j (j<18)。旧脚本"唯一命中"为自洽构造（目标 mm 本身取自其网格），对真实 mm 不成立 |
| `KSNITCH_LOCAL_CHECK.md` §二/§四 | "4 核 → hashsize=1024"；"单用 1024 判定" | 实测 nproc=6（在线）；num_possible 未读。hashsize 需真机确认（预期 2048）；唯一性建议改为"单用实测 hashsize" |
| `FEASIBILITY_v008.md` §1.0/§1.2 | `PAGE_OFFSET=0xffffff8000000000` | **更正为 `0xffffffc000000000`**（is_vmalloc_addr 常量反解 + 模块区布局三方自洽，§4.3）。R2 换算式相应改为 `pa = va − 0xffffffc000000000 + PHYS_OFFSET`；PHYS_OFFSET 与 memstart_addr 关系需复核（`memstart_offset_seed` 符号存在，memstart 可能随机化，不影响窗口覆盖但影响绝对换算） |
| `LIVE_PROBE_RESULT.md` §2/§3 | "futex 哈希桶时序侧信道 WORKS"、"阶段①真机成立" | 降级：信号存在但**桶索引性未验证**（§5），碰撞方程不能据此构造 |
| 参考 `kernelsnitch.h` `__measure` | （文档未声明）WAKE(0) 为纯遍历 | 4.9 源码语义：WAKE(0) 也唤醒首个匹配项（§5.2）；本机所有旧计时数据（含 110×）都带此语义 |

---

## 7. 设备终态与待办（下次连接时）

本轮探针均为纯用户态、零重启（会话期间无任何重启迹象）、无持久化写入。**清理未完成**
（设备会话中被取走），下次连接需按序执行：

1. 复核基线与 uptime（确认期间无 OTA/重启）；
2. 删除 `/data/local/tmp/` 下：`perf_probe spray_probe e2e_probe same_bucket_probe calib_probe
   transfer_probe ks_e2e_result.txt`（transfer2_probe 未推送）；
3. 读取 `/sys/devices/system/cpu/possible`、`online`（确定 num_possible_cpus → hashsize）；
4. **执行 `transfer2_probe`**（已编译于 `live_probe/transfer2_probe`）——终审 G1 桶索引性：
   - pause 时 hit 变冷 + 迁移后 hit 变冷 + 新集随迁移变化 ⇒ 桶模型成立，G1 复活，
     G2 失败原因需另查（此时优先怀疑 hash(A)==hash(B) 巧合与 plist 时序细节）；
   - 迁移后 hit 仍热 ⇒ 机制非桶索引 ⇒ **KernelSnitch 在本机不可用于地址恢复，方向 A 关闭**，
     GhostLock ① 类地址泄露判"无现有手段可得"，四层判定维持 NO-GO 且不再重开。

## 8. 本轮文件变更

| 文件 | 变更 |
|---|---|
| `live_probe/LIVE_PROBE_RESULT_v4.md` | 新增（本文） |
| `live_probe/{perf,spray,e2e,same_bucket,calib,transfer,transfer2}_probe.c` | 新增（源码可入库；二进制不入库） |
| `tools/debug_g2_offline.py` / `debug_g2_models.py` / `debug_g2_models2.py` / `debug_g2_winfix.py` | 新增（离线枚举/模型隔离脚本，复算可复现） |
| `live_probe/ks_e2e_result_run2.txt` | 真机碰撞集原始数据（供复算） |
| `HANDOVER.md` §44 / `HANDOVER_RESUME.md` | 更正与新结论登记 |

## 9. 一句话

**P2（perf 排除）与 P1（skb 生命周期可控）按 v008 口径正式闭合；但端到端恢复实验以完整证据链失败，
并暴露出 G1 计时信号可能不是桶索引 oracle（WAKE(0) 实为"唤醒首匹配"、迁移实验 hit 集不随堆积地址变化）——
KernelSnitch 方向 A 在本机从"G1 ✅"降级为"观测机制未验证"，四层 ROOT 判定 NO-GO 不变。**

---

## 10. v5 增补（2026-11-19，详见 HANDOVER.md §45）

> ⚠️ **本节已被 §11（v6）部分更正**：第 1 条的"G1 桶索引性成立"收窄为"仅 crowd 自身桶可观测"；
> 第 2 条的"26 真实 hit"应为"26 个通过 pausecheck 的计时 hit"；第 4 条的"唯一剩余假设"已被定量证实。
> 引用时以 §11 与 HANDOVER.md §46 为准。

本文 §5.4"G1 降级"与 §9 一句话的表述已被后续终审**部分推翻**，引用时以本节为准：

1. **G1 复活**：transfer2_probe 终审通过（修复迁移竞态后：pause 冷、迁 B/C 冷且仅当前堆积地址热、迁回 A 复热
   2927–6660 ticks）——计时信号确为"桶索引 oracle"。
2. **e2e2 端到端**：`e2e2_probe.c` 重跑得 26 真实 hit（rate 1/1260），数据入库 `live_probe/ks_e2e2_result.txt`；
   设备端 + 离线 G2（双窗口 × 结构性/32 全网格 × mask-2048）仍全零。
3. **内核镜像逐指令终审**（`firmware_F16/vmlinux.elf` 与设备构建串一致，为权威）：哈希=标准 jhash2、key 布局、
   hashsize=2048、桶 stride=128B、task->mm@0x5c8、sizeof(mm_struct)=872（SLUB 步长 896）、
   KASLR 线性映射滑移恒为 0——**模型/网格/窗口/oracle 四要素均无错**（详见 HANDOVER.md §45.3 表）。
4. **矛盾定位**：唯一剩余假设 = **hit 集被他进程瞬时 futex 热污染**（26 vs 期望 16 的偏差吻合；300ms pausecheck
   窗口可漏检短命 waiter）。鲁棒搜索 `tools/g2_maxmatch.py` 已就绪，本轮运行中被中止，**待重跑**。
5. 清理清单更新（10 项）：`perf_probe spray_probe e2e_probe same_bucket_probe calib_probe transfer_probe
   transfer2_probe e2e2_probe ks_e2e_result.txt ks_e2e2_result.txt`。

---

## 11. v6 增补（2026-11-19，详见 HANDOVER.md §46）

**§10 的第 1、4 条与本文 §5 的机制解释均需按本节更正**，引用时以本节为准：

1. **"G1 桶索引性成立"→ 收窄为"仅 crowd 自身桶可观测"**。离线搜索脚本存在统计量错误（用完整 32 位哈希
   比较，而设备判据是 `hash & 2047`），"零命中"因此不具判决力。修正后 2×2.35 亿候选全扫：
   26 个 hit 的最大同桶一致数 = **3**（二项零模型期望 ≤3），邻行对假设下 = **4**（期望 4）。
   ⇒ hit 集与 26 个随机地址统计上不可区分，"能判定第三方地址同桶"未获支持。
2. **"26 真实 hit"→ 改为**"26 个通过 pausecheck 的计时 hit"，且实测彼此不同桶。
   pausecheck 不是纯度 oracle：`measure()` 的 `FUTEX_WAKE_PRIVATE, val=1` 对污染地址是破坏性的
   （第一次 WAKE 就唤醒它正在测量的 waiter），前热后冷是必然结果。
3. **§5.1/§5.2 的机制解释仍成立**（计时=走到 plist 首匹配项的位置），但"回 A 复热"另有混淆项：
   `resume_crowd()` 后 256 线程同时 re-wait 会造成短时全系统测量抬升。
4. **新增探针** `live_probe/purity_probe.c`：逐 hit × 5 轮 pause/resume，同轮"候选/对照"比值判据，
   resume 后等 1.5 s 让风暴衰减；输出 genuine/contaminated/ambiguous。
5. `tools/hash_emu.py` 已修 64 位寄存器截断缺陷（此前 `bucket_of()` 返回未掩码哈希）。

---

## 12. v8 增补：G2 闭合（2026-11-19，详见 HANDOVER.md §48）

**本文 §5、§10、§11 中关于"G1 判别性/G2 失败"的全部判断以本节为准。**

1. **G1 成立**：`purity_probe` 翻转测试 18/19 genuine；`bucket_scale_probe` 把 crowd 规模
   256→64→16 递减，命中地址耗时等比下降 3.68×（同桶 plist 遍历期望 4）。
2. **G2 成立**：两套独立数据在放开窗口后各得唯一解，**全量 hit 100% 同桶**
   （19/19、26/26）。证据：`live_probe/ks_g2_breakthrough.txt`。
3. **根因**：`memstart_addr` 被 KASLR 以 1 GB 为单位下移，本次开机约 100–105 GB；
   v3–v7 的窗口（`PAGE_OFFSET..+8 GB`）整体错位。§5.3 的"迁移实验 hit 集不随堆积地址变化"
   与 §5.1 的"跨桶升温/热量粘滞"等反常，均可由测量噪声与窗口无关因素解释，不再作为机制反证。
4. `/proc/zoneinfo` 实测：zone DMA `start_pfn=0x80000`（phys 2 GB）、zone Normal `0x100000`（4 GB），
   设备 DRAM 物理区间 `[0x80000000, 0x200000000)`。
