# KernelSnitch 本机参数离线闭环验证结论

> 纯离线分析：只读参考源码、未连接设备、未产出任何可运行 PoC、未修改 `ref_pc/km00`。
> 验证脚本：`tools/ksnitch_local_check.py`（自包含，可直接 `python tools/ksnitch_local_check.py`）。

## 一、先确认的源码事实（复现依据，非臆测）

来自 `ref_pc/km00/exploit/src/kernelsnitch/futex_hash.h`：

- `__futex_hash_from(size_t addr, size_t mm, uint32_t hsz)`（L203）参数顺序是 **(addr, mm, hsz)**，地址在前、mm 在后。
- 私有 futex key 布局（小端）：`[0..7]=mm`、 `[8..15]=addr & ~0xfff`、 `[16..19]=addr & 0xfff`。
- `futex_hash_no_trunc()`（L187）调用 `jhash2((u32*)key, offsetof(both.offset)/4, key->both.offset)`，即 **4 个 u32 = `[mm_lo, mm_hi, page_lo, page_hi]`，initval = `addr & 0xfff`**，返回完整 32-bit 哈希；`__futex_hash()` 再做 `& (hsz-1)`。
- mainline jhash：`JHASH_INITVAL=0xdeadbeef`，`__jhash_mix`/`__jhash_final` 逐字复现。

来自 `kernelsnitch.h` 的 `__mm_leak()`（L197-263）：

- bruteforce 步长实际是 `mm_struct_sz`（`mm_slab_sz = ks->mm_struct_sz`，L206），`MM_ORDER` **不参与**哈希闭环。
- `h_sizes[] = {256,512,1024,2048,4096,8192,16384,32768,65536}`（L219）；对某 mm 候选，若**任一** hsz 下所有碰撞 futex 落入同一桶即判命中（OR 语义，命中即 break）。
- 用户态时钟：`mrs cntvct_el0`（timeutils.h），本验证不涉及。

**结论（方向A最重要判定）：本机 4.9 内核的 futex 哈希与 `ref_pc/km00/futex_hash.h` 的复现【逐字节一致】。**
依据如下反汇编↔源码对照（以 `firmware_F16/vmlinux.elf` 真实二进制为准，非参考源码推测）：

| 判定项 | 本机 vmlinux 反汇编证据 | 与参考项目 jhash2 复现 |
|---|---|---|
| 哈希算法 | `futex_wait_setup`@`0xffffff80081622f8` 内联的 mix 用 ror 28,26,24,16,13,28；final 用 ror 18,21,7,16,28,18,8 | = rol 4,6,8,16,19,4 与 rol 14,11,25,16,4,14,24（编译器 rol→ror(32-n) 等价），即标准 `__jhash_mix`/`__jhash_final` ✓ |
| 种子/长度 | `w22=0xdeadbeff`（`mov #0xbeff`+`movk #0xdead`）= `0xdeadbeef + 16`（`length<<2`，length=4 已折叠） | `jhash2(k,4,initval)` 初值 `0xdeadbeef+(4<<2)+initval` ✓ |
| key 布局（关键） | `get_futex_key`@`0xffffff8008161d08`：`1d40 str w8,[x2,#0x10]`（offset=`uaddr&0xfff`）；`1d6c sub x20,x0,x8`（页基址）；`1f24 stp x23,x20,[x19]` → **key[+0]=current->mm(x23), key[+8]=address(x20), key[+0x10]=offset** | 参考 `futex_key_t`：`private.mm@+0, private.address@+8, offset@+0x10` ✓ **顺序一致（mm 在前）** |
| hash 输入字序 | hash 处 `23ac ldp w9,w11,[key,#0x48]`→mm_lo/mm_hi；`23a8 ldr w10,[key,#0x50]`→addr_lo；`23a4 ldp w12,w8,[key,#0x54]`→addr_hi/offset。即 jhash2 输入 = `[mm_lo,mm_hi,addr_lo,addr_hi]`，initval=offset | 脚本 `futex_key_words()` 返回 `[mm_lo,mm_hi,page_lo,page_hi]` ✓ **字序一致** |
| 桶索引 | `245c w10=futex_hashsize-1`；`246c and x8,x10,x8`（`hash & (hashsize-1)`）；`add x28,x9,x8,lsl#7`（bucket 128B 步长） | `__futex_hash()` 的 `& (hsz-1)` ✓ |

**一个重要陷阱（已排除）**：本地参考源码 `src_ref/futex_4.9/futex.h` 的 `union futex_key` 写的是旧布局 `{address, mm, offset}`（address 在前），若按它复现会与本机二进制**字序相反、哈希全错**。但 `firmware_F16/vmlinux.elf` 的真实二进制用的是新布局 `{mm, address}`（`stp x23,x20,[x19]` 中 mm 在 +0），与参考项目一致。**必须以二进制为准**，不能用随附的 4.9 头文件布局。

脚本已把这条判定固化为断言：`kernel_hash_from_disasm()` 按上述反汇编逐指令复现哈希，在 200 组随机 (mm,addr) 上与脚本哈希逐位比对全部一致（自检输出含该项 PASS）。

## 二、本机适配需改哪些常量

| 项 | 参考值(PCKM00/4.14.180) | 本机 K3 值 | 是否需改 | 说明 |
|---|---|---|---|---|
| `MM_STRUCT_SZ` (common.h:51) | `0x3a8` (936) | **896 (0x380)** | **必须改** | slabinfo: `mm_struct 336 378 896 18 4`。`util.c:611` 的 mm_sizes[] 回退表已含 `0x380`，`prepare_kernel_page` 路径会自动重试到它；但 `setup_kernelsnitch()` 首次传入值仍应直接改对，省一轮全窗口扫描。 |
| `MM_ORDER` (common.h:52) | `3` (8 页/32KB) | **2**（4 页/16KB，由 pagesperslab=4 推得） | **建议改，需设备复核** | 对 KernelSnitch 哈希闭环**无影响**（步长用 mm_struct_sz）。但影响 `ORDER3_SIZE = PAGE_SIZE<<MM_ORDER`：`pipe.c:123` 的 `objs_per_slab=ORDER3_SIZE/MM_STRUCT_SZ`  spray 数量，以及 `util.c:643` 的 `base = leaked & ~(ORDER3_SIZE-1)` slab 基址。若实际 order=2 而代码仍用 3，`objs_per_slab` 从真实 18 算成 36，堆布局与基址都会错。**阻挡项见第六节。** |
| futex 桶数 | `k_next_pow2(256*ncpu)`，8 核=2048 | **1024**（4 核×256，已 pow2） | **无需改代码** | `futex_init()`（futex_hash.h:222）运行时按 `sysconf(_SC_NPROCESSORS_ONLN)` 计算，本机自动得 1024；`h_sizes[]` 已含 1024（索引 2）。所谓“2048→1024”是参数变化而非硬编码常量。 |
| `IDENTITY_START/END` (kernelsnitch.h:39-45) | `0xffffff8000000000`，+64GB | 本任务验证窗口 8GB | **需确认** | 参考 VA_BITS=39 线性窗口起点。本机 K3 若 VA_BITS/KASLR/direct-map 窗口不同须相应调整；`slide` 模块拿到内核基址后可收窄窗口。本脚本按任务给的 8GB 窗口验证。 |
| `KSNITCH_COLLISIONS` (common.h:55) | `4` | 4（本任务指定 3-4，取 4） | **不要下调** | 唯一性由它决定，详见第四节；N=2/3 会误报爆炸。 |

## 三、闭环结果（脚本实测，全部断言 PASS）

- jhash 复现自检：`jhash2` 与独立的 `jhash()` 字节流版在 200 组随机向量上完全一致；numpy 向量版与标量版在随机样本上一致。两条独立代码路径互证，复现可信。
- 构造：目标 mm = `0xffffff8041eed880`（8GB 窗口内 896 对齐网格点），构造 4 个用户 futex 地址（如 `0x7f003d90f6ec` 等），在 `hsz=1024` 下全部落入桶 **465**。
- 全窗口 bruteforce：扫描 `[0xffffff8000000000, +8GB)`、步长 896，共 **9,586,981** 个候选，**唯一命中目标 mm，误报 0 个**（numpy 全逐候选扫描，2.26 秒）。
- 正确性判别：正确 mm 通过多 hashsize 检查；相邻 896 对齐的错误 mm (`0xffffff8041eedc00`) 在全部 hsz 下被排除。

**结论：哈希逻辑在本机参数下闭环自洽，能唯一找回 mm_struct 线性地址。**

## 四、唯一性 / 误报量化

误报概率近似 `P ≈ Σ_{hsz∈h_sizes} (1/hsz)^(N-1)`，被最小 hsz=256 主导（见下方“OR 退化”）。期望误报 = 候选数 × P：

| 碰撞数 N | 额外比较 (N-1) | P_fp ≈ | 8GB 误报期望 | 判定 |
|---|---|---|---|---|
| 2 | 1 | 7.8e-3 | 7.5e4 | 大量误报 |
| 3 | 2 | 2.0e-5 | 1.95e2 | 大量误报 |
| **4（本机/参考默认）** | 3 | 6.8e-8 | **0.65** | 边缘可用 |
| 5 | 4 | 2.5e-10 | 2.4e-3 | 唯一 |
| 8 | 7 | 1.4e-17 | 1.3e-10 | 唯一 |
| 16 | 15 | 7.5e-37 | 7.2e-30 | 唯一 |

- **重要洞察 —— OR 语义退化为必要条件**：若某候选在较大 hsz 下碰撞一致，则必然在最小 hsz=256 下也一致（低 8 位是低 10/11/…位的子集，jhash 结果 & 更小 mask）。因此 `h_sizes[]` 的“任一命中”检查逻辑上等价于**仅用 hsz=256 检查**。它确实保证了对任意真实桶数 ≥256（2 的幂）的鲁棒性，但**误报率被 256 而非 1024 决定**——这是 N=4 时期望仍达 0.65 的根因。构造碰撞集在 2048 及以上通常不一致（脚本 (b) 实测证实），所以不能简单改成“所有 hsz 都必须一致(AND)”。
- 缓解建议：本机已确认真实桶数=1024，可把一致性判定**单用 1024**（AND 退化为最强检查），误报期望降到 `(1/1024)^3 × 9.6e6 ≈ 8.9e-6`；或把碰撞数提高到 ≥5。二者都能把唯一性从“边缘”提升为“稳固”，且不改内核侧逻辑。
- 成本量级：候选数 ≈ 2^23.19。参考原样（每候选 9×2=18 次 jhash，共 1.73 亿次）单线程 C ≈ 8.6 s、8 线程 ≈ 1.1 s；纯 Python ≈ 554 s。若按“仅用 256/1024”优化为 2 次哈希/候选（1917 万次），8 线程 C ≈ 0.5 s。bruteforce 在 C 实现下是秒级，不是瓶颈。

## 五、复现所作假设（源码未覆盖处，据此报告）

1. **小端**：ARM64 小端；`jhash2` 对 u32 数组与 `jhash()` 对字节流结果一致已由自检证明，故 key 的 u32 拆分顺序可信。
2. **COARSE_SZ 层**：`__mm_leak` 的 `coarse_addr`→`slab_addr`→`mm_struct_candidate` 三层中，因 `mm_slab_sz == mm_struct_sz`，后两层等价；第三层循环体只跑一次。脚本用单步长 896 的等价扫描。
3. **MTE 分支**：`mte_enabled=1` 的 tag 枚举分支（L242-257）未模拟；参考调用（`util.c:28/564`）传入 0，假设本机 MTE 关闭。K3 若启用 MTE 需另行处理 tag 候选。
4. **哈希均匀性**：误报解析假设 jhash 输出近似均匀；脚本全窗口实测 0 误报与该假设一致。
5. **候选网格**：真实 mm 对象按 896 对齐、每 18 对象有 256B padding；步长 896 的扫描是真实地址集合的超集，只会高估候选数，不影响“目标唯一命中”的结论。

## 六、阻挡项与待确认

1. **MM_ORDER / slab 基址（主要阻挡项，影响整体利用而非哈希闭环）**：本机 slabinfo 显示 mm_struct `pagesperslab=4`（order 2），参考 `MM_ORDER=3`。虽然 KernelSnitch 哈希闭环不受影响，但 `ORDER3_SIZE` 用于 spray 数量和 `base = leaked & ~(ORDER3_SIZE-1)` 的 slab 基址计算。需在本机确认 mm_cachep 真实 order，若确为 2 则把 `MM_ORDER` 改为 2，否则 `prepare_kernel_page` 的堆布局会错位。
2. **线性窗口范围**：参考 ARM 分支为 VA_BITS=39、`0xffffff8000000000` +64GB；本机 8GB 窗口与 KASLR/direct-map 布局需核对，必要时调整 `IDENTITY_START/END` 与 `identity_diff` 线程切分。
3. **唯一性边缘**：N=4 时因 OR 退化误报期望约 0.65，存在偶发假阳性风险；建议按第四节提升到 1024 单桶判定或 N≥5（纯用户态参数调整，无需改内核侧）。
4. **非哈希侧依赖**：本验证只覆盖 KernelSnitch 的哈希可闭环性；完整链路还依赖 futex 侧信道的时序区分度（`KERNELSNITCH_THRESHOLD_MULT`、测量噪声）、mm_struct 释放/回收的可控性等，均需设备实测，超出离线验证范围。

**总判定：KernelSnitch 哈希逻辑本身可在本机参数下闭环工作，无哈希层面的致命阻挡；落地前需确认 `MM_ORDER`(=2) 与线性窗口范围，并建议加固唯一性判定。**
