# OPPO K3 临时 ROOT 可行性研究

> **一份负结果、一次突破、以及一条重开的路径**：在不解 BL 的前提下，对一台 OPPO K3（`PCGM00` / SDM710 / 内核 `4.9.227` / SPL `2022-04-05`）评估了五个内核候选面与多条服务面线索。四个内核面判定不可达；Wi-Fi 私有事务面已打通——从 shell 可让 root 服务以 `uid=0` 执行任意命令（2026-11-18，两次复现），但处于 SELinux 域限制内，**是"受限 root 命令执行"，尚非可用 root**。
>
> **v3.0（2026-11-19）新增**：外部审核意见 v007 指向一个同类参考项目后，我们重开了此前"冻结"的 GhostLock 路径——真机实测证明 **futex 哈希桶时序侧信道在本机可用（110× 信号）**。**但可用 root 判定不变**：侧信道给出的地址类型填不进 GhostLock 的 fake waiter，核心缺口从"没有地址"精确化为"地址类型不对 + 缺内核堆喷原语"。这是**研究路径重开，不是结论翻转为 go**。
>
> **v008 口径更正（2026-11-19，权威见 [`FEASIBILITY_v008.md`](FEASIBILITY_v008.md)）**：撤回"端到端可得 KASLR slide"的表述。三类地址**互相独立**：① KernelSnitch 只给 mm_struct 在线性映射（DPM）中的地址；② 到物理地址是**编译期固定常量**的确定性换算、无秘密可泄；③ `.text` 的 KASLR slide 由 `kimage_voffset`（启动期独立计算）承载，**不能由 ①/② 反推**，本机无获取它的原语。另：110× 只证明时序 oracle 存在，与 N=4 唯一性是两道独立的门。
>
> **v6 口径修正（2026-11-19，审核 v009 响应，见 [`HANDOVER.md`](HANDOVER.md) §46）**：v3 说的"侧信道能拿 mm_struct 地址"**已被自己的数据推翻**。原因是一个统计量错误——离线搜索脚本把"哈希值相等"当成"哈希桶相等"（设备判据是 `hash & 2047`），真 mm 因此也判 0 分，于是"零命中"不具判决力。修正后重扫 2×2.35 亿候选：**26 个 hit 的最大同桶一致数只有 3，与纯随机期望完全吻合** ⇒ hit 集不含桶归属信息。现存结论只剩：**crowd 自身所在桶的计时显著更高**；"判定某个第三方地址与本进程同桶"未获支持。
>
> **v7 口径再修正（2026-11-19，见 [`HANDOVER.md`](HANDOVER.md) §47）**：v6 的"hit 集不纯"结论**被实测推翻**。新探针 `purity_probe` 用逐 hit 的 pause/resume **翻转重复性**判定：**18/19 是真 hit**（5/5 轮双向稳定）。另一探针 `bucket_scale_probe` 做了**模型无关**验证——把 crowd 规模 256→64→16 递减，命中地址耗时按 **3.68 倍**等比下降（同桶 plist 遍历期望 4）⇒ **"hot ⇔ 与本进程同桶"成立**，且 v6 批评的 `pausecheck` 破坏性问题确实存在但实测未造成污染。**G2 恢复仍然失败**：在指令级确认的模型下穷尽 512 GB 内核空间（64 B 粒度）与两个 8 GB 窗口（4 B 粒度），无一候选超过随机基线——当前阻塞点是一个**可证伪的模型矛盾**（§47.7），而非"判据不存在"。
>
> **v8 突破（2026-11-19，见 [`HANDOVER.md`](HANDOVER.md) §48）**：**G1 与 G2 均已成立。** 把搜索空间从 `PAGE_OFFSET..+8 GB` 放开到整个内核 VA 空间（512 GB / 64 B 粒度，8.59 G 候选）后立即出解：两套独立设备数据各得**唯一**候选，且**全量 hit 100% 同桶**（19/19 → `mm=0xffffffda42a97100`；26/26 → `mm=0xffffffda434d5500`）。根因是 `memstart_addr` 被 KASLR 以 **1 GB** 为单位下移，本次开机约 **100–105 GB**——v5 §45.3 把 1 GB 对齐掩码 `0xffffffffc0000000` 误读为 256 GB，因而错判"平移恒为 0"，导致 v3–v7 全部搜索窗口整体错位。**边界**：mm 地址仅本次开机有效；这仍是线性映射平移、不是 `.text` 的 KASLR slide；① 类闭合**不构成提权**（②/③ 未闭合）。
>
> **v10 M2 否证（2026-11-19，见 [`HANDOVER.md`](HANDOVER.md) §50）**：以已知 mm 为锚、依赖 buddy 分配流"时间邻接"推导 AF_UNIX skb 喷射页落点的路线（参考项目固定 delta 的移植前提）**被真机示踪实验证伪**。新增"mm 示踪粒子"方法（fork 的 fresh mm slab 页可被 futex oracle 恢复，充当分配流示踪）：两轮 9 个示踪的相邻 fresh slab 页落点 **1.0–5.5 GiB 随机散布**，简单固定/线性 delta 模型不成立。**K 的独立影响未测得**（run1 实际 K 仅 12 块、run2 两个 K=768 步骤的中间示踪 T2 缺失 ⇒ d12/d23 均 N/A）：现有数据否证的是"固定 delta"，不能外推为"喷射规模无影响"。结构事实同步修正：kmalloc 缓存至 8192 为止 ⇒ 16 KB skb data 走 `kmalloc_large` 直连 buddy（payload 16064 + shared_info 320 = 16384，**每包恰一个 order-2 块**）；`SO_RCVBUF` 被 rmem_max 钳制 ⇒ 每 socket 仅装 ~12 个 16 KB 包。**② 维持未闭合，NO-GO 不变。**
>
> **v10.1 增补（2026-11-19，见 [`HANDOVER.md`](HANDOVER.md) §51/§52，纯离线、零上机）**：响应外部审核 v010。① **唯一性升级为脚本断言**——9/9 个示踪的满命中候选数 `n_full`=1、**次高分恒为 3**（噪声地板），最优/次优相差 ≥10 个约束；两个原在 1 GB 邻域出解者已补扫 16 GB 复核，同为全局唯一（`tools/m2_unique_globals.py`）。② **`/dev/diag` DCI 解析子树静态否证**——三条回传路径均有"声明长度⇄实收长度"门 + 缓冲容量二次校验，子树内无 `copy_to_user`；余量 R1–R3。③ 探针补记 dummy 实际成功数/errno 与 `posttracer` slabinfo（待上机验证）。**四层判定不变：可用 root / 持久 ROOT 仍 NO-GO。**
>
> **v11 增补（2026-11-19，见 [`HANDOVER.md`](HANDOVER.md) §53/§54，纯离线、零上机）**：响应审核 v011。① **③ 类改为"已审接口范围内无可用 oracle"**——逐项审完 16 条可达接口（`/proc/*`、`dmesg`、`sysrq`、perf、BPF、tracefs、debugfs、`/sys/module/*/sections`、hung_task），唯一含 sp 的输出是 oops 寄存器 dump，而 `panic_on_oops` **本机不可观测**（两个可用域均被 SELinux 拒，§59.1）⇒ 不构成 oracle；范围限制见 §60.3。② **Track C 撞到物料墙**——解析 `WCNSS_qcom_cfg.ini` 的 qcacld-3.0 不在镜像内（`hdd_*`/`qdf_*` 符号 0 个），需先只读拉取 `qca_cld3_wlan.ko`（已于 §55 取回，14.6 MB 未剥离）。**四层判定不变：可用 root / 持久 ROOT 仍 NO-GO。**
>
> **v12 增补（2026-11-20，见 [`HANDOVER.md`](HANDOVER.md) §61，纯离线、零上机）**：响应审核 v012。① **研究主线正式从 GhostLock 转向 KGSL 内存对象生命周期**，GhostLock ②/③ 冻结。② **K1「所有权」一半关闭**：不变量 I1–I5 在本机二进制上全部成立（取引用需持锁且拒绝 `pending_free`、释放有唯一赢家、id 只在 detach 撤销、取/放配对 21:42 逐函数对齐）。③ **K1「销毁前提」一半被证伪——KO-1**：`SPARSE_PHYS` 的"有绑定则不可释放"门**只实现在 `SPARSE_PHYS_FREE` 一个入口**，而 `GPUMEM_FREE_ID`（`0x873d564`）与 `GPUOBJ_FREE`（`0x873d5ec`）都以 `flags=0` 查 id ⇒ 可释放仍被绑定的物理块，留下**悬空 IOMMU 映射**与**悬空 `p_memdesc`**。**静态成立。**（→ **§62 上机判定：本机 sparse 面整支 `ENOTSUPP`，KO-1 已关闭**）④ 附：legacy 分派表全解（86 槽 / 37 入口 / 命令字 + handler），解除 §58.2 的"表项指针恒为 0"限制。**四层判定不变：NO-GO。**

> **v12.1 上机判定（2026-11-20，见 [`HANDOVER.md`](HANDOVER.md) §62，只读 + 最小探针）**：**KO-1 关闭**。本机 `kgsl_device::flags` 的 BIT(1)（上游即 `KGSL_FLAG_SPARSE`）未置位，六个 sparse 入口（phys/virt alloc/free、bind、gpu_sparse_command）**全部返回 `ENOTSUPP(524)`**，且都发生在任何分配之前 ⇒ `SPARSE_PHYS` 对象无法创建，KO-1 与 C-2/C-3 一并不适用，仅保留为潜在缺陷（latent）。控制项齐备：`getproperty`(type=8/非法指针)=`EFAULT`、`(type=0)`=`EINVAL`、`syncsource_create`=0、未注册 nr=`ENOTTY`，证明分派层与处理器到达性正常，负结果不是"打不进去"造成的。同轮更正一次工具层误判（`strerror(-ret)` 把所有失败打成 `EPERM`，§62.3）。**`boot_id` 全程不变、`uptime` 连续、探针已删；四层判定不变：NO-GO。**

> **v12.2 非 sparse 释放前提（2026-11-20，见 [`HANDOVER.md`](HANDOVER.md) §63，离线 + 判定型上机）**：承接 §62.7 的可达面重排。**非 sparse 释放链自洽**：新增 I10–I12 三条全称不变量在本机二进制全部成立（`set_pend` 唯一赢家、释放必 `idr_remove`+幂等 unmap gpuaddr、四释放分支共享 `pending_free` 且引用配对），并排除三处"看似缺陷"（`put_gpuaddr` 双调用因清零而幂等、命令用 gpuaddr 走 pagetable 故不需 get entry、四分支汇聚同一 destroy 链而非单点门错位）。**I4 上机证实**：`GPUOBJ_ALLOC`(4096)→FREE→再 FREE 同 id 返回 `EINVAL(22)`、`GPUMEM_FREE_ID` 交叉验证一致 ⇒ 无 double-free；`param` 阶段五分支全 EINVAL 证明解析正确。**K2「索引与生命周期」里程碑在本机可达面内达成，KGSL 生命周期主线阶段性关闭**；K3 并发动态测试因须制造悬空窗口、超"不重启"边界而**登记不作**。`boot_id` 全程不变、`uptime` 连续 +24 s、探针已删、内核日志无异常。**四层判定不变：NO-GO。**

| | |
|---|---|
| 目标设备 | OPPO K3 `PCGM00`（`OP4679`，`sdm710`），Android 11，内核 `4.9.227-perf+`（clang 10.0.7，2025-03 构建） |
| 安全补丁 | `2022-04-05` |
| 启动状态 | BL 锁定、AVB `green`、dm-verity `enforcing`、A-only（v3 实测复核一致，无 OTA） |
| 可用入口 | `uid=2000(shell)` + `u:r:shell:s0`，SELinux Enforcing，`Seccomp: 0` |
| **总体判定** | **受限 root 已达成，可用 root / 持久 ROOT 仍为 NO-GO。** 主线 **KGSL 对象生命周期**已阶段性收口：所有权（I1–I5）成立、KO-1 本机不可达已关闭（§62）、**非 sparse 释放链自洽（I10–I12）+ I4 上机证实（§63）** ⇒ K2 达成；K3 并发登记不作。GhostLock 已冻结：① 类闭合（G1 18/19 + G2 唯一解）；② 未闭合（v10 时间流否证）；③ **已审接口范围内无可用 oracle** |
| 设备终态 | 未刷写、未解锁、未改分区、未装持久化文件；`/data/local/tmp` 已清空；累计 5 次内核重启（均前期实验，v3 实测零重启） |

---

## 当前状态一览（v12）

| 面 | 机制 | 卡点 / v12 状态 |
|---|---|---|
| **KGSL 对象生命周期**（v12 主线，已阶段性收口） | shell 可 open `/dev/kgsl-3d0` 且 `DRAWCTXT_CREATE` 成功（实测） | 长度维度 **14/14 有界**（§58）；所有权 **I1–I5 成立**；KO-1 已关闭（sparse 面 `ENOTSUPP`，§62）；**非 sparse 释放链自洽（I10–I12）+ I4 上机证实（无 double-free，§63）** ⇒ **K2 达成、主线阶段性关闭**；K3 并发登记不作 |
| **GhostLock** `CVE-2026-43499` | 成立（`-EDEADLK` 10+ 次复现），栈载体已闭合（3 条 xattr 候选） | **冻结（v12）**：① 类**已闭合**（G1 18/19 genuine + 3.68× 缩放；G2 两套数据唯一解、全量 100%，§48/§49）；**缺 ② 可控 rt_mutex 堆地址（时间流锚定于 §50 证伪）/ ③ 栈地址（已审接口范围内无可用 oracle，§53/§60）** |
| KGSL `CVE-2023-33107` | 成立（源码 pre-fix） | 命中缺陷即 `BUG()` panic，无中间态 |
| binder `CVE-2023-20938` | 不成立（未引入） | — |
| binder `CVE-2022-20421` | pre-fix | ticket spinlock 使原语退化为常数加法 |
| FastRPC `CVE-2023-33063` | 面存在 | uid 0 域下更封闭（权限并集 ∅） |
| `/dev/diag` | 入口层无缺陷；**DCI 解析子树 v10.1 已否证**（三条回传路径均有"声明长度⇄实收长度"门） | 余量 R1–R3（`extract_dci_ctrl_pkt` 控制语义、两条非 apps 入口、长度字段功能边界）；依赖内核指针的利用仍被 ②/③ 阻断 |
| **OPPO Wi-Fi 私有事务**（非内核） | **已利用** | `\n`/反引号绕过 11 字符黑名单 → `sh -c` 以 `uid=0` 执行（域受限）；缺口 = 域逃逸（§24 判无路径） |
| 私有 Binder / `system_server` / Wi-Fi 消费者 | 方法级否证 | 7/7 闭合、`system_server` 取句柄处断开、消费者三道门全封（§33–§37） |

**最终判定：[`CLOSURE.md`](CLOSURE.md)**（v12 分层判定）。完整证据链：**[`HANDOVER.md`](HANDOVER.md)**——新对话从 `HANDOVER_RESUME.md` 开始，再读 §61 → §60 → §58 → §53 → §52。

---

## GhostLock 重开路径（v3 核心）

### 地址类型三档——缺的不是"任意地址"，而是特定类型

| 档 | 类型 | 本机状态（v6） | 能否填 fake waiter 的 lock/rb |
|---|---|---|---|
| ① | mm_struct 线性地址（DPM 中的堆页位置） | **已闭合（本次开机）**：`0xffffffda42a97100`（19/19）与 `0xffffffda434d5500`（26/26）；盲扫 512 GB @64 B 出唯一解（§48） | ❌ 不够：解引用 + 结构校验过不了，且缺 ② 兑现 |
| ①-s | KASLR slide（镜像 VA，v008 细分） | ❌ **拿不到**：由 `kimage_voffset` 独立承载，不能由 ① 反推（见 `FEASIBILITY_v008.md` §1） | ❌ 不够，且本机无获取原语 |
| ② | 可控 rt_mutex 的堆地址（pi_state / skb 喷射页） | ❌ 生命周期可控（3072 对象/轮、spread 0.00%），**缺地址锚点**；`SLAB_FREELIST_RANDOM=n` ⇒ slab 内布局确定；**v10：页级"时间流锚定"已证伪**（示踪 delta GB 级随机，§50） | ✅ 能——参考项目 `fake_lock = payload_base + LOCK_OFF` 的成功路径 |
| ③ | W 线程内核栈基址（持有 stale waiter 者） | ❌ 无侧信道：futex key 不含栈地址；USENIX'25 栈侧信道依赖 VMAP_STACK，本机 `!VMAP_STACK` | ✅ 能（几何偏移已静态解决，缺的是拿栈基址的 oracle） |

**参考项目为何能成功**：`yijiacloud/GhostLock-OPPO-PCKM00` 用 KernelSnitch 泄露的 mm_struct 地址 + AF_UNIX skb 喷射，把 payload 落到内核堆的已知地址，`lock` 指向那处受控 rt_mutex——**从不需要栈地址**。K3 缺的正是那个 skb 堆喷原语，所以同样的 slide 无法兑现。

**v7 判定（历史）**：① 类判据已由实测确立（这是 KernelSnitch 在本机可用的前提），但**恢复环节卡在一个可证伪的模型矛盾上**（§47.7）；②/③ 仍未闭合，缺口仍是"任意一个内核堆地址锚点"。里程碑按 M1（mm 地址）/ M2（可控 rt_mutex 地址）/ M3（利用链）独立记账。**可用 root 判定不变。**

**v10 判定**：M1 冻结为已验证工具；M2 的"mm 锚 + 时间邻接 + 固定 delta"子路线**正式关闭**（§50），保留 AF_UNIX skb 为对象生命周期研究对象；split-pair 结构邻接仅作理论线索（无 skb 落点 oracle，无法实证）。下一阶段缺口不变：**② 可控 rt_mutex 堆地址 / ③ W 线程栈基址**。

### 关键证据（v3–v6）

1. **方向 A（可移植性）**：`tools/hash_emu.py`（逐指令模拟内核哈希块）+ `tools/g2_maxmatch.py --selftest` 三方对拍 300/300 一致；哈希模型、hashsize=2048、桶 stride=128B 均已二进制确认。
2. **方向 B（硬门槛）**：`artifacts_adb/WAITER_ADDRESS_ANALYSIS.md` 逐行证明 lock 被解引用、真正门槛是"可控 rt_mutex 内核地址"，futex key 不含栈地址。
3. **真机实测**：`live_probe/LIVE_PROBE_RESULT_v4.md` 记录 `cntvct_el0` EL0 可读（19.2 MHz）、crowd 桶 40–125× 计时差异；零重启。
4. **v6 定量否定**：`live_probe/ks_g2_maxmatch_result.txt` / `ks_g2_maxmatch_linepair.txt` —— 2×2.35 亿候选，两种桶约束假设下的计数谱均与二项零模型吻合，最大一致数 3（同桶）/ 4（邻行对）。
5. **综合结论**：`DUAL_TRACK_RESULT.md`、`FEASIBILITY_v007.md`、`FEASIBILITY_v008.md`。

---

## 五个值得单独看的结果

1. **符号可用性**：项目早期"镜像重排、符号不可用"的判断是错的——真实原因是解析器把 kallsyms 偏移当 base-relative。`vmlinux-to-elf` 重建后 123,784 个符号可用（§1.3 / `firmware_F16/README.md`）。教训：先怀疑工具，而不是目标。
2. **GhostLock 的自我推翻链**：第一版"397 入口 0 载体"判死 → 外部审核指出扫描器用函数名判重漏了 18,074 个栈上下文、且漏 `strncpy_from_user` → 修正后找到 3 条 xattr 栈覆盖候选 → 静态收束证明栈复用是几何确定、NUL 不阻断 → 缺口从"载体"变成"地址" → v3 声称"① 地址真机可得" → **v6 用可复算统计推翻自己**：那个"可得"来自一个把桶索引当成完整哈希的脚本，修正后 2×2.35 亿候选里没有一个超过随机期望（§5.2 / §15 / §38–§46）。
3. **ticket spinlock 把 4 字节 UAF 写降级成常数加法**：`CVE-2022-20421` pre-fix 确证，但本机无 qspinlock，公开原语退化（§5.3）。
4. **两个"看起来能用、实际走不通"的面**：KGSL（命中即 panic）、FastRPC（读写/调用各封一半）（§5.1 / §5.4）。
5. **一个 root 服务里的 `sh`：从被拦到 uid=0**：六轮审计 + 外部复评 + 上机验证的完整弧线；"临时 ROOT 实锤"曾误判撤回一次，最终用从未试过的 `\n`/反引号载荷达成受限 root（§16 / §20 / §23）。

---

## 为什么这不是"没试够"

| 维度 | 已量化事实 |
|---|---|
| 覆盖面 | 5 个内核面 + Wi-Fi 私有事务 + 7 个私有 Binder 服务 + 域逃逸 + 消费者面 + `system_server` 句柄 + GhostLock 地址链（v3） |
| 判据形式 | 全部可证伪：帧深 `[0x288, 0x2BE]`、连续非零前缀 `81/129/161 B`、`off_end` 三元式、spinlock 指令序列、地址类型三档 |
| 失败可解释 | 每处失败都能指出"缺哪一环"，而不是"崩了" |
| 工具化 | 帧计算、载体扫描（含自我推翻修正版）、CIL 求值引擎（28 用例）、KernelSnitch 闭环脚本均已脚本化、可离线复跑 |
| 负知识 | 主动记录 **25+ 条**被自己或外部推翻的"确定结论"，含 v3 的"无地址泄露"部分作废（§6 / `CLOSURE.md` §4） |

---

## 仓库结构

```
HANDOVER.md                 # 主文档：§1–§37 历史证据链 + §38–§42 v3（GhostLock 重开）
README.md / HANDOVER_RESUME.md / CLOSURE.md   # 入口 / 一页摘要 / 分层判定
FEASIBILITY_v007.md         # v007 方案评估 + 可行性评估（§12.1 已加 v008 更正块）
FEASIBILITY_v008.md         # v008 响应：三类地址独立关系 + oracle/唯一性分离 + 研究重排（权威）
DUAL_TRACK_RESULT.md        # 双方向预研综合结论
tools/
├── kfn.py / klen_scan.py / kcopy.py        # vmlinux 反汇编与拷贝点判界
├── cil_policy.py / cil_selftest.py         # CIL 求值引擎（28 用例）
├── ksnitch_local_check.py / .md            # 方向A：KernelSnitch 本机闭环验证
├── gl_frame_calc.py / gl_carrier_rescan.py / gl_nul_analysis.py   # GhostLock 几何/NUL
├── kgsl_ioctl_scan.py                      # v11：KGSL ioctl 拷贝点与长度来源
├── kgsl_lifecycle.py                       # v12：KGSL 取/放点普查 + pending_free 访问点
└── ...                                      # 其余分析器与探针
artifacts_adb/
├── binder_audit/           # AUDIT_REPORT / GHOSTLOCK_NUL_ANALYSIS / WAITER_ADDRESS_ANALYSIS 等
└── ...
live_probe/                 # 真机只读探针源码 + LIVE_PROBE_RESULT.md（二进制不入库）
ref_pc/（不入库）           # 克隆的 PCKM00 参考项目（第三方 GPL，仅本地比对）
src_ref/                    # 权威 4.9 源码与补丁
docs_archive/               # 历史文档存档（含 v2.24+ 旧版全文，数值不可引用）
firmware_F16/               # 仅说明文件：如何从自己的固件重建 vmlinux.elf
```

`.gitignore` 排除厂商固件/镜像、厂商工具包、第三方完整利用代码、克隆的参考项目、探针编译产物，原因见下节。

---

## 离线复跑（不需要设备）

```bash
python -m pip install pyelftools capstone ziglang
# 前提：自行重建 vmlinux.elf（步骤见 firmware_F16/README.md）

python tools/g2_maxmatch.py --selftest              # v6：哈希模型三方对拍（numpy / C 转录 / 逐指令模拟器）
python tools/g2_maxmatch.py --jobs 20               # v6：桶索引约束全窗口 max-match（复算 §46 的否定）
python tools/g2_maxmatch.py --line-pair --threshold 8 --jobs 20   # v6：64B 邻行对约束
python tools/hash_emu.py                            # v6 已修：逐指令模拟哈希块，返回真实桶索引
python tools/ksnitch_local_check.py                 # 方向A：KernelSnitch 本机闭环验证
python tools/gl_frame_calc.py                           # 帧几何 → waiter 绝对偏移 -0x288
python tools/gl_carrier_rescan.py --mode context --copy-extra strncpy_from_user  # 3 条 xattr 候选
python tools/gl_nul_analysis.py                         # NUL 语义 / 72B 字节映射
python tools/cil_selftest.py                            # CIL 28 用例
python tools/kfn.py --list 'futex|ashmem|configfs|nfulnl'  # 符号查询
python tools/kgsl_lifecycle.py                      # v12：KGSL 取/放点普查 + 机械可疑项
python tools/kgsl_lifecycle.py --pending            # v12：pending_free(entry+0xb0) 访问点
python tools/kgsl_ioctl_scan.py --detail            # v11：54 入口 / 14 拷贝点（长度维度）
```

真机只读探针（**纯用户态 futex 计时，不会 panic**；GhostLock 端到端 PoC 不提供）：

```bash
zig cc -target aarch64-linux-musl -O2 -static -o timer_probe live_probe/timer_probe.c
zig cc -target aarch64-linux-musl -O2 -static -pthread -o collision_probe live_probe/collision_probe.c
zig cc -target aarch64-linux-musl -O2 -static -pthread -o purity_probe live_probe/purity_probe.c   # v6：hit 纯度甄别（翻转重复性判据）
export MSYS_NO_PATHCONV=1                 # Git Bash 必须关闭路径转换
adb push live_probe/collision_probe /data/local/tmp/
adb shell '/data/local/tmp/collision_probe'
```

KGSL 判定型探针（v12.1，**不提交 GPU 命令、不 mmap**，分阶段独立进程；每阶段前后校验 `boot_id`/`uptime`）：

```bash
zig cc -target aarch64-linux-musl -O2 -static -o live_probe/kgsl_sparse_probe live_probe/kgsl_sparse_probe.c
adb push live_probe/kgsl_sparse_probe /data/local/tmp/ && adb shell 'chmod 755 /data/local/tmp/kgsl_sparse_probe'
adb shell '/data/local/tmp/kgsl_sparse_probe prop'     # 处理器到达性（EFAULT / EINVAL）
adb shell '/data/local/tmp/kgsl_sparse_probe matrix'   # 分派层真值表（ENOTTY / ENOTSUPP）
adb shell '/data/local/tmp/kgsl_sparse_probe sparse'   # 六个 sparse 入口（本机：全 524）
adb shell 'rm -f /data/local/tmp/kgsl_sparse_probe'
```

---

## 为什么二进制不在仓库里

1. **厂商固件不是我的版权**：`boot.img`（67 MB）、`kernel.decompressed`（33 MB）、`vmlinux.elf`（39 MB）合计约 140 MB，属 OPPO 发行物及派生二进制。
2. **厂商工具含授权组件**：`REF/` 的 OPPO 官方 exe/dll 不再分发。
3. **厂商镜像与提取二进制不入库**：`vendor.img`、`odm.img`、提取的 HAL service 等；文档给出从官方 OTA 只取 584 MiB 的复现路径。
4. **第三方完整利用代码不重新分发**：参考项目（含 `ref_pc/km00`）只标注出处，读者自行取用。
5. **探针编译产物不入库**：`live_probe/` 只推 `.c` 源码与报告，二进制平台相关且体积大。

替代方案：`firmware_F16/README.md` 说明如何从**自己的**固件/设备重建四件物料，并附自证方法（`stext` 反汇编应得 `head.S`）。

**本仓库没有任何可用于提权的完整利用代码。** `tools/` 与 `live_probe/` 的 C 程序是触发与只读探针；真机探针只做用户态 futex 计时，不构成提权链。

---

## 责任使用

- 全部实验在**作者自有设备**上进行，未针对任何第三方系统；序列号已脱敏。
- **结论不是单一负结果**：确实取得了受限 root（§23）与 GhostLock 侧信道实证（§41）两项结果；但**可用 root / 持久 ROOT 仍判定为否**。仓库不提供、也不承诺一键 root / 解锁能力。
- **GhostLock 端到端 PoC 不提供**：参考项目自报 ~97% 概率 panic，且本机无 panic 文本通道；v3 只做用户态侧信道探针。
- 本项目包含对厂商私有接口的分析（§16–§23），**不提供调用样例/命令串/载荷/利用代码**——只记录机制、判定与判据。对非自有设备使用等同于攻击。
- 发现任何可用于真实攻击且有实际危害的遗漏，请开 issue 而非直接扩散。

---

## 审阅须知（v12）

外部复核者请按以下靶面攻击，**只接受可复算的反例**。1–6 为 GhostLock（已冻结，仅保留靶面），7–9 为当前主线：

1. **② 堆路径**：是否存在 K3 上"把可控数据写到已知内核地址"的原语？这是把 slide 兑现为受控 rt_mutex 的前提（参考项目靠 AF_UNIX skb 喷射，K3 无）。
2. **③ 栈路径**：4.9 / `!VMAP_STACK` 下是否存在针对 order-2 连续页栈地址的泄露面？futex 哈希侧信道已证不行，USENIX'25 TLB 侧信道依赖 VMAP_STACK（本机关闭）。
3. **方向 A 的唯一性**：`N=4` 误报期望 ~0.65 属边缘，建议复核 `tools/ksnitch_local_check.py` 的误报模型与 hsz=1024 单档判定。**注意（v008）：这与 110× oracle 是两道独立的门——oracle 证明"能采到真碰撞"，唯一性决定"这些碰撞够不够唯一"，互不蕴含。**
4. **侧信道实测能否放大**：本机 110× 信号是否足以支撑"在真实噪声下稳定找到碰撞"？探针用 256 线程，参考项目用 4096。
5. **地址三档的完备性**：是否存在第 ④ 类可用地址（既非栈、非 pi_state 堆、非仅 slide）？
6. **三类地址是否独立（v008）**：见 `FEASIBILITY_v008.md` §1 的反汇编证据；要构成推翻，须给出 `mm_va → kimage_voffset` 的可复算数学关系，而非再证一次侧信道可用。
7. **~~KO-1 的可达性~~（已关闭，v12.1）**：实测六个 sparse 入口同一门 `ENOTSUPP(524)`，`device->flags` BIT(1)（`KGSL_FLAG_SPARSE`）未置位 ⇒ 对象无法创建。若你认为该位可在本机构造，请给出可复算路径。
8. **~~KO-1 的泛化~~（已阶段性关闭，v12.2 / §63）**：非 sparse 面的释放链已由 I10–I12 三条全称不变量覆盖，且 I4 上机证实无 double-free（K2 达成）；不再列为当前可动方向。**仅接受**违反 I10–I12 的新指令级反例，或新的可达面对象/路径；重复提交已审入口不构成推翻。向外评述请沿用 §63 的限定：K2 在「非 sparse、已审静态路径 + 立即释放判定」范围内达成，延迟释放动态行为与 K3 不在实证范围内。
9. **C-3 的已知性（降级）**：`tmp_size = size - v_off - offset`（§61.7）是否为该分支已知实现？因 sparse 整支不可达，此条仅作潜在缺陷记录。

| 不构成推翻 | 构成推翻 |
|---|---|
| "侧信道能拿地址了，所以能 root 了" | 给出 ② 或 ③ 类地址的可复算获取路径，并说明如何填进 fake waiter 的 lock/rb |
| "GhostLock 历史上有漏洞" | 指明本机某字段越界点，给出可复算反汇编地址 |
| "可能还有别的面" | 指名该面并给出策略/rc/二进制中的存在证据 |
| 用其它 SPL/内核外推 | 指明本机 SPL `2022-04-05` / 内核 `4.9.227-perf+` 下同一路径的差异 |
| "KGSL 历史 CVE 很多，应该有问题" | 给出本机某 ioctl 的**释放门缺失**或**序号/索引未校验**的具体指令地址（对照 §61.5 的 I1–I9 指出违反了哪一条） |
| "某 CVE 进了 CISA KEV / 有公开 PoC / 在野利用" | 给出该 CVE 在本机 `4.9.227-perf+` 上的**引入形态 + 域可达性 + 安全边界**证据。外部 PoC/KEV 不构成本机适用性证据；「pre-fix 形态 ≠ 可利用」「EOL ≠ 已修复」——判据是 commit 演变 + 本机反汇编，不是 SPL 或公告日期（v14 §0/§7） |

---

## 何时应重开 / 已重开

1. **【v3 已重开 · v12 冻结】GhostLock**：重开理由是侧信道真机可用（① 类地址可得），而非"任一地址泄露"。**v12 起冻结**：②/③ 在已审接口范围内均无路径，重开条件收紧为"出现新的、可独立验证的内核对象地址来源"。**注意：路径重开 ≠ 已 root。**
2. **【v12 主线 · v12.2 阶段性收口】KGSL 生命周期**：KO-1（§61.6）已由 §62 上机关闭（sparse 面 `ENOTSUPP`）；非 sparse 释放链自洽（I10–I12）+ I4 上机证实 ⇒ K2 达成、主线阶段性关闭，K3 并发登记不作。重开条件收紧为：新同 SPL 的 sparse 可达面、K3 新证据（可承受重启的独立设备 + 新授权）、或违反 I10–I12 的可复算非 sparse 不变量反例。
3. binder 线：出现面向 4.9 / ticket spinlock 的 UAF 原语研究 → 靶点、pre-fix 证据、堆条件已备。
4. SPL / 内核构建变化 → 全部偏移/形态/策略作废，须整体重跑（故建议关闭 OTA）。
5. 取得 pstore / dmesg / last_kmsg 任一 → 可定位 panic 精确点。
6. Wi-Fi 面：**已打通**（受限 root）；主缺口 = SELinux 域逃逸，§24 判无路径。
7. 其余各面的重开条件见 `HANDOVER.md` §7 与 `CLOSURE.md`。
8. **【v14 已收敛】联网 CVE 候选**：全部外部 CVE 已按四层筛选收敛为负结果或静态分诊；唯一新增复核项 `CVE-2025-38352` 已由任务 E1 完成离线复核（pre-fix 结构同构证实、动态可达性未证、动态默认禁止、不升级授权，见 `docs_archive/CVE-2025-38352_E1形态复核_2026-11-20.md`）。仅在出现适配 4.9/arm64、不依赖 5.10 slab 几何与 `.text` slide 的新原语，且有可承受重启的独立测试设备并重新授权时重开。

---

## 致谢

分析依赖以下公开工作：`marin-m/vmlinux-to-elf`（符号重建转折点）、`NebuSec/CyberMeowfia`（CVE-2026-43499 原始研究）、`yijiacloud/GhostLock-OPPO-PCKM00`（v3 侧信道参考）、`JoinChang/ghostlock-oneplus` / `mobilehackinglab/ghostlock-a17`（arm64 移植）、`0xkol`（CVE-2022-20421 论文）、Google Project Zero（CVE-2023-33107 RCA）、Linux v4.9 源码（GPLv2，结构体基准）、NDSS'25 KernelSnitch 与 USENIX'25 TLB 侧信道论文（v3 侧信道分析）。

---

## English summary

**A negative result, one breakthrough, and a reopened path.** On an OPPO K3 (`PCGM00`, SDM710, kernel `4.9.227`, SPL `2022-04-05`, locked bootloader, shell-only), five kernel surfaces and several service surfaces were evaluated. Four kernel surfaces are unreachable; the Wi-Fi private transaction **worked** — a shell-reachable root service executes attacker strings via `sh -c` as `uid=0` (twice reproduced), though confined to a MAC-restricted domain, so this is **confined root command execution, not a usable root**.

**v3 (2026-11-19)**: after external review pointed to a sibling-device reference project, the previously frozen **GhostLock** path was **reopened**. A live probe proved the futex hash-bucket timing side-channel works on this device (110× signal), making the mm_struct's linear-map address obtainable. **The usable-root verdict is unchanged**: the obtained address class (①) cannot fill the fake waiter's `lock`/rb fields; the real gap is now precisely **address type** — a controllable `rt_mutex` kernel address (②, heap-spray) or the W-thread kernel stack base (③) — neither of which this device currently provides. This is a **research-path reopening, not a verdict flip**.

**v008 caliber correction (2026-11-19)**: the earlier claim of "end-to-end KASLR slide" is withdrawn. Three address relations are independent: (R1) KernelSnitch yields only the mm_struct's position in the direct physical mapping; (R2) conversion to a physical address uses compile-time constants and leaks no secret; (R3) the `.text` KASLR slide is carried by a separately boot-computed `kimage_voffset` and **cannot** be derived from R1/R2 on this arm64 kernel (binary evidence in `FEASIBILITY_v008.md` §1). The 110× signal proves the timing oracle exists, but is a separate gate from the N=4 uniqueness problem.

**v12.1 (2026-11-20)**: KO-1 went to the device and came back **closed**. The hypothesis was sound in the code — the "a bound physical block must not be freed" guard exists in exactly one ioctl — but this device does not implement the feature at all: `kgsl_device::flags` BIT(1) (`KGSL_FLAG_SPARSE` upstream) is clear, so all six sparse entry points return `ENOTSUPP(524)` before touching any state. Control probes rule out the alternative explanation that the ioctls never reached the driver: `getproperty` with a bad pointer still yields `EFAULT`, an unregistered command yields `ENOTTY`, and `syncsource_create` returns 0. KO-1, C-2 and C-3 are therefore **latent code defects on an unreachable path**, and the reachable audit surface narrows to the non-sparse objects. One methodological correction is recorded in §62.3: the first probe reported every failure as `EPERM` because it computed `strerror(-ret)` instead of reading `errno` — the only "new finding" of that hour was a bug in my own tooling.

The write-up keeps the full evidence chain, the quantifiable gates, the reusable tooling, and deliberately **25+ previously "certain" conclusions later falsified** by this project's own experiments or external review. Start with [`HANDOVER_RESUME.md`](HANDOVER_RESUME.md), then [`HANDOVER.md`](HANDOVER.md) §62 → §61 → §60 → §53.

---

## License

- 代码（`tools/`、`live_probe/`）：**MIT**，见 [`LICENSE`](LICENSE)。
- 文档（`HANDOVER.md`、`README.md`、`docs_archive/`）：**CC BY 4.0**。
- `src_ref/` 内的内核源码与补丁：保留原始许可（GPLv2 及其对应条款）。

分范围的完整说明见 [`NOTICE.md`](NOTICE.md)。
