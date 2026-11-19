# 接手摘要（v5 内核镜像终审 + G2 矛盾定位 · 2026-11-19）

> 一页式入口。完整证据在 `HANDOVER.md`（§45 本轮 + §44 v4 实测 + §38–§43 + 历史）；分层判定在 `CLOSURE.md`；
> 审阅入口在 `README.md`；实测报告在 `live_probe/LIVE_PROBE_RESULT_v4.md`（v5 增补见 §8）。
> **v5 要点**：① **transfer2_probe 终审通过——G1 桶索引性成立（复活）**；② e2e2 端到端 26 真实 hit（rate 1/1260），
> 但 G2 仍全零 → ③ 对本机内核二进制做逐指令终审（`firmware_F16/vmlinux.elf` 构建串与设备完全一致，为权威镜像）：
> **哈希模型（标准 jhash2）、key 布局、hashsize=2048、桶 stride=128B、task->mm@0x5c8、sizeof(mm_struct)=872
> （SLUB 步长 896）、KASLR 线性映射滑移恒为 0 全部二进制确认**——模型/网格/窗口/oracle 四要素均无错，
> 矛盾唯一剩余解释：**26 个 hit 中约 10 个疑为他进程瞬时 futex 热通过 pausecheck（300ms 窗口）污染约束集**。
> ④ 鲁棒方案 `tools/g2_maxmatch.py`（最大匹配搜索）已写好，本轮运行中被中止、未出结果，**待重跑**。
> 四层 ROOT 判定 NO-GO 不变。
> **设备待办**（下次连接）：重跑 g2_maxmatch.py 对应的离线搜索（无需设备）→ 若出解则端到端验证 →
> 清理 `/data/local/tmp`（10 项，清单见 §5）。
> **v008 口径**：三类地址独立（① mm 线性地址 / ② 物理换算无秘密 / ③ KASLR slide 需独立镜像 VA 泄露）；权威见 `FEASIBILITY_v008.md`。
> 历史版本已归档到 `docs_archive/`，数值不可引用。

## 1. 当前结论（四层，不可混用）

| 层次 | 状态 |
|---|---|
| Wi-Fi 域内 Root UID 命令执行 | **已达成**（2026-11-18，`\n`/反引号绕过黑名单 → `sh -c` 以 `uid=0`、域 `u:r:oplus_wifi_service:s0` 执行，两次复现，§23） |
| 可用 root（脱离 SELinux 域） | **未达成**；域逃逸静态审计无路径（§24），FastRPC 在 uid 0 域下反而更封闭（§32） |
| 持久 ROOT | **未达成**，按约定不做任何持久化写入 |
| **GhostLock 内核地址泄露** | **v5 更新**：① 类地址原语 KernelSnitch——**G1 桶索引性成立**（transfer2 终审：pause 冷、迁 B/C 冷且仅当前堆积地址热、迁回 A 复热 2927-6660 ticks）；G1∧G2 端到端仍未达成，阻塞点收窄为 hit 集污染假设（待 max-match 重跑判定）。② 维持未闭合（缺地址可知性）；③ perf 路线已实测排除（paranoid=3） |

**总体**：BL 锁定条件下可用 ROOT 仍为 NO-GO。方向 A（KernelSnitch）处于"最后一公里"：若 max-match
搜索找到唯一 mm ⇒ G2 复活 ⇒ ① 类地址闭合；若仍无解 ⇒ 机制存在未识别偏差，需重新审视 G1 语义。

## 2. v3/v4/v5 本轮做了什么（2026-11-19）

| 节 | 内容 | 结果 |
|---|---|---|
| §38–§43 | v3 证据链 + v008 响应 | 三类地址独立、oracle/唯一性分离 |
| §44 | v4 真机实测 | P2 perf 排除；P1 skb 生命周期可控；G2 全窗口零命中；transfer2 待终审 |
| **§45** | **v5 终审与矛盾定位** | **transfer2 通过（G1 复活）；e2e2 端到端 26 hit；内核镜像逐指令终审全要素确认；三种约束搜索仍零命中；新假设=hit 集污染；max-match 搜索待重跑** |

**关键口径变化**（引用旧结论时必须更正）：

- ❌ "G1 桶索引性未验证/降级"（v4 §5.4） → ✅ **v5 复活**：transfer2_probe 终审成立（迁移语义正确：先改指针再 WAKE 旧地址）。
- ❌ "步长 896 扫描是真实地址集合的超集"（KSNITCH_LOCAL_CHECK §五.5）与 v4 的"结构性枚举"口径 → ✅ **v5 二进制确认**：
  `sizeof(mm_struct)=872`（proc_caches_init 第 5 次 kmem_cache_create，w1=0x368），SLUB 步长 = ALIGN(872,64) = **896**；
  正确结构性枚举 = **8192 对齐 slab 基址（覆盖 order-1/2/3）× 896×j (j<36)**。
- ❌ "futex 计时信号可能不是桶索引 oracle"（v4） → ✅ transfer2 终审成立，WAKE(1) 计时污染已用 WAKE(0)/迁移语义修复规避。
- ✅ **KASLR 线性映射随机化排除**（新增）：`memstart_offset_seed` 符号存在（0xffffff8009a851ac），但本配置下
  `ARM64_MEMSTART_ALIGN=256GB`，滑移量上界 < 2^38，量化后**恒为 0**——线性映射 = PAGE_OFFSET + phys，无滑移。
- ✅ **哈希模型最终确认**：futex_wake/futex_requeue 内联块 movz `0xdeadbeff` 是编译器折叠（0xdeadbeef+16），
  实为**标准 mainline jhash2(k=[mm_lo,mm_hi,page_lo,page_hi], 4, off=addr&0xfff)**；`tools/hash_emu.py`
  逐指令模拟器与 numpy 实现 300/300 对拍一致。
- ✅ **futex_hashsize=2048**（futex_init：256 × popcount(possible 掩码字节)，二进制确认）；桶结构 stride=**128B**
  （init 循环 `add x8,x8,#0x80`），futex_queues @ 0xffffff8009e0e150，hashsize @ 0xffffff8009e0e160。
- ✅ **task->mm @ 0x5c8**（copy_process：`ldr x0,[mm_cachep@0xffffff800a0229c0]` → alloc → `str [x19,#0x5c8]`）。

## 3. 下一步（按性价比）

1. **[最高优先，纯离线]** **重跑 `python tools/g2_maxmatch.py`**（被中止，未出结果）。对每个候选 mm 统计与 inc
   同桶的 hit 数；真 mm 应得 ~16-26，随机 mm 期望 0.013——对 hit 集污染鲁棒。出解 ⇒ 用该 mm 在设备上做
   mask-2048 预测命中率验证（e2e2 的 VERIFY 段逻辑）；无解 ⇒ 转第 3 条。
2. **[需设备]** 若 max-match 出解：编译并运行端到端验证探针（基于 e2e2_probe.c 改造：用恢复的 mm 预测同桶地址，
   计时验证）；随后清理 `/data/local/tmp`。
3. **[需设备，若 1 无解]** 设计"hit 污染"甄别探针：单 hit 地址迁移实验（迁移 crowd 至单个 hit 地址 H，若 H 与
   inc 不同桶则迁移后 inc 变冷）逐个甄别 26 个 hit 的真伪，取纯净子集再做 G2。
4. **[纯离线]** 若 3 也无解：扩大搜索窗口（物理内存顶端 SDM710 6GB 布局 VA 上界恰在 +8GB，可扩展至 +16GB 复核），
   或重新审视 hashsize 字节（`0xffffff8009e0dfc8` 的符号身份未最终确认）。
5. **[不做]** boot_id / ashmem 后置实现；GhostLock 端到端 PoC；依赖未验证 G2 的上机动作。

## 4. 工具与物料入口

```bash
python tools/g2_maxmatch.py                      # v5：最大匹配 G2 搜索（待重跑，被中止未出结果）
python tools/hash_emu.py                         # v5：内联哈希块逐指令模拟器（ground truth，已修 3 个 bug 后可用）
python tools/g2_pair_search.py                   # v5：桶对约束搜索（cache-line 邻桶假设，已证伪但仍留档）
python tools/g2_pair_search2.py                  # v5：无+16 变体搜索（已证伪：0xdeadbeff 为编译器折叠）
python tools/device_config.txt                   # v5：设备 /proc/config.gz 解压（VA_BITS=39/SLUB/RANDOMIZE_BASE=y 等）
python tools/ksnitch_local_check.py              # 方向A 本机闭环验证
python tools/kfn.py --list 'futex|jhash|memstart'  # 符号查询（只认 firmware_F16/vmlinux.elf）
python tools/kfn.py --addr 0xffffff800815de00 --n 0xdc      # futex_wake 内联哈希块（v5 终审对象）
# 关键地址速查（vmlinux 静态 VA）：
#   get_futex_key 0xffffff8008161d08  futex_wake 0xffffff800815dda0  futex_init 0xffffff8009a158d8
#   arm64_memblock_init 0xffffff8009a08ff0  kaslr_early_init 0xffffff8009a087d8  proc_caches_init 0xffffff8009a0b098
#   mm_cachep 0xffffff800a0229c0  futex_queues 0xffffff8009e0e150  futex_hashsize 0xffffff8009e0e160
#   memstart_offset_seed 0xffffff8009a851ac  memstart_addr 0xffffff80098524f8  module_alloc_base 0xffffff80098524e0
# 真机探针编译/推送：
#   python -m ziglang cc -target aarch64-linux-musl -O2 -static -pthread -o live_probe/X live_probe/X.c
#   MSYS_NO_PATHCONV=1 adb push ... /data/local/tmp/ && adb shell chmod 755 ...   # Git Bash 必须关路径转换
```

## 5. 运营约定

- 设备 `PCGM00_11_F.16`（SDM710，6GB，PAGESIZE=4096，构建 `4.9.227-perf+ #1 Wed Mar 26 16:32:43 CST 2025`）
  未刷写、未解锁、未改分区、未装持久化文件；真机实测零重启。
- **`/data/local/tmp` 清理清单（10 项，未执行）**：`perf_probe spray_probe e2e_probe same_bucket_probe
  calib_probe transfer_probe transfer2_probe e2e2_probe ks_e2e_result.txt ks_e2e2_result.txt`。
- e2e2 原始数据已拉取入库：`live_probe/ks_e2e2_result.txt`（region=0x77be2a0000，inc=0x77be2a0080，
  26 个真实 hit）——离线 G2 全部以此为输入。
- **建议关闭 OTA**：SPL / 内核构建变化会使全部偏移、形态、策略判定作废。
- 厂商二进制/镜像、第三方完整利用代码不入库（见 `.gitignore`）；报告与脚本可入库。
- 新对话从本文件开始 → `HANDOVER.md` §45（v5 终审）→ §44（v4 实测）→ §42–§43；口径权威在 `FEASIBILITY_v008.md`。
