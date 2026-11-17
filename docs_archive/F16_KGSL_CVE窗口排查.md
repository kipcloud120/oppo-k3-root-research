# F.16（4.9.227）KGSL CVE 补丁窗口排查

- 日期：2026-11-13
- 目标：从 shell（uid 2000，`/dev/kgsl-3d0` 世界可 open）出发，筛出**在 F.16 上可能仍未修复、且 4.9 版本适用**的 KGSL（Adreno GPU 驱动）CVE
- 依据：F.16 内核符号表（`firmware_F16/kallsyms_out.txt`，123784 符号）做"版本适用性"闸门 + 公开 CVE/补丁资料 + `k3_kernel_config.txt`
- 结论等级：**【实】** 符号/配置一手；**【源】** 公开 CVE 库/公告；**【推】** 推断

---

## 0. 结论先行

1. **两个最出名的"在野利用"KGSL CVE 不适用于 K3**（4.9 无对应代码）：
   - `CVE-2023-33106`：靶点 `kgsl_ioctl_gpu_aux_command` —— **F.16 符号表不存在**（4.9 无该 ioctl，补丁目标 msm-4.19）。
   - `CVE-2022-22057`：靶点 `kgsl_timeline` / `kgsl_timeline_fence` —— **F.16 符号表不存在**（4.9 无 timeline 特性）。
2. **两条"强候选"（4.9 代码路径存在 + 修复晚于 SPL 2022-04）**：
   - **① `CVE-2026-21385`**：KGSL `kgsl_memdesc_get_align()` 符号扩展 → 对齐整数溢出（CWE-190）；修复 2026-03-05，CISA KEV（2026-03-03，在野利用）；`gpumem_alloc/gpuobj_alloc` 路径在 4.9 存在 → **大概率未修**。
   - **② `CVE-2023-33107`**：KGSL SVM/IOMMU 整数溢出（`IOCTL_KGSL_GPUOBJ_IMPORT`/`MAP_USER_MEM` → `arm_lpae_init_pte` 返回值未检查）；修复 2023-12-05，CISA KEV；**4.9 的 SVM + arm_lpae 全套符号存在** → **适用**；且**有公开 PoC（ex.c，~88KB）**。
3. **补充面**：`CVE-2023-33063`（DSP FastRPC UAF）—— `fastrpc_*` 符号存在，但面是 `/dev/adsprpc*`，shell 可达性待测。
4. **已修/排除**：`CVE-2021-1905`（gpumem_vm_close UAF，2021-05 修复，≤SPL 2022-04，已打）。

> **结论**：KGSL 路线**确有可用候选**，且 `CVE-2023-33107` 有公开利用可参考，**实战价值不低于 GhostLock**；`CVE-2026-21385` 更新、更"确定未修"。两者都需要 4.9 专属适配（偏移/堆喷/该机 KASLR）。

---

## 1. 补丁基线（为什么"2022-04 之后基本不修"）

| 事实 | 值 | 含义 |
|---|---|---|
| 设备 SPL | `2022-04-05` | 内核安全补丁冻结在 2022-04 |
| 内核 | `4.9.227-perf+`（vendor fork，2025-03 构建但 SPL 未前进） | 构建日期 ≠ 补丁日期 |
| **SDM710 平台状态** | **高通在 Android 11 / 内核 4.9 上已停止支持 SDM670/710/712**（不再列入受影响列表、不再出 CAF/CLO tag）【源】 | **2022-04 之后的 vendor KGSL 补丁不会进入 K3** |
| 结果 | — | 凡修复日期 > 2022-04-05 的 KGSL CVE，**默认未修**（除非 OPPO 手工 backport，EOL SoC 不太可能） |

---

## 2. 筛选方法

对每条候选 CVE，依次过三道闸：

1. **可达性**：是否能从 shell/普通 App 经 `/dev/kgsl-3d0` 触发（PR:N、无特殊权限）→ KGSL ioctl 均为 yes。
2. **版本适用性（本次核心）**：其**受影响函数/ioctl 是否在 F.16 符号表中存在**——不存在即 4.9 无此代码，直接排除（避免"看新闻瞎套"）。
3. **补丁窗口**：修复日期 > SPL `2022-04-05` → 大概率未修；< → 已修。

---

## 3. 逐条判定

| CVE | 组件/靶点 | 修复 | 4.9 适用性（符号闸门） | 结论 |
|---|---|---|---|---|
| **CVE-2026-21385** | KGSL `kgsl_memdesc_get_align()` 对齐符号扩展→整数溢出（CWE-190） | 2026-03-05（KEV，在野） | `gpumem_alloc`/`gpuobj_alloc` 路径在；`memdesc_get_align` 多为内联、无独立符号（需代码级确认 signed） | **强候选①（大概率未修）** |
| **CVE-2023-33107** | KGSL SVM/IOMMU：`GPUOBJ_IMPORT`/`MAP_USER_MEM` 大尺寸→`arm_lpae_init_pte` 返回值未检查→悬垂 PTE→UAF | 2023-12-05（KEV，在野；有公开 PoC） | **SVM 全套在**：`kgsl_mmu_set_svm_region`/`kgsl_mmu_find_svm_region`/`kgsl_iommu_map`/`arm_lpae_map_sg`/`arm_lpae_init_pte`；ioctl 在：`kgsl_ioctl_gpuobj_import`/`map_user_mem`/`gpu_command` | **强候选②（适用）** |
| CVE-2023-33106 | KGSL `IOCTL_KGSL_GPU_AUX_COMMAND` 同步点列表越界 | 2023-12（msm-4.19） | **`kgsl_ioctl_gpu_aux_command` 不存在** | **排除（4.9 无此 ioctl）** |
| CVE-2022-22057 | KGSL `kgsl_timeline` UAF（GHSL-2022-037） | 2022-05（msm-5.4） | **`kgsl_timeline` 不存在** | **排除（4.9 无 timeline）** |
| CVE-2023-33063 | DSP FastRPC DMA UAF（非 KGSL） | 2023-12（msm-5.15/4.14） | `fastrpc_*` 在（`fastrpc_buf_alloc`/`internal_invoke`…）；面为 `/dev/adsprpc*` | **备选（可达性待测）** |
| CVE-2021-1905 | KGSL `gpumem_vm_close`/`get_unmapped_area` 映射 UAF | 2021-05 | 函数在，但**已含于 SPL 2022-04** | **排除（已修）** |

**关键点**：仅"看 CVE 标题像 KGSL"会误判——`33106`/`22057` 在 4.9 根本无对应代码；真正的 4.9 面是 **SVM/IOMMU（33107）** 与 **对齐分配（2026-21385）**。

---

## 4. 优先级与实战化排序

| 排序 | CVE | 理由 | 现成利用 |
|---|---|---|---|
| **1** | **CVE-2023-33107** | 4.9 SVM 证据最硬；ioctl 全在；**有公开可参考 PoC（ex.c）**；KEV 在野 | 有（device-dependent，需按 4.9/本机适配） |
| 2 | CVE-2026-21385 | 最新、KEV、几乎必然未修；但靶点内联、需代码级确认 signed 对齐 | 无公开 PoC（仅公告） |
| 3 | CVE-2023-33063 | FastRPC 面存在；非 KGSL；shell 可达性未证 | 公开分析有，PoC 少 |

**与 GhostLock 对比**：
- GhostLock：`futex` 系统调用触发（无需设备节点，可达性最稳），但需从零写 4.9 利用。
- **CVE-2023-33107**：`/dev/kgsl-3d0`（已证可 open）+ **有公开 PoC 骨架** → 起步更快，但 PoC 依赖固定地址/偏移，需重做布局。
- 建议：**KGSL/CVE-2023-33107 与 GhostLock 并行**，前者"有参考实现"更适合先出可利用原型。

---

## 5. 验证计划（把"推断"变"实锤"）

### 5.1 CVE-2023-33107（优先）
1. 取 **CAF msm-4.9 KGSL 源码**（与 4.9.227 对应 tag），定位 `arm_lpae_map_sg()` / `arm_lpae_init_pte()`：
   - 补丁前：`arm_lpae_init_pte` 返回值**未检查**、`ms.num_pte` 仍自增 → 即本机形态。
   - 补丁后：检查返回值、失败即 bail。
2. 反汇编 F.16 的 `arm_lpae_map_sg`（符号在 `0x005bf650`）与 `arm_lpae_init_pte`（`0x005bfd48`），确认是否有返回值检查分支。
3. 对照公开 PoC（`ex.c`）的 ioctl 序列（GPUOBJ_ALLOC→MAP_USER_MEM→GPU_COMMAND→free→shrinker），映射到 4.9 的结构体布局。
4. 若确认 pre-fix → 做 4.9 适配，目标"临时 root（改 addr_limit / cred）"。

### 5.2 CVE-2026-21385
1. 在 msm-4.9 KGSL 源码确认 `kgsl_memdesc_get_align()` 的返回类型：`int`（漏洞）/ `u32`（已修）。
2. 反汇编 `kgsl_ioctl_gpumem_alloc`（`0x006c93e8`）/`kgsl_ioctl_gpuobj_alloc`（`0x006c91b8`）看对齐值处理是否 sign-extend。
3. 若 signed → 未修，按"构造大对齐值→分配尺寸回绕→相邻堆破坏"设计原语。

### 5.3 FastRPC（备选）
- 先测 `/dev/adsprpc-smd`（或 `/dev/fastrpc-*`）对 shell 的可打开性（ADB 已断，需下次连机；或用 SELinux 策略静态判断）。

---

## 6. 边界与不确定性

- 本判定以**符号存在性**做版本闸门，属强证据；但"补丁是否回移"未逐条反汇编确认（列于 §5 验证计划）。
- `CVE-2026-21385` 的受影响芯片列表（235 项）未明确列出 SDM710（列表截断）；判定基于"通用 KGSL 对齐缺陷 + 4.9 代码路径存在 + EOL 不修"，属**高置信推断**，需 §5.2 实锤。
- 所有 KGSL 利用均需处理本机 **KASLR**（`RANDOMIZE_BASE=y`，且 kallsyms 不可读）与 **SLUB 喷堆**（`FREELIST_RANDOM` 未开，利好）。
- 未做动态验证（无 root、无连机）。
