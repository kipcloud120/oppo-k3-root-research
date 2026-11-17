# OPPO K3 临时 ROOT 可行性研究

> **一份负结果的完整记录**：在不解 BL 的前提下，对一台 OPPO K3（`PCGM00` / SDM710 / 内核 `4.9.227` / SPL `2022-04-05`）评估了五个候选面，全部判定为**无法达成临时 ROOT**——且每一面都停在**一个可命名的缺口**上，而不是"跑崩了"或"试不下去了"。

| | |
|---|---|
| 目标设备 | OPPO K3 `PCGM00`（`OP4679`，`sdm710`），Android 11，内核 `4.9.227-perf+`（clang 10.0.7，2025-03 构建） |
| 安全补丁 | `2022-04-05` |
| 启动状态 | BL 锁定、AVB `green`、dm-verity `enforcing`、A-only |
| 可用入口 | `uid=2000(shell)` + `u:r:shell:s0`，SELinux Enforcing，**`Seccomp: 0`** |
| 结论 | **no-go**。五个候选面：3 个机制成立但缺关键原语，1 个漏洞未引入，1 个被双重封闭 |
| 设备终态 | 系统未变，**未刷写、未解锁、未改分区、未 root**；累计 5 次内核重启（均为前期竞态实验） |

---

## 结论一览

| 候选面 | 机制是否成立 | 卡在哪一环 | 缺口能否参数化 |
|---|---|---|---|
| **KGSL** `CVE-2023-33107` | 成立（源码级 pre-fix 确定） | `arm_lpae_init_pte()` 的 `BUG_ON(!suppress_map_failures)`：静态变量运行期恒 false ⇒ **进入缺陷路径即 panic**，没有"先命中再利用"的中间态 | 否 |
| **GhostLock** `CVE-2026-43499` | 成立（`-EDEADLK` 10+ 次确定性复现） | **无栈覆盖载体**：`rt_mutex_waiter` 位于 `-0x288`，397 个 syscall 入口全扫 **0 命中**；合格带仅 54 字节宽，落在"浅 syscall"与"select 家族"之间的死区 | 否 |
| **binder** `CVE-2023-20938` | **不成立**（漏洞未引入） | `off_end_offset` 形态处于 `44d8047f1d87 … 32e9f56a96d8` 之间：`is_failure=1 且 failed_at=0` 时清理循环执行 0 次 | — |
| **binder** `CVE-2022-20421` | 成立（pre-fix 形态确证） | 本机是 **ticket spinlock**，公开技术依赖 qspinlock；原语退化为"对两半相等的 4 字节字加 `0x00010001`"，并带 `wfe` 死等风险 | 部分 |
| **FastRPC** `CVE-2023-33063` | 面存在 | 对 shell **双重封闭**：`O_RDWR` 被 SELinux 拒（`EACCES`）；只读 fd 上 7 个已实现 ioctl 全部 `EPERM` | 否 |

完整论证、证据与可复算数字见 **[`HANDOVER.md`](HANDOVER.md)**（597 行）。

---

## 四个值得单独看的结果

### 1. 把"符号不可用"从死路变成可解——问题根本不在镜像

项目前 16 节（v1）花了大量精力论证"镜像节区/函数重排、kallsyms 未同步、地址加减 delta 无效"，并据此放弃精确定位。**这个判断是错的**：真实原因是解析器把 kallsyms 偏移当作 base-relative 处理。

用 [`vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) 从 `kernel.decompressed` 重建 ELF 后，`stext` 反汇编得到的就是 arm64 `head.S` 的真实内容（`bl preserve_boot_args / bl el2_setup / …`），符号空间完全对齐，**123,784 个符号可用**。

> 教训：当一个"不可解"的结论支撑了后续几十页推理时，先怀疑工具，而不是先怀疑目标。

### 2. GhostLock：54 字节的死区，以及"为什么不是参数没调对"

`rt_mutex_waiter` 在 `do_futex` 帧内的绝对位置可由三个独立的 `sub xN, x29, #0xa8` 交叉确认为 `-0x288`；攻击者需要把 72 字节的 fake waiter 完整放进某个 syscall 的**用户可控栈缓冲区**里。判据是纯几何的：

```
d = 0x110 + Σ(调用链帧)          # 到缓冲区的深度
需  d - buf_off ∈ [0x288, 0x2BE]  # 54 字节宽的合格带
```

对 397 个 syscall 入口（含全部 `SyS_*` / `compat_SyS_*`，调用深度 ≤3）全量扫描：**命中 0，近失配 66**。最接近的 `fcntl_getlk` 也只覆盖 waiter 的前 16 字节。

`pselect6` 家族为什么救不回来：`core_sys_select` 单帧 `0x1c0` 加 `stack_fds @ sp+0x50`，把下限钉死在 `0x320`——比合格带深 98 字节。这不是 NFDS 调不调得对的问题，是**本机构建的帧几何与公开实现的目标设备不同**，公开实现里的 `PSELECT_SHIFT`（±2 字）量级远小于此差值。

### 3. ticket spinlock 把 4 字节 UAF 写降级成一个常数加法

`CVE-2022-20421` 在本机确证为 pre-fix（`binder_inc_ref_for_node` 尾部结构精确等于修复前的 `unlock; if (new_ref && ref != new_ref) kfree(new_ref);`），但公开技术的前提是 qspinlock：一次 lock+unlock 可把目标指针的低 2 位置零，从而破坏对齐、触发类型混淆。

本机没有 `queued_spin_lock_slowpath`，`_raw_spin_lock` 是 `ldaxr` → `+0x10000` → `stxr` → `wfe`，`_raw_spin_unlock` 是低 16 位 `+1`。⇒ 本机原语 = **"对一个两半相等的 4 字节字加 `0x00010001`"**，且不满足"两半相等"时会**挂死而非写入**。整条"对齐破坏 → 类型混淆 → 任意读写"的后续链条无法套用。

这条被记录为 **"pre-fix 但无可用原语"**，不是"不可利用"——两者差别很大。

### 4. 两个"看起来能用、实际一步都走不通"的面

- **KGSL**：同源 4.9 源码里 `arm_lpae_map_sg()` 确实不接 `arm_lpae_init_pte()` 的返回值且无条件 `ms.num_pte++`，符合 RCA 描述。但 `suppress_map_failures` 只在驱动自检期为 true，运行期恒 false ⇒ 一旦 `mmap` 撞上已存在的有效 PTE，执行的是 `BUG_ON()` 而不是返回 `-EEXIST`。三轮实测吻合：300 µs 延时立即掉线，3000/5000 µs 安全。
- **FastRPC**：`/dev/adsprpc-smd` 可 `O_RDONLY` 打开，`ioctl(fd, 0)` 返回 `ENOTTY` 说明请求已穿过 SELinux 钩子进了驱动；但 `O_RDWR` 被策略拒（`EACCES`），而只读 fd 上 7 个已实现 ioctl 全部在参数拷贝前返回 `EPERM`。写通道与调用通道各被封一半。

---

## 为什么这不是"没试够"

| 维度 | 已量化的事实 |
|---|---|
| 覆盖面 | 4 类组件、5 个候选面（KGSL / GhostLock / FastRPC / binder ×2 CVE），全部有"机制是否成立"的判定 |
| 判据形式 | 全部可证伪：帧深区间 `[0x288, 0x2BE]`、`off_end` 三元式形态、spinlock 指令序列、`EPERM` 实测 |
| 失败可解释 | 每一处失败都能指出"缺哪一环"，而不是"崩了" |
| 工具化 | 帧计算、载体扫描、符号重建、补丁形态比对均已脚本化，可离线复跑 |
| 负知识 | 主动记录 **17 条**曾被自己认定为"确定"、后被实验推翻的结论及推翻依据（`HANDOVER.md` §6） |

---

## 仓库结构

```
HANDOVER.md                 # 主文档：结论页 + 逐面论证 + 关键常数 + 重开条件
README.md                   # 本文件
LICENSE                     # MIT（代码）/ CC BY 4.0（文档）
tools/                      # 55 个文件：25 个 Python 分析器 + 28 个 C 实验程序
├── gl_frame_calc.py        # 帧几何计算（读 vmlinux.elf，输出 waiter 绝对偏移）
├── gl_carrier_scan.py      # 397 个 syscall 入口的载体扫描
├── f16_rtmux_49_layout.py  # 4.9 rtmutex/futex 结构体布局（离线复算 waiter=72B）
├── f16_layout_v2.py        # task_struct 布局引擎（含 slab 校准）
├── g1_edeadlk.c → g3c_v7.c # 三锁环触发 + 三段式换向 + A′ 活帧对照
├── k3_*.c                  # KGSL 阶段 A/B/C 与竞速实验
└── surface_probe.c / frpc_ioctl_probe.c   # 攻击面普查、ioctl 表枚举
src_ref/                    # 权威源码与补丁（v4.9 tag 的 rtmutex.c/futex.c、修复 diff、RCA）
artifacts_adb/              # 设备原始输出与逐步日志（g_logs/），共 60+ 份
docs_archive/               # 历史文档存档，见其中 README.md 的状态标注（数值不可引用）
firmware_F16/               # 仅说明文件：如何从自己的固件重建 vmlinux.elf
```

`.gitignore` 排除了厂商固件、内核二进制、厂商 Windows 工具包与第三方完整利用代码，原因见下一节。

---

## 离线复跑（不需要设备）

```bash
# 依赖
python -m pip install pyelftools capstone
#   注意：本机 pip 指向 Python312 而 python 是 3.13，两者不是同一环境，务必用 python -m pip

# 前提：自行重建 vmlinux.elf（步骤见 firmware_F16/README.md）

python tools/gl_frame_calc.py        # 帧大小与 waiter 绝对偏移 → -0x288
python tools/gl_carrier_scan.py      # 397 个入口 → 0 命中，66 近失配
python tools/f16_rtmux_49_layout.py  # 4.9 结构体布局 → waiter = 72 B（非 80）
```

设备侧实验（**会触发内核 panic，仅限自有设备**）：

```bash
ZIG=.build/zig-windows-x86_64-0.13.0/zig.exe
$ZIG cc -target aarch64-linux-musl -static -O2 -pthread -o .build/g3c_v7 tools/g3c_v7.c

export MSYS_NO_PATHCONV=1                       # Git Bash 必须关闭路径转换
adb push .build/g3c_v7 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/g3c_v7; timeout 25 /data/local/tmp/g3c_v7"
```

---

## 为什么二进制不在仓库里

1. **厂商固件不是我的版权**。`boot.img`（67 MB）、解压后的 `kernel.decompressed`（33 MB）、由此重建的 `vmlinux.elf`（39 MB）合计约 140 MB，属 OPPO 发行物及其派生二进制，不宜公开再分发。
2. **厂商工具包含授权组件**。`REF/` 内含 OPPO 官方刷机/鉴权程序的 exe/dll，同样不再分发。
3. **第三方完整利用代码不重新分发**。参考的公开 PoC 只在文档中标注出处，读者自行取用。

替代方案已给出：`firmware_F16/README.md` 说明如何从**自己的**固件或设备转储重建四件物料，并附自证方法（`stext` 反汇编应得到 `head.S`）。

**本仓库里没有任何可用于提权的完整利用代码。** `tools/` 下的 C 程序是触发与探针程序，在目标内核上的最好结果是 `-EDEADLK` 或 panic（DoS），不构成提权链。

---

## 责任使用

本项目的目的**只有一个**：判断"在不解 BL 的前提下，这台设备是否存在可行路径"，并把这个判断的依据留在可复核的形式里。

- 全部实验在**作者自有的设备**上进行，未针对任何第三方系统。
- 所有结论是**负结果**。仓库不提供、也不承诺提供 root / 解锁能力。
- `tools/` 中的触发程序会使目标内核 **panic 并重启**。仅在你有权处置的设备上运行；不要在他人设备、生产设备或含未备份数据的设备上运行。
- 发布触发程序是因为它们是"机制是否成立"这一判定的唯一硬证据；若你重跑，请自行承担设备风险。
- 发现本项目中任何**可用于真实攻击且有实际危害**的遗漏，请开 issue 而不是直接扩散。

---

## 何时应重开

出现任一条即须重评（详见 `HANDOVER.md` §7）：

1. 出现面向 4.9 / arm64 **ticket spinlock** 的 UAF 原语研究 → binder 线可直接接上（靶点、pre-fix 证据、堆条件已备）。
2. 出现能把用户数据写到 **`[-0x288, -0x240)`** 的新 syscall / 驱动 ioctl → GhostLock 线可直接接上。
3. 设备 **SPL 或内核构建变化** → 帧几何、binder 形态、全部符号偏移同时失效，须整体重跑（**故建议关闭 OTA**）。
4. 取得 **pstore / dmesg / last_kmsg** 任一 → 可定位 panic 精确点，判断是否为 vendor 差异。
5. GhostLock 上游出现**非栈复用**的利用路线。

---

## 致谢

本项目的分析大量依赖以下公开工作：

- [`marin-m/vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) —— 本项目的转折点，把"符号不可用"变成可解。
- [`NebuSec/CyberMeowfia`](https://github.com/NebuSec/CyberMeowfia) —— CVE-2026-43499 的原始研究与 x86 链。
- `JoinChang/ghostlock-oneplus`、`mobilehackinglab/ghostlock-a17` —— arm64 移植与标定旋钮（`PSELECT_SHIFT` / `KPHYS` / `KIMAGE_TEXT_BASE`）。
- `0xkol`，《Racing Against the Lock》—— CVE-2022-20421 的论文级分析。
- Google Project Zero —— CVE-2023-33107 的 RCA（`src_ref/projectzero_33107_rca.md`）。
- Linux 内核 v4.9 源码（GPLv2）—— 全部结构体布局与行号引用的基准。

---

## English summary

**A documented negative result.** On an OPPO K3 (`PCGM00`, SDM710, kernel `4.9.227`, SPL `2022-04-05`, locked bootloader, shell-only access), five candidate exploit surfaces were evaluated for a temporary-root path. None is viable, and each one stops at a *nameable* gap rather than an unexplained crash:

- **KGSL `CVE-2023-33107`** — pre-fix in source, but `BUG_ON(!suppress_map_failures)` makes "reaching the bug" and "panicking" the same event. No intermediate state exists.
- **GhostLock `CVE-2026-43499`** — the vulnerability is real and deterministically reachable (`-EDEADLK`, 10+ reproductions), and the repointing primitive was positively proven with a live-frame control. What is missing is a **stack-overwrite carrier**: the `rt_mutex_waiter` sits at `-0x288`, and none of 397 syscall entries can reach it (eligible window is 54 bytes wide; 0 hits, 66 near-misses).
- **binder `CVE-2023-20938`** — not introduced in this build (`off_end_offset` sits between `44d8047f1d87` and `32e9f56a96d8`).
- **binder `CVE-2022-20421`** — pre-fix, but this device uses a **ticket spinlock**, so the public qspinlock-based primitive degrades to "add `0x00010001` to a 4-byte word whose halves must be equal".
- **FastRPC `CVE-2023-33063`** — doubly closed for shell: `O_RDWR` denied by SELinux, and all seven implemented ioctls return `EPERM` on a read-only fd.

The write-up keeps the full evidence chain, the quantifiable gates, the reusable tooling, and — deliberately — **17 previously "certain" conclusions that were later falsified by this project's own experiments**.

Start with [`HANDOVER.md`](HANDOVER.md).

---

## License

- 代码（`tools/`）：**MIT**，见 [`LICENSE`](LICENSE)。
- 文档（`HANDOVER.md`、`README.md`、`docs_archive/`）：**CC BY 4.0**。
- `src_ref/` 内的内核源码与补丁：保留原始许可（GPLv2 及其对应条款）。

分范围的完整说明见 [`NOTICE.md`](NOTICE.md)。
