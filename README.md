# OPPO K3 临时 ROOT 可行性研究

> **一份负结果、一次突破、以及一条重开的路径**：在不解 BL 的前提下，对一台 OPPO K3（`PCGM00` / SDM710 / 内核 `4.9.227` / SPL `2022-04-05`）评估了五个内核候选面与多条服务面线索。四个内核面判定不可达；Wi-Fi 私有事务面已打通——从 shell 可让 root 服务以 `uid=0` 执行任意命令（2026-11-18，两次复现），但处于 SELinux 域限制内，**是"受限 root 命令执行"，尚非可用 root**。
>
> **v3.0（2026-11-19）新增**：外部审核意见 v007 指向一个同类参考项目后，我们重开了此前"冻结"的 GhostLock 路径——真机实测证明 **futex 哈希桶时序侧信道在本机可用（110× 信号）**，端到端可得 mm_struct 地址 / KASLR slide。**但可用 root 判定不变**：侧信道给出的地址类型填不进 GhostLock 的 fake waiter，核心缺口从"没有地址"精确化为"地址类型不对 + 缺内核堆喷原语"。这是**研究路径重开，不是结论翻转为 go**。

| | |
|---|---|
| 目标设备 | OPPO K3 `PCGM00`（`OP4679`，`sdm710`），Android 11，内核 `4.9.227-perf+`（clang 10.0.7，2025-03 构建） |
| 安全补丁 | `2022-04-05` |
| 启动状态 | BL 锁定、AVB `green`、dm-verity `enforcing`、A-only（v3 实测复核一致，无 OTA） |
| 可用入口 | `uid=2000(shell)` + `u:r:shell:s0`，SELinux Enforcing，`Seccomp: 0` |
| **总体判定** | **受限 root 已达成，可用 root / 持久 ROOT 仍为 NO-GO。** 但 **GhostLock 研究路径已于 v3 重开**（侧信道实测可用），当前缺口为地址类型 ②/③（见下） |
| 设备终态 | 未刷写、未解锁、未改分区、未装持久化文件；`/data/local/tmp` 已清空；累计 5 次内核重启（均前期实验，v3 实测零重启） |

---

## 当前状态一览（v3）

| 面 | 机制 | 卡点 / v3 状态 |
|---|---|---|
| **GhostLock** `CVE-2026-43499` | 成立（`-EDEADLK` 10+ 次复现），栈载体已闭合（3 条 xattr 候选） | **v3 重开**：futex 侧信道真机可用，① 类地址（mm_struct/slide）可得；**缺 ② 可控 rt_mutex 堆地址 / ③ W 线程栈基址** |
| KGSL `CVE-2023-33107` | 成立（源码 pre-fix） | 命中缺陷即 `BUG()` panic，无中间态 |
| binder `CVE-2023-20938` | 不成立（未引入） | — |
| binder `CVE-2022-20421` | pre-fix | ticket spinlock 使原语退化为常数加法 |
| FastRPC `CVE-2023-33063` | 面存在 | uid 0 域下更封闭（权限并集 ∅） |
| `/dev/diag` | 入口层无缺陷 | 55/55 拷贝点判界；DCI 子树未审，且依赖内核指针的利用被 ②/③ 缺口阻断 |
| **OPPO Wi-Fi 私有事务**（非内核） | **已利用** | `\n`/反引号绕过 11 字符黑名单 → `sh -c` 以 `uid=0` 执行（域受限）；缺口 = 域逃逸（§24 判无路径） |
| 私有 Binder / `system_server` / Wi-Fi 消费者 | 方法级否证 | 7/7 闭合、`system_server` 取句柄处断开、消费者三道门全封（§33–§37） |

**最终判定：[`CLOSURE.md`](CLOSURE.md)**（v3 分层判定）。完整证据链：**[`HANDOVER.md`](HANDOVER.md)**——新对话从 `HANDOVER_RESUME.md` 开始，再读 §38–§42（v3）。

---

## GhostLock 重开路径（v3 核心）

### 地址类型三档——缺的不是"任意地址"，而是特定类型

| 档 | 类型 | 本机状态 | 能否填 fake waiter 的 lock/rb |
|---|---|---|---|
| ① | mm_struct 线性地址 / KASLR slide / DPM 基址 | **真机可得**（侧信道 110× 信号） | ❌ 不够：lock 会被解引用（trylock 写 + owner/waiters 读 + `BUG_ON`），且缺堆喷把它兑现 |
| ② | 可控 rt_mutex 的堆地址（pi_state / skb 喷射页） | ❌ 无堆喷原语 | ✅ 能——参考项目 `fake_lock = payload_base + LOCK_OFF` 的成功路径 |
| ③ | W 线程内核栈基址（持有 stale waiter 者） | ❌ 无侧信道：futex key 不含栈地址；USENIX'25 栈侧信道依赖 VMAP_STACK，本机 `!VMAP_STACK` | ✅ 能（几何偏移已静态解决，缺的是拿栈基址的 oracle） |

**参考项目为何能成功**：`yijiacloud/GhostLock-OPPO-PCKM00` 用 KernelSnitch 泄露的 mm_struct 地址 + AF_UNIX skb 喷射，把 payload 落到内核堆的已知地址，`lock` 指向那处受控 rt_mutex——**从不需要栈地址**。K3 缺的正是那个 skb 堆喷原语，所以同样的 slide 无法兑现。

**重开判定**：GhostLock 作为活跃研究路径重开，当前阶段"① 已解决、②/③ 未解决"。**可用 root 判定不变**——②/③ 任一闭合前不构成提权。

### v3 关键证据

1. **方向 A（可移植性）**：`tools/ksnitch_local_check.py` 证明 KernelSnitch 的 jhash2 与本机逐字节兼容、全 8GB 唯一命中、0 误报、秒级成本。脚本可直接运行。
2. **方向 B（硬门槛）**：`artifacts_adb/WAITER_ADDRESS_ANALYSIS.md` 逐行证明 lock 被解引用、真正门槛是"可控 rt_mutex 内核地址"，futex key 不含栈地址。
3. **真机实测**：`live_probe/LIVE_PROBE_RESULT.md` 记录 `cntvct_el0` EL0 可读（19.2 MHz）与碰撞观测 110× 信号；零重启、临时文件清空。
4. **综合结论**：`DUAL_TRACK_RESULT.md`、`FEASIBILITY_v007.md`。

---

## 五个值得单独看的结果

1. **符号可用性**：项目早期"镜像重排、符号不可用"的判断是错的——真实原因是解析器把 kallsyms 偏移当 base-relative。`vmlinux-to-elf` 重建后 123,784 个符号可用（§1.3 / `firmware_F16/README.md`）。教训：先怀疑工具，而不是目标。
2. **GhostLock 的自我推翻链**：第一版"397 入口 0 载体"判死 → 外部审核指出扫描器用函数名判重漏了 18,074 个栈上下文、且漏 `strncpy_from_user` → 修正后找到 3 条 xattr 栈覆盖候选 → 静态收束证明栈复用是几何确定、NUL 不阻断 → 缺口从"载体"变成"地址" → **v3 再把"地址"细分为三档并真机验证 ① 可得**（§5.2 / §15 / §38–§42）。
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
FEASIBILITY_v007.md         # v007 方案评估 + 可行性评估
DUAL_TRACK_RESULT.md        # 双方向预研综合结论
tools/
├── kfn.py / klen_scan.py / kcopy.py        # vmlinux 反汇编与拷贝点判界
├── cil_policy.py / cil_selftest.py         # CIL 求值引擎（28 用例）
├── ksnitch_local_check.py / .md            # 方向A：KernelSnitch 本机闭环验证
├── gl_frame_calc.py / gl_carrier_rescan.py / gl_nul_analysis.py   # GhostLock 几何/NUL
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

python tools/ksnitch_local_check.py                     # v3 方向A：哈希闭环验证（全部 PASS）
python tools/gl_frame_calc.py                           # 帧几何 → waiter 绝对偏移 -0x288
python tools/gl_carrier_rescan.py --mode context --copy-extra strncpy_from_user  # 3 条 xattr 候选
python tools/gl_nul_analysis.py                         # NUL 语义 / 72B 字节映射
python tools/cil_selftest.py                            # CIL 28 用例
python tools/kfn.py --list 'futex|ashmem|configfs|nfulnl'  # 符号查询
```

真机只读探针（**纯用户态 futex 计时，不会 panic**；GhostLock 端到端 PoC 不提供）：

```bash
zig cc -target aarch64-linux-musl -O2 -static -o timer_probe live_probe/timer_probe.c
zig cc -target aarch64-linux-musl -O2 -static -pthread -o collision_probe live_probe/collision_probe.c
export MSYS_NO_PATHCONV=1                 # Git Bash 必须关闭路径转换
adb push live_probe/collision_probe /data/local/tmp/
adb shell '/data/local/tmp/collision_probe'
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

## 审阅须知（v3）

外部复核者请按以下靶面攻击，**只接受可复算的反例**：

1. **② 堆路径**：是否存在 K3 上"把可控数据写到已知内核地址"的原语？这是把 slide 兑现为受控 rt_mutex 的前提（参考项目靠 AF_UNIX skb 喷射，K3 无）。
2. **③ 栈路径**：4.9 / `!VMAP_STACK` 下是否存在针对 order-2 连续页栈地址的泄露面？futex 哈希侧信道已证不行，USENIX'25 TLB 侧信道依赖 VMAP_STACK（本机关闭）。
3. **方向 A 的唯一性**：`N=4` 误报期望 ~0.65 属边缘，建议复核 `tools/ksnitch_local_check.py` 的误报模型与 hsz=1024 单档判定。
4. **侧信道实测能否放大**：本机 110× 信号是否足以支撑"在真实噪声下稳定找到碰撞"？探针用 256 线程，参考项目用 4096。
5. **地址三档的完备性**：是否存在第 ④ 类可用地址（既非栈、非 pi_state 堆、非仅 slide）？

| 不构成推翻 | 构成推翻 |
|---|---|
| "侧信道能拿地址了，所以能 root 了" | 给出 ② 或 ③ 类地址的可复算获取路径，并说明如何填进 fake waiter 的 lock/rb |
| "GhostLock 历史上有漏洞" | 指明本机某字段越界点，给出可复算反汇编地址 |
| "可能还有别的面" | 指名该面并给出策略/rc/二进制中的存在证据 |
| 用其它 SPL/内核外推 | 指明本机 SPL `2022-04-05` / 内核 `4.9.227-perf+` 下同一路径的差异 |

---

## 何时应重开 / 已重开

1. **【v3 已重开】GhostLock**：理由不是"任一地址泄露"，而是**侧信道真机可用**（① 类地址可得）。下一步闭合 ② 或 ③（见审阅须知 1–2）。**注意：路径重开 ≠ 已 root。**
2. binder 线：出现面向 4.9 / ticket spinlock 的 UAF 原语研究 → 靶点、pre-fix 证据、堆条件已备。
3. SPL / 内核构建变化 → 全部偏移/形态/策略作废，须整体重跑（故建议关闭 OTA）。
4. 取得 pstore / dmesg / last_kmsg 任一 → 可定位 panic 精确点。
5. Wi-Fi 面：**已打通**（受限 root）；主缺口 = SELinux 域逃逸，§24 判无路径。
6. 其余各面的重开条件见 `HANDOVER.md` §7 与 `CLOSURE.md`。

---

## 致谢

分析依赖以下公开工作：`marin-m/vmlinux-to-elf`（符号重建转折点）、`NebuSec/CyberMeowfia`（CVE-2026-43499 原始研究）、`yijiacloud/GhostLock-OPPO-PCKM00`（v3 侧信道参考）、`JoinChang/ghostlock-oneplus` / `mobilehackinglab/ghostlock-a17`（arm64 移植）、`0xkol`（CVE-2022-20421 论文）、Google Project Zero（CVE-2023-33107 RCA）、Linux v4.9 源码（GPLv2，结构体基准）、NDSS'25 KernelSnitch 与 USENIX'25 TLB 侧信道论文（v3 侧信道分析）。

---

## English summary

**A negative result, one breakthrough, and a reopened path.** On an OPPO K3 (`PCGM00`, SDM710, kernel `4.9.227`, SPL `2022-04-05`, locked bootloader, shell-only), five kernel surfaces and several service surfaces were evaluated. Four kernel surfaces are unreachable; the Wi-Fi private transaction **worked** — a shell-reachable root service executes attacker strings via `sh -c` as `uid=0` (twice reproduced), though confined to a MAC-restricted domain, so this is **confined root command execution, not a usable root**.

**v3 (2026-11-19)**: after external review pointed to a sibling-device reference project, the previously frozen **GhostLock** path was **reopened**. A live probe proved the futex hash-bucket timing side-channel works on this device (110× signal), making mm_struct address / KASLR slide end-to-end obtainable. **But the usable-root verdict is unchanged**: the obtained address class (①) cannot fill the fake waiter's `lock`/rb fields; the real gap is now precisely **address type** — a controllable `rt_mutex` kernel address (②, heap-spray) or the W-thread kernel stack base (③) — neither of which this device currently provides. This is a **research-path reopening, not a verdict flip**.

The write-up keeps the full evidence chain, the quantifiable gates, the reusable tooling, and deliberately **25+ previously "certain" conclusions later falsified** by this project's own experiments or external review. Start with [`HANDOVER_RESUME.md`](HANDOVER_RESUME.md), then [`HANDOVER.md`](HANDOVER.md) §38–§42.

---

## License

- 代码（`tools/`、`live_probe/`）：**MIT**，见 [`LICENSE`](LICENSE)。
- 文档（`HANDOVER.md`、`README.md`、`docs_archive/`）：**CC BY 4.0**。
- `src_ref/` 内的内核源码与补丁：保留原始许可（GPLv2 及其对应条款）。

分范围的完整说明见 [`NOTICE.md`](NOTICE.md)。
