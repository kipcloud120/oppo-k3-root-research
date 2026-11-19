# 真机实测结果：futex 哈希桶时序侧信道（2026-11-19，用户授权）

> 用户明确授权真机实测。**安全边界**：只跑 KernelSnitch 第①步（用户态 futex 计时），
> 未触发 GhostLock UAF、未写内核、未做持久化、未刷机、未碰 `/proc`。
> 设备 `PCGM00_11_F.16`（序列号已脱敏）。全程 `/data/local/tmp` 临时文件，用后已清空。

---

## 0. 前置基线核验（只读，确认无 OTA 漂移）

| 项 | 实测值 | 与 F.16 基线 |
|---|---|---|
| SPL | `2022-04-05` | ✅ 一致 |
| 内核 | `4.9.227-perf+`，clang 10.0.7，2025-03-26 构建 | ✅ 一致 |
| `ro.hardware` | `qcom` | ✅ 一致 |
| 指纹 | `OPPO/PCGM00/OP4679:11/RKQ1.201217.002/1704167642389:user/release-keys` | ✅ 一致 |
| 身份 / SELinux | `uid=2000(shell)` / `Enforcing` | ✅ 一致 |

⇒ §7 第 3 条（OTA 触发作废）**未触发**，全部既有偏移/形态判定仍有效。

---

## 1. 实测一：计时原语（timer_probe）

**硬前提**：KernelSnitch 阶段①用 `mrs cntvct_el0` 计时，需确认 EL0 可读。

| 项 | 实测值 |
|---|---|
| `cntfrq_el0` | `19,200,000 Hz`（≈52 ns/tick） |
| `cntvct_el0` EL0 可读 | **YES**（第一条 `mrs` 未 SIGILL） |
| back-to-back 读差 | 9 tick ≈ 365 ns |
| `clock_gettime` 差 | 365 ns（vDSO 基于同一计数器） |

⇒ **高精度计时在用户态可用**。此前 `CONFIG_ARM_ARCH_TIMER_VCT_ACCESS not set` 引发的疑虑**实测排除**——该 config 不等于 `CNTKCTL_EL1.EL0VCTEN`，arm64 默认开放 EL0 读。

---

## 2. 实测二：futex 哈希桶碰撞观测（collision_probe）

**方法**（PCKM00 `__increase`+`__measure` 的用户态缩小版）：
- `mmap` 16 MB futex 区；目标 futex 在 offset 128；
- 起 **256 个** `FUTEX_WAIT_PRIVATE` 线程（带 2s 超时）堆积目标桶（PCKM00 用 4096，本探针缩小）；
- 对目标 + 512 个候选地址做 `FUTEX_WAKE_PRIVATE`，用 `cntvct_el0` 计时，取 32 次中 8 个最快平均；
- 判据：耗时 > 10× 基线即判同桶碰撞。

**结果**：

| 项 | 值 |
|---|---|
| 空桶基线 | 9 tick |
| 堆积目标桶 | **992 tick（110× 基线）** |
| 512 候选中命中碰撞 | **1 个**（`0x78675fd080`，4224 tick） |
| 判定 | **futex 哈希桶时序侧信道 WORKS** |

⇒ KernelSnitch 阶段①的核心 oracle——"用计时识别与已知堆积桶同哈希的 futex 用户地址"——**在本机真机成立**。

---

## 3. 综合判读

| 环节 | 此前状态 | 实测后 |
|---|---|---|
| 计时原语 EL0 可读 | 存疑（VCT_ACCESS） | ✅ 确认可用（19.2 MHz） |
| KernelSnitch 阶段①（碰撞观测） | 未实测 | ✅ **真机成立**（110× 信号） |
| KernelSnitch 阶段②（离线 bruteforce） | 方向 A 脚本证闭环 | ✅ 已证（0 误报、秒级） |
| → 获得 mm_struct 线性地址 | 算法可得 | ✅ 真机 oracle（G1）+ 离线恢复（G2 on 合成目标）**分别**验证 |

**这是本轮实测的实质进展**：方向 A 的 ① 类地址（mm_struct 线性地址）从"算法可得、待实测"升级为**真机可行**。

> ⚠️ **v008 更正（权威见 `FEASIBILITY_v008.md` §2）**：本次真机只验证了 G1（oracle：110×），G2（唯一性）是离线在合成目标上验证算法自洽，**二者未在真机串成对未知 mm 的完整恢复**；KASLR slide（R3）未获取——它由 `kimage_voffset` 独立承载，不能由 mm 线性地址反推。原"全链端到端可行"表述偏强，已降级。

**但对 GhostLock 的净影响不变**：方向 B 已证 fake waiter 需要的是 ②（可控 rt_mutex 堆地址）或 ③（W 线程栈基址），KernelSnitch 给的 ① 填不进去，且 K3 无堆喷原语兑现 slide。**实测成功不改变"重开条件未触发"的判定**——它只是把"我们缺的那块"从"不确定能不能拿到 ①"进一步锁定为"① 能拿到，但需要的根本不是 ①"。

---

## 4. 设备终态（运营约定）

| 项 | 值 |
|---|---|
| uptime | 推送前 `161773.71` → 结束后 `161800.38`（+27s），**零重启** |
| 临时文件 | `/data/local/tmp/{timer_probe,collision_probe}` 已删除，`/data/local/tmp` 已清空 |
| 持久化改动 | **无** |
| 设备状态 | online |

---

## 5. 复用物料

- 源码：`live_probe/timer_probe.c`、`live_probe/collision_probe.c`（纯用户态、带安全边界注释）
- 工具链：`pip install ziglang`，`zig cc -target aarch64-linux-musl -O2 -static -pthread`
- 编译：`zig cc -target aarch64-linux-musl -O2 -static -o timer_probe live_probe/timer_probe.c`
- 推送注意：Git Bash 下须加 `MSYS_NO_PATHCONV=1`，否则 `/data/local/tmp` 被误转成本地路径。

---

## 6. 一句话

**真机实测确认 futex 哈希侧信道在本机可用（110× 信号），KernelSnitch 的观测（G1）真机成立、离线恢复（G2）算法自洽——但拿到的是 mm_struct 线性地址（非 slide），仍填不进 GhostLock 的 fake waiter。** 缺口性质不变：不是"拿不到地址"，而是"拿到的地址类型不对 + 缺堆喷原语"。（v008 更正：G1/G2 未串成真机端到端，R3 slide 未获取，见 `FEASIBILITY_v008.md`。）
