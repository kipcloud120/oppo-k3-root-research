# 接手摘要（v3.0 · 2026-11-19 · GhostLock 重开）

> 一页式入口。完整证据在 `HANDOVER.md`（v3 章节 §38–§42 + 历史 §1–§37）；分层判定在 `CLOSURE.md`；审阅入口在 `README.md`。
> 历史版本（v2.24+，2026-11-18）已归档到 `docs_archive/HANDOVER_v2.24_2026-11-18_full.md` 等，数值不可引用。

## 1. 当前结论（四层，不可混用）

| 层次 | 状态 |
|---|---|
| Wi-Fi 域内 Root UID 命令执行 | **已达成**（2026-11-18，`\n`/反引号绕过黑名单 → `sh -c` 以 `uid=0`、域 `u:r:oplus_wifi_service:s0` 执行，两次复现，§23） |
| 可用 root（脱离 SELinux 域） | **未达成**；域逃逸静态审计无路径（§24），FastRPC 在 uid 0 域下反而更封闭（§32） |
| 持久 ROOT | **未达成**，按约定不做任何持久化写入 |
| **GhostLock 内核地址泄露** | **v3 新进展：futex 哈希侧信道真机实测可用**（110× 信号），端到端可得 mm_struct 线性地址 / KASLR slide；**但拿不到 fake waiter 需要的地址类型** |

**总体**：BL 锁定条件下可用 ROOT 仍为 NO-GO。**但 GhostLock 从"冻结/收口"重开为活跃研究路径**——因为其此前的唯一阻断理由"无内核地址泄露"已被部分推翻（侧信道实测可用）。这是**研究路径重开，不是结论翻转为 go**：可用 root 仍未达成。

## 2. v3 本轮做了什么（2026-11-19）

| 节 | 内容 | 结果 |
|---|---|---|
| §38 | 审核意见 v007 方案评估 | 方向对（补地址泄露）但入口排序错——boot_id 是后置技术 |
| §39 | 可行性评估（符号级） | 三条路线逐项判定；boot_id/ashmem 前提缺失，KernelSnitch 条件成立 |
| §40 | 双方向预研 | 方向A：KernelSnitch 4.14→4.9 哈希逐字节兼容、采样可控（脚本 `tools/ksnitch_local_check.py`）；方向B：fake waiter 硬门槛精确化为"可控 rt_mutex 内核地址"（`artifacts_adb/WAITER_ADDRESS_ANALYSIS.md`） |
| §41 | **真机实测（用户授权）** | `cntvct_el0` EL0 可读（19.2 MHz）；futex 碰撞侧信道 **110× 信号**、命中真实碰撞——**KernelSnitch 全链端到端可行**（`live_probe/LIVE_PROBE_RESULT.md`） |
| §42 | 重开判定 | 地址按类型分三档：(① mm_struct/slide 可得；② 可控 rt_mutex 堆地址 无堆喷原语；③ W 线程栈基址 无侧信道)。GhostLock 需要的 ②/③ 仍缺 ⇒ 路径重开但缺口明确 |

**关键口径变化**（引用旧结论时必须更正）：

- ❌ "GhostLock 阻断在'无内核地址泄露'" → ✅ **部分作废**：侧信道能泄露 ① 类地址（mm_struct/slide）；但 fake waiter 需要的 ②/③ 类仍无泄露。
- ❌ "§7 第2条(a) 任一可用内核地址泄露即重开" → ✅ **需按类型细分**：① 类不足，②/③ 类才算触发。
- ❌ "KernelSnitch 4.14→4.9 需整体重做、输出精度未知" → ✅ **推翻**：哈希逐字节兼容、采样秒级、真机成立。
- ❌ "VMAP_STACK 无关" → ✅ **本机实测 `!VMAP_STACK`**，栈在线性映射区，但 futex key 不含栈地址 ⇒ 仍够不着栈。

## 3. 下一步（按性价比）

1. **[最高优先，纯离线]** 找 K3 上"把可控数据写到已知内核地址"的原语（走 ② 堆路径的前提）——这是把 slide 兑现为可用地址的本质缺口。
2. **[高优先，纯离线]** 调研 4.9 / `!VMAP_STACK` 下针对 order-2 连续页栈地址（③）的泄露面；futex 哈希侧信道已证不行。
3. **[可证伪条件]** 出现"以内核栈地址（thread_info / task_struct.stack）为键、用户可观测"的新侧信道 ⇒ 直接闭合 ③。
4. **[不做]** boot_id / ashmem 后置实现（前置写原语不存在）；GhostLock 端到端 PoC（参考项目自报 ~97% panic，且本机 panic 文本不可读）。

## 4. 工具与物料入口

```bash
python tools/ksnitch_local_check.py              # 方向A：KernelSnitch 本机闭环验证（全部断言 PASS）
python tools/kfn.py --list 'futex|ashmem|configfs|nfulnl'   # 符号查询（只认 vmlinux.elf）
# 真机只读探针（源码在 live_probe/，二进制不入库）：
#   zig cc -target aarch64-linux-musl -O2 -static -o timer_probe live_probe/timer_probe.c
#   MSYS_NO_PATHCONV=1 adb push ... /data/local/tmp/   # Git Bash 必须关路径转换
```

## 5. 运营约定

- 设备 `PCGM00_11_F.16` 未刷写、未解锁、未改分区、未装持久化文件；真机实测**零重启**；`/data/local/tmp` 已清空。
- **建议关闭 OTA**：SPL / 内核构建变化会使全部偏移、形态、策略判定作废。
- 厂商二进制/镜像、第三方完整利用代码不入库（见 `.gitignore`）；报告与脚本可入库。
- 新对话从本文件开始 → `HANDOVER.md` §42（重开判定）→ §38–§41（本轮全部证据）。
