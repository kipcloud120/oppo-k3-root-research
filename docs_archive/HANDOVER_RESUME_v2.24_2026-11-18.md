# 接手摘要（2026-11-18 18:45，v2.24+）

> 一页式入口。完整证据在 `HANDOVER.md` §1–§37、一页判定在 `CLOSURE.md`、审阅入口在 `README.md`「审阅须知（v2.24）」。

## 1. 当前结论（三层，不可混用）

| 层次 | 状态 |
|---|---|
| Root UID 命令执行 | **已达成**：shell → tx10070 → `\n`/反引号绕过黑名单 → `sh -c` 以 `uid=0`、域 `u:r:oplus_wifi_service:s0` 执行（§23，两次复现） |
| 可用 root | **未达成**：该域读不到 `/data/system`、`selinuxfs`、`proc_security`；无可执行写面、无 `mount`、无域转换（§24，v2.24+ 重算仍为 0） |
| 持久 ROOT | **未达成**，且按约定不做任何持久化写入 |

**总体**：BL 锁定条件下 NO-GO 维持。四条方向的断点：SELinux 域、内核能力集（SELinux 侧反而放行）、无内核地址泄露、"触发"步失败（不是"通道"缺失）。

## 2. v2.24+ 本轮做了什么（按章节）

| 节 | 内容 | 结果 |
|---|---|---|
| §33 | 重写 CIL 求值（`tools/cil_policy.py`，28 用例）并回归历史结论 | 两个独立缺陷：`not` 语义 + 版本名合并；**antirootdialog 否证作废**（策略可达）；`module_load` 的墙是内核签名 |
| §34 | 域级重算 + G-A1 闭合 + 配置依赖 | 四条核心否证维持；**§26 前提作废**（消费者有 `system_server` binder，断点改为"无法触发"）；antirootdialog 实现为单 `int` 事务、无 sink ⇒ 7/7 以"无能力"闭合 |
| §35 | 私有服务面重测 | shell 可 `find` **228/235** 服务、**36/36** OPPO 私有服务；`binder:call` 也通铺 ⇒ 门槛移到方法级鉴权；44 行初筛无新路径 |
| §36 | G-P1 闭合 | `power_monitor` / `usage` 的 Stub 无鉴权但可控串未流向 sink；`Runtime` 是假阳性、`SystemProperties.set` 在 `dump()` |
| §37 | 三个 native 服务补审 | hans 有 netlink `sendto` 但调用链未闭合（保留观察）；horae 的 `getCallingUid` 返回值被丢弃；oiface 无可控路径 |

**重要口径变化**（引用旧结论时必须更正）：

- ❌ "shell 对 anti_root_dialog 零权限 / 不可达" → ✅ 策略可达，但实现无能力。
- ❌ "模块加载被策略断链" → ✅ 策略放行、能力具备，墙是 `CONFIG_MODULE_SIG_FORCE=y`（`CLOSURE.md` §8 配置依赖）。
- ❌ "读可写路径的域都没有 `system_server` binder" → ✅ hostapd/supplicant/fstman 都有；结论靠"无法触发"维持。
- ❌ "旧脚本算出的 89 属性/307 allow 是本域基线" → ✅ 新基线 **775/347**；旧数字可由 A 口径逐位复算。

## 3. 下一步（按性价比）

1. **hans netlink 调用链**（§37 唯一"差一步"）：找到 `0x416c` 的调用点，证明参数来自 Parcel 并到达 `sendto` 载荷。需要完整反编译/符号物料。
2. **`diag` DCI 解析子树**（G1）：需同源 `msm-4.9` 内核源码；与 GhostLock 撞同一面"无地址泄露"的墙。
3. **OTA 后全量重算**：与"关闭 OTA"的建议冲突；若发生则 §7 第 3 条触发，全部偏移/形态/策略作废。

**不建议**：重复已验证的注入实验、盲试 `service call`、再用旧 `sepolicy_domain_audit.py`（v2.23）算权限。

## 4. 工具入口

```bash
python tools/cil_selftest.py                 # 28/28 语义自检
python tools/sepolicy_domain_audit.py --domain oplus_wifi_service --top 20
python tools/sepolicy_domain_audit.py --query shell,anti_root_dialog_service,service_manager
python tools/sepolicy_regression.py          # A/B/C 三口径回归
python tools/conclusion_recheck.py           # 否证重算
python tools/svc_registrar_index.py --any-string   # 服务名 → 注册点
python tools/svc_impl_triage.py              # 鉴权/sink 初筛
python tools/native_svc_audit.py <elf> --xref getCallingUid --context 12
```

## 5. 运营约定

- 设备 `PCGM00_11_F.16` 未刷写、未解锁、未改分区、未装持久化文件；`/data/local/tmp` 已清空；累计 5 次内核重启（均前期竞态实验）；本轮仅只读探针。
- **建议关闭 OTA**。
- 厂商二进制/镜像不入库（见 `.gitignore`）；报告与脚本可入库。
- 新对话从 `HANDOVER.md` §17 接手清单开始，再读 §33–§37；本文件只是一页索引。
