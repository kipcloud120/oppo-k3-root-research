# GhostLock 载体扫描复核（响应 2026-11-17 审核意见）

- 触发：审核意见第二条指出 `tools/gl_carrier_scan.py` 的 `seen` 以函数名为唯一键、全局共享，
  丢失不同调用路径的累计栈帧上下文；且深度固定 3、拷贝原语只认三组前缀，认为"397/0"证明力被高估。
- 复核日期：2026-11-17
- 性质：**纯静态复核**，未上机、未触发内核、未改设备。

## 1. 结论（重要：结论发生变化）

**审核意见成立。原版"397 入口 / 0 命中"是漏报结果，不能支撑"所有 syscall 路线都无栈覆盖载体"的结论。**
修正判重并补齐拷贝原语后，**发现 3 条满足几何判据的栈覆盖候选**，GhostLock 面需从"判死(no-go)"
**降级为"载体候选已找到、可利用性待验证"**。这不等于已可提权，但原 no-go 的一个支柱已被推翻。

| 判定项 | 原结论 | 复核后 |
|---|---|---|
| `seen` 判重 | 无问题 | **有漏报**：18,691 次跳过中 18,074 次是不同累计帧上下文 |
| 397/0/66 的证明力 | 穷尽证明 | **不成立**：近失配 66→112（仅修正判重）→120（补原语）|
| 栈覆盖载体 | 0 个 | **3 个**（xattr 族，size=256，经 `strncpy_from_user` 写栈）|
| GhostLock 面 | 不可利用（no-go）| **载体候选已找到，可利用性待验证** |

## 2. 三个问题逐一核实

### 2.1 `seen` 函数名判重（成立，影响巨大）

原版第 120/123-125 行：`seen` 是全局 set，`walk()` 开头 `if name in seen: return`，
只以函数名为键。修正为 `(name, frames)` 后重跑：
- 原口径跳过 18,691 次，其中 **18,074 次是不同累计栈帧上下文**（约 96.7%）；
- 近失配从 66 增至 112——出现了原版看不到的上下文（`sock_set_timeout` d-buf=0x288、
  `sock_getsockopt`=0x2a8 等）。

### 2.2 深度固定 3（限制确认）

`MAX_DEPTH=3` 是硬上限，非完整路径枚举。本轮保持 3 未改（先隔离变量）；即便如此已发现候选，
说明原版结论在限定深度内都不可靠。深度>3 的覆盖属已知未闭合项。

### 2.3 拷贝原语遗漏（成立，直接导致漏报）

从 `vmlinux.elf` 符号表枚举出 110 个拷贝相关符号，原版只认 3 组前缀，**遗漏**：
`strncpy_from_user`、`strncpy_from_unsafe`、`iov_iter_copy_from_user_atomic`、
`kfifo_copy_from_user`、`csum_partial_copy_from_user`、`__arch_copy_in_user`、`kgsl_ioctl_copy_in` 等。

补入 `strncpy_from_user` 后，**从 0 命中变为 4 命中**（去重后 3 条独立路径）。

## 3. 新发现的栈覆盖候选（核心证据）

反汇编确认：`getxattr`/`setxattr` 中的调用形态为 `add x0, sp, #8; mov w2, #0x100; bl strncpy_from_user`
——用户可控字符串写入**栈上 `sp+8`,长度上限 256 字节**。逐帧路径（无别名重复计帧）：

| 调用路径 | 累计帧 | 缓冲绝对位置 | 覆盖区间 | waiter 在缓冲内偏移 | 判据 |
|---|---|---|---|---|---|
| `SyS_fgetxattr→getxattr` | 0x190 | -0x298 | [-0x298, -0x198] | **0x10** | ✅ |
| `SyS_getxattr→getxattr` | 0x1c0 | -0x2c8 | [-0x2c8, -0x1c8] | 0x40 | ✅ |
| `SyS_setxattr→path_setxattr→setxattr` | 0x1e0 | -0x2e8 | [-0x2e8, -0x1e8] | 0x60 | ✅ |

waiter 为 72 字节(fake waiter 需 `task`/`lock`/`prio` 三字段在偏移 0x30/0x38/0x40)。
`fgetxattr` 路径起点偏移 0x10 ≤ 约束 54 字节，三字段全部落在 256 字节可控区内。

**为什么原版漏掉**：`strncpy_from_user` 不在 `COPY_PREFIX` 中，且 `getxattr` 会经多条入口
(`SyS_getxattr`/`SyS_fgetxattr`/`SyS_lgetxattr`)到达——按函数名判重使部分入口的上下文被跳过。

## 4. 仍未知 / 不构成"已可利用"的部分

1. **栈重生时机**：候选要求 W 线程在 futex wait 超时早退后、以同一内核栈进入 xattr syscall，
   使新栈帧复用旧 waiter 槽。此路径未在实机验证（HANDOVER 触发构造 §5.2.3 的 W 出口已确认
   `handle_early_requeue_pi_wakeup()` 不清 `pi_blocked_on`，但 xattr 复用是新增假设）。
2. **NUL 截断**：`strncpy_from_user` 遇 NUL 停止；fake waiter 的指针字段含 0 字节，
   能否构造出通过链走查校验的 `task`/`lock`/`prio` 值未经证实。
3. **栈槽内核覆写**：xattr 进入后内核自身会在该栈区写局部量，是否覆盖写入的 fake waiter 未知。
4. **深度>3** 未穷尽。

⇒ 这四条是"待验证"，不是"已排除"。审核意见的正确结论是"证据不足"，本复核同样不宣称"已可利用"。

## 5. 建议（可证伪，按优先级）

1. **更新 HANDOVER §5.2**：把"无栈覆盖载体、不可利用"改为"公开 select/pselect 路线不成立，
   但修正扫描后发现 xattr 栈覆盖候选，可利用性待验证"；§7 增重开条件：xattr 栈覆盖候选的
   栈重生 + fake waiter 构造验证。
2. **受控实验（需用户授权）**：W 线程 wait 超时后调用 `fgetxattr` 写入受控值，观察是否能影响
   后续链走查；判据须先登记（遵守 HANDOVER §11 运营约定）。
3. 若实验否证（NUL 截断/栈覆写/时机任一阻断），再恢复 no-go，但理由必须更新为具体阻断，
   不能再用"397/0 穷尽证明"。

## 6. 工具

- 原版：`tools/gl_carrier_scan.py`（保留，作为历史基线）
- 修正版：`tools/gl_carrier_rescan.py`（`--mode context` 按 (name,frames) 判重；`--copy-extra` 扩原语）
- 复核命令：`python tools/gl_carrier_rescan.py --mode context --copy-extra strncpy_from_user ...`
