# 接手摘要（v12.2 + v13/v14 分诊收口：**非 sparse 释放链自洽、I4 上机证实、K2 达成；KGSL 主线阶段性关闭；外部 CVE 与 WLAN 输入面分诊完成，四层判定仍 NO-GO**，2026-11-20）

> 一页式入口。完整证据：`HANDOVER.md` §63（非 sparse 释放前提 + I4 上机，最新）+ §62（sparse 关判定）+ §61（v12-K1 生命周期）+ §60 + §58 + §57 + §56 + §55 + §53；**本轮三份分诊报告见 `docs_archive/` 的 `项目评审与下一步规划_v13`、`联网调研_高优先级突破方向_v14`、`CVE-2025-38352_E1形态复核`、`R0_覆盖台账`、`R1_WLAN非配置输入可达性矩阵`（均 2026-11-20）**。
> 分层判定 `CLOSURE.md`；审阅入口 `README.md`。

> **v13/v14 分诊收口（2026-11-20 下午，**纯离线、零上机，不改变四层判定**）**：
> ① **v13 评审**：维持 NO-GO；KGSL/GhostLock 冻结；下一轮主线从"继续找漏洞"改为"文档同步 + 可达性优先"，即 R0（交接口径）+ R1（WLAN 非配置输入可达性矩阵）。
> ② **v14 联网调研**：四个 CVE 候选中仅 `CVE-2025-38352`（POSIX CPU timers TOCTOU）值得登记；其余排除/降级。**任务 E1 已完成**：本机 `run_posix_cpu_timers` 无 `exit_state` 门、`posix_cpu_timer_del` lock-fail 不读 `firing`、无 task_work 缓解 ⇒ pre-fix 结构同构证实，但动态可达性未证、高 panic + 缺 `.text` slide ⇒ **不升级授权、动态默认禁止**。
> ③ **R0 覆盖台账 + 交接口径修正已完成**（`docs_archive/R0_覆盖台账`）；**R1 WLAN 非配置输入可达性矩阵已完成**（`docs_archive/R1_WLAN非配置输入可达性矩阵`）：ioctl/FTM/cfg80211/日志/debugfs 五类面，仅 wifi uid0 域可达、shell 域仅经已终局的 Binder 私有事务，**无合格 R3 候选**。
> ④ 三份权威文档（`HANDOVER.md`/`HANDOVER_RESUME.md`/`CLOSURE.md`）**未改写历史正文**，仅增补本节与 §64 摘要；四层判定不变：**可用 root / 持久 ROOT 仍 NO-GO**。
>
> **v12.2 三句话**：
> ① **非 sparse 释放链自洽**：新增 I10–I12 三条全称不变量在本机 `vmlinux.elf` 全部成立——
>   `set_pend` 唯一赢家门、释放必 `idr_remove`+幂等 unmap gpuaddr、四释放分支共享 `pending_free` 且引用配对。
>   排除了三处"看似缺陷"：`put_gpuaddr` 双调用是幂等、命令不 get entry 引用是设计、四分支不是单点门错位（§63.2）。
> ② **I4 上机证实（判定型）**：`GPUOBJ_ALLOC`(4096)→FREE→再 FREE 同 id，第二次返回 `EINVAL(22)` ⇒
>   id 已撤销、无 double-free；`GPUMEM_FREE_ID` 交叉验证一致。`param` 阶段五分支全 EINVAL，证明分支解析正确。
>   全程未提交 GPU 命令、未 mmap、未构造悬空映射；`boot_id` 不变、`uptime` 连续 +24 s（§63.3/§63.5）。
> ③ **K2 达成、主线阶段性关闭**：K2「索引与生命周期」停止条件（无可达过期引用/错误状态转换）在本机非 sparse 面满足；
>   K3 并发动态测试因须制造悬空窗口、超出"不重启"边界而**登记不作**。四层判定不变：NO-GO。
>   除非出现新可达面（启用 sparse 的同 SPL 机型 / K3 并发新证据），不再投入 KGSL 生命周期。

## 0. 本轮送审要点（v12.2，对应 `HANDOVER.md` §63）

**一个正面结果（K2 达成）+ 三处"看似缺陷"排除**

| # | 结论 | 证据等级 |
|---|---|---|
| 1 | **I4（id 撤销）上机证实**：alloc→FREE→再 FREE 同 id，第二次 `EINVAL(22)`；`GPUMEM_FREE_ID` 交叉验证一致 ⇒ 无 double-free | 真机实测（`boot_id` 不变） |
| 2 | **非 sparse 释放链自洽**：I10（set_pend 唯一赢家）/ I11（id 撤销 + 幂等 unmap gpuaddr）/ I12（四分支共享 pending_free、引用配对）静态全成立 | 本机 `vmlinux.elf` 逐指令 |
| 3 | **三处排除**：`put_gpuaddr` 双调用幂等、命令不 get entry 引用是设计、四释放分支非单点门错位 | 反汇编（§63.2） |

**判定矩阵（可复算，§63.3）**

| 命令 | 实测 | 作用 |
|---|---|---|
| `GPUOBJ_FREE` flags=0 / on_timestamp / on_fence / bad_type（bad id） | 全 `EINVAL(22)` | 四分支解析正确、无异常 deref |
| `GPUOBJ_ALLOC`(4096) | `0`, id=1 | 对象真实创建 |
| `GPUOBJ_FREE` #1 / #2 同 id | `0` / **`EINVAL(22)`** | **I4 成立，无 double-free** |
| `GPUMEM_FREE_ID` 同 id | `EINVAL(22)` | 两条通用路径共享 idr |

**明确未覆盖（不要外推）**

- **K3 并发动态测试未做**：set_pend 原子性只静态确认；测竞态须制造悬空窗口 → 超出"不重启"边界，登记不作。
- KO-1（sparse）代码层缺陷仍为 latent（本机不可达，§62）；非 sparse 面本轮未发现新候选。
- 其余 vendor `.ko`（41 个模块只取回 `qca_cld3_wlan.ko`）。

**v12.1 送审要点（历史，§62）**

| # | 结论 | 证据等级 |
|---|---|---|
| 1 | KO-1 不可达 → 关闭：六个 sparse 入口同一门 `ENOTSUPP(524)` | 真机实测 |
| 2 | 门定位：`kgsl_device::flags` BIT(1) = `KGSL_FLAG_SPARSE` 未置位 | 六 handler 首三条指令一致 |
| 3 | 工具更正：`strerror(-ret)` 把失败全打成 `EPERM` | §62.3 |

**建议审核回答的问题（更新）**

1. 本轮已回答 v12.1 的第 2 问：非 sparse 面**不存在**对称的"释放前提缺失"（I10–I12 成立 + I4 上机证实）。
2. 仍未回答：K3 并发一致性（fence signal 与 free 竞态）——但受"不重启"硬约束，本环境无法安全测试，须另择条件。

---

## 1. 当前结论（四层，不可混用）

| 层次 | 状态 |
|---|---|
| Wi-Fi 域内 Root UID 命令执行 | **已达成**（2026-11-18，§23） |
| 可用 root（脱离 SELinux 域） | **未达成**（§24 / §32） |
| 持久 ROOT | **未达成**，按约定不做持久化写入 |
| GhostLock 地址缺口 | ① **闭合**（本次开机）；② **未闭合**（§50 时间流否证）；③ **已审接口范围内无可用 oracle**（§53/§60）。**v12 起冻结** |
| KGSL 生命周期（主线） | 所有权 **成立**（I1–I5，§61.5）；**KO-1 本机不可达已关闭（§62）**；**非 sparse 释放链自洽（I10–I12）、I4 上机证实（§63）** ⇒ K2 里程碑在本机可达面内达成，主线阶段性关闭；K3 并发登记不作 |

## 2. v12 三轮做了什么

| 轮 | 日期 | 性质 | 结果 |
|---|---|---|---|
| §61（v12-K1） | 2026-11-20 上午 | 纯离线 | 六态状态机 + 不变量 I1–I9；I1–I5 成立、I6 被违反（KO-1）；legacy 分派表全解（86 槽/37 入口） |
| §62（v12-K2） | 2026-11-20 上午 | 上机（判定型） | KO-1 **关闭**：六个 sparse 入口 `ENOTSUPP`；`boot_id` 不变、`uptime` 连续；探针已删 |
| §63（v12.2） | 2026-11-20 上午 | 离线 + 上机（判定型） | 非 sparse 释放链自洽（I10–I12），I4 上机证实（再 FREE = EINVAL，无 double-free）；K2 达成、主线阶段性关闭；`boot_id` 不变、探针已删 |

## 3. 下一步（v12.2 收口）

1. **[主线阶段性关闭]** KGSL 生命周期在本机非 sparse 可达面已收口（K2 达成）；仅在出现新可达面时重开：启用 sparse 的同 SPL 机型、或 K3 并发新证据。
2. **[登记不作]** K3 并发动态测试（须制造悬空窗口，超"不重启"边界）；sparse 子树（KO-1/C-2/C-3，本机不可达）；GhostLock ②/③；C1 的 `sscanf` 面；重载 `wlan`。
3. **[维持]** ROOT NO-GO；不做 GhostLock 端到端 PoC；**不重启设备**；建议关闭 OTA（SPL/内核变化会使全部偏移与判据作废）。

## 4. 工具与物料入口

```bash
# —— KGSL 生命周期（纯离线）——
python tools/kgsl_lifecycle.py                # 取/放点普查 + 机械可疑项
python tools/kgsl_lifecycle.py --pending      # pending_free(entry+0xb0) 访问点
python tools/kgsl_lifecycle.py --fn sparse_bind_range

# —— 上机探针（判定型）——
zig cc -target aarch64-linux-musl -O2 -static -o live_probe/kgsl_sparse_probe live_probe/kgsl_sparse_probe.c
adb push live_probe/kgsl_sparse_probe /data/local/tmp/
adb shell '/data/local/tmp/kgsl_sparse_probe matrix'   # 分派层真值表
adb shell '/data/local/tmp/kgsl_sparse_probe sparse'   # 六个 sparse 入口（本机应全 524）

# —— 非 sparse 释放前提（§63，判定型）——
# 注意 Git Bash 下需 export MSYS_NO_PATHCONV=1，否则 /data/local/tmp 被改成 Windows 路径
ZIG=".build/zig-windows-x86_64-0.13.0/zig.exe"
"$ZIG" cc -target aarch64-linux-musl -O2 -static -o live_probe/kgsl_life_probe live_probe/kgsl_life_probe.c
adb push live_probe/kgsl_life_probe /data/local/tmp/
adb shell /data/local/tmp/kgsl_life_probe param   # 四分支参数门（应全 EINVAL，零副作用）
adb shell /data/local/tmp/kgsl_life_probe life    # alloc→FREE→再 FREE（第二次应 EINVAL = I4 成立）

# —— C2 长度维度 / Track A ——
python tools/kgsl_ioctl_scan.py --detail
python tools/kfn.py proc_pid_stack
```

## 5. 运营约定

- 设备 `PCGM00_11_F.16`（SDM710，6 GB，futex_hashsize=2048），未刷写/解锁/改分区；**mm 地址随开机变化**。
- 上机授权已获得（2026-11-20），但**硬约束：不得重启**。任何可能 panic 的动作（GPU 命令提交、悬空映射访问）都不在授权含义内。
- 只读拉取 `.ko` 属设备操作；`persist/wlan` 写入永久禁止。
- 建议关闭 OTA：SPL/内核变化会使全部偏移与判据作废。
- 新对话从本文件开始 → `HANDOVER.md` §62 → §61 → §60 → §58 → §53。
