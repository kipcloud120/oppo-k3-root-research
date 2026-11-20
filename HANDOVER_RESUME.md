# 接手摘要（**v13.1：dumpstate 路径实证取得当前 boot 的 `.text` KASLR slide（`0x1953600000`）并固化为 `KASLR_EVIDENCE.md`；阶段 3 收尾——B3 全局 rt_mutex 并发语义审计完成、可用性被否证；四层判定仍 NO-GO**，2026-11-20）

> 一页式入口。完整证据：`HANDOVER.md` §71（v13.1 阶段 3 收尾，最新）+ §70 + §69 + §68 + §67 + §66 + §63 + §62 + §61；**dumpstate KASLR 路径权威证据台账：[`KASLR_EVIDENCE.md`](KASLR_EVIDENCE.md)，方法原始记录：`live_probe/DUMPSTATE_KASLR_PATH.md`；B3 审计：[`GHOSTLOCK_B3_CONCURRENCY_AUDIT.md`](GHOSTLOCK_B3_CONCURRENCY_AUDIT.md)**。
> 分层判定 `CLOSURE.md`；审阅入口 `README.md`。

> **v13 证据收口（2026-11-20 下午，响应审核 v013；纯文档/离线，零上机，不改变四层判定）**：
> ① **当前 boot 的 `.text` KASLR slide 已实证取得**：dumpstate 第三主体路径（`ctl.start dumpstate → bugreport → 内核日志原始 pc/lr → vmlinux.elf 静态符号`）+ **一次用户明确授权的重启**。当前 boot（`boot_id=b9f9f06a-…`）slide = **`0x1953600000`**，运行时 `_text = 0xffffff995b680000`，2 MB 对齐，pc/lr 两路独立 + 寄存器族一致；重启前 boot（`27520eec-…`）slide = `0x16a000000`（last_kmsg 四路一致），跨 boot 复现命中。**slide 每 boot 随机，再重启即失效**。
> ② **证据固化（P0.1–P0.4 全部落档 [`KASLR_EVIDENCE.md`](KASLR_EVIDENCE.md)）**：原始 pc/lr/寄存器族整理、全部物料 SHA-256 台账（vmlinux.elf `6588c871…`、boot.img `22fc0926…`、newboot.zip `754925b4…` 等）、当前/重启前/历史 last_kmsg 的地址归属区分（.5–.10 早期副本 WARN 形态不同 ⇒ 旧内核构建不可用当前符号表推导）、dumpstate 日志保留边界与成功/失败条件清单。
> ③ **判定语义（v013 纪律，不得混用）**：①-s 类 slide 获取原语成立 ≠ 可用 root——GhostLock **②（可控 rt_mutex 堆地址）/③（W 线程栈基址）缺口不变**；dumpstate 附带的 `sp` 属 init/swapper 栈，不满足 ③ 判据；v008"已审接口内无 slide 原语"表述在其范围内仍成立。
> ④ **v13 主线定义**：不再重复寻找已得到的 slide；第一主线 = dumpstate 证据固化（**阶段 1 已完成**）+ 运行期 WARNING 观察面静态审计（P1）；第二主线 = GhostLock ②/③ 地址条件分别复评（P2，**阶段 3 已完成，含 G4 B3 审计**）；并行 = WLAN `hdd_driver_command` 调用链静态审计（P3，待启动）。**阶段 2（WARNING 观察面）按用户指示暂缓（非关闭）；改代码与调试类工作待用户通知。**
> ⑥ **阶段 3 复评 + 收尾结论（G0–G4 五份文档；`HANDOVER.md` §67 + §71）**：地址缺口收敛为**单一 N1**（有效、可控、结构合法 rt_mutex 对象地址 = ②或③）；slide 只补 N3(ii)（已知镜像地址可计算），不满足 N1；方向 A（W 线程栈）与 B1/B2（pi_state/skb 喷页）均无 oracle 维持冻结。**B3（全局静态 rt_mutex）已完成两阶段工作：① 枚举——厂商源码 + 本机符号表实证 4 个静态实例（`uid_lock`/`msm_bus_adhoc_lock`/`msm_bus_dbg_cllist_lock`/`proc_uid_lock`，运行时 VA = 静态 VA + slide）；② 并发语义审计（G4）——结论为否：链走查 `:702` 无条件读 `lock->waiters_leftmost`，空树 ⇒ `NULL+0x38` fault，非空树 ⇒ 必有地址不可知的真实 waiter，`:705` `rb_erase(fake)` 只能是"孤儿/幽灵 waiter"或"不可控写 + 树损坏" ⇒ 不满足 N1 的"可控"**。B3 由"待审计候选"改为"**已审计否决**"。**GhostLock 维持冻结；四层判定不变：NO-GO。**
> ⑦ **阶段 2 审计 + 裁决结论（`WARN_ADDRESS_SURFACE_AUDIT.md` §1–§8，`HANDOVER.md` §68/§69）**：WARN() 寄存器 dump 是**非致命、上下文本地的 sp 观测通道**（双 boot 实证）——③ 的唯一潜在 oracle 形态；稳态自然 WARN=0、自然事件全部在内核线程上下文；`hdd_driver_command` 与 KGSL 已审 ioctl 函数内 0 个 WARN 点。**候选集裁决已完成**：厂商源码（`oppo-source/android_kernel_oppo_sdm710`，双锚点校准通过）落地后，futex PI 路径 68 点全部排除——唯一用户路径候选 `futex.c:1302` 被 4 处 `-EINVAL` 前置检查拦截（死防御代码，用户态不可达，反汇编交叉印证）。**③ 的 WARN-oracle 假设被否决，③ 回到"无可用 oracle"（已完整裁决为否）；四层判定不变：NO-GO。**
> ⑤ 冻结/维持项（v013 §3）：KernelSnitch M1 冻结为已验证工具；M2 时间邻接固定 delta 继续关闭；KGSL 非 sparse 生命周期阶段性关闭；GhostLock 固定地址移植方案关闭；FastRPC 旧路径、WLAN persist 输入关闭；`CVE-2025-38352` 动态测试暂停。四层判定不变：**可用 root / 持久 ROOT 仍 NO-GO**。

> **v13/v14 分诊收口（2026-11-20 下午，**纯离线、零上机，不改变四层判定**）**：
> ① **v13 评审**：维持 NO-GO；KGSL/GhostLock 冻结；下一轮主线从"继续找漏洞"改为"文档同步 + 可达性优先"，即 R0（交接口径）+ R1（WLAN 非配置输入可达性矩阵）。
> ② **v14 联网调研**：四个 CVE 候选中仅 `CVE-2025-38352`（POSIX CPU timers TOCTOU）值得登记；其余排除/降级。**任务 E1 已完成**：本机 `run_posix_cpu_timers` 无 `exit_state` 门、`posix_cpu_timer_del` lock-fail 不读 `firing`、无 task_work 缓解 ⇒ pre-fix 结构同构证实，但动态可达性未证、高 panic + 缺 `.text` slide ⇒ **不升级授权、动态默认禁止**。
> ③ **R0 覆盖台账 + 交接口径修正已完成**（`docs_archive/R0_覆盖台账`）；**R1 WLAN 非配置输入可达性矩阵已完成**（`docs_archive/R1_WLAN非配置输入可达性矩阵`）：ioctl/testmode/cfg80211/日志/debugfs 五类面；**v12.3.1 更正后**（见下）——不能只建 shell 直接访问模型，§23 的受限 UID 0 子进程是独立代理主体、其域满足驱动面权限门，`0x89f1 → hdd_driver_command` 列为**首选离线审计候选**（R1 §6 已完成首轮），FTM testmode 次选；**不宣告"无 R3 候选"**，但不在当前设备做动态输入。
> ④ 三份权威文档（`HANDOVER.md`/`HANDOVER_RESUME.md`/`CLOSURE.md`）**未改写历史正文**，仅增补本节与 §64 摘要；四层判定不变：**可用 root / 持久 ROOT 仍 NO-GO**。
>
> **v12.3.1 更正（2026-11-20，响应外部复审，纯离线）**：R1 初版 §2.1 误用 `F16_WIFI_FTM_TRACE.md` §12 的早期撤回，写成"所有注入均被拒绝、不产生 uid 0"——**这是事实错误，已撤回**。原始证据（`P1_L3_EVIDENCE.txt` 第 28 行 + F 节、HANDOVER §23、负知识表、`WIFI_P1_ROOT_COMMAND_AUDIT.md` §3）证明：`\n`/反引号绕过 11 字符黑名单，两次真机回显 `uid=0(root)`、域 `u:r:oplus_wifi_service:s0`（含 NET_ADMIN/NET_RAW/SYS_MODULE）⇒ **受限 UID 0 命令执行仍为已达成**。更正后的可达模型必须把该 UID 0 子进程作为**独立于 shell 的代理主体**——其域满足 WLAN 驱动面权限门。据此 R1 将 **`0x89f1 → hdd_driver_command` 重列为首选离线审计候选**（已完成首轮 §6：上界 `0x2000` + 显式 NUL + 98 项白名单 + 全路径释放），FTM testmode 为次选。**连接点未证**（用户态 iwpriv 与内核态 `0x89f1` 的绑定缺物料）；**不做动态输入**；完整 ROOT 仍 NO-GO。
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
| GhostLock 地址缺口 | ① **闭合**（本次开机）；② **未闭合**（§50 时间流否证）；③ **已审接口范围内无可用 oracle**（§53/§60）。**v12 起冻结**；**v13：①-s（`.text` slide）已取得但 ②/③ 缺口不变** |
| `.text` KASLR slide（①-s） | **已取得（v13，当前 boot `b9f9f06a-…`，slide=`0x1953600000`，运行时 `_text=0xffffff995b680000`）**：dumpstate 路径 + 一次授权重启；每 boot 随机、再重启即失效。台账：`KASLR_EVIDENCE.md` |
| KGSL 生命周期（主线） | 所有权 **成立**（I1–I5，§61.5）；**KO-1 本机不可达已关闭（§62）**；**非 sparse 释放链自洽（I10–I12）、I4 上机证实（§63）** ⇒ K2 里程碑在本机可达面内达成，主线阶段性关闭；K3 并发登记不作 |

## 2. v12 三轮做了什么

| 轮 | 日期 | 性质 | 结果 |
|---|---|---|---|
| §61（v12-K1） | 2026-11-20 上午 | 纯离线 | 六态状态机 + 不变量 I1–I9；I1–I5 成立、I6 被违反（KO-1）；legacy 分派表全解（86 槽/37 入口） |
| §62（v12-K2） | 2026-11-20 上午 | 上机（判定型） | KO-1 **关闭**：六个 sparse 入口 `ENOTSUPP`；`boot_id` 不变、`uptime` 连续；探针已删 |
| §63（v12.2） | 2026-11-20 上午 | 离线 + 上机（判定型） | 非 sparse 释放链自洽（I10–I12），I4 上机证实（再 FREE = EINVAL，无 double-free）；K2 达成、主线阶段性关闭；`boot_id` 不变、探针已删 |

## 3. 下一步（v13.1 口径，响应审核 v013 + v013-step3）

1. **[已完成]** 阶段 1（证据收口）：`KASLR_EVIDENCE.md` + 三入口 v13 同步。
2. **[已完成]** 阶段 2（运行期 WARNING 观察面静态审计）：`WARN_ADDRESS_SURFACE_AUDIT.md` + `HANDOVER.md` §68–§69；结论：WARN dump = 非致命上下文本地 sp 通道（③ 唯一潜在 oracle 形态）；稳态自然 WARN=0、可达入口函数 0 个 WARN 点；**futex PI 路径 68 点候选集已获厂商源码并完整裁决：全部排除（`futex.c:1302` 有 -EINVAL 前置检查，死防御代码），③ = 无可用 oracle（已完整裁决为否）**。
3. **[已完成]** 阶段 3（GhostLock ②/③ 复评）：`GHOSTLOCK_ADDRESS_BASELINE.md` / `_REQUIREMENTS.md` / `_SOURCE_MATRIX.md` / `_PHASE3_DECISION.md`（G0–G3）+ `HANDOVER.md` §67；结论：缺口收敛为 N1，GhostLock 维持冻结。
4. **[已完成]** 补做（厂商源码到手后，`HANDOVER.md` §69.4/§70）：B3 全局 rt_mutex 静态枚举 → **4 个已编入内核的静态实例**（`uid_lock` / `msm_bus_adhoc_lock` / `msm_bus_dbg_cllist_lock` / `proc_uid_lock`，运行时 VA = 静态 VA + slide `0x1953600000`，详见 G2 §2.3 / G3 §6）；厂商 rtmutex 机制核验通过；**waiter 布局修正：0x50 字节、内嵌 `deadline@0x48`（厂商源码 + 二进制双证，§8.1 旧记录 72 B/无 deadline 错误已标记更正）；`MAX_DL_PRIO=0` ⇒ deadline 永不被解引用**。
5. **[已完成]** 阶段 3 收尾 / G3 重开条件②（`GHOSTLOCK_B3_CONCURRENCY_AUDIT.md`（G4）+ `HANDOVER.md` §71；复算 `python tools/b3_audit.py`）：B3 并发语义静态审计 → **结论为否**（空树 `:702` `NULL+0x38` fault；非空树必有不可控真实 waiter，`:705` `rb_erase(fake)` 只能孤儿化或不可控写）⇒ **B3 可用性被否证，GhostLock ②/③ 维持冻结（不是"待审计"）**。
6. **[待启动]** 阶段 4（WLAN 静态审计，可并行）→ `WLAN_IOCTL_CHAIN_AUDIT.md`；缺用户态↔内核连接点证据前不做动态输入。
7. **[待启动]** 阶段 5（总体验收）→ 新版 `CLOSURE.md` 逐条列明已证明/未证明/不可达/冻结路线。
8. **[维持]** ROOT NO-GO；不做 GhostLock 端到端 PoC；**不重启**（重启需单独、逐次授权）；建议关闭 OTA。

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

# —— 阶段 3 收尾：B3 并发语义审计（G4，纯离线复算）——
python tools/b3_audit.py                       # 符号/对象字节/adjust_pi 参数/:702 top_waiter 解引用/waiter 布局，7 项断言
```

## 5. 运营约定

- 设备 `PCGM00_11_F.16`（SDM710，6 GB，futex_hashsize=2048），未刷写/解锁/改分区；**mm 地址随开机变化**。
- 上机授权已获得（2026-11-20），但**硬约束：不得重启**。任何可能 panic 的动作（GPU 命令提交、悬空映射访问）都不在授权含义内。
- **重启是单独、逐次授权的操作**：2026-11-20 16:32 的一次授权重启仅覆盖当次 dumpstate 实验，不构成永久重启许可（v013 明文）。
- 只读拉取 `.ko` 属设备操作；`persist/wlan` 写入永久禁止。
- 建议关闭 OTA：SPL/内核变化会使全部偏移与判据作废。
- 新对话从本文件开始 → `KASLR_EVIDENCE.md`（v13 证据台账）→ `HANDOVER.md` §66 → §63 → §62 → §61。
