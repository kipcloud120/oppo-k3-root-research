# 判定：PCGM00 F.16 —— 可用 ROOT 为 NO-GO；GhostLock 冻结（B3 已否证）；KGSL 非 sparse 生命周期阶段性关闭；**v13.2：WLAN 调用链审计完成（候选 A 重定向到 WEXT 私有面）、FTM 条件性关闭、项目五层验收**（2026-11-20）

| | |
|---|---|
| 设备 | OPPO K3 `PCGM00`（`OP4679`，`sdm710`），`PCGM00_11_F.16`，Android 11 |
| 内核 | `4.9.227-perf+`（clang 10.0.7，2025-03-26 构建） |
| 安全补丁 | `2022-04-05` |
| 启动状态 | BL 锁定、AVB `green`、dm-verity `enforcing`、A-only（v3 实测基线复核一致，无 OTA） |
| 唯一入口 | `uid=2000(shell)` + `u:r:shell:s0`，SELinux Enforcing，`Seccomp: 0` |
| 判定版本 | `HANDOVER.md` v3.0 + v008 + v6（§46）+ v7（§47）+ v8（§48）+ v9（§49）+ v10（§50）+ v10.1（§51/§52）+ v11（§53/§54）+ v11.1（§55）+ v11.2（§56）+ v11.5（§57–§59）+ v11.6（§60）+ v12（§61）+ v12.1（§62，sparse 上机判定）+ v12.2（§63，非 sparse 释放前提 + I4 上机）+ v12.3（§64，分诊收口）+ v12.3.1（§65，R1 更正）+ **v13（§66 + [`KASLR_EVIDENCE.md`](KASLR_EVIDENCE.md)，dumpstate slide 证据固化）** + **v13.1（§71 + [`GHOSTLOCK_B3_CONCURRENCY_AUDIT.md`](GHOSTLOCK_B3_CONCURRENCY_AUDIT.md)，B3 审计收尾）** + **v13.2（§72 + [`WLAN_IOCTL_CHAIN_AUDIT.md`](WLAN_IOCTL_CHAIN_AUDIT.md) / [`WLAN_HANDLER_AUDIT.md`](WLAN_HANDLER_AUDIT.md) / [`WLAN_WEXT_HANDLER_AUDIT.md`](WLAN_WEXT_HANDLER_AUDIT.md) / [`WLAN_FTM_AUDIT.md`](WLAN_FTM_AUDIT.md) / [`VENDOR_SURFACE_MATRIX.md`](VENDOR_SURFACE_MATRIX.md)，WLAN 调用链 + 分诊 + 五层验收）** |
| 判定范围 | **本机、本固件、不解 BL**。不是"任何条件下不可能"，也不是"任何设备不可能" |

> **v13.2 WLAN 调用链 + 五层验收（2026-11-20，响应审核 v0132；纯离线、零上机，不改变可用 ROOT 判定）**：
> ① **候选 A 重定向**：`0x89f1 → hdd_driver_command` 的真实用户态调用方是 **`wpa_supplicant` 的 `DRIVER` 通道**（Android `android_priv_cmd`，4 处 ioctl；控制接口 `"DRIVER "` → `wpa_drv_driver_cmd` → `ops+0x308`），`/odm/bin/iwpriv` 只发 **WEXT 私有**（`0x8BE0..0x8BFF`，23 父项 / 101 子命令（223 参数））——**不经 `hdd_driver_command`**。审核 v0132 要求的"用户态→内核"连接在 `0x89f1` 上成立，但主语是 `wpa_supplicant`；`executeDriverCommand` 的真实端点是 **WEXT 私有面**（[`WLAN_IOCTL_CHAIN_AUDIT.md`](WLAN_IOCTL_CHAIN_AUDIT.md)）。
> ② **可达性（P1-D）**：受限 UID 0 代理可执行 `/odm/bin/iwpriv` 且持 `net_admin` ⇒ WEXT SET 面**域满足**；但它对 `wifi_vendor_wpa_socket` **无任何 SELinux allow** ⇒ wpa_cli/supplicant 通道对代理**关闭**；shell 无 `wcnss_service_exec` 执行权 ⇒ 不能跑 iwpriv。`0x89f1` 在内核层**无 `CAP_NET_ADMIN` 门**（`dev_ioctl` 源码），shell 的 `neverallowx` 与内核 xperm 生效性**未决**（不做动态验证）。
> ③ **handler 审计**：98 项 `hdd_drv_cmds` 见 [`WLAN_HANDLER_AUDIT.md`](WLAN_HANDLER_AUDIT.md)；代理可达的 WEXT 23 父项 + 101 子命令 见 [`WLAN_WEXT_HANDLER_AUDIT.md`](WLAN_WEXT_HANDLER_AUDIT.md)（4.9 wext 核心以 `kzalloc(extra_size)+copy_from_user(extra_size)` 归一化长度，"用户长度 < 结构体 ⇒ 堆越界读"不成立，handler 侧需按字段/索引校验重审）。
> ④ **FTM 条件性关闭**：`0x89fd` 仅在 `conparam==5` 受理；正常启动链 `init.wlan.target.rc` 的 `insmod` 无 con_mode 参数（默认 0），运行期改 con_mode 会触发整驱动模式重启；随固件出货的用户态程序无 `0x89fd` 调用方（[`WLAN_FTM_AUDIT.md`](WLAN_FTM_AUDIT.md)）。
> ⑤ **vendor 分诊**：37 个 `.ko` / **32 个实际加载**；非 WLAN 模块中"真实加载 + 用户态接口 + shell/代理两主体可达"合格者 **0**（[`VENDOR_SURFACE_MATRIX.md`](VENDOR_SURFACE_MATRIX.md)）。
> ⑥ **五层验收见 §1**；四层判定不变：Wi-Fi 域内受限 UID 0 命令执行已达成；**可用 ROOT / 持久 ROOT 仍 NO-GO**。

> **v13 证据收口（2026-11-20，`HANDOVER.md` §66 + [`KASLR_EVIDENCE.md`](KASLR_EVIDENCE.md)，纯文档/离线 + 一次**已授权**重启，不改变四层判定）**：
> ① **`.text` KASLR slide（①-s 类）已实证取得**：dumpstate 第三主体路径 + 用户明确授权的一次重启。当前 boot（`b9f9f06a-…`）slide = `0x1953600000`、运行时 `_text = 0xffffff995b680000`（pc/lr 两路独立 + 寄存器族一致 + 2 MB 对齐）；重启前 boot（`27520eec-…`）slide = `0x16a000000`（last_kmsg 四路一致），跨 boot 预测复现命中。**slide 每 boot 随机，再重启即失效，须重走流程**。
> ② **本文此前"`.text` slide 拿不到（v008）"的表述自本轮起仅在"已审接口范围 + 未授权重启"这一限定下成立**——v008 口径在其原范围内不被推翻，但事实状态已由 dumpstate 路径（该范围外第三主体）补齐。证据、哈希与归属台账见 `KASLR_EVIDENCE.md`。
> ③ **判定语义不变**：slide ≠ 可用 root。GhostLock **②（可控 rt_mutex 堆地址）与 ③（W 线程栈基址）仍未闭合**；dumpstate 附带的 `sp` 属 init/swapper 栈，不满足 ③ 判据；M2 固定 delta 维持关闭。
> ④ **v13 阶段进度**：阶段 1（证据收口）、阶段 2（WARNING 观察面审计 + 候选裁决，`WARN_ADDRESS_SURFACE_AUDIT.md` §1–§9 + §68/§69/§70：WARN dump 通道实证但 futex 68 点候选集经厂商源码裁决**全部排除**，③ 的 WARN-oracle 假设被否决，③ 回到"无可用 oracle"）与阶段 3（GhostLock ②/③ 复评，§67 + `GHOSTLOCK_PHASE3_DECISION.md` 等 G0–G3 文档：**缺口收敛为单一 N1，GhostLock 维持冻结**）已完成；**厂商源码补做（§69.4/§70，2026-11-20）：B3 全局 rt_mutex 静态枚举完成——4 个已编入内核的静态实例（`uid_lock`/`msm_bus_adhoc_lock`/`msm_bus_dbg_cllist_lock`/`proc_uid_lock`，地址可由 slide 复算，G2 §2.3 / G3 §6）；waiter 布局修正为 0x50 字节（内嵌 `deadline@0x48`，厂商源码 + 二进制双证；`MAX_DL_PRIO=0` ⇒ 该字段永不被解引用）**；**阶段 3 收尾（v13.1，§71 + `GHOSTLOCK_B3_CONCURRENCY_AUDIT.md`（G4），纯离线）：B3 并发语义静态审计完成、结论为否——链走查 `:702` 无条件读 `lock->waiters_leftmost`（空树 ⇒ `NULL+0x38` fault；非空树 ⇒ 必有地址不可知的真实 waiter），`:705` `rb_erase(fake)` 只能产生孤儿/幽灵 waiter 或不可控写 ⇒ B3 不满足 N1 的"可控"，由"待审计候选"改为"已审计否决"（复算 `python tools/b3_audit.py`）**；阶段 4（WLAN 调用链）与阶段 5（总验收）**已于 v13.2 完成**（见本节顶部 v13.2 摘要与 `CLOSURE.md` §1 五层验收）。
> ⑤ **四层判定不变：Wi-Fi 域内受限 UID 0 命令执行已达成；可用 ROOT / 持久 ROOT 仍 NO-GO。**

> **v12.3.1 分诊摘要（2026-11-20，`HANDOVER.md` §64/§65，纯离线、零上机，不改变四层判定）**：
> ① **v13 评审 / v14 联网调研 / 任务 E1 / R0 覆盖台账 / R1 WLAN 可达性矩阵**五份分诊报告已完成并归档于 `docs_archive/`，均为离线分析，未产生新的提权原语；
> ② **`CVE-2025-38352`**：本机 pre-fix 结构同构证实（无 `exit_state` 门、lock-fail 不读 `firing`、无 task_work 缓解），但动态可达性未证、高 panic + 缺 `.text` slide ⇒ 保持离线，不升级授权；
> ③ **R1 已更正（响应外部复审）**：初版误用早期失败记录覆盖后来的正向实测，已按 `P1_L3_EVIDENCE.txt` + §23 + `WIFI_P1_ROOT_COMMAND_AUDIT.md` §3 撤回并重写——**受限 UID 0 命令执行仍为已达成**（`\n`/反引号绕过黑名单，两次回显 `uid=0(root)`，域 `oplus_wifi_service`）；该 UID 0 子进程作为独立代理主体满足 WLAN 驱动面权限门，`0x89f1 → hdd_driver_command` 列为首选离线审计候选（首轮见 R1 §6）。用户态 iwpriv 与内核态 ioctl 的连接点未证；不做动态输入；
> ④ **四层判定不变**：Wi-Fi 域内 UID 0 命令执行已达成（受限）；**可用 ROOT / 持久 ROOT 仍 NO-GO**；KGSL 阶段性关闭、GhostLock 冻结维持。本摘要与 §1–§63 历史证据不冲突，后者仍为技术事实权威。

> **v8 更正（2026-11-19，§48）**：① 类地址**已闭合**。两件事同时成立：
> ① G1 判别性由设备实验确立（翻转测试 18/19 genuine；crowd 规模 256→64→16 时命中耗时等比 3.68×）；
> ② G2 恢复 mm 地址成功——两套独立数据各得唯一解，**全量 hit 100% 同桶**（19/19、26/26）。
> 此前 v5–v7 的"零候选 / hit 集污染 / 判别性不成立"全部撤回，根因是**搜索窗口错位**：
> `memstart_addr` 被 KASLR 以 **1 GB** 为单位下移，本次开机 ≈ **100–105 GB**，
> 而历史窗口一律是 `PAGE_OFFSET..+8 GB`（v5 §45.3 把 1 GB 对齐掩码误读为 256 GB，遂误判"平移恒为 0"）。
> **边界**：mm 地址仅本次开机有效（shift 每开机随机）；这仍然是**线性映射平移**，不是 `.text` 的 KASLR slide；
> 且 ① 类闭合不构成提权——②/③ 未闭合。**四层 NO-GO 不变。**

> **v10 否证（2026-11-19，§50）**：M2 评估完成——以已知 mm 为锚、依赖 buddy 分配流"时间邻接"
> 推导 AF_UNIX skb 喷射页落点的路线（参考项目固定 delta 的移植前提）**被真机示踪实验证伪**：
> mm 示踪粒子法显示相邻 fresh mm slab 页（间隔秒级）落点 **1.0–5.5 GiB 随机散布**，
> 简单**固定/线性 delta** 模型不成立。**K 的独立影响未测得**（run1 实际 K 仅 12 块；
> run2 两个 K=768 步骤的中间示踪 T2 缺失 ⇒ d12/d23 均 N/A），故不宣称"喷射规模无影响"。
> ② 维持未闭合，且新增"时间流锚定不可行"否证；split-pair 结构邻接
> 因 fork 分配序未审计 + skb 落点无观测 oracle，不作为闭合依据。**NO-GO 不变。**

> **v10.1 增补（2026-11-19，§51/§52，纯离线，零上机）**：
> ① **唯一性升级为脚本断言**：9/9 个示踪的满命中候选数 `n_full`=1，**次高分恒为 3**（噪声地板），
>    最优/次优相差 ≥10 个约束；两个原在 1 GB 邻域出解者已补扫 16 GB 复核，同为全局唯一。
>    ⇒ §50 的否证依据从"人工观察 + 概率估算"变为"可复算断言"，**结论方向不变**。
> ② **`/dev/diag` DCI 解析子树静态否证**：三条回传路径均有"声明长度⇄实收长度"门 + 缓冲容量二次校验，
>    子树内无 `copy_to_user`；余量 R1–R3（ctrl 包控制语义 / 两条非 apps 入口 / 长度字段功能边界）。
> ③ 探针补记 dummy 实际成功数与 errno、增 `posttracer` slabinfo 快照（**待上机验证**）。
> **四层判定不变：可用 root / 持久 ROOT 仍 NO-GO。**

> **v11 增补（2026-11-19，§53/§54，纯离线）**：
> ① **③ 类改为"已枚举 + 本机实测否证"**：逐项审完 16 条低权限可达接口（另有实测：`kstkesp/kstkeip` 恒 0、
>    `/proc/self/stack` 在 shell 域被 SELinux 直接拒，§55.1），**唯一含 sp 的输出是 oops 寄存器 dump**，
>    而 `panic_on_oops` **本机不可观测**（两域均被 `proc_panic` 标签拒绝，§59.1）⇒ 触发即重启、同时作废 ① 类地址，不构成 oracle。其余接口只吐
>    `%pK` 门控的**文本地址**或纯符号名。按审核 v011 停止标准，③ 子方向关闭；
>    保留两项 5 秒只读复核（`/proc/self/stat` 28–30 字段、`/proc/self/stack`，待授权）。
> ② **Track C 缺物料**：qcacld-3.0 不在内核镜像（`hdd_*`/`qdf_*` 符号 0 个），
>    `WCNSS_qcom_cfg.ini` 的解析器在 `qca_cld3_wlan.ko`；本仓库无 `.ko` ⇒ 审计前置条件为只读拉取该模块。
> ③ DCI 的 R2 部分办结（remote 入口门已确认）。**四层判定不变。**

> **v11.2 增补（2026-11-20，§56，只读实测）**：
> **Track C1（WLAN 配置解析器）降级为"无可达输入路径"**——`/vendor` 为 dm-verity 只读挂载、
> 驱动 `fwpath` 参数为空 ⇒ 只读 vendor 副本；可写的 `persist/wlan` 副本与解析器之间无消费关系。
> `cfg_parse` 形态核对：27 处拷贝全为 `strlcpy`（dst 为结构体固定偏移），模块未导入无界 `strcpy`。
> **v11.5 增补（2026-11-20，§59，上机实测）**：三项标注为"推断"的判据已逐条验证——
> ① `panic_on_oops` **两个可用域均读不到**（`proc_panic` SELinux 拒），改写为"不可观测"、结论不依赖该值；
> ② `request_firmware` 回落 `/vendor/firmware` 由四条独立证据证实；
> ③ KGSL 长度门实为 **`min(entry, cmd)`**，非初稿所称"严格相等"——差分测试（`kgsl_cmdprobe`）推翻并已更正 §58.1。
> 安全性结论不变（min 仍是有界），**机制描述已修正**。

> **v11.6 增补（2026-11-20，§60，只读实测）**：送审前补测——基线未变、`CapEff=0x13000` 实测
> （无 `CAP_SYS_ADMIN/SYSLOG`）、Track A 逐项复核（`kallsyms` 拒；`/proc/self/stack` 在 uid-0 域
> **可读但为空**，已据此修正 §55.1 的"彻底关闭"表述）、C1 两份 ini 大小不同（12,592 vs 21,663）
> ⇒ 可写副本与解析器无消费关系。**四层判定不变。**

> **v12 主线变更 + K1（2026-11-20，§61，纯离线）**：
> ① **主线正式转为 KGSL 内存对象生命周期**（接受审核 v012 的 P0）；GhostLock ②/③ **冻结**，
>    仅在出现新的、可独立验证的内核对象地址来源时重开。
> ② **K1「所有权」一半关闭**：不变量 I1–I5（取引用需持锁且拒绝 pending、释放有唯一赢家、id 只在 detach 撤销、
>    取/放配对）全部在本机二进制上成立；21 个取引用点与 42 个释放点逐函数对齐。
> ③ **K1「销毁前提」一半被证伪 —— KO-1**：`SPARSE_PHYS` 的"有绑定则不可释放"门**只实现于 `SPARSE_PHYS_FREE` 一个入口**，
>    而 `GPUMEM_FREE_ID`（`0x873d564`）与 `GPUOBJ_FREE`（`0x873d5ec`）都以 `flags=0` 查 id ⇒ 可释放仍被绑定的物理块 ⇒
>    悬空 IOMMU 映射 + bind 节点悬空 `p_memdesc`。**静态成立**（§62 上机后判定：本机 sparse 面不可达，已关闭）。
> ④ 附：legacy 分派表全解（86 槽 / 37 入口 / 命令字 + handler），并解除 §58.2"表项函数指针恒为 0"的限制。
> **四层判定不变：可用 root / 持久 ROOT 仍 NO-GO。**

> **v12.1 上机判定（2026-11-20，§62，只读 + 最小探针，`boot_id` 不变）**：
> **KO-1 关闭**——本机 `kgsl_device::flags` 的 BIT(1)（上游即 `KGSL_FLAG_SPARSE`）未置位，
> 六个 sparse 入口（phys/virt alloc/free、bind、gpu_sparse_command）**全部返回 `ENOTSUPP(524)`**，
> 且都发生在任何分配之前 ⇒ `SPARSE_PHYS` 对象无法创建，KO-1 与 C-2/C-3 一并不适用。
> 控制项：`getproperty`(type=8/非法指针)=`EFAULT`、`(type=0)`=`EINVAL`、`syncsource_create`=0、
> 未注册 nr=`ENOTTY` ⇒ 分派层与处理器到达性均已证实，负结果不是"打不进去"造成的。
> 同时更正一次工具层误判：`strerror(-ret)` 会把所有失败打印成 `EPERM`（详见 §62.3）。
> **四层判定不变。**

> **v12.2 非 sparse 释放前提（2026-11-20，§63，离线审计 + 判定型上机，`boot_id` 不变）**：
> **K2 里程碑在本机非 sparse 可达面内达成**——① 新增全称不变量 I10–I12 在本机二进制全部成立
> （`set_pend` 唯一赢家、释放必 `idr_remove`+幂等 unmap gpuaddr、四分支共享 `pending_free` 且引用配对）；
> ② 排除三处"看似缺陷"（`put_gpuaddr` 双调用因清零而幂等、命令用 gpuaddr 走 pagetable 故不需 get entry、
> 四释放分支汇聚同一 destroy 链而非单点门错位）；③ **I4 上机证实**：`GPUOBJ_ALLOC`→FREE→再 FREE 同 id
> 第二次 `EINVAL(22)`、`GPUMEM_FREE_ID` 交叉验证一致 ⇒ 无 double-free；`param` 五分支全 EINVAL 证明解析正确。
> **K3 并发动态测试登记不作**（须制造悬空窗口，超"不重启"边界）。KGSL 生命周期主线**阶段性关闭**。
> `boot_id` 全程一致、`uptime` 连续 +24 s、探针已删、内核日志无异常。**四层判定不变：NO-GO。**

> **Track C2（KGSL 长度维度）**：54 入口 / 14 拷贝点，**长度维度已闭合 14/14**（§58）——
> `copy_in/out` 取 `min(_IOC_SIZE(cmd), 表项 size)`，adreno 表项最大 0x20；其余为 min 钳位/同尺寸分配/定长。
> **结构层面自 v12 起成为主线**（§61）：所有权已清，销毁前提未闭合（KO-1）。

---

## 0. 一句话（v8 主体；v10 仅追加 M2 否证，不改判）

**这台机器能给你的上限，仍是"以 root 身份在别人写好的笼子里跑命令"。**

GhostLock 那面"无地址泄露"的墙，从 v3 起就被报告"有一道缝"，但随后四轮（v4–v7）反复自我推翻，
直到 v8 才把因果钉死：

1. **计时确实按 futex 桶归属判别**（G1）：翻转测试 18/19 为真 hit；
   把 crowd 规模 256→64→16 递减，命中地址耗时等比下降 **3.68×**（同桶 plist 遍历期望 4）。
2. **mm_struct 地址确实可恢复**（G2）：两套独立设备数据各得唯一解，
   **全量 hit 100% 同桶**（19/19、26/26）。
3. 此前所有失败源于一个**窗口错位**：`memstart_addr` 被 KASLR 以 1 GB 为单位下移，
   本次开机约 100–105 GB；而 v3–v7 的搜索窗口一律是 `PAGE_OFFSET..+8 GB`。

**但这不是提权**：① 类地址只是 GhostLock 的前置条件；② 可控 rt_mutex 堆地址、③ 内核栈基址仍未闭合，
`.text` 的 KASLR slide 也仍拿不到（v008 口径）。**四层判定 NO-GO 不变。**

<details>
<summary>v6 原文（历史记录，"① 无恢复"已于 v8 撤回）</summary>

> GhostLock 那面"无地址泄露"的墙，v3 曾报告"打开了一道缝（侧信道能拿 mm_struct 线性地址）"；
> v6 复核后这道缝比 v3 描述窄得多：计时确实能分辨"crowd 自己在哪个桶"，但无法判定任意候选地址是否同桶。
> 修正统计量后，2×2.35 亿候选全扫也没有任何一个地址的桶一致性组合超过随机期望（max=3 vs 期望 ≤3）。

</details>

---

## 1. 五层验收（v13.2，唯一最终判定口径）

> 审核 v0132 §七要求：最终验收不应只写一句 NO-GO，而应把已取得的成果、已否证的方向、已阶段性关闭的面、待审计项与未解决项分开。以下五层，每层给证据等级与停止条件/边界。

| 层 | 条目 | 状态 | 证据等级 | 交付 / 停止条件 |
|---|---|---|---|---|
| **已达成** | Wi-Fi 受限 UID 0 命令执行 | **达成**（2026-11-18，两次回显 `uid=0(root)`） | 真机实测 | §23；域 `oplus_wifi_service`，**非**可用 root |
| **已达成** | dumpstate 取得当前 boot `.text` KASLR slide | **达成**（`0x1953600000`，当前 boot `b9f9f06a-…`） | 真机实测 + 静态符号 | [`KASLR_EVIDENCE.md`](KASLR_EVIDENCE.md)；每 boot 随机 |
| **已达成** | KernelSnitch Direct Map（`mm_struct`）地址观测方法 | **达成**（G1 18/19 genuine + G2 唯一解） | 真机实测 + 可复算 | §48/§49；仅本次开机 |
| **已完成否证** | GhostLock A（W 线程栈基址） | **否证**：已审接口范围内无可用 oracle | 已审接口穷尽 + 实测 | §53 / §60 |
| **已完成否证** | GhostLock B1（`pi_state` 堆地址） | **否证**：无独立地址锚点 | 静态 + 实测 | §67 / G0–G3 |
| **已完成否证** | GhostLock B2（skb 喷页） | **否证**：M2 固定 delta / 时间邻接不成立 | 真机示踪 | §50 |
| **已完成否证** | GhostLock B3（4 个全局静态 `rt_mutex`） | **否证**：地址可得、对象不可用（空树必 fault / 非空树不可控） | 指令级 + 厂商源码 | G4 / §71 |
| **已完成否证** | futex PI 路径 68 个 WARN 候选 | **全部排除**（唯一用户路径被 4 处 `-EINVAL` 拦截） | 厂商源码 + 反汇编 | `WARN_ADDRESS_SURFACE_AUDIT.md` §8 |
| **已阶段性关闭** | KGSL 非 sparse 生命周期 | **K2 达成**（I1–I5、I10–I12、I4 上机证实） | 静态 + 判定型上机 | §63；K3 并发登记不作 |
| **已阶段性关闭** | KGSL sparse（KO-1） | **本机不可达**（六入口 `ENOTSUPP`） | 上机判定 | §62 |
| **已阶段性关闭** | WLAN 配置解析链 C1 | **无可达输入路径** | 只读实测 | §56 |
| **已完成审计** | WLAN `0x89f1 → hdd_driver_command` 调用链 | **连接成立，主语 = `wpa_supplicant`**；`iwpriv` 负结果（只发 WEXT 私有） | 指令级 + 内核源码 + CIL | [`WLAN_IOCTL_CHAIN_AUDIT.md`](WLAN_IOCTL_CHAIN_AUDIT.md) |
| **已完成审计** | 98 项 `hdd_drv_cmds` handler | **0 个内存安全反例**；5 项残留已收口（`MAXTXPOWER` 值域 [-100,100]；4 个 `FMT-UNRESOLVED` 全为 `%31s`/`%d`）；2 个**非内存破坏**反例：H1 `SETMCRATE` 未检解析返回值、H2 `MAXTXPOWER` 解析失败读未初始化栈（受值域门约束） | 指令级（本机 `.ko`） | [`WLAN_HANDLER_AUDIT.md`](WLAN_HANDLER_AUDIT.md) + [`WLAN_RESIDUAL_AUDIT.md`](WLAN_RESIDUAL_AUDIT.md) |
| **已完成审计** | WEXT 23 父项 + 101 子命令（代理可达面） | **全部收口：21 有界 / 2 无功能 / 0 未决；未发现越界读/写**；更正首轮 12 个 SET/GET 方向误判（core 只对偶数用 `set_args` 夹长度）；`0x8BFE` 是 8 B 空桩、`0x8BFF` 的 `extra` 只有 5 B；信息泄露方向关闭（GET 缓冲均 `kzalloc` 清零、回填长度自洽）；剩余为下游 `value` 域与 INI `wext_control` 配置门 | 指令级 + WEXT 源码 | [`WLAN_WEXT_HANDLER_AUDIT.md`](WLAN_WEXT_HANDLER_AUDIT.md) + [`WLAN_WEXT_HANDLER_AUDIT_2.md`](WLAN_WEXT_HANDLER_AUDIT_2.md) |
| **条件性关闭** | FTM testmode `0x89fd` | **需 `con_mode==5` + 驱动模式重启**；正常启动不可达；U2 已证 `myftm`/`ftmdaemon` 全走 nl80211、**固件无 `0x89fd` 调用方**（收紧为 (a)）；U1 已证 HAL 9 个 HIDL 方法**无方法级权限门** | 指令级 + 固件脚本 + CIL | [`WLAN_FTM_AUDIT.md`](WLAN_FTM_AUDIT.md) + [`WLAN_RESIDUAL_AUDIT.md`](WLAN_RESIDUAL_AUDIT.md) |
| **已完成分诊** | 其余 vendor 模块 | **两主体可达的合格者 0** | 取证 + 源码 + CIL | [`VENDOR_SURFACE_MATRIX.md`](VENDOR_SURFACE_MATRIX.md) |
| **未解决** | 可用 ROOT（脱离 SELinux 域的系统管理能力） | **NO-GO** | 域逃逸静态无路径 | §24 / §32 |
| **未解决** | 持久 ROOT | **NO-GO** | 且全程未做持久化写入 | 项目约定 |

> **注（独立线，不并入本判定）**：GhostLock ② 另有一个**独立**的 G5/T3 设备线（T1/T2/KernelSnitch 设备验证 + T3 触发，结论"② 机制性 NO-GO"，T3 五次在 `sched_setattr` 处 panic）。按该会话的明确要求，其内容**不并入本五层验收**；如需引用，以 [`HANDOVER_G5_T3_2026-11-20.md`](HANDOVER_G5_T3_2026-11-20.md) 为准。本文的 GhostLock 结论仍为"① 闭合、②/③ 冻结（B3 已否证）"。

### 1.1 四层判定（历史口径，保留）

| 层次 | 结果 |
|---|---|
| Root UID 命令执行 | **达成**（2026-11-18，两次独立载荷复现，§23） |
| 可用 root（脱离域限制的系统管理能力） | **NO-GO**（域逃逸静态无路径 §24；FastRPC 在 uid 0 域下更封闭 §32） |
| 持久 ROOT | **NO-GO**（且全程未做任何持久化写入） |
| GhostLock 内核地址泄露 | **① 已闭合（v8，本次开机）**：G1 成立（18/19 genuine、3.68× 规模缩放）+ G2 成立（两套数据唯一解、全量 100% 同桶）；② 可控 rt_mutex 堆地址（**v10：时间流锚定证伪**）/ ③ 内核栈基址**已审接口范围内无可用 oracle**（§53 + §60）；`.text` slide：**v13 已实证取得（当前 boot `b9f9f06a-…`，`0x1953600000`，见 `KASLR_EVIDENCE.md`）——每 boot 随机，不改变 ②/③ 未闭合状态**。**v13.1：B3 全局静态 rt_mutex 的 4 实例已枚举并完成并发语义审计（G4）——地址可得但不可用（空树 `:702` 必 fault；非空树必有不可控真实 waiter），不构成 ② 的替代，已审计否决。v12 起冻结。** |
| KGSL 对象生命周期（v12 主线） | 所有权 **成立**（I1–I5，§61.5）；KO-1 **本机不可达已关闭**（sparse 面 `ENOTSUPP`，§62）；**非 sparse 释放链自洽**（I10–I12 静态 + I4 上机证实，§63）⇒ **K2 达成、主线阶段性关闭**；K3 并发登记不作 |

---

## 2. GhostLock 重开判定（v3 核心）

### 2.1 此前的收口理由与其 v3 状态

旧稿把 GhostLock 收口在"载体已闭合、缺内核地址泄露"（§15.4 / §23.9）。v3 逐项复核：

| 旧判据 | v3 状态 | 依据 |
|---|---|---|
| "本机无内核地址泄露" | **作废范围进一步收窄（v6）**：futex 计时对 **crowd 自身桶**成立（40–125×），但**不能判定第三方地址同桶**，故 mm_struct 地址不可恢复（§46）；KASLR slide 亦拿不到（v008） | §46.4；`live_probe/ks_g2_maxmatch*.txt`；`FEASIBILITY_v008.md` §1 |
| "fake waiter 的 lock/rb 需非零内核地址" | **维持并精确化**：lock 会被解引用（trylock 写 + owner/waiters 读 + `BUG_ON` 校验），需要"可控、内核可写、结构合法 rt_mutex 的内核地址" | `artifacts_adb/WAITER_ADDRESS_ANALYSIS.md` §2 |
| "载体侧已闭合" | **维持**：xattr 三条栈覆盖候选、NUL 不阻断、栈复用几何确定 | §15 / GHOSTLOCK_NUL_ANALYSIS |
| "`!VMAP_STACK` 无关" | **更正**：本机实测 `!VMAP_STACK`，栈在线性映射区且与 mm_struct 同区；但 futex key 不含栈地址 ⇒ 仍够不着栈 | §42 / WAITER_ADDRESS_ANALYSIS §5.5 |

### 2.2 按地址类型分档（重开条件的新口径）

> GhostLock 真正缺的**不是"任意一个内核地址"**，而是特定类型。§7 第2条(a) 的旧表述"任一可用内核地址泄露即重开"过宽，v3 细分为：

| 档 | 地址类型 | 本机状态（v6 口径） | 能否填 fake waiter |
|---|---|---|---|
| ① | mm_struct 线性地址 | **已闭合（本次开机）**：`mm=0xffffffda42a97100`（19/19）与 `mm=0xffffffda434d5500`（26/26）两个独立进程唯一解；KASLR 线性映射平移实测 100–105 GB（§48） | ❌ 不够：解引用 + 结构校验过不了，且缺 ② 把它兑现 |
| ② | 某个可控 rt_mutex 的堆地址（pi_state / skb 喷射页，等价参考项目 `payload_base`） | ❌ 生命周期可控（v4 P1 闭合：3072 对象/轮、spread 0.00%），但**缺地址锚点**；`SLAB_FREELIST_RANDOM=n` 使 slab 内布局确定；**v10：页级邻接的"时间流锚定"已证伪**（示踪 delta GB 级随机；K 的独立影响未测得，§50） | ✅ 能——这是参考项目的成功路径 |
| ③ | 当前内核栈地址（W 线程，持有 stale waiter） | ❌ **已审接口范围内无可用 oracle（v11/§53 + §60 逐项复核）**：16 条可达接口全查，唯一含 sp 的是 oops 寄存器 dump，而 `panic_on_oops` **本机不可观测**（§59.1）；`/proc/self/stack` 在 uid-0 域可读但只吐 `%pK` 文本地址且对运行态任务为空；perf 实测排除、futex key 不含栈地址、TLB 侧信道依赖 VMAP_STACK（本机未启用）。**范围限制：debugfs 目录在 SELinux 下不可列、其余 vendor `.ko` 未审。** | ✅ 能（几何偏移已静态解决，缺的是拿栈基址的 oracle） |

⇒ **v6 结论**：① 从"已解决"降级为"未闭合"，② 与 ① 收敛为同一缺口——**缺任意一个内核堆地址锚点**。
**可用 root 判定不变**——三档均未闭合前，不构成提权。

### 2.3 参考项目为何能成功（关键反证）

`yijiacloud/GhostLock-OPPO-PCKM00`（PCKM00 / 4.14.180）用 `fake_lock = payload_base + LOCK_OFF`，其中 `payload_base` 来自 **KernelSnitch 泄露的 mm_struct 地址 + AF_UNIX skb 喷射落到内核堆的可控页** ⇒ lock 指向内核堆上的受控 rt_mutex，**从头到尾不需要栈地址**。K3 缺的正是那个 skb 堆喷原语，所以同样的 slide 在 K3 无法兑现。

---

## 3. 其余三条方向的否证（v3 维持）

### 3.1 域逃逸（原主线）—— 策略层否证

`HANDOVER.md` §24 / `SELINUX_DOMAIN_AUDIT.md`

| 候选 | 断点 |
|---|---|
| 写文件 → 高权限域执行 | 该域可写全部文件类型上持有 `execute` 的域数 = 0（v2.24+ 修正引擎重算仍为 0） |
| `CAP_SYS_ADMIN` 挂载 | 策略无 `filesystem mount`；SELinux 放行 `sys_admin`，墙在内核能力集 `CapEff=0x13000` |
| 加载自定义模块 | 墙是模块签名 `CONFIG_MODULE_SIG_FORCE=y`（策略与 `CAP_SYS_MODULE` 都就位） |
| 属性写 → init 执行 | 命中的 11 条触发器全是 `chmod`/`chown`/`setprop`，无 `start`/`exec` |
| 域转换 | 唯一可达 `crash_dump`，可读集与可写集交集为空，零收益 |

### 3.2 其它内核原语 —— 机制或前提层否证

| 面 | 结论 |
|---|---|
| KGSL `CVE-2023-33107` | 命中缺陷即 `BUG()` panic，无中间态 |
| **KGSL 生命周期（v12）** | **KO-1 → 已关闭（§62）**：sparse 绑定门只在专用入口实现，但本机 sparse 面整支 `ENOTSUPP`，对象无法创建 ⇒ latent。**非 sparse 面（§63）**：I10–I12 成立、I4 上机证实（释放后 id 撤销，无 double-free），未发现过期引用/单点缺门 ⇒ K2 达成、主线阶段性关闭；K3 并发未测（登记不作） |
| binder `CVE-2023-20938` | 漏洞未引入 |
| binder `CVE-2022-20421` | pre-fix 但 ticket spinlock 使原语退化 |
| FastRPC `CVE-2023-33063` | uid 0 域下并集 ∅，比 shell 更封闭（§32） |
| `/dev/diag` | 入口层逐路径复核 + 55/55 拷贝点判界、无 mmap、post-fix 形态；**DCI 解析子树 v10.1 静态否证**（log/events/pkg_rsp 三路均有"声明长度⇄实收长度"门 + 缓冲容量二次校验，子树内无 `copy_to_user`）；余量 R1–R3 为逻辑/来源面，且依赖内核指针的利用仍被 ②/③ 缺口阻断（§51） |

### 3.3 服务面 —— 方法级否证

7 个私有 Binder 服务 7/7 闭合（理由多为"无能力"而非"不可达"）；`system_server` 通道在取句柄处双向断开；Wi-Fi 可写面消费者三道门全封。详见 `HANDOVER.md` §33–§37。

---

## 4. 判定可能错在哪（自我声明）

1. **枚举完备性**：所有消费者/攻击面结论依赖枚举集合；若有未被枚举的面（尤其不经过文件/binder、纯内核驱动接口），收口不成立。
2. **②/③ 缺口的绝对性**：本轮证明 futex 侧信道够不着栈，但未穷尽 4.9 上所有可能的栈地址泄露面（见 §7 可证伪条件）。
3. **策略工具的闭包精度**：v2.24 已兑现成实际错误（`not` 语义 + 版本名合并），修正后多条理由被更正；本域之外尚未逐个回归。
4. **rc 与运行态偏差**：`rc 文本 ≠ 生效集合`，一律以 `init.svc.*` 为准（v2.18 纪律）。
5. **v008 地址口径**：口径收紧由审核 v008 触发、以 `vmlinux.elf` 反汇编为据（`__primary_switched` 的 `kimage_voffset` 计算）；未在真机 dump 运行时 `kimage_voffset` 值（属上机，未授权）。若未来固件改变线性映射随机化行为，R2/R3 关系须重算。
6. **v6 的 G2 否定是"条件性"的**：'真 hit ≤3' 依赖三个前提同时成立——哈希模型、物理窗口、`PAGE_OFFSET` 假设。
   三者中模型已三方对拍、窗口按 DRAM 区间取满，但 `PAGE_OFFSET` 仍是反解值而非实测值。
   若真址落在两个候选窗口之外，本次否定不成立（可复算的反例：给出窗口外的可行性证据）。
7. **v8 的 ① 类闭合是"限本次开机"的**：`memstart_addr` 的 KASLR 平移每开机随机（1 GB 量化），
   故 mm 地址不可跨重启复用；方法可复用（盲扫 8.59 G 候选 @64 B ≈ 38 min/20 进程）。
   若未来固件关闭 `RANDOMIZE_BASE` 或改变 `ARM64_MEMSTART_ALIGN`，窗口规则须重算。

---

## 5. 如何推翻本文（只接受可复算的反例）

| 不构成推翻 | 构成推翻 |
|---|---|
| "侧信道能拿地址了，所以能 root 了" | 给出 ② 或 ③ 类地址的可复算获取路径，并说明如何填进 fake waiter 的 lock/rb 字段 |
| "GhostLock 历史上有漏洞" | 指明本机某字段的越界点，给出可复算的反汇编片段 |
| "root 应该能做更多" | 给出本域能力集的实测反例（当前 `CapEff=CapBnd=0x13000`） |
| 用其它 SPL/内核外推 | 指明本机 SPL `2022-04-05` / 内核 `4.9.227-perf+` 下同一路径的差异 |
| "KernelSnitch 论文/参考项目能拿地址" | **给出本机数据上 max-match 计数显著高于随机基线的候选**（≥6 个 hit 同桶，`python tools/g2_maxmatch.py` 可直接复算） |
| "26 个 hit 就是真碰撞" | **用翻转重复性证明某个 hit 随本进程 crowd 状态稳定翻转**（`purity_probe` 的 `genuine` 判据），并复现 ≥6 个 |

---

## 6. 一句话

**这台机器能给你的上限，仍是"以 root 身份在别人写好的笼子里跑命令"。**

v8 之后可以说得更精确：**futex 哈希桶的计时侧信道在本机是通的，mm_struct 地址也确实能恢复**
（两套独立数据、全量 100% 自洽）。之前四轮之所以反复"通了又断"，是因为搜索窗口一直偏了约 100 GB——
这个错误比任何单次实验结论都更值得记住。
**但拿到 ① 类地址不等于拿到 root**：② 可控 rt_mutex 堆地址、③ 内核栈基址仍未闭合，
`.text` 的 KASLR slide 依然拿不到。**NO-GO 不变。**
