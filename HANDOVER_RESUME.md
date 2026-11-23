# 接手摘要（**v13.2：WLAN 调用链审计完成——候选 A 重定向到 WEXT 私有面；98 handler / WEXT handler / FTM / vendor 分诊落档；项目五层验收；四层判定仍 NO-GO**，2026-11-20）

> 一页式入口。**先读本页 → [`CLOSURE.md`](CLOSURE.md)（五层验收=唯一最终判定）→ [`HANDOVER.md`](HANDOVER.md) §72（v13.2 完整记录）**。
> 完整历史：`HANDOVER.md` §72 + §71 + §70 + §69 + §68 + §67 + §66 + §63 + §62 + §61；slide 权威台账 [`KASLR_EVIDENCE.md`](KASLR_EVIDENCE.md)；B3 审计 [`GHOSTLOCK_B3_CONCURRENCY_AUDIT.md`](GHOSTLOCK_B3_CONCURRENCY_AUDIT.md)；v13.2 WLAN 交付见 §1 表。
> 外部审阅入口 [`README.md`](README.md)（v13.2 审阅须知）。

## 0. v13.2 一句话

**审核 v0132 的 P1「先证明调用链，再审漏洞」已按"证否 + 重定向"完成**：`0x89f1 → hdd_driver_command` 的调用链**存在**，但主语是 `wpa_supplicant` 的 `DRIVER` 通道，不是 `iwpriv`；`/odm/bin/iwpriv` 只发 **WEXT 私有**（`0x8BE0..0x8BFF`，32 handler / 223 参数），所以 **OPPO HAL `executeDriverCommand` 的真实内核端点是 WEXT 私有面**。受限 UID 0 代理对 WEXT SET 面"域满足"，但对 wpa 控制 socket **无 SELinux 权限** ⇒ 走不到 98 项 `hdd_driver_command`。**没有发现新的提权原语；可用 ROOT / 持久 ROOT 仍 NO-GO。**

---

## 1. v13.2 交付与结论（响应审核 v0132 §二–§七）

| 审核项 | 交付 | 结论（证据等级） |
|---|---|---|
| **P0** 文档收口 | ① `live_probe/DUMPSTATE_KASLR_PATH.md` 头部更正（"当前 boot slide 不可得"作废，§8 已取得；`KASLR_EVIDENCE.md` 为权威台账，本文件只记方法过程）；② `HANDOVER.md` 顶部 v13.2 口径；③ `README.md` 审阅须知 v13.2；④ 本文件；⑤ `CLOSURE.md` 五层验收 | 完成 |
| **P1-A** 用户态↔内核连接 | [`WLAN_IOCTL_CHAIN_AUDIT.md`](WLAN_IOCTL_CHAIN_AUDIT.md) | **连接成立但重定向**：`wpa_supplicant`（`android_priv_cmd`，4 处 ioctl；ctrl `"DRIVER "` → `wpa_drv_driver_cmd` → `ops+0x308`）→ `ioctl(0x89f1)` → `hdd_ioctl@0x38050` → `hdd_driver_command@0x38320`；`/odm/bin/iwpriv` **不发** `0x89f1/0x89fd`（指令级） |
| **P1-B** 98 项 handler | [`WLAN_HANDLER_AUDIT.md`](WLAN_HANDLER_AUDIT.md) + [`WLAN_RESIDUAL_AUDIT.md`](WLAN_RESIDUAL_AUDIT.md) + `handler_audit.csv`（98 行） | **0 个内存安全反例**（无无界 `%s`、无输入长度入拷贝、栈槽重叠 0）；5 项残留收口（`MAXTXPOWER` 值域 [-100,100]；4 个 `FMT-UNRESOLVED` 全为 `%31s`/`%d`）；2 个**非内存破坏**反例：H1 `SETMCRATE` 未检返回、H2 `MAXTXPOWER` 解析失败读未初始化栈（受值域门约束） |
| **P1-B 追加** 代理真实可达面（WEXT 23 父项 + 101 子命令） | [`WLAN_WEXT_HANDLER_AUDIT.md`](WLAN_WEXT_HANDLER_AUDIT.md) + [`WLAN_WEXT_HANDLER_AUDIT_2.md`](WLAN_WEXT_HANDLER_AUDIT_2.md) + `wext_audit(_2).csv` | **全部收口：21 有界 / 2 无功能 / 0 未决；0 越界读写反例**；更正首轮 12 个 SET/GET 方向误判（偶数=SET 才用 `set_args`）；`0x8BFE` 8 B 空桩、`0x8BFF` extra=5 B；信息泄露方向关闭；剩余为下游 value 域/INI 配置门（WEXT-2 §4） |
| **P1-C** 独立安全价值 | 同上两份 §结论 | 三分类：`executeDriverCommand → hdd_driver_command` **不存在⇒关闭**；`wpa_supplicant → 0x89f1` 连接存在但**代理不可达**；WEXT 私有面为代理可达面，价值是"扩展受控面"而非"首次 uid 0" |
| **P1-D** 受限 UID 0 代理路径 | `WLAN_IOCTL_CHAIN_AUDIT.md` §4 | 代理可执行 `iwpriv` + `net_admin` ⇒ WEXT SET 域满足；**无 `wifi_vendor_wpa_socket` allow** ⇒ wpa 通道关闭；shell 无 `wcnss_service_exec` 执行权；`0x89f1` 内核层无 CAP 门，但 shell 的 `neverallowx` 生效性**未决** |
| **P2** FTM | [`WLAN_FTM_AUDIT.md`](WLAN_FTM_AUDIT.md) + [`WLAN_RESIDUAL_AUDIT.md`](WLAN_RESIDUAL_AUDIT.md) | `0x89fd` 仅 `conparam==5` 受理（`0x38138/0x38144`）；正常启动 `init.wlan.target.rc` 无 con_mode 参数（默认 0），运行期改 con_mode 触发整驱动模式重启；**U2 已证 `myftm`/`ftmdaemon`/`ftmtest` 全部走 nl80211、不导入 ioctl（myftm）或 ioctl 只落 NFC/BT/tty ⇒ 固件无 `0x89fd` 调用方（收紧为 (a)）**；U1 已证 HAL 9 个 HIDL 方法**无方法级权限门**（89 个 PLT 导入无 caller/uid 检查、`.text` 0 条 `svc`） |
| **P3** vendor 分诊 | [`VENDOR_SURFACE_MATRIX.md`](VENDOR_SURFACE_MATRIX.md) | 37 个 `.ko` / **32 个实际加载**（`/proc/modules`）；非 WLAN 模块中"真实加载 + 用户态接口 + 两主体可达"合格者 **0** |
| **P4** GhostLock 长期冻结 | 冻结维持；独立 G5/T3 会话给出 ② 机制性 NO-GO 的设备证据（[`HANDOVER_G5_T3_2026-11-20.md`](HANDOVER_G5_T3_2026-11-20.md)） | 冻结，不重开；G5/T3 结论以该独立文档为准，不入本文五层验收 |
| **P5** 总验收 | `CLOSURE.md` §1 五层验收 | 已达成 3 / 已否证 5 / 阶段性关闭 3 / 已完成审计 4 / 条件性关闭 1 / 分诊 1 / 未解决 2 |

**证据等级纪律**：`指令级`（本机 `.ko` / 固件二进制反汇编）、`源码级`（厂商内核树 `net/*`/`wext-priv.c`）、`策略级`（CIL）、`取证级`（设备文本）；正文逐条标注，未标注不引用。

---

## 2. 五层验收（摘要；唯一最终判定见 `CLOSURE.md` §1）

| 层 | 条目 |
|---|---|
| **已达成** | ① Wi-Fi 受限 UID 0 命令执行（§23，两次回显）；② dumpstate 取得当前 boot `.text` slide = `0x1953600000`（`KASLR_EVIDENCE.md`）；③ KernelSnitch Direct Map `mm_struct` 地址观测（G1/G2） |
| **已完成否证** | GhostLock A（无 oracle）、B1（无锚点）、B2（固定 delta 否证）、B3（G4 并发语义否证）、futex WARN 68 候选全排除 |
| **已阶段性关闭** | KGSL 非 sparse 生命周期（K2）、KGSL sparse（KO-1 本机不可达）、WLAN 配置链 C1 |
| **已完成审计** | WLAN `0x89f1` 调用链（主语 wpa_supplicant）、98 项 `hdd_drv_cmds` handler、WEXT 23 父项 + 101 子命令（代理可达面）、其余 vendor 模块分诊 |
| **条件性关闭** | FTM `0x89fd`（需 `con_mode==5` + 驱动模式重启） |
| **未解决** | **可用 ROOT（域逃逸）NO-GO**；**持久 ROOT NO-GO** |

**四层判定（不可混用）**：Wi-Fi 域内 Root UID 命令执行 = 已达成；可用 root = 未达成；持久 ROOT = 未达成；GhostLock 地址缺口 = ① 闭合、②/③ 冻结（B3 已否证）。

---

## 3. 下一步（v13.2 收口后的可选项，均需用户决定）

1. **[已完成]** 阶段 4 前半：WLAN 调用链（`WLAN_IOCTL_CHAIN_AUDIT.md`）。
2. **[已完成]** 阶段 4 后半：98 handler + WEXT handler 审计（首轮两份报告；续做 `WLAN_RESIDUAL_AUDIT.md` + `WLAN_WEXT_HANDLER_AUDIT_2.md`）；**[未做]** 动态验证（`iwpriv` 在代理域内的只读枚举、`0x89f1` 是否真被 shell 拒绝）——**需独立授权**。
3. **[已完成]** 阶段 5：`CLOSURE.md` 五层验收（已同步续做结果）。
4. **[已完成]** WEXT 深审收口：23 父项 + 101 子命令 = 21 有界 / 2 无功能 / 0 未决（`WLAN_WEXT_HANDLER_AUDIT_2.md`）；剩余只是下游/配置级抽样（该报告 §4 的 2/3/5 条）。
5. **[可选，需授权]** 下游抽样：`0x8BE5` 17 路输出函数是否真按上限截断、`wma_cli_set_command` 对 `value` 的二次解释、INI `wext_control` 默认值（决定可达性，不决定有界性）。
6. **[维持]** ROOT NO-GO；不做 GhostLock 端到端 PoC；**不重启**（重启需单独、逐次授权）；建议关闭 OTA；**不做任何动态 WLAN 输入测试**（审核 v0132 §三 P1-C 明文）。

---

## 4. 工具与物料入口（v13.2 新增）

```bash
cd "D:/AI_tools/AI_Workspace/WBK_OPK_RT_CRA"

# —— v13.2 WLAN（纯离线）——
python tools/wlan_cmd_table.py                 # 98 项 hdd_drv_cmds（名称/handler/flag）
python tools/wlan_wext_table.py                # we_private 32 handler + we_private_args 223 条（父子映射）
python tools/ko_fn.py hdd_ioctl                # 0x89f1/0x89fd 两个 case
python tools/ko_fn.py hdd_driver_command       # 长度门/NUL/白名单/释放
python tools/scan_ioctl_const.py .build/odm_bin/iwpriv --vals 0x89f0,0x89f1,0x89fd
python tools/scan_ioctl_const.py .build/odm_bin/wpa_supplicant --vals 0x89f0,0x89f1,0x89fd
python tools/scan_ioctl_bin.py                 # 全固件二进制常量盘点（见文件头用法）
python tools/wlan_handler_scan.py              # 98 handler 结构化事实（CSV）
python tools/wlan_wext_scan.py                 # WEXT handler 扫描
python tools/wlan_wext_subcmd.py               # WEXT 23 父项/101 子命令（--args/--subcmd）
python tools/wlan_residual_scan.py             # 98 handler 残留 5 项（FMT 跨 bl 数据流）
python tools/hal_perm_gate.py                  # HAL HIDL 方法权限门（U1）
python tools/ftm_tool_surface.py               # FTM 工具通道判定（U2）

# —— 既有 ——
python tools/b3_audit.py                       # B3 并发语义审计
python tools/kgsl_lifecycle.py                 # KGSL 取/放点
python tools/kfn.py --list 'pattern'           # 符号查询
```

物料：`vendor_ko/qca_cld3_wlan.ko`（SHA `f45c1c1c…d00`）、`.build/vendor/vendor.img` / `.build/vendor/x/euclid/odm.img`（7-Zip 可解；已解 `bin`/`lib64`/`lib` 到 `.build/vendor_bins/`）、`.build/vendor_kernel_full`（内核源码）、`.build/sepolicy`（CIL）。

---

## 5. 运营约定（不变）

- 设备 `PCGM00_11_F.16`（SDM710，6 GB，futex_hashsize=2048），未刷写/解锁/改分区；**mm 地址随开机变化**。
- 上机授权已获得（2026-11-20），但**硬约束：不得重启**；重启是单独、逐次授权。
- 只读拉取 `.ko` 属设备操作；`persist/wlan` 写入永久禁止；**不做动态 WLAN 输入测试**。
- 建议关闭 OTA：SPL/内核变化会使全部偏移与判据作废。

---

## 6. 工作区并发写入事件与后续合并（2026-11-20 19:02 → 2026-11-23，务必知悉）

- v13.2 会话期间，一个**非本代理的并发写入方**（另一个会话/进程）在 19:02 创建了 `GHOSTLOCK_HEAP_RECLAIM_FEASIBILITY.md`（自称 "G5 ② 同页 slab 回收"）与 `tools/reclaim_model.py`，并**修改** `HANDOVER.md`/`README.md`/`CLOSURE.md`/`HANDOVER_RESUME.md`/`GHOSTLOCK_ADDRESS_SOURCE_MATRIX.md` 为 "v13.3" 口径，随后 **commit 并 push 到 `origin/main`（提交 `e370348`）**。
- 主代理当时的处置：本地 `git reset --mixed HEAD~1` 回到 `7d8c796`；把两份越界文件归档到 [`docs_archive/out_of_scope_v13.2/`](docs_archive/out_of_scope_v13.2/)（含 `README.md` 说明"未纳入判定、未复核"）；根目录文档恢复 v13.2 口径。
- **后续（已解决）**：G5 会话继续完成了设备侧 T1/T2/T3 验证，产出**独立**交接 [`HANDOVER_G5_T3_2026-11-20.md`](HANDOVER_G5_T3_2026-11-20.md)（结论：GhostLock ② **机制性 NO-GO**；T3 五次在 `sched_setattr` 处 panic）。两条线已通过 merge 汇合，`origin/main` 与本地当前同为 `ccd3663`（0/0）；根目录 G5 离线文档已移除、归档保留。**v13.2 的五层验收与四层判定不因该线改变**；G5/T3 的证据与结论以 `HANDOVER_G5_T3_2026-11-20.md` 为准，本文不重复引用其数值。
- **并发纪律（后续会话遵守）**：改根目录五份文档前先 `git status`；不要 push 与当前 HEAD 分叉的分支；G5/T3 这类独立研究线写独立 `HANDOVER_*.md`，不合并进 v13.2 收口文档。

---

## 7. 读法

新对话：本文件 → `CLOSURE.md` §1（五层）→ `HANDOVER.md` §72 → `WLAN_IOCTL_CHAIN_AUDIT.md` → 两份 handler 报告（`WLAN_HANDLER_AUDIT.md` / `WLAN_WEXT_HANDLER_AUDIT.md` + `_2`）→ `WLAN_RESIDUAL_AUDIT.md` → `WLAN_FTM_AUDIT.md` / `VENDOR_SURFACE_MATRIX.md` → 需要时回溯 §71/§70/§69/§66/§63/§62/§61。G5/T3 线单独读 `HANDOVER_G5_T3_2026-11-20.md`。
