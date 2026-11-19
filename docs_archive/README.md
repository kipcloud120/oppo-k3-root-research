# docs_archive/ — 历史文档存档（数值不可引用）

本目录保存研究过程中的中间文档。**除 `HANDOVER.md` 外，本目录任何文件中的数值与结论都可能已被后续实验推翻**，仅作过程证据保留。

引用规则：结论与数字以根目录 `HANDOVER.md` 为唯一权威；本目录文档若与 `HANDOVER.md` 冲突，以 `HANDOVER.md` 为准。

| 文件 | 主题 | 状态 |
|---|---|---|
| `HANDOVER_v1_2026-11-17_full.md` | 交接文档 v1 全文（13 轮增补版，3368 行） | **存档**。被 `HANDOVER.md` 取代，仅供回溯过程推理 |
| `F16_基线_与C17结论失效说明.md` | 声明 C.17 基线对本机失效 | 有效（基线澄清） |
| `K3_CVE解锁可行性分析.md` | 基于 C.17 的解锁路径分析 | **作废**。基线失效，主题也偏离本项目（文首已自述） |
| `F16_可移植性判定与攻击面重排.md` | 攻击面排序 | **部分作废**。binder 排第 ④ 的理由写"2019 前多已修"，该时间窗判断对 SPL 2022-04 不成立 |
| `F16_KGSL_CVE窗口排查.md` | 5 个 KGSL CVE + FastRPC 附注 | 结论已并入 `HANDOVER.md` §5.1 / §5.5 |
| `临时ROOT_GhostLock_移植性评估.md` | GhostLock 移植性初评 | **被取代**。见 `HANDOVER.md` §5.2（含 397 入口载体扫描） |
| `F16_ADB取证汇总.md` | 首轮设备取证汇总 | 设备事实仍有效；符号相关结论已被 §3.1 取代 |
| `F16_固件获取与C17清理记录.md` | 整包分段下载与提取方法 | 有效（方法论） |
| `ADB_K3_信息采集清单.md` | 采集项清单 | 有效（操作参考） |
| `k3_采集判读.md` | 首轮采集结果判读 | 有效（背景） |
| `OPPO_K3_机型代号与ROOT生态调查汇总.md` | 机型/生态调研 | 背景参考 |
| `ROOT_实施方案.md` | 早期 Magisk / 刷机路线 | **非本项目路径**（需解 BL，已移除） |
| `github_research.md` | 外部仓库与 issue 调研笔记 | 背景参考 |
| `审核意见CHATGPT.txt` | 第一次外部复审（主张 Binder 私有服务升 P0） | **已响应**：`artifacts_adb/binder_audit/AUDIT_REPORT.md`（五轮）、`HANDOVER.md` §14 |
| `审核意见CHATGPT-v001.txt` | 第二次外部复审（指出扫描器判重 bug、要求 GhostLock 上机验证 + 文档同步） | **已响应**：`GHOSTLOCK_RESCAN.md`（判重复核）、`GHOSTLOCK_NUL_ANALYSIS.md`（剩余两项静态收束）、`HANDOVER.md` §15 |
| `审核意见CHATGPT-v002…v006-2.txt` | 中间复审批次（服务面/策略引擎/入口层等 P0/P1） | 已响应，见 `HANDOVER.md` §14、§25–§37 |
| `审核意见CHATGPT-v007.txt` | 指向同类参考项目，建议补运行时地址（boot_id / KernelSnitch / ashmem） | **已响应**：`FEASIBILITY_v007.md`、`DUAL_TRACK_RESULT.md`、`live_probe/`；`HANDOVER.md` §38–§42 |
| `审核意见CHATGPT-v008.txt` | 收紧三类地址口径（mm 线性地址 ≠ KASLR slide）、分离 oracle/唯一性、重排研究优先级 | **已响应**：`FEASIBILITY_v008.md`（权威）、`FEASIBILITY_v007.md` §12.1 更正块、`HANDOVER.md` §43；四层判定不变 |
| `审核意见CHATGPT-v009.txt` | 指出 G2 统计量错误（哈希值 ≠ 哈希桶）、要求 hit 集纯度定量 | **已响应**：`HANDOVER.md` §46–§49（G2 闭合、端到端 32/32） |
| `审核意见CHATGPT-v010.txt` | 四个审计问题（唯一性断言 / dummy 计数 / 两种 order-2 不同源 / 文档版本口径）+ 建议转向 DCI 与栈地址观察面 | **已响应**：`HANDOVER.md` §52（脚本级唯一性断言、探针计数修补、口径修正）+ §51（DCI 解析子树否证）；四层判定不变 |
| `审核意见CHATGPT-v011.txt` | 撤回 DCI 为 P0；改推 Track A（栈地址）/ C（厂商驱动）/ B（对象锚点）三线 | **已响应（部分）**：§53（Track A 16 接口枚举 ⇒ 否证）+ §54（Track C 物料缺口：qcacld 不在镜像）；Track B 未开展 |

`HANDOVER.md` §6「负知识清单」汇总了 17 条**曾被认为是确定结论、后被自己推翻**的判断，以及推翻它们的依据——比删掉这些文档更有价值，也能防止后来者重走同一条死路。
