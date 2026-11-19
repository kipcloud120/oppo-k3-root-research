# 接手摘要（v10.1：**审核 v010 响应 —— 唯一性转为脚本断言 + DCI 解析子树否证**，2026-11-19）

> 一页式入口。完整证据：`HANDOVER.md` §52（记账修补/复算）+ §51（DCI 审计）+ §50（M2 示踪实验）+
> §49（端到端验证）+ §48（G2 闭合）。分层判定 `CLOSURE.md`；审阅入口 `README.md`；
> 复算证据 `live_probe/ks_m2_tracer_summary_run{1,2}_v101.txt`。
>
> **v10.1 三句话**：
> ① **唯一性不再是人工结论**：`m2_tracer_analysis.py` 改为从全量分数直方图导出
>   `n_full / 次高分`，9/9 个示踪 **`n_full`=1、次高分恒为 3**（噪声地板），最优/次优相差 ≥10 个约束；
>   两个原在 1 GB 邻域出解者（run1/T3、run2/T3）已补扫 16 GB，同为全局唯一。
>   ⇒ §50 否证成立，理由升级为"可复算断言 + 分离度量化"。
> ② **`/dev/diag` DCI 解析子树静态否证**（§51）：三路回传均有"声明长度⇄实收长度"门，
>   缓冲追加前二次校验容量，子树内无 `copy_to_user`；余量 R1–R3。**§25.7 的 G1 办结。**
> ③ 四层 ROOT 判定不变：**NO-GO**（① 类已闭合，②③ 仍缺；M2 时间流锚定已否证）。

## 1. 当前结论（四层，不可混用）

| 层次 | 状态 |
|---|---|
| Wi-Fi 域内 Root UID 命令执行 | **已达成**（2026-11-18，§23） |
| 可用 root（脱离 SELinux 域） | **未达成**（§24 / §32） |
| 持久 ROOT | **未达成**，按约定不做持久化写入 |
| **GhostLock 内核地址泄露** | **① 类闭合（本次开机，§48/§49）**；② **未闭合**（v10 否证时间流锚定）；③ 内核栈基址仍缺 |

## 2. v10.1 本轮做了什么（2026-11-19，**纯离线，零上机**）

| 节 | 内容 | 结果 |
|---|---|---|
| §52.1 | `recover_mm()` 增 `_window_stats()`：`n_top/n_full/次高分/n_ge6`，返回 `UNIQUE-FULL` 或 `MULTI(...)`，逐行落盘 | 唯一性成为**程序级断言** |
| §52.1 | `spray_tracer_probe.c`：dummy 记实际成功数 + errno；新增 `posttracer` slabinfo 快照 | 编译通过，**待上机验证** |
| §52.1 | 新增 `tools/m2_unique_globals.py`：强制 16 GB 复核 W1 出解项 | 两项均 `UNIQUE-FULL` |
| §52.2 | 复用 `live_probe/ks_tracer_run{1,2}_*.txt` 重跑分析（~37 min/16 jobs） | **9/9 `n_full`=1，次高分恒为 3** |
| §52.3 | 口径修正三处 | 见下 |
| §51 | DCI 解析子树审计（`extract_dci_*` 全线） | **否证**；G1 办结 |

**§52.3 三处口径修正**：
1. "与喷射规模 K 无关" → **"未测得 K 的独立影响"**（run1 实际 K 仅 12 块；run2 两个 K=768 步骤中间示踪
   T2 缺失 ⇒ `d12/d23` N/A）。否证对象是**固定/线性 delta**。
2. 审核给出的 `d13 − 2·d01 = 3076` **成立**（页对齐复算：`d01=−70355`、`d13=−137634`），
   但**无记账基础**——`payload 16064 + shared_info 320 = 16384` 恰为 order-2，每包**恰好一块**。
3. mm slab（SLUB）与 `kmalloc_large`（`__GFP_COMP`）**不同分配域** ⇒ §50 是对**简单时间邻接模型**的强否证，
   不是对 buddy 所有邻接关系的穷尽否证。

## 3. 下一步（按性价比）

1. **[待上机]** 探针 v10.1 计数与 `posttracer` 快照验证（仅当要继续 M2 结构性讨论时才需要；
   时间流路线已关，不急于做）。
2. **[纯离线]** `extract_dci_ctrl_pkt` 控制语义（R1）与两条非 apps 入口（R2）——低优先，
   需先出现"这类逻辑面可兑现为提权"的理由。
3. **[维持]** ROOT NO-GO；生产级 GhostLock PoC 不做；②③ 未闭合前任何地址公式不构成提权。

## 4. 工具与物料入口

```bash
# —— 唯一性审计（v10.1，纯离线，无需设备）——
python tools/m2_tracer_analysis.py --prefix ks_tracer_run1_ \
    --meta live_probe/ks_tracer_meta_run1.txt \
    --out live_probe/ks_m2_tracer_summary_run1_v101.txt --jobs 16
python tools/m2_unique_globals.py --auto        # 对 W1 出解项强制 16 GB 复核

# —— DCI 子树审计（纯离线）——
python tools/kfn.py diag_process_single_dci_pkt
python tools/kfn.py extract_dci_log        # 0x10 路径与长度门
python tools/kfn.py extract_dci_events     # 0x60 路径与逐记录游标
python tools/kfn.py extract_dci_pkt_rsp    # 0x93/0x94 路径与扩容逻辑

# —— M2 示踪实验（v10 标准流程，需设备）——
python -m ziglang cc -target aarch64-linux-musl -O2 -static -pthread -o live_probe/spray_tracer_probe live_probe/spray_tracer_probe.c
export MSYS_NO_PATHCONV=1; adb push live_probe/spray_tracer_probe /data/local/tmp/spray_tracer_probeX
adb shell "mv /data/local/tmp/spray_tracer_probeX /data/local/tmp/spray_tracer_probe && chmod 755 /data/local/tmp/spray_tracer_probe"
adb shell /data/local/tmp/spray_tracer_probe          # ~6-8 min
```

## 5. 运营约定

- 设备 `PCGM00_11_F.16`（SDM710，6 GB，DRAM phys 从 2 GB 起，possible 0-7 ⇒ futex_hashsize=2048），
  未刷写/解锁/改分区。**mm 地址随开机变化，重启后需重扫；v10 示踪同样仅该次开机有效。**
- `/data/local/tmp` 已清空；本轮 v10.1 **零上机**，设备状态未变。
- 建议关闭 OTA：SPL/内核变化会使全部偏移与判据作废。
- 厂商二进制/镜像、第三方完整利用代码不入库；报告与脚本可入库。
- 新对话从本文件开始 → `HANDOVER.md` §52 → §51 → §50 → §49 → §48。
