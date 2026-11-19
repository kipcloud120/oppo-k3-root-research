# 接手摘要（v10：**M2 时间流锚定证伪 —— 页级邻接不可 groom**，2026-11-19）

> 一页式入口。完整证据：`HANDOVER.md` §50（M2 示踪实验）+ §49（端到端验证）+ §48（G2 闭合）。
> 分层判定 `CLOSURE.md`；审阅入口 `README.md`；闭合证据 `live_probe/ks_tracer_run{1,2}_*.txt`。
>
> **v10 三句话**：
> ① **M2 评估完成（否证）**：mm 示踪粒子法（新进程的 mm slab 页可被 futex oracle 恢复，
>   充当 buddy 分配流的示踪）实测两轮 9 个满命中唯一解——相邻 fresh slab 页落点
>   **1.0–5.5 GiB 随机散布、与喷射规模 K 无关**。参考项目（PCKM00）"mm 锚 + 固定 delta"
>   的时间邻接前提在本机（52h 开机、碎片化 buddy）**不存在，路线证伪**。
> ② **结构事实修正**：kmalloc 缓存至 8192 为止 ⇒ 16 KB skb data 走 `kmalloc_large`
>   **直连 buddy（order-2）**，每包恰一块，无 SLUB 中间层；`SO_RCVBUF` 被 rmem_max 钳制
>   ⇒ **每 socket 只装 ~12 个 16 KB 包**（§44.1"3072/轮"= 256×12 的由来）；THP 未启用。
> ③ 四层 ROOT 判定不变：**NO-GO**（① 类地址已三重闭合，②③ 仍缺；M2 新增否证，
>   M1 进展不得推断 M2/M3）。

## 1. 当前结论（四层，不可混用）

| 层次 | 状态 |
|---|---|
| Wi-Fi 域内 Root UID 命令执行 | **已达成**（2026-11-18，§23） |
| 可用 root（脱离 SELinux 域） | **未达成**（§24 / §32） |
| 持久 ROOT | **未达成**，按约定不做持久化写入 |
| **GhostLock 内核地址泄露** | **① 类闭合（本次开机，端到端确认 §49）**；② **未闭合（v10 新增否证：时间流锚定不可行）**；③ 内核栈基址仍缺 |

## 2. v10 本轮做了什么（2026-11-19，同一次开机 uptime 52 h+）

| 节 | 内容 | 结果 |
|---|---|---|
| §50.1 | 离线结构审计：kmalloc 上限 8192 ⇒ skb data 直连 buddy；THP=n；mm_cachep order-2、仅 12 空闲对象 | 探针设计依据 |
| §50.1 | `spray_tracer_probe.c`：dummy 漂洗 + skb 喷射 + fork 示踪 + 共享 active 槽位 | 编译/推送/两轮运行通过 |
| §50.2 | run1（K≈0 对照）5 示踪全恢复；run2（K=768）4/5 恢复；9/9 满命中唯一解 | delta 全部 GB 级 ⇒ **线性流/固定 delta 证伪** |
| §50.2 | slabinfo 交叉验证：mm_struct slabdata 每步 +2，符合模型 | 示踪新鲜度确认 |
| §50.3 | 口径：M2 维持未闭合；split-pair 结构邻接不作为闭合依据（fork 分配序未审计 + skb 落点无观测 oracle） | 记账更新 |

## 3. 下一步（按性价比）

1. **[纯离线]** fork 路径 order-2 分配序审计（vmlinux 反汇编 copy_process：task_struct→栈→files/fs/sighand/mm 的 slab order 与顺序），评估 (栈, mm) 与 (skb, mm) split-pair 配对是否有确定公式——只有配对公式存在且可 groom 时，M2 才有结构性候选；注意 skb 落点仍无观测 oracle，公式无法实证，仅作理论边界。
2. **[可选][需设备]** 若做 ① 后需要实测配对：示踪法已可复用（`spray_tracer_probe` + `m2_tracer_analysis`，16 GB 宽窗 ~6 min/示踪）。
3. **[维持]** ROOT NO-GO；不做 GhostLock 端到端 PoC；② ③ 未闭合前任何地址公式不构成提权。

## 4. 工具与物料入口

```bash
# —— M2 示踪实验（v10 标准流程，需设备）——
python -m ziglang cc -target aarch64-linux-musl -O2 -static -pthread -o live_probe/spray_tracer_probe live_probe/spray_tracer_probe.c
export MSYS_NO_PATHCONV=1; adb push live_probe/spray_tracer_probe /data/local/tmp/spray_tracer_probeX
adb shell "mv /data/local/tmp/spray_tracer_probeX /data/local/tmp/spray_tracer_probe && chmod 755 /data/local/tmp/spray_tracer_probe"
adb shell /data/local/tmp/spray_tracer_probe          # ~6-8 min，产出 ks_tracer{0..4}.txt + ks_tracer_meta.txt
adb pull /data/local/tmp/ks_tracer_meta.txt live_probe/ks_tracer_meta_runN.txt
for i in 0 1 2 3 4; do adb pull /data/local/tmp/ks_tracer$i.txt live_probe/ks_tracer_runN_$i.txt; done
adb shell "rm /data/local/tmp/ks_tracer*.txt /data/local/tmp/spray_tracer_probe"
python tools/m2_tracer_analysis.py --prefix ks_tracer_runN_ --meta live_probe/ks_tracer_meta_runN.txt \
    --out live_probe/ks_m2_tracer_summary_runN.txt --jobs 12    # 64B 网格；1GB 簇窗 → 16GB 宽窗自动放宽

# —— v9 端到端预测验证（M1 标准流程，见 §49 / v9 摘要）——
#   e2e_predict_probe + g2_maxmatch 窗口恢复 + ks_hold_ans 回填（13.6 s 唯一解）
# —— 旧探针（G1 判据/纯度/迁移，仍可复用）——
#   live_probe/purity_probe.c / bucket_scale_probe.c / spray_probe.c
```

## 5. 运营约定

- 设备 `PCGM00_11_F.16`（SDM710，6 GB，DRAM phys 从 2 GB 起，possible 0-7 ⇒ futex_hashsize=2048），
  未刷写/解锁/改分区。**注意：mm 地址随开机变化，重启后需重扫；本轮示踪实验同样仅本次开机有效。**
- `/data/local/tmp` 本轮结束已清空（探针与结果均已回收，先取回后删）。
- 建议关闭 OTA：SPL/内核变化会使全部偏移与判据作废。
- 厂商二进制/镜像、第三方完整利用代码不入库；报告与脚本可入库。
- 新对话从本文件开始 → `HANDOVER.md` §50（v10）→ §49 → §48 → §47 → §46。
