# 接手摘要（v11.4：**③ 实测否证；C1 无输入路径；C2 长度维度闭合 14/14**，2026-11-20）

> 一页式入口。完整证据：`HANDOVER.md` §58（C2 长度维度闭合）+ §57（C2 首轮）+ §56（C1 可达性/C2 首扫）+ §55（上机只读取证/物料）+ §53（Track A 枚举）+ §54（Track C 边界）+
> §52（唯一性断言/复算）+ §51（DCI 否证）+ §50（M2 证伪）。分层判定 `CLOSURE.md`；审阅入口 `README.md`。
>
> **v11.1 三句话**：
> ① **③ 从"缺 oracle 未知"变成"已实测否证"**：逐项审完 16 条可达接口（`/proc/*`、`dmesg`、`sysrq`、
>   perf、BPF、tracefs、debugfs、`/sys/module/*/sections`、hung_task），**唯一含 sp 的输出是 oops 寄存器
>   dump，而 `panic_on_oops` 推断为 1（未实测）** ⇒ 触发即重启，不构成 oracle。按审核 v011 的停止标准，③ 子方向关闭。
> ② **Track C 的物料墙已拆**：解析 `WCNSS_qcom_cfg.ini` 的 qcacld-3.0 不在内核镜像内
>   （`hdd_*`/`qdf_*` 符号 0 个；`cfg80211` 907 个在镜像内属上游）。已用 `adb exec-out` 流式取回
>   `qca_cld3_wlan.ko`（`adb pull` 被 sync 服务的 SELinux 拒）：14,601,726 B、`vermagic=4.9.227-perf+`、
>   **符号表未剥离**，落在 `vendor_ko/`（已 gitignore）。调用链已钉到 `request_firmware`。
> ③ 四层 ROOT 判定不变：**NO-GO**（① 闭合；② 未闭合；③ 已实测否证）。

## 0. 本轮送审要点（v11.1–v11.4，对应 `HANDOVER.md` §55–§58）

**三个负结果**

| # | 结论 | 证据等级 |
|---|---|---|
| 1 | ③ 类（W 线程栈基址）**无可达 oracle** | 16 接口逐项枚举（§53）+ 本机实测（§55.1：`kstkesp/kstkeip=0`、`/proc/self/stack` 被 SELinux 拒） |
| 2 | Track C1（WLAN 配置解析）**无可达输入** | `/vendor` dm-verity `ro` + 驱动 `fwpath` 为空（§56.1，只读实测） |
| 3 | Track C2（KGSL）**长度维度 14/14 有界** | 逐点反汇编 + 分派表静态解析（§57/§58） |

**请重点质疑的三处推断**（我方标为"未实测/推断"，若成立需撤回）

1. `panic_on_oops` 推断为 1（§53.3/§55）：本机 `/proc/sys/kernel/panic_on_oops` 被 SELinux 拒读。
   若该值实为 0，oops 路径仍需"可从低权限触发的 oops"才成立——本机无已知。
2. `request_firmware` 的实际搜索路径：由 `fwpath` 为空**推得**回落到 `/vendor/firmware`，
   未在运行时抓取 `request_firmware` 的入参（无 ftrace 权限）。
3. KGSL 分派表 `size` 字段的位置（`(w0>>16)&0x3fff`）：由反汇编语义推定，
   与实际结构体声明的一致性未用源码核对（厂商未提供源码）。

**明确未覆盖（不要外推为"已否证"）**

- KGSL 结构层面：`gpuobj` id→对象生命周期、`sparse_bind` 索引区间、refcount/UAF、并发竞争。
- `sscanf`/item-handler 层（C1）：因无输入路径，未审。
- 其余 vendor `.ko`（41 个模块中只取回了 `qca_cld3_wlan.ko`）。

**建议审核回答的三个问题**

1. ③ 是否还存在"非 oops、非 perf、非 futex"的栈地址来源（尤其 vendor 驱动 debugfs 类接口）？
2. C1 的"无可达输入"是否成立？若认为不成立，请指出可写副本进入 `request_firmware` 的具体机制。
3. C2 的结构层面是否值得投入？若值得，建议先切哪个子目标（我方倾向 `gpuobj_free` 的 id 复用窗口）。

---

## 1. 当前结论（四层，不可混用）

| 层次 | 状态 |
|---|---|
| Wi-Fi 域内 Root UID 命令执行 | **已达成**（2026-11-18，§23） |
| 可用 root（脱离 SELinux 域） | **未达成**（§24 / §32） |
| 持久 ROOT | **未达成**，按约定不做持久化写入 |
| **GhostLock 地址缺口** | ① **闭合**（本次开机，§48/§49）；② **未闭合**（§50 时间流否证）；③ **已枚举否证**（§53，16 接口全查） |

## 2. v11 本轮做了什么（2026-11-19，**纯离线，零上机**）

| 节 | 内容 | 结果 |
|---|---|---|
| §53.3 | 16 个接口逐项判定：吐出什么 / 是否含栈地址 / 门 / 证据等级 | 无非 oops 的 sp 来源 |
| §53.4 | 两项 5 秒只读复核（`/proc/self/stat` 字段 28–30；`/proc/self/stack`） | **待授权** |
| §54.1 | WLAN 主机驱动是否在镜像内 | **不在**（0 个 `hdd_*`/`qdf_*`）⇒ 需 `.ko` 物料 |
| §54.2–54.3 | 镜像内可达厂商面 + Track C 排序（C1 WLAN .ko / C2 KGSL ioctl / C3 其余 .ko） | C2 可立即离线开工 |
| §51.4 R2 | DCI 非 apps 入口 | remote 侧门已确认（`len<0x2202`、`len+5 ≤ 剩余`）；transaction 侧为驱动自建帧 |
| §55 | **上机只读取证**（设备在环，零写入） | `kstkesp/kstkeip=0`、`/proc/self/stack` 被 SELinux 拒 ⇒ ③ 实测否证 |
| §55 | **`qca_cld3_wlan.ko` 已取回**（14.6 MB，未剥离符号） | `hdd_context_create → cfg_parse → qdf_ini_parse → qdf_file_read → request_firmware` |
| §56.1 | **C1 可达性判定**（只读实测） | `/vendor` 为 dm-verity **ro**、`fwpath` 为空 ⇒ 驱动只读 vendor 副本，**可写 persist 副本不进入解析器** |
| §56.3 | `cfg_parse` 形态核对 | 27 处拷贝全为 `strlcpy`（dst = 结构体固定偏移）；模块**未导入**无界 `strcpy` |
| §56.4 | **C2 KGSL 首扫**（新工具 `tools/kgsl_ioctl_scan.py`） | 54 入口 / 14 拷贝点（CONST 3 / REG 11） |
| §57 | **C2 首轮判读** | 6/8 REG 由「min 钳位」或「同尺寸分配」闭合；11/13 点带 `__check_object_size` |
| §58 | **C2 长度维度闭合** | 14/14 有界：`copy_in/out` = `min(_IOC_SIZE(cmd), 表项 size)`，adreno 表最大 0x20；`gpuobj_import` 第 2 点夹到 4 |

## 3. 下一步（C1 已降级，C2 为主）

1. **[纯离线 · 主线]** C2 结构层面：`gpuobj` 的 id→对象查找与生命周期、`sparse_bind` 的索引区间校验、
   refcount/UAF。KGSL 历史缺陷集中于此；长度维度已闭合（§58），不再重复。
   可达性已实测：shell（uid 2000）可 open `/dev/kgsl-3d0` 且 `DRAWCTXT_CREATE` 成功。
2. **[纯离线 · 低优先]** C1 的 `sscanf %s` 面：仅在有"可达输入路径"新证据后才值得做
   （当前 `/vendor` 只读、`fwpath` 空 ⇒ 无可达输入）。
3. **[登记不作]** 重载 `wlan` 模块并覆盖 `fwpath` —— 会拆掉 Wi-Fi（唯一 root 通道），且重启作废 ① 类地址。
4. **[维持]** ROOT NO-GO；不做 GhostLock 端到端 PoC；**不重启设备**。

## 4. 工具与物料入口

```bash
# —— Track A：接口语义核对（纯离线）——
python tools/kfn.py --list "stack"            # 栈相关符号
python tools/kfn.py proc_pid_stack            # 输出格式（[<%pK>] %pB）
python tools/kfn.py proc_pid_wchan            # %s（lookup_symbol_name）
python -c "d=open('firmware_F16/kernel.decompressed','rb').read(); print(d.count(b'[<%pK>] %pB'))"

# —— Track C：厂商面 ——
grep -cE "hdd_|qdf_" firmware_F16/kallsyms_out.txt      # 0 ⇒ qcacld 不在镜像
grep -c "cfg80211" firmware_F16/kallsyms_out.txt        # 907 ⇒ 上游无线栈在镜像内

# —— 唯一性审计（v10.1，纯离线）——
python tools/m2_tracer_analysis.py --prefix ks_tracer_run1_ \
    --meta live_probe/ks_tracer_meta_run1.txt \
    --out live_probe/ks_m2_tracer_summary_run1_v101.txt --jobs 16
python tools/m2_unique_globals.py --auto
```

## 5. 运营约定

- 设备 `PCGM00_11_F.16`（SDM710，6 GB，DRAM phys 从 2 GB 起，possible 0-7 ⇒ futex_hashsize=2048），
  未刷写/解锁/改分区。**mm 地址随开机变化**：重启后 ① 类需重扫、示踪数据作废。
- 本轮 v11 **零上机**；`/data/local/tmp` 已清空。
- 只读拉取 `.ko` 不写设备，但仍属设备操作，须先获授权；`persist/wlan` 写入永久禁止（跨重启持久化）。
- 建议关闭 OTA：SPL/内核变化会使全部偏移与判据作废。
- 新对话从本文件开始 → `HANDOVER.md` §53 → §54 → §52 → §51 → §50 → §49 → §48。
