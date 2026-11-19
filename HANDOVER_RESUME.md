# 接手摘要（v11.1：**③ 实测否证 + WLAN 模块已取回**，2026-11-19）

> 一页式入口。完整证据：`HANDOVER.md` §55（上机只读取证/物料）+ §53（Track A 枚举）+ §54（Track C 边界）+
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

## 3. 下一步（明日起点）

1. **[纯离线 · 已完成一半]** Track C1 首轮 triage（§55.3）：`cfg_parse` 是唯一必查点——
   27 处 `strlcpy` 的 **dst 尺寸逐处核对**（工具 `tools/ko_fn.py SYM --copy-sites`）。
2. **[纯离线 · 前置问题，先答再谈漏洞]** `persist/wlan/*.ini` 与 `/vendor/firmware/wlan/*.ini`
   的关系：驱动只走 `request_firmware`，可写副本必须经 root 脚本复制才能进解析器；
   若该复制存在且可被本域触发，才存在"可写 → 解析"链路（但写 persist 属跨重启持久化，**本项目禁止**）。
3. **[纯离线 · 可立即做]** KGSL ioctl 面系统枚举（C2）：`/dev/kgsl-3d0` 0666；判据 =
   任一 ioctl 的 `copy_from_user` 长度未与对象尺寸绑定。
4. **[可选上机 · 只读]** 用 `tools/wifi_exec.py` 在 `oplus_wifi_service` 域复核 `/proc/self/stack`
   （shell 域已拒；该域无 `CAP_SYSLOG`，预期仍拒）。
5. **[维持]** ROOT NO-GO；不做 GhostLock 端到端 PoC；**不重启设备**（重启作废 ① 类地址与示踪数据）。

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
