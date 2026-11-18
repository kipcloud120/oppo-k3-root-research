# 厂商维护类工具面盘点（响应审核意见 v006-2）

> 方法：设备只读列举（`ls -lZ` / `find -maxdepth 3`）＋ 策略侧判据（`tools/sepolicy_domain_audit.py`）。
> **0 次写操作、0 次刷写、0 次重启。**

## 0 一句话

`/vendor/bin`、`/odm/bin`、`/system_ext/bin` 里确实有一批维护/诊断工具，但
**本域（`u:r:oplus_wifi_service:s0`）对块设备权限为 0、无任何域转换**，
且**Android 用户态不存在 Sahara/Firehose/OEM Download 组件**。
⇒ "厂商工具 → 分区维护 → 解锁/刷写"这条方向在**当前策略与物料下不可达**，
可以正式排除，而不是"未审计"。

## 1 清单（只读列举，节选维护/诊断相关）

| 分区 | 条目 | 性质 |
| --- | --- | --- |
| `/odm/bin` | `bspFwUpdate` | BSP 固件更新（**shell 连 stat 都被拒**，标签不可读） |
| `/odm/bin` | `opposysd`、`self-init`、`setgsiprop`、`rpmbengclient_test` | 系统守护/工程/密钥 |
| `/odm/bin` | `iwpriv`、`iwpriv_vendor`、`wifi_diag`、`tinyplay_ftm` | Wi-Fi/音频工程命令（§22 已审） |
| `/odm/bin` | `init.oppo.wifi.sh`、`init.oplus.bsp_debug.sh`（172 KB）、`init.vendor.wifi.autochmod.sh` | 脚本（§28.4 已全文审 1,036 行） |
| `/vendor/bin` | `applypatch`、`KmInstallKeybox`、`SoterProvisioningTool`、`cfrtool` | 补丁/密钥/加密 |
| `/vendor/bin` | `athdiag`、`adpl`、`adsprpcd`、`cdsprpcd` | 诊断/DSP（§32 已判 FastRPC 面封闭） |
| `/system_ext/bin` | `hephaestus`、`hans`、`atlasservice`、`dpmd`、`diag_mdlog_system` | 私有服务（§19/§33 已审） |
| `/system_ext/bin` | `extractCurrentUefiLog`、`bspCriticalLog`、`criticallog`、`PmicHistoryClear` | 日志/PMIC 历史 |

## 2 四条判据（决定"能不能碰分区"）

| # | 判据 | 实测/策略原文 | 结果 |
| --- | --- | --- | --- |
| 1 | 能否**执行**厂商二进制 | `(allow oplus_wifi_service vendor_file (file (execute execute_no_trans …)))`；`vendor_shell_exec`、`vendor_toolbox_exec`、`netutils_wrapper_exec`、`wcnss_service_exec` 亦可 | **能**（这是本域最宽的一项授权） |
| 2 | 执行后能否**写块设备** | 该域 `blk_file` 规则：**0 条**（`block_device`/`system_block_device`/`userdata_block_device`/`frp_block_device` 全 ∅） | **不能** |
| 3 | 执行后能否**换域** | `typetransition` 中源为本域的条目：**0 条** | **不能**（一律 `execute_no_trans` 留在本域） |
| 4 | 能否提供**原始 IO / 卸载模块 / 改策略** | `capability` 仅放行 chown/fowner/fsetid/setgid/setuid/net_admin/net_raw/sys_module/sys_admin/sys_resource；`security` 类 0 条；`filesystem` 仅 `getattr` | 能力检查放行但**内核能力集不含 CAP_SYS_ADMIN/CAP_SETUID**，且无 `security`/`mount` 权限 |

⇒ 结论：**"能执行工具"与"能维护分区"之间隔着三道独立的门**（块设备 MAC、域转换、内核能力），
三道门在本机同时关闭。`bspFwUpdate` 即使被以本域身份拉起，也只能在 `vendor_file` 可写范围内活动。

## 3 EDL / Sahara / Firehose：不存在

全分区 `find -maxdepth 3`（`*sahara*` / `*firehose*` / `*edl*` / `*appsboot*` / `*prog_*` / `*qf*`）只命中：

```
/vendor/lib64/libqfp-service.so
/vendor/etc/init/init_qfp_daemon.rc
```

`init_qfp_daemon.rc` 全文：`service qfp-daemon /vendor/bin/qfp-daemon`，用途是
`/data/vendor/misc/qti_fp`、`/persist/qti_fp` 等**指纹**目录创建——**qfp = Qualcomm Fingerprint**，
不是 Flash Programmer。`init.svc.qfp-daemon = running`。

⇒ 结论：Android 用户态**没有**任何可直接触发 Sahara/Firehose 的组件；
EDL 只能由"关机/重启进入 EDL + 主機侧签名 programmer"这条**PC 侧**路径产生，
与本机 `oplus_wifi_service` 域无交集。审核意见 v006-2 的"两者不要混为一谈"成立。

## 4 与既有结论的衔接

- §22 已把 `iwpriv` / `myftm` 两支的过滤器与黑名单审到指令级（11 字符黑名单 + `\n` 绕过），
  本轮不重复；`/odm/bin` 里没有新的同类入口。
- §28.4 已把 `init.oppo.wifi.sh` 全文（1,036 行）审完；本轮新看到的
  `init.oplus.bsp_debug.sh`（172 KB）**未审**，但它位于 `/odm/bin`，
  其可执行标签与 `vendor_file` 不同（`ls -lZ` 对 shell 拒绝），且即便可跑也在本域内执行，
  不改变第 2 节的三道门。**列为缺口而非结论。**

## 5 缺口与可证伪条件

| 缺口 | 性质 | 重开条件 |
| --- | --- | --- |
| `bspFwUpdate` / `init.oplus.bsp_debug.sh` 的实现未读 | 物料限制（shell 读不到，需 root 侧物料或固件镜像） | 拿到 `/odm` 镜像或该文件的字节 |
| 是否存在以 `vendor_file` 标签存在、却自带 `setuid` 位的二进制 | 未逐一核（`ls -l` 在 `/vendor/bin` 未见 `s` 位） | 出现 `-rwsr-xr-x` 条目 |
| `qfp-daemon` 的接口面 | 未审（指纹方向，与主线无关） | 若指纹面进入主线 |
