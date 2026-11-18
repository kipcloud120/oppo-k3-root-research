# 探针登记：antirootdialog 的 Binder 可达性（2026-11-18，v006 回归 P1）

## 为什么必须实测

新引擎给出两个静态结论，与 §24.13 的"对 shell 不可达"直接冲突：

| 判据 | 规则原文 | 结论 |
| --- | --- | --- |
| `service_manager:find` | `(allow shell base_typeattr_511 (service_manager (find)))` | 允许 |
| `binder:call` | `(allow appdomain appdomain (binder (call transfer)))` | 允许（shell 与宿主域同属 `appdomain`） |

这两条都属于"旧工具能算出来、但报告结论写反了"的类型，因此必须用设备回显确认，
而不是继续在静态层互相引用。

## 探针设计（执行前登记）

- 命令：`service call anti_root_dialog 65535`
  - `65535` 越界事务码：**不触发任何业务方法**，只走 `find` + `call` 两道 LSM 检查，
    随后由服务端返回 "Unknown transaction code"。
  - 不写文件、不改属性、不传参、不重试。
- 风险：单次 Binder 事务，越界码。预期最坏结果是服务端抛异常，无状态变更。
- 判据（先登记，后执行）：

| 观测 | 判读 |
| --- | --- |
| 输出含 `Unknown transaction code 65535` 且无 AVC | **可达**：find + call 均放行，§24.13 的否证作废 |
| 输出含 `Permission denied` / `SecurityException` | **不可达**：静态结论错误，需回查规则 |
| 出现 `avc: denied { find }` 或 `{ call }` | 同上，并按 scontext/tcontext 定位是哪一道门 |

- 正对照：`service call alarm 65535`（一个 shell 常规可用的系统服务），
  用于区分"SELinux 拒"与"这个 shell 本来就不能 service call"。
- 采集：`logcat -d` 中 `avc` 行（`dmesg` 对 shell 不开放，见 §23.9）。
