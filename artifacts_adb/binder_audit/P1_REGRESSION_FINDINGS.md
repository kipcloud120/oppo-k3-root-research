# P1 回归：三处口径翻转与四条保持（2026-11-18）

> 数据表由 `tools/sepolicy_regression.py` 生成 → `SHELL_ATTR_REGRESSION.md`。
> 本文是对该表的**判读**，不是重复。语义引擎 `tools/cil_policy.py`，用例 `tools/cil_selftest.py`（28/28）。

## 0 一句话

审核意见 v006 关于"历史 shell 权限结论必须用修好的解析器重算"的判断成立，且后果比预期更严重：
**§24.13 的 antirootdialog 否证被推翻——该服务对 shell 是可达的**。同时发现此前"能力集是墙"的
表述在**归因**上有误：`sys_module`/`sys_admin`/`setuid` 三者在 SELinux 层是**放行**的，
真正的墙在别处（§3）。

## 1 引擎修正分两步，不能合成一步

| 步骤 | 修正内容 | 单独修的影响 |
| --- | --- | --- |
| 一 | CIL 集合语义（`and` 交、`or` 并、`xor` 对称差、`not` 全集补、`all` 全集；不支持算子 → 审计失败） | `(not X)` 不再把 X 当成员 |
| 二 | 版本化名字（`X_30_0`）不再一律合并 | `(typeattributeset base_typeattr_179_30_0 ((all)))` 这类占位不再撑满基准属性 |

三档并存以便归因：**A** = legacy 语义 + 一律合并（= v2.23 原样）、**B** = 正确语义 + 一律合并、
**C** = 正确语义 + `alias`（新基线）。A 能复算出 §32.8 的 131/1,012 与 §24.13 的 89/307，
说明复刻是准的，C 与 A 的差异可归因到上面两条。

第 1 步的证据是构造用例：v2.23 的 `closure()` 对 `(not X)` 会**把 X 及其成员当作该属性成员**
（方向相反），并且丢掉其余真实成员（同时是上界与下界错误）。见 `cil_selftest.py` 第 10 组。

第 2 步的证据是策略原文：

```
plat_sepolicy.cil        (typeattributeset base_typeattr_179      (and (hal_lazy_test_server) (not (hal_lazy_test))))
plat_pub_versioned.cil   (typeattributeset base_typeattr_179_30_0 ((all)))
```

合并后该属性 = 全类型（4,078 个名字），凡是拿它当源/目标的规则会扩散到所有对象。
新口径取 `alias`：只有当 `X_N_M` **自身没有成员定义**时才视为 `X` 的别名——
这样 `(allow oplus_wifi_service system_server_30_0 (binder (call)))` 这类 vendor 侧规则仍然生效
（否则 vendor 策略整体失效），而 `((all))` 占位不会污染基准属性。

## 2 翻转一（最重要）：antirootdialog 对 shell 可达

| 判据 | 规则原文 | 旧（A） | 新（C） | 设备实证 |
| --- | --- | --- | --- | --- |
| `service_manager:find` | `(allow shell base_typeattr_511 (service_manager (find)))`<br>`base_typeattr_511 = (and (service_manager_type) (not (apex_service …)))` | ∅ | **find** | 事务送达 |
| `binder:call` | `(allow appdomain appdomain (binder (call transfer)))`，shell 与宿主域同属 `appdomain` | call,transfer | call,transfer | 事务送达 |

宿主：`ps -A -Z` → `u:r:color_system_service_app:s0 system 2833 com.coloros.exsystemservice`（uid 1000）。

探针（判据先登记，见 `p1_probes/PROBE_ANTIROOT_CRITERIA.md`；原文 `p1_probes/ANTIROOT_PROBE_20261118.txt`）：
`service call anti_root_dialog 65535`（越界事务码，不触发业务方法）返回
`Result: Parcel(Error: 0xffffffffffffffb6 "Not a data message")` —— 事务**已送达并收到回包**；
`logcat` 无 `scontext=u:r:shell:s0` 相关 `avc: denied`。

**结论**：§24.13 的"策略不给路径"不成立。性质回到 §19.3 的原始状态——
**可达，但实现未审计**（`com.oplus.exsystemservice` 的 dex 有 `IHephaestus`/`AntiRootDialog`
描述符字符串，但 4,068 个 class_def 中无一实现类；odex/vdex 仅 51/82 KB，不含完整 dex）。

这条不改写 ROOT 总体结论，但**"七服务覆盖度 7/7"必须退回 6/7**。

## 3 翻转二：`module_load` 的墙不是 SELinux

上一版把"加载模块"归因为"策略断链 + 能力集不足"。逐条复核后：

| 层 | 事实 | 判读 |
| --- | --- | --- |
| SELinux | `(allow oplus_wifi_service vendor_file (system (module_load)))`（vendor_sepolicy.cil，direct） | **放行** |
| 内核能力 | `CapEff=0x13000` 含 `CAP_SYS_MODULE`(bit16) | **具备** |
| 内核配置 | `CONFIG_MODULE_SIG=y` + `CONFIG_MODULE_SIG_FORCE=y` + `MODULE_SIG_ALL=y`（SHA-512） | **只接受厂商签名模块** |

同时 `(allow oplus_wifi_service self (capability (chown fowner fsetid setgid setuid
net_admin net_raw sys_module sys_admin sys_resource)))` 是 **direct** 授予——
即 `setuid`/`sys_admin`/`sys_module` 三道能力检查在 SELinux 层**全部放行**。

⇒ 归因修正：**墙在"模块签名 + 内核能力集"，不在 SELinux**。
`setuid(1000)` 失败的原因是 `CAP_SETUID` 不在 `CapEff`，不是策略不许。

**这不是新路径**（签名无法伪造），但它把"四堵墙"的措辞从"策略"改成"签名"，
而这两者的重开条件完全不同：**未来若出现签名绕过（或该内核配置变化），这条线立刻通**。
`CLOSURE.md` 的墙表据此修正。

## 4 翻转三：`hal_orms_hwservice` 的 `add,find` 是假阳性

中间口径（B：只修集合语义、仍合并版本名）给出 `add,find`，新口径（C）为 ∅。
差异全部来自 `base_typeattr_*_30_0` 的 `((all))` 占位撑满。
⇒ §19.3 对 orms/oiface 的"hwservice 不可达"**维持**。

## 5 四条保持不变（重算后仍成立）

| 结论 | 复核方式 | 结果 |
| --- | --- | --- |
| §32 FastRPC 两节点 `open` 并集 = ∅ | 新引擎重算 `qdsp_device`/`xdsp_device` chr_file | ∅，与实测 AVC 一致 |
| §32 正对照 `/dev/diag` | 同一查询 | 10 项权限齐全，正对照仍有效 |
| §24.1 无"写-执行"同域类型 | 对 13 个可写 file/dir 目标逐个查 `execute` | **0 个** |
| §24 无挂载/无安全类权限 | `filesystem` 仅 `getattr`；`security` 类 0 条 | 0 |

## 6 对 v006 其它两点的状态

- `xor`：本策略 5 份 CIL 的 `typeattributeset` 里 **0 处** `xor`、**0 处** `range`。
  引擎仍实现 `xor` 并在遇到 `range` 时**审计失败**（不静默），但这类构造当前不影响本机结果。
- "未解析表达式的数量与归属"：现在 `stats()['errors']` 恒为 0（全策略 2,135 条
  `typeattributeset` 全部可求值），并且 `validate()` 在**查询前**全量求值一遍，
  不再有"被查询到才报错"的静默路径。

## 7 新基线与旧数字的对照（供复核）

**A 口径是逐字复刻，不是近似**：它复算出 `shell` = 131 属性 / 1,012 allow、
`oplus_wifi_service` = 89 属性 / 307 allow，与 §32.8、§24.13 已发布数字**逐位相同**。
因此 C 列与 A 列的差异只可能来自那两处修正。

| 域 | 属性（A→C） | 适用 allow（A→C） |
| --- | --- | --- |
| `shell` | 131 → **752** | 1012 → **1271** |
| `oplus_wifi_service` | 89 → **775** | 307 → **347** |
| `system_app` | 149 → **842** | 1254 → **1513** |
| `hephaestus` | 96 → **796** | 691 → **718** |
| `mediaserver` | 106 → **795** | 665 → **706** |

属性数量普遍上抬 5–7 倍，原因是本策略里 **1,491 处 `typeattributeset` 含 `not`**，
而旧实现把 `(not X)` 整个算成空集或错集——即"属性继承面"被系统性低估。
allow 数的变化方向不一致（shell +259、hephaestus +27、mediaserver +41），说明旧口径
既漏算也误算，**不能简单用"旧的是下界"一句话概括**；这也是本轮改用逐条查询而非
只看总量的原因。

