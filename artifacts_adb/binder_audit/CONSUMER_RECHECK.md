# 策略级否证的逐条重算（2026-11-18，纯离线）

> 工具：`tools/conclusion_recheck.py`（新增）、`tools/cil_policy.py`
> 结构化结果：`.build/sepolicy/recheck.json`、`sweep_domains.json`、`find_diff_shell.json`
> 触发：§33.9 遗留项——"本域之外的域/结论是否也被旧引擎低估"。

## 0 一句话

四条核心否证（写-执行、挂载/安全类、域转换、属性触发）在修正后的引擎下**全部维持**；
但 §26 的一条**支撑性前提**被推翻：**消费者域并非"都没有 `system_server` binder"**——
hostapd / supplicant / fstman 都有（经 `hal_*_server → hal_*_client` 回调规则）。
§26 的结论仍然成立，但成立的理由必须换成 §28 的实测事实（服务未运行、无 `-c` 配置），
不能再引用"没有通道"。

## 1 为什么要重做

§33 只回归了 `shell`、七个私有服务域与本域。其余否证属于**最脆弱的论证形式**：
"全量表里没有这一行"。而 §33 已经证明该形式会出错（antirootdialog）。所以本轮把每条否证
重新编码成**可执行判据**，在 A（v2.23 口径）与 C（新基线）下各跑一遍。

额外改进：消费者集合不再手工列举，改为**从策略反推**——"对本域可写的每个类型持有
read/open 的域"。这直接回应了审核意见长期批评的"枚举完备性"。

## 2 四条核心否证：全部维持

| # | 判据 | A（v2.23） | C（基线） | 结论 |
| --- | --- | --- | --- | --- |
| R1 | 本域可写类型上持有 `execute` 的域 | ∅ | **∅** | §24.1 写-执行链仍不成立 |
| R3 | 本域 `unix_stream_socket connectto` 目标 | 仅 `init` | 仅 `init` | §26 门 1 不变 |
| R4 | 本域可写属性类型 | 仅 `vendor_oppo_prop` | 仅 `vendor_oppo_prop` | §26 门 3 不变 |
| R5 | 源为本域的 `typetransition` | ∅ | ∅ | §24.7 不变 |

R1 的"∅"是双向确认：不是"我们没找到消费者"，而是**13 个可写 file/dir 目标上，任何域都没有
`execute`**。这条是 §24 的核心否定，现在是新引擎算出来的。

## 3 §26 的前提被推翻：消费者**有** `system_server` 通道

### 3.1 枚举（从策略反推，不再手工列举）

C 口径下，对本域可写类型持有 read/open/getattr/map/search 的域共 **135 个**（A 口径 107 个）。

其中**能 `binder call system_server`** 的（部分）：

```
hal_wifi_hostapd_default        call,transfer      ← §26 明确点名"没有"
hal_wifi_supplicant_default     call,transfer      ← 同上
fstman                          call,transfer      ← 同上
hal_face_oppo / hal_fingerprint_oppo / mediaserver / installd / keystore / location …
wcnss_service                   ∅                  ← §26 这点是对的
vendor_autochmod                ∅                  ← 同上
```

### 3.2 规则原文（方向已核对）

```
(allow hal_wifi_hostapd_server   hal_wifi_hostapd_client   (binder (call transfer)))
(allow hal_wifi_supplicant_server hal_wifi_supplicant_client (binder (call transfer)))
(allow hal_fstman_server          hal_fstman_client          (binder (call transfer)))

hal_wifi_hostapd_client     = { system_server }        # 属性成员就是 system_server
hal_wifi_hostapd_server     = { hal_wifi_hostapd_default }
```

即 AOSP 的 HIDL 回调方向："server 可回调 client"。这里 client 集合的**唯一成员就是
`system_server`**，所以 hal 侧确实持有通往 `system_server` 的 `binder:call`。
⇒ §26 那句"读这些路径的域**全部没有** `system_server` binder，唯一有的是本域"**不成立**。

### 3.3 但 §26 的结论为什么仍然成立

跳板要成立需要三步，缺一不可：

| 步骤 | 判据 | 结果 |
| --- | --- | --- |
| ① 通道 | 消费者能 `binder call system_server` | **成立**（hostapd/supplicant/fstman 都有） |
| ② 触发 | 我们能让该消费者**读我们写的文件并当配置解析** | **不成立**：`init.svc.hostapd/fstman = []`（§28.2 实测未运行）；supplicant/hostapd 均无 `-c <path>`；fstman 带 `-c` 但本域无法触发 |
| ③ 能力 | 该消费者解析后能做到我们做不到的事 | 未知（解析器未审，G-W1） |

⇒ **结论不变，但承重墙从 ① 换成了 ②。** 这不是文字游戏：①的失效条件是"策略加一条规则"，
②的失效条件是"rc 改一个参数"。两者重开概率差一个量级。

## 4 旧引擎对本域"服务可达性"的低估：0 → 303

`findable(dom)` = 该域能 `service_manager:find` 的服务类型集合（按目标侧属性展开）。

| 域 | A | C | 说明 |
| --- | --- | --- | --- |
| `shell` | **0** | **303** | 其中 300 个 `*_service`，OPPO 私有 27 个 |
| `oplus_wifi_service` | 0 | 0 | §27 的"零规则"结论在新引擎下**依然成立** |

shell 侧 303 个里包含 `anti_root_dialog_service`、`hephaestus_service`、`hans_service`、
`horae_service`、`oiface_service`、`atlas_service`、`OPPO_service`、`color_accesscontrol_service` 等。

⇒ **§24.13 的 antirootdialog 漏算不是孤例，而是"shell 的服务可达面整体为 0"这个错误的一个切片。**
旧引擎把 `base_typeattr_511 = (and (service_manager_type) (not …))` 算成了近空集。

## 5 全域扫描：还有没有下一个 antirootdialog？

对 480 个域逐个比较 A 与 C 的画像（适用 allow / `service_manager find` 规则数 /
`binder call` 规则数 / 可执行类型数）：

| 指标 | 0→N 的域数 | 说明 |
| --- | --- | --- |
| `service_manager find`（规则级） | **1** | 仅 `vzwomatrigger_app`（find 0→4）；其余域的 find 规则在 A 下就是非零，差异在**目标可达性**，已由 §4 单独量化 |
| 可执行类型数 | **0** | 无任何域"从无 exec 变成有 exec" |
| `binder call`（规则级） | **0** | 同上 |

`binder call` 减少的域 6 个（`init` 3→2、`installd` 5→4、`iorapd` 7→6、`isolated_app` 9→8、
`vold` 18→17、`webview_zygote` 1→0）——均因 `((all))` 占位不再污染，属**收紧**，方向安全。

⇒ **没有发现第二个"antirootdialog 级"的翻转。** 但要注意本扫描是**规则级**指标，
只能保证"没有整类权限的从无到有"；目标级的差异仍以 §4 的 `findable()` 方式单独核过。

## 6 纪律（写进 §34 的负知识）

1. **"某域没有 X 权限"必须用集合求值给出，不能用"没搜到以它命名的规则"。**
   本族错误已出现三次（§24.13 两处、§26 一处）。
2. **"某实现不存在"必须先证明索引完备**：dex 被 strip 后 `source_file` 为 0/4,068，
   按名字搜不到不等于不存在（见 `P2_ANTIROOT_IMPLEMENTATION.md` §1）。
3. **跳板类结论要分开写"通道 / 触发 / 能力"三步**，并指明每一步各自的失效条件。
   混在一起写会导致"前提被推翻、结论却看起来没变"这种难以复核的状态。
