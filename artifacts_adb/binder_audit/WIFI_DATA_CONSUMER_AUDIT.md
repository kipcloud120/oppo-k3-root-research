# Wi-Fi 可写面的高权限消费者审计（P1）

> 响应 `docs_archive/审核意见CHATGPT-v004.txt` 第七节 **P1**：
> "检查 `/data/vendor/wifi` 和相关 vendor 属性的高权限读取者，关注配置解析和权限混淆。
> 特别是 `system_server`、`wcnss_service` 和 `self_init` 的数据处理逻辑。"
>
> **本轮口径：策略层 + init rc + 运行态三源交叉，纯离线为主**（仅两次 `adb shell` **只读**查询：
> `ls -l /system/etc/selinux/`、`ps -A`；未 push、未写属性、未改任何文件）。
> 二进制级解析器审计**未做**，登记为缺口 G（§6）。

---

## 0. 结论（一句话）

**消费面（我们写文件 → 别的域读）不构成提权通道。** 三条前置门全部被策略封死，
且在**所有只读这些路径的域里，唯一持有 `system_server` binder 通道的是我们自己的域**——
信任边界的"高权限一侧"本就是我们。跨域收益是 **DAC 降级**（uid 0 → 1010/1000），唯一例外是 supplicant 域的 `keystore` 通道（§5 末），而它不构成 ROOT。

**残余风险只有一类**：消费端解析器的内存安全缺陷（0day 级），且即便命中，
落点仍在 uid 1010/1000 的域内，对该域**没有 `system_data_file` 写权、没有 `system_server` binder**，
所以**拿不到完整 ROOT**。

---

## 1. 方法与判据

| 源 | 用途 |
|---|---|
| `vendor_file_contexts` / `plat_file_contexts` | 二进制与配置的**标签**（决定域与可写性） |
| `.build/sepolicy/rc/**`（197 份 init rc） | 消费者的**真实路径、启动参数、uid/gid、capabilities、是否 disabled** |
| 5 份 CIL | 每个消费者域的 `binder` / `unix_stream_socket` / `file` 权限 |
| 设备 `ps -A`（只读） | 哪些消费者**在本机真在跑** |

**判据三段式**（缺一不可）：①我们能写这个文件 ②该消费者会读它 ③读到的内容能产生**超出本域已有权限**的效果。

---

## 2. 可写面（承 §24.4）与消费者全集

| 可写目标 | 落点 | 持有 `read` 的域 | 持有 `execute` |
|---|---|---|---|
| `wifi_vendor_data_file` | `/data/vendor/wifi(/.*)?` | hostapd、supplicant、wcnss_service、fstman、usage_hidl、vendor_autochmod、cnd、hal_wigig | **0** |
| `mnt_vendor_file` | `/mnt/vendor(/.*)?`（含 `persist/wlan`） | rild、ueventd、self_init、hal_audio/camera/health、wcnss_service 等 20+ | **0** |
| `vendor_oppo_prop` | 55 条前缀（`vendor.oplus.wifi.*`、相机、显示、vold serialno、modem dump） | 含 **`system_server`** | — |

> `execute` 全为 0 是 §24.5 的核心否定：**"写脚本/写 ELF → 等别人执行"在本机从策略层不成立**，
> 因此 `openssl_engine=` 这类"让消费者 `dlopen` 我们放的 .so"的经典链，**在第一步就断了**（dlopen 需要文件 `execute`）。

---

## 3. 三条前置门：全部封死

| 门 | 内容 | 判定 | 证据 |
|---|---|---|---|
| **连接门** | 能否与消费者直接通信（ctrl socket / HIDL / binder） | **封死** | 本域 `unix_stream_socket connectto` 目标只有一个：`init`（`(allow oplus_wifi_service init_30_0 (unix_stream_socket (connectto)))`）。**没有**到 `hal_wifi_hostapd` / `hal_wifi_supplicant` / `wcnss_service` 的任何 connectto ⇒ hostapd 的 `-g /data/vendor/wifi/hostapd/global` 全局控制口虽在**我们可写的目录里**，我们仍连不上 |
| **执行门** | 能否让消费者执行我们的代码 | **封死** | 两个可写文件类型上 `execute` 规则的域数 = **0**（§24.5）。`wpa_supplicant` 支持 `openssl_engine` / `pkcs11` 等加载外部模块，但被此门阻断 |
| **触发门** | 能否让消费者**重新读**我们刚写的文件 | **封死** | 唯一的"属性 → root 执行脚本"范式由 `sys.oplus.wifi.dump.trigger`（`system_prop`）驱动，本域**无 `set`**（§24.6）；`service triggerwifidump` 为 `disabled` + `oneshot`，只能由该属性启动 |

**结论**：所谓"跨域信任边界"在本机是**单向的**——数据可以流过去，但**控制流和代码流都流不过去**。

---

## 4. 逐消费者登记（含"本机是否真在跑"）

> **v2.18 实测更正（设备在环，见 `HANDOVER.md` §28）**：
> 下表原本基于 rc 文本。实测 `init.svc.*` 后：**`hostapd`、`fstman`、`fstman_wlan0`、`triggerwifidump` 在本机全部未定义（`[]`）**；
> 生效平台是 `ro.hardware=qcom`（不是 atoll）。同时**发现两个漏项**：`wifiserver`（`/odm/bin/init.oppo.wifi.sh`，root，开机跑）
> 与 `wifisar`（root，属性触发）——**本表集合不完备**，补登见 `HANDOVER.md` §28.3。
> 结论方向不变（更不可达），但**判据必须以 `init.svc.*` 为准**。

| 消费者 | 域 | 身份（rc 原文） | 本机运行 | 配置来源 | 判定 |
|---|---|---|---|---|---|
| `hostapd` | `hal_wifi_hostapd_default`（`typetransition init hal_wifi_hostapd_default_exec →`） | `user wifi` / `group wifi net_raw net_admin` / caps **NET_ADMIN NET_RAW** / `disabled` + `oneshot` | **否**（SoftAP 未开） | `-dd -g /data/vendor/wifi/hostapd/global`，**无 `-c`** ⇒ 配置走 ctrl/HIDL，非文件 | 不可达（连接门） |
| `wpa_supplicant` | `hal_wifi_supplicant_default`（`typetransition init hal_wifi_supplicant_default_exec →`） | `user wifi` | **是**（pid 6399） | `-O/data/vendor/wifi/wpa/sockets -dd -g@android:wpa_wlan0`，**无 `-c`** ⇒ 无文件配置路径 | 不可达（无文件消费） |
| `fstman` / `fstman_wlan0` | `fstman`（`typetransition init fstman_exec →`） | `user wifi` / caps **NET_ADMIN NET_RAW** / `disabled` + `oneshot` | **否**（探测时） | `-c /data/vendor/wifi/fstman.ini` ← **唯一"我们可写、且确为配置文件"的实例**（`vendor.qti.hardware.fstman@1.0-service.rc`） | **仍不可达，但理由要改（v2.17）**：二进制**存在**（`ls -l /vendor/bin/fstman` → *Permission denied* 而非 *No such file*）、服务定义**存在**（HIDL `IFstManager`）；本域对该 hwservice **无 `find`**、对 `fstman` 域**无 `binder call`** ⇒ 触发门 |
| `cnss-daemon` / `wcnss_service` | `wcnss_service` | `user system` / `group system inet net_admin wifi` / caps NET_ADMIN | 未见进程 | NV/persist 数据 | 不可达（连接门）；且其身份与域均不高于本域 |
| `oplus.usage-1-0`（transmessage） | 其 HAL 域 | `user system` / `group system wifi` | 未见进程 | `/mnt/vendor/persist` 等 | 同上 |
| `vendor_autochmod`（`init.vendor.wifi.autochmod.sh`） | `vendor_autochmod`（`typetransition init wifi_vendor_autochmod_exec process`） | `user root` / 脚本由 init 直接执行 | 按需 | 脚本内容在 `/odm`（只读） | 不可达（触发门）；其域只有 `vendor_data_file` 写 + `sysfs` 写 |
| `rild` / `ueventd` / `self_init`（`mnt_vendor_file` 读方） | 各自 | — | — | `/mnt/vendor/persist/**` | 见 §5：无 `system_server` 跳板，且写该类路径不可逆（§24 R1 禁令） |

**两个可直接落地的负结果**：

1. `wpa_supplicant` 与 `hostapd` 在本机**都没有 `-c <config>`**（rc 原文），配置经 ctrl/HIDL 传入
   ⇒ **"改配置文件让 supplicant/hostapd 按我们的意图工作"这条最常被担心的路径，在本机不存在**。
2. ~~唯一带 `-c /data/vendor/wifi/fstman.ini` 的 `fstman`，在本机型（atoll）上既无服务定义也无进程 ⇒ 实例死亡。~~
   **【v2.17 更正：本条撤回，两处都错】**
   (a) **平台锚点错**：本机 SoC 是 **SDM710**；`atoll` 在公开 Qualcomm 命名里对应 SM7125/720G 一系（评审 v0041 第四节指出）。
   用 `init.wlan.atoll.rc` 判定本机部署情况属**未经证实的机型映射**；正确依据是 `ro.hardware` 决定导入哪一份 = **G-W5**。
   (b) **"无服务定义/无进程"→"未部署"错**：`ls -l /vendor/bin/fstman` 返回的是 *Permission denied*（`fstman_exec` 的 getattr 被 MAC 拒），**不是 No such file**；
   且 `vendor.qti.hardware.fstman@1.0-service.rc` 明确定义了 `fstman` 与 `fstman_wlan0`（`-c /data/vendor/wifi/fstman.ini`，HIDL `IFstManager`，`disabled`+`oneshot`）。
   ⇒ 正确结论：**实例存在、探测时未运行，但本域无法触发**——本域 `hwservice_manager find` 只对 `oplus_wifi_hal_service` 生效（§25.9），对 `hal_fstman_hwservice` **无权限**；
   对 `fstman` 域也**无 `binder call`**。**触发门仍然成立，但机制是"名字查找 + binder"，不是"未部署"。**

---

## 5. 决定性判据：跳板方向是反的

对 §2 消费者全集逐个核对"能否 `binder` 到 `system_server` / `init` / `vold` / `installd`"：

| 域 | binder 可达目标（全量） | `system_data_file` 写 |
|---|---|---|
| `hal_wifi_hostapd_default` | **无任何 binder 规则** | 0 |
| `hal_wifi_supplicant_default` | `hwservicemanager`、**`keystore`**、`wifi_keystore_service_server` | 0 |
| `wcnss_service` | `hwservicemanager`、`vndservicemanager`、`vendor_per_mgr`（仅 `connectto init`） | 0 |
| `vendor_autochmod` | **无任何 binder 规则**（仅 `connectto init`） | 0 |
| `fstman` | `hwservicemanager` | 0 |
| **`oplus_wifi_service`（本域）** | **`system_server`（`binder call transfer`）**、`hwservicemanager` | 0 |

⇒ **在这批域里，唯一能向 `system_server` 发 binder 的是我们自己。**
所谓"低信任数据被高权限组件消费"的模型，在本机的实际形态是：
**我们（uid 0、能呼 system_server）写数据 → uid 1010/1000、呼不到 system_server 的域去读。**
即便读方被完全控制，其能力集也是本域的**子集**（caps 上 hostapd 的 NET_ADMIN/NET_RAW ⊂ 我们的 `0x13000`），
**这是一次降级，不是提权。**

**唯一例外（必须点出，否则就是过度否定）**：`hal_wifi_supplicant_default` 持有
`(allow hal_wifi_supplicant_default keystore_30_0 (binder (call transfer)))` 与
`wifi_keystore_service_server` 通道，**本域没有**。⇒ 若能在 supplicant 域内执行代码，
获得的增量是"以 supplicant 身份使用 keystore"（限于 supplicant 自己的别名空间），
以及 `/dev/wlan` 的 nl80211/NET_ADMIN 操作（我们 caps 已有 NET_ADMIN，但设备节点未必有）。
**这两项都不构成 ROOT**：该域无 `system_data_file` 写权、无 `system_server`/`vold` binder，
进不去 `/data/system`、装不了 `su`、改不了 `/system`。

---

## 6. 残余风险与缺口（不得外推）

| # | 内容 | 说明 |
|---|---|---|
| G-W1 | **消费端解析器的内存安全缺陷** | 未做二进制级审计（需要逐个反编译 supplicant/hostapd/cnss-daemon 的 ini/bin 解析器）。这是本面**唯一**的残余风险类，且属 0day 级 |
| G-W2 | `vendor_oppo_prop` 的**值语义** | 55 条前缀中含相机/显示/vold serialno/modem dump；`system_server` 是读方。已确认无"属性值被当命令/路径解释"的**策略层**证据（§24.6），但**值语义**未逐条审计 |
| G-W3 | `mnt_vendor_file` 的二进制解析 | `rild`/`self_init` 读 `persist` 下的 modem/NV 数据；写该类路径跨重启持久化（§24 R1 **禁止写实验**），只能静态看解析器 |
| G-W4 | 本机实际生效的 rc 子集 | 197 份 rc 覆盖多机型（atoll/bengal/holi/kona/lahaina/lito/msmnile…）。**v2.17 更正：先前用 `atoll` 当本机锚点是错的**——本机 SoC 为 SDM710，`atoll` 公开对应 SM7125/720G 一系 |
| **G-W5** | **SDM710 实际导入的 rc 是哪一份** | 依据是 `ro.hardware`，不是机型名。需一次只读查询：`getprop ro.hardware` + `ls /vendor/etc/init/hw/`。**本轮设备离线（`adb devices` 返回空），未执行** ⇒ 这是评审 v0041 的 P1，也是本报告结论 3 唯一剩余的依据缺口 |

---

## 7. 判定与可证伪条件

### 7.1 判定

| 问题 | 答案 |
|---|---|
| 我们能写高权限消费者读的配置吗？ | **部分能**（`/data/vendor/wifi/**`、`/mnt/vendor/persist/**`） |
| 消费者会按我们的意图改变行为吗？ | **否**——supplicant/hostapd 无 `-c`；唯一带 `-c` 的 `fstman` **存在但不可触发**（无 hwservice find / 无 binder call，v2.17 更正） |
| 能让消费者执行我们的代码吗？ | **否**（可写类型上 `execute` = 0） |
| 能借消费者跳到更高域吗？ | **否**（消费者域均无 `system_server`/`vold` binder；唯一有该通道的是本域） |
| 收益上限是什么？ | **DAC 降级**（uid 0 → 1010/1000） + 同层域内代码执行 |
| 因此这条路能拿完整 ROOT 吗？ | **不能** |

### 7.2 可证伪条件（进 §7 主清单）

满足任一条才重开本面：

1. 本机 rc 实际生效版本中，`hostapd` 或 `wpa_supplicant` **带 `-c <我们可写的路径>`**（当前二者都没有）；
2. 本域获得 `hal_fstman_hwservice` 的 `hwservice_manager find` **或** 对 `fstman` 域的 `binder call`（当前二者皆无）；
3. 某消费者域获得 `system_server` / `vold` / `installd` 的 `binder call`（当前均为 0）；
4. 某可写类型获得 `execute`（当前 0 个域持有，见 §24.5）；
5. 出现影响上述消费者**配置解析器**的公开漏洞，且该消费者在本机运行。

**不重开**：向 `/data/vendor/wifi` 写"看起来像配置"的文件做试探、改 `persist` 下任何内容（跨重启持久化）。

---

## 8. 对审核意见 v004 第四节 P1 的逐条回应

| 审核意见 | 处置 |
|---|---|
| "检查 `/data/vendor/wifi` 和相关 vendor 属性的高权限读取者" | **完成（策略 + rc + 运行态三源）**：§2 全集、§4 逐个登记 |
| "关注配置解析和权限混淆" | **配置解析**：本机无文件配置消费实例（§4 两个负结果）；**权限混淆**：§5 证明跳板方向反了 |
| "特别是 `system_server`、`wcnss_service` 和 `self_init` 的数据处理逻辑" | `system_server`：作为 `vendor_oppo_prop` 读方，**只读值、不解释为命令/路径**（策略层证据 §24.6；值语义未逐条审计 = G-W2）。`wcnss_service`：`system` 身份、无 `system_server` binder，写面不构成提权（§5）。`self_init`：读 `mnt_vendor_file`，**该类路径禁写**（§24 R1），只能静态看解析器（= G-W3） |
| 建议先做静态、不要为验证假设而改设备配置 | **遵守**：零写入；`persist` 类路径全程只读推理 |
