# P1 审计：同族 root 命令接口与入参过滤边界（2026-11-18，纯离线）

> 响应 `docs_archive/审核意见CHATGPT-v0021.txt` 第三节 P1（"检查另外三个 root 命令接口：
> `sendSupplicantCommand` / `runWiFiScript` / `catchSnifferLog`"）与第二节第 3 点（"补齐静态过滤路径"）。
> **全程未连设备、无写操作**；物料仅两个已入库二进制：
> - `vendor.oplus.hardware.wifi@1.1-service`（115,408 B，`.build/vendor/x/odm/bin/hw/`）
> - `oppo-wifi-service.dex`（`artifacts_adb/binder_audit/dex/`）
>
> 复现工具：`tools/wifi_slot_audit.py`（本轮新增，vtable 枚举 + PLT 解析 + ADRP/ADD 字符串回填），
> PLT 映射 `rela.plt` 第 i 项 ↔ `0x18d30 + 0x10*i`；Java 侧用 androguard `DEX` 逐方法 dump。

---

## 0. 结论摘要

| 项 | 结论 |
|---|---|
| 复评 P1 的三个接口 | **全部不构成新的 shell 可达攻击面**：`runWiFiScript` / `sendSupplicantCommand` 在全系统 Java 中**无任何调用方**（死入口）；`catchSnifferLog` 只接受 `(int,int)`，仅由 system_server 内部 SnifferMode 调用 |
| 新发现 A（重要） | **regex 黑名单不完整**：字符类仅覆盖 11 个字符，**缺 `\n` `\r` `` ` `` `<` `>` `\` 与引号**。因此**即便走"已过滤"的 iwpriv 分支，换行/反引号仍可穿越校验**——注入面不依赖 `myftm` 五字节前缀 |
| 更正 B | 旧文档"iwpriv 分支参数经 `to_string(int)` 转换"**不成立**：该分支是把**整条原始入参**裸拼到 `/odm/bin/iwpriv ` 之后再做 regex 校验。`wlan0 setMonChan <int>` 属于 `catchSnifferLog`（slot3），不是本分支 |
| 新发现 C（潜在） | `getIniVersion(String)` 直接把入参当路径 `fopen(path,"r")` 后回传文件内容 ⇒ **任意 root 读**。但无 Java 调用方，未构成本机可利用路径 |
| 判定 | Wi-Fi 面 **L1/L2 静态证据加强，L3 仍未证**；整体 no-go 不翻转，**不上机**（L3 需用户授权） |

---

## 1. vtable 与九类 HIDL 命令的完整映射

`vtable @0x1a0a0`（`.data.rel.ro`），槽位 2–10 依次对应 HIDL code 1–9：

| 槽 | 地址 | HIDL code | 方法 | 签名 | 生效命令模板 | 过滤 | 依据 |
|---|---|---|---|---|---|---|---|
| 2 | `0x90a0` | 1 | `changeConnectionMode` | `(int)` | `/vendor/bin/ifconfig wlan0 up`、`insmod … con_mode` | 无（入参为 int） | 日志串 `"Enter changeConnectionMode with connection mode %d"` |
| 3 | `0xad20` | 2 | `catchSnifferLog` | `(int,int)` | `tar -czvf … && rm -rf …`、`/odm/bin/iwpriv wlan0 setMonChan <to_string(u32)>` | 无（入参为 int） | 串 `@0x6e9c`、`@0x6e55`、`to_string` ×3 |
| 4 | `0x9684` | 3 | `resetConnectionMode` | `()` | 无（`kill`/`waitpid`/`SetProperty`） | — | 日志串 `"No child process found"` |
| 5 | `0x992c` | 4 | **`executeDriverCommand`** | `(String)` | ①`/vendor/bin/myftm <input[5:]>`（无过滤）②`/odm/bin/iwpriv <input>`（regex） | ①无 ②有（不完整） | §2 / §3 |
| 6 | `0xa0dc` | 5 | `setupFTMdaemon` | `()` | `/vendor/bin/ftmdaemon` | 无（固定串） | `0xa18c` 处引用 `/vendor/bin/ftmdaemon` |
| 7 | `0xa568` | 6 | `sendSupplicantCommand` | `(String)` | `/vendor/bin/wpa_cli <input>` | **有**（regex，不完整） | §4.1 |
| 8 | `0xa898` | 7 | `runWiFiScript` | `(String,String)` | `/vendor/bin/<script> <arg>` | **有**（前缀校验 + regex，不完整） | §4.2 |
| 9 | `0xb2ec` | 8 | `sendIniContent` | `(String)` | 写固定路径 `/mnt/vendor/persist/ini_temp.txt` | 路径固定 | 串 `@0x6ac5` |
| 10 | `0xb65c` | 9 | `getIniVersion` | `(String)` | `fopen(<input>,"r")` 后回传内容 | **无** | §5 |

> HIDL code 与槽位的对应关系由 `IOppoWifiService$Proxy` 各方法的 `const/4 v3, N` 直接读出：
> `catchSnifferLog=2`、`executeDriverCommand=4`、`sendSupplicantCommand=6`、`runWiFiScript=7`；
> 其余按 vtable 顺序与行为证据（日志串 / 参数类型 / 写入路径）唯一确定，code8/9 的"写/读"归属由
> `fopen` 模式与固定路径反推，标注为**行为推断**而非直接常量证据。

**全程序命令执行原语统计**（`--scan-exec`）：**无 `system`/`popen` 导入**，只有两组 `vfork`+`execv`：

| 包装器 | 入口 | exec 目标 | 调用点数 | 调用点 |
|---|---|---|---|---|
| W1 | `0x95b4` | `execv("/vendor/bin/sh",{sh,"-c",cmd,NULL})` | 9 | `0x91c8` `0x9864` `0x9cb8` `0x9e20` `0xa7c0` `0xac8c` `0xb0e8` `0xb124` `0xbd24` |
| W2 | `0xa390` | 同上 + `prctl(PR_SET_PDEATHSIG,9)` | 2 | `0xa2e4` `0xb1dc` |

`0xbd24` 的命令是**硬编码** `rm -rf /data/vendor/wifi/snifferlog.tar.gzip`（`@0x698d`），无入参。

---

## 2. `executeDriverCommand`：两条分支的真实形态（更正 B）

### 2.1 分支判据（复核一致）

```
0x9a04/0x9a20/0x9a38  "myft" + 第 5 字节 'm'  →  orr/cbz
0x9a5c  cbz w8, 0x9b7c        ; 前 5 字节 == "myftm" → myftm 分支
0x9a60  …                     ; 否则 → iwpriv 分支
```

### 2.2 iwpriv 分支（shell 实际可走的那条）

```
0x9a64/0x9ad0  cmd = "/odm/bin/iwpriv"            ; @0x696b，15 B
0x9b1c         append(" ", 1)
0x9b38..0x9b4c c_str() → strlen → 拷进 std::string（sp+0x18，**整条原始入参，无任何转换**）
0x9d58         append(sp+0x18, len)               ; 裸追加
0x9dac/0x9db0  sub_9f64(cmd)                      ; regex 黑名单校验
0x9dc8         tbnz w21,#0 → 0x9e08               ; 通过 → 执行
0x9e20         bl 0x95b4(cmd)                     ; W1 → sh -c
```

**更正**：`HANDOVER.md` §5 表与 `WIFI_P0_PARAMETER_TRACE.md` §5 把本分支写成
"`/odm/bin/iwpriv wlan0 setMonChan <to_string(int)>`、参数经整数转换"，**与本轮逐指令复核不符**：

- 本分支追加的是 `c_str()` 指向的**完整字符串**（`append(const char*, size_t)`），中间无 `atoi/strtol/to_string`；
- `wlan0 setMonChan ` 模板（`@0x6b6d`）+ `to_string(u32)`（`0xae8c/0xaee0/0xaf3c`）实际属于
  **slot3 `catchSnifferLog`**（`0xad20`，入参 `(int,int)`），两条路径此前被混为一谈。

该更正**不改变** `-3` 的归因结论（`-3` 仍=regex 命中/参数非法），但改变了"过滤前是否发生过类型收敛"这一前提：
**iwpriv 分支不做收敛，只依赖 regex**。这也意味着"参数被整数化所以安全"的解释从根上不成立。

### 2.3 myftm 分支（复核一致，无过滤）

`0x9bf4` 取 `input+5` → `0x9c40 append(" ")` → `0x9c64 append(input[5:])` → `0x9cb8 bl 0x95b4`。
`sub_9f64` 全程序仅 3 个调用点（`0x9db0` / `0xa78c` / `0xac58`），**均不在本分支**。

---

## 3. 发现 A：regex 黑名单不完整（本轮最重要的独立结论）

### 3.1 字符集逐字节确认

`sub_9f64` 的模式串固定在 `@0x6dcb`，长度 `0x0e`：

```
bytes: 5b 40 23 24 25 26 2a 5e 3a 3b 3f 7c 5d 2b 00
ascii: [ @ # $ % & * ^ : ; ? | ] +
```

**覆盖集合（11 个）**：`@ # $ % & * ^ : ; ? |`

**未覆盖且对 `sh -c` 有语法意义的字符**：

| 字符 | shell 语义 | 是否被拒 |
|---|---|---|
| `\n` (0x0A) | **命令列表分隔符**（等价 `;`） | **否** |
| `\r` (0x0D) | 空白/分隔 | 否 |
| `` ` `` (0x60) | **命令替换** | **否** |
| `<` / `>` | 输入/输出重定向（root 身份写文件） | **否** |
| `\` (0x5C) | 转义 | 否 |
| `"` `'` | 引用（可重组被拒字符，见下） | 否 |
| `(` `)` `{` `}` | 分组/子 shell（需配合 `;`/`\n`） | 否 |

⇒ 由于 `\n` 与反引号均不在黑名单，**"regex 校验通过"不等于"命令串是一个 token"**。

### 3.2 对 shell 可达路径的影响

`executeDriverCommand` 是**唯一**从 shell 可达的 HIDL 命令（§4.3），其 iwpriv 分支形态为：

```
cmd = "/odm/bin/iwpriv " + <整条入参>
```

入参含换行即构成两条命令。示例（静态推演，未上机）：

| 入参 | 组装后的 cmd | 校验 | 预期 shell 行为 |
|---|---|---|---|
| `myft -h; id` | `/odm/bin/iwpriv myft -h; id` | `;` 命中 → `-3` | 拒绝（历史结果一致） |
| `myft id \| logger` | `/odm/bin/iwpriv myft id \| logger` | `\|` 命中 → `-3` | 拒绝（历史结果一致） |
| `x\nid` | `/odm/bin/iwpriv x` ⏎ `id` | **无命中 → 通过** | 两条命令，均在 uid 0 上下文 |
| `` `id` `` | ``/odm/bin/iwpriv `id` `` | **无命中 → 通过** | 反引号内容先执行（输出作参数） |
| `x > /data/local/tmp/o` | `/odm/bin/iwpriv x > /data/local/tmp/o` | **无命中 → 通过** | 以 root 身份重定向写文件 |

**这一点比 myftm 分支更强**：不需要 5 字节前缀匹配，历史 4 次失败实验之所以失败，
是因为它们只尝试了 `;` 和 `|`（恰好都在黑名单内），**从未尝试换行或反引号**。

### 3.3 证据边界（必须同时记录）

- 本结论是**静态的**：仓库内没有一次携带 `\n` 的实测记录；L3（现场 `uid=0` 回显）**未证**。
- 静态链完整：`AIDL 10070 → helper.sendFTMCommand（空权限实现）→ HalService.executeDriverCommand
  → HIDL writeString → hidl_string → append → regex → sh -c`，中间**没有任何字符规范化**（§4.3）。
- HIDL/AIDL 的字符串是长度前缀字节串，换行可完整传输；`c_str()` 不截断 `\n`。
- 未验证项：真机 `/vendor/bin/sh`（mksh）对 `\n` 的解析（属动态，需授权）；
  `hidl_string` 是否在 Java→HIDL 边界做过 UTF-8 归一（静态未见，动态未测）。

---

## 4. 复评 P1 三个接口的正面回答

### 4.1 `sendSupplicantCommand`（slot7 / `0xa568`）

```
0xa5a8  "/vendor/bin/wpa_cli" (@0x6b1c) + " " + input         ; 0xa680 append / 0xa738 append
0xa78c  sub_9f64(cmd)                                          ; regex 校验
0xa7c0  bl 0x95b4(cmd)                                         ; 通过后执行
```

- 有过滤，但**与 §3 同一个不完整黑名单** ⇒ 同样存在 `\n`/反引号穿越。
- **`0xa5a0 cbz x0, 0xa600`**：空串返回 `-2`（日志串 `"empty command or it contains invaild char"`，`@0x6e0b`——注意该日志把"空"和"非法字符"合并，说明二者共用同一拒绝出口）。
- `stat("/vendor/bin/wpa_cli")` 失败返回 `-4`（`"wpa_cli is not found!"`）。

### 4.2 `runWiFiScript`（slot8 / `0xa898`）

| 阶段 | 指令 | 作用 |
|---|---|---|
| 长度检查 | `0xa904 cmp x0,#0x17; 0xa9ac cmp x21,#0xc` | 入参长度 ≥ 12，否则 `-3` |
| 前缀检查 | `0xaa28..0xaa3c` 组装 `"/vendor/bin/"`（x24=`/vendor/`, w26=`bin/`）→ `memcmp` | 脚本必须在 `/vendor/bin/` 下 |
| 拼接 | `0xabd8 append(script)`、`0xac0c append(arg2)` | 两条入参都进命令串 |
| 过滤 | `0xac58 sub_9f64(cmd)` | **同款不完整黑名单** |
| 执行 | `0xac8c bl 0x95b4` | 通过后 `sh -c` |

- 前缀校验只约束**第一个参数**，第二个参数（`String`）经 `append` 后仅受 regex 约束 ⇒ 同样可被 `\n` 穿越。
- 但该接口**无任何 Java 调用方**（§4.3），不构成本机可达面。

### 4.3 可达性审计（本轮的决定性否定）

在 `oppo-wifi-service.dex` 全量方法体上检索 `IOppoWifiService;-><method>` 与 `OplusWifiHalService;-><method>`
的调用点，并在 `jars/` 与 `dex/` 全部物料上做二进制检索：

| 接口 | Java 调用方 | 结论 |
|---|---|---|
| `executeDriverCommand` | `OplusWifiTransactionHelper.sendFTMCommand`（唯一） | **shell 可达**（tx 10070，§16.9 已实测到 10069；10070 未执行） |
| `catchSnifferLog` | `OplusWiFiSnifferModeManager$1.lambda$doInBackground$0`（内部类，`(int,int)`） | 仅 system_server 内部；**shell 无入口**；入参为 int，无注入面 |
| `runWiFiScript` | **无** | 死入口（全镜像仅 `oppo-wifi-service.jar` 自身出现该方法名） |
| `sendSupplicantCommand` | **无** | 死入口（同上） |
| `sendIniContent` / `getIniVersion` | `OplusWifiNative`（→ `OplusWifiHalService`），上层未见 AIDL 暴露 | 不可达 |

`helper.sendFTMCommand` 本体（dex）：

```
enforceAccessPermission()          →  return-void（1 条指令，空实现）
getOplusWifiInjectManager().getOplusWifiHalService()
  .executeDriverCommand(String)    →  原样透传，无长度/字符校验
```

⇒ **复评 P1 的三个接口，对"临时 ROOT"目标不增加攻击面**；`catchSnifferLog` 虽内部执行
`tar … && rm -rf`，但入参是 `int`，且入口在 system_server 内部。

**覆盖缺口（诚实登记）**：`framework.dex` / `oplus-framework.dex` 因 androguard 解析 hiddenapi 段失败被跳过；
已用二进制串检索交叉确认这三个方法名**不出现在**任何其他 jar/dex 中，故判断不依赖被跳过的解析。

---

## 5. 发现 C：`getIniVersion` 的任意 root 读（潜在，未达）

```
0xb6f4..0xb710  hidl_string → std::string          ; 无前缀校验
0xb7d8          fopen(input, "r")                  ; @0x6cbb = "r"
0xb7dc..       逐行读入 → hidl_string 回调回传内容
```

- 形态：**以 root 打开入参指定路径并回传文件内容**（任意读，受该进程 SELinux 域与 DAC 约束）。
- 本机不构成路径：无 Java 调用方（§4.3），且 HIDL 服务不对 shell 直接开放。
- 记录理由：一旦将来出现"任一可调用该 HIDL 接口的 system 上下文执行点"（§16.6 重开条件），
  这条会立刻成为**信息泄露**原语——而项目当前最大的阻断点恰是"缺内核地址泄露"（GhostLock）。
  值得在重开条件里并列登记。

---

## 6. 与项目结论的关系（严守三层次）

| 层次 | 状态 | 本轮变化 |
|---|---|---|
| **L1** shell 能调私有事务、字符串被 uid 0 服务接收 | 已证（§16.9，tx 10069 实测） | 不变 |
| **L2** 字符串进入 `sh -c` 的语法解析面 | 已证（两分支均 `execv(sh,{-c,cmd})`） | **加强**：iwpriv 分支也可注入（§3），不再依赖 myftm 前缀 |
| **L3** 真机取得 `uid=0` 回显 | **未证** | 不变（本轮纯离线，未上机） |

**整体 no-go 不翻转**。Wi-Fi 面定性由"myftm 单分支静态开放"扩展为
**"shell 可达分支的过滤器存在可绕过的字符集缺口"**——这是同一攻击面的更强表述，不是新的独立漏洞。

---

## 7. 待授权的动态验证设计（最小、可观察、可回滚）

> 前置：必须由用户明确授权。判据沿用 §16.11：①服务端 `completed successfully`，②只读副作用，③现场 `uid=0` 回显。

| 步 | 动作 | 预期 | 失败即停止 |
|---|---|---|---|
| 1 | 用 `javaprobe` 发 tx 10070，入参 `x\nid` | 回调 status 0；`logcat` 出现 `uid=0(root)` 相关输出 | 若返回 `-3`，说明换行被上层拦截，结论改写 |
| 2 | 入参 `x\nid > /data/local/tmp/poc_uid`，再 `cat` 该文件 | 文件存在且内容为 root | 同上 |
| 3 | 若 1/2 失败，改测反引号 `` `id` `` | 同上 | 收束为"过滤器实际有效" |

**副作用控制**：只写 `/data/local/tmp`；单次调用；不留驻留物；不改属性、不加用户、不触碰 `/system` `/vendor`。

---

## 8. 未穷尽项

1. `runWiFiScript` 的脚本前缀校验只做了 `memcmp("/vendor/bin/")` 与 `memchr('/')` 的静态判读，
   未逐步重建第二参数的完整组装顺序（两参数谁在前只按 `0xabd8`→`0xac0c` 的顺序判读）。
2. `sendIniContent` 的写入内容未做进一步分析（固定路径，暂判无价值）。
3. W2（`0xa390`）的 argv 布局按 `sp+8` 判读，未逐字节展开（与 W1 结构一致，风险低）。
4. `framework.dex` / `oplus-framework.dex` 解析失败，已用二进制串检索兜底（§4.3）。
5. 换行/反引号的 shell 行为**全部为静态推演**，未经真机验证。
