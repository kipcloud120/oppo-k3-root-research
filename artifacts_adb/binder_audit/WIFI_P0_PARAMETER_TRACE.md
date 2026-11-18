# P0 静态定性：`-3 INVAILD_PARAMETER` 的来源与命令拼接格式（2026-11-18，纯离线；v2.10 复评更正见 §7）

> 响应 `HANDOVER.md` §17.3 P0。全程未连设备；只分析两个已入库二进制：
> - native：`artifacts_adb/binder_audit/rootbin/../.build/vendor/x/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service`（115,408 B，stripped ELF64）
> - Java：`artifacts_adb/binder_audit/dex/oppo-wifi-service.dex`（`OplusWifiHalService`）
> 复现工具：`python elf_analyze.py` / `python artifacts_adb/binder_audit/deep_method.py` + capstone 5.0.7；
> PLT 映射：`rela.plt` 第 i 项 ↔ PLT stub `0x18d30 + 0x10*i`（GOT 基 `0x1aa88`）。

---

## 1. 一句话结论

**`-3 INVAILD_PARAMETER` 由 native 侧写入（返回给 Java 的状态码 -3），归因是 `executeDriverCommand`
在 iwpriv 分支对入参做正则黑名单校验失败；Java 层只做透传与埋点，不改写状态码。
所有历史注入串都因前缀不匹配进了 iwpriv 分支并被拒，从未进入 myftm 分支。**

> **⚠️ v2.10 更正（外部复评）：上述归因仅适用于 iwpriv 分支。原文此处断言"受限 root 工具接口、
> 不是任意命令执行"已撤销——myftm 分支经逐指令复核证实为 `/vendor/bin/myftm <原始尾串>` 裸拼进
> `sh -c`，无引号/转义/过滤，注入面静态开放，Wi-Fi P0 重开。L3 未证，整体 no-go 不翻转。见 §4/§7。**

---

## 2. `-3` 的确定性归因（逐层证据）

### 2.1 Java 层：只透传 status，不改写

回调链（dex 反汇编，`deep_method.py`）：

```
executeDriverCommand(String v7):
    构造 OplusWifiServiceResult("executeDriverCommand(" + v7 + ")")   ← 构造函数里 Log.d("entering …")
    mIOppoWifiService.executeDriverCommand(v7, new Callback{ f$0=result })
    → onValues(int status, String value)
        → lambda$executeDriverCommand$1(result, status, value)
            → result.setResult(status, value)      // 2 条指令，原样转发
```

- `OplusWifiServiceResult.isSuccess()`：`return mStatus == 1`（只认 status==1，其余全失败）。
- `OplusWifiServiceResult.getResult()`：`isSuccess() ? mValue : ""`（失败回空串）。
- `setResult(int,String)` 调 `access$700(methodName,status)`（埋点/统计，与提权无关）后写 `mStatus/mValue`。
- **`onValues` 所在类 `uD6hk53bOimZNTzE924fVOYf3t8` 就是个 lambda 壳，3 条指令，只转发，无校验逻辑。**

⇒ §17.3 里"查 `uD6hk53bOimZNTzE924fVOYf3t8.onValues` 里哪个码对应"这个问题的答案是：
**它里面没有码表，status 由 native 直接给出，`-3` 在 native 写入。**

> 关键更正：`entering executeDriverCommand(<s>)` 这条日志在 `OplusWifiServiceResult`
> **构造函数**里打印（入参 `v7` 拼进 methodName），因此它是**函数调用回显**，与命令是否执行无关。
> 这正是 09:35–09:44 误判的直接技术根因（§16.11）。

### 2.2 native 层：`-3` 的写入点

`slot5 = executeDriverCommand @ 0x992c`（vtable `.data.rel.ro @0x1a0a0` slot5，HIDL code 4）。
`-3` 在 **iwpriv 分支的公共尾部** `0x9ddc` 写入：

```
0x9dcc  adrp x1, 0x697b   ; "INVAILD_PARAMETER"
0x9dd4  add  x0, sp, #0xe0
0x9dd8  bl   hidl_string::C1(const char*)     ; value = "INVAILD_PARAMETER"
0x9ddc  mov  w8, #-3
0x9de0  str  w8, [sp, #0x48]                   ; status = -3
0x9de4  ldr  x0, [x20, #0x20] ; cbz … ; blr [x8+0x30]   ; 调 HIDL callback.onValues(-3, "INVAILD_PARAMETER")
```

同函数其它状态码（全部 native 写入，给出完整码表）：

| status | 触发条件 | 字符串 | 反汇编位置 |
|---|---|---|---|
| `0` | 命令拼装并执行（`system()` 返回） | `" "` | `0x9e8c` / `0x9e7c` |
| `-2` | `c_str()` 返回空 → 空命令 | `EMPTY_PARAMETER` | `0x9994` |
| `-3` | **regex 校验命中黑名单 / 参数解析失败** | `INVAILD_PARAMETER` | `0x9ddc` |
| `-4` | `stat()` 找不到 `iwpriv` / `myftm` | `FILE_NOT_EXIST` | `0x9aa0` / `0x9bbc` |
| `-5` | `system()` 执行失败 | `UNKNOWN` | `0x9cf8` / `0x9e50` |

### 2.3 `-3` 的根因函数 `sub_9f64 @ 0x9f64`（regex 黑名单校验）

```
0x9fc4  adrp x1, 0x6dcb  ; "[@#$%&*^:;?|]+"   (长度 14 = x2 = x1+0xe)
0x9fe4  bl   0xd17c      ; std::regex 构造（模式串，标志）
0x9ffc  ldrb w8,[x19] … 0xa024 bl 0x158ec    ; std::regex_search(cmd, re, flags) → w0
0xa028  … 0xa040 tbz w19,#0,0xa06c
   命中 → 0xa044 Log "String contains invaild character"，返回 0（false）
   未命中 → 0xa06c 返回 1（true）
```

`0x158ec` / `0xd17c` 为 libc++ `std::regex_search` / `std::regex` 构造的内部实现（反汇编见正文分析记录）。
模式串字节级确认：`0x6dcb..0x6dd8 = b"[@#$%&*^:;?|]+"`（14 B）。

**黑名单字符**：`@ # $ % & * ^ : ; ? |`（`>`、`<`、反引号、反斜杠 `\`、换行**不在**其中）。
⇒ `myft -h; id`（含 `;`）、`myft id | logger`（含 `|`）命中 → `-3`，与历史日志吻合。

---

## 3. `myft -h` 为何"成功"：分支判据更正（本次最重要发现）

### 3.1 前缀判据是 5 字节 `myftm`，不是 4 字节 `myft`

`0x9a04` 处的常量与比较：

```
0x9a04  mov  w8, #0x796d ; movk w8, #0x7466, lsl #16   → w8 = 0x7466796d = "myft" (LE)
0x9a1c  ldr  w10, [sp, #0x120]       ; 入参前 4 字节
0x9a34  eor  w8, w10, w8             ; 比较前 4 字节
0x9a20  mov  w9, #0x6d               ; 'm'
0x9a38  ldrb w10, [sp, #0x124]       ; 入参第 5 字节
0x9a4c  eor  w9, w10, w9
0x9a50  orr  w8, w8, w9
0x9a5c  cbz  w8, 0x9b7c              ; 前 5 字节 == "myftm" → myftm 分支
```

⇒ **进入 myftm 分支的充要条件是入参前 5 字节恰为 `m y f t m`**。

### 3.2 历史注入串全部没进 myftm 分支

| 输入 | 前 5 字节 | 实际分支 |
|---|---|---|
| `myft -h` | `myft ` (空格) | iwpriv（非 myftm） |
| `myft id > …` | `myft ` | iwpriv |
| `myft -h; id` | `myft ` | iwpriv |
| `myft id \| logger` | `myft ` | iwpriv |
| `myftm -h` | `myftm` | myftm ✓ |

**文档 §7.7 记录的"前缀等于 myft → myftm 分支"是不精确的（漏了第 5 字节 'm' 的比较），本轮更正。**

### 3.3 两条分支的实际行为

- **iwpriv 分支**（`0x9a60`，历史测试实际走的）：
  拼 `/odm/bin/iwpriv wlan0 setMonChan <to_string(int)>` → 调 `sub_9f64` regex 校验 →
  命中黑名单或解析失败 ⇒ `-3`；否则 `system()` 执行固定模板命令 ⇒ status 0。
  `myft -h` 无黑名单字符 ⇒ 命令拼装成功 ⇒ status 0（被 Java 判 isSuccess，但执行的是 iwpriv 固定命令）。
- **myftm 分支**（`0x9b7c`，本次新识别，历史从未走到）：
  ```
  0x9bf4 x21 = sp+0x125            ; 入参[5:]（跳过 "myftm"）原样指针
  0x9c30 strb #0x22,[sp+0x48]      ; SSO 长度字节 17<<1（非引号！）
  0x9c38 stur q0,[sp+0x49]         ; "/vendor/bin/myftm" 数据区
  0x9c40 append(" ", 1)            ; 追加一个【空格】(sp+0x31=0x20)
  0x9c64 append(input[5:])         ; std::string::append(const char*) 裸追加
  0x9cb8 bl 0x95b4                 ; execv("/vendor/bin/sh",{sh,-c,cmd})
  ```
  逐字节重建 SSO 结构确认最终命令 = **`/vendor/bin/myftm <入参[5:]>`**（命令 + 一个空格 + 原始尾串）。
  **该分支不调 `sub_9f64`**（无 regex 黑名单校验）；`sub_9f64` 全程序仅 3 个调用点
  （`0x9db0` iwpriv / `0xa78c` / `0xac58`），均不在 myftm 分支。
  **⚠️ v2.10 更正：这里原写"不是任意 shell 命令串/无法跳出单个 token"是错误断言，见 §4 与 §7。**

---

## 4. 与项目结论的关系（严守 §17.2 三层次）——**v2.10 重写**

> **本节在 v2.9 写的"参数无法跳出单个 token、非任意命令执行"是错误断言，已撤销。**
> 起因：`审核意见CHATGPT-v002.txt` 指出混淆了 shell 的参数分隔与 shell 控制操作符。经逐指令复核，批评成立。

| 层次 | 证据 | 状态 |
|---|---|---|
| L1 字符串被 root 服务接收 | Java `executeDriverCommand(v7)` 原样下传；native `c_str()` 读入 | 已证 |
| L2 命令被执行 | 两条分支均调 `execv("/vendor/bin/sh",{sh,-c,cmd})`；cmd 由拼接得到 | **myftm 分支：注入面静态开放**（见下） |
| L3 提权成立 | 从未上机验证 myftm 分支注入；无 `uid=0` 回显 | **未证，分支已重开** |

- `0x95b4` shell 包装确证：`signal(SIGHUP,SIG_IGN)` → `vfork()` → 子进程
  `execv("/vendor/bin/sh", {"/vendor/bin/sh","-c",cmd,NULL})`（argv 在 `sp+8`：`0x6ae6`,`0x6f69`,`cmd`,`NULL`）。
- **iwpriv 分支**（历史测试实际走的）：regex 黑名单 `[@#$%&*^:;?|]+`（`sub_9f64`）确实拦截 `;` `|` `$` `&` 等 ⇒ 历史注入串全部 `-3`，这部分归因仍成立。
- **myftm 分支**（历史从未走到）：命令 = `/vendor/bin/myftm <input[5:]>`，**无引号封装、无转义、无过滤、无 regex**。
  POSIX shell 对 `sh -c` 的字符串做完整语法解析，`;` `|` `&&` `||` `$()` 反引号 等控制操作符
  **不依赖空格**即可被识别。例：`input="myftm; id"` ⇒ `cmd="/vendor/bin/myftm ; id"` ⇒ shell 执行两条命令。
  **v2.9 所谓"空格后当 myftm 的参数"只在参数是纯 token 时成立，对 shell 元字符不成立。**
- **正确结论**：myftm 分支是一个**静态上开放的命令注入面**，应重开审计并列为最高研究优先级；
  但仍**不能宣称可提权**——需先排除别处是否存在统一过滤/转义（本章已证本分支无，但未穷尽所有调用路径），
  且 L3 必须经授权上机回显 `uid=0`。**整体 no-go 维持，但 Wi-Fi P0 不关闭。**

---

## 5. 合法命令格式表（P0 产出）

| 前缀 | 分支 | 生效命令 | 参数约束 | 结果 |
|---|---|---|---|---|
| `myftm…`（5 B 精确匹配） | myftm `0x9b7c` | `/vendor/bin/myftm ` + 入参[5:]（无引号/转义/过滤） | **注入面静态开放**：shell 元字符可被解析；L3 未上机验证 | status 0/-4/-5 |
| 其它（含 `myft `） | iwpriv `0x9a60` | `/odm/bin/iwpriv wlan0 setMonChan <int>` | regex `[@#$%&*^:;?|]+` 拦截；参数经 `to_string(int)` | status 0/-3/-4/-5 |
| 空串 | — | 无 | `c_str()==NULL` | status -2 `EMPTY_PARAMETER` |

同族接口（同样 root，固定模板，未逐一深挖）：`sendSupplicantCommand`(slot7→`wpa_cli`)、
`runWiFiScript`(slot8)、`catchSnifferLog`(slot3→`tar … && rm -rf`)、`changeConnectionMode`(slot2→写 `con_mode`)。

---

## 6. 对 §17.3 下一步的影响 —— **v2.10 修订**

1. **`-3` 归因仍成立**：`-3` = iwpriv 分支 native regex 黑名单（历史注入串走此分支）。合法格式表见 §5。
2. **P1 部分撤销**：9 类命令中 iwpriv 等分支确为固定模板；但 **myftm 分支不是**——它是
   `/vendor/bin/myftm <原始尾串>` 裸拼进 `sh -c`，**注入面静态开放**。v2.9"不构成任意命令执行"的断言已撤销。
3. **myftm 分支重开为最高优先级**：静态已证无引号/转义/过滤，shell 元字符可被解析；
   L3 仍须经**用户明确授权**上机、以 `uid=0` 回显为唯一判据（§17.2）。**在不上机前提下，先补齐静态证据**：
   确认 Java/HIDL 传输层与 `myftm` 二进制自身是否对尾串再做过滤（本次只审了 HAL 服务的拼接点）。
4. **设备终态**：本轮纯离线，未连设备，无写操作。

---

## 7. v2.10 复评更正（来源：`docs_archive/审核意见CHATGPT-v002.txt`）

**触发**：外部复评指出 v2.9 在"myftm 分支不是任意命令执行"上推论不成立——
混淆了 shell 的**参数分隔（空格）**与**控制操作符（`;` `|` `&&` `$()` 反引号）**：后者不依赖空格即被 `sh -c` 解析。

**复核方法**：逐指令重建 `0x9be8–0x9cb8` 的 libc++ SSO string 栈布局
（`sp+0x48`=`"/vendor/bin/myftm"` len 17；`sp+0x30`=`" "`；两次 `append`）+ 全程序搜索 `sub_9f64` 调用点。

| 复评要求证明的三点 | 静态复核结果 |
|---|---|
| ① `input[5:]` 追加前有无全局过滤 | HAL 服务拼接点：`c_str()`→`append()` 之间无 `sub_9f64`、无转义循环。**该层无过滤**；Java/HIDL 传输层未逐层穷尽 |
| ② 最终 `sh -c` 串有无正确引用/转义/参数隔离 | **无**：命令 = `"/vendor/bin/myftm " + input[5:]`，无单/双引号、无反斜杠转义 |
| ③ shell 控制操作符能否被解释为命令语法 | **能**：POSIX `sh -c` 对整串做语法解析，`;` `\|` `&&` `$()` 等均为操作符 |

**结论**：myftm 分支**从"已否证"改判为"静态注入面开放、待授权验证"**；
Wi-Fi P0 **重开**、不随 P1 关闭。L3（真实 `uid=0` 回显）仍未证，整体 no-go 不翻转。
**不上机**（复评亦建议先审计清楚再决定）；下一次更新聚焦补齐静态过滤路径，不新增 CVE。

---

## 8. 新 P0 收束（2026-11-18，纯离线）：Java 传输层 + myftm 二进制

> 响应 §20 / 复评"需证明三件事"。本轮补齐了 §7 遗留的两条静态路径，**未连设备、无写操作**。
> 新解出 `/vendor/bin/myftm`（vendor.img，225,752 B，AArch64 PIE）落 `rootbin/_p2/`（gitignored）。

### 8.1 Java/HIDL 传输层：确认全程无过滤（复评第①点的传输段）

逐方法 dump（dex 反汇编）：

| 环节 | 方法 | 结论 |
|---|---|---|
| 入口 | `OplusWifiTransactionHelper.sendFTMCommand(String v1)` | `enforceAccessPermission()` **= 1 条 return-void 空实现**；`v1` 原样传 `executeDriverCommand` |
| HAL | `OplusWifiHalService.executeDriverCommand(v7)` | 原样拼日志 + 原样传 HIDL |
| HIDL Proxy | `IOppoWifiService$Proxy.executeDriverCommand` | `writeString(v6)` 原样写 Parcel，code=4；回调 `onValues(status,value)` 原样回传 |

⇒ **Java/HIDL 层无转义、无过滤、无引号封装，字符串逐字节透传到 native**（与 §2.1 一致）。

### 8.2 `/vendor/bin/myftm` 本体：第二道约束（关键发现）

逆向结果（PLT 经 GOT 精确映射，非 stub 序号猜测）：

- **参数解析**：导入 `getopt_long` + `atoi`/`strtol`/`sscanf`/`strtok_r`；option spec 串为
  `hdi:nb:e:Em:S:w:Wr:Rg:f:p:Pqt:Tua:Ax:s:C:c:D:k:G:j:y:z:lL:M:B:H:I:JN:O:o:Q:X:Y:U:rateBw:nss:...`
  ——典型的**高通 Wi-Fi ATE 工厂测试工具**，argv 由固定选项表解析成结构化参数，不是 shell 串。
- **main（`0x10048`）**：`argc==2` 才继续（否则 return -1）；argv[1] 内容在 main 里**从未被读取**去拼命令。
- **popen（3 处）+ system（5 处）命令全部硬编码**，逐字节读出的代表：
  - `cat /proc/modules | grep %s`（`%s`=`wlan` 硬编码 @`0x48ad`）→ popen 检查模块
  - `/system/bin/rmmod wlan`
  - `/system/bin/insmod /system/lib/modules/wlan.ko con_mode=5`
  - 其余 system 点（`0x10680`/`0x106c4`）参数亦为 adrp 固定串常量
- ⇒ **argv（即 input[5:] 尾串）不进入任何 popen/system 的命令串**；元字符会被 `getopt_long` 当作未知选项或普通参数解析掉。

### 8.3 判定（诚实标注边界）

复评第①点的"HAL 拼接点无过滤"仍成立（§4/§7 不改）；但**新增的第二道约束改变了注入面的实际可达性**：

| 层次 | 结论 |
|---|---|
| HAL 拼接点 `/vendor/bin/myftm <input[5:]>` | 无引号/转义 ⇒ `sh -c` 会把 `;` 解析为**外层 shell 的操作符** |
| 但外层 shell 执行的是 `myftm` + 一个参数 token | 带 `;` 的串会被外层 shell 拆成第二条命令——这点复评仍对 |
| **myftm 对 argv[1] 的处理** | getopt_long 固定选项解析 + 硬编码 system 命令 ⇒ 即使元字符进入 argv，myftm 不会把它当 shell 执行 |

**关键澄清**：外层 `sh -c` 的注入与 myftm 的 parser 是**两个独立层面**。复评指出的
`input="myftm; id"` → `cmd="/vendor/bin/myftm ; id"` → 外层 sh 执行 `id` —— **这条路径不经过 myftm 的 getopt，
myftm 的 parser 无法阻挡**。因此 §8.2 的发现**不能用来否证复评的注入路径**，只能说明"若 payload 作为 myftm 的参数 token 传入，则被约束"。

**最终判定**：
- 复评的"myftm 分支注入面静态开放"**维持**——因为元字符可在**外层 shell**层面生效，绕过 myftm。
- myftm 本体的 getopt+硬编码命令是**额外信息**，但不构成对复评的有效反驳。
- L3（真实 `uid=0` 回显）仍未证，整体 no-go 不翻转。**仍不上机**；下一步若要继续，须用户明确授权。

### 8.4 未穷尽项（诚实登记）

- 未逐一审计 myftm 全部 5 个 system 调用点的每个 option 分支（已审 main + 2 处代表，均为固定串）。
- 未验证外层 `sh -c` 对 `;` 的解析在真机 shell（`/vendor/bin/sh`,mksh）上的具体行为（属动态，需授权）。
