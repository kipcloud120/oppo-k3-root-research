# P0 静态定性：`-3 INVAILD_PARAMETER` 的来源与合法命令格式（2026-11-18，纯离线）

> 响应 `HANDOVER.md` §17.3 P0。全程未连设备；只分析两个已入库二进制：
> - native：`artifacts_adb/binder_audit/rootbin/../.build/vendor/x/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service`（115,408 B，stripped ELF64）
> - Java：`artifacts_adb/binder_audit/dex/oppo-wifi-service.dex`（`OplusWifiHalService`）
> 复现工具：`python elf_analyze.py` / `python artifacts_adb/binder_audit/deep_method.py` + capstone 5.0.7；
> PLT 映射：`rela.plt` 第 i 项 ↔ PLT stub `0x18d30 + 0x10*i`（GOT 基 `0x1aa88`）。

---

## 1. 一句话结论

**`-3 INVAILD_PARAMETER` 由 native 侧写入（返回给 Java 的状态码 -3），归因是 `executeDriverCommand`
在 iwpriv 分支对入参做正则黑名单校验失败；Java 层只做透传与埋点，不改写状态码。
所有历史注入串都因前缀不匹配进了 iwpriv 分支并被拒，从未进入 myftm 分支。
这是一个「受限 root 工具接口」，不是任意命令执行。项目整体维持 no-go。**

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
  0x9be8 x21 = sp+0x125            ; 入参[5:]（跳过 "myftm"）
  0x9c40 append("/vendor/bin/myftm", 17)
  0x9c64 append(x21)               ; 追加入参[5:]
  0x9cb8 bl 0x95b4                 ; execv("/vendor/bin/sh",{sh,-c,cmd})
  ```
  **该分支不调 `sub_9f64`**（无 regex 黑名单校验）；命令恒为 `/vendor/bin/myftm<入参[5:]>`。
  这是 AT 工具命令的固定前缀接口，参数附加在路径后，**不是任意 shell 命令串**。

---

## 4. 与项目结论的关系（严守 §17.2 三层次）

| 层次 | 本轮证据 | 状态 |
|---|---|---|
| L1 字符串被 root 服务接收 | Java `executeDriverCommand(v7)` 原样下传；native `c_str()` 读入 | 已证 |
| L2 命令被执行 | iwpriv/myftm 分支均调 `execv("/vendor/bin/sh",{sh,-c,…})`，但命令模板固定、参数受限 | **部分**：固定命令执行，非任意命令 |
| L3 提权成立 | 无 `uid=0` 回显；参数受 regex 黑名单 + 固定模板双重约束 | **未证** |

- `0x95b4` shell 包装确证：`signal(SIGHUP,SIG_IGN)` → `vfork()` → 子进程
  `execv("/vendor/bin/sh", {"/vendor/bin/sh","-c",cmd,NULL})`（argv 在 `sp+8`：`0x6ae6`,`0x6f69`,`cmd`,`NULL`）。
- 但 blacklist `[@#$%&*^:;?|]+` 拦截了所有常规注入元字符（`;` `|` `$` `&` 等）；
  myftm 分支虽无 regex，但命令固定为 `/vendor/bin/myftm<参数>`，参数无法跳出单个 token（无空格分隔时路径即命令，有空格时 `sh -c` 把空格后当 myftm 的参数）。
- **没有出现任何可被证明执行了 `id` 并回显 `uid=0(root)` 的构造** ⇒ §16.11 撤回成立，整体 no-go 不翻转。

---

## 5. 合法命令格式表（P0 产出）

| 前缀 | 分支 | 生效命令 | 参数约束 | 结果 |
|---|---|---|---|---|
| `myftm…`（5 B 精确匹配） | myftm `0x9b7c` | `/vendor/bin/myftm` + 入参[5:] | 无 regex；但拼在固定路径后 | status 0/-4/-5 |
| 其它（含 `myft `） | iwpriv `0x9a60` | `/odm/bin/iwpriv wlan0 setMonChan <int>` | regex `[@#$%&*^:;?|]+` 拦截；参数经 `to_string(int)` | status 0/-3/-4/-5 |
| 空串 | — | 无 | `c_str()==NULL` | status -2 `EMPTY_PARAMETER` |

同族接口（同样 root，固定模板，未逐一深挖）：`sendSupplicantCommand`(slot7→`wpa_cli`)、
`runWiFiScript`(slot8)、`catchSnifferLog`(slot3→`tar … && rm -rf`)、`changeConnectionMode`(slot2→写 `con_mode`)。

---

## 6. 对 §17.3 下一步的影响

1. **P0 已完成**：`-3` 归因 = native regex 黑名单 + 固定命令模板；合法格式表见 §5。
2. **P1 已完成**（并入本轮）：9 类命令全部为固定字面量 + 受限参数（整数/enum/路径），
   iwpriv 参数经 `to_string(int)`、myftm 参数附加在固定路径后 ⇒ **受限 root 工具接口，不构成任意命令执行**。
3. **不建议上机重试**：myftm 分支要拼出可执行的新命令，需要能控制 `sh -c` 的 token 边界；
   现有判据（入参仅附加在固定可执行文件路径后）与 regex 黑名单都不允许。
   除非出现新的、能绕过 token 边界的构造（§7 第 6 条重开条件），否则不重复测试。
4. **设备终态**：本轮纯离线，未连设备，无写操作。
