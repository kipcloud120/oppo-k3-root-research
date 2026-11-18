# FastRPC 面在 `oplus_wifi_service` 域下的封闭性

> 响应 **审核意见 CHATGPT-v005** 的唯一 P0 建议：
> 「FastRPC 在 `oplus_wifi_service` 身份下的访问封闭证据」。
> 执行时间 2026-11-18 14:30–14:32，设备在环，只读；无写入、无 ioctl、无持久化。

---

## 1. 结论

**该面在 `oplus_wifi_service`（uid 0）下不是"倾向封闭"，是实测封闭——而且比 shell 更封闭。**

| 层 | 判据 | 结果 |
|---|---|---|
| L1 标签 | `/dev/adsprpc-smd` → `u:object_r:qdsp_device:s0`；`-secure` → `u:object_r:xdsp_device:s0` | 设备实测与 `vendor_file_contexts` 一致 |
| L2 策略 | 本域对两类型的 `chr_file` 权限并集（direct + 89 个所属属性 + 目标侧属性展开） | **∅**（open/read/write/ioctl/getattr 全无） |
| L3 遮蔽 | 是否存在 `dontaudit` 使拒绝不被审计 | 无（唯一 `crash_dump → dev_type` 不适用于本域） |
| 运行期 | 域内实际 `open()` | `O_RDONLY` → `denied { read }`；`O_WRONLY` → `denied { write }`；均 `permissive=0` |

**因此 CVE-2023-33063 的利用前置（拿到一个可写/可 ioctl 的 adsprpc fd）在本域不成立；
v2.22 的"对 shell 双重封闭"升级为"对特权域单门硬封闭"。**

---

## 2. 为什么这条必须单独补：身份变化使 DAC 门失效

v2.22 的 FastRPC 结论建立在 **shell（uid 2000, u:r:shell:s0）** 上。而 §23 之后项目已握有
**uid=0 + gid 1010(wifi) + 附加组 1000(system)**，域为 `oplus_wifi_service`。这两点差异是决定性的：

```
crw-rw-r-- 1 system system u:object_r:qdsp_device:s0  224,0 /dev/adsprpc-smd          # 0664
crw-r--r-- 1 system system u:object_r:xdsp_device:s0  224,1 /dev/adsprpc-smd-secure   # 0644
```

- shell（uid 2000，无 `system` 组）：DAC 只给 `r--`，**写打开在 DAC 层就被挡**；
- `oplus_wifi_service`（uid 0，附加组含 1000(system)）：组权限命中 `rw`，**DAC 对 `smd` 放行读写**。

⇒ 对这个节点，**SELinux 是唯一的门**。v2.22 §5.4 的 `EACCES` 无法区分"DAC 拒"与"SELinux 拒"，
所以必须换身份重测——这正是 v005 指出的证据缺口。

> **实测更正**：§5.4 记 `-secure` 节点为 `0640`，设备实测为 **`0644`**（属主/属组 system:system）。
> 该节点即使 SELinux 放行，写打开仍会被 DAC 拒（组位仅 `r`，且本域无 `CAP_DAC_OVERRIDE`）。

---

## 3. L1 标签层（设备实测）

```
$ adb shell ls -lZ /dev/adsprpc*
crw-rw-r-- 1 system system u:object_r:qdsp_device:s0  224,0 1977-03-18 10:58 /dev/adsprpc-smd
crw-r--r-- 1 system system u:object_r:xdsp_device:s0  224,1 1977-03-18 10:58 /dev/adsprpc-smd-secure
```

与 `.build/sepolicy/vendor_file_contexts` 第 1152/1201 行完全对应：

```
/dev/adsprpc-smd          u:object_r:qdsp_device:s0
/dev/adsprpc-smd-secure   u:object_r:xdsp_device:s0
```

---

## 4. L2 策略层：完整 CIL 授权情况

策略规模：5 份 CIL，**24,657 条 allow**；本域所属属性 **89** 个。

```bash
python tools/fastrpc_domain_gate.py --domain oplus_wifi_service --cil .build/sepolicy
```

```
qdsp_device：并集=∅   open=False ioctl=False write=False read=False
             direct=0 via=0 via目标属性=0
             目标所属属性: base_typeattr_711, dev_type, mlstrustedobject
xdsp_device：并集=∅   open=False ioctl=False write=False read=False
             direct=0 via=0 via目标属性=0
```

三处容易出错的地方都已排除：

| 陷阱 | 检查 | 结果 |
|---|---|---|
| 规则目标写成属性（`allow X dev_type (...)`) | 目标侧展开 `dev_type` / `base_typeattr_711` / `mlstrustedobject` | 无一条命中 |
| 通过属性继承（`appdomain` 等） | 源侧展开全部 89 个所属属性 | 本域**不在** `appdomain` |
| `ioctl` 的具体命令号（xperm） | 扫 `allowx ... (ioctl chr_file ...)`，涉及该类型 18 条 | 适用于本域 **0** 条 |

对照（同一份策略，规则确实存在，只是不含本域）：

- `qdsp_device` 上有 `open` 的显式域 **17** 个（`adsprpcd`/`cdsprpcd`/`hal_camera_default`/`vendor_dspservice` …）；
- 另有属性 **9** 个携带该授权，**本域不是其中任何一个的成员**；
- `xdsp_device` 上显式域 14 个、属性 10 个，同样不含本域。

---

## 5. L3 遮蔽层：否认会被审计

全策略针对该二类型的 `dontaudit` 只有一条，且不适用于本域：

```
(dontaudit crash_dump dev_type (chr_file (read write)))
```

⇒ 运行期若**没有**出现 AVC，就**不能**解释为"被 dontaudit 吞了"，只能是两种可能：
放行，或根本没有发起调用。下一节的对照实验正是为此设计。

---

## 6. 运行期实测（判据先登记、后执行）

### 6.1 判据（执行前登记）

1. **必须证明测试机制有效**：在本域内对策略显式授权的同类字符设备做正对照，须得 `ok`；
2. 对目标节点的 `O_RDONLY` / `O_WRONLY` 各做一次，**以域内进程自身的返回值**为准（`if/else` 分支写 logcat），
   不以"有没有 AVC"为准；
3. 全程不调用任何 `ioctl`（一旦 open 失败，ioctl 无从谈起；open 成功也不越权尝试）。

### 6.2 执行通道

复用 §23 的 L3 通道（tx 10070 → `OplusWifiHalService.executeDriverCommand` → `sh -c`）。
唯一约束是 11 字符黑名单 `@#$%&*^:;?|`；因此分支用**换行**分隔（`if / then / else / fi` 各占一行），
不使用 `;`/`&&`/`||`。

### 6.3 结果

| # | 探针 | 域内返回值 | AVC |
|---|---|---|---|
| 0a | `true < /dev/null` | `FRPC_K0 : ctrl_ok` | — |
| 0b | `true < /dev/diag`（**同类设备正对照**，策略显式授权 9 项） | `FRPC_D0 : diag_open_ok` | — |
| 1 | `true < /dev/adsprpc-smd` | `FRPC_A1 : smd_rdonly_denied` | `denied { read }` |
| 2 | `true < /dev/adsprpc-smd-secure` | `FRPC_A2 : secure_rdonly_denied` | `denied { read }` |
| 3 | `echo -n > /dev/adsprpc-smd`（`O_WRONLY`） | `FRPC_W4 : wronly_denied` | `denied { write }` |
| 4 | `true <> /dev/adsprpc-smd`（`O_RDWR`） | `FRPC_W1 / FRPC_W3 : denied` | 无独立记录（见 6.5） |

正对照 0b 是关键：**同一个域、同一个对象类（chr_file）、同一套测量方法**，对 `/dev/diag`
返回 `ok`。因此 1–4 的 `denied` 不是测量假阴性。

### 6.4 AVC 原文

```
11-18 14:31:11.870  8275  8275 W sh : type=1400 audit(0.0:17095): avc: denied { read } for name="adsprpc-smd" \
  dev="tmpfs" ino=13590 scontext=u:r:oplus_wifi_service:s0 tcontext=u:object_r:qdsp_device:s0 tclass=chr_file permissive=0

11-18 14:31:11.890  8275  8275 W sh : type=1400 audit(0.0:17096): avc: denied { read } for name="adsprpc-smd-secure" \
  dev="tmpfs" ino=14405 scontext=u:r:oplus_wifi_service:s0 tcontext=u:object_r:xdsp_device:s0 tclass=chr_file permissive=0

11-18 14:32:10.560  8413  8413 W sh : type=1400 audit(0.0:17129): avc: denied { write } for name="adsprpc-smd" \
  dev="tmpfs" ino=13590 scontext=u:r:oplus_wifi_service:s0 tcontext=u:object_r:qdsp_device:s0 tclass=chr_file permissive=0
```

执行者身份（同一通道回显，`20261118T143021_FRPCID.log`）：

```
I FRPC_ID : uid=0(root) gid=1010(wifi) groups=1010(wifi),1000(system),2901(vendor_qti_diag),3005(net_admin) context=u:r:oplus_wifi_service:s0
```

### 6.5 一处日志学异常（如实记录）

`O_RDWR`（`<>`）两次均返回 denied，但**没有独立的 AVC 记录**，而 `O_WRONLY` 有。两种可能：
内核 AVC 缓存/审计去重，或 open 在 `read` 检查处即失败、`write` 未被单独求值。

这项不影响判定：读、写两个方向各有一次**独立且带 AVC 的**测量，`O_RDWR` 的结果只能更严
（需同时满足 read 与 write，二者已分别被拒）。原文见 `20261118T143120_FRPCW.log`
与 `20261118T143153_FRPCW2.log`。

---

## 7. 结构性发现：提权之后，这个面反而更小

同一份策略、同一个节点，两个身份：

| 身份 | 域 | `qdsp_device` 权限 | 结果 |
|---|---|---|---|
| uid 2000 | `shell` | `getattr ioctl lock map open read`（经 `appdomain`） | 可 `O_RDONLY`；`ioctl` 可达；写被拒 |
| uid 0 | `oplus_wifi_service` | **∅** | open 全方向被拒 |

`shell ∈ appdomain`，而平台基线 `(allow appdomain qdsp_device (chr_file (ioctl read getattr lock map open watch watch_reads)))`
把 FastRPC 的**读通道与 ioctl 通道**授予了包括 shell 在内的应用域；`oplus_wifi_service` **不在** `appdomain`。

这同时把 §5.4 两个旧观测解释干净了：

- `ioctl(fd,0) == ENOTTY`：因为 `ioctl` 权限**被授予**，请求穿过了 LSM 钩子进到驱动；
- `open(O_RDWR) == EACCES`：因为 `write` **未**授予（并集里没有 `write`），而 DAC 侧 shell 也无组权限。

⇒ **"从 shell 拿到 uid 0"不是在这条路径上"更进一步"，而是"换了一条更窄的路"。**
这条负结论应写进负知识清单：**uid 0 ≠ 权限更大**，域属性归属的差异可以反向吃掉 DAC 的增益。

---

## 8. 与 v005 建议的逐项对应

| v005 的要求 | 本文件对应 |
|---|---|
| 明确的设备标签 | §3（设备实测 + `file_contexts` 双证） |
| 完整 CIL 授权情况 | §4（direct / 属性继承 / 目标侧属性展开 / allowx 四路穷举） |
| 目标服务身份下的拒绝结果 | §6（域内返回值 + AVC 原文 + 正对照） |
| 不要动结论本身 | 结论方向未变，强度上调：由"倾向支持"变为"实测封闭" |

---

## 9. 未闭合项（不得外推）

1. **ioctl 语义面**：因 open 即被拒，本域无法到达任何 ioctl，故无从测"若 open 成功驱动会怎样"。
   `frpc_ioctl_probe.c` 的 7 条 `EPERM`（§5.4）仍是 shell 身份的结论，本文件不覆盖其语义。
2. **`O_RDWR` 无 AVC**：见 6.5，属日志层观察，不构成反例，也未获得解释性复现。
3. **相邻 DSP 面**：`ssr_device`（`subsys_adsp`）、`ramdump_device`、`qce_device`、`tee_device`、
   通用 `device`（`smcinvoke`）在本域同样为 **0 权限**（同法核算），但这只是策略层，
   未上机逐个验证。

---

## 10. 复现与文件

```bash
# 静态（离线，无需设备）
python tools/fastrpc_domain_gate.py --domain oplus_wifi_service --cil .build/sepolicy
python tools/fastrpc_domain_gate.py --domain shell              --cil .build/sepolicy   # 对照

# 运行期（需设备 + L3 通道）
python tools/wifi_exec.py --tag FRPCID --cmd 'log -t FRPC_ID `id`'
python tools/wifi_exec.py --tag FRPCD  --cmd '<if true < /dev/diag 的 if/else 块>'
```

| 文件 | 内容 |
|---|---|
| `tools/fastrpc_domain_gate.py` | 本文件的三层判定脚本（新增） |
| `.build/sepolicy/fastrpc_gate.json` | 结构化结果 |
| `artifacts_adb/binder_audit/fastrpc_gate_output.txt` | 静态判定原文 |
| `p1_probes/20261118T143021_FRPCID.log` | 域内 `id` 回显 |
| `p1_probes/20261118T143100_FRPCK.log` | 正对照 `/dev/null` |
| `p1_probes/20261118T143136_FRPCD.log` | 正对照 `/dev/diag` |
| `p1_probes/20261118T143112_FRPCA.log` | 两节点只读打开 + AVC |
| `p1_probes/20261118T143210_FRPCW3.log` | 写打开 + `{ write }` AVC |
| `p1_probes/20261118T143120_FRPCW.log`、`…143153_FRPCW2.log` | `O_RDWR` 两次 |

---

## 11. 方法学副产物：一个必须记下的工具缺陷

`tools/sepolicy_domain_audit.py` 的属性闭包原有实现，对**成员名同时是 type 与 attribute** 的情况
（`shell` / `bluetooth` / `sensors` / `mediaserver` …，Android 策略里很常见）会把该成员**丢弃**，
只做展开，导致经它继承的规则被漏计。已修正（`result.add(m)` + 继续展开）。

影响评估：

- 本域数字**不变**（`oplus_wifi_service` 不与任何属性同名）：89 个属性 / 307 条适用 allow，
  与 §24 的既有记录一致；
- 对照域 `shell` 由错误的少量属性变为 **131 个属性 / 1,012 条 allow**——旧实现会**低估**
  shell 的权限面。凡以往用该脚本评估"名字与属性同名的域"（shell、bluetooth、sensors…）的结论，
  都应视为**下界**。
