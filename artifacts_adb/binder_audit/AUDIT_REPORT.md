# OPPO K3 F.16 · OPPO 私有 Binder 服务静态审计（五轮，已完结）

- 日期：2026-11-17
- 触发：`docs_archive/审核意见CHATGPT.txt` 主张将"OPPO 私有 Binder 服务审计"提升为 P0，并以 CVE-2026-70386（OnePlus atlasservice 未授权 → root 命令执行）等为历史证据。
- 对应交接文档：HANDOVER v2 §4、§7 第 6 条（"binder 服务面出现具体线索 → 走静态审计，不盲试 service call"）。
- 性质：**只读静态审计**。未推送任何二进制、未调用 `service call`、未触发内核、未改动设备状态。

---

## 1. 结论（第二轮更新）

**审计发现了 HANDOVER §7 第 6 条意义上的"具体线索"——本机 atlasservice 与 CVE-2026-70386 的关键结构同构。但证据链在 native 层被权限阻断，尚不足以判定可利用。判定从"材料不足"升级为"有具体线索、待验证"，仍不推翻 no-go。**

三阶段演进：

| 阶段 | 覆盖度 | 结论 |
|---|---|---|
| 第一轮（9 jar） | 2/35 服务 | 材料不足，未闭合 |
| **第二轮（补 framework.jar/services.jar/atlas apk）** | **28/35 服务接口 + atlas 实现链** | **发现具体可疑分支，证据链在 native 层中断** |

### 决定性发现：atlasservice 与 CVE-2026-70386 结构同构

| 要素 | CVE-2026-70386（OnePlus） | 本机 K3 F.16 | 判定 |
|---|---|---|---|
| 关键接口 | `atlasservice.setEvent(String8,String8)` | `IOppoMMAtlasService`/`IOppoAtlasService` 的 `setEvent(int,String)` | **同名同族，签名略异** |
| Java 层鉴权 | 缺失 | `Stub.onTransact` 仅 `enforceInterface`，`setEvent` 分派无 `getCallingUid`/`enforceCalling` | **同样缺失** |
| 能力出口 | 参数 → 系统属性 | `setEvent→OppoAtlas.setEvent()→libatlasservice.so::AtlasService::setEvent` → `OplusAtlasLogWriter::caputureLogs` → `OplusAtlasLogThread` | **第四轮已完整反汇编证实** |
| root 服务 | `audiodumpinfo`，uid 0，`u:r:dumpstate:s0`，拼进 `system()` | `atlasservice`，`user root`（PID 1420），`/system_ext/bin/atlasservice`，`atlasservice.rc` | **root init service 存在** |
| 命令执行 | `system()` 拼**未转义的用户参数** | `libatlasservice.so` 确有 `system`/`popen` 导入；`checkPath`/`doLogCaputure`/`threadLoop` 三处调 `system()`。但格式串经解析**全部硬编码**：`dmesg > %s%s%s` → `dmesg > <固定路径>_dmesg.txt`、`chmod 0777 %s`、`%s > %s%s` | **本质差异：命令目标硬编码，非 value 拼接** |

> ⚠️ **重要更正**：前几轮"用户态 so 无 `system()` 字符串"的结论**作废**——根因是本机 Git Bash 无 `strings` 命令（返回空被误读为"没有"）。改用 Python 正则提取后确认 so 含 `system`/`popen` 导入符号。教训同 HANDOVER §10：工具可用性必须先自证。

**结论（第四轮 native 静态反汇编后更新）**：对可读的 `libatlasservice.so` 做了符号级反汇编,完整还原了 `setEvent` 的下游调用图:

```
AtlasService::setEvent(int, String8 value)
  ├─ OppoAudioState::setModeInfo(value)
  ├─ OplusAtlasLogWriter::caputureLogs(value)
  │    └─ new OplusAtlasLogThread(value) → start()
  │         └─ threadLoop → doLogCaputure → checkPath(value) → system()
  ├─ atoi(value) → kill(...)
  └─ AtlasLooper::sendMessage(...)
```

`system()` 确被调用 3 次,**但命令模板是 rodata 硬编码**(`dmesg`/`chmod 0777`/`%s > %s%s%s`),第一个 `%s` 不是 value。用户 value 的实际流向是**路径构造**(`strtok`/`stat`/`mkdir` 的目标)与 `kill` 的 pid 参数。

**这与 CVE-2026-70386"value 直接拼进 `system()` 命令"有本质差异。** 证据链第 5 环经实证后判定为 **不成立(至少不在可读的 `libatlasservice.so` 路径上)**。root 二进制本体虽仍不可读,但 native 侧可读库已不含注入模式。**判定:该项 specific lead 基本否证,维持 no-go。** 路径 B(受控探针)的技术价值因此大幅下降——见 §4。

### 第五轮：解出 root 二进制，证据链最终闭合（2026-11-17）

此前唯一剩余缺口是"root 二进制 `/system_ext/bin/atlasservice` 对 shell/adbd 不可读"。本轮用**纯静态**方式从官方 OTA 整包解出该二进制并分析，缺口关闭。

**取流与重建（全程离线，直连下载不走代理）**：
1. 用 Range 只取 OTA ZIP 中 `system.new.dat.br` 条目区间 `[5546, 2736576775]`（2.55 GiB），未下 3.71 GiB 整包；`system.transfer.list`（26357 B）单独 Range 提取。
2. 关键格式自证（两次纠错后才确定）：
   - `transfer.list` v4 逗号分隔 + **范围编码**——覆盖度自检 uncovered=0/overlap=0；
   - `new.dat` 是**固定 4096 字节块**的原始流、**无长度前缀**——`len(new.dat) == Σ(e−s)×4096`，diff=0（此前误按"4B 长度+数据"解析，在块 256 失败）。
3. brotli 解压 → `system.new.dat`(4.76 GiB)；sdat2img 重建 → `system.img`(4958 MiB)；7-Zip 读 ext4 提取目标。

**决定性结论**：
- root 二进制 `system_ext/bin/atlasservice`（11608 B，ELF64，SHA256 `c7807798…`）是一个**薄壳**：字符串仅 65 个，无 `system`/`popen`；`main()` 只做 `AtlasService()` 构造 → `addService("AtlasService")` → binder 线程池。DT_NEEDED 含 `libatlasservice.so`。
- **字节级比对**：镜像解出的 `lib64/libatlasservice.so` 与第四轮反汇编的设备拉取版 SHA256 完全一致（`b65dde22…`）。故第四轮的 `setEvent → … → system()` 分析**就是 root 进程实际加载库的分析**。
- ⇒ root 侧不存在"第二处把 value 拼进命令"的逻辑。第五环经 root 二进制实证后**确定否证**，不是"因不可读而存疑"。**atlas 线索彻底闭合：no-go。**

**方法论产出**：`tools/dl_range.py`（指定区间分段下载）、`tools/sdat2img.py`（范围编码 + 固定块长重建，含覆盖度/大小双校验）、`tools/rebuild_system.py`、`tools/elf_analyze.py`。厂商二进制不入库。

### 次要发现

1. **覆盖度 28/35**（第一轮仅 2/35）。7 个 MISSING：`IAntiRootDialog`、`IHephaestus`、`IHoraeService`、`IOIfaceService`、`IHansComunication`、`IOppoAppDataService`、`OplusResourceManagerService`（后者仅有 IFACE 无 Stub）——其实现在独立 apk/服务中，未纳入本轮。
2. **`IOplusCustomizeService$Stub` 是 28 个里唯一在 Stub 层调用 `checkPermission()` 的**——说明厂商确实知道要鉴权，反衬其他服务依赖 SELinux/实现层。
3. **`OplusWifiHalService.executeDriverCommand`** —— **【2026-11-17 已定性，见 `F16_WIFI_FTM_TRACE.md`】** 该方法本身是内部 helper（44 条指令），**不是 Binder 接口**；真正的暴露点是手写的 `OplusWifiTransactionHelper.onTransact`（798 条指令，实现 `IOplusWifiManager` + `IWifiTransactionHelper`），客户端 `android.net.wifi.OplusWifiManager` 用 tx **10070** 直接 transact 到 `wifi` binder 上。
   该分支**只有 `enforceInterface()`，无调用者身份检查**；`enforceAccessPermission()` 是 1 条指令的空实现。
   但**外部可达性未证明**：7 次只读探测（含 AOSP 对照组）全部止于描述符校验，**未出现 `Permission Denial`**；下游 vendor HAL 不可判。**不改变 no-go**（即便打通也只到 vendor Wi-Fi HAL，不产生 uid 0）。

---

## 2. 完成的工作

### 2.1 设备侧（只读）
- 两轮共拉取 11 个 jar/apk（约 52 MB）+ 4 个 native so + atlasservice.rc，全部落在 `artifacts_adb/binder_audit/`。
- 关键材料：`framework.jar`(33.7 MB, 4 dex)、`services.jar`(18.3 MB, 2 dex)、`OppoAtlasService.apk`、`libatlasservice.so` 等。
- 确认 `atlasservice` 以 root 运行、`/system_ext/bin/atlasservice` 对 shell 不可读。
- 保存 `service_list_F16.txt`（236 服务 / 35 私有）。

### 2.2 CVE 核验（外部）
审核意见引用的 5 个 CVE 全部属实，但均为跨设备/跨版本案例，无一直接指向 K3（详见第一轮记录）。

### 2.3 离线审计
- 环境：纯 Python `androguard 4.1.4`（含 HiddenApi bug 补丁），无需 JRE。
- 脚本：`full_audit.py`（35 服务覆盖+Stub 审计）、`scan_classes.py`、`audit_services.py`、`audit_ontransact.py`、`deep_method.py`。
- 产出：`full_audit_report.txt`（35444 类 / 17 dex）、`services_perm_matrix.txt`、`ontransact_report.txt`、`atlas_impl.txt`。

**方法论要点**：AIDL/HIDL `Stub.onTransact` 只有 `enforceInterface`，从不在 Stub 层做调用者鉴权（28 个服务中 27 个 perm_calls=0 是正常现象，唯一例外是 `IOplusCustomizeService`）。鉴权在服务实现方法或 SELinux 层。未据此误判漏洞。

---

## 3. 覆盖度与证据链缺口

| 环节 | 状态 |
|---|---|
| 35 服务接口定义 | **28/35 覆盖** |
| 7 个服务实现 | 未纳入（独立 apk/服务） |
| atlas `setEvent` Java→native 链 | **已证实**（含 root init service） |
| native 层参数处理 | **已反汇编证实**（第四轮）：`libatlasservice.so` 未 strip，`setEvent`/`caputureLogs`/`checkPath`/`doLogCaputure`/`threadLoop` 调用图完整还原 |
| shell 对 atlas 服务的 SELinux 可达性 | **已实证：可达**。用标准只读 `dumpsys AtlasService` 作探针（DUMP_TRANSACTION，非业务事务号），捕获新增 avc：`avc: denied { use } for path="pipe" scontext=u:r:atlasservice:s0 tcontext=u:r:shell:s0 tclass=fd`——主语是 root 域 atlasservice 在使用 shell 传入的 fd，证明 shell 的 binder 调用**确实到达** root 服务进程，SELinux 未在 `{ call }` 层拦截。对照组 `dumpsys commondcs` → "Can't find service"，无 avc。按 HANDOVER 约定未盲试业务事务号。 |
| 第二个 atlas 服务 | `0 AtlasService: [android.atlas.service]`（**root atlasservice 直接持有**）与 `121 multimediaDaemon: [IOppoMMAtlasService]`（`u:r:system_app:s0` 持有）并存。可达性实证针对前者。 |
| 命令注入环节 | **确定否证**（第四+五轮）：`system()` 调用 3 处均属实，但命令模板 `dmesg > %s%s%s` / `chmod 0777 %s` / `%s > %s%s` **首参硬编码**；用户 value 流向路径构造与 `kill` pid,非命令本体。第五轮解出 root 二进制本体，证实其为薄壳且加载的 so 与已反汇编版字节一致（SHA256 `b65dde22…`），无第二处注入逻辑。 |

---

## 4. 关于"路径 B（受控 setEvent 探针）"的评估与下一步

**结论：路径 B 的技术价值在第四轮后已大幅下降，不建议执行。** 原因：

- 静态反汇编已证明可读 native 库中的 `system()` 命令模板是硬编码的,用户 value 不进入命令本体。**盲发探针即使触发 `system()`,也只会执行固定的 `dmesg`/`chmod` 命令,不会验证"命令注入"。**
- 盲试无法观测结果:本机 dmesg/kmsg/pstore 全不可读(HANDOVER §2.3),`system()` 输出无回显通道。
- 它违反 HANDOVER"不盲试事务号"约定,且对 root 服务发构造参数有真实副作用,收益/风险比已不成立。

**时长的直接回答**（若仍坚持):准备探针程序(Zig 交叉编译)+ 物色事件号 int 值 + 上机观察,**净执行约 0.5–1 小时**;但由于事件号取值空间未知、`setEvent` 触发的是异步 `OplusAtlasLogThread`、且无输出 oracle,**实际极可能是"发出去了但什么也证明不了"**,超时或反复试探会拉长到数小时且无结论。**时间不是主要成本,无效性才是。**

**建议的收尾路径（按优先级）：**

1. ~~确认 shell 可达性~~ **已完成（第三轮）**。
2. ~~native 命令注入环节~~ **已完成（第四轮）：基本否证**。
3. ~~纯静态补强：解出 root 二进制~~ **已完成（第五轮）**：Range 只取 2.55 GiB 的 `system.new.dat.br` 重建镜像并解出 root 二进制，证实为薄壳、加载 so 与已反汇编版一致，无第二处注入逻辑。此路径关闭。
4. **维持 no-go 并归档**：五环证据全部闭合，atlas 线索确定否证——本机上被审计得最彻底的一条，结论为"结构相似但注入模式不成立"。不再需要设备在线。

**红线不变**：不盲试 `service call` 业务事务号、不做破坏性实验、不推送 su/Magisk、每重启先补文档。

---

## 5. 一句话交接

> 审核意见属实但为跨设备类比；五轮审计把覆盖度从 2/35 提到 28/35，把 atlas 线索从"类比"追到"本机 root 二进制"：`setEvent(int,String)` Java 层无鉴权 → native `setEvent` → `OplusAtlasLogWriter` → `OplusAtlasLogThread` → `system()`,shell binder 可达、root init service 存在,但 `system()` 命令模板全部硬编码(`dmesg > …`/`chmod 0777 …`),value 只进路径与 pid。**第五轮纯静态解出 root 二进制,证实其为薄壳且加载的 so 与已反汇编版字节一致(SHA256 `b65dde22…`),无第二处注入逻辑——证据链 5/5 闭合,线索确定否证,维持 no-go。** 全程未盲试业务事务号、未走代理下载大文件、未改动设备。
