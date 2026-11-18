# Hephaestus 两个 init 实例的关系（响应审核意见 v006-1）

> 物料：`_p2/hephaestus`（19,216 B，AArch64，stripped）＋ `_p2/self_init_hephaestus.rc`。
> 全部离线：`capstone` 全量反汇编 → `_p2/hephaestus.dis.txt`（578 行，含字符串与 PLT 注释）。
> 本轮**未上机执行该二进制**。

## 0 一句话

两个实例跑**同一个二进制**，也跑**同一份 Binder 实现**，唯一区别是注册的服务名与进程身份；
UID 门禁在 `onTransact` 内部，**root 实例并不绕过它**。因此"root oneshot 实例"不是一条
免门禁的命令执行接口。

## 1 rc 原文（`self_init_hephaestus.rc`）

```
service hephaestus /system_ext/bin/hephaestus
    seclabel u:r:hephaestus:s0   class late_start   user system
    group system root media_rw   oneshot   disabled
on property:oppo.sau.hephaestus=1        → start hephaestus
on property:oppo.sau.hephaestus=0        → stop  hephaestus

service hephaestus_install /system_ext/bin/hephaestus installd
    seclabel u:r:installd:s0     class late_start   user root
    group system root media_rw   oneshot   disabled
on property:oppo.sau.hephaestus_install=1 → start hephaestus_install
on property:oppo.sau.hephaestus_install=0 → stop  hephaestus_install
```

要点：**同一路径，第二个多一个参数 `installd`**；身份分别是 `user system`（uid 1000）与
`user root`（uid 0，域 `installd`）；两者都是 `oneshot + disabled`，只靠属性触发启动。

## 2 逐条回答 v006-1 的五个问题

### Q1 哪个实例实际注册 IHephaestus？

**两个都注册**。`main`（0x2548 起）的执行序：

| 地址 | 指令 | 含义 |
| --- | --- | --- |
| 0x2598 | `cmp w21,#2 ; b.lt 0x25c0` | `argc < 2` 则跳过参数判断 |
| 0x25a0 | `ldr x0,[x19,#8]` → `strcmp(argv[1], "installd")` | 比较第一个参数 |
| 0x25b4 | `csel x20, x8, x20, eq` | 相等取 `hephaestus_install` 那个名字对象，否则取 `hephaestus` |
| 0x2604 | `defaultServiceManager()` | 取 servicemanager |
| 0x265c | `blr x8`（vtable +0x30） | `sm->addService(String16(name), svc)` |
| 0x26d8 / 0x26e0 | 成功分支：`ProcessState::startThreadPool` + `IPCThreadState::joinThreadPool(true)` | **常驻**服务线程 |

⇒ 差别只有 `String16` 名字：`"hephaestus"` / `"hephaestus_install"`。

### Q2 `hephaestus_install` 是否运行相同的 Binder 实现？

**是。** 只有一份二进制、一份 vtable；`onTransact`（0x2438 起）就是那唯一实现：

| 地址 | 指令 | 含义 |
| --- | --- | --- |
| 0x2468 / 0x246c | `IPCThreadState::self()` → `getCallingUid()` | 取调用者 uid |
| 0x248c | `__android_log_print(3,"HEPHAESTUS","calling uid is: %d", uid)` | 记录 |
| 0x2490–0x24b0 | 魔数乘法 + `msub` | 计算 `uid % 100000` |
| 0x24b0 | `cmp w8,#0x3e8 ; b.ne 0x24fc` | **不等于 1000 就跳走** |
| 0x24fc | 日志 `"not apply to this uid: %d"` → `Status::ok()` | 静默返回 |
| 0x24c0–0x24cc | `String8(client_string)` → 取 `char*` | 取参数字符串 |
| 0x24f0 | `system(x21)` | 以**自身身份**执行该字符串 |

所以：**门禁是"调用者 uid"的门禁，不是"实例身份"的门禁**。root 实例被调用时，
门禁检查的仍然是调用者（shell 2000 / Wi-Fi 域 0），一样被拒。

### Q3 oneshot 的生命周期

`oneshot` 只表示"退出后不自动重启"；但 `joinThreadPool(true)` 使进程**常驻**服务循环，
因此一旦 `oppo.sau.hephaestus_install=1` 被设置，`hephaestus_install` 会以 uid 0 / `u:r:installd:s0`
**持续在服务列表里**，直到属性置 0 或进程被杀。

补充事实：`oppo.sau.*` 在 5 份 CIL 与各分区 `*_property_contexts` 中**没有命名空间定义**
（唯一相关的是 `/proc/sau_pwknum`）。即这两个触发属性落在默认属性类型上；
本轮未进一步验证谁能 `set`（`oplus_wifi_service` 对 `sau_prop` 无 `set` 权限，查询结果为空）。

### Q4 是否存在真正的 UID 1000 客户端调用链？

**没有在物料中找到。** 三类候选逐个排除：

| 候选 | 身份 | 判据 | 结论 |
| --- | --- | --- | --- |
| `hans` / `horae` / `oiface` | uid 1000（`ps -A -Z` 实测） | 三个二进制的字符串里**无** `hephaestus`、无 `checkService/getService("hephaestus")` | 不是客户端 |
| `com.coloros.exsystemservice` | uid 1000，域 `color_system_service_app` | dex 字符串池含 `com.oppo.hephaestus.IHephaestus`、`HephaestusService`、`HephaestusService.java`、`hephaestus_install`；但 4,068 个 class_def 里**无一**引用该接口（`source_file` 亦无匹配）；`odex`/`vdex` 仅 82/51 KB 且不含完整 dex | **仅字符串痕迹，无可执行证据** |
| `system_server` / 其他 system 服务 | uid 1000 | 未做全量 dex 检索 | 未闭合（见 §3） |

### Q5 是否有客户端把外部参数传进受保护操作？

在 Q4 找到客户端之前，这个问题无对象。但要注意：**即使存在** uid-1000 客户端，
它能传入的也只是自己的字符串，收益是"在 `hephaestus` 域里以 uid 1000 执行"，
而不是 root——除非它调用的是 `hephaestus_install`（root 实例），而该实例的门禁同样是 uid 1000。

## 3 这条线的真实形状

```
shell(2000) ──binder call──▶ [任一实例] ──onTransact──▶ uid%100000==1000 ? system(str) : 静默丢弃
                                   ▲
                                   └── 门禁看的是**调用者**，两个实例共用同一份判断
```

⇒ 要让门禁通过，必须找到一个**本身就是 uid 1000**、且愿意把外部字符串原样转发给
`hephaestus` 的进程。这就是审核意见 v006-1 所说的"身份代理"，也是本线唯一未闭合处。

未闭合处的**可证伪条件**：给出 `com.coloros.exsystemservice`（或任一 uid 1000 进程）中
一个满足"可由 shell 触发 + 参数原样下发到 `checkService("hephaestus")`"的方法体。
本轮在 dex 里找不到该接口的任何 class_def，因此把缺口记为**物料不足**，而不是"不存在"。

## 4 与既有结论的关系

- §19.2 的"`system()` 被 uid==1000 门禁挡住"**成立且更精确**：门禁在 `onTransact`，
  与实例身份无关；`system@plt = 0x2ab0` 仍是唯一调用点（0x24f0），本轮反汇编复核一致。
- §19.3 的表格不涉及 hephaestus，无需改动；但其"六服务无命令执行"的判据是**导入表检查**，
  对 hephaestus 这类"导入了 `system` 但被门禁挡住"的形态不适用——判据要补一条：
  **有 `system`/`exec` 导入时必须连鉴权一起读**。
- 新增负知识：**"root 实例"不等于"免门禁接口"**。判断 oneshot root 服务时必须读它的
  `onTransact` 鉴权，而不是看 rc 里的 `user root`。
