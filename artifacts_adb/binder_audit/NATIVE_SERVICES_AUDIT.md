# 三个 native 私有服务的补充审计：hans / horae / oiface（2026-11-18，纯离线）

> 承接 §19.3 的"导入表初筛"与 §36 的方法论。新增工具 `tools/native_svc_audit.py`
> （不依赖符号表的 AArch64 PLT xref）。物料：`rootbin/_p2/{hans,horae,oiface}`。**全程离线。**

## 0 一句话

**三个 native 服务都没有发现"调用者可控数据 → 内核/文件/模块加载"的已证路径；
horae 唯一的 `getCallingUid` 返回值被丢弃（不是门禁），hans 的 `sendto` helper 没有直接调用者
（经函数指针/回调，未能证明由 Binder 事务驱动）。⇒ 缺口按"未发现路径"闭合，
但审计深度是**导入/xref 级**，不是完整反编译，重开条件已明确。**

## 1 工具与方法

`elf_analyze.py` 依赖符号表，对 stripped 二进制失效。新工具的做法：

1. 从 `.rela.plt` 取导入名顺序；
2. 在 `.plt` 中识别 `adrp x16 / ldr x17 / add x16 / br x17` 四指令桩，建立 **PLT 地址 → 导入名**；
3. 线性反汇编 `.text`，按 `bl <plt>` 做 xref，并注释附近的 `adrp+add` 字符串引用。

三个二进制的 PLT 映射分别 55 / 178 / 287 条，与 dynsym 数量吻合。

## 2 逐服务结果

### 2.1 hans（31,936 B，.text 0x1888）

| 项 | 结果 |
| --- | --- |
| 接口描述符 | `oppo.hans.IHansComunication`（字符串 `IHansComunication`） |
| Binder 框架 | `defaultServiceManager` ×2、`startThreadPool`、`joinThreadPool` |
| 调用者鉴权 | **无 `getCallingUid` 导入**（0 处） |
| 内核通道 | 有 `socket` / `sendto` / `recvfrom` / `bind` / `socket_local_client`；字符串 `sendMessageToKernel`、`setupSocketToFw`、`netlinkSockCreate`、`enableCpuCtl`、`parseAndProcessMessage` |
| `sendto` 位置 | 0x42d0，所在函数约 `0x416c..0x4508`（232 指令，含 `close`/`bind`） |
| 直接调用者 | **0 个 `bl` 指向该函数起点** ⇒ 只能经函数指针/vtable/线程回调调用 |
| 判读 | 内核通道存在且无 uid 门禁，但**未能证明它由 Binder 事务驱动、或载荷来自调用者**；这是本轮最接近"值得继续"的一条，但证据不足以下结论 |

### 2.2 horae（245,752 B，.text 0x23620）

| 项 | 结果 |
| --- | --- |
| 调用者鉴权 | `getCallingUid` **仅 1 处** @0x1609c |
| 该处上下文 | `setThreadPoolMaxThreadCount` → `giveThreadPoolName` → `joinThreadPool` → `getCallingUid`；**返回值 w0 未被比较**，随后是 String16 析构与栈保护检查 ⇒ **线程池初始化路径，不是门禁** |
| 文件访问 | `fopen` ×3（0x1f1f0 / 0x1f330 / 0x24a4c）、`__open_2` ×1（0x12f54，紧接 `fstat`）；附近调用只有 `__android_log_print` / ostream，**未见 Parcel 读取串流入路径参数** |
| 判读 | 无 uid 门禁，但也无"调用者可控 → 文件"证据；与 §19.3"仅 fopen 读配置"一致 |

### 2.3 oiface（710,352 B，.text 0x7407c）

| 项 | 结果 |
| --- | --- |
| 调用者鉴权 | **无 `getCallingUid` 导入** |
| 模块加载 | `dlopen` ×5；其中两处附近可见格式串 `"%s%ld%ld%ld%ld%ld%ld%ld"`（构造库名），**未见来自 Parcel 的串** |
| 文件访问 | `fopen` ×1（0x2eb04） |
| Binder 传递 | `Parcel::writeStrongBinder` ×1（0x2b84c）——**出站**（把句柄写给对端），不是接收句柄；不会给本域新增能力 |
| 其它 | 字符串含 `android.content.pm.IPackageManager`（作为 client），`bindTencentTask: disabled by cosa` 等开关 |
| 判读 | 无证据表明加载路径/文件路径来自调用者 |

## 3 判定与缺口

| 服务 | 鉴权 | 危险能力 | 是否可控 | 判定 |
| --- | --- | --- | --- | --- |
| hans | 无 | netlink send | **未证**（无直接调用者） | 未发现路径，保留观察 |
| horae | 无（返回值丢弃） | fopen/open | 未证 | 闭合 |
| oiface | 无 | dlopen/fopen | 未证 | 闭合 |

**共同范围限定（不得外推）**：
1. 本轮只做到**导入 xref + 直接上下文**，不是完整反编译；未重建 `onTransact` 的完整分派表
   （三个二进制都 stripped，vtable 需从 `.data` 重定位逐项解析）。
2. hans 的 `sendto` 经函数指针调用，**调用链未闭合**——这是本轮唯一"差一步"的地方。
3. OTA 后二进制变化需重做。

## 4 重开条件

| 缺口 | 重开条件 |
| --- | --- |
| hans netlink 通道 | 找到 0x416c 的调用点，并证明其参数来自 `Parcel::readInt32`/`readString16` 且最终到达 `sendto` 的载荷 |
| horae / oiface | 找到任一 `fopen`/`dlopen` 的路径参数来自 `Parcel::readString16` 的证据 |
| 全部 | OTA 或镜像变化 |

## 5 方法论沉淀

- **"无 `getCallingUid` 导入"只证明"没有显式 uid 门禁"，不证明"没有鉴权"**——可能通过
  `checkCallingPermission`/`AppOps`/服务端状态实现。本轮三个二进制这两类导入也没有，
  但结论仍限定在"未发现"，不作"绝对无鉴权"的表述。
- **"有 `sendto`"不等于"有可达接口"**：必须补上"谁调用它、参数从哪来"两跳。
  hans 正好卡在第一跳（无直接调用者），因此不能升级为发现。
