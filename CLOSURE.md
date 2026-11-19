# 判定：PCGM00 F.16 —— 可用 ROOT 为 NO-GO；GhostLock 研究路径重开（v3.0 + v008 口径收紧，2026-11-19）

| | |
|---|---|
| 设备 | OPPO K3 `PCGM00`（`OP4679`，`sdm710`），`PCGM00_11_F.16`，Android 11 |
| 内核 | `4.9.227-perf+`（clang 10.0.7，2025-03-26 构建） |
| 安全补丁 | `2022-04-05` |
| 启动状态 | BL 锁定、AVB `green`、dm-verity `enforcing`、A-only（v3 实测基线复核一致，无 OTA） |
| 唯一入口 | `uid=2000(shell)` + `u:r:shell:s0`，SELinux Enforcing，`Seccomp: 0` |
| 判定版本 | `HANDOVER.md` v3.0 + v008 口径收紧（含 v007 评估、双方向预研、真机实测 §38–§42；v008 响应 §43，权威 `FEASIBILITY_v008.md`） |
| 判定范围 | **本机、本固件、不解 BL**。不是"任何条件下不可能"，也不是"任何设备不可能" |

---

## 0. v3 一句话

**这台机器能给你的上限，仍是"以 root 身份在别人写好的笼子里跑命令"——可用 root 判定不变。但笼子的一面墙（GhostLock 的"无地址泄露"）在 v3 被真机实测打开了一道缝：futex 哈希侧信道可用，能拿到 mm_struct 在线性映射（DPM）中的地址；只是这道缝通向的不是 fake waiter 需要的那间房。因此 GhostLock 从"收口冻结"重开为活跃研究路径，缺口从"没有地址"精确化为"地址类型不对 + 缺堆喷原语"。v008 进一步收紧口径：这道缝给的是 DPM 堆页位置（+无秘密的物理换算），**不是** `.text` 的 KASLR slide（后者由 `kimage_voffset` 独立承载，本机拿不到）。**

---

## 1. 四层判定

| 层次 | 结果 |
|---|---|
| Root UID 命令执行 | **达成**（2026-11-18，两次独立载荷复现，§23） |
| 可用 root（脱离域限制的系统管理能力） | **NO-GO**（域逃逸静态无路径 §24；FastRPC 在 uid 0 域下更封闭 §32） |
| 持久 ROOT | **NO-GO**（且全程未做任何持久化写入） |
| GhostLock 内核地址泄露 | **部分达成**：① mm_struct 线性地址真机可得（§41）；slide 拿不到（v008 更正，`FEASIBILITY_v008.md` §1）；②/③ fake waiter 所需地址类型仍缺（§40/§42）⇒ **研究路径重开** |

---

## 2. GhostLock 重开判定（v3 核心）

### 2.1 此前的收口理由与其 v3 状态

旧稿把 GhostLock 收口在"载体已闭合、缺内核地址泄露"（§15.4 / §23.9）。v3 逐项复核：

| 旧判据 | v3 状态 | 依据 |
|---|---|---|
| "本机无内核地址泄露" | **部分作废**：futex 哈希侧信道真机可用（110× 信号），可得 mm_struct 线性地址（DPM 堆页位置）；**KASLR slide 拿不到**（v008 更正） | §41 实测；`live_probe/LIVE_PROBE_RESULT.md`；`FEASIBILITY_v008.md` §1 |
| "fake waiter 的 lock/rb 需非零内核地址" | **维持并精确化**：lock 会被解引用（trylock 写 + owner/waiters 读 + `BUG_ON` 校验），需要"可控、内核可写、结构合法 rt_mutex 的内核地址" | `artifacts_adb/WAITER_ADDRESS_ANALYSIS.md` §2 |
| "载体侧已闭合" | **维持**：xattr 三条栈覆盖候选、NUL 不阻断、栈复用几何确定 | §15 / GHOSTLOCK_NUL_ANALYSIS |
| "`!VMAP_STACK` 无关" | **更正**：本机实测 `!VMAP_STACK`，栈在线性映射区且与 mm_struct 同区；但 futex key 不含栈地址 ⇒ 仍够不着栈 | §42 / WAITER_ADDRESS_ANALYSIS §5.5 |

### 2.2 按地址类型分档（重开条件的新口径）

> GhostLock 真正缺的**不是"任意一个内核地址"**，而是特定类型。§7 第2条(a) 的旧表述"任一可用内核地址泄露即重开"过宽，v3 细分为：

| 档 | 地址类型 | 本机状态 | 能否填 fake waiter |
|---|---|---|---|
| ① | mm_struct 线性地址 / KASLR slide / DPM 基址 | **真机可得**（§41），侧信道可用 | ❌ 不够：解引用 + 结构校验过不了；缺堆喷把它兑现 |
| ② | 某个可控 rt_mutex 的堆地址（pi_state / skb 喷射页，等价参考项目 `payload_base`） | ❌ 无堆喷原语（setxattr 2000 次仅 33 次成功、kmalloc-128 delta=0；无 SYSVIPC） | ✅ 能——这是参考项目的成功路径 |
| ③ | 当前内核栈地址（W 线程，持有 stale waiter） | ❌ 无侧信道：futex key 不含栈地址；USENIX'25 栈侧信道依赖 VMAP_STACK，本机恰好关闭 | ✅ 能（几何偏移已静态解决，缺的是拿栈基址的 oracle） |

⇒ **重开结论**：GhostLock 作为研究路径重开；当前处于"① 已解决、②/③ 未解决"的阶段。**可用 root 判定不变**——②/③ 任一闭合前，不构成提权。

### 2.3 参考项目为何能成功（关键反证）

`yijiacloud/GhostLock-OPPO-PCKM00`（PCKM00 / 4.14.180）用 `fake_lock = payload_base + LOCK_OFF`，其中 `payload_base` 来自 **KernelSnitch 泄露的 mm_struct 地址 + AF_UNIX skb 喷射落到内核堆的可控页** ⇒ lock 指向内核堆上的受控 rt_mutex，**从头到尾不需要栈地址**。K3 缺的正是那个 skb 堆喷原语，所以同样的 slide 在 K3 无法兑现。

---

## 3. 其余三条方向的否证（v3 维持）

### 3.1 域逃逸（原主线）—— 策略层否证

`HANDOVER.md` §24 / `SELINUX_DOMAIN_AUDIT.md`

| 候选 | 断点 |
|---|---|
| 写文件 → 高权限域执行 | 该域可写全部文件类型上持有 `execute` 的域数 = 0（v2.24+ 修正引擎重算仍为 0） |
| `CAP_SYS_ADMIN` 挂载 | 策略无 `filesystem mount`；SELinux 放行 `sys_admin`，墙在内核能力集 `CapEff=0x13000` |
| 加载自定义模块 | 墙是模块签名 `CONFIG_MODULE_SIG_FORCE=y`（策略与 `CAP_SYS_MODULE` 都就位） |
| 属性写 → init 执行 | 命中的 11 条触发器全是 `chmod`/`chown`/`setprop`，无 `start`/`exec` |
| 域转换 | 唯一可达 `crash_dump`，可读集与可写集交集为空，零收益 |

### 3.2 其它内核原语 —— 机制或前提层否证

| 面 | 结论 |
|---|---|
| KGSL `CVE-2023-33107` | 命中缺陷即 `BUG()` panic，无中间态 |
| binder `CVE-2023-20938` | 漏洞未引入 |
| binder `CVE-2022-20421` | pre-fix 但 ticket spinlock 使原语退化 |
| FastRPC `CVE-2023-33063` | uid 0 域下并集 ∅，比 shell 更封闭（§32） |
| `/dev/diag` | 入口层逐路径复核 + 55/55 拷贝点判界、无 mmap、post-fix 形态；DCI 解析子树（G1）未审，且依赖内核指针的利用被 ②/③ 缺口阻断 |

### 3.3 服务面 —— 方法级否证

7 个私有 Binder 服务 7/7 闭合（理由多为"无能力"而非"不可达"）；`system_server` 通道在取句柄处双向断开；Wi-Fi 可写面消费者三道门全封。详见 `HANDOVER.md` §33–§37。

---

## 4. 判定可能错在哪（自我声明）

1. **枚举完备性**：所有消费者/攻击面结论依赖枚举集合；若有未被枚举的面（尤其不经过文件/binder、纯内核驱动接口），收口不成立。
2. **②/③ 缺口的绝对性**：本轮证明 futex 侧信道够不着栈，但未穷尽 4.9 上所有可能的栈地址泄露面（见 §7 可证伪条件）。
3. **策略工具的闭包精度**：v2.24 已兑现成实际错误（`not` 语义 + 版本名合并），修正后多条理由被更正；本域之外尚未逐个回归。
4. **rc 与运行态偏差**：`rc 文本 ≠ 生效集合`，一律以 `init.svc.*` 为准（v2.18 纪律）。
5. **v008 地址口径**：口径收紧由审核 v008 触发、以 `vmlinux.elf` 反汇编为据（`__primary_switched` 的 `kimage_voffset` 计算）；未在真机 dump 运行时 `kimage_voffset` 值（属上机，未授权）。若未来固件改变线性映射随机化行为，R2/R3 关系须重算。

---

## 5. 如何推翻本文（只接受可复算的反例）

| 不构成推翻 | 构成推翻 |
|---|---|
| "侧信道能拿地址了，所以能 root 了" | 给出 ② 或 ③ 类地址的可复算获取路径，并说明如何填进 fake waiter 的 lock/rb 字段 |
| "GhostLock 历史上有漏洞" | 指明本机某字段的越界点，给出可复算的反汇编片段 |
| "root 应该能做更多" | 给出本域能力集的实测反例（当前 `CapEff=CapBnd=0x13000`） |
| 用其它 SPL/内核外推 | 指明本机 SPL `2022-04-05` / 内核 `4.9.227-perf+` 下同一路径的差异 |

---

## 6. 一句话

**这台机器能给你的上限，仍是"以 root 身份在别人写好的笼子里跑命令"。v3 打开了 GhostLock 那面墙的一道缝（侧信道能拿 mm_struct 线性地址），但缝后不是你要的房间（缺 ②/③ 地址类型 + 堆喷原语）；v008 更正：这道缝也给不了 KASLR slide（`kimage_voffset` 独立承载）。本文封存四面墙的最新测量结果，并按 v008 重排优先级（堆地址边界 → 栈泄露面 → 口径收紧）继续挖掘。**
