# GHOSTLOCK_ADDRESS_BASELINE.md —— 阶段 3 / G0：地址证据基线（2026-11-20）

> v13 阶段 3 第一步（响应审核 `审核意见CHATGPT-v013-step3.txt` G0）。**纯离线文档，零上机，零新增设备操作，不改变四层判定**。
> 哈希链与取证台账的**唯一权威**是 [`KASLR_EVIDENCE.md`](KASLR_EVIDENCE.md)；本文只登记 GhostLock 复评所需的**地址清单基线**与**强制审计规则**，不复制其内容。

## 0. 一句话

**v13 基线下的四类地址状态：①A（`.text` slide）已取得（当前 boot `b9f9f06a-…`）；①B（Direct Map / mm_struct）已验证（上一次 boot，需重新采集）；②（有效、可控 rt_mutex 对象地址）未解决；③（持 stale waiter 的 W 线程栈地址）未解决。GhostLock 的核心约束在 ②/③，v13 新成果没有改变它们。**

---

## 1. 地址证据 ↔ 取证物料绑定表（G0 交付核心）

| 地址项 | 运行时值 | 所属 boot | 绑定的取证物料 | 有效性 |
|---|---|---|---|---|
| ①A `.text` slide | `0x1953600000`（运行时 `_text = 0xffffff995b680000`） | `b9f9f06a-2f2c-470f-8887-c9bb004bdaa2` | `newboot.zip` KERNEL LOG 段（pc/lr `0xffffff995b8dcb68/64`） | 仅本 boot；再重启失效 |
| ①A 复现链（重启前 boot） | slide `0x16a000000` | `27520eec-0945-44db-930d-0c0fd61c1eeb` | last_kmsg（两份逐字节一致副本，SHA `262b2631…`） | 复现用，非当前值 |
| ①A 符号基准 | `vmlinux.elf`（SHA `6588c871…`，`sysfs_create_dir_ns=0xffffff80082dcab0` 等） | 与固件 `PCGM00_11_F.16` 绑定 | `firmware_F16/vmlinux.elf` + `boot.img`（SHA `22fc0926…`） | OTA 后全部作废 |
| ①B mm_struct | `0xffffffda42a97100`（19/19）、`0xffffffda434d5500`（26/26） | **上一台次开机**（v8 采集时点，早于 ①A 的 boot） | `live_probe/` v8 数据 | **已随重启失效**；方法可复用 |
| ② rt_mutex 对象 | 无 | — | — | **未解决** |
| ③ W 线程栈 | 无 | — | — | **未解决** |
| 旁证 sp | `0xffffffc51fa1f910` 等 | 两类 boot 均有 | dumpstate WARN 寄存器 dump | **init/swapper 栈**，不满足 ③（§3 规则 R4） |

> 注意 ①B 与 ①A 属于**不同的 boot**：mm 地址在 v8 采集的开机上有效，slide 在 2026-11-20 16:32 授权重启后的 boot 上有效。两者不可混用；若未来同时需要 ①A+①B，须在同一 boot 内分别采集。

---

## 2. 地址能力的"能证明 / 不能证明"强制规则（step3 意见 P2，成为审计纪律）

| 观察到的内容 | 能证明 | **不能证明** |
|---|---|---|
| PC/LR（原始） | 当前 boot 的代码运行时地址（⇒ slide） | 任何目标对象地址 |
| `.text` slide | 内核镜像运行时位置；**任一有符号名的镜像内对象的运行时地址** | 内核堆布局；任何堆/栈对象位置 |
| Direct Map / mm_struct | 该 mm_struct 所在线性映射页的位置 | 其他对象（含同进程线程栈）的具体地址 |
| 某线程的 SP | **该线程**当时的栈地址信息 | **另一个线程**的栈地址（同进程各线程独立 16 KB 栈） |
| 静态符号 VA | 链接期位置 | 运行时位置（须 + 当前 boot slide 才可换算） |

**本轮新登记的推论（由 ①A 派生，须按规则 R2 使用）**：slide 使得"静态符号 VA → 运行时 VA"的换算在当前 boot 成立。这改变了"已知内核地址"类的可得性（G1/G2 中使用），但按 step3 意见 §1 的技术判断——**普通内核地址 ≠ 有效 rt_mutex 对象**——它不自动满足 ②。

---

## 3. 强制审计规则（阶段 3 全程有效）

- **R1（类型规则）**：任何新地址必须先归类——镜像地址 / Direct Map 地址 / 堆对象地址 / 特定线程栈地址，四者互不可替代。
- **R2（时间规则）**：任何运行时地址必须绑定 `boot_id` + 内核构建（固件哈希）；跨 boot 引用一律无效。
- **R3（对象身份规则）**："看起来合法的地址"不算 ②。②的判据是**有独立证据确认对象类型**（反汇编/源码级证据证明该地址处确实是结构合法的 `rt_mutex`）。
- **R4（线程归属规则）**：③的判据是地址**属于目标 W 线程**（持有 stale waiter 者）。init/swapper、kworker、其他线程的 SP 均不满足；同进程不同线程栈互相独立。
- **R5（生命周期规则）**：对象在被观察时必须有效；已释放/复用地址不得当作活对象登记。
- **R6（证据等级不可互换）**：静态源码证明 < 精确固件反汇编证明 < 离线数据推导 < 真机运行时观测 < 独立交叉验证，五级各自独立记账，高级别结论不因低级别补证而升级，反之亦然。

## 4. 基线冻结项（承接 step3 意见 §八）

| 项 | 决定 |
|---|---|
| 静态符号表重复提取 | 冻结（本轮已确认 `vmlinux.elf` 符号 `st_size` 全为 0，尺寸枚举类工作受物料限制，见 G2 §B3） |
| 重复验证 KASLR slide | 冻结为当前 boot 证据（`KASLR_EVIDENCE.md` 停止标准） |
| KernelSnitch 重复扫描 | 冻结（M1 已冻结为已验证工具） |
| M2 时间邻接固定 delta | 继续冻结（v10 真机示踪否证不受 slide 影响） |
| 泛化"非零内核地址"搜集 | 不作为有效进展记账 |
| 未经验证的 W 线程栈地址假设 | 不纳入利用条件 |

---

## 5. 引用

- 哈希链与取证台账：[`KASLR_EVIDENCE.md`](KASLR_EVIDENCE.md)（§1 推导、§2 元数据、§3 完整性、§4 归属、§5 边界）
- 方法原始记录：`live_probe/DUMPSTATE_KASLR_PATH.md` §8
- 需求分解：`GHOSTLOCK_ADDRESS_REQUIREMENTS.md`（G1）
- 来源矩阵：`GHOSTLOCK_ADDRESS_SOURCE_MATRIX.md`（G2）
- 决策：`GHOSTLOCK_PHASE3_DECISION.md`（G3）
