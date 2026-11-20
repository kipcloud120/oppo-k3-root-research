# KASLR 证据固定（v13 阶段 1 交付物，2026-11-20）

> 状态：**权威证据台账**。把 `live_probe/DUMPSTATE_KASLR_PATH.md` §8 的一次成功实验固化为可复算、可审计的证据记录（响应审核 v013 P0.1–P0.4）。
> 性质：纯离线文档收口，零上机，不改变四层判定（可用 root / 持久 ROOT 仍 NO-GO）。
> 方法原始记录：`live_probe/DUMPSTATE_KASLR_PATH.md`（§1–§7 路径判定、§8 上机判定）。

---

## 0. 一句话

**当前 boot（`b9f9f06a…`）的 `.text` KASLR slide = `0x1953600000`，运行时 `_text = 0xffffff995b680000`；由 dumpstate 内核日志中 `sysfs_create_dir_ns+0xb8` 的原始 pc/lr 经 `vmlinux.elf` 静态符号独立推出，两路一致、2 MB 对齐、寄存器族核对通过，并与重启前 boot（slide `0x16a000000`）的四路推导跨 boot 复现。**

本文件回答四个问题：证据是什么（§2）、证据是否完整且未被篡改（§3）、每个地址属于哪个 boot（§4）、什么条件下该证据能/不能再次取得（§5）。

---

## 1. 推导链（可复算，全部数值本轮重新独立复算）

### 1.1 静态符号基准（`vmlinux.elf` 符号表，权威）

| 符号 | 静态链接 VA | 来源 |
|---|---|---|
| `sysfs_create_dir_ns` | `0xffffff80082dcab0` | `vmlinux.elf`（`tools/kfn.py sysfs_create_dir_ns` 复核） |
| `proc_register` | `0xffffff80082cccf0` | 同上 |
| `_text` | `0xffffff8008080000` | 同上 |

> 方法学警示（沿用 §3 记录）：`firmware_F16/kallsyms_out.txt` 中的地址是**文件偏移**而非链接 VA，符号换算必须用 `vmlinux.elf`。

### 1.2 当前 boot（slide = `0x1953600000`）

原始证据（newboot 的 bugreport KERNEL LOG 段，行 33804–33820 区间）：

```
pc  : 0xffffff995b8dcb68   = runtime(sysfs_create_dir_ns) + 0xb8
lr  : 0xffffff995b8dcb64   = runtime(sysfs_create_dir_ns) + 0xb4
sp  : 0xffffffc51fa1f910   （init/swapper 内核栈，③ 类方向的旁证，非 W 线程栈）
x29 : 0xffffffc51fa1f910   （帧指针 = sp，一致）
x28 : 0xffffff995d084e50   x27 : 0xffffff995d622000   （数据段族）
x15 : 0xffffff995ba898b8   x7  : 0xffffff995d46af38   （文本/数据段族）
```

slide 推导（两路独立 + 对齐校验）：

```
slide = pc − (static(sysfs_create_dir_ns) + 0xb8) = 0xffffff995b8dcb68 − 0xffffff80082dcb68 = 0x1953600000
slide = lr − (static(sysfs_create_dir_ns) + 0xb4) = 0xffffff995b8dcb64 − 0xffffff80082dcb64 = 0x1953600000  ✓ 一致
运行时 _text = 0xffffff8008080000 + 0x1953600000 = 0xffffff995b680000
对齐校验：0x1953600000 mod 0x200000 = 0  ✓（arm64 4.9 KASLR 2 MB 粒度）
寄存器族静态对应（供复核，不做符号指认）：x28−slide=0xffffff8009a84e50、x27−slide=0xffffff800a022000、
x15−slide=0xffffff80084898b8、x7−slide=0xffffff8009e6af38
```

本轮新增核对：`PC: 0xffffff995b8dcb28` 的 oops 反汇编窗头 = `runtime(sysfs_create_dir_ns)+0x78`，与寄存器族一致 ✓。

**判据满足情况（对照 §8 判据）**：pc/lr 两路独立推出同一 slide ✓；寄存器族同函数偏移一致 ✓；2 MB 对齐 ✓；跨 boot 预测复现（§1.3）✓。本轮 boot 的第二个 WARN（`proc_register`，t=0.966 s）不在 dmesg 段内（段止于 0.371 s），**未采**——判据已由 pc+lr+寄存器族满足，不强求（§8.4-3 口径不变）。

### 1.3 重启前 boot（slide = `0x16a000000`，跨 boot 复现）

原始证据：`/cache/recovery/last_kmsg`（重启后采集，内容为重启前 boot 的 console 全量；SHA-256 见 §3，与重启前拉取副本**逐字节一致**，预测"重启后 last_kmsg = 重启前 boot"命中）。

```
pc1 = 0xffffff81722dcb68 = runtime(sysfs_create_dir_ns) + 0xb8 → slide = 0x16a000000
lr1 = 0xffffff81722dcb64 = runtime(sysfs_create_dir_ns) + 0xb4 → slide = 0x16a000000
pc2 = 0xffffff81722ccde8 = runtime(proc_register)        + 0xf8 → slide = 0x16a000000
lr2 = 0xffffff81722ccde4 = runtime(proc_register)        + 0xf4 → slide = 0x16a000000
运行时 _text = 0xffffff8172080000；2 MB 对齐 ✓；四路全部一致 ✓
```

两 boot slide 差值 = `0x17e9600000`（≈ 102 GiB 量级），进一步佐证 slide 逐 boot 独立。

---

## 2. 取证元数据台账（每次一条，按审核 v013 要求的字段）

### 记录 A：当前 boot（**唯一对当前有效的 slide**）

| 字段 | 值 |
|---|---|
| `boot_id` | `b9f9f06a-2f2c-470f-8887-c9bb004bdaa2` |
| 重启方式 | 用户**明确授权的一次性** `adb reboot`（16:32）；不构成后续重启许可 |
| 内核镜像 SHA-256（boot.img） | `22fc092657f73049505982478974e9ca03265b8069f68bfce8555ddb00a36c3f` |
| 解压内核 SHA-256（kernel.decompressed） | `95a70412da3d1cb6be14c7f8ba62112617634035101dc20dfb669395613baebc` |
| vmlinux.elf SHA-256 | `6588c87178ecbf840f19d5fef4a0ce8f71343b7183eed721e06c546c6e36189a` |
| bugreport 采集时间 | 2026-11-20 16:33:56 启动（uptime ≈ 100 s），16:36 完成 |
| 证据文件 | `.build/bugreport_20261120/newboot.zip`（SHA-256 `754925b4b6aee631e206cb1df8ae9618badc227e2e2b3cdd642feef2a0b8379b`）；解包主报告 `bugreport-PCGM00-…-16-33-56.txt`（SHA-256 `ab0d72575a4687fb9cb6b8da121258d48cff6c6f2f450f226b545603513c0795`） |
| 原始 pc / lr | `0xffffff995b8dcb68` / `0xffffff995b8dcb64` |
| **slide** | **`0x1953600000`** |
| 对齐与符号偏移校验 | 2 MB 对齐 ✓；+0xb8/+0xb4 与静态反汇编窗一致 ✓；寄存器族一致 ✓ |
| 有效性 | **仅本 boot**。再重启即失效，须重走 dumpstate 流程 |

### 记录 B：重启前 boot（历史值，仅作方法学复现）

| 字段 | 值 |
|---|---|
| `boot_id` | `27520eec-0945-44db-930d-0c0fd61c1eeb`（自 2026-11-20 上午起持续 76 h 的 boot） |
| 内核镜像 / vmlinux.elf | 与记录 A 相同（同固件，未 OTA） |
| 采集时间 | 2026-11-20 16:17:19（`final.zip`）与 16:33:56（newboot.zip 内 last_kmsg 副本，两份逐字节一致） |
| 证据文件 | `final.zip`（SHA-256 `c9c8109186e44d4596160d6786469d08d7285cb576596116eec7c447ef4d4664`）；`unzipped/…16-17-19.txt`（SHA-256 `59b76258141e421e1f43a88b3392d30ce402b0e6b843cd903e79eea7fa17b194`）；last_kmsg（SHA-256 `262b263169917a30b08677f40b8ee76d3b91af0060c85163caa81956dfb9e553`） |
| 原始 pc/lr（两 WARN 四路） | `0xffffff81722dcb68/64`（sysfs）、`0xffffff81722ccde8/e4`（proc_register） |
| **slide** | **`0x16a000000`**（四路一致） |
| 有效性 | 对当前 boot（`b9f9f06a…`）**无效**；仅证明推导链可跨 boot 复现 |

---

## 3. 证据完整性与已知异常（P0.2）

### 3.1 SHA-256 台账

| 文件 | SHA-256 | 说明 |
|---|---|---|
| `firmware_F16/vmlinux.elf` | `6588c871…6e36189a` | 符号权威 |
| `firmware_F16/kernel.decompressed` | `95a70412…5613baebc` | 内核解压镜像 |
| `firmware_F16/boot.img` | `22fc0926…db00a36c3f` | 原始启动分区镜像 |
| `newboot.zip` | `754925b4…f2a0b8379b` | **当前 boot 的完整 bugreport（含 KERNEL LOG 段）** |
| `newboot.zip` 内主报告 txt | `ab0d7257…513c0795` | 解包后单文件 |
| `newboot.zip` 内 `FS/cache/recovery/last_kmsg` | `262b2631…dfb9e553` | 重启前 boot 的 console（353,178 B） |
| `final.zip` | `c9c81091…7ef4d4664` | 重启前 boot 的完整 bugreport |
| `unzipped/…16-17-19.txt` | `59b76258…fa17b194` | 重启前主报告 |
| `unzipped/FS/cache/recovery/last_kmsg` | `262b2631…dfb9e553` | 与 newboot.zip 内副本**逐字节一致**（跨 boot 预测复现的证据本体） |

> 证据目录 `.build/bugreport_20261120/` 按 `.gitignore` 不入库；公开报告只保留方法、偏移关系、哈希与脱敏摘要（审核 v013 安全发布建议）。

### 3.2 本轮核查发现的异常（如实记录）

| # | 异常 | 影响 | 处置 |
|---|---|---|---|
| 1 | `klog_newboot.txt` 为 **0 字节**（§8.5 曾列为留存证据之一），当前 boot 的 KERNEL LOG 文本提取未落盘 | 无损：主报告 txt 已在 `newboot.zip` 内完整留存，KERNEL LOG 段（33566–33960 行）已重新解包核对 | 以 `newboot.zip` 内主报告为准；空文件仅作异常登记 |
| 2 | `last_kmsg_postreboot.txt` 未在证据目录中（§8.5 提及） | 无损：`newboot.zip` 内 `FS/cache/recovery/last_kmsg` 即该文件本体，且与重启前副本逐字节一致 | 以 zip 内文件为准 |
| 3 | 两个 adb 拉取产物文件名末字符截断（`…dumpstate_log-5611.tx`、`…16-17-19.zi`） | 已在 §6 登记（adb pull 文件名截断教训的又一实例）；完整文件分别在 `unzipped/` 与 `final.zip` | 保留作教训物证，不作判据 |

---

## 4. 地址归属区分（P0.3）

**原则：每个运行时内核地址只属于它被打印时所在的那个 boot。**

| 归属 | boot_id | slide | 证据物 | 对当前 boot 有效性 |
|---|---|---|---|---|
| **当前 boot** | `b9f9f06a-…` | `0x1953600000` | `newboot.zip` KERNEL LOG 段 | ✅ **唯一有效来源** |
| 重启前 boot | `27520eec-…` | `0x16a000000` | last_kmsg（两份逐字节一致副本） | ❌ 复现用 |
| 历史 boot ×4（.1–.4） | 各自不同 | 各自不同 | `unzipped/…/last_kmsg.1–.4`，pc 各异（如 .1 = `0xffffff9c562dcb68`、.2 = `0xffffff89adcdcb68`、.3/.4 显示 `+0xb8` 相对量相同但绝对值不同） | ❌ 仅证 slide 逐 boot 随机 |
| 历史 boot ×5（.5–.10） | 各自不同 | 不可按当前符号表换算 | `last_kmsg.5–.10` 的 WARN 源与当前内核不同（偏移形态 0xa0/0xd4，非 0xb8/0xf8 对） | ❌ **大概率出自旧内核构建**，不可用当前 `vmlinux.elf` 推导 |

> .5–.10 的形态差异是**新登记的边界事实**：早期 WARN 集合不是恒定的"sysfs + proc_register"对；跨 OTA/内核构建后，符号基准必须重新核对。当前内核（2025-03-26 构建）的必现对为 sysfs(t≈0.28 s) + proc_register(t≈0.97 s)。

附带泄露的 `sp`（两 boot 均为 init/swapper 栈，`0xffffffc51fa1f910` / 旧 boot 对应值）属 ③ 类方向的**旁证信号**，不外推为 W 线程栈（v013 纪律：init/swapper 的 SP 不能填 GhostLock ③）。

---

## 5. dumpstate 日志保留边界与成功/失败条件（P0.4）

### 5.1 时序边界（本次双 boot 实测）

| 事实 | 数值/条件 | 来源 |
|---|---|---|
| 必现 WARN 时刻 | t≈0.278 s（sysfs）、t≈0.966 s（proc_register） | 新旧 boot 一致 |
| 新 boot 的 KERNEL LOG 段覆盖 | **t = 0 → 0.371 s**（396 行），段在 0.371 s 截止 | 本次实测（机制未定，见 5.3） |
| 76 h 老 boot 的段覆盖 | 仅最近 ~26 分钟（ring 被 76 h 高频厂商日志覆盖，早期 WARN 已逐出） | §4 |
| `logcat -b kernel`（256 KiB logd 缓冲） | 两个时点均为空 | **不能替代 dumpstate** |
| pstore/ramoops | 只保留上一次 boot 的 console（与 last_kmsg 同源） | 对当前 boot 无效 |
| dumpstate 流程耗时 | ≈ 2m45s–3m（bugreportz -p，5505/5505） | §1/§8.1 |

### 5.2 成功条件（判定型清单）

同时满足以下全部条件，才能取得**某 boot** 的 slide：

1. 该 WARN 事件仍在该 boot 的 dmesg ring / dumpstate KERNEL LOG 覆盖窗口内（**重启后尽早采集**是唯一已证充分手段——本次 uptime ≈100 s 采集即命中）；
2. 经 `ctl.start dumpstate`（init 服务路径；shell 直接执行二进制被拒）；
3. 产物经 `bugreportz -p` socket 协议产出 zip，shell 属主可读可拉取；
4. 段内至少含一个 `WARNING` 的原始 `pc : [<addr>]`（本轮判据：pc + lr 同函数 + 寄存器族；单 pc 亦可推，但置信降档）；
5. 用与该 boot 同固件的 `vmlinux.elf` 做符号换算（OTA 后旧符号表作废）。

### 5.3 失败条件（已观测或可预期）

| 条件 | 后果 |
|---|---|
| 高 uptime 后才采集（早期 WARN 已被 ring 覆盖） | 老_boot 形态：段只剩最近 ~26 分钟，取不到早期 WARN |
| 新 boot 段提前截止（如本次止于 0.371 s） | 第二个 WARN（0.966 s）采不到——单 pc+lr 判据仍成立，但属降档证据 |
| 重启后再采集 | 得到的是**新** boot 的 slide，旧 slide 作废（记录 A 的有效性随之终止） |
| OTA 更换内核 | 静态符号表全部失效，须重建 `vmlinux.elf` 并重新核对 WARN 集合（§4 .5–.10 教训） |
| logcat/pstore 替代路径 | 已实测不可用（5.1） |

### 5.4 停止标准（审核 v013 口径）

当前 boot 的 slide 已取得、符号对应与交叉验证一致 → **冻结该 boot 的结果**：不重复扫描、不为"再证明一次"而重启。重启属于**单独、逐次授权**的操作；本次授权不构成永久重启许可。

---

## 6. 对项目判定的意义与边界

1. **①-s 类（`.text` KASLR slide）获取原语在本机成立**：`ctl.start dumpstate → bugreport → 内核日志原始 pc/lr → vmlinux.elf 静态符号 → slide`。`FEASIBILITY_v008.md` "本机无获取 `kimage_voffset` 原语"的表述在**已审接口范围内**仍然成立；本路径经 dumpstate 第三主体 + 一次授权重启在其范围外实证补齐。
2. **slide ≠ 可用 root**：GhostLock ②（可控 rt_mutex 堆地址）与 ③（W 线程内核栈基址）缺口不变；slide 不能推导堆对象地址，也不能推导持锁 W 线程的栈地址。
3. **附带 `sp` 仅登记**：两 boot 的 `sp` 均属 init/swapper，不满足 ③ 的判据（地址须属于目标 W 线程）。
4. **四层判定不变：可用 root / 持久 ROOT 仍 NO-GO。**

## 7. 安全发布边界

- 公开仓库（本文件 + README/CLOSURE/HANDOVER 摘要）保留：方法链、静态符号偏移（+0xb8/+0xf8 等）、哈希台账、对齐判据、成功/失败条件。
- 受控证据归档（`.build/bugreport_20261120/`，不入库）保留：原始运行时地址、完整 bugreport、last_kmsg 全量。
- 公开正文中的运行时地址以**本文件为唯一完整记录点**，外部引用应指向哈希与本文件，而非转载原始指针值。
