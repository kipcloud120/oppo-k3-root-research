# `/dev/diag` DCI 报文解析子树审计（v10.1，2026-11-19，纯离线）

> 承接 `DIAG_DRIVER_AUDIT.md`（§25 入口层审计）的余量项 **G1**，响应审核意见 v010 的 P0 建议（Track A）。
> **全程离线**：只用 `firmware_F16/vmlinux.elf`；0 次上机、0 次 ioctl、0 次设备写入。
> 判定范围：本机 `PCGM00_11_F.16` / `4.9.227-perf+` 的该镜像；不外推其它机型或其它 SPL。

---

## 0. 结论（先行）

**未发现可被用户触发的缺陷。** 解析子树的三个落盘/回传路径
（`extract_dci_log` / `extract_dci_events` / `extract_dci_pkt_rsp`）**全部具备"包内声明长度 ⇄ 实收长度"的门**，
且目标缓冲容量在追加前二次校验；子树内部**不存在 `copy_to_user`**（数据只能经已审的客户端读取路径回用户态，
该路径按已填充长度复制）。

⇒ G1 由"未穷尽的攻击面"降级为「**静态否证（含明确残余项）**」。
**这不构成提权**：即便存在逻辑缺陷，仍需 ②/③ 类地址才能兑现（`CLOSURE.md` §2.2）。

---

## 1. 可达性（先证入口，再谈缺陷）

直接调用链（`bl` 目标扫描，`.kernel` + `.kernel2` 全覆盖，非启发式）：

```
diagchar_write              (file_operations.write，§25.5 已审长度门)
  └─ diag_user_process_dci_apps_data   (用户数据 → diag_mempool[0]，len ≤ item_size)
       └─ diag_process_apps_dci_read_data   (cmd ∈ {0x100, 0x200, 0x400})
            └─ diag_process_single_dci_pkt  (按首字节分派)
                 ├─ 0x93 / 0x94 → extract_dci_pkt_rsp
                 ├─ 0x98        → extract_dci_ext_pkt → {extract_dci_log | extract_dci_events}
                 ├─ 0x9a        → extract_dci_ctrl_pkt
                 ├─ 0x10        → extract_dci_log
                 └─ 0x60        → extract_dci_events
```

- **内容完全攻击者可控**：`write()` 载荷经 `diag_mempools[0]` 拷入内核后原样进入解析器，
  包内所有长度字段（`u16@+2`、`u16@+1`、`u8` 子长度）都由调用者给出。
- **调用者身份**：`diag_device` 的 `chr_file` 全操作在本机策略中仅有 `oplus_wifi_service`
  等少数域持有 allow（`HANDOVER.md` §32 表第 6 项）；shell 域不可达。
  即"可达但需以 Wi-Fi 受限 root 域身份运行"——该域正是本项目已掌握的命令执行面。

> 审计纪律：先证入口可达（本节），再证缺陷可控（§2–§3），最后单独判定"能否兑现为提权"（§4）。三者不互相替代。

---

## 2. 三条回传/落盘路径的长度门（判决性证据）

| 路径 | 门（反汇编地址，vaddr） | 判定 |
|---|---|---|
| `extract_dci_log`（0x10） | ① `cmp w1,#7; b.gt` ⇒ 实收 ≥ 8<br>② `w27 = ldrh[pkt+2]`；`cmp w27,#0xfffc; b.lo` ⇒ 声明长度 < 0xFFFC<br>③ `x8 = w27+4; cmp x8, w26(len); b.ls` ⇒ **声明长度 + 4 ≤ 实收长度**<br>④ `memcpy(dst, pkt+4, w27)`（0x8615f34） | ✅ 无越界读 |
| `extract_dci_events`（0x60） | ① `cmp w1,#2; b.gt` ⇒ 实收 ≥ 3<br>② `w1 = ldrh[pkt+1]`；`cmp w1+3, len; b.ne` ⇒ **长度字段必须精确等于 实收-3**<br>③ 逐记录游标 `w23` 每步 `cmp w23, len; b.gt → 丢弃`<br>④ 子长度 `u8`，复制前 `cmp 累计+子长, len; b.gt → 丢弃`<br>⑤ `memcpy(dst, pkt+k, w25)`（0x86156f4 / 0x861571c） | ✅ 游标全程受 `len` 约束 |
| `extract_dci_pkt_rsp`（0x93/0x94） | ① `w9 = (byte0==0x93) ? 1 : 4`；`cmp w9+4, len; b.hi → 返回` ⇒ 实收 ≥ 5/8<br>② `w20 = len - (w9+4)` 作为载荷长度<br>③ 追加前 `used + (w20+0xD) > capacity` ⇒ 按需 `vzalloc(capacity + w20+0xD)` 扩容并搬旧数据<br>④ `memcpy(buf+used, pkt+w9+4, w20)`（0x8615464） | ✅ 长度与容量双向自洽 |

`extract_dci_ext_pkt`（0x98）本身不做拷贝：它要求 `len > 8`、拒绝 `pkt[0]==0xFF`，
再以前缀偏移 8 二次分派给 log/events，并把 `len-8` 作为子长度传入（`0x8615fe8`–`0x8616004`）⇒ 不引入新窗口。

`extract_dci_ctrl_pkt`（0x9a）**函数体内无任何 `memcpy`/`copy_to_user`**，仅做
`diag_ws_on_read` / `diag_ws_on_copy_fail` 流控与 `diag_dci_notify_client` 通知 ⇒ 不构成数据回传面。

---

## 3. 目标缓冲的容量语义（`diag_dci_get_buffer` @0x8618fc8）

```
if (size > 0x4000) return -EINVAL;              // 0x8618fe8: cmp w2, #4, lsl #12
if (buf && (buf->used + size) < buf->capacity   // 0x861900c: add; cmp; b.hs → 换新
         && !buf->full) return buf;
else 分配新 entry（kmem_cache_alloc 0x60）+ 新 data
```

即"追加前先保证 `used + size < capacity`"，随后 `memcpy` 的长度恰为同一个 `size`；
`size` 本身由 §2 的门算出，上限 16 KB。**不存在"按 A 长度分配、按 B 长度写"的错配。**

同时 `diag_dci_notify_client` 只做唤醒，不搬运数据；客户端读取走 §25.3 已审的
`copy_to_user`（按已填充长度复制），故**解析子树不可能把内核未初始化字节带进用户态**。

---

## 4. 残余项（明确列出，不外推为"完全穷尽"）

| # | 残余 | 为什么现在不追 | 何时回来 |
|---|---|---|---|
| R1 | `extract_dci_ctrl_pkt` 的**控制语义**（不只是数据面）：它改写的 mask/状态字段是否会与 `diag_dci_query_*` 形成不一致，从而影响后续解析分支 | 控制语义属逻辑面，与"信息泄露/内存破坏"不同类；且其无拷贝 | 出现引用该控制流的公开缺陷 |
| R2 | `diag_process_remote_dci_read_data` / `diag_process_dci_transaction` 两条**非 apps** 入口（caller 已定位，未逐路径复核其长度门） | 与 apps 入口共用同一分派器，长度门在分派器与 extract 内；但入口侧来源不同（modem / transaction 表） | 若需从 modem 侧注入，再补 |
| R3 | u16 长度字段的**语义边界**（例如 `0xFFFC` 上限是否覆盖真实日志记录）属功能性判断，不做安全结论 | 需同源源码或真机日志 | 拿到源码 |

---

## 5. 与 §25 的关系

- §25 的"入口层否证"**不变**；本文件只补 §25.7 的 G1。
- 合并后的口径应为：「`/dev/diag`：入口层 + DCI 解析子树**双双否证**；余量为 R1–R3 三项逻辑/来源面，
  且任何利用仍被 ②/③ 地址缺口阻断」。
- **不改变四层判定**：可用 root / 持久 root 仍 NO-GO。

---

## 6. 复现命令

```bash
python tools/kfn.py diag_process_single_dci_pkt        # 分派器
python tools/kfn.py extract_dci_log                    # 0x10 路径与长度门
python tools/kfn.py extract_dci_events                 # 0x60 路径与逐记录游标
python tools/kfn.py extract_dci_pkt_rsp                # 0x93/0x94 路径与扩容逻辑
python tools/kfn.py diag_dci_get_buffer                # 容量语义
```

调用链由 `bl` 立即数目标全局扫描得到（`.kernel` + `.kernel2`，非启发式、非抽样）。
