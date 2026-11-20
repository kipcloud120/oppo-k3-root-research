# 路径 1 离线证据链：IMEM KASLR 落盘 + /dev/mem（2026-11-20）

> 状态：**离线证据链完整，待上机判定（设备未连接）**。本文件只记录机制、判据与只读判定方法，不含任何写原语或利用载荷。

## 1. 机制（来源：tjtech.me《How to get kaslr offset on ARM64》+ Qualcomm 下游内核）

高通下游 4.9 内核在启动期把 `.text` 的 KASLR slide（`kimage_vaddr - KIMAGE_VADDR`，即 `kimage_voffset` 承载的值）以固定格式写入设备树指定的 IMEM 物理地址；Qualcomm ramparser 依据同一机制解析 ramdump。写入布局：

```
base+0 : 0xdead4ead（魔数）
base+4 : slide 低 32 位
base+8 : slide 高 32 位
```

这**正面命中**项目 v008 口径的缺口：③ 类地址（`.text` KASLR slide，`kimage_voffset` 独立承载、不可由 ① 类 mm 地址反推）。IMEM 落盘是第三种、且是**确定性**的获取渠道，与 KernelSnitch 侧信道完全独立。

## 2. 本机物料上的四条独立离线证据（均可复算）

| # | 证据 | 物料 | 结果 |
|---|---|---|---|
| E1 | dtb 节点存在性 | `kernel_appended.dtb`（FDT 结构化解析） | `/soc/qcom,msm-imem@146bf000/kaslr_offset@6d0`，compatible=`qcom,msm-imem-kaslr_offset`，**reg = <0x6d0, 0xc>** ⇒ 落盘物理地址 `0x146BF000 + 0x6D0 = 0x146BF6D0`，长度 12 字节（恰为魔数+lo32+hi32 布局） |
| E2 | 驱动 compatible 字符串 | `kernel.decompressed` | 含 `msm-imem-kaslr_offset` 字符串 |
| E3 | 驱动数据结构 | `kallsyms_out.txt` | `kaslr_imem_addr` 全局变量存在（b 符号，0x0230eee8）；`kimage_voffset`（R 符号，0x017d5b70） |
| E4 | 写入代码指令级形态 | `kernel.decompressed` @ 0xAFA314 | `MOVZ W8,#0x4EAD` + `MOVK W8,#0xDEAD,LSL#16` + `STR W8,[X0]`（0xdead4ead 写 base+0）→ `+4`/`+8` 两个 32 位 store（对应 lo32/hi32）→ `BL`（iounmap 形态）。与下游发布代码逐条吻合。字面量搜索阴性是编译器拆立即数所致，指令编码搜索为**唯一命中** |

## 3. 读取侧判据（离线符号表）

| 判据 | 结果 | 含义 |
|---|---|---|
| `mem_fops` / `mem_open` / `phys_mem_access_prot` | 存在 | `CONFIG_DEVMEM=y`，`/dev/mem` 编译进内核 |
| `devmem_is_allowed` | **不存在** | 4.9 上该函数仅随 `CONFIG_STRICT_DEVMEM=y` 生成 ⇒ **`CONFIG_STRICT_DEVMEM` 未启用** ⇒ `/dev/mem` 大概率对全部物理地址开放（含 IMEM） |
| KPTI 符号（`unmap_kernel_at_el0`、`kpti_install_ng_mappings`） | 存在 | 与本路径无关，但记录：CCS'16 prefetch translation-level oracle 大概率被 KPTI 掐死（路径 3 前置判定） |

## 4. 上机判定门（只读，脚本 `imem_kaslr_probe.sh`）

1. **门 1**：`ls -l /dev/mem` — 节点是否存在（char 1:1）。
2. **门 2**：`kptr_restrict` / `perf_event_paranoid` 实际值（仅记录，供路径 2）。
3. **门 3**：`dd if=/dev/mem bs=4096 skip=83647 count=1`（读 0x146BF000 起 1 页）后取 `+0x6D0` 的 12 字节。**命中判据**：首 4 字节 = `ad 4e ad de`（LE 0xdead4ead）；随后 8 字节 = slide（lo32 在 +4，hi32 在 +8）。slide 验证方式：加到 `vmlinux.elf` 静态符号地址上，与任何一次已知输出（如未来 oops 寄存器 dump）交叉比对；或直接与 `kimage_voffset` 变量语义一致性核对（无独立 oracle 时至少核对区间合理性）。
4. **安全控制**：boot_id / uptime 前后校验（脚本已内置）；探针文件用后即删；无写操作、无 panic 面（IMEM 读为纯内存读）。

判定分支：
- 门 1 失败（节点不存在）⇒ ueventd 未创建节点，路径 1 在"节点"层关闭（内核侧机制仍在，仅无用户态入口）。
- 门 1 通过、门 3 SELinux `EPERM`/`EACCES` ⇒ shell 域不可达；是否动用 uid=0 `oplus_wifi_service` 域属授权决策（HANDOVER §23 已建立该主体），须单独授权后再判。
- 门 3 命中 0xdead4ead ⇒ **③ 类地址（KASLR slide）在本机获得确定性获取路径**，按 README 审阅须知登记为新面，四层判定重审。

## 5. 上机判定结果（2026-11-20 16:00–16:04，已执行，负结果）

> 授权：用户明确授权 shell 域被拒后改用 uid=0 `oplus_wifi_service` 域（§23 事务形态，`tools/wifi_exec.py`，一次事务一条只读命令）。
> 安全控制：`boot_id` 全程不变（`27520eec-0945-44db-930d-0c0fd61c1eeb`），uptime 连续（272381→272851 s），三事务均只读，探针脚本/ftmprobe.jar/载荷已删，`/data/local/tmp` 清空，零重启。

| 门 | 结果 | 证据 |
|---|---|---|
| 门 1（shell 域） | **`/dev/mem` 不存在**（ENOENT，非 SELinux 拒） | `ls: /dev/mem: No such file or directory` |
| 内核侧注册状态 | **`/sys/class/mem/` 无 `mem` 条目**（仅 full/kmsg/null/random/urandom/zero）⇒ 内核未创建 /dev/mem 设备对象 | shell 域 sysfs 列表 |
| 能力层 | **uid=0 域无 `CAP_MKNOD`**：`CapEff=0x13000`（NET_ADMIN+NET_RAW+SYS_MODULE，§24 CAPS 原文）⇒ 节点无法补建 | `20261118T123130_CAPS.log` |
| 事务 1（KPTR） | `kptr_restrict` 读取被拒：`avc: denied { read } for name="kptr_restrict" ... scontext=u:r:oplus_wifi_service:s0 tcontext=u:object_r:proc_security:s0 permissive=0` | `p1_probes/20261120T160240_KPTR.log` |
| 事务 2（DEVS） | `/proc/devices` 读取被拒（`tclass=proc`，同域） | `p1_probes/20261120T160321_DEVS.log` |
| 事务 3（KALS） | `/proc/kallsyms` 探针事务已执行（同 `proc_security` 家族预期拒绝，原文见日志） | `p1_probes/20261120T160338_KALS.log` |
| 旁证 | `perf_event_paranoid=3`（shell 域可读）⇒ `kallsyms_for_perf()` 不满足；`/proc/kcore`、`/dev/kmem` 均未编译（kallsyms 0 命中） | shell 域 sysctl + 离线符号表 |

### 5.1 自我修正（对照 §2/E3 与第 3 节推断）

第 3 节"`CONFIG_DEVMEM=y`"的推断**被上机事实推翻**：`mem_lseek`/`open_mem`/`chr_dev_init` 等符号存在只是静态符号残留，不能证明 devlist 条目被编译；`/sys/class/mem` 缺 `mem` 条目才是决定性判据。修正结论：**DEVMEM=n 或厂商移除 devlist[1]，二者对本路径等效（关闭）**。

### 5.2 分支判定落位

- **路径 1（IMEM 落盘 + /dev/mem）：关闭**。三道门叠加：内核未创建设备对象 + 无节点 + 可达主体无 CAP_MKNOD。IMEM 落盘机制本身（§1/§2 离线证据）仍然成立——slide 仍每次开机写入 0x146BF6D0，缺口精确化为"**任一固定物理地址读原语**"。
- **路径 2（kptr_restrict/kallsyms，oplus_wifi_service 域）：关闭**。`proc_security` 标签两域均拒 + `perf_event_paranoid=3`。**未测**：dumpstate 第三主体（CAP_SYSLOG + 自身 sepolicy），登记为下一步候选。
- 路径 3（KPTI 编译在内核）维持远景。

## 6. 重开条件（路径 1）

1. 出现任一"固定物理地址读"原语（含新面发现的缺陷、或可写 `/dev` 的可达主体获得 CAP_MKNOD + SELinux 放行）；
2. dumpstate/bugreport 第三主体实测可行（其 kmsg 若含 4.9 裸 `%p` 指针，则成为独立地址源）；
3. SPL/内核构建变化 ⇒ 本文件全部偏移与符号判据作废。

## 7. 边界与口径

- 所有证据绑定 SPL `2022-04-05` / 内核 `4.9.227-perf+` 本机编译产物；SPL/内核变化全部作废。
- E4 的指令级解读以本机反汇编为准，不依赖外部公告（对齐 v14 §0/§7 判据）。
- 若门 3 命中，`/dev/mem` 全物理读本身即是更强的原语（不止 slide），须按"新面"整体重审，而非直接并入 GhostLock 链。
