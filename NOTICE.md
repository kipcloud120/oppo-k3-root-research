# 许可范围说明（NOTICE）

本仓库按内容分三类授权，请按目录区分：

| 范围 | 许可 | 说明 |
|---|---|---|
| `tools/` 下的源代码与构建脚本 | **MIT**（见 `LICENSE`） | 可自由使用、修改、再分发，保留版权声明即可 |
| `HANDOVER.md`、`README.md`、`docs_archive/` 的文档内容 | **CC BY 4.0** | 转载/引用请注明来源与链接 |
| `src_ref/` 内的第三方材料 | **保留原始许可** | 见下 |

## `src_ref/` 的第三方材料

| 内容 | 原始许可与出处 |
|---|---|
| `kernel_49_mainline/`、`futex_4.9/`、`kgsl_4.9/` 等内核源码 | Linux 内核，**GPLv2**；部分为 Qualcomm msm-4.9 厂商树（同样以 GPLv2 发布） |
| `lineage_*.patch`、`ghostlock_fix.patch` | 上游内核补丁，随其来源项目的许可 |
| `projectzero_33107_rca.md` | Google Project Zero 公开报告的本地存档，版权归原作者 |
| `realmeX_master_io-pgtable-arm.c` | Qualcomm 厂商内核源码，GPLv2 |

本仓库对上述材料仅作**研究与评注用途的引用**，未主张任何额外权利。若权利人认为某项材料的收录方式不当，请开 issue，我会移除。

## 未收录的第三方内容

第三方完整利用代码（如 CVE-2023-33107 的公开 PoC）**未随本仓库分发**，文档中仅标注出处供读者自行取用；这类材料的许可状态不由本项目代为声明。
