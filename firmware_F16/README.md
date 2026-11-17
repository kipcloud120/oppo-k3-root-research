# firmware_F16/ — 物料说明（二进制不随仓库分发）

本目录在仓库中**只有这一份说明**。原始物料（`boot.img`、`kernel.decompressed`、`vmlinux.elf`、`kallsyms_out.txt`）合计约 140 MB，属厂商固件与派生二进制，**不纳入公开仓库**（`.gitignore` 已排除），原因见根 `README.md` 的「为什么二进制不在仓库里」。

本项目的全部结论都建立在下列四件物料上，读者须**从自己持有的固件或自己的设备**重新生成：

| 文件 | 尺寸 | 来源 | 说明 |
|---|---|---|---|
| `boot.img` | 67,108,864 | OPPO 官方 F.16 整包（`PCGM00_11_F.16_2025032621191106`） | Android boot image v2，A-only |
| `kernel.decompressed` | 33,155,096 | `boot.img` 的 kernel 段 gzip 解压（单 member） | 原始 Image |
| `vmlinux.elf` | 39,151,975 | `vmlinux-to-elf` 从 `kernel.decompressed` 重建 | **唯一可用于反汇编的物料** |
| `kallsyms_out.txt` | 4,682,865 | 自 `kernel.decompressed` 内嵌 kallsyms 解析 | 123,784 个符号，**只用于查名字** |

## 重建步骤

```bash
# 1) 取 boot.img：从自己的设备读出（需 root 或厂商刷机包），或从官方整包中提取
#    sha256 = 22fc0926…a36c3f（F.16 原版）

# 2) 解出 kernel 段后 gunzip（单 member）
python -c "import gzip,sys; open('kernel.decompressed','wb').write(gzip.open('kernel.gz','rb').read())"
#    sha256 = 95a70412…baebc，size = 33155096

# 3) 重建带符号的 ELF —— 本项目最关键的一步
pip install vmlinux-to-elf
vmlinux-to-elf kernel.decompressed vmlinux.elf
```

`vmlinux.elf` 的自证（务必自己复核一次）：反汇编 `stext` 应得到 arm64 `head.S` 的真实内容——

```
stext @ 0xffffff8009a00000
  bl preserve_boot_args / bl el2_setup / bl set_cpu_boot_mode_flag
  bl __create_page_tables / bl __cpu_setup / bl __primary_switch
```

**地址换算公式**（`.kernel` 节）：

```
file_offset = 0x240 + (va - 0xffffff8008080000)
```

## 两条禁止条款

1. **不要用 `kallsyms_out.txt` 的偏移定位代码**。在 futex / binder 区，该表比真实值大 0x6 万–0x9 万字节（例：`SyS_futex` 表值 `0xe7da0`，实际 `0xe1b68`）。原因不是"镜像重排"，而是旧解析器把 kallsyms 偏移当作 base-relative 处理；`vmlinux-to-elf` 定位 `kallsyms_offsets` 于 `0x1380600`，比旧工具的 `0x13807e0` 早 0x1E0。
2. **不要跨机型套用本目录的任何数字**。帧几何、结构体偏移、spinlock 形态全部与具体构建绑定；换构建即全部作废（见 `HANDOVER.md` §7 第 3 条）。
