#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wifi_slot_audit.py — OPPO Wi-Fi HIDL 服务 (vendor.oplus.hardware.wifi@1.1-service) 槽位审计。

目标：给定 vtable 槽位或函数地址，反汇编并标注
  - BL/BLR 目标：PLT 导入名 / 内部函数地址
  - ADRP(+ADD) 字符串引用：解析为实际字符串内容
  - 是否出现 system/popen/execv/execve 等命令执行原语

用法:
  python tools/wifi_slot_audit.py --vtable            # 打印 vtable 槽位 → 函数地址
  python tools/wifi_slot_audit.py 0xa898 0x120        # 反汇编 [addr, addr+len)
  python tools/wifi_slot_audit.py --slot 8            # 按槽位反汇编（自动定长）
  python tools/wifi_slot_audit.py --scan-exec         # 全 .text 搜命令执行原语调用点
"""
import sys
import struct
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_INS_BL, ARM64_INS_BLR, ARM64_INS_ADRP, ARM64_INS_ADD, ARM64_INS_B

BIN = ".build/vendor/x/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service"
VTABLE = 0x1a0a0
EXEC_SYMS = {"system", "popen", "execv", "execve", "execvp", "execl", "execlp",
             "posix_spawn", "fork", "vfork", "__system_property_set", "setprop"}


class Bin:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.raw = open(path, "rb").read()
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True
        self._build_plt()

    def sec_of(self, addr):
        for s in self.elf.iter_sections():
            a = s["sh_addr"]
            if a and a <= addr < a + s["sh_size"]:
                return s
        return None

    def read(self, addr, n):
        s = self.sec_of(addr)
        if not s:
            return b""
        off = s["sh_offset"] + (addr - s["sh_addr"])
        self.f.seek(off)
        return self.f.read(n)

    def cstr(self, addr, maxlen=160):
        b = self.read(addr, maxlen)
        z = b.find(b"\x00")
        if z >= 0:
            b = b[:z]
        try:
            return b.decode("utf-8", "replace")
        except Exception:
            return repr(b)

    def _build_plt(self):
        dynsym = self.elf.get_section_by_name(".dynsym")
        names = [s.name for s in dynsym.iter_symbols()]
        order = []
        for s in self.elf.iter_sections():
            if isinstance(s, RelocationSection) and s.name == ".rela.plt":
                order = [names[r["r_info_sym"]] for r in s.iter_relocations()]
                break
        self.plt = {}
        plt0 = self.elf.get_section_by_name(".plt")["sh_addr"]
        for i, n in enumerate(order):
            self.plt[plt0 + 0x20 + 0x10 * i] = n
        self.plt_order = order

    def resolve_call(self, addr):
        if addr in self.plt:
            return "PLT:" + self.plt[addr]
        s = self.sec_of(addr)
        if s and s.name == ".text":
            return "fn_" + hex(addr)
        return hex(addr)

    def disasm(self, start, length, title=""):
        code = self.read(start, length)
        ins = list(self.md.disasm(code, start))
        # 收集 adrp 页基址，用于 add 时解析字符串指针
        pages = {}
        out = []
        for i in ins:
            line = f"{i.address:#08x}  {i.mnemonic:<8} {i.op_str}"
            note = ""
            if i.id == ARM64_INS_ADRP:
                try:
                    rd = i.reg_name(i.operands[0].reg)
                    pages[rd] = i.operands[1].imm
                except Exception:
                    pass
            if i.id == ARM64_INS_ADD and len(i.operands) == 3:
                try:
                    rd = i.reg_name(i.operands[0].reg)
                    rn = i.reg_name(i.operands[1].reg)
                    op2 = i.operands[2]
                    if rn in pages and op2.type == ARM64_OP_IMM:
                        va = pages[rn] + op2.imm
                        txt = self.cstr(va)
                        if txt and all(32 <= ord(c) < 127 or c in "\t" for c in txt):
                            note = f'   ; "{txt}" @{va:#x}'
                except Exception:
                    pass
            if i.id in (ARM64_INS_BL, ARM64_INS_BLR):
                try:
                    if i.id == ARM64_INS_BL:
                        tgt = i.operands[0].imm
                    else:
                        tgt = None
                    note += "   ; -> " + (self.resolve_call(tgt) if tgt is not None else self.reg_note(i))
                except Exception:
                    pass
            out.append(line + note)
        if title:
            print(f"\n===== {title} =====")
        print("\n".join(out))
        return ins

    def reg_note(self, i):
        try:
            r = i.reg_name(i.operands[0].reg)
            return f"blr {r}"
        except Exception:
            return "blr ?"

    def func_end(self, start):
        """用 eh_frame FDE 或下一条对齐边界近似函数长度。"""
        for sec in self.elf.iter_sections():
            if sec.name != ".eh_frame":
                continue
            # 简化：扫描 FDE 的 initial_location
        return None


def vtable_dump(b):
    data = b.read(VTABLE, 0x120)
    ptrs = struct.unpack("<%dQ" % (len(data) // 8), data)
    for idx, p in enumerate(ptrs):
        s = b.sec_of(p) if p else None
        print(f"slot{idx:<3} @{VTABLE + idx * 8:#x} -> {p:#x}  {s.name if s else '-'}")


def scan_exec(b):
    text = b.elf.get_section_by_name(".text")
    code = b.read(text["sh_addr"], text["sh_size"])
    hits = []
    pages = {}
    prev = None
    ins = list(b.md.disasm(code, text["sh_addr"]))
    for i in ins:
        if i.id == ARM64_INS_ADRP:
            pages[i.reg_name(i.operands[0].reg)] = i.operands[1].imm
            prev = i
        if i.id in (ARM64_INS_BL,):
            tgt = i.operands[0].imm
            nm = b.plt.get(tgt)
            if nm and nm in EXEC_SYMS:
                hits.append((i.address, nm))
    for a, n in hits:
        print(f"{a:#08x}  bl {n}")
    print(f"-- total {len(hits)} command-exec call sites --")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("addr", nargs="?", help="起始地址(hex)")
    ap.add_argument("length", nargs="?", help="长度(hex)")
    ap.add_argument("--vtable", action="store_true")
    ap.add_argument("--slot", type=int)
    ap.add_argument("--scan-exec", action="store_true")
    ap.add_argument("--bin", default=BIN)
    a = ap.parse_args()
    b = Bin(a.bin)
    if a.vtable:
        vtable_dump(b)
    if a.scan_exec:
        scan_exec(b)
    if a.slot is not None:
        ptrs = struct.unpack("<32Q", b.read(VTABLE, 0x100))
        start = ptrs[a.slot]
        nxt = next((p for p in ptrs[a.slot + 1:] if b.sec_of(p) and b.sec_of(p).name == ".text"), start + 0x200)
        b.disasm(start, min(nxt - start, 0x400), f"slot{a.slot} @{start:#x}")
    if a.addr:
        start = int(a.addr, 16)
        ln = int(a.length, 16) if a.length else 0x120
        b.disasm(start, ln, f"{a.addr}")
