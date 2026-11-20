#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_ioctl_bin.py — 离线盘点用户态 ELF 中「真正把 net_device 私有 ioctl 常量
(默认 0x89f1 / 0x89fd) 作为 ioctl(2) 第 2 参数发出」的指令级证据。

设计要点
--------
* 只反汇编 ELF 的可执行节区（SHF_EXECINSTR），不做全文件盲搜，避免 .rodata /
  字符串 / 动态符号表里的同值字节造成误报。
* 两层判定：
    1) 常量站点：反汇编后找立即数 == 目标值的指令（mov/movz/movk/orr/add/...），
       以及 `ldr wN, [pc, #imm]` 从字面量池加载到目标值的情况。
    2) 指令级确认：从常量站点向前做极短程寄存器数据流（<= --max-insn 条），
       跟踪 w1/x1 是否仍持有该值，直到 `bl <ioctl>`（PLT/GOT 或 dynsym/symtab
       中的 ioctl）；若中途 w1 被覆盖 / 出现 ret / 无关调用清栈，则不算命中。
  只有第 2 层成立才标记 CONFIRMED；常量出现但未连到 ioctl 的记为 WEAK(仅常量)。
* PLT 解析：`.rela.plt` 顺序 == PLT stub 顺序；stub 几何（header/stride）用
  reloc[0] 的 GOT 槽反推校验，AArch64 通常是 .plt+0x20+i*0x10。
* 支持 AArch64（完整）与 ARM/Thumb（尽力而为：movw/mov 立即数 + PLT 几何探测；
  无法确认的记为 WEAK 并注明原因）。其余机器类型只做「是否含常量字节」的记录。

用法
----
  python tools/scan_ioctl_bin.py DIR_OR_FILE [DIR_OR_FILE ...] \
      [--vals 0x89f1,0x89fd] [--jobs 8] [--max-insn 64] [--json out.json] \
      [--text out.txt] [--quiet] [--no-weak]

输出：文本命中表（文件 / 节区 / 文件偏移 / 指令地址 / 指令 / ioctl 调用点 /
解析到的导入符号 / CONFIRMED|WEAK），以及可选 JSON 全量记录。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

DEFAULT_VALS = (0x89F1, 0x89FD)
SHF_EXECINSTR = 0x4
SHT_NOBITS = 8

A64_MOVZ = 0b10100101          # sf=0, opc=10 -> MOVZ (32-bit)
A64_MOVK = 0b11100101          # sf=0, opc=11 -> MOVK (32-bit)


# --------------------------------------------------------------------------- ELF
class Image:
    """一个 ELF 的节区/符号/PLT 视图。"""

    def __init__(self, path):
        self.path = path
        self.f = open(path, 'rb')
        self.elf = ELFFile(self.f)
        self.secs = list(self.elf.iter_sections())
        self.by_name = {s.name: s for s in self.secs}
        self.machine = self.elf['e_machine']
        self.eclass = self.elf.elfclass
        self._vmap = None
        self._symmap = None
        self.plt_names = []
        self.plt_geom = None          # (header, stride)
        self._load_plt()

    # -- address helpers ---------------------------------------------------
    def vmap(self):
        if self._vmap is None:
            m = []
            for s in self.secs:
                if s['sh_type'] == SHT_NOBITS or s['sh_size'] == 0:
                    continue
                m.append((s['sh_addr'], s['sh_addr'] + s['sh_size'],
                          int(s['sh_offset']), s.name))
            m.sort()
            self._vmap = m
        return self._vmap

    def read_vaddr(self, addr, n):
        for lo, hi, off, _ in self.vmap():
            if lo <= addr and addr + n <= hi:
                self.f.seek(off + (addr - lo))
                return self.f.read(n)
        return None

    def sec_of(self, addr):
        for s in self.secs:
            if s['sh_flags'] & SHF_EXECINSTR and s['sh_addr'] <= addr < s['sh_addr'] + s['sh_size']:
                return s
        return None

    def file_off(self, sec, addr):
        return int(sec['sh_offset']) + (addr - int(sec['sh_addr']))

    # -- symbols -----------------------------------------------------------
    def symmap(self):
        if self._symmap is None:
            d = {}
            for nm in ('.symtab', '.dynsym'):
                if nm not in self.by_name:
                    continue
                st = self.by_name[nm]
                for sym in st.iter_symbols():
                    a = sym['st_value']
                    if a and sym.name:
                        d.setdefault(a, sym.name)
            self._symmap = d
        return self._symmap

    def sym_at_or_below(self, addr):
        sm = self.symmap()
        best = None
        for a, n in sm.items():
            if a <= addr and (best is None or a > best[0]):
                best = (a, n)
        return best

    # -- PLT ---------------------------------------------------------------
    def _load_plt(self):
        plt = self.by_name.get('.plt')
        rels = []
        relsec = None
        for s in self.secs:
            if isinstance(s, RelocationSection) and s.name == '.rela.plt':
                relsec = s
                break
        if relsec is None:
            for s in self.secs:
                if isinstance(s, RelocationSection) and s.name == '.rel.plt':
                    relsec = s
                    break
        if relsec is not None:
            tab = self.elf.get_section(relsec['sh_link'])
            for r in relsec.iter_relocations():
                sym = tab.get_symbol(r['r_info_sym'])
                rels.append((int(r['r_offset']), sym.name))
        self.plt_names = [n for _, n in rels]
        self.plt_rels = rels

        if plt is None or not rels:
            return
        base = int(plt['sh_addr'])
        size = int(plt['sh_size'])
        # 用 stub0 反推几何：header + stride*i，stub0 的 GOT 槽应等于 relocs[0].r_offset
        cands = []
        if self.machine == 'EM_AARCH64':
            cands = [(0x20, 0x10)]
        elif self.machine == 'EM_ARM':
            cands = [(0x20, 0x10), (0x14, 0xC), (0x14, 0x8), (0x10, 0x8), (0, 0x8), (0, 0xC)]
        for hdr, stride in cands:
            if stride <= 0 or size <= hdr:
                continue
            n = (size - hdr) // stride
            if n < len(rels):
                continue
            got = self._stub_got(base + hdr, stride)
            if got is not None and got == rels[0][0]:
                self.plt_geom = (hdr, stride)
                break
        if self.plt_geom is None and cands:
            # 未校验成功也接受首选几何，但调用方会以 sym 名为准
            self.plt_geom = cands[0]

    def _stub_got(self, stub, stride):
        """解析 PLT stub 里载入的 GOT 槽地址（AArch64: adrp+ldr / ARM: add+ldr）。"""
        raw = self.read_vaddr(stub, stride)
        if not raw:
            return None
        if self.machine == 'EM_AARCH64':
            if len(raw) < 8:
                return None
            i0, i1 = struct.unpack_from('<II', raw, 0)
            # adrp x16, #imm ; ldr x17, [x16, #imm12]
            if (i0 & 0x9F00001F) != 0x90000010:
                return None
            imm = (((i0 >> 5) & 0x7FFFF) << 2) | ((i0 >> 29) & 0x3)
            if imm & (1 << 20):
                imm -= 1 << 21
            page = (stub & ~0xFFF) + (imm << 12)
            if (i1 & 0xFFC00000) != 0xF9400000:
                return None
            off = ((i1 >> 10) & 0xFFF) * 8
            return page + off
        if self.machine == 'EM_ARM':
            # add ip, pc, #imm ; add ip, ip, #imm ; ldr pc, [ip, #imm]
            if len(raw) < 12:
                return None
            a, b, c = struct.unpack_from('<III', raw, 0)
            if (a & 0xFFFFF000) != 0xE28FC000:
                return None
            i1 = a & 0xFFF
            i2 = b & 0xFFF
            i3 = c & 0xFFF
            return stub + 8 + i1 + i2 + i3
        return None

    def resolve_plt(self, addr):
        """bl 目标 -> 导入符号名；不匹配返回 None。"""
        plt = self.by_name.get('.plt')
        if plt is None or self.plt_geom is None:
            return None
        base, size = int(plt['sh_addr']), int(plt['sh_size'])
        if not (base <= addr < base + size):
            return None
        hdr, stride = self.plt_geom
        if addr < base + hdr:
            return None
        i = (addr - (base + hdr)) // stride
        if 0 <= i < len(self.plt_names):
            return self.plt_names[i]
        return None

    def resolve_call(self, addr):
        """bl/b 目标 -> (符号名, 来源)。优先 PLT，其次 dynsym/symtab。"""
        n = self.resolve_plt(addr)
        if n:
            return n, 'plt'
        sm = self.symmap()
        if addr in sm:
            return sm[addr], 'sym'
        return None, None


# --------------------------------------------------------------------- scanning
def _is_target_imm(insn, vals):
    """指令里是否直接出现目标立即数。返回 (val, dest_reg) 或 None。"""
    if insn.id == 0:  # skipdata 产生的 .byte，不是真实指令
        return None
    try:
        ops = insn.operands
    except Exception:
        return None
    if not ops:
        return None
    for op in insn.operands:
        if op.type == ARM64_OP_IMM:
            if insn.mnemonic == 'movk':
                continue
            v = int(op.imm) & 0xFFFFFFFF
            if v in vals:
                dest = None
                if insn.operands and insn.operands[0].type == ARM64_OP_REG:
                    dest = insn.reg_name(insn.operands[0].reg)
                return v, dest
    return None


def _literal_load(insn, img):
    """`ldr wN, [pc, #imm]` / `ldr xN, [pc, #imm]` -> (val, dest) 或 None。"""
    if insn.id == 0 or insn.mnemonic != 'ldr' or len(insn.operands) < 2:
        return None
    dst, mem = insn.operands[0], insn.operands[1]
    if dst.type != ARM64_OP_REG or mem.type != ARM64_OP_MEM:
        return None
    if mem.mem.base != 0 or mem.index != 0:  # 仅 PC 相对字面量
        return None
    raw = img.read_vaddr(insn.address + mem.disp, 4)
    if not raw:
        return None
    v = struct.unpack('<I', raw)[0]
    return v, insn.reg_name(dst.reg)


def _reg_key(name):
    """统一成 xN 键（wN 写入即零扩展覆盖 xN）。"""
    m = re.fullmatch(r'([wx])(\d+)', name or '')
    if not m:
        return None
    n = int(m.group(2))
    if n == 31:  # sp / wzr / xzr 不作为数据流寄存器
        return None
    return 'x%d' % n


def _written(insn):
    try:
        _, w = insn.regs_access()
    except Exception:
        return set()
    return {insn.reg_name(r) for r in w}


def confirm(img, md_d, site, val, dest, max_insn):
    """从常量站点向前做短程数据流，判断 w1 是否把 val 传给 ioctl。

    返回 dict：confirmed / call_addr / call_insn / import / reason / path(指令列表)
    """
    sec = img.sec_of(site.address)
    if sec is None:
        return {'confirmed': False, 'reason': 'site-not-in-exec-section'}
    off = site.address - int(sec['sh_addr'])
    data = sec.data()[off:off + max_insn * 4]
    regs = {}
    stack = {}
    d = _reg_key(dest)
    if d:
        regs[d] = val
    trace = []
    n = 0
    for ins in md_d.disasm(data, site.address):
        if ins.id == 0:
            break
        n += 1
        trace.append('%x: %s %s' % (ins.address, ins.mnemonic, ins.op_str))
        if n > max_insn:
            break
        mn = ins.mnemonic
        if mn in ('bl', 'b') and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            tgt = int(ins.operands[0].imm)
            name, how = img.resolve_call(tgt)
            if name == 'ioctl':
                if regs.get('x1') == val:
                    return {'confirmed': True, 'call_addr': ins.address,
                            'call_insn': '%s %s' % (mn, ins.op_str), 'import': name,
                            'call_how': how, 'trace': trace}
                return {'confirmed': False, 'reason': 'ioctl-call-but-w1-clobbered',
                        'call_addr': ins.address, 'call_insn': '%s %s' % (mn, ins.op_str),
                        'import': name, 'trace': trace}
            if name is not None:
                regs.clear(); stack.clear()
                continue
            if mn == 'bl':
                regs.clear(); stack.clear()
                continue
            return {'confirmed': False, 'reason': 'unconditional-branch-before-ioctl',
                    'call_addr': ins.address, 'trace': trace}
        if mn == 'blr':
            return {'confirmed': False, 'reason': 'indirect-call-before-ioctl',
                    'call_addr': ins.address, 'trace': trace}
        if mn == 'ret':
            return {'confirmed': False, 'reason': 'ret-before-ioctl', 'trace': trace}
        # --- 数据流 -----------------------------------------------------
        wr = {_reg_key(x) for x in _written(ins)} - {None}
        if not wr:
            continue
        # 先取快照再按指令语义更新
        ops = ins.operands
        dst = ins.reg_name(ops[0].reg) if ops and ops[0].type == ARM64_OP_REG else None
        dk = _reg_key(dst)
        newv = None
        if mn == 'mov' and len(ops) == 2 and ops[1].type == ARM64_OP_REG:
            newv = regs.get(_reg_key(ins.reg_name(ops[1].reg)))
        elif mn == 'mov' and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
            newv = int(ops[1].imm) & 0xFFFFFFFF
        elif mn == 'movz' and len(ops) >= 2 and ops[1].type == ARM64_OP_IMM:
            newv = (int(ops[1].imm) & 0xFFFF) << _shift(ins)
        elif mn == 'movk' and len(ops) >= 2 and ops[1].type == ARM64_OP_IMM:
            base = regs.get(dk, 0)
            newv = (base & ~(0xFFFF << _shift(ins))) | ((int(ops[1].imm) & 0xFFFF) << _shift(ins))
        elif mn == 'orr' and len(ops) == 3 and ops[1].type == ARM64_OP_REG \
                and ins.reg_name(ops[1].reg) in ('wzr', 'xzr') and ops[2].type == ARM64_OP_IMM:
            newv = int(ops[2].imm) & 0xFFFFFFFF
        elif mn == 'add' and len(ops) == 3 and ops[2].type == ARM64_OP_IMM \
                and ops[1].type == ARM64_OP_REG and regs.get(_reg_key(ins.reg_name(ops[1].reg))) is not None:
            newv = (regs[_reg_key(ins.reg_name(ops[1].reg))] + int(ops[2].imm)) & 0xFFFFFFFF
        elif mn == 'ldr':
            lit = _literal_load(ins, img)
            if lit and _reg_key(lit[1]):
                newv = lit[0]
            elif len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
                mem = ops[1]
                base = ins.reg_name(mem.mem.base) if mem.mem.base else ''
                if base in ('sp', 'wsp') and mem.index == 0 and mem.disp in stack:
                    newv = stack[mem.disp]
        elif mn == 'str' and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
            mem = ops[1]
            base = ins.reg_name(mem.mem.base) if mem.mem.base else ''
            if base in ('sp', 'wsp') and mem.index == 0 and ops[0].type == ARM64_OP_REG:
                sv = regs.get(_reg_key(ins.reg_name(ops[0].reg)))
                if sv is not None:
                    stack[mem.disp] = sv
                else:
                    stack.pop(mem.disp, None)
            for r in wr:
                regs.pop(r, None)
            continue
        else:
            newv = None
        for r in wr:
            if r == dk and newv is not None:
                if newv <= 0xFFFFFFFF or True:
                    regs[r] = newv
            else:
                regs.pop(r, None)
    return {'confirmed': False, 'reason': 'window-exhausted', 'trace': trace}


def _shift(ins):
    for op in ins.operands:
        if op.type == 3 and getattr(op, 'shift', None) and op.shift.type == 1:  # ARM64_SFT_LSL
            return int(op.shift.value)
    return 0


# ------------------------------------------------------------------- per-file
def scan_a64(path, vals, max_insn):
    img = Image(path)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    md_d = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md_d.detail = True
    hits, weak, consts = [], [], []
    nsec = 0
    for sec in img.secs:
        if not (sec['sh_flags'] & SHF_EXECINSTR) or sec['sh_type'] == SHT_NOBITS:
            continue
        if sec['sh_size'] < 4:
            continue
        nsec += 1
        data = sec.data()
        base = int(sec['sh_addr'])
        for ins in md.disasm(data, base):
            got = _is_target_imm(ins, vals)
            lit = None if got else _literal_load(ins, img)
            if lit and lit[0] in vals:
                got = (lit[0], lit[1])
            if not got:
                continue
            val, dest = got
            consts.append({'sec': sec.name, 'addr': ins.address,
                           'insn': '%s %s' % (ins.mnemonic, ins.op_str), 'val': val,
                           'file_off': img.file_off(sec, ins.address)})
            r = confirm(img, md_d, ins, val, dest, max_insn)
            rec = {'sec': sec.name, 'addr': ins.address, 'val': val,
                   'insn': '%s %s' % (ins.mnemonic, ins.op_str),
                   'file_off': img.file_off(sec, ins.address),
                   'dest': dest,
                   'confirmed': r['confirmed'],
                   'call_addr': r.get('call_addr'),
                   'call_insn': r.get('call_insn'),
                   'import': r.get('import'),
                   'call_how': r.get('call_how'),
                   'reason': r.get('reason')}
            (hits if r['confirmed'] else weak).append(rec)
    img.f.close()
    return {'path': path, 'machine': 'AArch64', 'ok': True,
            'exec_sections': nsec, 'consts': consts, 'hits': hits, 'weak': weak}


def scan_arm(path, vals, max_insn):
    """ARM/Thumb 尽力而为：movw/mov 立即数 -> bl PLT(ioctl)。"""
    img = Image(path)
    results = {'path': path, 'machine': 'ARM', 'ok': True, 'exec_sections': 0,
               'consts': [], 'hits': [], 'weak': []}
    # 判断入口是否 Thumb
    try:
        thumb = bool(int(img.elf['e_entry']) & 1)
    except Exception:
        thumb = False
    mode = CS_MODE_THUMB if thumb else CS_MODE_ARM
    md = Cs(CS_ARCH_ARM, mode | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    for sec in img.secs:
        if not (sec['sh_flags'] & SHF_EXECINSTR) or sec['sh_type'] == SHT_NOBITS:
            continue
        results['exec_sections'] += 1
        data = sec.data()
        base = int(sec['sh_addr'])
        for ins in md.disasm(data, base):
            if ins.id == 0:
                continue
            val = None
            dest = None
            for op in ins.operands:
                if op.type == 2 and ins.mnemonic in ('movw', 'mov'):
                    v = int(op.imm) & 0xFFFFFFFF
                    if v in vals:
                        val = v
                        break
            if val is None and ins.mnemonic == 'ldr' and len(ins.operands) == 2:
                mem = ins.operands[1]
                if mem.type == 3 and (mem.mem.base == 15 or not mem.mem.base):
                    raw = img.read_vaddr((ins.address + 8) & ~3 if not thumb else (ins.address + 4) & ~3, 4)
                    if raw:
                        v = struct.unpack('<I', raw)[0]
                        if v in vals:
                            val = v
            if val is None:
                continue
            rec = {'sec': sec.name, 'addr': ins.address, 'val': val,
                   'insn': '%s %s' % (ins.mnemonic, ins.op_str),
                   'file_off': img.file_off(sec, ins.address),
                   'confirmed': False, 'reason': 'arm-best-effort-unresolved'}
            # 简单向前找 bl，且中间不改 r1
            off = ins.address - int(sec['sh_addr'])
            regs = {'x1': val}
            d = None
            for o in ins.operands:
                if o.type == 1:
                    d = _reg_key(ins.reg_name(o.reg))
                    break
            if d:
                regs = {d: val}
            for ins2 in md.disasm(data[off:off + max_insn * 4], ins.address):
                if ins2.id == 0:
                    break
                mn = ins2.mnemonic
                if mn in ('bl', 'blx') and ins2.operands and ins2.operands[0].type == 2:
                    nm, how = img.resolve_call(int(ins2.operands[0].imm))
                    if nm == 'ioctl':
                        if regs.get('x1') == val:
                            rec.update({'confirmed': True, 'call_addr': ins2.address,
                                        'call_insn': '%s %s' % (mn, ins2.op_str),
                                        'import': nm, 'call_how': how})
                        else:
                            rec['reason'] = 'ioctl-call-but-r1-clobbered'
                        break
                    regs.clear()
                elif mn in ('mov', 'movw') and ins2.operands and ins2.operands[0].type == 1:
                    k = _reg_key(ins2.reg_name(ins2.operands[0].reg))
                    if len(ins2.operands) > 1 and ins2.operands[1].type == 1:
                        src = _reg_key(ins2.reg_name(ins2.operands[1].reg))
                        if src in regs:
                            regs[k] = regs[src]
                        else:
                            regs.pop(k, None)
                    elif len(ins2.operands) > 1 and ins2.operands[1].type == 2:
                        regs[k] = int(ins2.operands[1].imm) & 0xFFFFFFFF
                elif mn == 'ret' or mn == 'bx':
                    break
            (results['hits'] if rec['confirmed'] else results['weak']).append(rec)
            results['consts'].append(rec)
    img.f.close()
    return results


def scan_file(job):
    path, vals, max_insn = job
    out = {'path': path, 'machine': None, 'ok': False, 'exec_sections': 0,
           'consts': [], 'hits': [], 'weak': [], 'error': None}
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
        if magic != b'\x7fELF':
            out['error'] = 'not-elf'
            return out
        with open(path, 'rb') as f:
            e = ELFFile(f)
            mach = e['e_machine']
        if mach == 'EM_AARCH64':
            r = scan_a64(path, vals, max_insn)
        elif mach == 'EM_ARM':
            r = scan_arm(path, vals, max_insn)
        else:
            out['machine'] = str(mach)
            out['error'] = 'arch-unsupported'
            return out
        out.update(r)
        out['ok'] = True
    except Exception as ex:  # 损坏 / 非标准 ELF
        out['error'] = '%s: %s' % (type(ex).__name__, ex)
    return out


# ---------------------------------------------------------------------- main
def discover(paths):
    files, skipped = [], []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    files.append(os.path.join(root, n))
        elif os.path.isfile(p):
            files.append(p)
        else:
            skipped.append({'path': p, 'reason': 'no-such-path'})
    return files, skipped


def fmt_hit(f):
    return ('%s  off=0x%x  addr=0x%x  %-28s -> ioctl@0x%x (%s)%s'
            % (f['sec'], f['file_off'], f['addr'], f['insn'],
               f['call_addr'] or 0, f['import'] or '?',
               '' if f['confirmed'] else '  [WEAK: %s]' % f.get('reason')))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--vals', default=','.join('0x%x' % v for v in DEFAULT_VALS))
    ap.add_argument('--jobs', type=int, default=min(8, os.cpu_count() or 4))
    ap.add_argument('--max-insn', type=int, default=64)
    ap.add_argument('--json')
    ap.add_argument('--text')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--no-weak', action='store_true', help='只输出 CONFIRMED')
    args = ap.parse_args(argv)
    vals = {int(x, 16) for x in args.vals.split(',') if x.strip()}

    files, skipped = discover(args.paths)
    jobs = [(p, vals, args.max_insn) for p in files]
    results = []
    with ProcessPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futs = [ex.submit(scan_file, j) for j in jobs]
        for fu in as_completed(futs):
            results.append(fu.result())
    results.sort(key=lambda r: r['path'])

    lines = []
    n_elf = n_ok = n_hit = n_weak = 0
    for r in results:
        if r.get('error') == 'not-elf':
            skipped.append({'path': r['path'], 'reason': 'not-elf'})
            continue
        if not r['ok']:
            skipped.append({'path': r['path'],
                            'reason': r.get('error') or 'scan-failed'})
            continue
        n_elf += 1
        if r['hits'] or r['weak']:
            lines.append('== %s  [%s]  exec_sections=%d consts=%d confirmed=%d weak=%d'
                         % (r['path'], r['machine'], r['exec_sections'],
                            len(r['consts']), len(r['hits']), len(r['weak'])))
            for h in r['hits']:
                n_hit += 1
                lines.append('   HIT   ' + fmt_hit(h))
            if not args.no_weak:
                for w in r['weak']:
                    n_weak += 1
                    lines.append('   WEAK  ' + fmt_hit(w))
            lines.append('')
        n_ok += 1

    head = ('scanned_files=%d  elf=%d  hit_records=%d  weak_records=%d  '
            'skipped=%d  vals=%s'
            % (len(files), n_ok, n_hit, n_weak, len(skipped),
               ','.join('0x%x' % v for v in sorted(vals))))
    out = head + '\n\n' + '\n'.join(lines)
    if skipped:
        out += '\n-- skipped --\n' + '\n'.join(
            '%s  (%s)' % (s['path'], s['reason']) for s in skipped)
    if not args.quiet:
        print(out)
    if args.text:
        open(args.text, 'w', encoding='utf-8').write(out + '\n')
        print('wrote', args.text, file=sys.stderr)
    if args.json:
        payload = {'meta': {'head': head, 'vals': sorted(vals),
                            'files': len(files), 'elf': n_ok,
                            'skipped': len(skipped)},
                   'results': results, 'skipped': skipped}
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=1)
        print('wrote', args.json, file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
