#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wlan_handler_scan.py — qcacld `hdd_driver_command` 98 个命令 handler 的纯离线静态扫描器。

输入（只读）：
  vendor_ko/qca_cld3_wlan.ko   ET_REL / EM_AARCH64（SHA-256 f45c1c1c…74d00）

本脚本不连接设备、不执行任何驱动命令、不联网。它只做三件事：
  ① 用 `tools/wlan_cmd_table.py` 的同一套 `.rela.rodata` ABS64 绑定还原 98 项命令表；
  ② 用 pyelftools 取 `.symtab` 的函数边界、用 `.rela.text` 解析每条 CALL26/JUMP26 的
     目标符号名与每条 MOVW_UABS_G0..G3（264/266/268/269）地址装载的字符串字面量；
  ③ 用 capstone 反汇编每个 handler，提取：帧大小、解析调用（kstrto*/sscanf/…）、
     解析目标栈槽（`add xN, sp, #imm`）与槽宽、解析后的 `cmp`/条件分支范围门、
     拷贝类调用、输出格式化调用及其长度参数、加锁/等待类调用。

设计原则（与审计纪律对齐）：
  * 只报"指令级可见"的事实，不把"符号存在"当证据；
  * 数据流是**有界窗口内的轻量前向/后向扫描**，不是完整 SSA —— 局限见 README/文档 §1.3；
  * 所有判定都带地址，可被人工逐条复核。

用法：
  python tools/wlan_handler_scan.py                        # 人读摘要
  python tools/wlan_handler_scan.py --csv                  # CSV（98 行，审计交付列）
  python tools/wlan_handler_scan.py --json                 # 完整结构化事实
  python tools/wlan_handler_scan.py --dump-dir artifacts_adb/r1_wlan_reach/handlers
  python tools/wlan_handler_scan.py --handler drv_cmd_set_dwell_time --disasm
  python tools/wlan_handler_scan.py --selftest             # 自检（不依赖设备）

CSV 前 10 列 = 审计要求的固定列：
  i,name,handler,handler_size,frame_size,parse_funcs,range_check,in_short,copy_ops,notes
其后追加便于复核的列：group,parse_evidence,copy_evidence,calls,strings
"""
import argparse
import json
import os
import re
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64 import (ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM,
                                ARM64_OP_CIMM)
    _HAVE_CAPSTONE = True
except Exception:                                            # pragma: no cover
    _HAVE_CAPSTONE = False

KO_DEFAULT = 'vendor_ko/qca_cld3_wlan.ko'

# ---- 命令表（与 tools/wlan_cmd_table.py 完全一致的常量） -------------------
TABLE_RODATA_OFF = 0x2bb8
ENTRY_SZ = 0x18
CMD_COUNT = 98
R_AARCH64_ABS64 = 257

# ---- 重定位类型 -----------------------------------------------------------
R_CALL26 = 283          # R_AARCH64_CALL26   -> bl
R_JUMP26 = 282          # R_AARCH64_JUMP26   -> b (尾调用)
MOVW_G0 = 264           # R_AARCH64_MOVW_UABS_G0_NC
MOVW_G1 = 266           # R_AARCH64_MOVW_UABS_G1_NC
MOVW_G2 = 268           # R_AARCH64_MOVW_UABS_G2_NC
MOVW_G3 = 269           # R_AARCH64_MOVW_UABS_G3
MOVW_LO = (MOVW_G0, MOVW_G1, MOVW_G2, MOVW_G3)
R_ADR_PREL_PG_HI21 = 275
R_ADD_ABS_LO12 = 277

STRING_SECTIONS = ('.rodata.str1.1', '.rodata.str', '.rodata.str4.4', '.rodata')

# ---- 函数名分类 -----------------------------------------------------------
# 输入解析：输入字节 -> 标量/缓冲
PARSE_FUNCS = {
    'kstrtou8', 'kstrtou16', 'kstrtou32', 'kstrtou64', 'kstrtouint',
    'kstrtoull', 'kstrtoul',
    'kstrtos8', 'kstrtos16', 'kstrtos32', 'kstrtos64', 'kstrtoint',
    'kstrtol', 'kstrtoll',
    'sscanf', 'vsscanf', 'sscanf_from_user', 'hex_to_bin', 'mac_pton',
    'strtobool', 'kstrtobool', 'qdf_sscanf',
}
# kstrto* 写入目标槽的宽度（字节）；sscanf 需由格式串决定
DEST_REG = {'hex_to_bin': 'x1', 'mac_pton': 'x1', 'strscpy': 'x0', 'strlcpy': 'x0', 'strcpy': 'x0', 'strncpy': 'x0'}

KSTRTO_WIDTH = {
    'kstrtou8': 1, 'kstrtos8': 1, 'kstrtobool': 1,
    'kstrtou16': 2, 'kstrtos16': 2,
    'kstrtou32': 4, 'kstrtos32': 4, 'kstrtouint': 4, 'kstrtoint': 4,
    'kstrtou64': 8, 'kstrtos64': 8, 'kstrtoull': 8, 'kstrtoll': 8,
    'kstrtoul': 8, 'kstrtol': 8,
}
# 拷贝/格式化类
COPY_FUNCS = {
    'memcpy', '__memcpy_chk', 'memmove', 'memset', 'qdf_mem_copy', 'qdf_mem_set',
    'qdf_mem_zero', 'strlcpy', 'strscpy', 'strncpy', 'strcpy', 'strcat',
    'strlcat', 'strncat', 'sprintf', 'snprintf', 'scnprintf', 'vsnprintf',
    'vscnprintf', 'skb_put', 'skb_push', 'skb_pull', 'memdup_user',
    '__arch_copy_to_user', '__arch_copy_from_user', 'copy_to_user',
    'copy_from_user', '__check_object_size', 'qdf_mem_malloc', '__qdf_mem_malloc',
    '__qdf_mem_free', 'qdf_mem_free', 'osif_request_alloc', 'osif_request_put',
}
OUT_FUNCS = {'__arch_copy_to_user', 'copy_to_user', 'scnprintf', 'snprintf',
             'sprintf', 'vsnprintf', 'vscnprintf'}
HEAP_FUNCS = {'__qdf_mem_malloc', 'qdf_mem_malloc', '__qdf_mem_free', 'qdf_mem_free',
              'osif_request_alloc', 'osif_request_put', 'memdup_user',
              'kzalloc', 'kmalloc', 'kfree', 'devm_kzalloc'}
LOCK_FUNCS = {'qdf_mutex_acquire', 'qdf_mutex_release', 'qdf_spin_lock',
              'qdf_spin_unlock', 'qdf_spin_lock_bh', 'qdf_spin_unlock_bh',
              'mutex_lock', 'mutex_unlock', 'spin_lock', 'spin_unlock',
              'down', 'up', 'down_interruptible', 'wait_for_completion',
              'wait_for_completion_timeout', 'wait_for_completion_interruptible',
              'complete', 'osif_request_wait_for_response'}
# 对外交互（发帧 / 通知固件 / 触发对端）——用于 5 分类
EXT_FUNCS = {
    'sme_fast_reassoc', 'sme_handoff_request', 'sme_roam_reassoc', 'hdd_reassoc',
    'sme_send_rmc_action_period', 'sme_send_rate_update_ind', 'sme_set_cckm_ie',
    'sme_set_ese_beacon_request', 'sme_set_plm_request', 'sme_set_max_tx_power',
    'hdd_set_p2p_noa', 'hdd_set_p2p_opps', 'sme_set_miracast',
    'ucfg_pmo_tgt_psoc_send_idle_roam_suspend_mode',
    'sme_get_tsm_stats', 'sme_get_link_status', 'wlan_hdd_get_rssi',
    'wlan_hdd_get_link_speed', 'wlan_hdd_get_ani_level',
    'hdd_softap_set_channel_change', 'hdd_set_antenna_mode',
    'wlan_hdd_disable_channels', 'wlan_hdd_restore_channels',
    'sme_update_dfs_scan_mode', 'hdd_set_tdls_offchannel',
    'hdd_set_tdls_scan_type', 'hdd_set_tdls_secoffchanneloffset',
    'hdd_set_tdls_offchannelmode', 'sme_update_is_fast_roam_ini_feature_enabled',
    'sme_update_empty_scan_refresh_period', 'sme_change_roam_scan_channel_list',
    'sme_set_ese_roam_scan_channel_list', 'hdd_wmmps_helper',
}

# 条件分支助记符 -> (谓词, 取反)
COND_BRANCH = {
    'b.eq': ('eq', 'ne'), 'b.ne': ('ne', 'eq'),
    'b.cs': ('cs', 'cc'), 'b.hs': ('cs', 'cc'), 'b.cc': ('cc', 'cs'), 'b.lo': ('cc', 'cs'),
    'b.mi': ('mi', 'pl'), 'b.pl': ('pl', 'mi'),
    'b.vs': ('vs', 'vc'), 'b.vc': ('vc', 'vs'),
    'b.hi': ('hi', 'ls'), 'b.ls': ('ls', 'hi'),
    'b.ge': ('ge', 'lt'), 'b.lt': ('lt', 'ge'),
    'b.gt': ('gt', 'le'), 'b.le': ('le', 'gt'),
}
# 无符号比较可以映射成"接受区间"
UNSIGNED_PRED = ('cc', 'cs', 'hi', 'ls')


def cstr(data, off, maxlen=400):
    if not (0 <= off < len(data)):
        return None
    end = data.find(b'\x00', off)
    if end < 0 or end - off > maxlen:
        return None
    raw = data[off:end]
    try:
        return raw.decode('latin-1')
    except Exception:
        return None


def sanitize(s, limit=400):
    """把非可打印字节转义成 \\xNN，保证 CSV/终端可安全输出。"""
    if s is None:
        return ''
    out = []
    for ch in s[:limit]:
        o = ord(ch)
        if o < 0x20 or o == 0x7f:
            out.append('\\x%02x' % o)
        elif 0x80 <= o <= 0xff:
            out.append('\\x%02x' % o)
        elif ch == '"':
            out.append("\\'")
        else:
            out.append(ch)
    return ''.join(out)


class Ko:
    """极简 ET_REL 视图：节、函数符号、.text 重定位。"""

    def __init__(self, path):
        self.path = path
        self.fh = open(path, 'rb')
        self.e = ELFFile(self.fh)
        self.secs = list(self.e.iter_sections())
        self.byname = {s.name: s for s in self.secs}
        self.symtab = self.byname['.symtab']
        self._syms = list(self.symtab.iter_symbols())
        # 函数符号，按地址排序，用于 addr -> name
        self.funcs = []
        self.func_by_name = {}
        for sym in self._syms:
            if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size']:
                rec = (sym['st_value'], sym['st_size'], sym.name)
                self.funcs.append(rec)
                self.func_by_name.setdefault(sym.name, rec)
        self.funcs.sort()
        self.text = self.byname['.text'].data()
        self._load_relocs()
        self._load_cmd_table()
        if _HAVE_CAPSTONE:
            self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.md.detail = True
        else:                                                # pragma: no cover
            self.md = None

    # -- 重定位 ------------------------------------------------------------
    def _load_relocs(self):
        self.rel_text = {}     # offset -> (type, symidx, symname, addend, shndx)
        sec = self.byname.get('.rela.text')
        if sec is None:
            return
        symtab = self.e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            sym = symtab.get_symbol(r['r_info_sym'])
            self.rel_text[r['r_offset']] = (
                r['r_info_type'], r['r_info_sym'], sym.name, r['r_addend'],
                sym['st_shndx'], sym['st_value'])

    def target_of(self, reloc):
        """把一条 MOVW/ABS 组解析成 (节名, 节内偏移) 或 (符号名, None)。"""
        typ, symidx, symname, addend, shndx, st_value = reloc
        if isinstance(shndx, int) and 0 < shndx < len(self.secs):
            s = self.secs[shndx]
            if s.name in STRING_SECTIONS or s.name in ('.rodata', '.data', '.bss'):
                return (s.name, st_value + addend)
        return (symname or None, None)

    def read_string_at(self, secname, off):
        if secname not in self.byname:
            return None
        return cstr(self.byname[secname].data(), off)

    # -- 命令表 ------------------------------------------------------------
    def _load_cmd_table(self):
        rel_ro = {}
        sec = self.byname.get('.rela.rodata')
        if sec is not None:
            symtab = self.e.get_section(sec['sh_link'])
            for r in sec.iter_relocations():
                if r['r_info_type'] != R_AARCH64_ABS64:
                    continue
                sym = symtab.get_symbol(r['r_info_sym'])
                rel_ro[r['r_offset']] = (sym, r['r_addend'])
        rodata = self.byname['.rodata'].data()
        self.cmds = []
        for i in range(CMD_COUNT):
            base = TABLE_RODATA_OFF + i * ENTRY_SZ
            row = {'i': i, 'name': None, 'handler': None, 'flag': None,
                   'handler_addr': None, 'handler_size': 0}
            rn = rel_ro.get(base)
            rh = rel_ro.get(base + 8)
            if rn:
                sym, addend = rn
                shndx = sym['st_shndx']
                if isinstance(shndx, int) and 0 < shndx < len(self.secs):
                    s = self.secs[shndx]
                    row['name'] = cstr(s.data(), sym['st_value'] + addend)
            if rh:
                sym, addend = rh
                addr = sym['st_value'] + addend
                row['handler_addr'] = addr
                hit = self.func_name(addr)
                row['handler'] = hit
                if hit:
                    row['handler_size'] = self.func_by_name[hit][1]
            row['flag'] = rodata[base + 0x10] if base + 0x10 < len(rodata) else None
            self.cmds.append(row)

    def func_name(self, addr):
        for v, sz, n in self.funcs:
            if v <= addr < v + sz:
                return n
        return None

    # -- 反汇编 ------------------------------------------------------------
    def disasm(self, name):
        base, size, _ = self.func_by_name[name]
        return base, size, list(self.md.disasm(self.text[base:base + size], base))

    def strings_in(self, base, size):
        """收集函数内 MOVW_UABS_G0..G3 四段重定位指向的字面量（按组去重）。"""
        groups = {}
        for off in range(base, base + size, 4):
            r = self.rel_text.get(off)
            if r is None:
                continue
            if r[0] in MOVW_LO:
                key = (r[1], r[3])          # symidx, addend
                g = groups.setdefault(key, {'offs': [], 'reloc': r})
                g['offs'].append(off)
            elif r[0] in (R_ADR_PREL_PG_HI21, R_ADD_ABS_LO12):
                key = ('adrp', r[1], r[3])
                g = groups.setdefault(key, {'offs': [], 'reloc': r})
                g['offs'].append(off)
        out = []
        for key, g in groups.items():
            secname, off = self.target_of(g['reloc'])
            if secname is None or off is None:
                continue
            s = self.read_string_at(secname, off)
            if s is None:
                continue
            out.append({'addr': min(g['offs']), 'section': secname,
                        'off': off, 'value': s})
        out.sort(key=lambda x: x['addr'])
        return out

    def calls_in(self, base, size):
        out = []
        for off in range(base, base + size, 4):
            r = self.rel_text.get(off)
            if r and r[0] in (R_CALL26, R_JUMP26):
                out.append({'addr': off, 'type': r[0], 'name': r[2]})
        out.sort(key=lambda x: x['addr'])
        return out


# ---------------------------------------------------------------------------
# 指令级辅助
# ---------------------------------------------------------------------------
_SP_RE = re.compile(r'^sp\s*$')


def _rn(md, reg):
    n = md.reg_name(reg)
    return 'x29' if n == 'fp' else ('x30' if n == 'lr' else n)



def _is_sp(op, md):
    return op.type == ARM64_OP_REG and _rn(md, op.reg) == 'sp'


def frame_size(insns, md):
    """返回 (frame_bytes, evidence_addr, form)。

    覆盖两种 prologue：`sub sp, sp, #imm` 与 `stp x29,x30,[sp,#-N]!`。
    """
    total = None
    ev = None
    form = []
    for ins in insns[:12]:
        if ins.mnemonic == 'sub' and len(ins.operands) == 3:
            if _is_sp(ins.operands[0], md) and _is_sp(ins.operands[1], md) \
                    and ins.operands[2].type == ARM64_OP_IMM:
                total = (total or 0) + ins.operands[2].imm
                ev = ins.address
                form.append('sub sp,#%#x' % ins.operands[2].imm)
        if ins.mnemonic in ('stp', 'str') and len(ins.operands) >= 2:
            mem = ins.operands[-1]
            if mem.type == ARM64_OP_MEM and _rn(md, mem.mem.base) == 'sp' \
                    and mem.mem.disp < 0 and (ins.writeback or ins.mnemonic == 'stp'):
                if ins.mnemonic == 'stp' and len(ins.operands) == 3 and ins.writeback:
                    total = (total or 0) + (-mem.mem.disp)
                    ev = ins.address
                    form.append('%s [sp,#-%#x]!' % (ins.mnemonic, -mem.mem.disp))
    if total is None:
        # 没有 sp 调整：帧大小即最大负偏移用量
        low = 0
        for ins in insns:
            for op in ins.operands:
                if op.type == ARM64_OP_MEM and _rn(md, op.mem.base) == 'sp' \
                        and op.mem.disp < 0:
                    low = min(low, op.mem.disp)
        total = -low
        ev = insns[0].address if insns else None
        form.append('leaf/no-sp-adjust')
    return total, ev, '+'.join(form)


def _imm_of(op):
    return op.imm if op.type == ARM64_OP_IMM else None


def _mem_of(op, md):
    """返回 (base_reg_name, disp) 或 (None, None)。"""
    if op.type != ARM64_OP_MEM:
        return None, None
    base = _rn(md, op.mem.base) if op.mem.base else None
    disp = op.mem.disp
    if op.mem.index:
        disp = None      # 带索引的寻址不当作固定槽
    return base, disp


def _eff_off(op, md, x29_base):
    """把 [sp,#d] / [x29,#d] 归一成 sp 相对位移；不可判定返回 (None, None)。"""
    base, disp = _mem_of(op, md)
    if disp is None:
        return None, None
    if base == 'sp':
        return 'sp', disp
    if base == 'x29' and x29_base is not None:
        return 'sp', x29_base + disp
    return base, disp


def resolve_arg_slot(insns, idx, regname, md, lookback=20, x29_base=None):
    """从 call 指令向前找 `add/sub xN, sp|x29, #imm` / `mov xN, sp`，返回 (sp_off, addr)。

    只做单层寄存器追踪（xN <- sp/x29+imm），覆盖本模块的编译器输出形态。
    """
    for j in range(idx - 1, max(-1, idx - 1 - lookback), -1):
        ins = insns[j]
        if ins.mnemonic in ('add', 'sub') and len(ins.operands) == 3:
            d, a, b = ins.operands
            if d.type == ARM64_OP_REG and _rn(md, d.reg) == regname \
                    and b.type == ARM64_OP_IMM:
                imm = b.imm if ins.mnemonic == 'add' else -b.imm
                if _is_sp(a, md):
                    return imm, ins.address
                if x29_base is not None and a.type == ARM64_OP_REG \
                        and _rn(md, a.reg) == 'x29':
                    return x29_base + imm, ins.address
            if d.type == ARM64_OP_REG and _rn(md, d.reg) == regname \
                    and a.type == ARM64_OP_REG and _rn(md, a.reg) == regname \
                    and b.type == ARM64_OP_IMM:
                return None, ins.address     # add xN,xN,#imm 形态：相对基址，不解析
        if ins.mnemonic == 'mov' and len(ins.operands) == 2:
            d, a = ins.operands
            if d.type == ARM64_OP_REG and _rn(md, d.reg) == regname \
                    and _is_sp(a, md):
                return 0, ins.address
        if ins.mnemonic == 'bl':
            break
    return None, None


def stack_map(insns, md):
    """收集函数内所有 sp 相对位移（把 x29 相对也折算进来），返回排序后的偏移列表。

    这是"栈对象边界"的可用近似：若某对象的写入区间 [off, off+need) 不含任何其它
    被独立使用的偏移，则可判定它没有覆盖到相邻对象。局限见文档 §1.3。
    """
    x29_base = None
    for ins in insns[:8]:
        if ins.mnemonic == 'add' and len(ins.operands) == 3:
            d, a, b = ins.operands
            if d.type == ARM64_OP_REG and _rn(md, d.reg) == 'x29' \
                    and _is_sp(a, md) and b.type == ARM64_OP_IMM:
                x29_base = b.imm
    offs = set()
    for ins in insns:
        for op in ins.operands:
            if op.type != ARM64_OP_MEM:
                continue
            base = _rn(md, op.mem.base) if op.mem.base else None
            if base == 'sp':
                offs.add(op.mem.disp)
            elif base == 'x29' and x29_base is not None:
                offs.add(x29_base + op.mem.disp)
    return sorted(offs), x29_base


def next_offset_after(offs, slot):
    for o in offs:
        if o > slot:
            return o
    return None


def const_in_reg(insns, idx, regname, md, lookback=10):
    """call 之前 xN/wN 的立即数（mov wN,#imm / movz/movk 单条形态）。"""
    for j in range(idx - 1, max(-1, idx - 1 - lookback), -1):
        ins = insns[j]
        if ins.mnemonic == 'mov' and len(ins.operands) == 2:
            d, a = ins.operands
            if d.type == ARM64_OP_REG and _rn(md, d.reg) in (regname, 'w' + regname[1:]) \
                    and a.type == ARM64_OP_IMM:
                return a.imm, ins.address
        if ins.mnemonic in ('bl',):
            break
    return None, None


def ptr_arg_target(k, insns, idx, regname, md, lookback=60, depth=3):
    """把 call 之前写给 regname 的地址还原成字面量字符串。

    本模块用 large code model：地址由
        movz xN,#:abs_g0_nc:sym ; movk xN,#:abs_g1_nc ; movk xN,#:abs_g2_nc ; movk xN,#:abs_g3
    四条带重定位的指令组成。只要命中其中任意一条并解出 (节, 偏移)，即可唯一定位该字面量。
    支持一层以上 `mov xD, xS` 寄存器搬运（编译器常把字面量先装进 callee-saved 寄存器）。
    返回 (字符串或 None, 装载指令地址或 None)。
    """
    cur = regname
    hops = 0
    for j in range(idx - 1, max(-1, idx - 1 - lookback), -1):
        ins = insns[j]
        if ins.mnemonic in ('mov', 'movz', 'movk') and ins.operands:
            d = ins.operands[0]
            if d.type == ARM64_OP_REG and _rn(md, d.reg) == cur:
                r = k.rel_text.get(ins.address)
                if r and r[0] in MOVW_LO:
                    sec, off = k.target_of(r)
                    if sec is not None and off is not None:
                        return k.read_string_at(sec, off), ins.address
                # mov xD, xS  -> 顺着看 xS
                if ins.mnemonic == 'mov' and len(ins.operands) == 2 \
                        and ins.operands[1].type == ARM64_OP_REG and hops < depth:
                    cur = _rn(md, ins.operands[1].reg)
                    hops += 1
                    continue
        if ins.mnemonic in ('bl', 'blr'):
            break
    return None, None


def _success_path(insns, addr, md, window=90):
    """判断从 addr 开始的路径是否返回成功（w0==0），返回 True/False/None。

    以 `mov w0, wzr` / `mov w0, #0` 判成功；以 `mov w0, #-N` 判失败；
    遇到 ret 且无定论返回 None。只跟随无条件 b，不建模条件分支。
    """
    try:
        idx = next(i for i, x in enumerate(insns) if x.address == addr)
    except StopIteration:
        return None
    k = idx
    steps = 0
    while k < len(insns) and steps < window:
        steps += 1
        ins = insns[k]
        m = ins.mnemonic
        if m == 'mov' and len(ins.operands) == 2 \
                and ins.operands[0].type == ARM64_OP_REG \
                and ins.operands[1].type == ARM64_OP_IMM:
            if _rn(md, ins.operands[0].reg) in ('w0', 'x0'):
                return ins.operands[1].imm == 0
        if m == 'ret':
            return None
        if m == 'b' and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            tgt = ins.operands[0].imm
            try:
                k = next(i for i, x in enumerate(insns) if x.address == tgt)
                continue
            except StopIteration:
                return None
        k += 1
    return None


def _complement(pred, imm):
    """某条件成立区间的补集（用于"分支跳到失败臂"的情形）。"""
    if pred == 'cc':
        return [imm, None]
    if pred == 'cs':
        return [0, imm - 1]
    if pred == 'hi':
        return [0, imm]
    if pred == 'ls':
        return [imm + 1, None]
    if pred == 'eq':
        return None
    if pred == 'ne':
        return [imm, imm]
    return None


def scan_checks(insns, start_idx, slot_off, md, window=44, x29_base=None):
    """解析调用之后的两类门：

      ret   —— 解析是否成功（`cbnz/cbz/tbnz w0` / `cmp w0,#N` + 条件分支）；
      range —— 解析出的值是否在允许区间（`ldr wT,[sp,#slot]` + `cmp wT,#imm` + 条件分支）。

    返回 {'ret': {...}|None, 'range': {...}|None}。
    """
    res = {'ret': None, 'range': None}
    reg_from_slot = None
    consts = {}
    for j in range(start_idx + 1, min(len(insns), start_idx + 1 + window)):
        ins = insns[j]
        m = ins.mnemonic

        if m in ('cbnz', 'cbz') and len(ins.operands) == 2:
            rn = _rn(md, ins.operands[0].reg) if ins.operands[0].type == ARM64_OP_REG else None
            if rn in ('w0', 'x0') and res['ret'] is None and j <= start_idx + 8:
                tgt = ins.operands[1].imm if ins.operands[1].type == ARM64_OP_IMM else None
                succ = _success_path(insns, tgt, md) if tgt is not None else None
                res['ret'] = {'form': m, 'reg': rn, 'addr': ins.address,
                              'target': tgt, 'target_success': succ,
                              'ok': (succ is False)}
                continue

        if m in ('tbz', 'tbnz') and len(ins.operands) == 3:
            a, bit, tgtop = ins.operands
            rn = _rn(md, a.reg) if a.type == ARM64_OP_REG else None
            if rn in ('w0', 'x0') and res['ret'] is None and j <= start_idx + 8:
                tgt = tgtop.imm if tgtop.type == ARM64_OP_IMM else None
                succ = _success_path(insns, tgt, md) if tgt is not None else None
                res['ret'] = {'form': m, 'reg': rn, 'addr': ins.address,
                              'bit': bit.imm, 'target': tgt, 'target_success': succ,
                              'ok': (succ is not None)}
                continue

        if m in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldur', 'ldurb', 'ldurh', 'ldursw') \
                and len(ins.operands) == 2:
            b, disp = _eff_off(ins.operands[1], md, x29_base)
            if b == 'sp' and disp == slot_off and ins.operands[0].type == ARM64_OP_REG:
                reg_from_slot = _rn(md, ins.operands[0].reg)
                continue

        if m == 'mov' and len(ins.operands) == 2 and ins.operands[1].type == ARM64_OP_IMM \
                and ins.operands[0].type == ARM64_OP_REG:
            consts[_rn(md, ins.operands[0].reg)] = ins.operands[1].imm
            continue

        if m == 'cmp' and len(ins.operands) == 2:
            a, b = ins.operands
            rn = _rn(md, a.reg) if a.type == ARM64_OP_REG else None
            imm = _imm_of(b)
            if imm is None and b.type == ARM64_OP_REG:
                imm = consts.get(_rn(md, b.reg))
            if imm is None:
                continue
            kind = None
            if rn in ('w0', 'x0') and res['ret'] is None:
                kind = 'ret'
            elif reg_from_slot is not None and rn is not None \
                    and rn.replace('x', 'w') == reg_from_slot.replace('x', 'w'):
                kind = 'range'
            if kind is None:
                continue
            # 紧随其后的条件分支
            br = None
            for k in range(j + 1, min(len(insns), j + 9)):
                if insns[k].mnemonic in COND_BRANCH:
                    br = insns[k]
                    break
                if insns[k].mnemonic in ('bl', 'blr', 'ret'):
                    break
            pred = COND_BRANCH[br.mnemonic][0] if br else None
            acc = _accepted_interval(pred, imm) if pred else None
            tgt_success = None
            if br is not None and br.operands and br.operands[0].type == ARM64_OP_IMM:
                tgt_success = _success_path(insns, br.operands[0].imm, md)
                if tgt_success is False and acc is not None:
                    acc = _complement(pred, imm)
            rec = {'cmp_imm': imm, 'cmp_addr': ins.address, 'reg': rn,
                   'branch': br.mnemonic if br else None,
                   'branch_addr': br.address if br else None,
                   'pred': pred, 'accepted': acc,
                   'target_success': tgt_success,
                   'slot': slot_off if kind == 'range' else None}
            if kind == 'ret' and res['ret'] is None:
                res['ret'] = rec
            elif kind == 'range' and res['range'] is None:
                res['range'] = rec

        if m in ('bl', 'blr', 'ret') and j > start_idx + 10:
            break
    return res


def _accepted_interval(pred, imm):
    """把 `cmp x,#imm; b.PRED` 语义化成"分支成立时 x 的区间"。"""
    if imm is None:
        return None
    if pred == 'cc':            # b.lo -> x < imm
        return [0, imm - 1]
    if pred == 'cs':            # b.hs -> x >= imm
        return [imm, None]
    if pred == 'hi':            # b.hi -> x > imm
        return [imm + 1, None]
    if pred == 'ls':            # b.ls -> x <= imm
        return [0, imm]
    if pred == 'eq':
        return [imm, imm]
    if pred == 'ne':
        return [imm + 1, None]  # 仅当 imm==0 时等价
    return None


SSCANF_CONV = re.compile(
    r'%(?:[-+ #0]*)(\d+|\*)?(?:\.\d+)?(?:hh|h|ll|l|z|j|t)?([diouxXeEfgGaAcspn\[%])')


def classify_sscanf(fmt):
    """分析 sscanf 格式串。

    返回 (描述, 级别, 最坏写入字节数)。
    级别：'bounded' = 所有 %s/%[ 都带字段宽度；'unbounded' = 有裸 %s/%[；
          'none' = 没有可写转换；'unresolved' = 格式串未能静态解析。
    """
    if fmt is None:
        return 'fmt-unresolved', 'unresolved', None
    convs = []
    unbounded = False
    worst = 0
    any_write = False
    for m in SSCANF_CONV.finditer(fmt):
        width_s, c = m.group(1), m.group(2)
        width = int(width_s) if (width_s and width_s.isdigit()) else None
        if c in ('s', '['):
            any_write = True
            if width is None:
                unbounded = True
                convs.append('%' + c + '(NO-WIDTH)')
                worst = None
            else:
                convs.append('%' + c + '(%d)' % width)
                need = width + 1
                worst = need if worst is None else max(worst or 0, need)
        elif c == 'c':
            any_write = True
            w = width or 1
            convs.append('%c(%d)' % w)
            worst = max(worst or 0, w)
        elif c == 'n':
            convs.append('%n')
            worst = max(worst or 0, 4)
        elif c == '%':
            continue
        else:
            any_write = True
            convs.append('%' + c)
            worst = max(worst or 0, 4)
    desc = '+'.join(convs) if convs else 'no-write-conv'
    if not any_write:
        return desc, 'none', 0
    if unbounded:
        return desc, 'unbounded', None
    return desc, 'bounded', worst


# ---------------------------------------------------------------------------
# 单个 handler 的完整事实
# ---------------------------------------------------------------------------
def analyze(k, name):
    if not _HAVE_CAPSTONE:
        raise RuntimeError('capstone 不可用')
    base, size, insns = k.disasm(name)
    md = k.md
    fsz, fsz_addr, fsz_form = frame_size(insns, md)
    calls = k.calls_in(base, size)
    strings = k.strings_in(base, size)
    str_at = {}
    for s in strings:
        str_at.setdefault(s['addr'], s['value'])

    facts = {
        'handler': name, 'addr': base, 'size': size,
        'frame_size': fsz, 'frame_addr': fsz_addr, 'frame_form': fsz_form,
        'calls': [c['name'] for c in calls],
        'call_detail': calls,
        'strings': [{'addr': s['addr'], 'value': s['value']} for s in strings],
        'parse': [], 'checks': [], 'copy': [], 'locks': [],
        'out_fmt': [], 'notes': [],
    }
    offs, x29_base = stack_map(insns, md)
    facts['stack_offs'] = offs
    facts['x29_base'] = x29_base

    # --- 解析调用 & 拷贝调用 ---
    for idx, ins in enumerate(insns):
        if ins.mnemonic not in ('bl', 'blr'):
            continue
        r = k.rel_text.get(ins.address)
        fname = r[2] if r and r[0] in (R_CALL26, R_JUMP26) else None
        if fname is None:
            continue

        if fname in PARSE_FUNCS:
            rec = {'fn': fname, 'addr': ins.address, 'slot': None,
                   'slot_addr': None, 'width': KSTRTO_WIDTH.get(fname), 'fmt': None,
                   'fmt_addr': None, 'convs': None, 'unbounded': False}
            if fname in ('sscanf', 'vsscanf'):
                fmt, fa = ptr_arg_target(k, insns, idx, 'x1', md)
                rec['fmt'] = fmt
                rec['fmt_addr'] = fa
                rec['convs'], rec['level'], rec['need'] = classify_sscanf(fmt)
                rec['unbounded'] = (rec['level'] == 'unbounded')
                # 输出指针：x2..x5
                outs = []
                for rn in ('x2', 'x3', 'x4', 'x5'):
                    o, oa = resolve_arg_slot(insns, idx, rn, md, x29_base=x29_base)
                    if o is not None:
                        outs.append({'reg': rn, 'slot': o, 'addr': oa})
                rec['slot'] = outs[0]['slot'] if outs else None
                rec['slot_addr'] = outs[0]['addr'] if outs else None
                rec['outs'] = outs
                rec['width'] = rec.get('need')
            else:
                dreg = DEST_REG.get(fname, 'x2')
                off, a = resolve_arg_slot(insns, idx, dreg, md, x29_base=x29_base)
                rec['slot'] = off
                rec['slot_addr'] = a
                rec['dest_reg'] = dreg
                rec['outs'] = [{'reg': dreg, 'slot': off, 'addr': a}] if off is not None else []
                if off is None:
                    rec['width'] = rec.get('width')
            facts['parse'].append(rec)
            continue

        if fname in COPY_FUNCS:
            rec = {'fn': fname, 'addr': ins.address}
            if fname in ('scnprintf', 'snprintf', 'vsnprintf', 'vscnprintf'):
                lim, la = const_in_reg(insns, idx, 'x1', md)
                rec['limit'] = lim
                rec['limit_addr'] = la
                fmt, fa = ptr_arg_target(k, insns, idx, 'x2', md)
                if fmt is None:
                    fmt = _fmt_for_call(k, strings, ins.address)
                    fa = None
                rec['fmt'] = fmt
                rec['fmt_addr'] = fa
                if fmt and '%s' in fmt:
                    rec['fmt_has_s'] = True
            if fname in ('memcpy', 'qdf_mem_copy', 'memmove', '__memcpy_chk'):
                ln, la = const_in_reg(insns, idx, 'x2', md)
                rec['len'] = ln
                rec['len_addr'] = la
            if fname in ('__arch_copy_to_user', 'copy_to_user'):
                ln, la = const_in_reg(insns, idx, 'x2', md)
                rec['len'] = ln
                rec['len_addr'] = la
            facts['copy'].append(rec)
            if fname in LOCK_FUNCS:
                facts['locks'].append({'fn': fname, 'addr': ins.address})

        if fname in LOCK_FUNCS:
            facts['locks'].append({'fn': fname, 'addr': ins.address})

        if fname in ('strncmp', 'strncasecmp', 'strncpy', 'strnlen', 'strlcpy'):
            ln, la = const_in_reg(insns, idx, 'x2', md)
            facts.setdefault('strn', []).append(
                {'fn': fname, 'addr': ins.address, 'len': ln, 'len_addr': la})

    # --- 解析后的范围门 + 栈槽边界 ---
    for rec in facts['parse']:
        if rec['slot'] is None or rec['slot'] < 0:
            continue
        ci = next((i for i, x in enumerate(insns) if x.address == rec['addr']), None)
        if ci is None:
            continue
        got = scan_checks(insns, ci, rec['slot'], md, x29_base=x29_base)
        need = rec.get('need') or rec.get('width') or 0
        nxt = next_offset_after(offs, rec['slot'])
        chk = {'for_fn': rec['fn'], 'for_call': rec['addr'],
               'slot': rec['slot'], 'width': rec['width'],
               'ret': got['ret'], 'range': got['range'],
               'need': need, 'next_off': nxt}
        if need:
            limit = nxt if nxt is not None else facts['frame_size']
            chk['stack_ok'] = (rec['slot'] + need) <= limit
        else:
            chk['stack_ok'] = None
        facts['checks'].append(chk)

    # --- 分类 ---
    facts['group'] = _group_of(facts)
    facts['in_short'] = _in_short(facts)
    return facts


def _fmt_for_call(k, strings, call_addr):
    """取 call 之前最近一个字面量；sscanf/scnprintf 的格式串由编译器就近装载。"""
    best = None
    for s in strings:
        if s['addr'] < call_addr:
            best = s['value']
        else:
            break
    return best


def _group_of(f):
    cs = set(f['calls'])
    if cs & (LOCK_FUNCS - {'qdf_mutex_release', 'qdf_spin_unlock', 'mutex_unlock',
                           'spin_unlock', 'up', 'complete', 'osif_request_put'}):
        return '并发管理'
    if cs & OUT_FUNCS or cs & HEAP_FUNCS:
        return '内存管理'
    if cs & EXT_FUNCS:
        return '外部交互'
    if cs & PARSE_FUNCS or cs & {'strpbrk', 'strnchr', 'hex_to_bin', 'mac_pton'}:
        return '参数解析'
    return '状态管理'


def _in_short(f):
    """操作定义：1 = 参数消费被"短输入"约束。

    判据（全部满足才为 1）：
      a) 无 sscanf 无界转换（裸 %s / %[）；"格式串未解析"不算有界，也不判为无界，
         而是令 in_short=0 并在 notes 标 FMT-UNRESOLVED，交由人工复核；
      b) 没有以输入派生长度调用的 memcpy/qdf_mem_copy；
      c) 所有解析目标槽宽 <= 8B（标量）。
    """
    for p in f['parse']:
        if p['fn'] in ('sscanf', 'vsscanf'):
            if p.get('level') == 'unbounded':
                return 0
            if p.get('level') == 'unresolved':
                return 0
    for c in f['copy']:
        if c['fn'] in ('memcpy', 'qdf_mem_copy', 'memmove', '__memcpy_chk') \
                and c.get('len') is None:
            return 0
    return 1


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
FLAG_LABEL = {0: 'NO-PARAM', 1: 'NEEDS-PARAM'}


def fmt_parse(p):
    if p['fn'] in ('sscanf', 'vsscanf'):
        s = '%s@%#x[%s]' % (p['fn'], p['addr'], p.get('convs') or '?')
        if p.get('fmt'):
            s += ' fmt="%s"' % sanitize(p['fmt'], 120)
        if p.get('outs'):
            s += ' out=' + ','.join('sp%+#x' % o['slot'] for o in p['outs']
                                    if o['slot'] is not None)
        return s
    if p['slot'] is None:
        return '%s@%#x[slot?]' % (p['fn'], p['addr'])
    return '%s@%#x[sp%+#x/%dB]' % (p['fn'], p['addr'], p['slot'], p['width'] or 0)


def fmt_check(c):
    """把一条解析结果压缩成"支撑性检查指令"记录。"""
    bits = []
    ret = c.get('ret')
    rng = c.get('range')
    if ret:
        if ret.get('form'):                      # cbnz/cbz w0
            bits.append('ret:%s %s@%#x->%s' %
                        (ret['form'], ret.get('reg'), ret['addr'],
                         'ok' if ret.get('ok') else 'fail?'))
        else:
            acc = ret.get('accepted')
            bits.append('ret:cmp#%#x;%s@%#x' % (ret.get('cmp_imm') or 0,
                                               ret.get('branch') or '?',
                                               ret.get('cmp_addr') or 0))
    if rng:
        acc = rng.get('accepted')
        if acc is not None:
            hi = '..' if acc[1] is None else '%#x' % acc[1]
            bits.append('val[%#x,%s]@cmp#%#x;%s' %
                        (acc[0], hi, rng['cmp_imm'], rng.get('branch') or '?'))
        else:
            bits.append('val@cmp#%#x;%s' % (rng['cmp_imm'], rng.get('branch') or '?'))
    if not ret and not rng:
        bits.append('no-check')
    if c.get('need'):
        if c.get('stack_ok') is True:
            bits.append('slot%dB<=%s' % (c['need'],
                                         ('%+#x' % c['next_off']) if c['next_off'] is not None
                                         else 'frame'))
        elif c.get('stack_ok') is False:
            bits.append('SLOT-OVERLAP need=%dB next=%s' %
                        (c['need'], ('%+#x' % c['next_off']) if c['next_off'] is not None else '-'))
    return ' '.join(bits)


def fmt_copy(c):
    s = c['fn']
    if c.get('limit') is not None:
        s += '(limit=%#x)' % c['limit']
    if c.get('len') is not None:
        s += '(len=%#x)' % c['len']
    if c.get('len') is None and c['fn'] in ('memcpy', 'qdf_mem_copy'):
        s += '(len=reg)'
    return '%s@%#x' % (s, c['addr'])


def notes_of(f):
    out = []
    for p in f['parse']:
        if p['fn'] in ('sscanf', 'vsscanf'):
            if p.get('level') == 'unbounded':
                out.append('SSCANF-NO-WIDTH')
            if p.get('level') == 'unresolved':
                out.append('FMT-UNRESOLVED')
    if not f['parse'] and not f['copy']:
        out.append('no-parse-no-copy')
    for c in f['copy']:
        if c['fn'] in ('memcpy', 'qdf_mem_copy') and c.get('len') is None:
            out.append('COPY-LEN-FROM-REG')
    if f['parse'] and not any((c.get('ret') or c.get('range')) for c in f['checks']):
        out.append('PARSE-NO-CHECK')
    for c in f['checks']:
        if c.get('stack_ok') is False:
            out.append('SLOT-OVERLAP')
    if f['locks']:
        out.append('locks')
    if any(c['fn'] in ('scnprintf', 'snprintf') and c.get('limit') is None
           for c in f['copy']):
        out.append('FMT-LIMIT-REG')
    if any(c.get('fmt_has_s') for c in f['copy']):
        out.append('OUT-FMT-HAS-%s')
    return ';'.join(out).replace('%s', 'S')


def csv_row(f, cmd):
    parse_s = ';'.join(fmt_parse(p) for p in f['parse']) or ''
    checks = ';'.join(fmt_check(c) for c in f['checks']) or ''
    if not checks and f['parse']:
        checks = 'none'
    copy_s = ';'.join(fmt_copy(c) for c in f['copy']) or ''
    extra = []
    if f['locks']:
        extra.append('locks=' + ','.join(sorted({l['fn'] for l in f['locks']})))
    if f.get('strn'):
        extra.append('strn=' + ','.join('%s(%s)' % (s['fn'], s['len']) for s in f['strn']))
    return [
        str(cmd['i']), cmd['name'] or '', f['handler'],
        str(f['size']), str(f['frame_size']),
        sanitize(parse_s, 300), sanitize(checks, 300), str(f['in_short']),
        sanitize(copy_s, 300),
        notes_of(f), f['group'],
        sanitize(parse_s, 300),
        sanitize(copy_s, 300),
        '|'.join(sorted(set(f['calls']))),
        '|'.join(sanitize(s['value'], 60) for s in f['strings'])[:400],
    ]


CSV_HEADER = ['i', 'name', 'handler', 'handler_size', 'frame_size', 'parse_funcs',
              'range_check', 'in_short', 'copy_ops', 'notes', 'group',
              'parse_evidence', 'copy_evidence', 'calls', 'strings']


def _csv_escape(v):
    if v is None:
        return ''
    v = str(v)
    if any(ch in v for ch in ',"\n\r'):
        return '"' + v.replace('"', '""') + '"'
    return v


def main(argv=None):
    ap = argparse.ArgumentParser(description='qcacld hdd_driver_command handler 静态扫描')
    ap.add_argument('--ko', default=KO_DEFAULT)
    ap.add_argument('--csv', action='store_true')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--dump-dir', default=None)
    ap.add_argument('--handler', default=None)
    ap.add_argument('--disasm', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--summary', action='store_true')
    ap.add_argument('--out', default=None, help='把 CSV/JSON 写入该文件（UTF-8）')
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

    if not _HAVE_CAPSTONE:
        print('capstone 不可用', file=sys.stderr)
        return 2
    if not os.path.exists(args.ko):
        print('找不到 %s' % args.ko, file=sys.stderr)
        return 2

    k = Ko(args.ko)
    unresolved = [c for c in k.cmds if not c['name'] or not c['handler']]
    if unresolved:
        print('命令表解析失败 %d 项' % len(unresolved), file=sys.stderr)
        return 3

    facts = [analyze(k, c['handler']) for c in k.cmds]

    if args.selftest:
        return self_test(k, facts)

    if args.handler:
        for c, f in zip(k.cmds, facts):
            if c['handler'] != args.handler and c['name'] != args.handler:
                continue
            print('# [%d] %s -> %s @%#x size=%d frame=%#x (%s)' %
                  (c['i'], c['name'], f['handler'], f['addr'], f['size'],
                   f['frame_size'], f['frame_form']))
            print('group=%s in_short=%d notes=%s' % (f['group'], f['in_short'], notes_of(f)))
            for p in f['parse']:
                print('  parse: ' + fmt_parse(p))
            for ch in f['checks']:
                print('  check: ' + fmt_check(ch))
            for cp in f['copy']:
                print('  copy : ' + fmt_copy(cp))
            for s in f['strings']:
                print('  str  : %#x %r' % (s['addr'], s['value']))
            if args.disasm:
                print('--- disasm ---')
                for ins in k.disasm(f['handler'])[2]:
                    r = k.rel_text.get(ins.address)
                    ann = '   ; %s' % r[2] if r and r[0] in (R_CALL26, R_JUMP26) else ''
                    print('%06x  %-22s %-10s %s%s' % (ins.address, ins.bytes.hex(),
                                                      ins.mnemonic, ins.op_str, ann))
            return 0
        print('未找到 handler/name: %s' % args.handler, file=sys.stderr)
        return 4

    if args.dump_dir:
        os.makedirs(args.dump_dir, exist_ok=True)
        for c, f in zip(k.cmds, facts):
            path = os.path.join(args.dump_dir, '%03d_%s.txt' % (c['i'], f['handler']))
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('# [%d] %s -> %s @%#x size=%d frame=%#x (%s) group=%s flag=%s\n' %
                         (c['i'], c['name'], f['handler'], f['addr'], f['size'],
                          f['frame_size'], f['frame_form'], f['group'],
                          FLAG_LABEL.get(c['flag'], c['flag'])))
                for ins in k.disasm(f['handler'])[2]:
                    r = k.rel_text.get(ins.address)
                    if r and r[0] in (R_CALL26, R_JUMP26):
                        ann = '   ; %s' % r[2]
                    elif r and r[0] in MOVW_LO:
                        sec, off = k.target_of(r)
                        sv = k.read_string_at(sec, off) if sec and off is not None else None
                        ann = '   ; .abs %s+%#x%s' % (sec, off, ('  %r' % sv) if sv else '')
                    else:
                        ann = ''
                    fh.write('%06x  %-22s %-10s %s%s\n' % (ins.address, ins.bytes.hex(),
                                                          ins.mnemonic, ins.op_str, ann))
        print('dumped 98 handlers -> %s' % args.dump_dir, file=sys.stderr)

    if args.json:
        text = json.dumps({'cmds': k.cmds, 'facts': facts}, ensure_ascii=False, indent=1)
        if args.out:
            with open(args.out, 'w', encoding='utf-8') as fh:
                fh.write(text + '\n')
            print('wrote %s' % args.out, file=sys.stderr)
        else:
            print(text)
        return 0

    if args.csv:
        lines = [','.join(CSV_HEADER)]
        for c, f in zip(k.cmds, facts):
            lines.append(','.join(_csv_escape(v) for v in csv_row(f, c)))
        text = '\n'.join(lines) + '\n'
        if args.out:
            with open(args.out, 'w', encoding='utf-8', newline='') as fh:
                fh.write(text)
            print('wrote %s (%d rows)' % (args.out, len(lines) - 1), file=sys.stderr)
        else:
            sys.stdout.write(text)
        return 0

    # 人读摘要
    print('%-3s %-32s %-46s %-5s %-6s %-8s %s' %
          ('#', 'name', 'handler', 'size', 'frame', 'group', 'notes'))
    for c, f in zip(k.cmds, facts):
        print('%-3d %-32s %-46s %-5d %-6d %-8s %s' %
              (c['i'], c['name'], f['handler'], f['size'], f['frame_size'],
               f['group'], notes_of(f)))
    from collections import Counter
    print('\n分类计数：')
    for g, n in Counter(f['group'] for f in facts).most_common():
        print('  %-8s %d' % (g, n))
    print('in_short=1: %d / in_short=0: %d' %
          (sum(f['in_short'] for f in facts), sum(1 - f['in_short'] for f in facts)))
    return 0


def self_test(k, facts):
    """自检：验证扫描器在已知 handler 上给出的关键事实。"""
    fails = []
    ok = 0

    def chk(cond, msg):
        nonlocal ok
        if cond:
            ok += 1
        else:
            fails.append(msg)

    chk(len(k.cmds) == 98, '命令表应为 98 项，实得 %d' % len(k.cmds))
    chk(all(c['name'] and c['handler'] for c in k.cmds), '命令表存在未解析项')
    by_name = {f['handler']: f for f in facts}
    # drv_cmd_set_dwell_time：kstrtouint -> sp+4，门限 cmp #0x2711
    f = by_name['drv_cmd_set_dwell_time']
    chk(f['frame_size'] == 0x30, 'set_dwell_time 帧应为 0x30，实得 %#x' % f['frame_size'])
    chk(any(p['fn'] == 'kstrtouint' for p in f['parse']), 'set_dwell_time 缺 kstrtouint')
    chk(len(f['checks']) == 4 and all(c['range'] and c['range']['cmp_imm'] == 0x2711
                                      and c['range']['accepted'] == [0, 0x2710]
                                      for c in f['checks']),
        'set_dwell_time 应有 4 个 kstrtouint，范围门 #0x2711 => [0,0x2710]')
    # drv_cmd_country：无解析、帧 0x20
    f = by_name['drv_cmd_country']
    chk(f['frame_size'] == 0x20, 'country 帧应为 0x20，实得 %#x' % f['frame_size'])
    chk(not f['parse'], 'country 不应有标量解析')
    # 命令表名称
    names = [c['name'] for c in k.cmds]
    chk(names[0] == 'P2P_DEV_ADDR' and names[97] == 'BTCOEXSCAN-STOP',
        '命令表首尾名称不符')
    print('selftest: %d ok, %d fail' % (ok, len(fails)))
    for m in fails:
        print('  FAIL: ' + m)
    return 0 if not fails else 1


if __name__ == '__main__':
    sys.exit(main())
