#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wlan_residual_scan.py — WLAN_RESIDUAL_AUDIT 的 A 组收口工具（纯离线）。

本脚本只读 vendor_ko/qca_cld3_wlan.ko（SHA-256 f45c1c1c…74d00），不连设备、不联网、
不运行任何驱动命令。它补上 `tools/wlan_handler_scan.py` 的两个盲区：

  A1  **偏置值域门**：扫描器只认 `ldr wT,[sp,#slot]` 后紧跟 `cmp wT,#imm`。
      本模块的真实形态常常是
          bl  kstrtoint
          ldr w20,[sp,#0x14]      ; 解析结果
          add w8, w20, #0x64      ; 偏置（把有符号区间折叠成无符号比较）
          cmp w8, #0xc8
          b.ls <成功臂>
      于是 `w8` 不是自槽位直载，扫描器判 `no-check`。本工具用"派生寄存器传播"
      （add/sub 立即数）把门重新对上槽位，并换算回原值的区间。

  A2  **跨 bl 的格式串解析**：`sscanf` 的格式串常被编译器先装进 callee-saved
      寄存器（x19..x28），再在多个调用点用 `mov x1, xN` 复用。扫描器的
      `ptr_arg_target()` 遇到 `bl` 就 break，因此解不出。本工具对**函数内 CFG**
      做前向数据流（寄存器常量格），按 AAPCS64 只在 `bl` 处失效 caller-saved
      (x0..x18)、保留 callee-saved (x19..x28)，从而解出格式串。

输出：
  * 人读摘要；
  * `--csv` 追加/写出行（与 residual_audit.csv 同表头，group=A）。

用法：
  python tools/wlan_residual_scan.py
  python tools/wlan_residual_scan.py --detail
  python tools/wlan_residual_scan.py --csv artifacts_adb/r1_wlan_reach/residual_audit.csv --append
  python tools/wlan_residual_scan.py --selftest
"""
import argparse
import os
import re
import sys
from collections import defaultdict

from elftools.elf.elffile import ELFFile

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64 import (ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM,
                                ARM64_OP_CIMM)
except Exception:                                            # pragma: no cover
    Cs = None

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from wlan_handler_scan import (Ko, KO_DEFAULT, R_CALL26, R_JUMP26, MOVW_LO,  # noqa: E402
                              R_ADR_PREL_PG_HI21, R_ADD_ABS_LO12,
                              classify_sscanf, sanitize, SSCANF_CONV)

# A 组目标 handler（命令名 -> handler 符号）
A1_HANDLER = 'drv_cmd_max_tx_power'
A2_HANDLERS = ['drv_cmd_ccx_beacon_req', 'drv_cmd_ccx_plm_req',
               'drv_cmd_set_disable_chan_list', 'drv_cmd_get_ani_level']

# 写 op0 的助记符前缀（用于寄存器状态失效）；其余凡写寄存器即清空其常量状态
NON_WRITE0 = {
    'cmp', 'cmn', 'tst', 'b', 'bl', 'br', 'blr', 'ret', 'cbz', 'cbnz', 'tbz',
    'tbnz', 'prfm', 'nop', 'dmb', 'dsb', 'isb', 'hlt', 'svc', 'stp', 'str',
    'strb', 'strh', 'stur', 'sturb', 'sturh', 'stnp', 'ccmp', 'ccmn',
}


def _norm(md, reg):
    """把 aarch64 寄存器名归一成 xN（w0 与 x0 同键）。"""
    n = md.reg_name(reg)
    if n == 'fp':
        return 'x29'
    if n == 'lr':
        return 'x30'
    if n == 'wsp':
        return 'xsp'
    if n.startswith('w') and n[1:].isdigit():
        return 'x' + n[1:]
    return n


def written_regs(md, ins):
    """返回该指令显式写到的寄存器名集合（归一化）。"""
    out = set()
    m = ins.mnemonic
    if m in NON_WRITE0 or m.startswith('b.') or m.startswith('st'):
        return out
    if m == 'ldp' and len(ins.operands) >= 2:
        if ins.operands[0].type == ARM64_OP_REG:
            out.add(_norm(md, ins.operands[0].reg))
        if ins.operands[1].type == ARM64_OP_REG:
            out.add(_norm(md, ins.operands[1].reg))
    elif ins.operands and ins.operands[0].type == ARM64_OP_REG:
        out.add(_norm(md, ins.operands[0].reg))
    return out


def br_targets(md, ins):
    """返回 (条件分支目标, 是否终止块)。只处理函数内直接分支。"""
    m = ins.mnemonic
    if m == 'ret' or m == 'br':
        return [], True
    if m == 'b':
        if ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            return [ins.operands[0].imm], True
        return [], True
    if m in ('cbz', 'cbnz', 'tbz', 'tbnz') or m.startswith('b.'):
        if ins.operands and ins.operands[-1].type == ARM64_OP_IMM:
            return [ins.operands[-1].imm], False
        return [], False
    return [], False          # bl / blr / 普通指令：落到下一条


class FmtResolver:
    """函数内 CFG 前向数据流，解 `bl sscanf` 的 x1（格式串）。

    常量格：None（未知）| ('ptr', sec, off, string, load_addr, via)
            | ('page', vaddr) | ('imm', v) | ('stack', off)
    连接（join）：相同才保留，否则 None（保守）。
    """

    CALLER_SAVED = ['x%d' % i for i in range(19)]

    def __init__(self, k):
        self.k = k
        self.md = k.md

    # -- 单条指令的转移 -----------------------------------------------------
    def _ptr_from_reloc(self, addr):
        r = self.k.rel_text.get(addr)
        if not r or r[0] not in MOVW_LO:
            return None
        sec, off = self.k.target_of(r)
        if sec is None or off is None:
            return None
        s = self.k.read_string_at(sec, off)
        if s is None:
            return None
        return ('ptr', sec, off, s, addr, ())

    def transfer(self, st, ins):
        """就地更新 st（dict reg->value）。返回 st。"""
        md = self.md
        m = ins.mnemonic
        ops = ins.operands
        # 先算"本指令定义的值"（若可判定）
        newv = None
        tgt = None
        if m == 'adrp' and len(ops) == 2 and ops[0].type == ARM64_OP_REG \
                and ops[1].type == ARM64_OP_IMM:
            tgt = _norm(md, ops[0].reg)
            newv = ('page', ops[1].imm)
        elif m == 'adr' and len(ops) == 2 and ops[0].type == ARM64_OP_REG \
                and ops[1].type == ARM64_OP_IMM:
            tgt = _norm(md, ops[0].reg)
            newv = ('imm', ops[1].imm)
        elif m == 'mov' and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
            tgt = _norm(md, ops[0].reg)
            if ops[1].type == ARM64_OP_IMM:
                newv = ('imm', ops[1].imm)
            elif ops[1].type == ARM64_OP_REG:
                src = _norm(md, ops[1].reg)
                if src == 'sp':
                    newv = ('stack', 0)
                else:
                    sv = st.get(src)
                    if sv and sv[0] == 'ptr':
                        via = sv[5] + ((src, ins.address),)
                        newv = ('ptr', sv[1], sv[2], sv[3], sv[4], via)
                    elif sv:
                        newv = sv
        elif m in ('movz', 'movk', 'movn') and ops and ops[0].type == ARM64_OP_REG:
            tgt = _norm(md, ops[0].reg)
            p = self._ptr_from_reloc(ins.address)
            if p is not None:
                # movz/movk 组里任一条都带同符号同 addend 的重定位 ⇒ 直接用解析值
                # 若目标寄存器此前已由同组指令建立，把 via 串起来
                newv = p
            elif m == 'movn' and len(ops) >= 2 and ops[1].type == ARM64_OP_IMM:
                newv = ('imm', ~ops[1].imm)
            else:
                newv = None
        elif m in ('add', 'sub') and len(ops) == 3 and ops[0].type == ARM64_OP_REG \
                and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
            tgt = _norm(md, ops[0].reg)
            src = _norm(md, ops[1].reg)
            imm = ops[2].imm if m == 'add' else -ops[2].imm
            sv = st.get(src)
            if src == 'sp':
                newv = ('stack', imm)
            elif sv and sv[0] == 'page':
                va = sv[1] + imm
                s = self.k.cstr_at(va) if hasattr(self.k, 'cstr_at') else None
                if s is None:
                    s = self._cstr_va(va)
                newv = ('ptr', None, va, s, ins.address, ()) if s is not None else ('imm', va)
            elif sv and sv[0] == 'ptr' and sv[1] and sv[2] is not None:
                sec, off, s = sv[1], sv[2] + imm, None
                s = self.k.read_string_at(sec, off)
                if s is not None:
                    newv = ('ptr', sec, off, s, ins.address, ())
                else:
                    newv = None
            else:
                newv = None
        # 写后失效：先清掉本指令写到的寄存器，再落 newv
        for w in written_regs(md, ins):
            st.pop(w, None)
        if tgt is not None and newv is not None:
            st[tgt] = newv
        # 调用约定：bl/blr 使 caller-saved 失效（callee-saved 保留 —— 这就是 A2 的关键）
        if m in ('bl', 'blr'):
            for r in self.CALLER_SAVED:
                st.pop(r, None)
            st.pop('x30', None)
        return st

    def _cstr_va(self, va):
        for s in self.k.e.iter_sections():
            a = s['sh_addr']
            if a and a <= va < a + s['sh_size']:
                off = va - a
                data = s.data()
                end = data.find(b'\x00', off)
                if end < 0 or end - off > 400:
                    return None
                try:
                    return data[off:end].decode('latin-1')
                except Exception:
                    return None
        return None

    # -- CFG 数据流（按指令地址的 worklist 不动点） ---------------------------
    def run(self, base, size):
        """返回 (insns, call_sites)。

        call_sites: [{addr, fn, x1}]，x1 = 该 `bl` 执行前的 x1 常量格。
        """
        md = self.md
        insns = list(md.disasm(self.k.text[base:base + size], base))
        idx_of = {i.address: n for n, i in enumerate(insns)}
        # 外部尾调用（`b` 带 JUMP26 重定位，目标地址 == 自身）⇒ 不建 CFG 边
        tail_ext = {i.address for i in insns
                    if (self.k.rel_text.get(i.address) or (None,))[0] == R_JUMP26}

        def succ(i):
            nxt = i.address + i.size
            if i.address in tail_ext:
                return []
            m = i.mnemonic
            if m in ('ret', 'br'):
                return []
            if m == 'blr':
                return [nxt] if nxt in idx_of else []
            tgts, term = br_targets(md, i)
            out = [t for t in tgts if t in idx_of]
            if not term and nxt in idx_of:
                out.append(nxt)
            return out

        IN = {base: {}}
        work = [base]
        guard = 0
        while work:
            guard += 1
            if guard > 200000:                       # 安全阀
                break
            a = work.pop()
            st = dict(IN[a])
            self.transfer(st, insns[idx_of[a]])
            for s in succ(insns[idx_of[a]]):
                cur = IN.get(s)
                if cur is None:
                    IN[s] = dict(st)
                    work.append(s)
                    continue
                changed = False
                for r, v in list(cur.items()):
                    if st.get(r) != v:
                        cur.pop(r, None)
                        changed = True
                if changed:
                    work.append(s)

        sites = []
        for n, i in enumerate(insns):
            if i.mnemonic not in ('bl', 'blr'):
                continue
            r = self.k.rel_text.get(i.address)
            fn = r[2] if r and r[0] == R_CALL26 else None
            if not fn:
                continue
            sites.append({'addr': i.address, 'fn': fn,
                          'x1': (IN.get(i.address) or {}).get('x1')})
        sites.sort(key=lambda x: x['addr'])
        return insns, sites


# ---------------------------------------------------------------------------
# A1：偏置值域门
# ---------------------------------------------------------------------------
def gate_scan(insns, start_idx, slot_off, md, window=48):
    """从解析调用之后找"由槽位派生的值"上的 cmp/条件分支。

    派生规则：`ldr wT,[sp,#slot]` 建立 T；`add/sub wT2,wT,#imm` 传递（带偏置）。
    返回 (record | None)；record 含 bias、cmp_imm、pred、branch、accepted。
    """
    derived = {}          # reg -> bias
    consts = {}
    ldr_reg = None
    for j in range(start_idx + 1, min(len(insns), start_idx + 1 + window)):
        ins = insns[j]
        m = ins.mnemonic
        ops = ins.operands
        if m in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldur', 'ldurb', 'ldurh', 'ldursw') \
                and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
            base = _norm(md, ops[1].mem.base) if ops[1].mem.base else None
            disp = ops[1].mem.disp
            if base == 'sp' and disp == slot_off and ops[0].type == ARM64_OP_REG:
                derived[_norm(md, ops[0].reg)] = 0
                ldr_reg = _norm(md, ops[0].reg)
                continue
            if ops[0].type == ARM64_OP_REG:
                derived.pop(_norm(md, ops[0].reg), None)
                consts.pop(_norm(md, ops[0].reg), None)
            continue
        if m in ('add', 'sub') and len(ops) == 3 and ops[0].type == ARM64_OP_REG \
                and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
            src = _norm(md, ops[1].reg)
            if src in derived:
                b = derived[src] + (ops[2].imm if m == 'add' else -ops[2].imm)
                derived[_norm(md, ops[0].reg)] = b
            else:
                derived.pop(_norm(md, ops[0].reg), None)
            continue
        if m == 'mov' and len(ops) == 2 and ops[0].type == ARM64_OP_REG \
                and ops[1].type == ARM64_OP_REG:
            src = _norm(md, ops[1].reg)
            if src in derived:
                derived[_norm(md, ops[0].reg)] = derived[src]
            else:
                derived.pop(_norm(md, ops[0].reg), None)
            continue
        if m == 'mov' and len(ops) == 2 and ops[0].type == ARM64_OP_REG \
                and ops[1].type == ARM64_OP_IMM:
            consts[_norm(md, ops[0].reg)] = ops[1].imm
            continue
        if m == 'cmp' and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
            rn = _norm(md, ops[0].reg)
            imm = ops[1].imm if ops[1].type == ARM64_OP_IMM else None
            if imm is None and ops[1].type == ARM64_OP_REG:
                imm = consts.get(_norm(md, ops[1].reg))
            if rn not in derived or imm is None:
                continue
            br = None
            for k in range(j + 1, min(len(insns), j + 9)):
                if insns[k].mnemonic in COND:
                    br = insns[k]
                    break
                if insns[k].mnemonic in ('bl', 'blr', 'ret'):
                    break
            rec = {'reg': rn, 'ldr_reg': ldr_reg, 'bias': derived[rn],
                   'cmp_addr': ins.address,
                   'cmp_imm': imm, 'branch': br.mnemonic if br else None,
                   'branch_addr': br.address if br else None,
                   'branch_target': (br.operands[0].imm
                                     if br and br.operands
                                     and br.operands[0].type == ARM64_OP_IMM else None)}
            rec['accepted_biased'] = _interval(_pred(br.mnemonic) if br else None, imm)
            return rec
        for w in written_regs(md, ins):
            derived.pop(w, None)
            consts.pop(w, None)
        if m in ('bl', 'blr'):
            derived.clear() if False else None
    return None


COND = {
    'b.eq': 'eq', 'b.ne': 'ne', 'b.cs': 'cs', 'b.hs': 'cs', 'b.cc': 'cc',
    'b.lo': 'cc', 'b.mi': 'mi', 'b.pl': 'pl', 'b.vs': 'vs', 'b.vc': 'vc',
    'b.hi': 'hi', 'b.ls': 'ls', 'b.ge': 'ge', 'b.lt': 'lt', 'b.gt': 'gt',
    'b.le': 'le',
}


def _pred(mn):
    return COND.get(mn)


def _interval(pred, imm):
    if pred is None or imm is None:
        return None
    if pred == 'cc':
        return [0, imm - 1]
    if pred == 'cs':
        return [imm, None]
    if pred == 'hi':
        return [imm + 1, None]
    if pred == 'ls':
        return [0, imm]
    if pred == 'eq':
        return [imm, imm]
    if pred == 'ne':
        return [imm, imm]
    if pred == 'gt':
        return [imm + 1, None]
    if pred == 'ge':
        return [imm, None]
    if pred == 'lt':
        return [None, imm - 1]
    if pred == 'le':
        return [None, imm]
    return None


def unbias(acc, bias):
    """把"比较值 u = v + bias 的接受区间"换算成 v 的区间（按 32 位补码）。"""
    if acc is None:
        return None
    lo, hi = acc
    if lo is not None:
        lo -= bias
    if hi is not None:
        hi -= bias
    return [lo, hi]


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def fmt_chain(v):
    """把 x1 的常量格渲染成可读证据链。"""
    if not v:
        return ''
    if v[0] != 'ptr':
        return ''
    sec, off, s, load, via = v[1], v[2], v[3], v[4], v[5]
    parts = []
    if via:
        parts.append(' <- '.join('%s@%#x' % (r, a) for r, a in via))
    loc = ('%s+%#x' % (sec, off)) if sec else ('va %#x' % off)
    parts.append('load@%#x(%s)' % (load, loc))
    parts.append('"%s"' % sanitize(s, 80))
    return ' '.join(parts)


def analyze_all(k):
    """对全部 98 个 handler 做同一套跨 bl 格式串解析，用于"全量复算"。

    返回 {'handlers': n, 'sites': [...], 'unresolved': n, 'unbounded': n}
    """
    sites = []
    for c in k.cmds:
        name = c['handler']
        try:
            base, size, _ = k.disasm(name)
        except KeyError:
            continue
        res = FmtResolver(k)
        _insns, all_sites = res.run(base, size)
        for s in all_sites:
            if s['fn'] not in ('sscanf', 'vsscanf'):
                continue
            v = s['x1']
            fmt = v[3] if v and v[0] == 'ptr' else None
            convs, level, need = classify_sscanf(fmt)
            sites.append({'cmd': c['name'], 'handler': name, 'call': s['addr'],
                          'fmt': fmt, 'convs': convs, 'level': level,
                          'need': need,
                          'off': v[2] if v and v[0] == 'ptr' else None})
    return {'handlers': len({s['handler'] for s in sites}),
            'sites': sites,
            'unresolved': sum(1 for s in sites if s['level'] == 'unresolved'),
            'unbounded': sum(1 for s in sites if s['level'] == 'unbounded')}


def analyze_a1(k):
    md = k.md
    base, size, insns = k.disasm(A1_HANDLER)
    # 找 kstrtoint 调用及其槽位
    idx = None
    for n, ins in enumerate(insns):
        r = k.rel_text.get(ins.address)
        if r and r[0] == R_CALL26 and r[2] in ('kstrtoint', 'kstrtouint'):
            idx = n
            break
    if idx is None:
        return {'handler': A1_HANDLER, 'verdict': '未决', 'reason': 'no kstrtoint'}
    # 槽位：x2 = sp + imm
    slot = None
    for j in range(idx - 1, max(-1, idx - 12), -1):
        ins = insns[j]
        if ins.mnemonic == 'add' and len(ins.operands) == 3 \
                and _norm(md, ins.operands[0].reg) == 'x2' \
                and _norm(md, ins.operands[1].reg) == 'sp' \
                and ins.operands[2].type == ARM64_OP_IMM:
            slot = ins.operands[2].imm
            break
    g = gate_scan(insns, idx, slot, md) if slot is not None else None
    ret_check = _ret_check(insns, idx, md)
    row = {
        'handler': A1_HANDLER, 'entry': base, 'call': insns[idx].address,
        'fn': k.rel_text[insns[idx].address][2], 'slot': slot,
        'gate': g, 'ret_gate': ret_check,
    }
    if g is None:
        row['verdict'] = '未决'
        row['reason'] = 'no derived-register gate found'
        return row
    acc = unbias(g['accepted_biased'], g['bias'])
    row['accepted'] = acc
    # 成功臂判定：b.ls -> 0x3fc14 是成功臂（trace SETMAXTXPOWER 后继续）
    row['verdict'] = '有界' if acc and acc[0] is not None and acc[1] is not None else '未决'
    # 槽位初值是否预置（决定"未检查返回值"的后果）
    row['slot_preinit'] = _slot_preinit(insns, slot, insns[idx].address, md)
    return row


def _ret_check(insns, idx, md):
    for j in range(idx + 1, min(len(insns), idx + 8)):
        ins = insns[j]
        if ins.mnemonic in ('cbnz', 'cbz') and ins.operands[0].type == ARM64_OP_REG \
                and _norm(md, ins.operands[0].reg) == 'x0':
            return {'form': ins.mnemonic, 'addr': ins.address}
        if ins.mnemonic in ('tbz', 'tbnz') and ins.operands[0].type == ARM64_OP_REG \
                and _norm(md, ins.operands[0].reg) == 'x0':
            return {'form': ins.mnemonic, 'bit': ins.operands[1].imm,
                    'addr': ins.address}
        if ins.mnemonic == 'cmp' and ins.operands[0].type == ARM64_OP_REG \
                and _norm(md, ins.operands[0].reg) == 'x0':
            return {'form': 'cmp', 'addr': ins.address}
        if ins.mnemonic in ('bl', 'blr'):
            break
    return None


def _slot_preinit(insns, slot, before, md):
    """slot 在解析调用之前是否被写过（含任意宽度）。"""
    x29_base = None
    for ins in insns[:8]:
        if ins.mnemonic == 'add' and len(ins.operands) == 3 \
                and _norm(md, ins.operands[0].reg) == 'x29' \
                and _norm(md, ins.operands[1].reg) == 'sp' \
                and ins.operands[2].type == ARM64_OP_IMM:
            x29_base = ins.operands[2].imm
    for ins in insns:
        if ins.address >= before:
            break
        if not ins.mnemonic.startswith('st'):
            continue
        for op in ins.operands[1:]:
            if op.type != ARM64_OP_MEM:
                continue
            b = _norm(md, op.mem.base) if op.mem.base else None
            d = op.mem.disp
            if b == 'sp':
                eff = d
            elif b == 'x29' and x29_base is not None:
                eff = x29_base + d
            else:
                continue
            if eff == slot:
                return ins.address
    return None


def analyze_a2(k):
    out = []
    for name in A2_HANDLERS:
        base, size, _ = k.disasm(name)
        res = FmtResolver(k)
        insns, sites = res.run(base, size)
        recs = []
        for s in sites:
            if s['fn'] not in ('sscanf', 'vsscanf'):
                continue
            v = s['x1']
            fmt = v[3] if v and v[0] == 'ptr' else None
            convs, level, need = classify_sscanf(fmt)
            recs.append({'call': s['addr'], 'fn': s['fn'], 'fmt': fmt,
                         'load': v[4] if v and v[0] == 'ptr' else None,
                         'sec': v[1] if v and v[0] == 'ptr' else None,
                         'off': v[2] if v and v[0] == 'ptr' else None,
                         'via': v[5] if v and v[0] == 'ptr' else (),
                         'convs': convs, 'level': level, 'need': need,
                         'chain': fmt_chain(v)})
        out.append({'handler': name, 'entry': base, 'size': size,
                    'sscanf': recs})
    return out


def render_a1(r):
    print('== A1  %s @%#x  (%s@%#x, slot=sp%+#x)' %
          (r['handler'], r['entry'], r.get('fn'), r['call'], r.get('slot') or 0))
    g = r.get('gate')
    if g:
        print('   gate: ldr %s,[sp%+#x] -> add %s,%s,#%+#x ; cmp %s,#%#x @%#x ; %s @%s -> %#x'
              % (g.get('ldr_reg') or '?', r.get('slot') or 0,
                 g['reg'], g.get('ldr_reg') or '?', g['bias'],
                 g['reg'], g['cmp_imm'], g['cmp_addr'],
                 g['branch'], ('%#x' % g['branch_addr']) if g['branch_addr'] else '-',
                 g['branch_target'] or 0))
        print('   accepted(compare value) = %s ; accepted(original) = %s'
              % (g['accepted_biased'], r.get('accepted')))
    else:
        print('   gate: NOT FOUND')
    print('   ret-gate: %s ; slot pre-initialised: %s'
          % (r.get('ret_gate'), r.get('slot_preinit') or 'NO (uninitialised)'))
    print('   verdict: %s' % r['verdict'])


def render_a2(rows):
    for h in rows:
        print('== A2  %s @%#x size=%d' % (h['handler'], h['entry'], h['size']))
        if not h['sscanf']:
            print('   (no sscanf)')
        for s in h['sscanf']:
            print('   sscanf@%#x  fmt=%r  level=%s need=%s' %
                  (s['call'], sanitize(s['fmt']), s['level'], s['need']))
            if s['chain']:
                print('            chain: ' + s['chain'])


def dump_handler(k, name, path):
    """带重定位注释的反汇编转储（替代 wlan_handler_scan.py --dump-dir 的崩溃路径）。"""
    base, size, insns = k.disasm(name)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('# %s @%#x size=%d\n' % (name, base, size))
        for ins in insns:
            r = k.rel_text.get(ins.address)
            ann = ''
            if r and r[0] in (R_CALL26, R_JUMP26):
                ann = '   ; %s' % r[2]
            elif r and r[0] in MOVW_LO:
                sec, off = k.target_of(r)
                sv = k.read_string_at(sec, off) if (sec and off is not None) else None
                if sec is not None and off is not None:
                    ann = '   ; abs %s+%#x%s' % (sec, off, ('  %r' % sv) if sv else '')
                else:
                    ann = '   ; abs %s' % (sec,)
            fh.write('%06x  %-10s %s%s\n' % (ins.address, ins.mnemonic, ins.op_str, ann))
    return path


CSV_HEADER = ['group', 'item', 'object', 'addr', 'evidence', 'verdict', 'level', 'note']


def a_rows(k, a1, a2):
    rows = []
    g = a1.get('gate') or {}
    acc = a1.get('accepted')
    ev = ('kstrtoint@%#x -> [sp%+#x]; ldr %s; add %s,%s,#%#x; cmp %s,#%#x @%#x; %s -> %#x' %
          (a1['call'], a1.get('slot') or 0, g.get('ldr_reg') or '?',
           g.get('reg'), g.get('ldr_reg') or '?', g.get('bias'),
           g.get('reg'), g.get('cmp_imm') or 0, g.get('cmp_addr') or 0,
           g.get('branch') or '?', g.get('branch_target') or 0))
    note = 'ret gate=%s; slot preinit=%s' % (a1.get('ret_gate'),
                                             a1.get('slot_preinit') or 'NO')
    rows.append(['A', 'A1 MAXTXPOWER (#74)', a1['handler'], '%#x' % a1['entry'],
                 ev, a1['verdict'], '指令级', note])
    for h in a2:
        for s in h['sscanf']:
            rows.append(['A', 'A2 %s' % h['handler'], h['handler'],
                         '%#x' % s['call'],
                         'sscanf x1 <- %s' % s['chain'],
                         '有界' if s['level'] == 'bounded' else
                         ('未决' if s['level'] == 'unresolved' else s['level']),
                         '指令级' if s['level'] != 'unresolved' else '未决',
                         'fmt=%s need=%s' % (sanitize(s['fmt'], 40), s['need'])])
    return rows


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------
def selftest(k, a1, a2):
    fails, ok = [], 0

    def chk(c, m):
        nonlocal ok
        if c:
            ok += 1
        else:
            fails.append(m)

    chk(a1['slot'] == 0x14, 'A1 槽位应为 sp+0x14，实得 %s' % hex(a1['slot'] or 0))
    g = a1.get('gate') or {}
    chk(g.get('cmp_imm') == 0xc8, 'A1 门限应为 #0xc8，实得 %s' % hex(g.get('cmp_imm') or 0))
    chk(g.get('bias') == 0x64, 'A1 偏置应为 +0x64，实得 %s' % hex(g.get('bias') or 0))
    chk(a1.get('accepted') == [-0x64, 0x64],
        'A1 换算区间应为 [-0x64,0x64]，实得 %s' % (a1.get('accepted'),))
    chk(a1.get('ret_gate') is None, 'A1 不应有返回值门（反例 H2），实得 %s' % a1.get('ret_gate'))
    chk(a1.get('slot_preinit') is None, 'A1 槽位不应预置，实得 %s' % a1.get('slot_preinit'))
    n = sum(len(h['sscanf']) for h in a2)
    chk(n == 17, 'A2 四个 handler 的 sscanf 总数应为 17，实得 %d' % n)
    chk(all(s['fmt'] is not None for h in a2 for s in h['sscanf']),
        'A2 仍有未解析格式串')
    chk(not any(s['level'] == 'unbounded' for h in a2 for s in h['sscanf']),
        'A2 出现无宽度 %s/%[ 转换')
    print('selftest: %d ok, %d fail' % (ok, len(fails)))
    for m in fails:
        print('  FAIL: ' + m)
    return 0 if not fails else 1


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--ko', default=KO_DEFAULT)
    ap.add_argument('--detail', action='store_true')
    ap.add_argument('--csv', default=None)
    ap.add_argument('--append', action='store_true')
    ap.add_argument('--dump', default=None, help='把 5 个 A 组 handler 的反汇编转储到该目录')
    ap.add_argument('--all', action='store_true', help='对全部 98 个 handler 复算格式串')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass
    k = Ko(a.ko)
    a1 = analyze_a1(k)
    a2 = analyze_a2(k)
    if a.selftest:
        return selftest(k, a1, a2)
    render_a1(a1)
    print()
    render_a2(a2)
    if a.all:
        al = analyze_all(k)
        print('\n== 全量复算：%d 个 handler / %d 处 sscanf / unresolved=%d / unbounded=%d'
              % (al['handlers'], len(al['sites']), al['unresolved'], al['unbounded']))
        from collections import Counter
        for f, n in Counter(s['fmt'] for s in al['sites']).most_common():
            print('   fmt=%-10r  %d 处' % (f, n))
        for s in al['sites']:
            if s['level'] != 'bounded':
                print('   !! %-34s sscanf@%#x fmt=%r level=%s'
                      % (s['handler'], s['call'], s['fmt'], s['level']))
    if a.dump:
        os.makedirs(a.dump, exist_ok=True)
        for n in [A1_HANDLER] + A2_HANDLERS:
            p = dump_handler(k, n, os.path.join(a.dump, n + '.txt'))
            print('dumped %s' % p)
    if a.csv:
        rows = a_rows(k, a1, a2)
        new = not (a.append and os.path.exists(a.csv))
        with open(a.csv, 'a' if new is False else 'w', encoding='utf-8', newline='') as fh:
            if new:
                fh.write(','.join(CSV_HEADER) + '\n')
            for r in rows:
                fh.write(','.join(_esc(x) for x in r) + '\n')
        print('\nwrote %d rows -> %s (%s)' % (len(rows), a.csv,
                                              'append' if not new else 'new'))
    return 0


def _esc(v):
    v = '' if v is None else str(v)
    if any(c in v for c in ',"\n\r'):
        return '"' + v.replace('"', '""') + '"'
    return v


if __name__ == '__main__':
    sys.exit(main())
