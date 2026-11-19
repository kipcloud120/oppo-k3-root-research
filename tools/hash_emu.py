#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hash_emu.py — 逐指令模拟本机内核 futex_wake 内联哈希块（ground truth）。

块范围: 0xffffff800815de00 .. 0xffffff800815ded8 (and x9, x10, x9 = bucket)
输入寄存器约定（get_futex_key 产出，key 在栈上）:
  [sp+0x10]=mm_lo [sp+0x14]=mm_hi [sp+0x18]=page_lo [sp+0x1c]=page_hi [sp+0x20]=offset
模拟结束时 x9 = bucket = hash & (futex_hashsize-1)
"""
import sys, struct
sys.path.insert(0, 'tools')
from kfn import Kernel
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import *

k = Kernel()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

START = 0xffffff800815de00
END   = 0xffffff800815ded8 + 4   # 含 and x9, x10, x9
CODE = k.read(START, END - START)
INSNS = list(md.disasm(CODE, START))

M32 = 0xFFFFFFFF

class Emu:
    def __init__(self, mm, va, hashsize=2048):
        self.r = {}
        self.mem = {}          # 32-bit words keyed by address
        # key 在栈上: sp 基准
        self.SP = 0x80000000
        self.r['sp'] = self.SP
        page = va & ~0xfff
        off = va & 0xfff
        self.mem[self.SP+0x10] = mm & M32
        self.mem[self.SP+0x14] = (mm >> 32) & M32
        self.mem[self.SP+0x18] = page & M32
        self.mem[self.SP+0x1c] = (page >> 32) & M32
        self.mem[self.SP+0x20] = off
        self.hashsize = hashsize
        # futex_hashsize @ 0xffffff8009e0e160, futex_queues @ 0xffffff8009e0e150
        self.mem[0xffffff8009e0e160] = hashsize
        self.mem[0xffffff8009e0e150] = 0xdead0000   # 指针值随意
        self.mem[0xffffff8009e0e154] = 0xffffff80

    def rname(self, rid):
        n = md.reg_name(rid)
        if n == 'xzr' or n == 'wzr':
            return 'wzr'
        if n.startswith('x'):
            return 'w' + n[1:]
        return n

    def rd(self, rid):
        n = self.rname(rid)
        if n == 'wzr':
            return 0
        return self.r.get(n, 0) & M32

    def wr(self, rid, val):
        n = self.rname(rid)
        if n == 'wzr':
            return
        self.r[n] = val & M32

    def getmem(self, addr):
        return self.mem.get(addr & ~3, 0)

    def run(self):
        for ins in INSNS:
            m = ins.mnemonic; ops = ins.operands
            if m == 'adrp':
                self.wr(ops[0].reg, ops[1].imm)
            elif m in ('ldr', 'ldur'):
                mo = ops[1].mem
                base = self.rd(mo.base)
                idx = self.rd(mo.index) if mo.index else 0
                addr = base + idx + mo.disp
                v = self.getmem(addr)
                self.wr(ops[0].reg, v)
            elif m == 'ldp':
                base = self.rd(ops[2].mem.base)
                off = ops[2].mem.disp
                self.wr(ops[0].reg, self.getmem(base + off))
                self.wr(ops[1].reg, self.getmem(base + off + 4))
            elif m == 'stp':
                base = self.rd(ops[2].mem.base)
                off = ops[2].mem.disp
                self.mem[(base+off) & ~3] = self.rd(ops[0].reg)
                self.mem[(base+off+4) & ~3] = self.rd(ops[1].reg)
            elif m == 'mov' or m == 'movz':
                self.wr(ops[0].reg, ops[1].imm if ops[1].type == ARM64_OP_IMM else self.rd(ops[1].reg))
            elif m == 'movk':
                sh = ops[1].shift.value if ops[1].shift.type else 0
                cur = self.rd(ops[0].reg)
                self.wr(ops[0].reg, (cur & ~(0xFFFF << sh)) | (ops[1].imm << sh))
            elif m == 'add':
                v = self.rd(ops[1].reg)
                for o in ops[2:]:
                    if o.type == ARM64_OP_IMM:
                        v += o.imm
                    elif o.type == ARM64_OP_REG:
                        v += self.rd(o.reg)
                    elif o.type == ARM64_OP_REG_MRS:
                        pass
                    elif o.shift.type == ARM64_SFT_LSL:
                        v += (self.rd(o.reg) << o.shift.value)
                self.wr(ops[0].reg, v)
            elif m == 'sub':
                v = self.rd(ops[1].reg)
                for o in ops[2:]:
                    if o.type == ARM64_OP_IMM:
                        v -= o.imm
                    elif o.type == ARM64_OP_REG:
                        if o.shift.type == ARM64_SFT_ROR:
                            r = o.shift.value
                            x = self.rd(o.reg)
                            v -= ((x >> r) | (x << (32 - r))) & M32
                        else:
                            v -= self.rd(o.reg)
                self.wr(ops[0].reg, v)
            elif m == 'eor':
                a = self.rd(ops[1].reg)
                o = ops[2]
                if o.shift.type == ARM64_SFT_ROR:
                    r = o.shift.value
                    x = self.rd(o.reg)
                    b = ((x >> r) | (x << (32 - r))) & M32
                else:
                    b = self.rd(o.reg)
                self.wr(ops[0].reg, a ^ b)
            elif m == 'ror':
                x = self.rd(ops[1].reg); r = ops[2].imm
                self.wr(ops[0].reg, ((x >> r) | (x << (32 - r))) & M32)
            elif m == 'and':
                a = self.rd(ops[1].reg)
                o = ops[2]
                b = o.imm if o.type == ARM64_OP_IMM else self.rd(o.reg)
                self.wr(ops[0].reg, a & b)
            elif m == 'lsl':
                self.wr(ops[0].reg, self.rd(ops[1].reg) << ops[2].imm)
            elif m == 'lsr':
                self.wr(ops[0].reg, self.rd(ops[1].reg) >> ops[2].imm)
            elif m == 'cbz' or m == 'cbnz':
                pass  # 块内无分支（除结尾），忽略
            elif m == 'bl' or m == 'b' or m == 'ret':
                raise RuntimeError('unexpected control flow at %x: %s' % (ins.address, ins.mnemonic))
            else:
                raise RuntimeError('unhandled mnemonic %s @ %x' % (m, ins.address))
        return self.r.get('w9', 0)   # x9 = bucket

def bucket_of(mm, va, hashsize=2048):
    return Emu(mm, va, hashsize).run()

if __name__ == '__main__':
    import random
    random.seed(1)
    # 与两个候选模型对照
    sys.path.insert(0, 'tools')
    import numpy as np
    from g2_pair_search2 import hash_va as h_no16
    from g2_pair_search import hash_va as h_with16

    for t in range(5):
        mm = random.getrandbits(64)
        va = (random.getrandbits(64) & ~0xfff) | random.choice([0x80, 0x0, 0x123, 0xffc])
        true_b = bucket_of(mm, va)
        m16 = int(h_with16(np.uint64(va), np.uint64(mm))) & 2047
        n16 = int(h_no16(np.uint64(va), np.uint64(mm))) & 2047
        print('mm=%016x va=%016x  emu=%d  with16=%d  no16=%d' % (mm, va, true_b, m16, n16))
