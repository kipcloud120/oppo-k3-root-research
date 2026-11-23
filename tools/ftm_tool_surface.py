#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ftm_tool_surface.py — C 组：`myftm` / `ftmdaemon` 的 ioctl 面离线判定。

要回答的唯一问题：**FTM 用户态工具到底走哪个内核入口？**
  (i)  nl80211 netlink（libnl / GENL / sendmsg）
  (ii) 字符设备（/dev/xxx + ioctl）
  (iii) WEXT 私有 ioctl（SIOCDEVPRIVATE 0x8xxx / 本驱动 0x89f1 / 0x89fd）

判据（脚本内固化，全部为可复核的静态事实）：
  * `DT_NEEDED` 与 `.dynsym` 未定义符号（UND）中是否有 `ioctl` / `socket` / `sendmsg` /
    `sendto` / `recvmsg` / `libnl` / `libdiag`；
  * `bl ioctl@plt` 的调用点数，以及每个调用点的 x0(fd)/x1(request) 静态可解值；
  * `.text` 中由 movz/movk 组装的 32 位常量、`.rodata/.data` 中的 32 位字面量，
    是否出现 `0x89fd` / `0x89f1`；
  * 字符串面是否出现 `/dev/`、`nl80211`、`genl` 等通道特征。

不做：动态执行、不连设备、不联网。

用法：
  python tools/ftm_tool_surface.py
  python tools/ftm_tool_surface.py --bin .build/vendor_bins/vendor/bin/myftm --bin ...
  python tools/ftm_tool_surface.py --csv artifacts_adb/r1_wlan_reach/residual_audit.csv --append
  python tools/ftm_tool_surface.py --selftest
"""
import argparse
import os
import re
import struct
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

FTM_BINS = [
    '.build/vendor_bins/vendor/bin/myftm',
    '.build/vendor_bins/vendor/bin/ftmdaemon',
    '.build/vendor_bins/vendor/bin/ftmtest',
    '.build/odm_bin/iwpriv',
]

NETLINK_SYMS = {'socket', 'sendmsg', 'sendto', 'recvmsg', 'recvfrom', 'bind',
                'nl_socket_alloc', 'nl_connect', 'nl_send_auto', 'nl_send_sync',
                'nl_send_auto_complete', 'nl_recvmsgs_default', 'nl_socket_add_membership',
                'genl_connect', 'genl_send_simple', 'nl_socket_get_fd'}
CHARDEV_SYMS = {'ioctl', 'open', 'openat', '__open_2', 'read', 'write', 'close'}
WEXT_MAGIC = {0x89f1: 'DRIVER_CMD (hdd_driver_command 私有 WEXT)',
              0x89fd: 'FTM testmode (hdd_ioctl 私有 cmd)'}
# ioctl 码形态：_IOC 编码 (dir<<30|size<<16|type<<8|nr) 或 <0x9000 的裸号
IOC_RE = re.compile(r'^(0x89f[0-9a-f]{2}|0x8[0-9a-f]{3}|0x[0-9a-f]{4})$')


class Bin:
    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.f = open(path, 'rb')
        self.elf = ELFFile(self.f)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True
        self.secs = [{'name': s.name, 'addr': s['sh_addr'], 'size': s['sh_size'],
                      'off': s['sh_offset'], 'sec': s} for s in self.elf.iter_sections()]
        self._build_plt()

    def sec_of(self, addr):
        for s in self.secs:
            if s['addr'] and s['addr'] <= addr < s['addr'] + s['size']:
                return s
        return None

    def read(self, addr, n):
        s = self.sec_of(addr)
        if not s:
            return b''
        self.f.seek(s['off'] + (addr - s['addr']))
        return self.f.read(n)

    def cstr(self, addr, maxlen=160):
        b = self.read(addr, maxlen)
        z = b.find(b'\x00')
        if z >= 0:
            b = b[:z]
        try:
            return b.decode('utf-8', 'replace')
        except Exception:
            return repr(b)

    def _build_plt(self):
        dynsym = self.elf.get_section_by_name('.dynsym')
        self.und = [s.name for s in dynsym.iter_symbols()
                    if s['st_shndx'] == 'SHN_UNDEF' and s.name]
        order = []
        for s in self.elf.iter_sections():
            if isinstance(s, RelocationSection) and s.name == '.rela.plt':
                names = [dynsym.get_symbol(r['r_info_sym']).name
                         for r in s.iter_relocations()]
                order = names
                break
        plt = self.elf.get_section_by_name('.plt') or self.elf.get_section_by_name('.plt.sec')
        self.plt = {}
        if plt is not None and order:
            base = plt['sh_addr'] + plt['sh_size'] - 0x10 * len(order)
            for i, n in enumerate(order):
                self.plt[base + 0x10 * i] = n
        self.plt_order = order

    def needed(self):
        out = []
        d = self.elf.get_section_by_name('.dynamic')
        if d:
            for t in d.iter_tags():
                if t.entry.d_tag == 'DT_NEEDED':
                    out.append(t.needed)
        return out

    def text(self):
        return self.elf.get_section_by_name('.text')

    def disasm_text(self):
        t = self.text()
        return list(self.md.disasm(self.read(t['sh_addr'], t['sh_size']), t['sh_addr']))


def _shift_of(op_str):
    """capstone 把 movk/movz 的 `lsl #N` 折进编码，不放进 operands；从文本里取。"""
    m = re.search(r'lsl #(\d+)', op_str or '')
    return int(m.group(1)) if m else 0


def mov_const_track(insns):
    """线性扫一遍 .text，返回 [(addr, reg, value, how)]（每次写入即记录）。

    注意：这是**线性**扫描，不建模控制流，同一寄存器在循环里的多次写入都会各自
    记一条；因此结果只作"候选常量清单"，任何结论都必须回到调用点窗口（见
    `ioctl_sites`）复核。
    """
    out = []
    cur = {}          # reg -> (value, addr_first, parts)
    for i in insns:
        m = i.mnemonic
        if m in ('movz', 'movk', 'movn') and i.operands \
                and i.operands[0].type == ARM64_OP_REG:
            rd = i.reg_name(i.operands[0].reg)
            try:
                imm = i.operands[1].imm
            except Exception:
                continue
            sh = _shift_of(i.op_str)
            if m == 'movn':
                v = ~imm & 0xffffffff
                cur[rd] = (v, i.address, 'movn')
                out.append((i.address, rd, v, 'movn'))
                continue
            if m == 'movz':
                v = (imm & 0xffff) << sh
                cur[rd] = (v, i.address, 'movz')
                out.append((i.address, rd, v, 'movz'))
            else:
                v0, a0, how = cur.get(rd, (0, i.address, 'movz?'))
                v = (v0 | ((imm & 0xffff) << sh)) & 0xffffffff
                cur[rd] = (v, a0, how + '+movk')
                out.append((i.address, rd, v, how + '+movk'))
        elif m == 'mov' and len(i.operands) == 2 \
                and i.operands[0].type == ARM64_OP_REG \
                and i.operands[1].type == ARM64_OP_IMM:
            rd = i.reg_name(i.operands[0].reg)
            v = i.operands[1].imm & 0xffffffff
            cur[rd] = (v, i.address, 'mov')
            out.append((i.address, rd, v, 'mov'))
        elif i.operands and i.operands[0].type == ARM64_OP_REG \
                and m not in ('cmp', 'cmn', 'tst', 'str', 'stp', 'stur', 'strb',
                              'strh', 'br', 'blr', 'bl', 'ret', 'cbz', 'cbnz',
                              'tbz', 'tbnz', 'prfm') and not m.startswith('b.'):
            cur.pop(i.reg_name(i.operands[0].reg), None)
    return [{'addr': a, 'reg': r, 'value': v, 'how': how} for a, r, v, how in out]


def ioctl_sites(b, insns):
    """返回每个 `bl ioctl@plt` 的 (addr, request, fd_note, window_lines)。"""
    sites = []
    plt_ioctl = [a for a, n in b.plt.items() if n == 'ioctl']
    if not plt_ioctl:
        return sites
    by_addr = {i.address: n for n, i in enumerate(insns)}
    for n, i in enumerate(insns):
        if i.mnemonic != 'bl' or not i.operands \
                or i.operands[0].type != ARM64_OP_IMM:
            continue
        if i.operands[0].imm not in plt_ioctl:
            continue
        win = []
        req = None
        fd = None
        cur = {}
        for j in range(max(0, n - 24), n):
            p = insns[j]
            if p.mnemonic == 'bl':
                cur.clear()
                continue
            if p.mnemonic in ('movz', 'movk', 'movn') and p.operands \
                    and p.operands[0].type == ARM64_OP_REG:
                rd = p.reg_name(p.operands[0].reg)
                imm = p.operands[1].imm
                sh = _shift_of(p.op_str)
                if p.mnemonic == 'movz':
                    cur[rd] = (imm & 0xffff) << sh
                elif p.mnemonic == 'movk':
                    cur[rd] = (cur.get(rd, 0) | ((imm & 0xffff) << sh)) & 0xffffffff
                else:
                    cur[rd] = ~imm & 0xffffffff
            elif p.mnemonic == 'mov' and len(p.operands) == 2 \
                    and p.operands[0].type == ARM64_OP_REG:
                rd = p.reg_name(p.operands[0].reg)
                if p.operands[1].type == ARM64_OP_IMM:
                    cur[rd] = p.operands[1].imm & 0xffffffff
                elif p.operands[1].type == ARM64_OP_REG:
                    rs = p.reg_name(p.operands[1].reg)
                    if rs in cur:
                        cur[rd] = cur[rs]
            elif p.mnemonic in ('ldr', 'ldur') and len(p.operands) == 2 \
                    and p.operands[0].type == ARM64_OP_REG:
                rd = p.reg_name(p.operands[0].reg)
                cur.pop(rd, None)
                if p.operands[1].type == ARM64_OP_MEM:
                    base = p.reg_name(p.operands[1].mem.base) \
                        if p.operands[1].mem.base else ''
                    if base == 'sp':
                        fd = ('stack', p.operands[1].mem.disp)
            win.append('%06x %-7s %s' % (p.address, p.mnemonic, p.op_str))
        req = cur.get('w1') or cur.get('x1')
        fdv = cur.get('x0') or cur.get('w0')
        sites.append({'addr': i.address, 'request': req,
                      'fd_const': fdv, 'fd_stack': fd,
                      'window': win[-10:]})
    return sites


def literals(b, vals):
    """在 .rodata/.data/.data.rel.ro 里找 32 位字面量命中（按文件偏移对齐 4B 扫）。"""
    hits = []
    pats = {}
    for v in vals:
        pats[struct.pack('<I', v)] = v
    for s in b.secs:
        if s['name'] not in ('.rodata', '.data', '.data.rel.ro', '.bss'):
            continue
        data = s['sec'].data()
        for off in range(0, len(data) - 3, 4):
            w = data[off:off + 4]
            if w in pats:
                hits.append((s['name'], s['addr'] + off, pats[w]))
    return hits


def str_scan(b, pats):
    out = []
    for s in b.secs:
        if s['name'] not in ('.rodata', '.dynstr', '.data'):
            continue
        data = s['sec'].data()
        for m in re.finditer(rb'[ -~]{4,80}', data):
            t = m.group().decode('latin-1')
            for p in pats:
                if p in t:
                    out.append((s['name'], s['addr'] + m.start(), t))
                    break
    return out


def func_start(insns, idx):
    """近似函数起点：向前找到最后一条 ret 或无条 `b`，取其后一条。"""
    j = idx - 1
    while j > 0:
        m = insns[j].mnemonic
        if m in ('ret', 'b') or (m == 'br'):
            return j + 1
        j -= 1
    return 0


def string_refs(b, insns, i0, i1):
    """函数体内 adrp+add 指向的可打印字符串。"""
    pages = {}
    out = []
    for i in insns[i0:i1]:
        if i.mnemonic == 'adrp' and i.operands:
            pages[i.reg_name(i.operands[0].reg)] = i.operands[1].imm
        elif i.mnemonic == 'add' and len(i.operands) == 3 \
                and i.operands[0].type == ARM64_OP_REG \
                and i.operands[1].type == ARM64_OP_REG \
                and i.operands[2].type == ARM64_OP_IMM:
            rn = i.reg_name(i.operands[1].reg)
            if rn in pages:
                va = pages[rn] + i.operands[2].imm
                s = b.cstr(va, 64)
                if s and len(s) >= 3 and all(32 <= ord(c) < 127 for c in s):
                    out.append((i.address, va, s))
    return out


def xref_string(b, insns, target_va):
    """返回引用 target_va 的指令地址列表（adrp+add / movz+movk+add 两种形态）。"""
    pages = {}
    hits = []
    for i in insns:
        if i.mnemonic == 'adrp' and i.operands:
            pages[i.reg_name(i.operands[0].reg)] = i.operands[1].imm
        elif i.mnemonic == 'add' and len(i.operands) == 3 \
                and i.operands[0].type == ARM64_OP_REG \
                and i.operands[1].type == ARM64_OP_REG \
                and i.operands[2].type == ARM64_OP_IMM:
            rn = i.reg_name(i.operands[1].reg)
            if rn in pages and pages[rn] + i.operands[2].imm == target_va:
                hits.append(i.address)
    return hits


def dev_map(b, r):
    """设备节点串 -> 引用它的函数 -> 该函数内是否有 ioctl 调用点。"""
    out = []
    ioctl_funcs = {s['func'] for s in r['ioctls']}
    insns = b.disasm_text()
    idx_of = {i.address: n for n, i in enumerate(insns)}
    for sec, va, text in r['devs']:
        if not text.startswith('/dev/'):
            continue
        for a in xref_string(b, insns, va)[:3]:
            n = idx_of[a]
            fs = insns[func_start(insns, n)].address
            out.append((text, a, fs, fs in ioctl_funcs))
    return out


def analyse(path):
    b = Bin(path)
    insns = b.disasm_text()
    needed = b.needed()
    consts = mov_const_track(insns)
    ioctls = ioctl_sites(b, insns)
    # 给每个 ioctl 站点标出所属函数与其字符串引用（用于判定"在哪个设备上"）
    idx_of = {i.address: n for n, i in enumerate(insns)}
    for s in ioctls:
        n = idx_of[s['addr']]
        j0 = func_start(insns, n)
        s['func'] = insns[j0].address
        s['refs'] = string_refs(b, insns, j0, n + 1)[:6]
    lit = literals(b, [0x89fd, 0x89f1, 0x8b01, 0x8b0b, 0x8b0d])
    devs = str_scan(b, ['/dev/', 'nl80211', 'genl', 'NL80211', '/sys/module/wlan'])
    syms = set(b.plt_order)
    netlink = sorted(syms & NETLINK_SYMS)
    chardev = [s for s in ('ioctl', 'open', 'openat', '__open_2') if s in syms]
    libnl = [n for n in needed if 'libnl' in n]
    libdiag = [n for n in needed if 'libdiag' in n]
    # 通道判定
    if 'ioctl' in syms:
        chan = 'chardev+ioctl' if chardev else 'ioctl'
    elif netlink or libnl:
        chan = 'netlink'
    else:
        chan = 'unknown'
    return {'path': path, 'size': b.size, 'needed': needed,
            'nplt': len(b.plt), 'syms': syms,
            'netlink_syms': netlink, 'chardev_syms': chardev,
            'libnl': libnl, 'libdiag': libdiag,
            'has_ioctl': 'ioctl' in syms,
            'consts': consts, 'ioctls': ioctls, 'literals': lit,
            'devs': devs, 'chan': chan, 'b': b, 'devmap': dev_map(b, {
                'devs': devs, 'ioctls': ioctls})}


def _ioc_like(v):
    """只保留"像 ioctl 码"的常量：_IOC 编码（dir 非 0 且 size 合理）或 0x89xx/0x8bxx 段。

    `_IOC` 编码 = dir<<30 | size<<16 | type<<8 | nr；要求 dir!=0、0<size<=0x100、type!=0，
    以过滤掉 zlib 之类代码里形如 0x40000000 的位掩码。

    这是**粗清单**：真实请求码以调用点窗口（`ioctl_sites`）为准。
    """
    if 0x8900 <= v <= 0x8bff:
        return True
    if v < 0x40000000:
        return False
    d = (v >> 30) & 0x3
    size = (v >> 16) & 0x3fff
    typ = (v >> 8) & 0xff
    return d != 0 and 0 < size <= 0x100 and typ != 0


def render(r, verbose=False):
    print('== %s  (%d B, PLT %d, DT_NEEDED %d)' %
          (r['path'], r['size'], r['nplt'], len(r['needed'])))
    print('   DT_NEEDED: %s' % ' '.join(r['needed']))
    print('   通道相关导入: netlink=%s chardev=%s libnl=%s libdiag=%s'
          % (r['netlink_syms'] or '-', r['chardev_syms'] or '-',
             r['libnl'] or '-', r['libdiag'] or '-'))
    print('   ioctl 导入: %s ；bl ioctl@plt 调用点: %d'
          % ('YES' if r['has_ioctl'] else 'NO', len(r['ioctls'])))
    for s in r['ioctls']:
        req = s['request']
        print('     ioctl@%#x  request=%s  fd_const=%s  fd_slot=%s  func=%#x'
              % (s['addr'],
                 ('%#x' % req) if req is not None else 'reg/undetermined',
                 ('%#x' % s['fd_const']) if s['fd_const'] is not None else '-',
                 s['fd_stack'] or '-', s.get('func', 0)))
        if s.get('refs'):
            print('        func strings: ' + ' | '.join('%r' % t for _, _, t in s['refs']))
        if verbose:
            for l in s['window']:
                print('        ' + l)
    # ioctl-like 常量
    ioc = [c for c in r['consts'] if _ioc_like(c['value'])]
    print('   32 位常量（ioctl-like 粗清单，%d 个；真实请求码以调用点为准）:' % len(ioc))
    for c in ioc[:24]:
        tag = WEXT_MAGIC.get(c['value'], '')
        print('     %#010x  @%#x  %-12s %s' % (c['value'], c['addr'], c['how'], tag))
    print('   0x89fd/0x89f1 字面量命中: %s' % (r['literals'] or '无'))
    print('   设备/通道字符串:')
    for sec, a, t in r['devs'][:30]:
        print('     %s @%#x  %r' % (sec, a, t))
    print('   >>> 通道判定: %s' % r['chan'])
    if r['devmap']:
        print('   /dev 节点 → 引用函数 → 是否含 ioctl:')
        seen = set()
        for t, a, fs, has in r['devmap']:
            k = (t, fs)
            if k in seen:
                continue
            seen.add(k)
            print('     %-14s xref@%#08x func=%#08x ioctl_in_func=%s'
                  % (t, a, fs, 'Y' if has else 'N'))
    print()


CSV_HEADER = ['group', 'item', 'object', 'addr', 'evidence', 'verdict', 'level', 'note']


def c_rows(rs):
    rows = []
    for r in rs:
        ev = ('DT_NEEDED=%s; ioctl_import=%s; ioctl_calls=%d; netlink=%s; libnl=%s'
              % (','.join(r['needed']), r['has_ioctl'], len(r['ioctls']),
                 ','.join(r['netlink_syms']) or '-', ','.join(r['libnl']) or '-'))
        note = '89fd/89f1 literal hits=%d' % len(r['literals'])
        rows.append(['C', 'C0 通道判定', os.path.basename(r['path']), '-', ev,
                     r['chan'], '指令级', note])
        if r['ioctls']:
            for s in r['ioctls']:
                rows.append(['C', 'C1 ioctl 调用点', os.path.basename(r['path']),
                             '%#x' % s['addr'],
                             'request=%s fd=%s' % (
                                 ('%#x' % s['request']) if s['request'] is not None else 'reg',
                                 ('%#x' % s['fd_const']) if s['fd_const'] is not None else 'reg'),
                             '非 0x89fd', '指令级', 'WEXT 私有码不成立'])
    return rows


def selftest(rs):
    fails, ok = [], 0

    def chk(c, m):
        nonlocal ok
        if c:
            ok += 1
        else:
            fails.append(m)

    by = {os.path.basename(r['path']): r for r in rs}
    chk('myftm' in by, '缺少 myftm')
    if 'myftm' in by:
        chk(not by['myftm']['has_ioctl'], 'myftm 不应导入 ioctl')
        chk(by['myftm']['libnl'], 'myftm 应链接 libnl')
    if 'ftmdaemon' in by:
        chk(by['ftmdaemon']['has_ioctl'], 'ftmdaemon 应导入 ioctl')
        chk(any(s['request'] is not None for s in by['ftmdaemon']['ioctls']),
            'ftmdaemon 的 ioctl request 应至少有一个静态可解')
    chk(all(not r['literals'] for r in rs), '不应出现 0x89fd/0x89f1 字面量')
    print('selftest: %d ok, %d fail' % (ok, len(fails)))
    for m in fails:
        print('  FAIL: ' + m)
    return 0 if not fails else 1


def _esc(v):
    v = '' if v is None else str(v)
    if any(c in v for c in ',"\n\r'):
        return '"' + v.replace('"', '""') + '"'
    return v


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--bin', action='append', default=None)
    ap.add_argument('--csv', default=None)
    ap.add_argument('--append', action='store_true')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass
    paths = a.bin or [p for p in FTM_BINS if os.path.exists(p)]
    missing = [p for p in (a.bin or FTM_BINS) if not os.path.exists(p)]
    rs = []
    print('# FTM 用户态工具 ioctl 面（纯离线）')
    if missing:
        print('# 未取得: %s' % ', '.join(missing))
    print()
    for p in paths:
        r = analyse(p)
        rs.append(r)
        render(r, a.verbose)
    if a.selftest:
        return selftest(rs)
    if a.csv:
        rows = c_rows(rs)
        new = not (a.append and os.path.exists(a.csv))
        with open(a.csv, 'a' if not new else 'w', encoding='utf-8', newline='') as fh:
            if new:
                fh.write(','.join(CSV_HEADER) + '\n')
            for r_ in rows:
                fh.write(','.join(_esc(x) for x in r_) + '\n')
        print('wrote %d rows -> %s' % (len(rows), a.csv))
    return 0


if __name__ == '__main__':
    sys.exit(main())
