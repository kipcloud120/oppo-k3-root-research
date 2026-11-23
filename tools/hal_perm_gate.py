#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hal_perm_gate.py — B 组：OPPO Wi-Fi HIDL 服务的**方法级权限门**离线核查。

目标（只读物料）：
  .build/vendor/x/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service   (115,408 B, ET_DYN)
  .build/hal_debugdata.elf                                            (.gnu_debugdata 解压后的符号表)

做四件事：
  1. 校验 debugdata 与主 ELF 同源（build-id 逐字节相等）；
  2. 从 vtable @0x1a0a0 槽 2..10 取出 9 个 HIDL 方法的入口，与 debugdata 符号名对齐；
  3. 逐方法反汇编，解析每条 BL 的 PLT 导入名 / 内部符号名，统计"身份/权限类"导入；
  4. 全 .text 扫描：BL→PLT 直方图、`svc` 直接系统调用、`mrs tpidr_el0`、间接调用 `blr`。

判据（写死在脚本里，避免"符号存在当证据"）：
  * 方法级权限门若存在，必然体现为下列之一：导入并调用
    `IPCThreadState::getCallingUid/getCallingPid/checkCallingPermission/
     checkCallingOrSelfPermission`、`getuid/geteuid/getpid`、`selinux_*`、`audit_*`；
    或读 `/proc/self/...`；或 `svc #0` 直接取 uid（__NR_getuid=174 / __NR_geteuid=175）。
  * 上述任一"不存在"，只能说明**该二进制内**没有方法级门；调用方身份是否在
    SELinux `service_manager find` 层被拦，由 sepolicy 决定（另一条证据线）。

用法：
  python tools/hal_perm_gate.py
  python tools/hal_perm_gate.py --csv artifacts_adb/r1_wlan_reach/residual_audit.csv --append
  python tools/hal_perm_gate.py --disasm-slots 5,6      # 额外转储指定槽位
  python tools/hal_perm_gate.py --selftest
"""
import argparse
import os
import re
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

HAL = '.build/vendor/x/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service'
DBG = '.build/hal_debugdata.elf'
VTABLE = 0x1a0a0            # IOppoWifiService 的 vtable（槽 2 起为 HIDL code 1）

# HIDL code -> 方法（由 oppo-wifi-service.dex 的 Proxy 常量与 vtable 顺序共同确定）
HIDL_CODE = {
    2: (1, 'changeConnectionMode(int32)'),
    3: (2, 'catchSnifferLog(uint32,uint32)'),
    4: (3, 'resetConnectionMode()'),
    5: (4, 'executeDriverCommand(string)'),
    6: (5, 'setupFTMdaemon()'),
    7: (6, 'sendSupplicantCommand(string)'),
    8: (7, 'runWiFiScript(string,string)'),
    9: (8, 'sendIniContent(string)'),
    10: (9, 'getIniVersion(string)'),
}

# 身份/权限类导入（方法级权限门的必要条件）
PERM_RE = re.compile(
    r'(getCallingUid|getCallingPid|getCallingTid|checkCallingPermission|'
    r'checkCallingOrSelfPermission|checkPermission|IPCThreadState|'
    r'getuid|geteuid|getgid|getegid|getpid|getppid|gettid|'
    r'selinux_|audit_|capget|capset|setresuid|setuid|setgid|'
    r'Permission|permission)', re.I)

# 需要人工看参数的"疑似"系统调用（prctl 既可能是 PR_SET_PDEATHSIG 也可能是
# PR_SET_NO_NEW_PRIVS / PR_SET_DUMPABLE，必须逐点核参）
PRCTL_RE = re.compile(r'(prctl|syscall)$')

# 特权原语（用于展示"无门直通到哪")
PRIV_RE = re.compile(
    r'(execv|execve|vfork|fork|system|popen|__system_property_set|SetProperty|'
    r'chown|chmod|kill|waitpid|open|fopen|stat|syscall|signal|setitimer|prctl)')

# 直接系统调用号（若出现 svc 且 x8 可静态确定为这些，则等价于 getuid 检查）
NR_GETUID, NR_GETEUID, NR_GETGID, NR_GETEGID = 174, 175, 176, 177


class Bin:
    def __init__(self, path, dbg=None):
        self.path = path
        self.f = open(path, 'rb')
        self.elf = ELFFile(self.f)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True
        self._build_sections()
        self._build_plt()
        self.syms = self._load_syms(dbg) if dbg else []
        self._name_cache = {}

    # -- 基础 ---------------------------------------------------------------
    def _build_sections(self):
        self.secs = []
        for s in self.elf.iter_sections():
            self.secs.append({'name': s.name, 'addr': s['sh_addr'],
                              'size': s['sh_size'], 'off': s['sh_offset'],
                              'sec': s})

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

    def cstr(self, addr, maxlen=200):
        b = self.read(addr, maxlen)
        z = b.find(b'\x00')
        if z >= 0:
            b = b[:z]
        try:
            return b.decode('utf-8', 'replace')
        except Exception:
            return repr(b)

    def build_id(self):
        s = self.elf.get_section_by_name('.note.gnu.build-id')
        return s.data() if s else b''

    def _build_plt(self):
        dynsym = self.elf.get_section_by_name('.dynsym')
        names = [s.name for s in dynsym.iter_symbols()]
        order = []
        for s in self.elf.iter_sections():
            if isinstance(s, RelocationSection) and s.name == '.rela.plt':
                order = [names[r['r_info_sym']] for r in s.iter_relocations()]
                break
        self.plt = {}
        plt0 = self.elf.get_section_by_name('.plt')['sh_addr']
        for i, n in enumerate(order):
            self.plt[plt0 + 0x20 + 0x10 * i] = n
        self.plt_order = order

    def _load_syms(self, path):
        with open(path, 'rb') as fh:
            e = ELFFile(fh)
            bid = e.get_section_by_name('.note.gnu.build-id')
            if bid is None or bid.data() != self.build_id():
                raise SystemExit('debugdata build-id 与主 ELF 不一致，拒绝使用')
            st = e.get_section_by_name('.symtab')
            out = []
            for s in st.iter_symbols():
                if s['st_info']['type'] == 'STT_FUNC' and s['st_size']:
                    out.append((s['st_value'], s['st_size'], s.name))
            out.sort()
            return out

    def sym_at(self, addr):
        for v, sz, n in self.syms:
            if v <= addr < v + sz:
                return n
        return None

    def resolve(self, addr):
        if addr in self.plt:
            return 'PLT:' + self.plt[addr]
        n = self.sym_at(addr)
        if n:
            return n
        return 'sub_%x' % addr if self.sec_of(addr) else '%#x' % addr

    def func_range(self, addr):
        n = self.sym_at(addr)
        if not n:
            return addr, 0x400
        for v, sz, nm in self.syms:
            if nm == n and v == addr:
                return v, sz
        return addr, 0x400

    def disasm(self, addr, size):
        return list(self.md.disasm(self.read(addr, size), addr))


def demangle_brief(n):
    """只做可读性压缩：_ZN6vendor...15OppoWifiService10loadDriverEPKcS7_ -> loadDriver"""
    m = re.search(r'(\d+)([A-Za-z_][A-Za-z0-9_]*)$', n)
    parts = re.findall(r'(\d+)([A-Za-z_][A-Za-z0-9_]*)', n)
    if parts:
        return parts[-1][1]
    return n


def scan_calls(b, addr, size):
    """返回该函数内所有 BL 的目标名与 blr 计数。"""
    calls = []
    blr = 0
    for i in b.disasm(addr, size):
        if i.mnemonic == 'bl' and i.operands and i.operands[0].type == ARM64_OP_IMM:
            calls.append((i.address, b.resolve(i.operands[0].imm)))
        elif i.mnemonic == 'blr':
            blr += 1
    return calls, blr


def whole_text_scan(b):
    text = b.elf.get_section_by_name('.text')
    start, size = text['sh_addr'], text['sh_size']
    codes = b.disasm(start, size)
    per_plt = {}
    svc = []
    mrs_tls = []
    blr = 0
    for i in codes:
        if i.mnemonic == 'bl' and i.operands and i.operands[0].type == ARM64_OP_IMM:
            t = i.operands[0].imm
            n = b.plt.get(t)
            if n:
                per_plt.setdefault(n, []).append(i.address)
        elif i.mnemonic == 'svc':
            svc.append((i.address, i.op_str))
        elif i.mnemonic == 'mrs' and 'tpidr' in i.op_str:
            mrs_tls.append(i.address)
        elif i.mnemonic == 'blr':
            blr += 1
    return per_plt, svc, mrs_tls, blr


def strings_scan(b, pats):
    """在 .rodata/.dynstr/.strtab 里找关键字串。"""
    hits = []
    for s in b.secs:
        if s['name'] not in ('.rodata', '.dynstr', '.strtab'):
            continue
        data = s['sec'].data()
        for m in re.finditer(rb'[ -~]{4,80}', data):
            txt = m.group().decode('latin-1')
            for p in pats:
                if re.search(p, txt, re.I):
                    hits.append((s['name'], s['addr'] + m.start(), txt))
                    break
    return hits


def vtable_methods(b):
    data = b.read(VTABLE, 0x60)
    import struct
    ptrs = struct.unpack('<%dQ' % (len(data) // 8), data)
    out = []
    for slot, code_name in HIDL_CODE.items():
        addr = ptrs[slot]
        code, sig = code_name
        n = b.sym_at(addr)
        size = b.func_range(addr)[1]
        out.append({'slot': slot, 'code': code, 'sig': sig, 'addr': addr,
                    'sym': n, 'brief': demangle_brief(n) if n else None,
                    'size': size})
    return out


def method_report(b, m):
    calls, blr = scan_calls(b, m['addr'], m['size'])
    perm = [(a, n) for a, n in calls if PERM_RE.search(n)]
    priv = [(a, n) for a, n in calls if PRIV_RE.search(n)]
    inner = [(a, n) for a, n in calls if not n.startswith('PLT:')]
    m2 = dict(m)
    m2.update({'calls': calls, 'perm_calls': perm, 'priv_calls': priv,
               'internal_calls': inner, 'blr': blr})
    return m2


def call_args(b, addr, nargs=3, lookback=8):
    """解析某 BL 之前 w0..w(nargs-1) 的立即数（用于 prctl/syscall 参数核对）。"""
    insns = b.disasm(addr - 4 * lookback, 4 * lookback + 4)
    cur = {}
    for i in insns:
        if i.mnemonic == 'mov' and len(i.operands) == 2 \
                and i.operands[0].type == ARM64_OP_REG \
                and i.operands[1].type == ARM64_OP_IMM:
            cur[i.reg_name(i.operands[0].reg)] = i.operands[1].imm & 0xffffffff
        elif i.mnemonic in ('movz', 'movk') and i.operands:
            rd = i.reg_name(i.operands[0].reg)
            imm = i.operands[1].imm
            sh = 16 if 'lsl #16' in i.op_str else (32 if 'lsl #32' in i.op_str else 0)
            if i.mnemonic == 'movz':
                cur[rd] = (imm & 0xffff) << sh
            else:
                cur[rd] = (cur.get(rd, 0) | ((imm & 0xffff) << sh)) & 0xffffffff
    return [cur.get('w%d' % k, cur.get('x%d' % k)) for k in range(nargs)]


def render(b, methods, per_plt, svc, mrs_tls, blr, strhits):
    print('# HAL: %s' % b.path)
    print('# build-id: %s' % b.build_id().hex())
    print('# debugdata 符号: %d 个（已校验 build-id 同源）' % len(b.syms))
    print('# PLT 导入: %d 个' % len(b.plt))
    print()
    print('== 1. 全部 PLT 导入中"身份/权限类"命中 ==')
    hits = [n for n in b.plt_order if PERM_RE.search(n)]
    if hits:
        for n in hits:
            print('   !! %s  (调用点 %s)' % (n, [hex(a) for a in per_plt.get(n, [])]))
    else:
        print('   0 个（%d 个导入全部为 libc/libc++/liblog/libhidlbase/libbase 常规符号）'
              % len(b.plt))
    print('   疑似项（须核参）:')
    for n in b.plt_order:
        if PRCTL_RE.search(n):
            for a in per_plt.get(n, []):
                print('     %-24s @%#x  args=%s' % (n, a, call_args(b, a, 3)))
    print()
    print('== 2. 直接系统调用 / TLS 读取 ==')
    print('   svc 指令: %d 条 %s' % (len(svc), svc[:8]))
    print('   mrs tpidr_el0: %d 条（bionic TLS，非权限检查）%s'
          % (len(mrs_tls), [hex(x) for x in mrs_tls[:6]]))
    print('   间接调用 blr: %d 条（std::function 回调 / 虚调用）' % blr)
    print()
    print('== 3. .rodata/.dynstr 中的权限关键串 ==')
    if strhits:
        for sec, a, t in strhits[:40]:
            print('   %s @%#x  %r' % (sec, a, t))
    else:
        print('   0 条（无 permission / uid / caller 相关文案）')
    print()
    print('== 4. vtable@%#x 的 9 个 HIDL 方法 ==' % VTABLE)
    hdr = '%-4s %-5s %-8s %-34s %-6s %s' % ('slot', 'code', 'entry', 'method', 'size', 'perm-calls')
    print(hdr)
    for m in methods:
        print('%-4d %-5d %#-8x %-34s %-6d %s'
              % (m['slot'], m['code'], m['addr'], m['sig'], m['size'],
                 ('!! ' + ','.join(n for _, n in m['perm_calls']))
                 if m['perm_calls'] else 'NONE'))
    print()
    print('== 5. 逐方法的"无门直通"证据（特权原语调用点） ==')
    for m in methods:
        print('-- slot%d code%d %s @%#x (%s, %d B)'
              % (m['slot'], m['code'], m['sig'], m['addr'],
                 m['sym'] or '?', m['size']))
        if m['priv_calls']:
            for a, n in m['priv_calls']:
                print('     %#08x  bl %s' % (a, n))
        else:
            print('     (无直接特权原语调用)')
        if m['internal_calls']:
            print('     内部调用: ' + ', '.join('%s@%#x' % (demangle_brief(n), a)
                                            for a, n in m['internal_calls']))
        if m['blr']:
            print('     间接调用 blr ×%d' % m['blr'])
    print()
    print('== 6. 全 .text 中特权原语的 BL 调用点统计 ==')
    for n in sorted(per_plt, key=lambda x: -len(per_plt[x])):
        if PRIV_RE.search(n):
            print('   %-40s %3d 处  %s' % (n, len(per_plt[n]),
                                           ' '.join(hex(a) for a in per_plt[n][:6])))


def b_rows(b, methods, per_plt):
    rows = []
    perm_hits = [n for n in b.plt_order if PERM_RE.search(n)]
    rows.append(['B', 'B0 HAL 导入面', os.path.basename(b.path), '-',
                 'PLT 导入 %d 个；身份/权限类命中 %d 个' % (len(b.plt), len(perm_hits)),
                 '无方法级权限门' if not perm_hits else '存在权限 API，需复核',
                 '指令级', 'build-id ' + b.build_id().hex()[:16]])
    for m in methods:
        ev = 'entry=%#x size=%d; perm-calls=%s; priv-calls=%s' % (
            m['addr'], m['size'],
            ','.join('%s@%#x' % (n, a) for a, n in m['perm_calls']) or 'none',
            ','.join('%s@%#x' % (n.split(':')[-1], a) for a, n in m['priv_calls']) or 'none')
        rows.append(['B', 'B%d code%d' % (m['slot'], m['code']),
                     '%s (%s)' % (m['sig'], m['sym'] or '?'), '%#x' % m['addr'], ev,
                     '无权限门（空权限直通）' if not m['perm_calls'] else '有权限检查',
                     '指令级', 'blr=%d' % m['blr']])
    return rows


def selftest(b, methods, per_plt, svc):
    fails, ok = [], 0

    def chk(c, m):
        nonlocal ok
        if c:
            ok += 1
        else:
            fails.append(m)

    chk(len(b.plt) == 89, 'PLT 导入应为 89，实得 %d' % len(b.plt))
    chk(len(methods) == 9, '应解出 9 个 HIDL 方法，实得 %d' % len(methods))
    by_addr = {m['addr']: m for m in methods}
    chk(0x90a0 in by_addr, 'changeConnectionMode 应在 0x90a0')
    chk(0x992c in by_addr, 'executeDriverCommand 应在 0x992c')
    chk(0xa0dc in by_addr, 'setupFTMdaemon 应在 0xa0dc')
    chk(0xad20 in by_addr, 'catchSnifferLog 应在 0xad20')
    chk(all(m['sym'] for m in methods), '有方法未对上 debugdata 符号')
    names = ' '.join(n for m in methods for _, n in m['perm_calls'])
    chk('getCallingUid' not in names, '意外出现 getCallingUid')
    chk(not [n for n in b.plt_order if PERM_RE.search(n)],
        '导入面意外出现权限 API')
    chk(not svc, '意外出现 svc 直接系统调用')
    # prctl 必须是 PR_SET_PDEATHSIG(1)/SIGKILL(9)，否则视为可疑门
    prctl_ok = True
    for n in b.plt_order:
        if PRCTL_RE.search(n) and n == 'prctl':
            for a in per_plt.get(n, []):
                args = call_args(b, a, 2)
                if args[:2] != [1, 9]:
                    prctl_ok = False
    chk(prctl_ok, 'prctl 参数不是 (PR_SET_PDEATHSIG=1, SIGKILL=9)')
    print('selftest: %d ok, %d fail' % (ok, len(fails)))
    for m in fails:
        print('  FAIL: ' + m)
    return 0 if not fails else 1


def dump_func(b, addr, size):
    """带 ADRP+ADD 字符串 / BL 目标注释的反汇编（导出侧字符串用 .rodata 直读）。"""
    pages = {}
    for i in b.disasm(addr, size):
        ann = ''
        if i.mnemonic == 'adrp' and i.operands \
                and i.operands[0].type == ARM64_OP_REG:
            pages[i.reg_name(i.operands[0].reg)] = i.operands[1].imm
        if i.mnemonic in ('add', 'ldr') and len(i.operands) == 3 \
                and i.operands[0].type == ARM64_OP_REG \
                and i.operands[1].type == ARM64_OP_REG \
                and i.operands[2].type == ARM64_OP_IMM:
            rn = i.reg_name(i.operands[1].reg)
            if rn in pages:
                va = pages[rn] + i.operands[2].imm
                s = b.cstr(va, 80)
                if s and all(32 <= ord(c) < 127 for c in s):
                    ann = '   ; "%s" @%#x' % (s, va)
        if i.mnemonic in ('bl', 'b') and i.operands \
                and i.operands[0].type == ARM64_OP_IMM:
            ann = '   ; -> ' + b.resolve(i.operands[0].imm)
        print('%06x  %-8s %-26s%s' % (i.address, i.mnemonic, i.op_str, ann))


CSV_HEADER = ['group', 'item', 'object', 'addr', 'evidence', 'verdict', 'level', 'note']


def _esc(v):
    v = '' if v is None else str(v)
    if any(c in v for c in ',"\n\r'):
        return '"' + v.replace('"', '""') + '"'
    return v


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--hal', default=HAL)
    ap.add_argument('--dbg', default=DBG)
    ap.add_argument('--disasm-slots', default=None)
    ap.add_argument('--dump', default=None, help='addr:len 十六进制，带字符串/调用注释转储')
    ap.add_argument('--csv', default=None)
    ap.add_argument('--append', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

    b = Bin(a.hal, a.dbg if os.path.exists(a.dbg) else None)
    methods = [method_report(b, m) for m in vtable_methods(b)]
    per_plt, svc, mrs_tls, blr = whole_text_scan(b)
    strhits = strings_scan(b, [r'permission', r'\buid\b', r'caller',
                               r'checkCalling', r'selinux', r'IPCThreadState'])
    if a.selftest:
        return selftest(b, methods, per_plt, svc)
    if not a.dump:
        render(b, methods, per_plt, svc, mrs_tls, blr, strhits)
    if a.dump:
        addr, ln = a.dump.split(':')
        print('\n===== %s =====' % a.dump)
        dump_func(b, int(addr, 16), int(ln, 16))
    if a.disasm_slots:
        for s in a.disasm_slots.split(','):
            slot = int(s)
            m = next(x for x in methods if x['slot'] == slot)
            print('\n===== slot%d %s @%#x =====' % (slot, m['sig'], m['addr']))
            for i in b.disasm(m['addr'], m['size']):
                ann = ''
                if i.mnemonic == 'bl' and i.operands \
                        and i.operands[0].type == ARM64_OP_IMM:
                    ann = '   ; -> ' + b.resolve(i.operands[0].imm)
                print('%06x  %-8s %s%s' % (i.address, i.mnemonic, i.op_str, ann))
    if a.csv:
        rows = b_rows(b, methods, per_plt)
        new = not (a.append and os.path.exists(a.csv))
        with open(a.csv, 'a' if not new else 'w', encoding='utf-8', newline='') as fh:
            if new:
                fh.write(','.join(CSV_HEADER) + '\n')
            for r in rows:
                fh.write(','.join(_esc(x) for x in r) + '\n')
        print('\nwrote %d rows -> %s' % (len(rows), a.csv))
    return 0


if __name__ == '__main__':
    sys.exit(main())
