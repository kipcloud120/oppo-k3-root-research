#!/usr/bin/env python3
"""阶段2 P1.1 工具：内核镜像与 qca_cld3_wlan.ko 的 WARN/BUG 调用点目录重建。

依据 (CONFIG_DEBUG_BUGVERBOSE=y, arm64 4.9):
  struct bug_entry { signed bug_addr_disp; signed file_disp; u16 line; u16 flags; }  // 12B
  brk 编码 0xD4210000 (brk #0x800)
  flags: bit0=WARN, 0=BUG, 高 8 位 = taint 索引 (如 0x901 = WARN + TAINT_WARN)

用法:
  python tools/bugtable_scan.py vmlinux   # 启发式重建 vmlinux.elf 目录（段已合并，无 __bug_table）
  python tools/bugtable_scan.py ko        # 精确解析 vendor_ko/qca_cld3_wlan.ko __bug_table
输出 JSON 到 .build/bugreport_20261120/（不入库）。
"""
import struct, json, bisect, os, sys
from elftools.elf.elffile import ELFFile

BRK = 0xD4210000
OUT = '.build/bugreport_20261120'

def load_vmlinux():
    elf = ELFFile(open('firmware_F16/vmlinux.elf','rb'))
    secs = sorted((s.header['sh_addr'], s.data()) for s in elf.iter_sections()
                  if s.name in ('.kernel','.kernel2'))
    funcs = set()
    for sec in elf.iter_sections():
        if sec.header['sh_type'] == 'SHT_SYMTAB':
            for sym in sec.iter_symbols():
                if sym['st_info']['type'] == 'STT_FUNC' and sym['st_value']:
                    funcs.add((sym['st_value'], sym.name))
    return secs, sorted(funcs)

def read_va(secs, va, n=120):
    for base, data in secs:
        if base <= va < base + len(data):
            o = va - base
            end = data.find(b'\x00', o, o+n)
            if end < 0: return None
            try: t = data[o:end].decode('ascii')
            except UnicodeDecodeError: return None
            return t if all(32 <= ord(c) < 127 for c in t) else None
    return None

def read_word(secs, va):
    for base, data in secs:
        if base <= va <= base + len(data) - 4:
            return struct.unpack_from('<I', data, va-base)[0]
    return None

def fn_of(funcs, va):
    i = bisect.bisect_right([a for a,_ in funcs], va) - 1
    return funcs[i][1] if i >= 0 else '?'

def scan_vmlinux():
    secs, funcs = load_vmlinux()
    out = []
    for base, data in secs:
        for i in range(0, len(data)-12, 4):
            d1, d2, ln, fl = struct.unpack_from('<iiHH', data, i)
            if ln == 0 or ln > 20000: continue
            if fl & 1 == 0 and fl != 0: continue      # 仅 0(BUG) 或 bit0(WARN)
            if fl >> 8 > 0x2F: continue               # taint 索引合理域
            insn_va = base + i + d1
            if read_word(secs, insn_va) != BRK: continue
            fstr = read_va(secs, base + i + 4 + d2)
            if fstr is None: continue
            out.append({'insn_va': insn_va, 'file': fstr, 'line': ln,
                        'flags': fl, 'func': fn_of(funcs, insn_va)})
    return out

def scan_ko():
    elf = ELFFile(open('vendor_ko/qca_cld3_wlan.ko','rb'))
    bt = elf.get_section_by_name('__bug_table')
    text = elf.get_section_by_name('.text')
    symtab = elf.get_section_by_name('.symtab')
    secs = {s.name: s for s in elf.iter_sections()}
    rels = {}
    rsec = elf.get_section_by_name('.rela__bug_table')
    for r in rsec.iter_relocations():
        s = symtab.get_symbol(r['r_info_sym'])
        # 文件指针 reloc: 符号 st_value + addend = 段内偏移; 段由符号 shndx 决定
        rels[r['r_offset']] = (r['r_info_sym'], s['st_value'], r['r_addend'], s['st_shndx'])
    funcs = sorted({(s['st_value'], s.name) for s in symtab.iter_symbols()
                    if s['st_info']['type'] == 'STT_FUNC' and s['st_value'] and s['st_shndx'] == 1})
    tdata = text.data(); btdata = bt.data()
    out = []
    for i in range(0, len(btdata), 12):
        ln, fl = struct.unpack_from('<HH', btdata, i+8)
        si0, sv0, ad0, sh0 = rels[i]
        si1, sv1, ad1, sh1 = rels[i+4]
        # +0: .text 内 insn 偏移（sv=0）
        insn_off = sv0 + ad0
        # +4: 文件字符串（符号所在段 + st_value + addend）
        secf = elf.get_section(sh1)
        fdata = secf.data()
        foff = sv1 + ad1
        end = fdata.find(b'\x00', foff, foff+200)
        fstr = fdata[foff:end].decode('ascii','replace') if end > 0 else '?'
        if struct.unpack_from('<I', tdata, insn_off)[0] != BRK:
            continue  # 校验失败则跳过
        out.append({'insn_off': insn_off, 'file': fstr, 'line': ln, 'flags': fl,
                    'func': fn_of(funcs, insn_off)})
    return out

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'all'
    os.makedirs(OUT, exist_ok=True)
    if mode in ('vmlinux','all'):
        r = scan_vmlinux()
        json.dump(r, open(f'{OUT}/vmlinux_bug_catalog.json','w'))
        w = sum(1 for x in r if x['flags'] & 1); b = len(r) - w
        print(f'vmlinux: {len(r)} entries (WARN {w} / BUG {b})')
    if mode in ('ko','all'):
        r = scan_ko()
        json.dump(r, open(f'{OUT}/wlan_bug_catalog.json','w'))
        w = sum(1 for x in r if x['flags'] & 1); b = len(r) - w
        print(f'qca_cld3_wlan.ko: {len(r)} entries (WARN {w} / BUG {b})')
