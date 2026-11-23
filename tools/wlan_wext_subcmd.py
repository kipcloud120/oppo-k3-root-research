#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wlan_wext_subcmd.py — qca_cld3_wlan.ko WEXT 子命令面枚举（纯离线，第二轮审计新增）。

背景：`iw_setint_getnone`（ioctl 0x8BE0）在 `sub_cmd = *(u32*)extra` 上做了
`cmp w22,#0x64 / b.hi`，然后 `ldr x8,[table + x22*8]` 分派到 `.rodata+0x6280`
的 101 项指针表（索引 0..100）。本工具把这张表全量解开，并对每个目标函数做
"可疑度分类"，用于回答：**有没有哪个子命令把 `wrq->u.value` / `u.mode` 当
长度或索引，或调用了可变长拷贝。**

与 wlan_wext_scan.py 的分工：
  * wlan_wext_scan.py 负责 we_private / 通用反汇编；
  * 本工具负责 0x8BE0 子命令表、任意地址区间反汇编（`--at`，绕开同名符号）、
    以及子命令目标函数的自动分类。

用法：
  python tools/wlan_wext_subcmd.py --subcmd            # 101 项子命令表 + 分类
  python tools/wlan_wext_subcmd.py --subcmd --csv      # 机器可读
  python tools/wlan_wext_subcmd.py --at 0x8a2c0 --len 0x188
  python tools/wlan_wext_subcmd.py --args              # we_private_args 父项
  python tools/wlan_wext_subcmd.py --clusters          # 按目标函数归并
"""
import argparse
import sys

# Windows 上 stdout 重定向到文件时 python 会用 locale(GBK) 编码，导致产物不是 UTF-8。
# 本工具的输出含中文，统一强制 UTF-8。
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

sys.path.insert(0, 'tools')
from wlan_wext_scan import Ko, HW_ADDR   # noqa: E402

SUBCMD_TABLE_SEC = '.rodata'
SUBCMD_TABLE_OFF = 0x6280
SUBCMD_TABLE_N = 101

# 认为"用户数据被当长度/来源"的危险接收者
DANGEROUS = {
    'mem_alloc_copy_from_user_helper': 'malloc(len+1)+copy_from_user(len)',
    '__arch_copy_from_user': 'copy_from_user',
    '__arch_copy_to_user': 'copy_to_user',
    'copy_from_user': 'copy_from_user',
    'qdf_mem_copy': 'memcpy',
    'memcpy': 'memcpy',
    'memmove': 'memmove',
    'strncpy': 'strncpy',
    'strlcpy': 'strlcpy',
    'strscpy': 'strscpy',
    'sscanf': 'sscanf',
    'snprintf': 'snprintf',
    'sprintf': 'sprintf',
    'strnlen': 'strnlen',
    'strlen': 'strlen',
    'strcpy': 'strcpy',
    'kstrtoint': 'kstrtoint',
    'kstrtouint': 'kstrtouint',
}

# 说明性接收者（看到就记录，但不自动判定危险）
NOTABLE = {
    'hdd_priv_get_data': '取 wrqu 里的用户指针+长度',
    'capable': 'CAP 复核',
    'hdd_check_private_wext_control': 'wext_control 门',
    'hdd_check_wext_control': 'wext_control 门',
    '__wlan_hdd_validate_context': '上下文有效性',
    'wma_cli_set_command': 'WMI 常量命令',
    'sme_cli_set_command': 'SME 常量命令',
    'wlan_hdd_set_mon_chan': 'monitor 信道',
    'hdd_wlan_get_stats': 'stats 输出',
    'hdd_wlan_list_fw_profile': 'profile 输出',
}

CALL_MNEM = ('bl', 'b', 'br', 'blr', 'cbz', 'cbnz', 'tbz', 'tbnz')


def calls_in(k, addr, size):
    """重定位解析出该区间内所有 CALL26 目标名（顺序无关，去重）。"""
    out = []
    for off, typ, label, pretty in k.relocs_in(addr, size):
        if typ not in (282, 283):
            continue
        out.append((off, pretty))
    return out


def classify(k, name, addr, size):
    """返回 (verdict_hint, is_bare_ret_stub, dangers[], notables[])。

    hint 语义：
      'null'  表项为 NULL
      'ret'   `mov w0,wzr; ret` 裸桩（handler 完全空转）
      'leaf'  无任何 CALL26（纯本地计算 / 只读全局）
      'calls' 有调用，但**没有**任何长度类/拷贝类/字符串解析被调用者
      'check' 调用了 DANGEROUS 里的长度类原语 -> 必须人工逐指令核
    """
    calls = calls_in(k, addr, size)
    dangers = [(o, n) for (o, n) in calls if n in DANGEROUS]
    notables = sorted({n for (o, n) in calls if n in NOTABLE})
    body = k.data['.text'][addr:addr + size]
    bare_ret = size <= 12 and body[:4] == b'\x00\x00\x80\x52' and b'\xc0\x03\x5f\xd6' in body
    if dangers:
        hint = 'check'
    elif bare_ret:
        hint = 'ret'
    elif not calls:
        hint = 'leaf'
    else:
        hint = 'calls'
    return hint, bare_ret, dangers, notables


def size_at(k, addr):
    """用 k.funcs 列表（不是 fn_by_name 字典）取覆盖 addr 的函数尺寸。

    本 .ko 里有**同名但不同地址**的函数（例如 iw_get_char_setnone 在
    0x8a2c0 和 0x96270 各有一份），fn_by_name 只会留下最后一个，
    所以按名字查尺寸会拿到错误值。
    """
    for v, sz, _n in k.funcs:
        if v <= addr < v + sz:
            return sz
    return 0


def subcmd_rows(k):
    rows = []
    for i, nm, raw in k.ptr_table(SUBCMD_TABLE_SEC, SUBCMD_TABLE_OFF, SUBCMD_TABLE_N):
        if nm == 'NULL':
            rows.append(dict(id=i, target='NULL', addr=None, size=0, hint='null',
                             dangers=[], notables=[], raw=raw))
            continue
        r = k.resolve(SUBCMD_TABLE_SEC, SUBCMD_TABLE_OFF + i * 8)
        tsec, toff = r[2], r[3]
        if tsec != '.text':
            rows.append(dict(id=i, target=raw, addr=toff, size=0, hint='nondrv',
                             dangers=[], notables=[], raw=raw))
            continue
        nm2 = k.func_at(toff) or raw
        size = size_at(k, toff)
        hint, bare_ret, dangers, notables = classify(k, nm2, toff, size)
        rows.append(dict(id=i, target=nm2, addr=toff, size=size, hint=hint,
                         dangers=dangers, notables=notables, raw=raw,
                         bare_ret=bare_ret))
    return rows


def cmd_subcmd(k, as_csv=False):
    rows = subcmd_rows(k)
    if as_csv:
        print('sub_id,index,target_func,addr,size,verdict_hint,notes')
        for r in rows:
            nt = ';'.join(([('danger:' + n) for (_o, n) in r['dangers']] +
                           [('notable:' + n) for n in r['notables']]))
            print('%d,%d,%s,%s,%d,%s,"%s"' % (
                r['id'], r['id'], r['target'],
                '0x%06x' % r['addr'] if r['addr'] is not None else '',
                r['size'], r['hint'], nt))
        return
    print('== .rodata+0x%x, %d entries (sub_cmd 0..%d) ==' % (
        SUBCMD_TABLE_OFF, SUBCMD_TABLE_N, SUBCMD_TABLE_N - 1))
    for r in rows:
        print('[%3d] 0x%06x sz=%-5d %-38s %-6s %s' % (
            r['id'], r['addr'] or 0, r['size'], r['target'], r['hint'],
            ('DANGER:' + ','.join(sorted({n for (_o, n) in r['dangers']}))
             if r['dangers'] else '')))
        if r['notables']:
            print('        notable: %s' % ','.join(r['notables']))
    # 统计
    from collections import Counter
    c = Counter(r['hint'] for r in rows)
    print('\n-- 分类计数 --')
    for kk, v in sorted(c.items()):
        print('   %-8s %d' % (kk, v))
    uniq = {}
    for r in rows:
        if r['target'] != 'NULL':
            uniq.setdefault(r['target'], []).append(r['id'])
    print('-- 唯一目标函数 %d 个；被多个 id 复用的: ' % len(uniq))
    for t, ids in sorted(uniq.items()):
        if len(ids) > 1:
            print('   %-38s ids=%s' % (t, ids))
    print('\n===== 可疑项（含可变长拷贝/字符串解析/cap 之外的 长度类调用）=====')
    for r in rows:
        if not r['dangers']:
            continue
        print('[%3d] 0x%06x %s' % (r['id'], r['addr'], r['target']))
        for off, n in r['dangers']:
            print('        +0x%-5x -> %-34s %s' % (off - r['addr'], n,
                                                   DANGEROUS.get(n, '')))
        if r['notables']:
            print('        notable: %s' % ','.join(r['notables']))


def cmd_clusters(k):
    rows = subcmd_rows(k)
    uniq = {}
    for r in rows:
        if r['target'] == 'NULL':
            continue
        uniq.setdefault(r['target'], []).append(r)
    print('unique targets: %d' % len(uniq))
    for t, rs in sorted(uniq.items()):
        r0 = rs[0]
        print('%-38s 0x%06x sz=%-5d ids=%-28s danger=%s notable=%s' % (
            t, r0['addr'], r0['size'], ','.join(str(x['id']) for x in rs),
            ','.join(sorted({n for (_o, n) in r0['dangers']})) or '-',
            ','.join(r0['notables']) or '-'))


def cmd_at(k, spec, ln):
    import re
    m = re.match(r'^(?:([.\w]+)\+)?0x([0-9a-fA-F]+)$', spec)
    if not m:
        raise SystemExit('--at 需要 0xADDR 或 SEC+0xADDR')
    sec = m.group(1) or '.text'
    off = int(m.group(2), 16)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    blob = k.data[sec][off:off + ln]
    for i in md.disasm(blob, off):
        line = '0x%06x  %-8s %s' % (i.address, i.mnemonic, i.op_str)
        r = k.resolve(sec, i.address)
        if r:
            kind, label, tsec, toff = r
            if kind == 'call':
                nm = k.func_at(toff) if tsec == '.text' else None
                line += '        ; -> %s' % (nm or label)
            else:
                line += '        ; = %s+0x%x' % (tsec, toff)
                s = k.cstr(tsec, toff)
                if s:
                    line += '  ; "%s"' % s[:70]
        print(line)


# ---------------------------------------------------------------------------
# 第二轮审计的判定表（人工结论 + 机器提取的地址/尺寸）
# key = ioctl 号；value = (判定, 证据摘要)
# ---------------------------------------------------------------------------
PARENT_VERDICT = {
    0x8BE0: ('有界', 'extra 只读 8B(ldp w22,w24,[x20]); sub_cmd<=0x64(@0x88e54) 后跳 .rodata+0x6280[101]; 子命令只收 (adapter,u32)'),
    0x8BE1: ('有界', 'GET 方向->core extra_size=0; 全部访问仅 str/ldr wX,[extra+0](4B); sub_cmd-1<=0x3c@0x89100 (1..0x3d, 61 路, 表 .rodata+0x4b02); 无 core copy_to_user'),
    0x8BE3: ('有界', 'len 1..4096 由 helper 0x85534 cmp x1,#4096 夹住; buf[len]=0; 消费方字符串/hex 解析; RRM 分支拷 min(len-1,32)->32B 栈'),
    0x8BE4: ('有界', '读 [extra+0x4/0x8/0xc] 恰好 16B; sub_cmd 1..0x15 跳表 .rodata+0x4a76'),
    0x8BE5: ('有界', 'sub_cmd=iwp->flags 1..17 跳表 .rodata+0x4b82; 全部输出走 2047B kzalloc 且显式传 0x7ff/0x400; iwp->length=strlen+1<=2047'),
    0x8BE6: ('有界', '完全不访问 extra; sub_cmd(u16 @wrqu+0x0a/@+0x06 compat) 8..0x13 跳表 .rodata+0x4c2c'),
    0x8BE7: ('有界', 'n=min(len,11)@0x8b684; 拷 4*n<=44B 到 44B 栈; 已在 r1 核'),
    0x8BE8: ('有界', 'len>=0x30(@0x9fd84 b.hi)+core len<=2047; key_len in{16,32}; data_len==len-0x30(@0x9fde0); 回复 copy_to_user(extra,len)<=2007B'),
    0x8BE9: ('有界', 'len==0x13(@0x8ba50); access_ok(ptr,76)@0x8ba58; copy_from_user 76B->76B 栈; 只回写 4B 状态到 union'),
    0x8BEB: ('有界', '读 4B tsid([x20])/写 4B status; 均在 16B union 内'),
    0x8BED: ('有界', '读 4B tsid/写 4B status; 均在 16B union 内'),
    0x8BEF: ('有界', '读 4B cmd; hdd_indicate_tsf 只写 extra+0/+4/+8 共 12B <= 16B'),
    0x8BF2: ('有界', '读 0..0x17 恰好 24B 声明尺寸; 已在 r1 核'),
    0x8BF4: ('有界', 'core len<=384(-E2BIG)+copy_from_user(384); len!=0@0x8c7f8; 以 (extra,len) 传 sme_set_ft_ies，无固定结构强转'),
    0x8BF5: ('有界', '固定 TLV 写 174B 后 strh iwp->length=0xae@0x8cd10; core copy min(0xae,2047)'),
    0x8BF6: ('有界', 'len==0x20 精确门; 读<=0x15; 已在 r1 核'),
    0x8BF7: ('有界', 'len>=3@0x8d440 且 len==3+20*buf[2]@0x8d4dc; helper 4096 上限; 下游按同式解释'),
    0x8BF8: ('有界', 'malloc(len+1) 文本解析; SSID 1..16/chan<98; 最坏写 0x1bf7<0x1c88; 已在 r1 核'),
    0x8BF9: ('有界', 'capable(0xc)@0x8e1dc; 读 extra+0 4B -> hdd_reg_set_band'),
    0x8BFA: ('无功能', '68B 只 trace + 恒 -EINVAL@0x8e360; 已在 r1 核'),
    0x8BFC: ('有界', 'sub_cmd 1..0x17 跳表; 只读 12B; 已在 r1 核'),
    0x8BFE: ('无功能', '8 字节桩 @0x8eb40: mov w0,wzr; ret —— 208B 声明尺寸无人消费'),
    0x8BFF: ('有界', 'core extra_size=5(kzalloc 5B); snprintf(extra,5,"%u")+strh iwp->length=5@0x8ecf4; core copy 5B'),
}

# 0x8BE0 子命令里"把 value 当索引"的三个（都带 b.hi 上界）
SUBCMD_INDEXED = {
    3: ('value 作跳表索引', 'sub w8,w1,#1; cmp w8,#3; b.hi@0x8ee84; 表 .rodata+0x4c5b[4]'),
    85: ('value 作跳表索引', 'sub w8,w19,#2; cmp w8,#0x17; b.hi@0x85be4; 表 .rodata+0x4a30[24]'),
    86: ('value 作跳表索引', 'cmp w19,#9; b.hi@0x91dfc; 表 .rodata+0x4c5f[10]'),
}


def parent_facts(k):
    import struct
    ro = k.data['.rodata']
    ARGS, N = 0x4d70, 223
    out = {}
    for i in range(N):
        off = ARGS + i * 0x18
        cmd, sa, ga = struct.unpack_from('<IHH', ro, off)
        nm = ro[off + 8:off + 24].split(b'\x00')[0].decode('latin-1')
        if not (0x8BE0 <= cmd <= 0x8BFF):
            continue
        tsz = lambda a: (1 if (a >> 12) in (1, 2) else 4)
        seta = (sa & 0x7FF) * tsz(sa)
        geta = (ga & 0x7FF) * tsz(ga)
        dirn = 'SET' if not (cmd & 1) else 'GET'
        off_s = 4 if nm == '' and dirn == 'SET' else 0
        if dirn == 'SET':
            extra = 0 if ((sa & 0x800) and (seta + off_s) <= 16) else seta
        else:
            extra = 0 if ((ga & 0x800) and geta <= 16) else geta
        r = k.resolve('.rodata', 0x4c70 + (cmd - 0x8BE0) * 8)
        toff = r[3] if r else None
        sym = (k.func_at(toff) if toff is not None else 'NULL') or 'NULL'
        out[cmd] = dict(sym=sym, addr=toff, size=(size_at(k, toff) if toff else 0),
                        dirn=dirn, sa=sa, ga=ga, name=nm, extra=extra)
    return out


def cmd_audit_csv(k, path):
    pf = parent_facts(k)
    rows = []
    rows.append('item_ioctl,sub_id,symbol,direction,set_args,get_args,core_extra_size,'
                'len_gate,target_size,max_struct_off,judgment,evidence')
    for ioctl in sorted(pf):
        f = pf[ioctl]
        j, ev = PARENT_VERDICT.get(ioctl, ('未决', '-'))
        lg = {
            0x8BE3: 'helper len<=4096 (+len>=1)',
            0x8BE7: 'n=min(len,11)',
            0x8BE8: '48<=len<=2047',
            0x8BE9: 'len==19',
            0x8BF2: 'len<=24',
            0x8BF4: 'len<=384',
            0x8BF6: 'len==32',
            0x8BF7: 'len>=3 && len==3+20*n',
            0x8BF8: 'len<=2047',
            0x8BFE: 'len<=208 (无人消费)',
            0x8BFF: 'n/a (GET: 输出方向)',
            0x8BE5: 'n/a (GET: 输出方向)',
            0x8BF5: 'n/a (GET: 输出方向)',
        }.get(ioctl, 'n/a (union 16B)' if f['extra'] == 0 else 'len<=%d' % f['extra'])
        sz = {'0x8BE0': '16B union', }.get('0x%04X' % ioctl,
                                          '%dB' % f['extra'] if f['extra'] else '16B union')
        rows.append('0x%04X,-,%s,%s,0x%04X,0x%04X,%d,"%s","%s",-,"%s","%s"' % (
            ioctl, f['sym'], f['dirn'], f['sa'], f['ga'], f['extra'], lg, sz, j,
            ev.replace('"', "'")))
    for r in subcmd_rows(k):
        if r['hint'] == 'null':
            j, ev = '无功能', '表项 NULL；父项 0x88e84 cbz x8 -> -EINVAL'
        elif r['id'] in SUBCMD_INDEXED:
            j, ev = '有界', SUBCMD_INDEXED[r['id']][1]
        elif r['target'].startswith('hdd_we_pps_'):
            j, ev = '有界', 'w3=value -> hdd_we_packet_power_save -> wma_cli_set_command (标量)'
        elif 'wma_cli_set_command' in r['notables']:
            j, ev = '有界', 'value 作 wma_cli_set_command(vdev,cmd,value) 的标量'
        elif r['hint'] == 'leaf':
            j, ev = '有界', '44B 叶函数，无调用；入参只作标量'
        else:
            j, ev = '有界(本层)', '子命令只收 (adapter,u32 value)，无用户指针/长度；下游取值域未展开'
        rows.append('0x8BE0,%d,%s,-,-,-,-,"n/a (子命令无用户长度)","%sB",-,"%s","%s"' % (
            r['id'], r['target'], r['size'], j, ev.replace('"', "'")))
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(rows) + '\n')
    print('wrote %s (%d rows)' % (path, len(rows) - 1))


def cmd_args(k):
    import struct
    ro = k.data['.rodata']
    ARGS, N = 0x4d70, 223
    print('== 父项（cmd in 0x8BE0..0x8BFF）：方向由 cmd 奇偶决定，与 set/get 声明无关 ==')
    for i in range(N):
        off = ARGS + i * 0x18
        cmd, sa, ga = struct.unpack_from('<IHH', ro, off)
        nm = ro[off + 8:off + 24].split(b'\x00')[0].decode('latin-1')
        if not (0x8BE0 <= cmd <= 0x8BFF):
            continue
        seta = (sa & 0x7FF) * (1 if (sa >> 12) in (1, 2) else 4)
        geta = (ga & 0x7FF) * (1 if (ga >> 12) in (1, 2) else 4)
        dirn = 'SET' if not (cmd & 1) else 'GET'
        off_s = 4 if nm == '' and dirn == 'SET' else 0
        if dirn == 'SET':
            extra = seta
            if (sa & 0x800) and (extra + off_s) <= 16:
                extra = 0
        else:
            extra = geta
            if (ga & 0x800) and extra <= 16:
                extra = 0
        print('[%3d] 0x%04X %s set=0x%04X get=0x%04X name=%-16r core_extra_size=%d' %
              (i, cmd, dirn, sa, ga, nm, extra))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--ko', default='vendor_ko/qca_cld3_wlan.ko')
    ap.add_argument('--subcmd', action='store_true')
    ap.add_argument('--clusters', action='store_true')
    ap.add_argument('--args', action='store_true')
    ap.add_argument('--csv', action='store_true')
    ap.add_argument('--at')
    ap.add_argument('--len', default='0x100')
    ap.add_argument('--audit-csv')
    a = ap.parse_args(argv)
    k = Ko(a.ko)
    if a.audit_csv:
        cmd_audit_csv(k, a.audit_csv)
        return 0
    if a.at:
        cmd_at(k, a.at, int(a.len, 0))
        return 0
    if a.args:
        cmd_args(k)
        return 0
    if a.clusters:
        cmd_clusters(k)
        return 0
    if a.subcmd:
        cmd_subcmd(k, a.csv)
        return 0
    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())
