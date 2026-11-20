# -*- coding: utf-8 -*-
"""生成 WLAN_HANDLER_AUDIT.md 的 §2 一览表（数据直接来自 handler_audit.csv）。"""
import csv, io, collections

CSV = r'artifacts_adb/r1_wlan_reach/handler_audit.csv'
OUT = r'WLAN_HANDLER_AUDIT.md'
rows = list(csv.DictReader(io.open(CSV, encoding='utf-8')))

GROUPS = ['参数解析', '内存管理', '状态管理', '并发管理', '外部交互']
by = collections.OrderedDict((g, []) for g in GROUPS)
for r in rows:
    by.setdefault(r['group'], []).append(r)


def cell(s, n=110):
    s = (s or '').replace('|', '\\|').replace('\n', ' ')
    return s if len(s) <= n else s[:n - 1] + '…'


def main():
    L = []
    L.append('## §2 98 行一览表（按 R1 的 5 类分组）\n')
    L.append('> 数据由 `tools/wlan_handler_scan.py --csv` 直接生成，逐行可复算；'
             '本表为压缩记录，指令地址见 CSV 的 `parse_evidence` / `copy_evidence` 列。\n')
    L.append('> 每行字段：**入口 → 参数来源/解析 → 长度与值域约束 → 对象生命周期 → 状态变化 → 错误出口**。\n')
    for g in GROUPS:
        rs = by.get(g, [])
        L.append('### %s（%d 项）\n' % (g, len(rs)))
        L.append('| i | 命令 | handler | 帧 | 解析 → 约束（指令级） | 拷贝/输出 | 备注 |')
        L.append('|---|---|---|---|---|---|---|')
        for r in rs:
            parse = cell(r['parse_funcs'], 120) or '—'
            chk = cell(r['range_check'], 120)
            cop = cell(r['copy_ops'], 90) or '—'
            note = cell(r['notes'], 40) or ''
            L.append('| %s | %s | %s | %#x | %s **⇒** %s | %s | %s |' % (
                r['i'], r['name'], r['handler'], int(r['frame_size']),
                parse, chk, cop, note))
        L.append('')
    # 附录：完整 CSV 快照（便于无工具复算）
    L.append('### §2.A 全量 CSV 快照（79 列宽的压缩版：前 10 列原文）\n')
    L.append('```')
    L.append('i,name,handler,handler_size,frame_size,parse_funcs,range_check,in_short,copy_ops,notes')
    for r in rows:
        L.append(','.join(r[k] for k in ['i', 'name', 'handler', 'handler_size',
                                         'frame_size', 'parse_funcs', 'range_check',
                                         'in_short', 'copy_ops', 'notes']))
    L.append('```')
    txt = '\n'.join(L) + '\n'
    base = io.open(OUT, encoding='utf-8').read() if __import__('os').path.exists(OUT) else ''
    marker = '<!-- SECTION2 -->'
    if marker in base:
        base = base.replace(marker, txt)
        io.open(OUT, 'w', encoding='utf-8', newline='\n').write(base)
        print('injected §2 into existing doc')
    else:
        io.open(OUT + '.section2.tmp', 'w', encoding='utf-8', newline='\n').write(txt)
        print('wrote temp section2')
    print('groups:', {g: len(by.get(g, [])) for g in GROUPS})


if __name__ == '__main__':
    main()
