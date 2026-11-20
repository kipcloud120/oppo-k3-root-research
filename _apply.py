import json, re, sys

# Usage: python _apply.py <target_file> <json_map_file>
# JSON: {"<1-based line number>": "translated full line", ...}
# Line count is preserved, so line numbers stay stable across batches.

target, mapfile = sys.argv[1], sys.argv[2]
han = re.compile(r'[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]')
lines = open(target, encoding='utf-8').read().split('\n')
mp = json.load(open(mapfile, encoding='utf-8'))
applied = 0
for k, v in mp.items():
    j = int(k) - 1
    if j < 0 or j >= len(lines):
        print(f"WARN line {k} out of range"); continue
    lines[j] = v
    applied += 1
open(target, 'w', encoding='utf-8').write('\n'.join(lines))
remain_chars = sum(len(han.findall(l)) for l in lines)
remain_lines = sum(1 for l in lines if han.search(l))
print(f"applied={applied} remaining_zh_chars={remain_chars} remaining_zh_lines={remain_lines}")
