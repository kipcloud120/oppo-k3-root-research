import json, re, sys

# Usage: python _apply_list.py <target_file> <json_array_file>
# Applies the array sequentially to the FIRST N Chinese-containing lines of target.
# Line count is preserved. Asserts N <= remaining to prevent silent truncation.

target, arrfile = sys.argv[1], sys.argv[2]
han = re.compile(r'[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]')
lines = open(target, encoding='utf-8').read().split('\n')
zh = [i for i, l in enumerate(lines) if han.search(l)]
arr = json.load(open(arrfile, encoding='utf-8'))
if len(arr) > len(zh):
    print(f"TOO MANY: got {len(arr)}, remaining {len(zh)}"); sys.exit(1)
for k, v in enumerate(arr):
    lines[zh[k]] = v
open(target, 'w', encoding='utf-8').write('\n'.join(lines))
print(f"applied={len(arr)} remaining_zh_lines={sum(1 for l in lines if han.search(l))} remaining_zh_chars={sum(len(han.findall(l)) for l in lines)}")
