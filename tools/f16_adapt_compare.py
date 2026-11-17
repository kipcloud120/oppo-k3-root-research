#!/usr/bin/env python3
# CVE-2023-33107 4.9 适配对照器
# 比较公开 PoC (src_ref/poc_ex.c) 与 realme 官方 4.9 UAPI 的
# ioctl 编号 / 结构体字段 / 关键常量，并核对 F.16 符号表中的函数存在性。
# 输出: artifacts_adb/f16_adapt_compare_output.txt 与 src_ref/adapt_compare.txt
import re
import sys

POC = "src_ref/poc_ex.c"
UAPI = "src_ref/kgsl_4.9/msm_kgsl.h"
SYMS = "firmware_F16/kallsyms_out.txt"
OUT = "src_ref/adapt_compare.txt"


def logical_lines(path):
    """合并 C 续行，返回 (行号, 文本)"""
    out, buf, start = [], "", 1
    for i, ln in enumerate(open(path, encoding="utf-8", errors="replace"), 1):
        s = ln.rstrip("\n")
        t = s.rstrip()
        if not buf:
            start = i
        if t.endswith("\\"):
            buf += t[:-1] + " "
        else:
            out.append((start, buf + s))
            buf = ""
    return out


IOC_RE = re.compile(
    r"#define\s+(IOCTL_KGSL_[A-Z0-9_]+)\s+(.+)$")
CALL_RE = re.compile(
    r"_IO(?:W?R?|R)\s*\(\s*[^,]+,\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*([^)]+)\)")


def ioctls(path):
    res = {}
    for ln, text in logical_lines(path):
        m = IOC_RE.search(text)
        if not m:
            continue
        name, body = m.group(1), m.group(2)
        c = CALL_RE.search(body)
        if c:
            res[name] = (int(c.group(1), 0), c.group(2).strip(), ln)
    return res


def structs(path):
    """提取 struct xxx { ... }; 的字段名。

    注意：PoC 大量使用 `uint64_t a, b;` 一行多字段声明，必须按逗号切分，
    否则会把 12 字段的 kgsl_gpu_command 误判成 6 字段。
    """
    src = open(path, encoding="utf-8", errors="replace").read()
    res = {}
    for m in re.finditer(r"struct\s+(kgsl_[a-z0-9_]+)\s*\{(.*?)\n\}", src, re.S):
        name, body = m.group(1), m.group(2)
        fields = []
        for raw in body.splitlines():
            line = raw.strip()
            if not line or line.startswith("/*") or line.startswith("*") or \
               line.startswith("//") or line.startswith("#"):
                continue
            line = line.split("/*")[0].split("//")[0].strip()
            if not line.endswith(";"):
                continue
            decl = re.sub(r"\b__user\b", "", line[:-1]).strip()
            parts = [p.strip() for p in decl.split(",") if p.strip()]
            if not parts:
                continue
            ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", parts[0])
            if len(ids) >= 2:
                fields.append(ids[-1])
            for p in parts[1:]:
                ids2 = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", p)
                if ids2:
                    fields.append(ids2[0])
        res[name] = fields
    return res


def load_syms():
    names = set()
    for line in open(SYMS, encoding="latin1"):
        if len(line) >= 13:
            names.add(line[12:].rstrip("\n"))
    return names


poc = ioctls(POC)
uapi = ioctls(UAPI)
ps, us = structs(POC), structs(UAPI)
syms = load_syms()

L = []
add = L.append
add("# CVE-2023-33107 → 4.9.227 适配对照表")
add("# 生成: python tools/f16_adapt_compare.py")
add("# PoC : src_ref/poc_ex.c (keto0422/CVE-2023-33107@main, 88,079 B)")
add("# UAPI: src_ref/kgsl_4.9/msm_kgsl.h (realme 官方 4.9, 50,115 B)")
add("")

add("## 1. ioctl 编号对照")
add("| ioctl | PoC (nr, struct) | 4.9 UAPI (nr, struct) | 判定 |")
add("|---|---|---|---|")
for name in sorted(set(poc) | set(uapi)):
    p, u = poc.get(name), uapi.get(name)
    ps_ = f"0x{p[0]:02x} / {p[1]}" if p else "—"
    us_ = f"0x{u[0]:02x} / {u[1]}" if u else "— (本 UAPI 无此宏)"
    if p and u:
        ok = "一致" if p[0] == u[0] and p[1] == u[1] else "**差异**"
    elif p and not u:
        ok = "PoC 自定；4.9 头文件未导出该宏（需查内核私有定义）"
    else:
        ok = "4.9 有、PoC 未用"
    add(f"| `{name}` | {ps_} | {us_} | {ok} |")

add("")
add("## 2. 关键结构体字段对照")
for name in sorted(set(ps) & set(us)):
    a, b = ps[name], us[name]
    add(f"- `struct {name}`: PoC {len(a)} 字段 / 4.9 {len(b)} 字段；"
        f"{'一致' if a == b else '**需逐字段核对**'}")
    if a != b:
        add(f"    - PoC : {a}")
        add(f"    - 4.9 : {b}")
add("")
add("仅 PoC 定义: " + ", ".join(f"`{x}`" for x in sorted(set(ps) - set(us))) or "（无）")
add("仅 4.9 定义: " + ", ".join(f"`{x}`" for x in sorted(set(us) - set(ps))) or "（无）")

add("")
add("## 3. F.16 符号表中相关函数存在性（仅存在性，偏移不可用 → §12）")
KEYS = [
    "kgsl_ioctl_gpuobj_alloc", "kgsl_ioctl_gpuobj_free", "kgsl_ioctl_gpuobj_import",
    "kgsl_ioctl_gpuobj_info", "kgsl_ioctl_map_user_mem", "kgsl_ioctl_gpu_command",
    "kgsl_ioctl_drawctxt_create", "kgsl_mmu_set_svm_region", "kgsl_mmu_find_svm_region",
    "kgsl_iommu_map", "kgsl_iommu_unmap", "kgsl_iommu_set_svm_region",
    "arm_lpae_map_sg", "arm_lpae_init_pte", "arm_lpae_unmap",
    "kgsl_mem_entry_detach_process", "kgsl_mem_entry_destroy_deferred",
    "kgsl_mmu_put_gpuaddr", "kgsl_shrinker", "kgsl_mem_entry_put_deferred",
]
for k in KEYS:
    add(f"- `{k}`: {'存在' if k in syms else '**不存在**'}")

add("")
add("## 4. PoC 硬编码常量（4.9.227 / SDM710 上必须重新标定）")
for ln, text in logical_lines(POC):
    m = re.match(r"\s*#define\s+([A-Z0-9_]+)\s+(0x[0-9a-fA-F]+U?L?L?|\d+)", text)
    if m and int(m.group(1) is not None):
        name, val = m.group(1), m.group(2)
        if any(t in name for t in ("START", "SIZE", "BASE", "STRIDE", "COUNT",
                                   "MAX", "ADDR", "SPRAY", "OFFSET", "TARGET")):
            add(f"- `{name}` = {val}  (line {ln})")

open(OUT, "w", encoding="utf-8").write("\n".join(L) + "\n")
print("\n".join(L))
