#!/usr/bin/env python3
# 量化「realme X 官方 4.9 源码」与「F.16 kernel.decompressed」的同源性
# 方法：抽取 io-pgtable-arm.c 中所有字符串字面量（取到第一个转义序列前），
#       检查其在镜像中是否逐字存在。命中率高说明该驱动在本机基本未变，
#       因而源码可作为 pre-fix 判定的可靠依据。
import re

SRC = "src_ref/realmeX_master_io-pgtable-arm.c"
IMG = "firmware_F16/kernel.decompressed"
src = open(SRC, encoding="utf-8", errors="ignore").read()
D = open(IMG, "rb").read()
BS = chr(92)

strs = set()
for m in re.finditer(r'"([^"]*)"', src):
    s = m.group(1).split(BS)[0].strip()
    if len(s) >= 10:
        strs.add(s)

hit = sorted(s for s in strs if s.encode() in D)
miss = sorted(s for s in strs if s.encode() not in D)
print(f"[*] {SRC}")
print(f"[*] 字符串字面量(>=10字符, 去重) = {len(strs)}")
print(f"[*] 镜像中逐字命中 = {len(hit)}  命中率 = {len(hit)/max(1,len(strs)):.1%}")
print("\n--- 命中（同源证据）---")
for s in hit:
    print("   ", repr(s[:110]), " @", hex(D.find(s.encode())))
print("\n--- 未命中 ---")
for s in miss:
    print("   ", repr(s[:110]))
print("\n--- 关键标识 ---")
for b in (b"io-pgtable-arm",
          b"Cannot accommodate DMA offset for IOMMU page tables"):
    p = D.find(b)
    print(f"    {b[:50]!r}: count={D.count(b)} first={hex(p) if p >= 0 else '-'}")
