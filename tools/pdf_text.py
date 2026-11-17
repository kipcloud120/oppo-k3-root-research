#!/usr/bin/env python3
"""极简 PDF 文本提取（仅用于本项目内部取论文正文，依赖 zlib + 正则）"""
import re
import sys
import zlib

path = sys.argv[1] if len(sys.argv) > 1 else ".build/refs/racing_lock.pdf"
data = open(path, "rb").read()

chunks = []
for m in re.finditer(rb"stream\r?\n", data):
    start = m.end()
    end = data.find(b"endstream", start)
    if end < 0:
        continue
    try:
        raw = zlib.decompress(data[start:end])
    except Exception:
        continue
    parts = []
    for mm in re.finditer(rb"\((?:\\.|[^\\()])*\)", raw):
        s = mm.group()[1:-1]
        s = s.replace(b"\\(", b"(").replace(b"\\)", b")")
        s = s.replace(b"\\\\", b"\\")
        parts.append(s.decode("latin-1"))
    if parts:
        chunks.append("".join(parts))

text = "\n".join(chunks)
out = path.rsplit(".", 1)[0] + ".txt"
open(out, "w", encoding="utf-8").write(text)
print("chars:", len(text), "->", out)
for kw in ["binder_proc", "inner_lock", "reclaim", "msg_msg", "pipe", "spin_lock",
           "kmalloc", "offset", "kmem_cache", "UAF", "race"]:
    print(f"  {kw:14s} {text.lower().count(kw.lower())}")
print("\n--- head ---\n" + text[:500])
