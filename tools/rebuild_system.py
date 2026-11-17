#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rebuild_system.py — brotli 解压 system.new.dat.br -> system.new.dat

用法: python rebuild_system.py INPUT.br OUTPUT.dat
分块流式解压，避免一次性占用过多内存。
"""
import sys
import brotli


def main():
    src, dst = sys.argv[1], sys.argv[2]
    d = brotli.Decompressor()
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        total = 0
        while True:
            chunk = fi.read(1024 * 1024)
            if not chunk:
                break
            out = d.process(chunk)
            if out:
                fo.write(out)
                total += len(out)
    print(f"decompressed {total} bytes ({total/1048576:.1f} MiB) -> {dst}")


if __name__ == "__main__":
    main()
