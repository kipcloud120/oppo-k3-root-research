#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sdat2img.py — Android OTA transfer.list + new.dat -> ext4 system.img

用法: python sdat2img.py TRANSFER_LIST NEW_DAT OUT_IMG

F.16 实测格式（已用数据自证，v4，逗号分隔，范围编码）：
  行0..3 = 版本 / total_blocks / stash / block_size(0 -> 4096)
  new <n>,<s1>,<e1>,...   n=数字个数(=范围数*2)，每对 [s,e) 是目标块范围
  zero/erase <n>,<s1>,<e1>,...  这些块范围写零
  move                    全量包无（已验证）

关键：new.dat 是**固定块长** bsize 字节的原始数据流，无长度前缀。
  自证：len(new.dat) == sum(e-s for new ranges) * 4096，差值 0。
  每个 new 块从 new.dat 顺序读 bsize 字节，写到目标块 (blk*bsize)。
"""
import sys


def parse(line):
    parts = line.replace(",", " ").split()
    return parts[0], [int(x) for x in parts[1:]]


def ranges(nums):
    assert len(nums) - 1 == nums[0], (nums[0], len(nums) - 1)
    body = nums[1:]
    assert len(body) % 2 == 0
    return [(body[i], body[i + 1]) for i in range(0, len(body), 2)]


def main():
    tl, dat, outp = sys.argv[1], sys.argv[2], sys.argv[3]
    lines = [x.strip() for x in open(tl, encoding="utf-8", errors="replace") if x.strip()]
    total = int(lines[1]); bsize = int(lines[3]) or 4096
    print(f"version={lines[0]} total_blocks={total} bsize={bsize}", flush=True)

    # 校验 new.dat 大小与 new 块数一致
    expect = sum(b - a for ln in lines[4:] if ln.startswith("new")
                 for a, b in ranges(parse(ln)[1])) * bsize
    import os
    actual = os.path.getsize(dat)
    print(f"new.dat size={actual} expected={expect} diff={actual-expect}", flush=True)
    if actual != expect:
        raise SystemExit("size mismatch, abort")

    fdat = open(dat, "rb")
    fout = open(outp, "wb")
    fout.truncate(total * bsize)
    n_new = n_zero = 0
    for ln in lines[4:]:
        cmd, nums = parse(ln)
        if cmd == "new":
            for s, e in ranges(nums):
                for blk in range(s, e):
                    data = fdat.read(bsize)
                    if len(data) != bsize:
                        raise ValueError(f"truncated at block {blk}")
                    fout.seek(blk * bsize)
                    fout.write(data)
                    n_new += 1
        elif cmd in ("zero", "erase"):
            for s, e in ranges(nums):
                fout.seek(s * bsize)
                fout.write(b"\0" * ((e - s) * bsize))
                n_zero += e - s
        elif cmd == "move":
            raise SystemExit("move present; unsupported")
        else:
            raise SystemExit(f"unknown cmd {cmd}")
    fout.flush(); fout.close(); fdat.close()
    print(f"done: new_blocks={n_new} zero_blocks={n_zero} -> {outp} ({total*bsize/1048576:.0f} MiB)", flush=True)


if __name__ == "__main__":
    main()
