#!/usr/bin/env python3
# B 阶段：复检 boot.img kernel 段的 gzip 流完整性
#
# 目的：排除「节区/函数顺序重排」其实是解包假象的可能。检查：
#   1) boot header v1 字段与 kernel 段实际偏移
#   2) gzip member 数、每个 member 的 ISIZE / 解压长度 / unused_data
#   3) kernel 段尾部是否有 appended DTB 或未消费数据
#   4) 现有 kernel.decompressed 是否等于完整 gzip 输出（长度 + SHA256）
#   5) 解压结果内部是否有多个 Image header / ELF / DTB / gzip / 大块零填充
#   6) 入口跳转目标 0x1980000 与文件前部的实际内容分布
#
# 用法: python tools/f16_bootimg_check.py
import hashlib
import re
import struct
import zlib

import numpy as np

BOOT = "firmware_F16/boot.img"
DEC = "firmware_F16/kernel.decompressed"
D = open(BOOT, "rb").read()
E = open(DEC, "rb").read()
u32 = lambda o: struct.unpack_from("<I", D, o)[0]
u64 = lambda o: struct.unpack_from("<Q", D, o)[0]
eu64 = lambda o: struct.unpack_from("<Q", E, o)[0]

print(f"[*] boot.img=0x{len(D):x}  kernel.decompressed=0x{len(E):x} "
      f"sha256(E)={hashlib.sha256(E).hexdigest()[:16]}…")

print("\n=== 1. boot header v1 ===")
magic = D[:8]
ksz, rsz = u32(8), u32(0x10)
ssz = u32(0x18)
psz, hver = u32(0x24), u32(0x28)
osv = u32(0x2c)
hs = u32(0x670) if hver >= 1 else 0
koff = psz
if hs:
    koff = ((hs + psz - 1) // psz) * psz
print(f"    magic={magic!r}  kernel_size={ksz} (0x{ksz:x})  "
      f"ramdisk_size={rsz}  second_size={ssz}")
print(f"    page_size={psz}  header_version={hver}  os_version=0x{osv:x}  "
      f"header_size@0x670={hs} (0x{hs:x})")
print(f"    => kernel offset 0x{koff:x}")
kseg = D[koff:koff + ksz]
print(f"    kernel head 16B = {kseg[:16].hex()}  "
      f"(gzip magic? {kseg[:3] == bytes([0x1f, 0x8b, 0x08])})")

roff = ((koff + ksz + psz - 1) // psz) * psz
print(f"    ramdisk offset 0x{roff:x}；kernel→ramdisk 填充 {roff-(koff+ksz)} B")
pad = D[koff + ksz:roff]
print(f"    填充区非零字节数 = {sum(1 for b in pad if b)}")

print("\n=== 2. gzip member 逐个解压 ===")
buf = kseg
off = 0
total = bytearray()
members = []
while buf[:3] == bytes([0x1f, 0x8b, 0x08]):
    do = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = do.decompress(buf) + do.flush()
    except zlib.error as ex:
        print(f"    [!] member#{len(members)} 解压失败: {ex}")
        break
    consumed = len(buf) - len(do.unused_data)
    isize = (struct.unpack_from("<I", buf, consumed - 4)[0]
             if consumed >= 4 and do.eof else None)
    members.append((off, len(out), consumed, isize, do.eof, len(do.unused_data)))
    total += out
    off += consumed
    buf = do.unused_data
    if not do.eof:
        break
for i, (o, n, c, isz, eof, rest) in enumerate(members):
    print(f"    member#{i} @kernel+0x{o:x}: out=0x{n:x} ({n})  "
          f"consumed=0x{c:x}  ISIZE={isz} (0x{isz:x})" if isz is not None else
          f"    member#{i} @kernel+0x{o:x}: out=0x{n:x}  consumed=0x{c:x}  eof={eof}")
    print(f"        eof={eof}  unused_data={rest} B  size_match="
          f"{isz is not None and isz == (n & 0xffffffff)}")
print(f"    member 总数 = {len(members)}；累计解压 = 0x{len(total):x} ({len(total)})")
print(f"    与现有 kernel.decompressed 长度一致? {len(total) == len(E)}")
print(f"    与现有 kernel.decompressed SHA256 一致? "
      f"{hashlib.sha256(total).hexdigest() == hashlib.sha256(E).hexdigest()}")
print(f"    尾部剩余（非 gzip）数据 = {len(buf)} B；前 48B = {buf[:48].hex()}")
print(f"    尾部是 DTB magic? {buf[:4] == bytes([0xd0, 0x0d, 0xfe, 0xed])}")

gzpos = [m.start() for m in re.finditer(b"\x1f\x8b\x08", kseg)]
print(f"    kernel 段内 gzip magic 候选 {len(gzpos)} 处，前 8: "
      + " ".join(hex(koff + p) for p in gzpos[:8]))

print("\n=== 3. 解压结果内部结构 ===")
print(f"    head[0:0x40] = {E[:0x40].hex()}")
print(f"    text_offset=0x{eu64(8):x}  image_size=0x{eu64(0x10):x}  "
      f"flags=0x{eu64(0x18):x}  magic@0x38=0x{struct.unpack_from('<I',E,0x38)[0]:x}")
for pat, label in ((b"ARMd", "Image header magic"),
                   (b"\x7fELF", "ELF magic"),
                   (b"\xd0\x0d\xfe\xed", "DTB magic"),
                   (b"\x1f\x8b\x08", "gzip magic")):
    pos = [m.start() for m in re.finditer(re.escape(pat), E)]
    print(f"    {label}: {len(pos)} 处  " + " ".join(hex(p) for p in pos[:8]))

Z = np.frombuffer(E, dtype=np.uint8)
nz = np.nonzero(Z)[0]
gaps = np.diff(nz.astype(np.int64)) - 1
big = np.nonzero(gaps >= 0x10000)[0]
print(f"    连续零填充 >=0x10000 的区段 {len(big)} 处：")
for i in big[:12]:
    print(f"      0x{int(nz[i])+1:x} 长度 0x{int(gaps[i]):x} ({int(gaps[i])})")

print("\n=== 4. 入口与关键位置内容分布 ===")
for o in range(0, 0x6000, 0x800):
    ch = E[o:o + 0x800]
    print(f"    0x{o:06x}: nonzero {sum(1 for b in ch if b):4d}/2048  "
          f"first8={ch[:8].hex()}")
for o in (0x10a5f00, 0x10a6000, 0x197f000, 0x197ff00, 0x1980000,
          0x1988b40, len(E) - 0x40):
    if 0 <= o < len(E) - 16:
        print(f"    0x{o:08x}: {E[o:o+32].hex()}")

print("\n=== 5. 结论 ===")
ok_gzip = (len(members) == 1 and members[0][4] and
           members[0][3] == (members[0][1] & 0xffffffff))
ok_same = (len(total) == len(E) and
           hashlib.sha256(total).hexdigest() == hashlib.sha256(E).hexdigest())
print(f"    gzip 单 member 且 ISIZE 自洽 : {ok_gzip}")
print(f"    kernel.decompressed == 完整 gzip 输出 : {ok_same}")
print(f"    kernel 段尾部剩余 : {len(buf)} B（DTB/未消费数据）")
print(f"    解压结果内 Image header 数量 : "
      f"{len([m.start() for m in re.finditer(b'ARMd', E)])}")
if ok_gzip and ok_same:
    print("    => 解包链路完整，不存在截断/多 member 假象；"
          "§12 的「节区/函数顺序重排」结论成立，转 C（换物料/取源码）。")
else:
    print("    => 解包链路存在异常，需重建 kernel.decompressed 后重跑 f16_symmap.py。")
