#!/usr/bin/env python3
"""
Parse the ext4 root directory from a sparse prefix of the system partition.

The OTA uses a BLOCK update: system.new.dat contains only "new" blocks, and
system.transfer.list maps them onto destination partition blocks. This script
builds that mapping so ext4 metadata can be read by *destination* block number.
"""
import os, struct, json, hashlib, bisect

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "unpacked_C17")
d = open(os.path.join(OUT, "system_prefix.bin"), "rb").read()
tl = open(os.path.join(OUT, "ota_meta", "system.transfer.list"), "r",
          encoding="utf-8", errors="replace").read().splitlines()
version, total_blocks = int(tl[0]), int(tl[1])
BS = 4096
ranges = []          # (dest_start, dest_end, src_start)
src = 0
for line in tl[4:]:
    if not line.startswith("new "):
        continue
    nums = [int(x) for x in line[4:].split(",")]
    cnt = nums[0]
    pairs = nums[1:1 + cnt]
    for i in range(0, len(pairs), 2):
        ds, de = pairs[i], pairs[i + 1]
        n = de - ds
        ranges.append((ds, de, src))
        src += n
print("transfer.list v%d, total_blocks=%d, new ranges=%d, new blocks=%d" %
      (version, total_blocks, len(ranges), src))
starts = [r[0] for r in ranges]

def dest_to_src(n):
    i = bisect.bisect_right(starts, n) - 1
    if i < 0: return None
    ds, de, ss = ranges[i]
    if n >= de: return None
    return ss + (n - ds)

def read_block(n):
    s = dest_to_src(n)
    if s is None or (s + 1) * BS > len(d): return None
    return d[s * BS:(s + 1) * BS]

sb = read_block(0)
if sb is None: raise RuntimeError("superblock not available")
# superblock lives at byte 1024 of the first block for 4K fs
sb = sb[1024:2048]
u16 = lambda o: struct.unpack_from("<H", sb, o)[0]
u32 = lambda o: struct.unpack_from("<I", sb, o)[0]
inodes, blocks = u32(0), u32(4)
first_data_block, log_bs = u32(0x14), u32(0x18)
bs = 1024 << log_bs
bpg, ipg = u32(0x20), u32(0x28)
first_ino, inode_size = u32(0x54), u16(0x58)
feat_incompat = u32(0x64)
desc_size = u16(0xFE) if (feat_incompat & 0x80) else 32
if desc_size < 32: desc_size = 32
print("ext4: blocks=%d inodes=%d bs=%d bpg=%d ipg=%d inode_size=%d desc_size=%d incompat=0x%x"
      % (blocks, inodes, bs, bpg, ipg, inode_size, desc_size, feat_incompat))
print("      volume_label=%r last_mounted=%r" %
      (sb[120:136].rstrip(b"\0").decode(), sb[136:200].rstrip(b"\0").decode()))

gdt_block = first_data_block + 1
gd = read_block(gdt_block)[:desc_size]
blk_bmp, ino_bmp, ino_tbl = struct.unpack_from("<III", gd, 0)
if desc_size >= 64 and (feat_incompat & 0x80):
    ino_tbl |= struct.unpack_from("<I", gd, 0x28)[0] << 32
print("group0: block_bitmap=%d inode_bitmap=%d inode_table=%d" % (blk_bmp, ino_bmp, ino_tbl))

def inode(n):
    off = ino_tbl * bs + (n - 1) * inode_size
    blk, within = divmod(off, bs)
    buf = read_block(blk)
    if buf is None: return b"\0" * inode_size
    if within + inode_size > bs:
        nb = read_block(blk + 1)
        if nb: buf += nb
    return buf[within:within + inode_size]

def extents(ino):
    b = ino[0x28:0x28 + 60]
    magic, entries, mx, depth = struct.unpack_from("<HHHH", b, 0)
    out = []
    if magic != 0xF30A: return out, magic, depth
    if depth == 0:
        for i in range(min(entries, 4)):
            eb, ln, hi, lo = struct.unpack_from("<IHHI", b, 12 + i * 12)
            out.append((eb, ln, (hi << 32) | lo))
    else:
        _, _, _, hi, lo = struct.unpack_from("<IHHI", b, 12)
        node = ((hi << 32) | lo) * bs
        nb = read_block((hi << 32) | lo)
        if nb is None: return out, magic, depth
        m2, n2, _, dep2 = struct.unpack_from("<HHHH", nb, 0)
        for i in range(min(n2, 100)):
            eb, ln, h2, l2 = struct.unpack_from("<IHHI", nb, 12 + i * 12)
            out.append((eb, ln, (h2 << 32) | l2))
    return out, magic, depth

root = inode(2)
mode, size_lo, flags = struct.unpack_from("<H", root, 0)[0], struct.unpack_from("<I", root, 4)[0], struct.unpack_from("<I", root, 0x20)[0]
print("inode 2 (/): mode=0%o size=%d flags=0x%x" % (mode, size_lo, flags))
ex, magic, depth = extents(root)
print("root dir extents: magic=0x%x depth=%d %s" % (magic, depth, ex))

dirents = []
for eb, ln, phys in ex:
    for k in range(min(ln, 8)):
        blkdata = read_block(phys + k)
        if blkdata is None: continue
        p = 0
        while p + 8 <= len(blkdata):
            ino, rec_len = struct.unpack_from("<IH", blkdata, p)
            if rec_len < 8 or p + rec_len > len(blkdata): break
            name_len, ftype = blkdata[p + 6], blkdata[p + 7]
            name = blkdata[p + 8:p + 8 + name_len].decode("utf-8", "replace")
            if ino and name_len:
                dirents.append({"inode": ino, "type": ftype, "name": name})
            p += rec_len

print("\n=== ext4 root directory of system.img (%d entries) ===" % len(dirents))
for e in dirents: print("  ino=%-6d type=%d %s" % (e["inode"], e["type"], e["name"]))

os.makedirs(os.path.join(OUT, "system_root"), exist_ok=True)
extracted, symlinks = {}, {}
for e in dirents:
    nm = e["name"]
    if nm in (".", ".."): continue
    ino = inode(e["inode"])
    m2 = struct.unpack_from("<H", ino, 0)[0]
    sz = struct.unpack_from("<I", ino, 4)[0]
    ftype = m2 >> 12
    if ftype == 10:  # fast symlink
        symlinks[nm] = ino[0x28:0x28 + 60].split(b"\0")[0].decode("utf-8", "replace")
    if ftype == 8 and sz < 4 * 1024 * 1024:
        ex2, _, dep2 = extents(ino)
        if dep2 == 0 and ex2:
            _, _, phys = ex2[0]
            parts = []
            for k in range(min((sz + bs - 1) // bs, 1024)):
                b2 = read_block(phys + k)
                if b2 is None: break
                parts.append(b2)
            blob = b"".join(parts)[:sz]
            # only persist files whose blocks were fully present in the prefix
            if len(blob) == sz and nm in (
                    "init", "default.prop", "init.rc", "ueventd.rc", "fstab.qcom",
                    "init.environ.rc", "init.usb.rc", "init.zygote64.rc", "prop.default",
                    "build.prop", "sepolicy"):
                open(os.path.join(OUT, "system_root", nm), "wb").write(blob)
                extracted[nm] = {"inode": e["inode"], "size": sz,
                                 "sha256": hashlib.sha256(blob).hexdigest(),
                                 "head": blob[:16].hex()}

print("\n=== extracted root files ===")
for k, v in extracted.items(): print("  %-24s %s" % (k, v))
print("=== symlinks in root ===")
for k, v in symlinks.items(): print("  %-24s -> %s" % (k, v))

json.dump({"transfer_list": {"version": version, "total_blocks": total_blocks,
                             "new_ranges": len(ranges), "new_blocks": src,
                             "first_ranges": ranges[:6]},
           "ext4": {"blocks": blocks, "inodes": inodes, "block_size": bs,
                    "inodes_per_group": ipg, "inode_size": inode_size,
                    "desc_size": desc_size, "feat_incompat": hex(feat_incompat),
                    "volume_label": sb[120:136].rstrip(b"\0").decode(),
                    "last_mounted": sb[136:200].rstrip(b"\0").decode()},
           "root_inode": {"mode": oct(mode), "size": size_lo, "extents": ex},
           "root_dirents": dirents, "extracted": extracted, "symlinks": symlinks},
          open(os.path.join(OUT, "ext4_root_report.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)
