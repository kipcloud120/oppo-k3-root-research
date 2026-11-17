#!/usr/bin/env python3
"""Navigate the sparse ext4 system rootfs and dump boot-critical files."""
import os, struct, json, bisect, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "unpacked_C17")
d = open(os.path.join(OUT, "system_prefix.bin"), "rb").read()
tl = open(os.path.join(OUT, "ota_meta", "system.transfer.list"), encoding="utf-8",
          errors="replace").read().splitlines()
BS = 4096
ranges, src = [], 0
for line in tl[4:]:
    if line.startswith("new "):
        nums = [int(x) for x in line[4:].split(",")]
        pairs = nums[1:1 + nums[0]]
        for i in range(0, len(pairs), 2):
            ds, de = pairs[i], pairs[i + 1]
            ranges.append((ds, de, src)); src += de - ds
starts = [r[0] for r in ranges]

def read_block(n):
    i = bisect.bisect_right(starts, n) - 1
    if i < 0: return None
    ds, de, ss = ranges[i]
    if n >= de: return None
    s = ss + (n - ds)
    if (s + 1) * BS > len(d): return None
    return d[s * BS:(s + 1) * BS]

sb = read_block(0)[1024:2048]
u16 = lambda o: struct.unpack_from("<H", sb, o)[0]
u32 = lambda o: struct.unpack_from("<I", sb, o)[0]
bs = 1024 << u32(0x18); inode_size = u16(0x58)
feat = u32(0x64); desc_size = u16(0xFE) if feat & 0x80 else 32
gd = read_block(u32(0x14) + 1)[:desc_size]
ino_tbl = struct.unpack_from("<I", gd, 8)[0]
if desc_size >= 64 and feat & 0x80:
    ino_tbl |= struct.unpack_from("<I", gd, 0x28)[0] << 32

def inode(n):
    off = ino_tbl * bs + (n - 1) * inode_size
    blk, within = divmod(off, bs)
    buf = read_block(blk)
    if buf is None: return None
    if within + inode_size > bs:
        nb = read_block(blk + 1)
        if nb: buf += nb
    return buf[within:within + inode_size]

def extents(ino):
    b = ino[0x28:0x28 + 60]
    magic, entries, _, depth = struct.unpack_from("<HHHH", b, 0)
    if magic != 0xF30A: return []
    out = []
    if depth == 0:
        for i in range(min(entries, 4)):
            eb, ln, hi, lo = struct.unpack_from("<IHHI", b, 12 + i * 12)
            out.append((eb, ln, (hi << 32) | lo))
    else:
        _, _, _, hi, lo = struct.unpack_from("<IHHI", b, 12)
        nb = read_block((hi << 32) | lo)
        if nb:
            _, n2, _, _ = struct.unpack_from("<HHHH", nb, 0)
            for i in range(min(n2, 100)):
                eb, ln, h2, l2 = struct.unpack_from("<IHHI", nb, 12 + i * 12)
                out.append((eb, ln, (h2 << 32) | l2))
    return out

def read_file(ino, size, limit=4 * 1024 * 1024):
    if size > limit: return None
    parts = []
    for eb, ln, phys in extents(ino):
        for k in range(min(ln, 1024)):
            b = read_block(phys + k)
            if b is None: return b"".join(parts)[:size] or None
            parts.append(b)
    return b"".join(parts)[:size]

def read_dir(n):
    ino = inode(n)
    if ino is None: return []
    sz = struct.unpack_from("<I", ino, 4)[0]
    ents = []
    for eb, ln, phys in extents(ino):
        for k in range(min(ln, 8)):
            blk = read_block(phys + k)
            if blk is None: continue
            p = 0
            while p + 8 <= len(blk):
                inum, rl = struct.unpack_from("<IH", blk, p)
                if rl < 8 or p + rl > len(blk): break
                nl, ft = blk[p + 6], blk[p + 7]
                name = blk[p + 8:p + 8 + nl].decode("utf-8", "replace")
                if inum and nl: ents.append((name, inum, ft))
                p += rl
    return ents

def resolve(path):
    n = 2
    for seg in [x for x in path.split("/") if x]:
        ents = read_dir(n)
        hit = [e for e in ents if e[0] == seg]
        if not hit: return None
        n = hit[0][1]
    return n

def symlink_target(ino):
    return ino[0x28:0x28 + 60].split(b"\0")[0].decode("utf-8", "replace")

# dump every regular file in / that is small
os.makedirs(os.path.join(OUT, "system_root"), exist_ok=True)
root_files = {}
for name, inum, ft in read_dir(2):
    ino = inode(inum)
    if ino is None: continue
    mode = struct.unpack_from("<H", ino, 0)[0]
    sz = struct.unpack_from("<I", ino, 4)[0]
    ft_i = mode >> 12
    if ft_i == 10:
        root_files[name] = {"type": "symlink", "target": symlink_target(ino)}
    elif ft_i == 8:
        blob = read_file(ino, sz)
        # avoid persisting a truncated file when its blocks lie beyond the prefix
        if blob is not None and len(blob) == sz:
            open(os.path.join(OUT, "system_root", name), "wb").write(blob)
            root_files[name] = {"type": "file", "size": sz,
                                "sha256": hashlib.sha256(blob).hexdigest()}

print("=== root files dumped: %d ===" % len(root_files))
for k, v in sorted(root_files.items()): print("  %-28s %s" % (k, v))

print("\n=== key path resolution ===")
for p in ["system/etc/prop.default", "system/bin/init", "system/etc/selinux/plat_file_contexts",
          "system/etc/fstab-at.qcom", "vendor/etc/fstab.qcom"]:
    n = resolve(p)
    print("  %-46s ino=%s" % (p, n))
    if n:
        ino = inode(n); sz = struct.unpack_from("<I", ino, 4)[0]
        blob = read_file(ino, sz, limit=2 * 1024 * 1024)
        if blob:
            fn = p.replace("/", "_")
            open(os.path.join(OUT, "system_root", fn), "wb").write(blob)
            print("      size=%d sha256=%s" % (sz, hashlib.sha256(blob).hexdigest()))

json.dump(root_files, open(os.path.join(OUT, "system_root_files.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)
