#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ext4_find_offset.py — 在 ext4 镜像里把「字节偏移」映射回「文件路径」。

用途：当你在 system.img / vendor.img 里 grep 到一个字符串偏移、但不知道它属于哪个
文件（7z 只能按名提取，不能按偏移反查）时用它定位，然后用 7z 提取该路径。

用法:
  python tools/ext4_find_offset.py IMAGE 0xf009d7e

限制：只读；支持 4K/1K 块、extent 树（depth 0 与 1）、64bit 组描述符；
不处理 inline_data / bigalloc。
"""
import struct
import sys


class Ext4:
    def __init__(self, path):
        self.f = open(path, "rb")
        sb = self._read(1024, 1024)
        self.inodes_count = struct.unpack_from("<I", sb, 0)[0]
        self.first_data_block = struct.unpack_from("<I", sb, 20)[0]
        log_bs = struct.unpack_from("<I", sb, 24)[0]
        self.bs = 1024 << log_bs
        self.blocks_per_group = struct.unpack_from("<I", sb, 32)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 40)[0]
        self.inode_size = struct.unpack_from("<H", sb, 88)[0]
        self.desc_size = struct.unpack_from("<H", sb, 254)[0] or 32
        incompat = struct.unpack_from("<I", sb, 96)[0]
        if not (incompat & 0x40):
            raise SystemExit("不是 ext4（无 EXTENTS 特性）")
        self.gdt_off = (self.first_data_block + 1) * self.bs
        ngroups = (self.inodes_count + self.inodes_per_group - 1) // self.inodes_per_group
        self.groups = ngroups

    def _read(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def inode_table(self, g):
        d = self._read(self.gdt_off + g * self.desc_size, 32)
        return struct.unpack_from("<I", d, 8)[0]

    def inode(self, ino):
        g = (ino - 1) // self.inodes_per_group
        idx = (ino - 1) % self.inodes_per_group
        off = self.inode_table(g) * self.bs + idx * self.inode_size
        return self._read(off, self.inode_size)

    def extents(self, inode):
        """返回 [(logical, physical, length)]"""
        flags = struct.unpack_from("<I", inode, 32)[0]
        if not (flags & 0x80000):
            # 退化：直接块（只取前 12 个）
            out = []
            for i in range(12):
                b = struct.unpack_from("<I", inode, 40 + i * 4)[0]
                if b:
                    out.append((i, b, 1))
            return out
        node = inode[40:100]
        return self._walk(node)

    def _walk(self, node):
        magic, entries, _max, depth = struct.unpack_from("<HHHH", node, 0)
        if magic != 0xF30A:
            return []
        out = []
        for i in range(entries):
            off = 12 + i * 12
            lblk, ln, hi, lo = struct.unpack_from("<IHHI", node, off)
            phys = (hi << 32) | lo
            if depth == 0:
                out.append((lblk, phys, ln))
            else:
                blk = self._read(phys * self.bs, self.bs)
                out.extend(self._walk(blk))
        return out

    def data(self, inode, size):
        buf = bytearray(size)
        for lblk, phys, ln in self.extents(inode):
            start = lblk * self.bs
            if start >= size:
                continue
            chunk = self._read(phys * self.bs, min(ln * self.bs, size - start))
            buf[start:start + len(chunk)] = chunk
        return bytes(buf)

    def size_of(self, inode):
        lo = struct.unpack_from("<I", inode, 4)[0]
        hi = struct.unpack_from("<I", inode, 108)[0]
        return (hi << 32) | lo

    def mode_of(self, inode):
        return struct.unpack_from("<H", inode, 0)[0]

    def build_paths(self):
        """inode -> 绝对路径（只走目录）"""
        names = {2: "/"}
        pending = [2]
        seen = {2}
        while pending:
            dino = pending.pop()
            inode = self.inode(dino)
            if (self.mode_of(inode) & 0xF000) != 0x4000:
                continue
            size = self.size_of(inode)
            data = self.data(inode, size)
            pos = 0
            while pos + 8 <= len(data):
                ino, rec, nlen, ftype = struct.unpack_from("<IHBB", data, pos)
                if rec < 8:
                    break
                if ino and nlen:
                    nm = data[pos + 8:pos + 8 + nlen].decode("utf-8", "replace")
                    if nm not in (".", ".."):
                        path = (names[dino].rstrip("/") + "/" + nm)
                        names.setdefault(ino, path)
                        if ftype == 2 and ino not in seen:
                            seen.add(ino)
                            pending.append(ino)
                pos += rec
        return names

    def who_owns(self, byte_off, paths):
        blk = byte_off // self.bs
        for ino in range(1, min(self.inodes_count, 200000) + 1):
            inode = self.inode(ino)
            if not inode or inode[0] == 0:
                continue
            for lblk, phys, ln in self.extents(inode):
                if phys <= blk < phys + ln:
                    return ino, paths.get(ino, f"<inode {ino}>")
        return None, None


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    img, off = sys.argv[1], int(sys.argv[2], 0)
    fs = Ext4(img)
    print(f"block_size={fs.bs} inodes={fs.inodes_count} groups={fs.groups} "
          f"inode_size={fs.inode_size} target_block={off // fs.bs}")
    print("building directory tree ...")
    paths = fs.build_paths()
    print(f"mapped inodes: {len(paths)}")
    ino, path = fs.who_owns(off, paths)
    if ino:
        print(f"OWNER: inode={ino}  path={path}")
        inode = fs.inode(ino)
        print(f"       size={fs.size_of(inode)} mode={oct(fs.mode_of(inode))}")
    else:
        print("no owner found (offset may be in metadata / free space)")


if __name__ == "__main__":
    main()
