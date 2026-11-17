#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ota_entry_range.py — 只读 OTA ZIP 的中央目录，列出条目在整包中的字节区间。

用于"只取需要的条目、不下整包"：给定 URL 与条目名，输出 [data_start, data_end]，
可直接喂给 tools/dl_range.py。

用法:
  python tools/ota_entry_range.py URL [关键字...]
  例: python tools/ota_entry_range.py URL vendor
      -> 打印所有含 "vendor" 的条目及其区间

无第三方依赖；默认直连（不走代理）。
"""
import struct
import sys
import urllib.request

EOCD_SIG = b"PK\x05\x06"
EOCD64_LOC = b"PK\x06\x07"


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def fetch(url, lo, hi, op, tries=5):
    req = urllib.request.Request(url, headers={"Range": f"bytes={lo}-{hi}"})
    last = None
    for _ in range(tries):
        try:
            with op.open(req, timeout=90) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            last = e
    raise last


def total_size(url, op):
    req = urllib.request.Request(url, headers={"Range": "bytes=0-0"})
    with op.open(req, timeout=60) as r:
        cr = r.headers.get("Content-Range", "")
        return int(cr.split("/")[1])


def main():
    url = sys.argv[1]
    keys = [k.lower() for k in sys.argv[2:]] or ["vendor"]
    op = opener()
    size = total_size(url, op)
    print(f"remote size = {size} bytes ({size/1048576:.1f} MiB)")

    tail = fetch(url, max(0, size - 65536), size - 1, op)
    i = tail.rfind(EOCD_SIG)
    if i < 0:
        sys.exit("EOCD not found")
    (_, disk, cd_disk, n_disk, n_total, cd_size, cd_off,
     comment_len) = struct.unpack("<IHHHHIIH", tail[i:i + 22])
    print(f"entries={n_total} cd_size={cd_size} cd_off={cd_off}")

    if cd_off == 0xFFFFFFFF or n_total == 0xFFFF:
        j = tail.rfind(EOCD64_LOC)
        if j < 0:
            sys.exit("zip64 locator not found")
        (eocd64_off,) = struct.unpack("<Q", tail[j + 8:j + 16])
        rec = fetch(url, eocd64_off, eocd64_off + 55, op)
        n_total, cd_size, cd_off = struct.unpack("<QQQ", rec[32:56])
        print(f"[zip64] entries={n_total} cd_size={cd_size} cd_off={cd_off}")

    cd = fetch(url, cd_off, cd_off + cd_size - 1, op)
    pos = 0
    hits = []
    while pos + 46 <= len(cd) and cd[pos:pos + 4] == b"PK\x01\x02":
        (_, _, _, _, method, _, _, crc, csize, usize, nlen, elen,
         clen, _, _, _, lho) = struct.unpack("<IHHHHHHIIIHHHHHII", cd[pos:pos + 46])
        name = cd[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
        pos += 46 + nlen + elen + clen
        low = name.lower()
        if any(k in low for k in keys):
            hits.append((name, lho, csize, usize, method))

    for name, lho, csize, usize, method in hits:
        lh = fetch(url, lho, lho + 29, op)
        if lh[:4] != b"PK\x03\x04":
            print(f"!! {name}: bad local header")
            continue
        nlen, elen = struct.unpack("<HH", lh[26:30])
        start = lho + 30 + nlen + elen
        print(f"{start}\t{start + csize - 1}\t{csize}\t{usize}\t{method}\t{name}")


if __name__ == "__main__":
    main()
