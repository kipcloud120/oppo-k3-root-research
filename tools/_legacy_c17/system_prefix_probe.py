#!/usr/bin/env python3
"""
Bounded prefix probe of system.new.dat.br.

Goal: confirm where the ramdisk/rootfs lives on this device (legacy SAR?).
Only the FIRST few MB of the 2.35 GB entry are fetched via HTTP Range;
the ozip per-block AES headers are decrypted locally, the ZIP deflate stream
is decompressed incrementally, and brotli is decompressed incrementally too.

Output: unpacked_C17/system_prefix.bin (first blocks of the system partition)
        unpacked_C17/system_prefix_report.json
"""
import os, sys, struct, zlib, subprocess, tempfile, json, binascii, hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ozip_range_extract as oz

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "unpacked_C17")
URL = oz.DEFAULT_URL
REF = oz.DEFAULT_REFERER
KEY = bytes.fromhex("ACAC1E13A12531AE4A1B21BB31C13C21")
HDR = oz.HDR
FETCH = 32 * 1024 * 1024    # compressed bytes to fetch (bounded prefix)

def fetch_with_retry(start, end, tries=5):
    last = None
    for i in range(tries):
        try:
            return oz.curl_range(URL, REF, start, end)
        except Exception as e:
            last = e
            print("  retry %d: %s" % (i + 1, str(e)[:120]))
    raise last

def main():
    head = oz.curl_head(URL, REF)
    total = int(head["content-length"])
    tail = fetch_with_retry(total - 256 * 1024, total - 1)
    cd = oz.parse_central_directory(tail, total - 256 * 1024, KEY)
    m = cd["entries"]["system.new.dat.br"]
    print("entry: csize=%d usize=%d lho=%d method=%d" %
          (m["csize"], m["usize"], m["lho"], m["method"]))

    lho = m["lho"]
    a = oz.aligned_start(lho + HDR)
    b = lho + HDR + 30 + 512 + min(FETCH, m["csize"]) - 1
    print("fetching physical range %d..%d (%d bytes)" % (a, b, b - a + 1))
    raw = fetch_with_retry(a, b)
    buf = bytearray(raw)
    oz.decrypt_block_headers(buf, a, KEY)
    base = a - HDR
    i = lho - base
    if buf[i:i + 4] != b"PK\x03\x04":
        raise RuntimeError("bad local file header")
    nlen, elen = struct.unpack_from("<HH", buf, i + 26)
    ds = i + 30 + nlen + elen
    comp = bytes(buf[ds:ds + FETCH])
    print("local header: nlen=%d elen=%d data starts at logical %d" % (nlen, elen, lho + 30 + nlen + elen))

    d = zlib.decompressobj(-15)
    br_prefix = d.decompress(comp)
    print("deflate -> brotli prefix: %d bytes" % len(br_prefix))
    open(os.path.join(OUT, "system_prefix.br"), "wb").write(br_prefix)

    # brotli CLI streaming decompression of a truncated stream:
    # it emits the decompressed prefix before failing on truncation.
    p = subprocess.run(["brotli", "-d", "-c", os.path.join(OUT, "system_prefix.br")],
                       capture_output=True)
    data = p.stdout
    print("brotli -> system data prefix: %d bytes (rc=%d, stderr=%s)" %
          (len(data), p.returncode, p.stderr.decode(errors="replace").strip()[:120]))
    open(os.path.join(OUT, "system_prefix.bin"), "wb").write(data)

    rep = {
        "entry": {k: m[k] for k in ("csize", "usize", "lho", "method", "crc")},
        "fetched_compressed_bytes": len(comp),
        "brotli_prefix_bytes": len(br_prefix),
        "system_prefix_bytes": len(data),
        "sha256_system_prefix": hashlib.sha256(data).hexdigest(),
    }
    if len(data) >= 2048:
        rep["ext4_superblock_magic_at_0x438"] = data[0x438:0x43a].hex()
        rep["ext4_superblock_detected"] = (data[0x438:0x43a] == b"\x53\xef")
        if rep["ext4_superblock_detected"]:
            sb = data[1024:1024 + 1024]
            inodes = struct.unpack_from("<I", sb, 0)[0]
            blocks_lo = struct.unpack_from("<I", sb, 4)[0]
            bsize = 1024 << struct.unpack_from("<I", sb, 24)[0]
            inodesize = struct.unpack_from("<H", sb, 88)[0]
            first_ino = struct.unpack_from("<I", sb, 84)[0]
            rep["ext4"] = {"inode_count": inodes, "block_count": blocks_lo,
                           "block_size": bsize, "inode_size": inodesize,
                           "first_ino": first_ino,
                           "volume_label": sb[120:136].rstrip(b"\0").decode("ascii", "replace"),
                           "last_mounted": sb[136:200].rstrip(b"\0").decode("ascii", "replace")}
    # directory entry name scanning (ext4 dirent stores plain names)
    import re
    names = {}
    for kw in [b"init", b"init.rc", b"fstab", b"system", b"vendor", b"sbin",
               b"default.prop", b"ueventd", b"recovery-from-boot", b"build.prop",
               b"magisk", b"su", b"plat_file_contexts", b"sepolicy"]:
        offs = [x.start() for x in re.finditer(re.escape(kw), data[:min(len(data), 8 * 1024 * 1024)])]
        names[kw.decode()] = len(offs)
    rep["keyword_hits_in_prefix"] = names
    # show printable strings in first 64 KiB (root directory area)
    strs = [x.group().decode("ascii", "replace") for x in
            re.finditer(rb"[ -~]{4,}", data[:65536])]
    rep["first_64k_strings_sample"] = strs[:80]
    json.dump(rep, open(os.path.join(OUT, "system_prefix_report.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print(json.dumps(rep, ensure_ascii=False, indent=2)[:4000])

if __name__ == "__main__":
    main()
