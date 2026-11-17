#!/usr/bin/env python3
"""
Deep static unpacker for OPPO K3 (PCGM00) C.17 boot.img / vbmeta.img.

Pure-Python, no external deps. Produces:
  unpacked_C17/
    boot_header.json          - full Android boot header v1/v2 decode
    kernel.bin                - raw kernel payload as stored
    kernel.decompressed       - decompressed kernel Image (if compressed)
    kernel_config.txt         - IKCFG_ST kernel .config (if present)
    initramfs.cpio            - extracted embedded initramfs (if present)
    initramfs/                - cpio contents extracted
    vbmeta_footer.json        - AVB footer decode
    vbmeta_header.json        - full vbmeta header + descriptor decode
    region_map.json           - byte-level layout of the 64 MiB image
    META-INF/...              - copies of OTA metadata texts
    deep_unpack_report.json   - consolidated findings
"""
import os, sys, json, struct, zlib, gzip, hashlib, io, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FW   = os.path.join(ROOT, "firmware_C17_root")
OUT  = os.path.join(ROOT, "unpacked_C17")
os.makedirs(OUT, exist_ok=True)

def sha(b): return hashlib.sha256(b).hexdigest()
def be32(b, o): return struct.unpack_from(">I", b, o)[0]
def be64(b, o): return struct.unpack_from(">Q", b, o)[0]
def le32(b, o): return struct.unpack_from("<I", b, o)[0]
def cstr(b):    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")

def jwrite(name, obj):
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def bwrite(name, b):
    with open(os.path.join(OUT, name), "wb") as f: f.write(b)

# ---------------------------------------------------------------- boot header
boot = open(os.path.join(FW, "boot.img"), "rb").read()
page = le32(boot, 36)
hdr_ver = le32(boot, 40)
os_ver  = le32(boot, 44)

H = {
    "magic":            boot[0:8].decode("ascii", "replace"),
    "kernel_size":      le32(boot, 8),
    "kernel_addr":      hex(le32(boot, 12)),
    "ramdisk_size":     le32(boot, 16),
    "ramdisk_addr":     hex(le32(boot, 20)),
    "second_size":      le32(boot, 24),
    "second_addr":      hex(le32(boot, 28)),
    "tags_addr":        hex(le32(boot, 32)),
    "page_size":        page,
    "header_version":   hdr_ver,
    "os_version_raw":   hex(os_ver),
    "os_version_decode": {
        "android_release": (os_ver >> 25) & 0x7f,
        "android_patch":   (os_ver >> 18) & 0x7f,
        "reserved":        (os_ver >> 11) & 0x7f,
        "spl_year":        2000 + ((os_ver >> 4) & 0x7f),
        "spl_month":       os_ver & 0xf,
    },
    "name":             cstr(boot[48:64]),
    "cmdline":          cstr(boot[64:576]),
    "id_sha1":          boot[576:608].hex(),
    "extra_cmdline":    cstr(boot[608:1632]),
}
if hdr_ver >= 1:
    H["recovery_dtbo_size"]   = le32(boot, 1632)
    H["recovery_dtbo_offset"] = struct.unpack_from("<Q", boot, 1636)[0]
    H["header_size"]          = le32(boot, 1644)
if hdr_ver >= 2:
    H["dtb_size"]  = le32(boot, 1648)
    H["dtb_addr"]  = hex(struct.unpack_from("<Q", boot, 1652)[0])
jwrite("boot_header.json", H)

def align(n, a=page): return ((n + a - 1) // a) * a

off = align(page)                       # header occupies 1 page (v1/v2 >= 1 page)
regions = []
def region(name, start, size, note=""):
    regions.append({"name": name, "offset": start, "size": size,
                    "sha256": sha(boot[start:start+size]) if size else None, "note": note})
    return start + align(size)

k_start = off
k_size  = H["kernel_size"]
k_end   = region("kernel", k_start, k_size, "compression detected separately")
off = k_end
r_start, r_size = off, H["ramdisk_size"]
region("ramdisk", r_start, r_size)
off += align(r_size)
s_start, s_size = off, H["second_size"]
region("second", s_start, s_size)
off += align(s_size)

kernel = boot[k_start:k_start + k_size]
bwrite("kernel.bin", kernel)

# ------------------------------------------------------- AVB footer (last 64)
footer = boot[-64:]
F = {}
if footer[0:4] == b"AVBf":
    F = {
        "magic": "AVBf",
        "version_major": be32(footer, 4), "version_minor": be32(footer, 8),
        "original_image_size": be64(footer, 12),
        "vbmeta_offset": be64(footer, 20),
        "vbmeta_size": be64(footer, 28),
        "reserved": footer[36:64].hex(),
        "footer_file_offset": len(boot) - 64,
    }
jwrite("vbmeta_footer.json", F)

# --------------------------------------------------------------- kernel probe
kinfo = {"size": k_size, "magic_head": kernel[:32].hex()}
sig = kernel[:8]
if sig[:3] == b"\x1f\x8b\x08":
    kinfo["compression"] = "gzip"
elif sig[:4] == b"\x02\x21\x4c\x18":
    kinfo["compression"] = "lz4_legacy"
elif sig[:4] == b"\x04\x22\x4d\x18":
    kinfo["compression"] = "lz4"
elif kernel[0x38:0x3a] == b"MZ" or kernel[:2] == b"MZ":
    kinfo["compression"] = "raw_arm64_Image"
else:
    kinfo["compression"] = "unknown"

dec = b""
members = []
if kinfo["compression"] == "gzip":
    # handle concatenated gzip members (kernel + appended payload)
    d = zlib.decompressobj(31)
    buf = kernel
    try:
        while buf:
            out = d.decompress(buf)
            dec += out
            buf = d.unused_data
            if d.eof:
                members.append({"decompressed_bytes": len(out), "remaining_input": len(buf)})
                if buf:
                    d = zlib.decompressobj(31)
                else:
                    break
            elif not buf:
                break
    except zlib.error as e:
        kinfo["gzip_error"] = str(e)
    kinfo["gzip_members"] = members
    kinfo["decompressed_size"] = len(dec)
    if dec: bwrite("kernel.decompressed", dec)
elif kinfo["compression"].startswith("raw"):
    dec = kernel

# scan for embedded initramfs cpio + IKCFG kernel config
findings = {"cpio_newc_offsets": [], "cpio_crc_offsets": [],
            "trailer_offsets": [], "gzip_inner_offsets": [], "ikcfg_offsets": [],
            "dtb_offsets": [], "qcdt_offsets": []}

def find_all(hay, needle, limit=40):
    r, i = [], 0
    while len(r) < limit:
        i = hay.find(needle, i)
        if i < 0: break
        r.append(i); i += 1
    return r

if dec:
    findings["cpio_newc_offsets"] = find_all(dec, b"070701")
    findings["cpio_crc_offsets"]  = find_all(dec, b"070702")
    findings["trailer_offsets"]   = find_all(dec, b"TRAILER!!!")
    findings["ikcfg_offsets"]     = find_all(dec, b"IKCFG_ST")
    findings["gzip_inner_offsets"] = find_all(dec, b"\x1f\x8b\x08", 200)
    findings["dtb_offsets"]       = find_all(dec, b"\xd0\x0d\xfe\xed", 20)
    findings["qcdt_offsets"]      = find_all(dec, b"QCDT", 20)

# kernel .config via IKCFG_ST
if findings["ikcfg_offsets"]:
    for io_ in findings["ikcfg_offsets"][:3]:
        try:
            # IKCFG_ST marker is 8 bytes, gzip stream follows
            cfg = zlib.decompress(dec[io_+8:], 31)
            bwrite("kernel_config.txt", cfg)
            findings["ikcfg_extracted_at"] = io_
            findings["ikcfg_bytes"] = len(cfg)
            break
        except Exception as e:
            findings.setdefault("ikcfg_errors", []).append(str(e))

# locate cpio archive: prefer a clean newc chain ending in TRAILER!!!
cpio_blob = None
cpio_src = None
candidates = []
for o in findings["trailer_offsets"]:
    candidates.append(("dec", o))
if dec:
    for o in findings["cpio_newc_offsets"][:10]:
        candidates.append(("dec", o))
# also try inner gzip members (initramfs cpio.gz linked into kernel)
inner = []
for o in findings["gzip_inner_offsets"][:60]:
    try:
        d = zlib.decompressobj(31)
        out = d.decompress(dec[o:])
        if out[:6] in (b"070701", b"070702"):
            inner.append({"offset": o, "size": len(out), "data": out})
    except Exception:
        pass
if inner:
    big = max(inner, key=lambda x: x["size"])
    cpio_blob, cpio_src = big["data"], "inner_gzip@%d" % big["offset"]
    findings["inner_gzip_cpio"] = [{"offset": x["offset"], "size": x["size"]} for x in inner]

def valid_cpio(b):
    return b[:6] in (b"070701", b"070702") and len(b) > 110

if cpio_blob is None and dec:
    # find first newc header that parses a plausible filename and chain to TRAILER
    for o in findings["cpio_newc_offsets"][:20]:
        chunk = dec[o:]
        try:
            ns = int(chunk[94:102], 16)
            nm = chunk[110:110+ns].split(b"\x00")[0]
            if valid_cpio(chunk) and (b"/" in nm or nm in (b"init", b"dev", b"proc", b"sys")) \
               and b"TRAILER!!!" in chunk[:min(len(chunk), 40_000_000)]:
                cpio_blob, cpio_src = chunk, "dec@%d" % o
                break
        except Exception:
            pass

# ------------------------------------------------------------ cpio extraction
def parse_cpio(blob, dest, max_files=20000):
    entries, pos, n = [], 0, 0
    while n < max_files and pos + 110 <= len(blob):
        magic = blob[pos:pos+6]
        if magic not in (b"070701", b"070702"):
            return entries, "bad_magic@%d:%r" % (pos, magic)
        try:
            fields = [int(blob[pos+6+i*8: pos+14+i*8], 16) for i in range(13)]
        except ValueError:
            return entries, "bad_header@%d" % pos
        ino, mode, uid, gid, nlink, mtime, fsize, dmaj, dmin, rdmaj, rdmin, namesize, check = fields
        name = blob[pos+110: pos+110+namesize].split(b"\x00", 1)[0].decode("utf-8", "replace")
        data_at = pos + align(110 + namesize, 4)
        data = blob[data_at: data_at + fsize]
        if name == "TRAILER!!!":
            return entries, "ok"
        ftype = (mode >> 12) & 0xf
        rec = {"name": name, "mode": oct(mode & 0o7777), "uid": uid, "gid": gid,
               "size": fsize, "type": {1:"fifo",2:"chr",4:"dir",6:"blk",8:"reg",10:"sym",12:"sock"}.get(ftype, str(ftype))}
        if rec["type"] == "sym":
            rec["link"] = data.decode("utf-8", "replace")
        elif rec["type"] == "reg":
            rel = name.lstrip("/")
            p = os.path.join(dest, rel)
            if rel and ".." not in rel.split("/"):
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "wb") as f: f.write(data)
            rec["sha256"] = sha(data)
        entries.append(rec)
        pos = align(data_at + fsize, 4)
        n += 1
    return entries, "limit_or_eof"

cpio_report = {"found": False}
if cpio_blob:
    bwrite("initramfs.cpio", cpio_blob)
    dest = os.path.join(OUT, "initramfs")
    if os.path.isdir(dest): shutil.rmtree(dest)
    os.makedirs(dest)
    entries, status = parse_cpio(cpio_blob, dest)
    cpio_report = {"found": True, "source": cpio_src, "blob_size": len(cpio_blob),
                   "parse_status": status, "entries": len(entries),
                   "names": [e["name"] for e in entries], "entry_details": entries}
    jwrite("initramfs_listing.json", cpio_report)

# ------------------------------------------------------------------- vbmeta
vb = open(os.path.join(FW, "firmware-update", "vbmeta.img"), "rb").read()
V = {}
if vb[:4] == b"AVB0":
    V = {
        "magic": "AVB0",
        "required_libavb_version_major": be32(vb, 4),
        "required_libavb_version_minor": be32(vb, 8),
        "authentication_data_block_size": be64(vb, 12),
        "auxiliary_data_block_size": be64(vb, 20),
        "algorithm_type": be32(vb, 28),
        "algorithm_name": {0:"NONE",1:"SHA256_RSA2048",2:"SHA256_RSA4096",
                           3:"SHA256_RSA8192",4:"SHA512_RSA2048",5:"SHA512_RSA4096",
                           6:"SHA512_RSA8192"}.get(be32(vb,28), "?"),
        "hash_offset": be64(vb, 32), "hash_size": be64(vb, 40),
        "signature_offset": be64(vb, 48), "signature_size": be64(vb, 56),
        "public_key_offset": be64(vb, 64), "public_key_size": be64(vb, 72),
        "public_key_metadata_offset": be64(vb, 80), "public_key_metadata_size": be64(vb, 88),
        "descriptors_offset": be64(vb, 96), "descriptors_size": be64(vb, 104),
        "rollback_index": be64(vb, 112),
        "flags": be32(vb, 120),
        "flags_decode": ("HASHTREE_DISABLED" if be32(vb,120) & 1 else "") + \
                        ("|VERIFICATION_DISABLED" if be32(vb,120) & 2 else "") or "NONE (verification fully enabled)",
        "rollback_index_location": be32(vb, 124),
        "release_string": cstr(vb[128:176]),
    }
    # auxiliary data begins after 256-byte header + auth block
    aux = 256 + V["authentication_data_block_size"]
    dstart = aux + V["descriptors_offset"]
    dend = dstart + V["descriptors_size"]
    # avbtool 1.1.0 descriptor layouts (all multi-byte fields big-endian)
    desc, p = [], dstart
    while p + 16 <= min(dend, len(vb)):
        tag, nbytes = be64(vb, p), be64(vb, p+8)
        if nbytes == 0 or nbytes > 100000: break
        body = vb[p+16: p+16+nbytes]
        d = {"tag": tag, "num_bytes_following": nbytes, "offset": p}
        if tag == 2:      # hash descriptor
            d["type"] = "hash"
            d["image_size"] = be64(body, 0)
            d["hash_algorithm"] = cstr(body[8:40])
            pnlen, saltlen, diglen = be32(body, 40), be32(body, 44), be32(body, 48)
            d["partition_name_len"], d["salt_len"], d["root_digest_len"] = pnlen, saltlen, diglen
            q = 116                        # 8 + 32 + 12 + reserved[64]
            d["partition_name"] = cstr(body[q:q+pnlen]); q += pnlen
            d["salt"] = body[q:q+saltlen].hex(); q += saltlen
            d["root_digest"] = body[q:q+diglen].hex()
        elif tag == 4:    # chain partition descriptor
            d["type"] = "chain_partition"
            d["rollback_index_location"], d["partition_name_len"], \
                d["public_key_blob_size"], d["flags"] = struct.unpack_from(">IIII", body, 0)
            q = 76                        # 16 + reserved[60]
            d["partition_name"] = cstr(body[q:q+d["partition_name_len"]])
            kq = q + d["partition_name_len"]
            if len(body) >= kq + 4:
                d["public_key_bits"] = be32(body, kq)
        elif tag == 0:    # property descriptor
            d["type"] = "property"
            klen, vlen = be64(body, 0), be64(body, 8)
            d["key"] = cstr(body[16:16+klen])
            d["value"] = cstr(body[16+klen+1:16+klen+1+vlen])
        elif tag == 3:
            d["type"] = "kernel_cmdline"; d["text"] = cstr(body)
        elif tag == 1:
            d["type"] = "hashtree"; d["raw_head"] = body[:32].hex()
        desc.append(d)
        p += 16 + ((nbytes + 7) // 8) * 8
    V["descriptors"] = desc
    V["aux_offset"] = aux
jwrite("vbmeta_header.json", V)

# ------------------------------------------- embedded vbmeta inside boot.img
EV = {}
if F.get("magic") == "AVBf":
    eoff, esize = F["vbmeta_offset"], F["vbmeta_size"]
    ev = boot[eoff:eoff+esize]
    if ev[:4] == b"AVB0":
        eaux = 256 + be64(ev, 12)
        EV = {
            "source": "boot.img embedded vbmeta (AVB footer)",
            "offset": eoff, "size": esize,
            "algorithm_type": be32(ev, 28),
            "algorithm_name": {0:"NONE",1:"SHA256_RSA2048",2:"SHA256_RSA4096",
                               3:"SHA256_RSA8192",4:"SHA512_RSA2048",5:"SHA512_RSA4096",
                               6:"SHA512_RSA8192"}.get(be32(ev,28), "?"),
            "authentication_data_block_size": be64(ev, 12),
            "auxiliary_data_block_size": be64(ev, 20),
            "descriptors_offset": be64(ev, 96), "descriptors_size": be64(ev, 104),
            "rollback_index": be64(ev, 112), "flags": be32(ev, 120),
            "release_string": cstr(ev[128:176]),
        }
        p = eaux + EV["descriptors_offset"]
        end = p + EV["descriptors_size"]
        eds = []
        while p + 16 <= min(end, len(ev)):
            tag, nbytes = be64(ev, p), be64(ev, p+8)
            if nbytes == 0 or nbytes > 100000: break
            body = ev[p+16:p+16+nbytes]
            d = {"tag": tag, "num_bytes_following": nbytes, "offset": p}
            if tag == 2:
                d["type"] = "hash"
                d["image_size"] = be64(body, 0)
                d["hash_algorithm"] = cstr(body[8:40])
                pn, sl, dl = be32(body,40), be32(body,44), be32(body,48)
                d["partition_name_len"], d["salt_len"], d["root_digest_len"] = pn, sl, dl
                q = 116
                d["partition_name"] = cstr(body[q:q+pn]); q += pn
                d["salt"] = body[q:q+sl].hex(); q += sl
                d["root_digest"] = body[q:q+dl].hex()
                # verify: digest should equal sha256(salt || image[0:image_size])
                try:
                    calc = hashlib.sha256(bytes.fromhex(d["salt"]) +
                                          boot[:d["image_size"]]).hexdigest()
                    d["digest_verified"] = (calc == d["root_digest"])
                    d["digest_calculated"] = calc
                except Exception as e:
                    d["digest_verified"] = "error: " + str(e)
            elif tag == 0:
                kl, vl = be64(body,0), be64(body,8)
                d["type"] = "property"
                # avbtool 1.1: key/value are NUL-terminated; lengths exclude the NUL
                d["key"] = cstr(body[16:16+kl])
                d["value"] = cstr(body[16+kl+1:16+kl+1+vl])
            elif tag == 3:
                d["type"] = "kernel_cmdline"; d["text"] = cstr(body)
            eds.append(d)
            p += 16 + ((nbytes+7)//8)*8
        EV["descriptors"] = eds
jwrite("boot_embedded_vbmeta.json", EV)

# ---------------------------------------------------------- whole-image scan
scan = {"gzip_magic_offsets": [], "cpio_magic_offsets": [], "nonzero_tail": None}
scan["gzip_magic_offsets"] = find_all(boot, b"\x1f\x8b\x08", 60)
scan["cpio_magic_offsets"] = find_all(boot, b"070701", 20)
# find last nonzero byte before AVB tail
tail = boot.rstrip(b"\x00")
scan["last_nonzero_byte_offset"] = len(tail) - 1
scan["last_nonzero_hex"] = tail[-32:].hex()

jwrite("region_map.json", {"image_size": len(boot), "page_size": page,
                           "regions": regions, "avb_footer": F,
                           "whole_image_scan": scan})

# ---------------------------------------------------------------- copy texts
for rel in ["META-INF/com/android/metadata",
            "META-INF/com/google/android/updater-script",
            "META-INF/com/google/android/removable_images.txt"]:
    src = os.path.join(FW, rel.replace("/", os.sep))
    dst = os.path.join(OUT, rel.replace("/", os.sep))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(src, dst)

report = {
    "boot_header": H, "avb_footer": F, "vbmeta": V,
    "boot_embedded_vbmeta": EV,
    "kernel": kinfo, "embedded_content_scan": findings,
    "initramfs": {k: v for k, v in cpio_report.items() if k not in ("entry_details",)},
    "region_map": regions, "whole_image_scan": scan,
}
jwrite("deep_unpack_report.json", report)

# ------------------------------------------------------------------- console
print("=" * 72)
print("BOOT HEADER")
for k, v in H.items(): print("  %-24s %s" % (k, v))
print("=" * 72)
print("AVB FOOTER:", F)
print("=" * 72)
print("KERNEL:", {k: v for k, v in kinfo.items() if k != "magic_head"})
print("  magic_head:", kinfo["magic_head"])
print("EMBEDDED SCAN:", {k: (v[:12] if isinstance(v, list) else v) for k, v in findings.items()})
print("INITRAMFS:", {k: v for k, v in cpio_report.items() if k not in ("entry_details", "names")})
if cpio_report.get("names"):
    print("  files (%d):" % len(cpio_report["names"]))
    for n in cpio_report["names"][:120]: print("    ", n)
print("=" * 72)
print("VBMETA:", {k: v for k, v in V.items() if k != "descriptors"})
print("  descriptors (%d):" % len(V.get("descriptors", [])))
for d in V.get("descriptors", []):
    print("    ", {k: v for k, v in d.items() if k in
          ("type","partition_name","image_size","hash_algorithm","flags","text","root_digest","dm_verity_version")})
print("=" * 72)
print("REGIONS:", regions)
print("SCAN:", {k: (v[:12] if isinstance(v, list) else v) for k, v in scan.items()})
print("OUTPUT:", OUT)
