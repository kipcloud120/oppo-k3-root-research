#!/usr/bin/env python3
"""Extract /chosen bootargs and root-node identity from the DTBs appended to Image.gz."""
import struct, json, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
b = open(os.path.join(ROOT, "firmware_C17_root", "boot.img"), "rb").read()
K0, KS = 4096, 16601683
seg = b[K0:K0 + KS]

def fdt_props(dtb):
    def u32(o): return struct.unpack_from(">I", dtb, o)[0]
    ts, os_, ostr = u32(4), u32(8), u32(12)
    def s(o):
        e = dtb.find(b"\0", o); return dtb[o:e].decode("ascii", "replace")
    q, path, out = os_, [], {}
    while q + 4 <= ts:
        tag = u32(q); q += 4
        if tag == 1:
            e = dtb.find(b"\0", q); nm = dtb[q:e].decode("ascii", "replace")
            q = (e + 1 + 3) & ~3; path.append(nm or "")
        elif tag == 2:
            if path: path.pop()
        elif tag == 3:
            ln, no = u32(q), u32(q + 4); q += 8
            val = dtb[q:q + ln]; q = (q + ln + 3) & ~3
            node = ("/" + "/".join(path)).replace("//", "/")
            out.setdefault(node, {})[s(ostr + no)] = val
        elif tag == 9:
            break
        else:
            break
    return out

def txt(v):
    return v.rstrip(b"\0").decode("ascii", "replace")

# locate all DTBs
p, dtbs = 0, []
while p + 8 <= len(seg):
    j = seg.find(b"\xd0\x0d\xfe\xed", p)
    if j < 0: break
    ts = struct.unpack_from(">I", seg, j + 4)[0]
    if 1000 < ts < 2_000_000:
        dtbs.append((j, ts)); p = j + ts
    else:
        p = j + 4

result = []
for i, (o, ts) in enumerate(dtbs):
    dtb = seg[o:o + ts]
    open(os.path.join(ROOT, "unpacked_C17", "dtb_%02d.dtb" % i), "wb").write(dtb)
    pr = fdt_props(dtb)
    rec = {
        "index": i, "kernel_relative_offset": o, "abs_offset": K0 + o, "size": ts,
        "model": txt(pr.get("/", {}).get("model", b"")),
        "compatible": txt(pr.get("/", {}).get("compatible", b"")),
        "bootargs": txt(pr.get("/chosen", {}).get("bootargs", b"")),
        "chosen_keys": list(pr.get("/chosen", {}).keys()),
        "root_node_keys": list(pr.get("/", {}).keys()),
    }
    result.append(rec)

with open(os.path.join(ROOT, "unpacked_C17", "dtb_bootargs.json"), "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)

print("DTBs: %d" % len(dtbs))
for r in result:
    print("  dtb%-2d abs=%-9d size=%-7d model=%s" % (r["index"], r["abs_offset"], r["size"], r["model"]))
    if r["bootargs"]: print("       bootargs: %s" % r["bootargs"])
    print("       chosen keys: %s" % ", ".join(r["chosen_keys"]))
print("\n=== /chosen of dtb0 in full ===")
pr = fdt_props(seg[dtbs[0][0]:dtbs[0][0] + dtbs[0][1]])
for k, v in pr.get("/chosen", {}).items():
    print("  %-24s %s" % (k, txt(v)[:400]))
