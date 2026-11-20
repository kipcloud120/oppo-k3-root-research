#!/usr/bin/env python3
"""Quick ELF header + string scan for user-space WLAN binaries (offline).

Usage: python tools/wlan_scan_str.py <binary> [<binary> ...]
"""
import re
import sys

try:
    from elftools.elf.elffile import ELFFile
except Exception:  # pyelftools optional
    ELFFile = None


def elf_info(path):
    with open(path, "rb") as f:
        hdr = f.read(20)
    out = {"magic": hdr[:4].hex()}
    if ELFFile is not None:
        with open(path, "rb") as f:
            e = ELFFile(f)
            out["class"] = e.elfclass
            out["machine"] = e["e_machine"]
            out["type"] = e["e_type"]
            out["entry"] = hex(e["e_entry"])
            secs = []
            for s in e.iter_sections():
                if s.name in (".text", ".plt", ".rodata", ".data", ".dynstr", ".rela.plt", ".rela.dyn"):
                    secs.append("%s@%s+%#x" % (s.name, hex(s["sh_addr"]), s["sh_size"]))
            out["secs"] = secs
    return out


def strings(data, minlen=5):
    return [m.group().decode("latin-1") for m in re.finditer(rb"[ -~]{%d,}" % minlen, data)]


KEY = ("iwpriv", "ioctl", "IOCTL", "SIOC", "driver", "Driver", "testmode", "con_mode",
       "/odm", "/vendor", "/system", "sh", "command", "wlan", "ftm", "FTM", "p2p", "P2P")


def main(argv):
    for path in argv[1:]:
        data = open(path, "rb").read()
        print("=" * 78)
        print(path, len(data), "bytes")
        try:
            print("elf:", elf_info(path))
        except Exception as exc:
            print("elf: n/a", exc)
        ss = strings(data)
        print("strings:", len(ss))
        seen = set()
        for s in ss:
            if s in seen:
                continue
            if any(k in s for k in KEY):
                seen.add(s)
                print("   ", s)


if __name__ == "__main__":
    main(sys.argv)
