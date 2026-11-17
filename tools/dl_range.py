#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dl_range.py — 下载 URL 的指定连续字节区间，多连接分段并发，落为一个文件。

用法: python dl_range.py URL START END OUT [CONNS] [PROXY]
用于从 OPPO OTA ZIP 中只取 system.new.dat.br 条目（避免下载整包）。
"""
import os
import sys
import threading
import urllib.request

CHUNK = 512 * 1024
URL = sys.argv[1]
START = int(sys.argv[2])
END = int(sys.argv[3])          # 含
OUT = sys.argv[4]
CONNS = int(sys.argv[5]) if len(sys.argv) > 5 else 16
PROXY = sys.argv[6] if len(sys.argv) > 6 else "http://127.0.0.1:7890"

TOTAL = END - START + 1


def opener():
    if PROXY:
        h = urllib.request.ProxyHandler({"http": PROXY, "https": PROXY})
        return urllib.request.build_opener(h)
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def fetch(lo, hi, idx, prog):
    op = opener()
    f = open(OUT, "r+b")
    pos = lo
    while pos <= hi:
        stop = min(pos + CHUNK - 1, hi)
        req = urllib.request.Request(URL, headers={"Range": f"bytes={pos}-{stop}"})
        for attempt in range(6):
            try:
                with op.open(req, timeout=90) as r:
                    data = r.read()
                if len(data) != stop - pos + 1:
                    raise ValueError(f"short read {len(data)}")
                break
            except Exception as e:
                if attempt == 5:
                    raise
                import time
                time.sleep(1 + attempt)
        f.seek(pos - START)
        f.write(data)
        f.flush()
        pos += len(data)
        with prog["lk"]:
            prog["n"] += len(data)
    f.close()


def main():
    print(f"range [{START}, {END}] total={TOTAL} ({TOTAL/1048576:.1f} MiB) conns={CONNS}", flush=True)
    if os.path.exists(OUT) and os.path.getsize(OUT) == TOTAL:
        print("already complete")
        return
    with open(OUT, "wb") as f:
        f.truncate(TOTAL)
    part = TOTAL // CONNS
    jobs = []
    for i in range(CONNS):
        lo = START + i * part
        hi = END if i == CONNS - 1 else START + (i + 1) * part - 1
        jobs.append((lo, hi, i))
    prog = {"n": 0, "lk": threading.Lock(), "stop": False}

    def monitor():
        import time
        while not prog["stop"]:
            time.sleep(15)
            with prog["lk"]:
                n = prog["n"]
            print(f"  {n}/{TOTAL} ({n*100.0/TOTAL:.1f}%)", flush=True)
    th = threading.Thread(target=monitor, daemon=True)
    th.start()

    ts = [threading.Thread(target=fetch, args=(lo, hi, i, prog)) for lo, hi, i in jobs]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    prog["stop"] = True
    with prog["lk"]:
        n = prog["n"]
    print(f"done bytes={n}/{TOTAL}", flush=True)
    if n != TOTAL:
        sys.exit(1)


if __name__ == "__main__":
    main()
