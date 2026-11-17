"""par_dl.py — 多连接分段并发下载（Range）。

用法: python par_dl.py URL OUT [CONNS] [PROXY]
单连接经本地代理速率受限，分段并发可显著提升聚合吞吐。
"""
import os
import sys
import threading
import urllib.request

CHUNK = 256 * 1024


def _opener(proxy):
    if proxy:
        h = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        return urllib.request.build_opener(h)
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get_size(url, proxy):
    req = urllib.request.Request(url, method="HEAD")
    with _opener(proxy).open(req, timeout=30) as r:
        return int(r.headers["Content-Length"]), r.headers.get("Accept-Ranges", "")


def fetch_range(url, proxy, start, end, out, idx, progress):
    op = _opener(proxy)
    pos = start
    f = open(out, "r+b")
    while pos <= end:
        stop = min(pos + CHUNK - 1, end)
        req = urllib.request.Request(url, headers={"Range": f"bytes={pos}-{stop}"})
        for attempt in range(5):
            try:
                with op.open(req, timeout=60) as r:
                    data = r.read()
                break
            except Exception:
                if attempt == 4:
                    raise
        f.seek(pos)
        f.write(data)
        f.flush()
        pos += len(data)
        with progress["lk"]:
            progress["n"] += len(data)
    f.close()


def main():
    url = sys.argv[1]
    out = sys.argv[2]
    conns = int(sys.argv[3]) if len(sys.argv) > 3 else 8
    proxy = sys.argv[4] if len(sys.argv) > 4 else "http://127.0.0.1:7890"

    size, ranges = get_size(url, proxy)
    print(f"size={size} accept_ranges={ranges!r} conns={conns}", flush=True)
    if os.path.exists(out) and os.path.getsize(out) == size:
        print("already complete")
        return

    with open(out, "wb") as f:
        f.truncate(size)

    part = size // conns
    jobs = []
    for i in range(conns):
        s = i * part
        e = size - 1 if i == conns - 1 else (i + 1) * part - 1
        jobs.append((s, e, i))

    progress = {"n": 0, "lk": threading.Lock()}

    def monitor():
        while not progress.get("stop"):
            progress["ev"].wait(10)
            progress["ev"].clear()
            with progress["lk"]:
                n = progress["n"]
            print(f"  progress {n}/{size} ({n*100.0/size:.1f}%)", flush=True)

    progress["ev"] = threading.Event()
    threading.Thread(target=monitor, daemon=True).start()

    threads = [
        threading.Thread(target=fetch_range, args=(url, proxy, s, e, out, i, progress))
        for s, e, i in jobs
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"done bytes={progress['n']} expected={size}", flush=True)


if __name__ == "__main__":
    main()
