#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ozip_range_extract.py — 通过 HTTP Range 只下载 OPPO 固件包中的指定文件。

支持两种容器格式
----------------
1. 加密 .ozip（默认）：文件头 0x1050 字节明文，其后按 0x4010 字节分块，
   每块 = 16 字节 AES-128-ECB 密文 + 0x4000 字节明文。ECB 各块独立，
   因此任意字节区间都能在本地还原，无需下载整个固件包。
2. 标准 .zip（--plain-zip）：component-ota 下发的全量包即为此格式，
   无头部、无加密，直接按 ZIP 结构做分段读取。

依赖：Python >= 3.8, curl, pycryptodome（仅 ozip 模式需要）

当前基线
--------
实机 ADB 确认设备为 PCGM00_11_F.16，故默认 URL / 输出目录均指向 F.16。
C.17 固件产物已于 2026-11-13 清理；tools/ 下其余脚本（deep_unpack.py、
kallsyms_recover.py、solve_names.py、fdt_chosen.py 等）仍硬编码
`firmware_C17_root/` 与 `unpacked_C17/`，重跑前必须先把路径指向 F.16。

用法
----
    # 当前基线 F.16（默认 URL，按 .zip 后缀自动识别为 plain ZIP）
    python tools/ozip_range_extract.py --list
    python tools/ozip_range_extract.py --out firmware_F16

    # 历史 C.17 加密 ozip（显式给 URL，按 .ozip 后缀自动识别）
    python tools/ozip_range_extract.py --url <C17_ozip_url> --out <dir> --list

    # 提取任意指定条目 / 强制指定格式
    python tools/ozip_range_extract.py --files boot.img firmware-update/dtbo.img
    python tools/ozip_range_extract.py --plain-zip --url <url> --out <dir>
    python tools/ozip_range_extract.py --ozip --key <32_hex> --url <url>

密钥说明
--------
内置密钥表来自 bkerler/oppo_ozip_decrypt (MIT)。K3 / Reno 使用
ACAC1E13A12531AE4A1B21BB31C13C21，脚本会用首个密文块自动验证
（解密后应为 PK\\x03\\x04）。--plain-zip 模式不需要密钥。
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import zlib

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

# 当前有效基线：实机 ADB 确认的 PCGM00_11_F.16（component-ota 全量包）
DEFAULT_URL = (
    'https://gauss-componentotacostmanual-cn.allawnfs.com/'
    'remove-d6d964be26dc3369433b90dcaf671314/component-ota/25/04/01/'
    'c428fe1c57ee4d2f9a84e5cca926fde6.zip'
)
DEFAULT_REFERER = 'https://www.coloros.com/rom/firmware?id=190'
DEFAULT_OUT = 'firmware_F16'
DEFAULT_FILES = [
    'boot.img',
    'firmware-update/vbmeta.img',
    'META-INF/com/android/metadata',
    'META-INF/com/google/android/updater-script',
    'META-INF/com/google/android/removable_images.txt',
]

OZIP_HDR = 0x1050      # 加密 ozip 明文头长度
BLK = 0x4010           # 加密分块长度
ENC = 16               # 每块被加密的字节数
TAIL_WINDOW = 256 * 1024
MERGE_GAP = 2 * 1024 * 1024

# 来自 bkerler/oppo_ozip_decrypt 的已知密钥；首个为 Reno / K3
KEYS = [
    'ACAC1E13A12531AE4A1B21BB31C13C21',  # Reno, K3
    'D6EECF0AE5ACD4E0E9FE522DE7CE381E',
    'D6ECCF0AE5ACD4E0E92E522DE7C1381E',
    'D6DCCF0AD5ACD4E0292E522DB7C1381E',
    'D7DCCE1AD4AFDCE2393E5161CBDC4321',
    'D7DBCE2AD4ADDCE1393E5521CBDC4321',
    'D4D2CD61D4AFDCE13B5E01221BD14D20',
    '261CC7131D7C1481294E532DB752381E',
    '1CA21E12271335AE33AB81B2A7B14622',
    'D4D2CE11D4AFDCE13B3E0121CBD14D20',
    '1C4C1EA3A12531AE491B21BB31613C11',
    '1C4A11A3A12513AE441B23BB31513121',
    '2442CE821A4F352E33AE81B22BC1462E',
    'ACAC1E13A72431AE4A1B22BBA1C1C6A2',
    '1C4411A3A12533AE441B21BB31613C11',
    '55EEAA33112133AE441B23BB31513121',
]


class NeedWiderWindow(Exception):
    def __init__(self, cd_phys: int):
        self.cd_phys = cd_phys


def curl_range(url: str, referer: str, start: int, end: int, plain: bool) -> bytes:
    """取 [start, end]（含）区间，要求服务端返回 206。

    注意：部分 OPPO CDN 的 WAF 会对自定义 UA / Referer 返回 403，
    裸请求反而正常，因此 plain-zip 模式使用最少的请求头。
    """
    fd, path = tempfile.mkstemp(prefix='range_', suffix='.bin')
    os.close(fd)
    try:
        cmd = ['curl', '-sS', '--fail', '--max-time', '600']
        if not plain:
            cmd += ['-A', 'Mozilla/5.0', '-H', 'Referer: ' + referer]
        cmd += ['-H', 'Range: bytes=%d-%d' % (start, end),
                '-o', path, '-w', '%{http_code}', url]
        res = subprocess.run(cmd, capture_output=True, text=True)
        code = res.stdout.strip()
        if res.returncode != 0 or code != '206':
            raise RuntimeError('Range %d-%d failed: HTTP %s, %s' %
                               (start, end, code, res.stderr.strip()[:200]))
        with open(path, 'rb') as f:
            return f.read()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def curl_head(url: str, referer: str, plain: bool) -> dict:
    cmd = ['curl', '-sSI', '--max-time', '90']
    if not plain:
        cmd += ['-A', 'Mozilla/5.0', '-H', 'Referer: ' + referer]
    cmd.append(url)
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        return {}
    info = {}
    for line in res.stdout.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            info[k.strip().lower()] = v.strip()
    return info


def decrypt_block_headers(buf: bytearray, phys_start: int, key, hdr: int) -> None:
    """就地解密落在区间内的每个 16 字节块头（AES-ECB，块间独立）。"""
    if key is None:
        return
    cipher = AES.new(key, AES.MODE_ECB)
    first_k = (phys_start - hdr) // BLK
    last_k = (phys_start + len(buf) - 1 - hdr) // BLK
    for k in range(first_k, last_k + 1):
        off = hdr + k * BLK - phys_start
        if 0 <= off and off + ENC <= len(buf):
            buf[off:off + ENC] = cipher.decrypt(bytes(buf[off:off + ENC]))


def aligned_start(phys_start: int, plain: bool) -> int:
    """ozip 需向下对齐到块边界以完整包含 16 字节块头；plain ZIP 不需要。"""
    if plain:
        return phys_start
    return OZIP_HDR + ((phys_start - OZIP_HDR) // BLK) * BLK


def parse_central_directory(tail: bytes, phys_start: int, key, hdr: int) -> dict:
    buf = bytearray(tail)
    decrypt_block_headers(buf, phys_start, key, hdr)
    e = buf.rfind(b'PK\x05\x06')
    if e < 0:
        raise RuntimeError('EOCD not found in tail window')
    (_, _, _, _, n_total, cd_size, cd_off, _) = struct.unpack_from(
        '<IHHHHIIH', buf, e)
    cd_phys = cd_off + hdr
    if cd_phys < phys_start:
        raise NeedWiderWindow(cd_phys)
    p = cd_phys - phys_start
    entries = {}
    for _ in range(n_total):
        if p + 46 > len(buf) or buf[p:p + 4] != b'PK\x01\x02':
            break
        (_, _, _, _flags, method, _mt, _md, crc, csize, usize,
         nlen, elen, clen, _d, _ia, _ea, lho) = struct.unpack_from(
            '<IHHHHHHIIIHHHHHII', buf, p)
        name = bytes(buf[p + 46:p + 46 + nlen]).decode('utf-8', 'replace')
        entries[name] = dict(csize=csize, usize=usize, lho=lho,
                             method=method, crc=crc)
        p += 46 + nlen + elen + clen
    return dict(entries=entries, cd_phys=cd_phys, cd_size=cd_size,
                eocd_phys=phys_start + e, count=n_total)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--url', default=DEFAULT_URL)
    ap.add_argument('--referer', default=DEFAULT_REFERER)
    ap.add_argument('--out', default=DEFAULT_OUT)
    ap.add_argument('--key', help='AES-128 key as 32 hex chars; auto-detected for ozip')
    ap.add_argument('--plain-zip', action='store_true',
                    help='force standard unencrypted ZIP (default auto-detected from .zip suffix)')
    ap.add_argument('--ozip', action='store_true',
                    help='force encrypted ozip (default auto-detected from .ozip suffix)')
    ap.add_argument('--size', type=int, help='package size in bytes (skip HEAD)')
    ap.add_argument('--files', nargs='+', default=DEFAULT_FILES)
    ap.add_argument('--list', action='store_true', help='list archive entries and exit')
    args = ap.parse_args()

    if args.ozip:
        plain = False
    elif args.plain_zip:
        plain = True
    else:
        plain = args.url.lower().split('?')[0].endswith('.zip')
    hdr = 0 if plain else OZIP_HDR

    head = curl_head(args.url, args.referer, plain)
    total = args.size or int(head.get('content-length', 0))
    if not total:
        raise RuntimeError('cannot determine package size; pass --size')
    print('package size : %d bytes (%.2f MiB)' % (total, total / 1048576))
    print('container    :', 'plain ZIP' if plain else 'encrypted ozip')
    print('server md5   :', head.get('x-amz-meta-filemd5') or
          head.get('x-amz-meta-content-md5') or 'n/a')
    print('accept-ranges:', head.get('accept-ranges', 'unknown (Range will be tested)'))

    # 1) 密钥（仅 ozip）
    key = None
    if not plain:
        if AES is None:
            raise RuntimeError('pycryptodome required for ozip: pip install pycryptodome')
        first = curl_range(args.url, args.referer, hdr, hdr + ENC - 1, plain)
        for k in ([args.key.upper()] if args.key else KEYS):
            pt = AES.new(binascii.unhexlify(k), AES.MODE_ECB).decrypt(first[:ENC])
            if pt[:4] in (b'PK\x03\x04', b'AVB0', b'ANDR'):
                key = binascii.unhexlify(k)
                print('AES key      :', k, '(verified, plaintext starts %r)' % pt[:4])
                break
        if key is None:
            raise RuntimeError('no matching AES key; supply --key')

    # 2) 尾部窗口，必要时扩大，直到覆盖完整中央目录
    window = TAIL_WINDOW
    while True:
        phys_start = max(0, total - window)
        tail = curl_range(args.url, args.referer, phys_start, total - 1, plain)
        try:
            cd = parse_central_directory(tail, phys_start, key, hdr)
            break
        except NeedWiderWindow as need:
            window = total - need.cd_phys + 65536
            print('widening tail window to %d bytes' % window)
            if window > total:
                raise RuntimeError('central directory window exceeds file size')
    print('tail fetched : %d bytes; %d archive entries' %
          (len(tail), len(cd['entries'])))

    if args.list:
        for name, m in sorted(cd['entries'].items(), key=lambda x: x[1]['lho']):
            print('%-62s csize=%-12d usize=%-12d lho=%d' %
                  (name, m['csize'], m['usize'], m['lho']))
        return 0

    missing = [n for n in args.files if n not in cd['entries']]
    if missing:
        raise RuntimeError('entries not found: ' + ', '.join(missing))

    # 3) 合并相邻目标区间，减少请求数
    items = sorted(((n, cd['entries'][n]) for n in args.files),
                   key=lambda x: x[1]['lho'])
    ranges = []
    for name, m in items:
        start, end = m['lho'], m['lho'] + 30 + 512 + m['csize']
        if ranges and start - ranges[-1][1] < MERGE_GAP:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end),
                          ranges[-1][2] + [name])
        else:
            ranges.append((start, end, [name]))

    os.makedirs(args.out, exist_ok=True)
    manifest = {
        'package_url': args.url, 'package_size_bytes': total,
        'package_md5_server_header': head.get('x-amz-meta-filemd5') or
                                     head.get('x-amz-meta-content-md5'),
        'container': 'plain ZIP' if plain else 'encrypted ozip',
        'ozip_aes_key': key.hex().upper() if key else None,
        'method': 'HTTP 206 Range + ZIP central directory parsing' +
                  ('' if plain else ' + AES-128-ECB per-0x4010-block header decryption'),
        'ranges': [], 'files': [],
    }
    downloaded = 0
    for idx, (start, end, names) in enumerate(ranges):
        a = aligned_start(start + hdr, plain)
        b = end + hdr - 1
        raw = curl_range(args.url, args.referer, a, b, plain)
        downloaded += len(raw)
        buf = bytearray(raw)
        decrypt_block_headers(buf, a, key, hdr)
        base = a - hdr
        manifest['ranges'].append(dict(index=idx, byte_start=a, byte_end=b,
                                       bytes=len(raw), entries=names))
        print('range %d: %d bytes -> %s' % (idx, len(raw), ', '.join(names)))

        for name in names:
            m = cd['entries'][name]
            i = m['lho'] - base
            if buf[i:i + 4] != b'PK\x03\x04':
                raise RuntimeError('bad local header for ' + name)
            nlen, elen = struct.unpack_from('<HH', buf, i + 26)
            ds = i + 30 + nlen + elen
            comp = bytes(buf[ds:ds + m['csize']])
            raw_file = zlib.decompress(comp, -15) if m['method'] == 8 else comp
            if len(raw_file) != m['usize'] or \
                    (zlib.crc32(raw_file) & 0xffffffff) != m['crc']:
                raise RuntimeError('CRC/size verification FAILED for ' + name)
            dest = os.path.join(args.out, *name.split('/'))
            os.makedirs(os.path.dirname(dest) or '.', exist_ok=True)
            with open(dest, 'wb') as f:
                f.write(raw_file)
            manifest['files'].append(dict(
                name=name, size=len(raw_file), crc32='%08x' % m['crc'],
                sha256=hashlib.sha256(raw_file).hexdigest(),
                md5=hashlib.md5(raw_file).hexdigest(),
                compressed_size=m['csize'], zip_method=m['method']))
            print('  OK %-58s %10d bytes' % (name, len(raw_file)))

    manifest['bytes_downloaded_total'] = downloaded
    manifest['note'] = 'Full firmware package was NOT downloaded.'
    with open(os.path.join(args.out, 'manifest.json'), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print('\ntransferred %d bytes (%.2f MiB) -> %s' %
          (downloaded, downloaded / 1048576, args.out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
