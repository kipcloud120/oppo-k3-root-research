#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wifi_exec.py —— 通过 Wi-Fi 私有事务（tx 10070）在 root 服务域内执行一条只读命令。

用途：把 §24.9 登记的只读探针（CapEff / 持久目录标签 / crash_dump 域转换）以及
      §23 的 L3 归档补齐，做成"一次事务、单变量、可复现"的标准动作。

约束（与 HANDOVER §11 / §17.4 一致）：
  * 一次调用只发一条命令，不做批量；
  * 载荷固定为 "x\\n" + cmd —— 前置的 `x` 让 iwpriv 分支先拿到一个合法 token，
    真正的命令由换行分隔的第二条语句执行；换行不在 11 字符黑名单内（§22.2）；
  * 命令内**不得**出现 `@ # $ % & * ^ : ; ? |`（黑名单），因此不能用 $(...)、&&、2>&1；
    需要取值时用反引号；
  * 结束后删除设备上的载荷文件，不留驻留物。

用法：
  python tools/wifi_exec.py --tag CAPS --cmd 'log -t CAPS `grep Cap /proc/self/status`'
  python tools/wifi_exec.py --tag P1UID2 --cmd 'log -t P1UID2 `id`'
"""

import argparse
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADB = os.path.join(ROOT, 'scrcpy-win64-v3.3.4', 'adb.exe')
JAR = os.path.join(ROOT, '.build', 'jdkpkg', 'ftmprobe.jar')
OUTDIR = os.path.join(ROOT, 'artifacts_adb', 'binder_audit', 'p1_probes')
TOKEN = 'android.net.wifi.IOplusWifiManager'
CODE = '10070'
BLACKLIST = set('@#$%&*^:;?|')


def adb(*args, **kw):
    env = dict(os.environ, MSYS_NO_PATHCONV='1')
    return subprocess.run([ADB, *args], capture_output=True, text=True, env=env, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tag', required=True)
    ap.add_argument('--cmd', required=True)
    ap.add_argument('--keep-logcat', action='store_true', help='不清空 logcat 缓冲')
    args = ap.parse_args()

    bad = sorted(set(args.cmd) & BLACKLIST)
    if bad:
        print('拒绝执行：命令含黑名单字符 %s' % bad, file=sys.stderr)
        return 2

    os.makedirs(OUTDIR, exist_ok=True)
    payload = 'x\n' + args.cmd
    local = os.path.join(ROOT, '.build', 'payload_%s' % args.tag)
    with open(local, 'wb') as f:
        f.write(payload.encode('utf-8'))
    remote = '/data/local/tmp/_probe_%s' % args.tag

    print('载荷 (%d B): %r' % (len(payload.encode()), payload))
    r = subprocess.run([ADB, 'push', local, remote], capture_output=True, text=True,
                       env=dict(os.environ, MSYS_NO_PATHCONV='1'))
    if r.returncode != 0:
        print('push 失败: %s' % r.stderr, file=sys.stderr)
        return 3

    if not args.keep_logcat:
        adb('logcat', '-c')

    t0 = time.time()
    # 必须作为单个字符串传给 adb shell：分多个 argv 时 CLASSPATH 前缀会丢失，
    # 表现为 "could not find class 'FtmProbe'" 后 app_process abort（2026-11-18 12:30 踩坑）。
    cmd = ('CLASSPATH=/data/local/tmp/ftmprobe.jar app_process /system/bin '
           'FtmProbe %s %s @file %s' % (CODE, TOKEN, remote))
    r = adb('shell', cmd)
    dt = time.time() - t0
    print('---- 客户端输出 (%.2fs) ----' % dt)
    print(r.stdout.strip() or r.stderr.strip())

    time.sleep(0.8)
    log = adb('logcat', '-d', '-v', 'threadtime')
    out = os.path.join(OUTDIR, '%s_%s.log' % (time.strftime('%Y%m%dT%H%M%S'), args.tag))
    with open(out, 'w', encoding='utf-8') as f:
        f.write(log.stdout)

    keys = [args.tag, 'OplusWifiHalService', 'avc: denied']
    print('---- 相关日志 ----')
    hit = 0
    for line in log.stdout.splitlines():
        if any(k in line for k in keys):
            print(line[:240])
            hit += 1
    if not hit:
        print('（无匹配行）')
    print('---- 全量日志: %s（%d 行）----' % (os.path.relpath(out, ROOT), len(log.stdout.splitlines())))

    adb('shell', 'rm -f %s' % remote)
    return 0


if __name__ == '__main__':
    sys.exit(main())
