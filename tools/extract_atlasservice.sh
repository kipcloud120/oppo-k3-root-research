#!/usr/bin/env bash
# 从 system.img 中提取 root atlasservice 二进制（7-Zip 读 ext4）
set -e
SEVENZ="/c/Program Files/7-Zip/7z.exe"
BASE="$(cd "$(dirname "$0")/.." && pwd)/artifacts_adb/binder_audit/rootbin"
IMG="$BASE/system.img"
OUT="$BASE/atlasservice"
WORK="$BASE/_extract"

echo "=== 列出镜像中 atlasservice 相关路径 ==="
"$SEVENZ" l "$IMG" 2>/dev/null | grep -i 'atlasservice' | head -20 || true

echo "=== 尝试路径1: system/system_ext/bin/atlasservice ==="
rm -f "$OUT"
"$SEVENZ" e -y -o"$WORK" "$IMG" 'system/system_ext/bin/atlasservice' >/dev/null 2>&1 || true
[ -f "$WORK/atlasservice" ] && cp "$WORK/atlasservice" "$OUT" && echo "found via path1"

echo "=== 尝试路径2: system_ext/bin/atlasservice ==="
if [ ! -f "$OUT" ]; then
  "$SEVENZ" e -y -o"$WORK" "$IMG" 'system_ext/bin/atlasservice' >/dev/null 2>&1 || true
  [ -f "$WORK/atlasservice" ] && cp "$WORK/atlasservice" "$OUT" && echo "found via path2"
fi

echo "=== 尝试路径3: 用 x 保留完整路径后 find ==="
if [ ! -f "$OUT" ]; then
  "$SEVENZ" x -y -o"$WORK" "$IMG" '*atlasservice*' >/dev/null 2>&1 || true
  FOUND=$(find "$WORK" -name atlasservice -type f 2>/dev/null | head -1)
  [ -n "$FOUND" ] && cp "$FOUND" "$OUT" && echo "found via path3: $FOUND"
fi

if [ -f "$OUT" ]; then
  echo "=== 提取成功 ==="
  ls -l "$OUT"
  head -c 4 "$OUT" | xxd | head -1
else
  echo "!!! 未找到 atlasservice"
  exit 1
fi
