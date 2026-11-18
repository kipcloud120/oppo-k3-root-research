#!/usr/bin/env bash
# 构建一个可在设备上运行的 Java Binder 探针（dex），用于验证私有事务是否可达。
#
# 为什么需要它：`service call` 只能拼出「裸参数」的 Parcel，无法复现 Java 侧
# `writeInterfaceToken` 的完整语义；AOSP 分支与 OPPO 私有分支对报文的要求不同，
# 于是出现「静态看没有门禁、动态却过不去」的僵局。真客户端能一次性排除这个变量。
#
# 依赖（均放在 .build/，不入库）：
#   .build/jdk/jdk-11.0.20+8/bin/{javac,jar,java}.exe     # Microsoft OpenJDK 11
#       https://aka.ms/download-jdk/microsoft-jdk-11.0.20-windows-x64.zip
#   .build/jdkpkg/r8.jar                                   # D8，来自 Google Maven
#       https://dl.google.com/dl/android/maven2/com/android/tools/r8/<ver>/r8-<ver>.jar
#
# 用法：bash tools/javaprobe/build.sh
# 产物：.build/jdkpkg/ftmprobe.jar（内含 classes.dex）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
JDK="${JDK:-$ROOT/.build/jdk/jdk-11.0.20+8/bin}"
R8="${R8:-$ROOT/.build/jdkpkg/r8.jar}"
WORK="$ROOT/.build/jdkpkg"
SRC="$ROOT/tools/javaprobe"

mkdir -p "$WORK/stubc" "$WORK/out" "$WORK/dex"
"$JDK/javac.exe" -nowarn -d "$WORK/stubc" "$SRC"/android/os/*.java
( cd "$WORK/stubc" && "$JDK/jar.exe" cf "$WORK/stubs.jar" . )
"$JDK/javac.exe" -nowarn -cp "$WORK/stubs.jar" -d "$WORK/out" "$SRC/FtmProbe.java"
"$JDK/java.exe" -cp "$R8" com.android.tools.r8.D8 --lib "$WORK/stubs.jar" \
    --min-api 30 --output "$WORK/dex" "$WORK/out/FtmProbe.class"
python - "$WORK" <<'PY'
import sys, zipfile, os
w=sys.argv[1]
z=zipfile.ZipFile(os.path.join(w,'ftmprobe.jar'),'w',zipfile.ZIP_DEFLATED)
z.write(os.path.join(w,'dex','classes.dex'),'classes.dex'); z.close()
print("built", os.path.join(w,'ftmprobe.jar'))
PY

cat <<'TIP'

运行（设备侧，只读事务）：
  adb push .build/jdkpkg/ftmprobe.jar /data/local/tmp/
  adb shell "CLASSPATH=/data/local/tmp/ftmprobe.jar app_process /system/bin FtmProbe 10069 android.net.wifi.IOplusWifiManager"
  # 参数：<transaction code> <interface token>
TIP
