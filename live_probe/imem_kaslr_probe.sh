#!/system/bin/sh
# ------------------------------------------------------------------
# IMEM KASLR offset 只读判定探针（路径 1，2026-11-20）
#
# 依据（离线证据链，见 IMEM_KASLR_EVIDENCE.md）：
#   /soc/qcom,msm-imem@146bf000/kaslr_offset@6d0  reg = <0x6d0 0xc>
#   落盘物理地址 = 0x146BF000 + 0x6D0 = 0x146BF6D0，长度 12 字节
#   布局: +0  magic 0xdead4ead
#         +4  slide 低 32 位 (kimage_vaddr - KIMAGE_VADDR)
#         +8  slide 高 32 位
#
# 只读性：仅 dd 读取 4096 字节 IMEM 页 + 12 字节提取；无任何写操作。
# 运行方法（Git Bash 下先 export MSYS_NO_PATHCONV=1）：
#   adb push live_probe/imem_kaslr_probe.sh /data/local/tmp/
#   adb shell 'sh /data/local/tmp/imem_kaslr_probe.sh'
#   adb shell 'rm -f /data/local/tmp/imem_kaslr_probe.sh'
# ------------------------------------------------------------------

BID1=$(cat /proc/sys/kernel/random/boot_id 2>&1)
UPT1=$(cat /proc/uptime 2>&1)
echo "boot_id_before=$BID1"
echo "uptime_before=$UPT1"

# 门 1: /dev/mem 节点是否存在
echo "--- gate1: ls /dev/mem ---"
ls -l /dev/mem 2>&1

# 门 2: 约束 sysctl 实际值（仅记录，供路径 2 参考）
echo "--- gate2: sysctls ---"
echo "kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>&1)"
echo "perf_event_paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>&1)"

# 门 3: 只读读出 IMEM 页（0x146BF000 起 1 页, 块号 83647）
echo "--- gate3: dd /dev/mem ---"
dd if=/dev/mem of=/data/local/tmp/imem_page.bin bs=4096 skip=83647 count=1 2>&1
if [ -f /data/local/tmp/imem_page.bin ]; then
    echo "--- extract @0x6d0 len 12 ---"
    # 期望首 4 字节: ad 4e ad de (little-endian 0xdead4ead)
    od -A d -t x1 -j 1744 -N 12 /data/local/tmp/imem_page.bin 2>&1
    # 附带: 同页其余 IMEM 子块原始内容只读留档（boot_stats/restart_reason 等）
    od -A x -t x1 -N 0x100 /data/local/tmp/imem_page.bin 2>&1 | head -20
fi

BID2=$(cat /proc/sys/kernel/random/boot_id 2>&1)
UPT2=$(cat /proc/uptime 2>&1)
echo "boot_id_after=$BID2"
echo "uptime_after=$UPT2"

rm -f /data/local/tmp/imem_page.bin
echo "cleanup_done"
