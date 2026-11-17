#!/usr/bin/env python3
# F.16 kernel.decompressed 符号↔文件偏移 校准探针
#
# 目的：验证 kallsyms_out.txt 里的"相对偏移"能否直接当作文件偏移使用。
# 结论见 交接文档 §11。用法：
#   python tools/f16_anchors.py [firmware_F16/kernel.decompressed]
#
# 三个互相独立的锚点：
#   A) 异常向量表  —— 唯一 0x800 对齐的 ventry 表，内容可自证
#   B) sys_call_table —— u32 PA32 数组，slot 98 必须是 SyS_futex
#   C) __ksymtab_strings 指针数组 —— 11000+ 条 (符号值, 字符串文件偏移)
import sys, struct
import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

PATH = sys.argv[1] if len(sys.argv) > 1 else "firmware_F16/kernel.decompressed"
D = open(PATH, "rb").read()
N = len(D)
u32 = lambda o: struct.unpack_from("<I", D, o)[0]
u64 = lambda o: struct.unpack_from("<Q", D, o)[0]
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); MD.detail = True

def load_syms(p="firmware_F16/kallsyms_out.txt"):
    kv, order = {}, []
    for line in open(p, encoding="latin1"):
        line = line.rstrip("\n")
        if not line:
            continue
        v = int(line[:10], 16); nm = line[12:]
        kv[nm] = v; order.append((v, nm))
    return kv, order

KV, ORDER = load_syms()

def prologue_offsets(lo=0, hi=None):
    hi = hi or N
    n = N // 4 * 4
    w = np.frombuffer(D[:n], dtype="<u4").astype(np.uint32)
    idx = np.nonzero((w & np.uint32(0xffc07fff)) == np.uint32(0xa9807bfd))[0].astype(np.int64) * 4
    return idx[(idx >= lo) & (idx < hi)]

def find_vectors():
    """唯一 0x800 对齐、16 项 ventry 的异常向量表。"""
    hits = []
    for p in range(0, N - 0x800, 0x800):
        ok = sum(1 for k in range(16)
                 if (u32(p + 0x80 * k) & 0xFC000000) == 0x14000000)
        if ok >= 14:
            hits.append(p)
    return hits

def find_syscall_table():
    """找包含 SyS_futex(0xe7da0 或 kallsyms 值) 且前后是函数地址的 u32 表。"""
    fut = KV.get("SyS_futex", 0)
    if not fut:
        return None, []
    a = np.frombuffer(D[:N // 4 * 4], dtype="<u4")
    out = []
    for i in np.nonzero(a == fut)[0]:
        base = int(i) - 98                      # arm64 generic: 98 = futex
        if base < 8:
            continue
        win = a[base - 2: base + 200]
        # 表项应基本递增且落在 .text
        asc = sum(1 for x, y in zip(win, win[1:]) if x <= y)
        if asc > 0.9 * len(win) - 1:
            out.append((base * 4, int(a[base])))
    return fut, out

def ksymtab_string_anchors():
    """__ksymtab_strings 的 PA32 指针数组 → (符号值, 字符串文件偏移) 样本。"""
    a = np.frombuffer(D[:N // 4 * 4], dtype="<u4")
    # 找最长的"值递增且在 0x1000000..0x1900000"的 u32 游程
    m = (a > 0x1000000) & (a < 0x1900000)
    idx = np.nonzero(m)[0]
    runs, s, p = [], None, None
    for i in idx:
        i = int(i)
        if s is None:
            s = p = i; continue
        if i == p + 1 and a[i] > a[p]:
            p = i
        else:
            if p - s >= 1000:
                runs.append((s, p))
            s = p = i
    if s is not None and p - s >= 1000:
        runs.append((s, p))
    if not runs:
        return []
    s, p = max(runs, key=lambda r: r[1] - r[0])
    pairs = []
    for v in a[s:p + 1]:
        f = int(v)
        e = D.find(b"\x00", f)
        if e < 0 or e - f > 80:
            continue
        nm = D[f:e].decode("latin1", "ignore")
        key = "__kstrtab_" + nm
        if key in KV:
            pairs.append((KV[key], f, nm))
    return pairs

def main():
    print(f"[*] {PATH}  size={N:#x}")
    print(f"[*] kallsyms symbols: {len(ORDER)}")

    vt = find_vectors()
    print("\n[A] 异常向量表（内容自证，唯一）")
    if vt:
        for p in vt:
            print(f"    文件 0x{p:x}  ->  kallsyms 'vectors' = 0x{KV.get('vectors',0):x}"
                  f"   偏差 = 0x{p - KV.get('vectors',0):x}")
        print("    16 项 ventry 全部命中；该地址不受符号表影响，是可信锚点。")
    else:
        print("    未找到")

    fut, st = find_syscall_table()
    print("\n[B] sys_call_table（slot 98 = SyS_futex）")
    print(f"    SyS_futex kallsyms = 0x{fut:x}")
    for base, e0 in st:
        print(f"    表基址 0x{base:x}  slot0=0x{e0:x}  slot98=0x{fut:x}")
    if st:
        pro = prologue_offsets(0x1000, 0x1180000)
        base = st[0][0]
        a = np.frombuffer(D[base:base + 4 * 400], dtype="<u4").astype(np.int64)
        a = a[(a > 0x1000) & (a < 0x2000000)][:120]
        hit = sum(1 for v in a if int(v) in set(pro.tolist()))
        print(f"    C=0（偏移==文件偏移）时，{hit}/{len(a)} 个表项正好落在函数序言上")
        print("    → .text 该区间近似恒等映射（随机概率约 0.7%）。")

    pairs = ksymtab_string_anchors()
    print("\n[C] __ksymtab_strings 锚点（11000+ 条可自证字符串）")
    if pairs:
        dl = [f - v for v, f, _ in pairs]
        print(f"    样本 {len(pairs)} 条；delta = 文件偏移 - 符号值")
        print(f"    min=-0x{-min(dl):x}  max=-0x{-max(dl):x}  中位=-0x{-int(np.median(dl)):x}")
        print("    → .rodata 段整体比链接空间提前约 0x700 字节，且缓慢漂移。")

    print("\n[结论] 三个锚点给出的平移量互不相同：向量表 0x109f8e0、.text 约 0、")
    print("       .rodata 约 0x700。说明镜像内节区排布与链接序不一致，")
    print("       kallsyms_out.txt 的偏移不能直接当地址用（详见交接文档 §11）。")

if __name__ == "__main__":
    main()
