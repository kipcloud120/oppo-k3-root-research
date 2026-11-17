#!/usr/bin/env python3
"""
gl_frame_calc.py — GhostLock(CVE-2026-43499) 栈重叠可行性计算器（arm64 / 4.9）

目的（§24.6 闸门 G1）：
  判定 futex 路径上 `rt_mutex_waiter` 的绝对栈位置，是否落在 pselect 路径
  `core_sys_select()` 的 `stack_fds`（用户可控 fd_set 位图区）之内。

输入：firmware_F16/vmlinux.elf（由 vmlinux-to-elf 从 kernel.decompressed 重建，
      符号空间已验证：stext 反汇编可读出 preserve_boot_args/el2_setup/__create_page_tables）

输出：两条路径的 SP 位移链、waiter/stack_fds 的绝对偏移、重叠判定、可用 NFDS 建议。

用法：
  python tools/gl_frame_calc.py
"""
import struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ELF = "firmware_F16/vmlinux.elf"
S_FRAME = 0x110          # arm64 pt_regs（kernel_entry 的 sub sp,sp,#S_FRAME_SIZE）
WAITER_SZ = 72           # 4.9: rb_node(24)+rb_node(24)+task(8)+lock(8)+prio(4) -> 72
FDS_USER_SETS = 3        # in/out/ex 三张位图被 copy_from_user


class Vmlinux:
    def __init__(self, path):
        self.fh = open(path, "rb")
        self.elf = ELFFile(self.fh)
        self.sec = [s for s in self.elf.iter_sections() if s.name == ".kernel"][0]
        self.base = self.sec["sh_addr"]
        self.syms = {}
        self.starts = []
        symtab = self.elf.get_section_by_name(".symtab")
        for s in symtab.iter_symbols():
            if s.name and s["st_info"]["type"] == "STT_FUNC":
                self.syms.setdefault(s.name, s["st_value"])
        self.starts = sorted(self.syms.values())

    def off(self, va):
        return self.sec["sh_offset"] + (va - self.sec["sh_addr"])

    def read(self, va, n):
        self.fh.seek(self.off(va))
        return self.fh.read(n)

    def end_of(self, va, limit=0x4000):
        for s in self.starts:
            if s > va:
                return min(s, va + limit)
        return va + limit

    def dis(self, va, n=None):
        if n is None:
            n = self.end_of(va) - va
        code = self.read(va, n)
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True
        return list(md.disasm(code, va))

    def addr(self, name):
        return self.syms.get(name)


def frame_size(insns):
    """函数入口的 SP 下移量（取前若干条 sub sp,sp,#imm / stp 预索引 的最大累计）"""
    total = 0
    for i in insns[:8]:
        if i.mnemonic == "sub" and len(i.operands) == 3:
            if i.op_str.replace(" ", "").startswith("sp,sp,#"):
                try:
                    total += int(i.op_str.split("#")[-1], 0)
                except ValueError:
                    pass
        elif i.mnemonic in ("stp", "str") and "!" in i.op_str and "[sp, #-" in i.op_str:
            try:
                total += int(i.op_str.split("[sp, #-")[1].split("]")[0], 0)
            except ValueError:
                pass
    return total


def find_calls(insns, target_names, syms):
    """返回 [(idx, 目标名 or None, 目标地址)]，含 bl/blr 与 adrp+add+blr 三连"""
    out = []
    for idx, i in enumerate(insns):
        if i.mnemonic == "bl":
            tgt = int(i.op_str.lstrip("#"), 0)
            nm = None
            for k, v in syms.items():
                if v == tgt:
                    nm = k
                    break
            out.append((idx, nm, tgt))
        elif i.mnemonic == "blr":
            # 回溯 adrp/add 组合
            reg = i.op_str.strip()
            nm = None
            for j in range(idx - 1, max(idx - 4, -1), -1):
                if insns[j].mnemonic == "add" and insns[j].op_str.startswith(reg + ", "):
                    if "sp" in insns[j].op_str:
                        break
                    nm = "<adrp+add:%s>" % insns[j].op_str
                    break
            out.append((idx, nm, None))
    return out


def prev_sp_rel(insns, idx, reg):
    """在 idx 之前找 add <reg>, sp, #imm / mov <reg>, sp，返回立即数"""
    for j in range(idx - 1, max(idx - 12, -1), -1):
        i = insns[j]
        if i.mnemonic == "add" and i.op_str.startswith(reg + ", sp"):
            try:
                return int(i.op_str.split("#")[-1], 0)
            except ValueError:
                return None
        if i.mnemonic in ("mov", "add") and i.op_str.replace(" ", "") == reg + ",sp":
            return 0
    return None


def main():
    v = Vmlinux(ELF)
    print(f"[+] base={v.base:#x}")
    report = {}

    # ---------- futex 路径 ----------
    names = ["SyS_futex", "do_futex", "rt_mutex_start_proxy_lock",
             "rt_mutex_wait_proxy_lock", "rt_mutex_cleanup_proxy_lock"]
    for n in names:
        print(f"    {n:30s} {v.addr(n) if v.addr(n) else 'ABSENT'}")

    sy = v.dis(v.addr("SyS_futex"))
    do = v.dis(v.addr("do_futex"))
    sy_f, do_f = frame_size(sy), frame_size(do)
    print(f"[+] SyS_futex  frame={sy_f:#x}  do_futex frame={do_f:#x}")

    calls = find_calls(do, names, v.syms)
    print("[+] do_futex 内可疑调用：")
    waiter_off = None
    for idx, nm, tgt in calls:
        if nm and nm.startswith("rt_mutex"):
            # rt_mutex_start_proxy_lock(lock=x0, waiter=x1, task=x2)
            rel = prev_sp_rel(do, idx, "x1")
            print(f"    {do[idx].address:#x} bl {nm}   waiter=x1 <- sp+{rel if rel is None else hex(rel)}")
            if nm == "rt_mutex_start_proxy_lock" and rel is not None:
                waiter_off = rel
        elif nm is None:
            print(f"    {do[idx].address:#x} blr {do[idx].op_str}  ({tgt and hex(tgt)})")
    report["waiter_off_in_do_futex"] = waiter_off
    report["sy_futex_frame"] = sy_f
    report["do_futex_frame"] = do_f

    # ---------- pselect 路径 ----------
    ps = v.dis(v.addr("SyS_pselect6"))
    cs = v.dis(v.addr("core_sys_select"))
    ps_f, cs_f = frame_size(ps), frame_size(cs)
    print(f"[+] SyS_pselect6 frame={ps_f:#x}  core_sys_select frame={cs_f:#x}")

    # stack_fds 的 sp 相对偏移：core_sys_select 中 bits=stack_fds 时会是 mov/add xN,sp,#imm
    fds_off = None
    cands = []
    for idx, i in enumerate(cs):
        if i.mnemonic == "add" and i.op_str.replace(" ", "").endswith(",sp,#0x0"):
            cands.append((idx, 0))
        elif i.mnemonic == "add" and ", sp, #" in i.op_str:
            try:
                cands.append((idx, int(i.op_str.split("#")[-1], 0)))
            except ValueError:
                pass
        elif i.mnemonic == "mov" and i.op_str.replace(" ", "") in ("x0,sp", "x1,sp", "x2,sp", "x8,sp"):
            cands.append((idx, 0))
    print(f"[+] core_sys_select 内 sp 相对地址候选 {len(cands)} 处：")
    for idx, imm in cands[:12]:
        print(f"    {cs[idx].address:#x}  {cs[idx].mnemonic} {cs[idx].op_str}   (sp+{imm:#x})")
    if cands:
        fds_off = min(imm for _, imm in cands)
    report["stack_fds_off"] = fds_off
    report["sy_pselect6_frame"] = ps_f
    report["core_sys_select_frame"] = cs_f

    # ---------- 汇总 ----------
    print("\n===== 汇总 =====")
    if waiter_off is None or fds_off is None:
        print("[!] 关键偏移未能确定，需人工复核（见上方候选）")
        return report

    # 绝对位置：以“进入内核时的栈顶”为 0，向下为负
    futex_abs = -(S_FRAME + sy_f + do_f + waiter_off)      # waiter 起始
    psel_abs = -(S_FRAME + ps_f + cs_f + fds_off)          # stack_fds 起始
    print(f"  futex 路径：pt_regs {S_FRAME:#x} + SyS_futex {sy_f:#x} + do_futex {do_f:#x} + waiter {waiter_off:#x}")
    print(f"    waiter 起始 = {futex_abs:#x}  … {futex_abs + WAITER_SZ:#x}")
    print(f"  pselect 路径：pt_regs {S_FRAME:#x} + SyS_pselect6 {ps_f:#x} + core_sys_select {cs_f:#x} + stack_fds {fds_off:#x}")
    print(f"    stack_fds 起始 = {psel_abs:#x}")

    max_user = 6 * 0  # placeholder
    for nfds in (64, 128, 192, 256, 320, 336):
        size = (nfds + 7) // 8
        total = 6 * size
        if total > 256:
            print(f"  NFDS={nfds}: 6*size={total} > 256 -> 走 kmalloc，不可用")
            continue
        user_len = FDS_USER_SETS * size
        b0 = psel_abs
        b1 = psel_abs + user_len
        ok = (b0 <= futex_abs) and (futex_abs + WAITER_SZ <= b1)
        word = (futex_abs - b0) // 8
        print(f"  NFDS={nfds}: size={size} 用户区=[{b0:#x},{b1:#x}) waiter=[{futex_abs:#x},{futex_abs + WAITER_SZ:#x}) "
              f"起始字={word if futex_abs >= b0 else 'N/A'} -> {'可行 ✅' if ok else '不重叠 ❌'}")
    return report


if __name__ == "__main__":
    main()
