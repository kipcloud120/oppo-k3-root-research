#!/usr/bin/env python3
# 4.9 task_struct 布局自动推导（无需 C 编译器）
#
# 思路：cffi 的 sizeof/offsetof 由内置 libffi 后端计算，只需提供合法 C 声明。
#   1) 按本机 k3_kernel_config.txt 展开 #if/#ifdef/#ifndef/#else/#elif/#endif
#   2) 清理 GNU 扩展（__attribute__ / __rcu / __user / cacheline 对齐等）
#   3) 解析 struct task_struct 字段（含数组、多变量声明、位域）
#   4) 为每个嵌套类型生成"大小+对齐"占位声明，交给 libffi 做对齐计算
#   5) 用已知 task_struct slab 大小 3840 (0xF00) 做终点校准
#
# 用法: python tools/f16_taskstruct_layout.py [--dump]
import re
import sys
import collections
from cffi import FFI

SCHED = "src_ref/futex_4.9/sched.h"
CONFIG = "artifacts_adb/k3_kernel_config.txt"


# ---------- 1) config ----------
def load_config(path):
    cfg = {}
    for line in open(path, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if line.startswith("CONFIG_") and "=" in line:
            k, v = line.split("=", 1)
            cfg[k] = v.strip().strip('"')
        elif line.startswith("# CONFIG_") and line.endswith("is not set"):
            cfg[line.split()[1]] = None
    return cfg


CFG = load_config(CONFIG)


def cond(expr):
    e = expr.strip()
    e = re.sub(r"defined\s*\(\s*([A-Za-z0-9_]+)\s*\)",
               lambda m: "1" if CFG.get(m.group(1)) is not None else "0", e)
    e = re.sub(r"defined\s+([A-Za-z0-9_]+)",
               lambda m: "1" if CFG.get(m.group(1)) is not None else "0", e)
    e = re.sub(r"IS_ENABLED\s*\(\s*([A-Za-z0-9_]+)\s*\)",
               lambda m: "1" if CFG.get(m.group(1)) == "y" else "0", e)

    def repl(m):
        k = m.group(0)
        v = CFG.get(k)
        if v is None:
            return "0"
        if v in ("y", "m"):
            return "1"
        if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", v):
            return str(int(v, 0))
        return "1"

    e = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", repl, e)
    e = e.replace("&&", " and ").replace("||", " or ")
    e = re.sub(r"!(?!=)", " not ", e)
    try:
        return bool(eval(e, {"__builtins__": {}}, {}))
    except Exception:
        return False


def preprocess(text):
    out, stack, cur = [], [], True
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            m = re.match(r"#\s*(\w+)\s*(.*)", s)
            if not m:
                continue
            d, rest = m.group(1), m.group(2).strip()
            if d in ("ifdef", "ifndef"):
                v = cond(("" if d == "ifdef" else "!") + f"defined({rest})") if cur else False
                stack.append([cur, v, cur and v])
                cur = cur and v
            elif d == "if":
                v = cond(rest) if cur else False
                stack.append([cur, v, cur and v])
                cur = cur and v
            elif d == "elif":
                if stack:
                    p, taken, _ = stack[-1]
                    v = (not taken and cond(rest)) if p else False
                    stack[-1][1] = taken or v
                    stack[-1][2] = p and v
                    cur = p and v
            elif d == "else":
                if stack:
                    p, taken, _ = stack[-1]
                    stack[-1][1] = True
                    stack[-1][2] = p and (not taken)
                    cur = p and (not taken)
            elif d == "endif":
                if stack:
                    cur = stack.pop()[0]
            continue
        if cur:
            out.append(line)
    return "\n".join(out)


# ---------- 2) GNU 清理 ----------
def strip_attributes(s):
    while True:
        i = s.find("__attribute__")
        if i < 0:
            break
        j = s.find("(", i)
        if j < 0:
            s = s[:i] + s[i + len("__attribute__"):]
            continue
        depth, k = 0, j
        while k < len(s):
            if s[k] == "(":
                depth += 1
            elif s[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        s = s[:i] + " " + s[k + 1:]
    return s


GUNK = [
    "__rcu", "__user", "__percpu", "__force", "__bitwise", "__nocast",
    "____cacheline_aligned_in_smp", "__cacheline_aligned_in_smp",
    "__cacheline_aligned", "asmlinkage", "__maybe_unused", "noinline",
    "__read_mostly", "__const", "__init", "__exit", "____cacheline_aligned",
]


def sanitize(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    text = strip_attributes(text)
    for g in GUNK:
        text = re.sub(r"\b" + re.escape(g) + r"\b", " ", text)
    text = re.sub(r"\b__aligned\s*\([^)]*\)", " ", text)
    text = re.sub(r"\b__printf\s*\([^)]*\)", " ", text)
    return text


# ---------- 3) 类型表 ----------
# (C 等价声明, size, align)。size/align 为 4.9 arm64 LP64 下的值。
BASE = {
    "char": ("char", 1, 1), "signed char": ("signed char", 1, 1),
    "unsigned char": ("unsigned char", 1, 1),
    "short": ("short", 2, 2), "unsigned short": ("unsigned short", 2, 2),
    "int": ("int", 4, 4), "unsigned int": ("unsigned int", 4, 4),
    "unsigned": ("unsigned int", 4, 4),
    "long": ("long", 8, 8), "unsigned long": ("unsigned long", 8, 8),
    "long long": ("long long", 8, 8),
    "unsigned long long": ("unsigned long long", 8, 8),
    "void *": ("void *", 8, 8),
    "u8": ("unsigned char", 1, 1), "s8": ("signed char", 1, 1),
    "u16": ("unsigned short", 2, 2), "s16": ("short", 2, 2),
    "u32": ("unsigned int", 4, 4), "s32": ("int", 4, 4),
    "u64": ("unsigned long long", 8, 8), "s64": ("long long", 8, 8),
    "bool": ("_Bool", 1, 1), "_Bool": ("_Bool", 1, 1),
    "atomic_t": ("int", 4, 4), "atomic64_t": ("long long", 8, 8),
    "pid_t": ("int", 4, 4), "uid_t": ("unsigned int", 4, 4),
    "gid_t": ("unsigned int", 4, 4), "size_t": ("unsigned long", 8, 8),
    "gfp_t": ("unsigned int", 4, 4), "cputime_t": ("unsigned long long", 8, 8),
    "clockid_t": ("int", 4, 4), "timer_t": ("int", 4, 4),
    "seqcount_t": ("unsigned int", 4, 4), "seqlock_t": (None, 16, 8),
    "spinlock_t": ("unsigned int", 4, 4), "raw_spinlock_t": ("unsigned int", 4, 4),
    "arch_spinlock_t": ("unsigned int", 4, 4),
    "plist_node": (None, 40, 8), "list_head": (None, 16, 8),
    "llist_node": (None, 8, 8), "rb_node": (None, 24, 8),
    "rb_root": ("void *", 8, 8), "hlist_node": (None, 16, 8),
    "callback_head": (None, 16, 8), "rcu_head": (None, 16, 8),
    "thread_info": (None, 16, 8), "sigset_t": (None, 8, 8),
    "cpumask_t": (None, 8, 8), "cpumask_var_t": (None, 8, 8),
    "sched_entity": (None, 192, 8), "sched_rt_entity": (None, 48, 8),
    "sched_dl_entity": (None, 160, 8), "sched_class": (None, 88, 8),
    "ravg": (None, 64, 8), "latency_record": (None, 24, 8),
    "thread_struct": (None, 160, 16), "cred": (None, 168, 8),
    "ftrace_ret_stack": (None, 32, 8), "kcov": (None, 16, 8),
    "task_struct": ("void *", 8, 8), "uprobe_task": (None, 8, 8),
    "mem_cgroup": (None, 8, 8), "vm_struct": (None, 8, 8),
    "related_thread_group": (None, 8, 8), "perf_event_context": (None, 8, 8),
    "task_delay_info": (None, 8, 8), "prev_cputime": (None, 16, 8),
    "signal_struct": (None, 8, 8), "sighand_struct": (None, 8, 8),
    "files_struct": (None, 8, 8), "fs_struct": (None, 8, 8),
    "mm_struct": (None, 8, 8), "nsproxy": (None, 8, 8),
    "sysv_sem": (None, 8, 8), "sysv_shm": (None, 8, 8),
    "sem_undo_list": (None, 8, 8), "user_struct": (None, 8, 8),
    "group_info": (None, 8, 8), "task_io_accounting": (None, 64, 8),
    "acct": (None, 8, 8), "audit_context": (None, 8, 8),
    "seccomp": (None, 16, 8), "restart_block": (None, 48, 8),
    "task_cputime": (None, 24, 8), "load_weight": (None, 8, 8),
    "sched_statistics": (None, 8, 8), "rt_mutex_waiter": (None, 80, 8),
    "timer_list": (None, 40, 8), "hlist_head": ("void *", 8, 8),
    "wait_queue_head_t": (None, 24, 8), "completion": (None, 24, 8),
    "page_frag": (None, 16, 8), "tlbflush_unmap_batch": (None, 16, 8),
    "nodemask_t": (None, 8, 8), "mempolicy": (None, 8, 8),
    "pipe_inode_info": (None, 8, 8), "io_context": (None, 8, 8),
    "taskstats": (None, 8, 8), " blk_plug": (None, 8, 8),
}
# 枚举（4 字节）
ENUMS = {"kcov_mode": 4, "perf_event_task_context": 4}
MACROS = {"TASK_COMM_LEN": 16, "LT_SAVECOUNT": 32, "MAX_NUMNODES": 1,
          "CONFIG_NR_CPUS": 8, "NR_CPUS": 8, "TASK_SLACK": 0}


def placeholder(name, size, align):
    ctype = {1: "char", 2: "short", 4: "int", 8: "long long", 16: "long long"}[align]
    return f"struct {name} {{ union {{ {ctype} _a; char _p[{size}]; }} _u; }};"


def type_to_c(texpr):
    """把字段类型表达式转成 (C声明, 未知类型列表)"""
    t = re.sub(r"\b(const|volatile)\b", "", texpr).strip()
    t = re.sub(r"\s+", " ", t)
    ptr = t.count("*")
    core = t.replace("*", "").strip()
    unknown = []
    if ptr:
        return "void *", unknown
    # struct/union/enum
    m = re.match(r"^(struct|union|enum)\s+([A-Za-z0-9_]+)$", core)
    if m:
        kind, name = m.group(1), m.group(2)
        if kind == "enum":
            return "unsigned int", unknown
        if name in BASE and BASE[name][0] is not None:
            return BASE[name][0], unknown
        if name in BASE:
            return f"struct {name}", unknown
        unknown.append(name)
        BASE[name] = (None, 8, 8)   # 首轮占位，后续校准
        return f"struct {name}", unknown
    if core in BASE:
        return BASE[core][0] if BASE[core][0] else f"struct {core}", unknown
    if core in ENUMS:
        return "unsigned int", unknown
    # typedef 未知
    unknown.append(core)
    BASE[core] = (None, 8, 8)
    return f"struct {core}", unknown


# ---------- 4) 解析字段 ----------
def parse_fields(body):
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    # 去掉预处理后残留的宏/属性
    body = sanitize(body)
    decls, buf = [], ""
    # 按分号切分（task_struct 体内无嵌套定义）
    for chunk in body.split(";"):
        s = " ".join(chunk.split())
        if not s or s.startswith("#"):
            continue
        # 去掉可能残留的 "struct xxx {" 之类（不应出现）
        decls.append(s)
    return decls


def split_top(s, sep=","):
    """按顶层逗号切分（忽略 [] 与 () 内的逗号）"""
    parts, buf, depth = [], "", 0
    for ch in s:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(buf.strip()); buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf.strip())
    return parts


def parse_decl(d):
    """解析一条声明 -> [(类型表达式, 名字, 数组或None, 位域或None)]"""
    s = d.strip()
    bits = None
    m = re.search(r":\s*(\d+)\s*$", s)
    if m:
        bits = int(m.group(1))
        s = s[:m.start()].rstrip()
    parts = split_top(s)
    out, base_type = [], None
    NAME = r"^(?P<type>.*?)\s*(?P<stars>\*+)?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<arr>\[[^\]]*\])?$"
    for i, p in enumerate(parts):
        p = p.strip()
        mm = re.match(NAME, p)
        if not mm:
            continue
        typ = (mm.group("type") + " " + (mm.group("stars") or "")).strip()
        if i > 0:
            typ = base_type or typ
        if i == 0:
            base_type = typ
        nm = mm.group("name")
        if nm in ("unsigned", "signed", "long", "short", "int", "char",
                  "struct", "union", "enum", "const", "volatile"):
            # 匿名位域 / 纯类型：忽略
            continue
        out.append((typ, nm, mm.group("arr"), bits if i == 0 else None))
    return out


def main():
    src = open(SCHED, encoding="utf-8", errors="ignore").read()
    m = re.search(r"struct task_struct \{(.*?)\n\};", src, re.S)
    if not m:
        sys.exit("[!] struct task_struct not found")
    body = "\n".join(preprocess(m.group(1)).splitlines())
    decls = parse_fields(body)
    print(f"[*] config entries={len(CFG)}  preprocessed field decls={len(decls)}")

    ffi = FFI()
    cdef_parts, lines, unknown = [], [], []
    # 占位声明（每次循环重建，因为 BASE 可能被追加）
    for name, (cdecl, size, align) in list(BASE.items()):
        if cdecl is None:
            cdef_parts.append(placeholder(name, size, align))
    ffi.cdef("\n".join(cdef_parts))

    # 生成 task_struct 字段
    flds, failed = [], []
    for d in decls:
        parsed = parse_decl(d)
        if not parsed:
            failed.append(d)
            continue
        for texpr, name, arr, bits in parsed:
            ctype, unk = type_to_c(texpr)
            unknown += unk
            decl = f"  {ctype} {name}"
            if arr:
                n = arr.strip("[]").strip()
                for k, v in MACROS.items():
                    n = n.replace(k, str(v))
                try:
                    n = str(eval(n, {"__builtins__": {}}, {}))
                except Exception:
                    n = "1"
                decl += f"[{n}]"
            elif bits:
                decl += f" : {bits}"
            flds.append((name, decl))
            lines.append(decl + ";")
    if failed:
        print(f"[*] 未解析 decl {len(failed)} 条: " + " | ".join(failed[:8]))

    # 未知类型可能在第一轮才加入 BASE，需要重建 cdef
    ffi2 = FFI()
    cdef2 = [placeholder(n, s, a) for n, (c, s, a) in BASE.items() if c is None]
    ffi2.cdef("\n".join(cdef2))
    ffi2.cdef("struct task_struct {\n" + "\n".join(lines) + "\n};")

    print(f"[*] parsed fields={len(flds)}  nested types={sum(1 for c,s,a in BASE.values() if c is None)}")
    print(f"[*] unknown/placeholder types: {sorted(set(unknown))}")
    print(f"\n[*] sizeof(struct task_struct) = {ffi2.sizeof('struct task_struct')}"
          f"  (target slab size 3840 / 0xF00)")
    for f in ("cred", "real_cred", "ptracer_cred", "pi_blocked_on",
              "pi_waiters", "pi_waiters_leftmost", "comm", "thread"):
        try:
            print(f"    offsetof({f:20s}) = 0x{ffi2.offsetof('struct task_struct', f):x}"
                  f" ({ffi2.offsetof('struct task_struct', f)})")
        except Exception as e:
            print(f"    offsetof({f:20s}) = N/A ({e})")
    if "--dump" in sys.argv:
        print("\n[*] 字段列表：")
        for n, d in flds:
            print("   ", d.strip())


if __name__ == "__main__":
    main()
