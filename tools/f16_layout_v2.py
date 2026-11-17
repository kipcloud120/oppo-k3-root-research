#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
4.9 task_struct 布局递归推导（无 C 编译器，纯 Python 布局引擎）
==============================================================
目标：从 4.9 源码头文件池 + 本机 k3_kernel_config.txt，递归推导
      struct task_struct 的真实内存布局，产出
      offsetof(real_cred) / offsetof(cred) / offsetof(pi_blocked_on)
      以及以 slab 大小 3840(0xF00) 为终点的校准与置信度。

设计要点：
  * 自写 LP64 布局引擎，完全可控对齐（含 ____cacheline_aligned / __aligned(N)）。
  * 用 config 驱动 #if/#ifdef 预处理（与 f16 前版同逻辑）。
  * 递归解析内联（by-value）嵌套结构；指针字段恒为 8 字节。
  * DECLARE_BITMAP / BITS_TO_LONGS / BITS_PER_LONG / NR_CPUS 等宏展开。
  * 未知类型降级为 8 字节占位并显式汇报，便于定位缺口。
"""
import re
import os
import sys

HDR_DIR = "src_ref/futex_4.9"
SCHED = os.path.join(HDR_DIR, "sched.h")
CONFIG = "artifacts_adb/k3_kernel_config.txt"
TARGET_SLAB = 3840  # 0xF00，来自 k3_info*.txt 的 task_struct slab 大小

# ----------------------------------------------------------------------
# 1) config 预处理
# ----------------------------------------------------------------------
def load_config(path):
    cfg = {}
    if not os.path.exists(path):
        return cfg
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
               lambda m: "1" if (CFG.get(m.group(1)) is not None or m.group(1) in MACROS) else "0", e)
    e = re.sub(r"defined\s+([A-Za-z0-9_]+)",
               lambda m: "1" if (CFG.get(m.group(1)) is not None or m.group(1) in MACROS) else "0", e)
    e = re.sub(r"IS_ENABLED\s*\(\s*([A-Za-z0-9_]+)\s*\)",
               lambda m: "1" if CFG.get(m.group(1)) == "y" else "0", e)

    def repl(m):
        k = m.group(0)
        if k in CFG:
            v = CFG[k]
            if v is None:
                return "0"
            if v in ("y", "m"):
                return "1"
            if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", v):
                return str(int(v, 0))
            return "1"
        if k in MACROS:
            return str(MACROS[k])
        return k  # 保留其他标识符交给外层（如宏名）

    e = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", repl, e)
    e = e.replace("&&", " and ").replace("||", " or ")
    e = re.sub(r"!(?!=)", " not ", e)
    try:
        return bool(eval(e, {"__builtins__": {}, **MACROS}, {}))
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


# ----------------------------------------------------------------------
# 2) 源码清洗
# ----------------------------------------------------------------------
def strip_comments(s):
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    s = re.sub(r"//[^\n]*", " ", s)
    return s


def strip_strings(s):
    return re.sub(r'"(\\.|[^"\\])*"', '""', s)


GUNK = [
    "__rcu", "__user", "__percpu", "__force", "__bitwise", "__nocast",
    "__attribute__", "__visible", "asmlinkage", "__maybe_unused", "noinline",
    "__read_mostly", "__const", "__init", "__exit", "__warm", "unlikely",
    "likely", "ACCESS_ONCE", "READ_ONCE", "WRITE_ONCE", "smp_mb", "barrier",
    "__attribute", "packed", "aligned",
]


def clean(text):
    text = strip_strings(strip_comments(text))
    # 把 cacheline 对齐标记成可识别的占位符
    text = re.sub(r"____cacheline_aligned_in_smp", " @CL@ ", text)
    text = re.sub(r"__cacheline_aligned_in_smp", " @CL@ ", text)
    text = re.sub(r"____cacheline_aligned\b", " @CL@ ", text)
    text = re.sub(r"__cacheline_aligned\b", " @CL@ ", text)
    text = re.sub(r"__aligned\s*\(\s*(\d+)\s*\)", r" @AL(\1)@ ", text)
    # 去掉 __attribute__((...)) 剩余
    while True:
        i = text.find("__attribute")
        if i < 0:
            break
        j = text.find("(", i)
        if j < 0:
            text = text[:i] + " " + text[i + len("__attribute"):]
            continue
        depth, k = 0, j
        while k < len(text):
            if text[k] == "(":
                depth += 1
            elif text[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        text = text[:i] + " " + text[k + 1:]
    for g in GUNK:
        text = re.sub(r"\b" + re.escape(g) + r"\b", " ", text)
    text = re.sub(r"\bvolatile\b", " ", text)
    text = re.sub(r"\bconst\b", " ", text)
    text = re.sub(r"\bstatic\b", " ", text)
    text = re.sub(r"\binline\b", " ", text)
    text = re.sub(r"\brestrict\b", " ", text)
    # DECLARE_BITMAP(name, n) -> unsigned long name[BITS_TO_LONGS(n)]
    def bitmap(m):
        name = m.group(1)
        n = m.group(2)
        try:
            nn = int(eval(n, {"__builtins__": {}}, MACROS))
            lon = (nn + 63) // 64
        except Exception:
            lon = 1
        return f"unsigned long {name}[{lon}]"
    text = re.sub(r"DECLARE_BITMAP\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([^)]*)\)",
                  bitmap, text)
    return text


# ----------------------------------------------------------------------
# 3) 标量 / typedef 表
# ----------------------------------------------------------------------
SCALAR = {
    "void": (0, 1), "char": (1, 1), "signed char": (1, 1), "unsigned char": (1, 1),
    "short": (2, 2), "unsigned short": (2, 2), "short int": (2, 2),
    "int": (4, 4), "unsigned int": (4, 4), "unsigned": (4, 4), "signed int": (4, 4),
    "long": (8, 8), "unsigned long": (8, 8), "long int": (8, 8),
    "unsigned long int": (8, 8), "long long": (8, 8), "unsigned long long": (8, 8),
    "bool": (1, 1), "_Bool": (1, 1), "float": (4, 4), "double": (8, 8),
    "long double": (16, 16),
    "u8": (1, 1), "s8": (1, 1), "u16": (2, 2), "s16": (2, 2),
    "u32": (4, 4), "s32": (4, 4), "u64": (8, 8), "s64": (8, 8),
    "size_t": (8, 8), "ssize_t": (8, 8), "pid_t": (4, 4), "uid_t": (4, 4),
    "gid_t": (4, 4), "gfp_t": (4, 4), "cputime_t": (8, 8), "clockid_t": (4, 4),
    "timer_t": (4, 4), "atomic_t": (4, 4), "atomic64_t": (8, 8),
    "atomic_long_t": (8, 8), "phys_addr_t": (8, 8), "dma_addr_t": (8, 8),
    "resource_size_t": (8, 8), "sector_t": (8, 8), "loff_t": (8, 8),
    "off_t": (8, 8), "pgoff_t": (8, 8), "cycles_t": (8, 8), "uintptr_t": (8, 8),
    "intptr_t": (8, 8), "dev_t": (4, 4), "ino_t": (8, 8), "mode_t": (4, 4),
    "umode_t": (4, 4), "nlink_t": (4, 4), "blkcnt_t": (8, 8), "key_serial_t": (4, 4),
    "qid_t": (4, 4), "kuid_t": (4, 4), "kgid_t": (4, 4), "projid_t": (4, 4),
    "aio_context_t": (8, 8), "mm_segment_t": (8, 8), "sighandl_t": (4, 4),
    "elf_greg_t": (8, 8), "elf_greg_t64": (8, 8), "compat_ulong_t": (4, 4),
    "compat_uptr_t": (4, 4), "compat_size_t": (4, 4), "compat_ssize_t": (4, 4),
    "int8_t": (1, 1), "int16_t": (2, 2), "int32_t": (4, 4), "int64_t": (8, 8),
    "uint8_t": (1, 1), "uint16_t": (2, 2), "uint32_t": (4, 4), "uint64_t": (8, 8),
    "fprec_t": (8, 8),
    "__uint128_t": (16, 16), "uint128_t": (16, 16), "__int128": (16, 16),
    "int128_t": (16, 16),
    # 内核专用标量（typedef 到 struct 的占位用真实尺寸）
    "kernel_cap_t": (8, 8), "kuid_t": (4, 4), "kgid_t": (4, 4),
    "kernel_sigset_t": (8, 8),
}

MACROS = {
    "BITS_PER_LONG": 64, "NR_CPUS": 8, "CONFIG_NR_CPUS": 8,
    "TASK_COMM_LEN": 16, "LT_SAVECOUNT": 32, "MAX_LOCK_DEPTH": 48,
    "L1_CACHE_BYTES": 64, "L1_CACHE_SHIFT": 6, "PAGE_SIZE": 4096,
    "BITS_PER_BYTE": 8, "_NSIG": 64,
    # 内核 C 编译必备且恒为真的宏（否则会被 #ifdef 整段删除）
    "__KERNEL__": 1,
}

TDEF = {}          # 名字 -> ('scalar',size,align) | ('compound',name) | ('typeexpr',str)
COMPOUNDS = {}     # 名字 -> Compound
ENUMS = set()      # 枚举名
UNRESOLVED = set() # 未能解析的名字


class Compound:
    def __init__(self, name, body, whole_cacheline=False, kind="struct"):
        self.name = name
        self.body = body
        self.fields = None      # list of (name, desc, cacheline)
        self.size = 0
        self.align = 8
        self.whole_cacheline = whole_cacheline
        self.kind = kind        # 'struct' or 'union'
        self.resolved = False


def align_up(x, a):
    if a <= 1:
        return x
    return ((x + a - 1) // a) * a


# ----------------------------------------------------------------------
# 4) 提取头文件中的定义
# ----------------------------------------------------------------------
def extract_defs():
    files = [os.path.join(HDR_DIR, f) for f in os.listdir(HDR_DIR) if f.endswith(".h")]
    raw = []
    for fp in files:
        try:
            raw.append(open(fp, encoding="utf-8", errors="ignore").read())
        except Exception:
            pass
    # 关键：先用 config 预处理整份头文本，统一处理文件级 #if 与结构体内 #if
    combined = preprocess("\n".join(raw))
    big = clean(combined)

    # enum： size 4
    for m in re.finditer(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", big):
        ENUMS.add(m.group(1))

    # typedef：先收集（含匿名 struct/union typedef）
    for m in re.finditer(r"\btypedef\s+(.*?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", big, re.S):
        spec, name = m.group(1).strip(), m.group(2)
        if re.match(r"^(struct|union)\b", spec) and "{" in spec:
            # typedef struct {...} NAME;  -> 匿名复合体，合成名字
            bm = re.search(r"\{(.*)\}", spec, re.S)
            if bm:
                kind = "union" if spec.strip().startswith("union") else "struct"
                c = Compound(name, bm.group(1), kind=kind)
                COMPOUNDS[name] = c
                TDEF[name] = ("compound", name)
        elif re.match(r"^(struct|union)\b", spec):
            TDEF[name] = ("typeexpr", spec)
        elif re.match(r"^enum\b", spec):
            ENUMS.add(name)
            TDEF[name] = ("scalar", 4, 4)
        else:
            TDEF[name] = ("typeexpr", spec)

    # struct / union 定义（任意括号深度）
    for m in re.finditer(r"\b(struct|union)\b\s+([A-Za-z_][A-Za-z0-9_]*)\s*(\{)", big):
        kind, name, _ = m.group(1), m.group(2), m.group(3)
        # 匹配到对应的 }
        depth, k = 0, m.start()
        started = False
        while k < len(big):
            ch = big[k]
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    break
            k += 1
        body = big[m.end():k]
        # 尾部属性（在 } 与 ; 之间）
        tail = big[k + 1:].split(";", 1)[0]
        whole_cl = "@CL@" in tail
        if name not in COMPOUNDS:
            COMPOUNDS[name] = Compound(name, body, whole_cacheline=whole_cl, kind=kind)
        else:
            # 已存在（可能来自 typedef 匿名或前向），用更完整的定义覆盖
            if not COMPOUNDS[name].resolved:
                COMPOUNDS[name].body = body
                COMPOUNDS[name].whole_cacheline = whole_cl
                COMPOUNDS[name].kind = kind


# ----------------------------------------------------------------------
# 5) 类型解析
# ----------------------------------------------------------------------
def resolve_scalar(expr):
    e = re.sub(r"\s+", " ", expr.strip().replace("*", "")).strip()
    if e == "":
        return None
    if e in SCALAR:
        return SCALAR[e]
    # 仅去掉独立的 signed 限定词（不能盲替，否则 "unsigned" 会被截成 "un"）
    e2 = re.sub(r"\bsigned\b", "", e).strip()
    if e2 in SCALAR:
        return SCALAR[e2]
    # 裸 "unsigned" -> unsigned int
    if e == "unsigned":
        return SCALAR["unsigned int"]
    # "unsigned X" 已在 SCALAR 中
    return None


def resolve_type(expr):
    """返回 (kind, ...) 描述符；kind in scalar/ptr/array/compound/bitfield-容器"""
    raw = expr.strip()
    # 函数指针 -> ptr
    if "(" in raw and "*" in raw:
        return ("ptr",)
    stars = raw.count("*")
    core = raw.replace("*", " ").split()
    core_txt = " ".join(core)
    if stars > 0:
        return ("ptr",)
    # struct / union
    m = re.match(r"^(struct|union)\s+([A-Za-z_][A-Za-z0-9_]*)$", core_txt)
    if m:
        nm = m.group(2)
        if nm in COMPOUNDS:
            return ("compound", nm)
        # 前向声明或未找到：占位
        UNRESOLVED.add(nm)
        if nm not in COMPOUNDS:
            COMPOUNDS[nm] = Compound(nm, "")  # 空体占位
        return ("compound", nm)
    if core_txt in ENUMS:
        return ("scalar", 4, 4)
    # typedef 别名
    if core_txt in TDEF:
        t = TDEF[core_txt]
        if t[0] == "scalar":
            return ("scalar", t[1], t[2])
        if t[0] == "compound":
            return ("compound", t[1])
        if t[0] == "typeexpr":
            return resolve_type(t[1])
    # 裸复合类型名（含手动注入的类型）直接按 compound 解析
    if core_txt in COMPOUNDS:
        return ("compound", core_txt)
    # 标量
    sc = resolve_scalar(core_txt)
    if sc:
        return ("scalar", sc[0], sc[1])
    # 裸标量归一（防 "unsigned"/"long int" 等漏匹配）
    norm = {"unsigned": "unsigned int", "signed": "int", "long int": "long",
            "unsigned long int": "unsigned long", "unsigned short int": "unsigned short",
            "unsigned long long int": "unsigned long long", "long long int": "long long"}
    if core_txt in norm:
        sc = resolve_scalar(norm[core_txt])
        if sc:
            return ("scalar", sc[0], sc[1])
    # 未知：保守当 4 字节标量，但记录
    UNRESOLVED.add(core_txt)
    return ("scalar", 4, 4)


# ----------------------------------------------------------------------
# 6) 字段解析（brace-aware 切分）
# ----------------------------------------------------------------------
def split_top_semi(body):
    parts, buf, depth = [], "", 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch in "{(":
            depth += 1
        elif ch in "})":
            depth -= 1
        if ch == ";" and depth == 0:
            parts.append(buf)
            buf = ""
        else:
            buf += ch
        i += 1
    if buf.strip():
        parts.append(buf)
    return parts


NAME = re.compile(
    r"^(?P<type>.*?)\s*(?P<stars>\*+)?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<arr>\[[^\]]*\])?\s*$"
)


def parse_decl(d):
    """单条声明 -> [(type_expr, name, arr_or_None, bits_or_None)]，多变量展开。"""
    d = d.strip()
    if not d:
        return []
    # 函数指针：long (*fn)(...) 或 type (*name)(...) -> 视为 8 字节指针
    fpm = re.search(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", d)
    if fpm and "(" in d:
        arr = None
        am2 = re.search(r"\[([^\]]*)\]", d)
        if am2:
            arr = am2.group(1)
        return [("void *", fpm.group(1), arr, None)]
    # 匿名 struct/union 内联
    am = re.match(r"^(struct|union)\s*\{", d)
    if am:
        # 抽取内联复合体
        depth, k = 0, d.find("{")
        while k < len(d):
            ch = d[k]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        inner = d[am.end():k]
        rest = d[k + 1:].strip()
        # rest 可能是名字 或 名字[..] 或 空
        nm = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", rest)
        anon_name = "_anon_" + str(parse_decl.cnt)
        parse_decl.cnt += 1
        kind = "union" if d.strip().startswith("union") else "struct"
        COMPOUNDS[anon_name] = Compound(anon_name, inner, kind=kind)
        arr = None
        bit = None
        if nm:
            after = rest[nm.end():].strip()
            am2 = re.match(r"\[([^\]]*)\]", after)
            if am2:
                arr = am2.group(1)
        return [(f"struct {anon_name}", nm.group(1) if nm else anon_name, arr, bit)]
    # 位域
    bits = None
    bm = re.search(r":\s*(\d+)\s*$", d)
    if bm:
        bits = int(bm.group(1))
        d = d[:bm.start()].rstrip()
    # 顶层逗号切分（忽略 [] 内）
    sub, buf, depth = [], "", 0
    for ch in d:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == "," and depth == 0:
            sub.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        sub.append(buf.strip())
    out, base = [], None
    for i, p in enumerate(sub):
        mm = NAME.match(p)
        if not mm:
            continue
        typ = (mm.group("type") + " " + (mm.group("stars") or "")).strip()
        if i > 0:
            typ = base or typ
        if i == 0:
            base = typ
        nm = mm.group("name")
        if nm in ("unsigned", "signed", "long", "short", "int", "char",
                  "struct", "union", "enum", "void", "float", "double",
                  "bool", "_Bool"):
            continue
        arr = mm.group("arr")
        out.append((typ, nm, arr, bits if i == 0 else None))
    return out


parse_decl.cnt = 0


def parse_body(body):
    """返回 [(name, descriptor, cacheline_flag)]，descriptor 见 resolve_type。"""
    res = []
    for part in split_top_semi(body):
        if "@CL@" in part:
            cl = True
            part = part.replace("@CL@", " ")
        else:
            cl = False
        al = re.search(r"@AL\((\d+)\)@", part)
        if al:
            cl_align = int(al.group(1))
            part = re.sub(r"@AL\(\d+\)@", " ", part)
        else:
            cl_align = 64 if cl else 0
        part = part.strip()
        if not part:
            continue
        # 跳过纯前向声明 struct X;
        if re.match(r"^(struct|union|enum)\s+[A-Za-z_][A-Za-z0-9_]*$", part):
            continue
        for typ, nm, arr, bits in parse_decl(part):
            if bits is not None:
                # 位域：底层类型
                desc = resolve_type(typ)
                basebytes = 4
                if desc[0] == "scalar":
                    basebytes = desc[1]
                elif desc[0] == "ptr":
                    basebytes = 8
                res.append((nm, ("bitfield", basebytes, bits), cl_align))
                continue
            desc = resolve_type(typ)
            if arr:
                n = arr.strip("[]").strip()
                for k, v in MACROS.items():
                    n = n.replace(k, str(v))
                try:
                    n = int(eval(n, {"__builtins__": {}}, {}))
                except Exception:
                    n = 1
                if desc[0] == "compound":
                    # 内联结构数组：需要元素大小
                    el = layout_compound(COMPOUNDS[desc[1]])
                    desc = ("array_compound", desc[1], n, el.size, el.align)
                else:
                    desc = ("array", desc, n)
            res.append((nm, desc, cl_align))
    return res


# ----------------------------------------------------------------------
# 7) 布局计算（递归 + 缓存）
# ----------------------------------------------------------------------
def layout_compound(c):
    if c.resolved:
        return c
    c.resolved = True  # 防自引用死循环（自引用指针不增加大小）
    if c.body is None or c.body.strip() == "":
        # 占位：8 字节
        c.size, c.align = 8, 8
        c.fields = []
        return c
    flds = parse_body(c.body)
    c.fields = flds
    off = 0
    maxalign = 1
    pending = None  # 位域累积 (basebytes, bitsoff, startoff)
    maxmember = 0   # union 用：最大成员尺寸
    for nm, desc, cl_align in flds:
        if desc[0] == "bitfield":
            basebytes, width = desc[1], desc[2]
            if pending and pending[0] == basebytes and pending[1] + width <= basebytes * 8:
                pending = (basebytes, pending[1] + width, pending[2])
            else:
                if pending:
                    off = align_up(off, pending[0])
                pending = (basebytes, width, off)
            continue
        # 关闭位域
        if pending:
            off = align_up(off, pending[0])
            pending = None
        if desc[0] == "ptr":
            sz, al = 8, 8
        elif desc[0] == "scalar":
            sz, al = desc[1], desc[2]
        elif desc[0] == "array":
            el = desc[1]
            if el[0] == "ptr":
                esz, eal = 8, 8
            elif el[0] == "scalar":
                esz, eal = el[1], el[2]
            else:
                esz, eal = 8, 8
            cnt = desc[2]
            sz, al = esz * cnt, eal
        elif desc[0] == "array_compound":
            sz, al = desc[2] * desc[3], desc[4]
        elif desc[0] == "compound":
            lc = layout_compound(COMPOUNDS[desc[1]])
            sz, al = lc.size, lc.align
        else:
            sz, al = 8, 8
        eff = al
        if cl_align:
            eff = max(al, cl_align)
        if c.kind == "union":
            # 联合：所有成员从 0 重叠，尺寸取最大成员（含对齐）
            maxalign = max(maxalign, eff)
            maxmember = max(maxmember, align_up(sz, eff))
        else:
            off = align_up(off, eff)
            off += sz
            maxalign = max(maxalign, eff)
            maxmember = max(maxmember, align_up(off, eff))
    if pending:
        off = align_up(off, pending[0])
        maxmember = max(maxmember, off)
    maxalign = max(maxalign, 1)
    if c.kind == "union":
        # union：成员重叠，尺寸取最大成员（含对齐）
        size = align_up(maxmember, maxalign)
    else:
        size = align_up(off, maxalign)
    if c.whole_cacheline:
        size = align_up(size, 64)
        maxalign = max(maxalign, 64)
    c.size, c.align = size, maxalign
    return c


# ----------------------------------------------------------------------
# 8) 主流程
# ----------------------------------------------------------------------
def inject_manual_types():
    """注入本机 4.9 真实、可验证的缺失类型尺寸（arch 头/缺漏头用已知 4.9 定义补全）。
    这些类型绝大多数位于 pi_blocked_on 之后的 tail，但补齐后可让 total 收敛到 3840，
    也是对布局引擎正确性的二次校验。"""
    # 数组维度宏（来自 asm/hw_breakpoint.h，池中缺失）
    MACROS["ARM_MAX_BRP"] = 16
    MACROS["ARM_MAX_WRP"] = 16
    # arch_spinlock_t (arm64 4.9, 无 QUEUED_SPINLOCKS/DEBUG) : { u16 owner; u16 next; } = 4
    COMPOUNDS["arch_spinlock_t"] = Compound("arch_spinlock_t", "u16 owner; u16 next;")
    # raw_spinlock_t / spinlock_t -> 4 (arch_spinlock_t 4, 无 DEBUG_SPINLOCK/LOCK_ALLOC)
    COMPOUNDS["raw_spinlock"] = Compound("raw_spinlock", "arch_spinlock_t raw_lock;")
    TDEF["raw_spinlock_t"] = ("compound", "raw_spinlock")
    COMPOUNDS["spinlock"] = Compound("spinlock", "struct raw_spinlock rlock;")
    TDEF["spinlock_t"] = ("compound", "spinlock")
    # seqcount_t : { unsigned sequence; } = 4
    COMPOUNDS["seqcount"] = Compound("seqcount", "unsigned sequence;")
    TDEF["seqcount_t"] = ("compound", "seqcount")
    # sigset_t : { unsigned long sig[_NSIG_WORDS]; } _NSIG_WORDS=1 -> 8
    COMPOUNDS["sigset_t"] = Compound("sigset_t", "unsigned long sig[1];")
    # __kernel 基本类型
    TDEF["__kernel_size_t"] = ("scalar", 8, 8)
    TDEF["__kernel_pid_t"] = ("scalar", 4, 4)
    TDEF["__kernel_clockid_t"] = ("scalar", 4, 4)
    # nodemask_t (CONFIG_NUMA 未设置 -> MAX_NUMNODES=1 -> 1 unsigned long) = 8
    COMPOUNDS["nodemask_t"] = Compound("nodemask_t", "unsigned long bits[1];")
    # optimistic_spin_queue : { struct optimistic_spin_queue *next,*prev; } = 16
    COMPOUNDS["optimistic_spin_queue"] = Compound(
        "optimistic_spin_queue",
        "struct optimistic_spin_queue *next; struct optimistic_spin_queue *prev;")
    # rcu_head 是 #define rcu_head callback_head（types.h），建立别名
    TDEF["rcu_head"] = ("compound", "callback_head")
    COMPOUNDS["rcu_head"] = Compound(
        "rcu_head", "struct callback_head *next; void (*func)(struct callback_head *head);")
    # task_io_accounting (CONFIG_TASK_XACCT=y && CONFIG_TASK_IO_ACCOUNTING=y) : 7*u64 = 56
    COMPOUNDS["task_io_accounting"] = Compound(
        "task_io_accounting",
        "u64 rchar; u64 wchar; u64 syscr; u64 syscw; "
        "u64 read_bytes; u64 write_bytes; u64 cancelled_write_bytes;")
    # page_frag (64-bit: page* + u32 offset + u32 size) = 16
    COMPOUNDS["page_frag"] = Compound(
        "page_frag", "struct page *page; u32 offset; u32 size;")
    # user_fpsimd_state (fpsimd_state 联合体内，补全以便联合尺寸正确)
    COMPOUNDS["user_fpsimd_state"] = Compound(
        "user_fpsimd_state", "__uint128_t vregs[32]; u32 fpsr; u32 fpcr;")
    # hrtimer (4.9 主线；CONFIG_TIMER_STATS 未设置 -> 64 字节)
    #   timerqueue_node = rb_node(24) + ktime_t(8) = 32
    #   hrtimer = 32 + 8 + 8(func ptr) + 8(base ptr) + 1 + 1 = 58 -> 64
    SCALAR["ktime_t"] = (8, 8)
    COMPOUNDS["timerqueue_node"] = Compound(
        "timerqueue_node", "struct rb_node node; ktime_t expires;")
    COMPOUNDS["hrtimer"] = Compound(
        "hrtimer",
        "struct timerqueue_node node; ktime_t _softexpires; "
        "void *function; void *base; u8 state; u8 is_rel;")


def main():
    extract_defs()
    inject_manual_types()
    # 预处理 task_struct 主体
    src = open(SCHED, encoding="utf-8", errors="ignore").read()
    m = re.search(r"struct task_struct \{(.*?)\n\};", src, re.S)
    if not m:
        sys.exit("[!] struct task_struct not found")
    raw_body = m.group(1)
    body = preprocess(raw_body)
    body = clean(body)
    ts = Compound("task_struct", body)
    COMPOUNDS["task_struct"] = ts
    ts = layout_compound(ts)

    print("=" * 70)
    print(" 4.9 task_struct 布局推导（递归 / 纯 Python / LP64）")
    print("=" * 70)
    print(f" config 条目数        : {len(CFG)}")
    print(f" 已解析 struct/union  : {len(COMPOUNDS)}")
    print(f" 已解析 typedef/enum  : {len(TDEF)} / {len(ENUMS)}")
    print(f" sizeof(task_struct)  : {ts.size}  (0x{ts.size:x})")
    print(f" 校准目标 slab 大小    : {TARGET_SLAB}  (0x{TARGET_SLAB:x})")
    print(f" 偏差                 : {ts.size - TARGET_SLAB:+d} 字节 "
          f"({100.0*ts.size/TARGET_SLAB:.1f}% of target)")
    print("-" * 70)
    print(" 目标偏移：")
    for f in ("real_cred", "cred", "ptracer_cred", "pi_blocked_on",
              "pi_waiters", "pi_waiters_leftmost", "seccomp", "comm",
              "thread_info", "restart_block", "thread"):
        off = find_offset(ts, f)
        if off is None:
            print(f"   offsetof({f:20s}) = N/A (字段未解析/未找到)")
        else:
            print(f"   offsetof({f:20s}) = 0x{off:04x}  ({off})")
    print("-" * 70)
    # 未解析类型（影响精度的缺口）
    if UNRESOLVED:
        print(f" 未解析类型（占位 8/4 字节，需核查）: {sorted(UNRESOLVED)}")
    else:
        print(" 未解析类型：无")
    # 校验若干已知结构大小
    print("-" * 70)
    print(" slab 标定校验（来自 /proc/slabinfo，计算 vs 真实）：")
    KNOWN_SLAB = {"task_struct": TARGET_SLAB, "cred": 192, "sighand_struct": 2112,
                  "mm_struct": 896, "files_struct": 768, "nsproxy": 56}
    for nm, real in KNOWN_SLAB.items():
        if nm in COMPOUNDS and COMPOUNDS[nm].body:
            lc = layout_compound(COMPOUNDS[nm])
            tag = "OK" if lc.size == real else "差 %+d" % (lc.size - real)
            print(f"   {nm:18s} 计算 {lc.size:5d}  真实 {real:5d}  [{tag}]")
        else:
            print(f"   {nm:18s} <未解析>")
    print("-" * 70)
    print(" 已知结构自检（list_head/rb_node/hlist_head/llist_node/plist_node）：")
    for nm, exp in (("list_head", 16), ("rb_node", 24), ("hlist_head", 8),
                    ("llist_node", 8), ("plist_node", 40)):
        if nm in COMPOUNDS:
            lc = layout_compound(COMPOUNDS[nm])
            mark = "OK" if lc.size == exp else "!!"
            print(f"   sizeof({nm:14s}) = {lc.size:3d}  期望 {exp:3d}  [{mark}]")
        else:
            print(f"   sizeof({nm:14s}) = <未定义>")
    if "--dump" in sys.argv:
        print("-" * 70)
        print(" task_struct 字段布局（前 60 个）：")
        dump_compound(ts, 0, 60)


def find_offset(c, name):
    off = 0
    pending = None
    for nm, desc, cl in c.fields:
        if desc[0] == "bitfield":
            continue
        if nm == name:
            return off
        if desc[0] == "ptr":
            sz, al = 8, 8
        elif desc[0] == "scalar":
            sz, al = desc[1], desc[2]
        elif desc[0] == "array":
            el = desc[1]
            esz = 8 if el[0] in ("ptr",) else (el[1] if el[0] == "scalar" else 8)
            eal = 8 if el[0] in ("ptr",) else (el[2] if el[0] == "scalar" else 8)
            sz, al = esz * desc[2], eal
        elif desc[0] == "array_compound":
            sz, al = desc[2] * desc[3], desc[4]
        elif desc[0] == "compound":
            lc = layout_compound(COMPOUNDS[desc[1]])
            sz, al = lc.size, lc.align
        else:
            sz, al = 8, 8
        eff = al
        if cl:
            eff = max(al, cl)
        off = align_up(off, eff)
        off += sz
    return None


def dump_compound(c, indent, limit):
    off = 0
    pending = None
    n = 0
    for nm, desc, cl in c.fields:
        if desc[0] == "bitfield":
            print(f"   {'':4} :{desc[2]} (base {desc[1]})")
            continue
        if desc[0] == "ptr":
            sz, al, t = 8, 8, "ptr"
        elif desc[0] == "scalar":
            sz, al, t = desc[1], desc[2], "scalar"
        elif desc[0] == "array":
            el = desc[1]
            esz = 8 if el[0] in ("ptr",) else (el[1] if el[0] == "scalar" else 8)
            eal = 8 if el[0] in ("ptr",) else (el[2] if el[0] == "scalar" else 8)
            sz, al, t = esz * desc[2], eal, f"array x{desc[2]}"
        elif desc[0] == "array_compound":
            sz, al, t = desc[2] * desc[3], desc[4], f"array(struct) x{desc[2]}"
        elif desc[0] == "compound":
            lc = layout_compound(COMPOUNDS[desc[1]])
            sz, al, t = lc.size, lc.align, f"struct {desc[1]}"
        else:
            sz, al, t = 8, 8, "?"
        eff = max(al, cl) if cl else al
        off = align_up(off, eff)
        print(f"   0x{off:04x}  {sz:4d}  {t:22s} {nm}"
              + ("  [CL]" if cl else ""))
        off += sz
        n += 1
        if n >= limit:
            break


if __name__ == "__main__":
    main()
