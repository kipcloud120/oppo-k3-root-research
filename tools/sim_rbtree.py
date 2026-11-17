"""sim_rbtree.py — 复刻 kgsl_iommu 的 rbtree 插入与区间查找。

两个比较器不一致正是漏洞根源：
  * _insert_gpuaddr()  —— 只比较 base（节点落位）
  * set_svm_region()   —— 比较 [base, base+size) 区间（重叠检测）
本脚本按 Linux rb_insert_color 重平衡规则，模拟给定插入顺序后的树形，
并对 OVERLAP 做区间查找，判断是否"绕过"UAF。
"""

M64 = (1 << 64) - 1


class Node:
    __slots__ = ("base", "size", "name", "left", "right", "parent", "red")

    def __init__(self, base, size, name):
        self.base = base
        self.size = size
        self.name = name
        self.left = None
        self.right = None
        self.parent = None
        self.red = True  # 新节点为红

    def end(self):
        return (self.base + self.size) & M64


class RB:
    def __init__(self):
        self.root = None

    # ---------- Linux rb_insert_color ----------
    def _rotate_left(self, node):
        right = node.right
        node.right = right.left
        if right.left:
            right.left.parent = node
        right.parent = node.parent
        if not node.parent:
            self.root = right
        elif node is node.parent.left:
            node.parent.left = right
        else:
            node.parent.right = right
        right.left = node
        node.parent = right

    def _rotate_right(self, node):
        left = node.left
        node.left = left.right
        if left.right:
            left.right.parent = node
        left.parent = node.parent
        if not node.parent:
            self.root = left
        elif node is node.parent.right:
            node.parent.right = left
        else:
            node.parent.left = left
        left.right = node
        node.parent = left

    def insert(self, base, size, name):
        """等价于 _insert_gpuaddr：只按 base 比较，重复 base 返回 False"""
        parent = None
        node = self.root
        while node:
            if base == node.base:
                return False, "duplicate base"
            parent = node
            node = node.left if base < node.base else node.right
        new = Node(base, size, name)
        new.parent = parent
        if not parent:
            self.root = new
        elif base < parent.base:
            parent.left = new
        else:
            parent.right = new
        self._insert_color(new)
        self.root.red = False
        return True, "ok"

    def _insert_color(self, node):
        while node.parent and node.parent.red:
            parent = node.parent
            g = parent.parent
            if parent is g.left:
                uncle = g.right
                if uncle and uncle.red:
                    parent.red = False
                    uncle.red = False
                    g.red = True
                    node = g
                else:
                    if node is parent.right:
                        node = parent
                        self._rotate_left(node)
                        parent = node.parent
                        g = parent.parent
                    parent.red = False
                    g.red = True
                    self._rotate_right(g)
            else:
                uncle = g.left
                if uncle and uncle.red:
                    parent.red = False
                    uncle.red = False
                    g.red = True
                    node = g
                else:
                    if node is parent.left:
                        node = parent
                        self._rotate_right(node)
                        parent = node.parent
                        g = parent.parent
                    parent.red = False
                    g.red = True
                    self._rotate_left(g)
        self.root.red = False

    # ---------- kgsl_iommu_set_svm_region 的区间查找 ----------
    def find_conflict(self, addr, size, trace=None):
        node = self.root
        end = (addr + size) & M64
        while node:
            if trace is not None:
                trace.append(
                    f"  at {node.name} [{node.base:#x},{node.end():#x}) "
                    f"vs [{addr:#x},{end:#x})"
                )
            nmatch = node.base
            nend = node.end()
            if end <= nmatch:
                if trace is not None:
                    trace.append("    -> 目标完全在左，走 left")
                node = node.left
            elif nend <= addr:
                if trace is not None:
                    trace.append("    -> 目标完全在右，走 right")
                node = node.right
            else:
                return node, trace
        return None, trace

    def dump(self):
        out = []

        def rec(n, d):
            if not n:
                return
            rec(n.right, d + 1)
            out.append(
                "  " * d
                + f"{n.name:<12} [{n.base:#011x}, {n.end():#011x}) "
                + ("RED" if n.red else "BLK")
            )
            rec(n.left, d + 1)

        rec(self.root, 0)
        return "\n".join(out)


def run(label, order):
    print("=" * 72)
    print(label)
    t = RB()
    for base, size, name in order:
        ok, why = t.insert(base, size, name)
        print(f"  insert {name:<12} base={base:#011x} -> {why}")
    print("  最终树（右→根→左）:")
    print(t.dump())
    return t


UAF = (0x7001FF000, 0x10004000, "UAF")
PLACEH = (0x710204000, 0x10000, "PLACEHOLDER")     # PoC 实际用的 0x10000
PLACEH_RCA = (0x710204000, 0x10400000, "PLACEHOLDER(RCA)")
BOGUS = (0x700204000, 0xFFFFFFFFFFEFD000, "BOGUS")
OVERLAP = (0x7001FE000, 0x7000)

for label, order in [
    ("A. UAF -> PLACEHOLDER(0x10000) -> BOGUS   [我们跑的序列]", [UAF, PLACEH, BOGUS]),
    ("B. UAF -> PLACEHOLDER(0x10400000) -> BOGUS [RCA 文档]", [UAF, PLACEH_RCA, BOGUS]),
    ("C. UAF -> BOGUS -> PLACEHOLDER", [UAF, BOGUS, PLACEH]),
]:
    t = run(label, order)
    trace = []
    node, trace = t.find_conflict(*OVERLAP, trace=trace)
    print("  OVERLAP 区间查找轨迹:")
    print("\n".join(trace))
    if node:
        print(f"  => 冲突：命中 {node.name} → set_svm_region 返回 -ENOMEM（未进 map_sg）")
    else:
        print("  => 无冲突：插入成功 → 进入 kgsl_mmu_map / map_sg（漏洞路径）")
    print()
