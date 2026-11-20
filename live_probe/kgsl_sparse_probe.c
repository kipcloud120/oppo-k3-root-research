/*
 * kgsl_sparse_probe.c — KGSL sparse 生命周期分阶段探针（v12-K2）
 *
 * 目的：把 §61.6 的 KO-1（通用释放路径绕过 sparse 绑定门）从"静态成立"推进到
 *       "本机可复现"。分三阶段，**每阶段独立进程**，任一阶段失败或异常都不会连累下一阶段。
 *
 *   stage=alloc : 只验证 SPARSE_PHYS_ALLOC / SPARSE_VIRT_ALLOC 在本机是否可用（可达性前提）
 *   stage=guard : 绑定后调用 SPARSE_PHYS_FREE —— 期望 -EINVAL（正向对照：门存在）
 *   stage=ko1   : 绑定后调用 GPUMEM_FREE_ID —— KO-1 假设下期望 0（门被绕过）
 *
 * 安全边界（硬约束，改代码前请先读 §61.6 与 HANDOVER_RESUME §5）：
 *   1. 不提交任何 GPU 命令、不 mmap、不执行 IB —— 悬空 PTE 不会被实际访问；
 *   2. 不构造非法用户指针（不使用 EFAULT 型探针手法）；
 *   3. 尺寸固定 1 页，几何取 offset=0（刻意避开 C-3 的算式异常区间）；
 *   4. stage=ko1 结束后**不调用** SPARSE_PHYS_FREE（对象已不在 idr 中）。
 * 已知残余风险：进程退出时 close(fd) 会触发 kgsl_release 销毁 virt 条目并 unmap 整段，
 * 该 unmap 只清 PTE、不解引用被释放的页；但若驱动在其他版本上行为不同，仍可能 panic。
 *
 * 命令字来自本机 ioctl 分派表（HANDOVER §61.3），不依赖目标 libc 的 _IOWR 展开。
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define IOC_SPARSE_PHYS_ALLOC 0xc0200950UL
#define IOC_SPARSE_PHYS_FREE  0x40040951UL
#define IOC_SPARSE_VIRT_ALLOC 0xc0280952UL
#define IOC_SPARSE_VIRT_FREE  0x40040953UL
#define IOC_SPARSE_BIND       0x40180954UL
#define IOC_GPUMEM_FREE_ID    0xc0080935UL

#define KGSL_SPARSE_BIND   0x1ULL
#define KGSL_SPARSE_UNBIND 0x2ULL

struct sparse_phys_alloc {
	uint64_t size, pagesize, flags;
	uint32_t id;
};

struct sparse_virt_alloc {
	uint64_t size, pagesize, flags, gpuaddr;
	uint32_t id;
};

struct sparse_bind_obj {
	uint64_t virtoffset, physoffset, size, flags;
	uint32_t id;
};

struct sparse_bind_list {
	uint64_t list;
	uint32_t id, size, count;
};

struct sparse_free_id {
	uint32_t id;
};

struct gpumem_free_id {
	uint32_t id, pad;
};

static void show(const char *what, long ret)
{
	int e = errno;

	if (ret < 0)
		printf("  %-26s = -1 errno=%d (%s)\n", what, e, strerror(e));
	else
		printf("  %-26s = %ld\n", what, ret);
}

static long do_bind(int fd, uint32_t virt_id, uint32_t phys_id, uint64_t flags,
		    uint64_t v_off, uint64_t p_off, uint64_t size)
{
	struct sparse_bind_obj obj;
	struct sparse_bind_list lst;

	memset(&obj, 0, sizeof(obj));
	obj.virtoffset = v_off;
	obj.physoffset = p_off;
	obj.size = size;
	obj.flags = flags;
	obj.id = phys_id;

	memset(&lst, 0, sizeof(lst));
	lst.list = (uint64_t)(uintptr_t)&obj;
	lst.id = virt_id;
	lst.size = sizeof(obj);
	lst.count = 1;

	return ioctl(fd, IOC_SPARSE_BIND, &lst);
}

int main(int argc, char **argv)
{
	const char *stage = (argc > 1) ? argv[1] : "alloc";
	const uint64_t SZ = 4096, PG = 4096;
	int fd, ret;
	long r_phys, r_virt;
	struct sparse_phys_alloc pa;
	struct sparse_virt_alloc va;
	struct sparse_free_id f;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("== kgsl_sparse_probe stage=%s ==\n", stage);

	fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		printf("  open /dev/kgsl-3d0 failed: %s\n", strerror(errno));
		return 10;
	}
	printf("  %-26s = %d\n", "open", fd);

	/* stage=sparse：逐个 sparse 入口的最小调用，验证"同一能力门" */
	if (strcmp(stage, "sparse") == 0) {
		char buf[64];
		static const struct { unsigned long cmd; const char *tag; } S[] = {
			{0xc0200950UL, "SPARSE_PHYS_ALLOC"},
			{0x40040951UL, "SPARSE_PHYS_FREE"},
			{0xc0280952UL, "SPARSE_VIRT_ALLOC"},
			{0x40040953UL, "SPARSE_VIRT_FREE"},
			{0x40180954UL, "SPARSE_BIND"},
			{0xc0380955UL, "GPU_SPARSE_COMMAND"},
		};
		for (unsigned i = 0; i < sizeof(S) / sizeof(S[0]); i++) {
			memset(buf, 0, sizeof(buf));
			show(S[i].tag, ioctl(fd, S[i].cmd, buf));
		}
		close(fd);
		return 0;
	}

	/* stage=prop：复刻 §59.3 的 EFAULT 判据——证明"处理器确实被到达" */
	if (strcmp(stage, "prop") == 0) {
		char buf[64];
		memset(buf, 0, sizeof(buf));
		*(uint32_t *)(buf + 0) = 8;          /* type = 8 */
		*(uint64_t *)(buf + 8) = 0x10;       /* 非法用户指针 */
		*(uint32_t *)(buf + 16) = 16;        /* sizebytes */
		show("getproperty type=8 badptr",
		     ioctl(fd, 0xc0180902UL, buf));  /* 处理器到达 ⇒ EFAULT(14) */
		memset(buf, 0, sizeof(buf));
		show("getproperty type=8 nullval",
		     ioctl(fd, 0xc0180902UL, buf));  /* type=0 ⇒ 应落在 default 分支 */
		close(fd);
		return 0;
	}

	/* stage=matrix：命令字矩阵，判定门是"按 nr"还是"按 size"，以及是否在分派前 */
	if (strcmp(stage, "matrix") == 0) {
		char buf[64];
		static const struct { unsigned long cmd; const char *tag; } M[] = {
			{0xc0180902UL, "nr=02 sz=18 已注册(EF预期)"},
			{0xc0180940UL, "nr=40 sz=18 已注册(0预期)"},
			{0xc0180956UL, "nr=56 sz=18 未注册"},
			{0x40180956UL, "nr=56 sz=18 未注册(W)"},
			{0xc0200940UL, "nr=40 sz=20 已注册"},
			{0xc0080950UL, "nr=50 sz=08 已注册"},
			{0xc0200950UL, "nr=50 sz=20 已注册(sparse)"},
			{0xc0180902UL, "nr=02 sz=18 重复"},
		};
		for (unsigned i = 0; i < sizeof(M) / sizeof(M[0]); i++) {
			memset(buf, 0, sizeof(buf));
			show(M[i].tag, ioctl(fd, M[i].cmd, buf));
		}
		close(fd);
		return 0;
	}

	/* stage=cmds：零副作用差分，判断"处理器是否被到达" */
	if (strcmp(stage, "cmds") == 0) {
		char buf[64];
		memset(buf, 0, sizeof(buf));

		show("0xc0180940 syncsrc_create",
		     ioctl(fd, 0xc0180940UL, buf));          /* 已知可用（§59.4） */
		show("0xc0200956 nr=0x56 未注册",
		     ioctl(fd, 0xc0200956UL, buf));          /* 期望 ENOTTY */
		show("0xc0200950 phys size=0",
		     ioctl(fd, IOC_SPARSE_PHYS_ALLOC, buf)); /* 期望 EINVAL */
		memset(buf, 0, sizeof(buf));
		((struct sparse_phys_alloc *)buf)->size = SZ;
		((struct sparse_phys_alloc *)buf)->pagesize = 8192;
		show("0xc0200950 phys pg=8192",
		     ioctl(fd, IOC_SPARSE_PHYS_ALLOC, buf)); /* 期望 EINVAL */
		memset(buf, 0, sizeof(buf));
		((struct sparse_phys_alloc *)buf)->size = SZ;
		((struct sparse_phys_alloc *)buf)->pagesize = PG;
		show("0xc0200950 phys 合法参数",
		     ioctl(fd, IOC_SPARSE_PHYS_ALLOC, buf));
		show("0xc0280952 virt 合法参数",
		     ioctl(fd, IOC_SPARSE_VIRT_ALLOC, buf)); /* size/pg 同上语义 */
		close(fd);
		return 0;
	}

	memset(&pa, 0, sizeof(pa));
	pa.size = SZ;
	pa.pagesize = PG;
	r_phys = ioctl(fd, IOC_SPARSE_PHYS_ALLOC, &pa);
	show("SPARSE_PHYS_ALLOC", r_phys);
	if (r_phys < 0) {
		printf("  => sparse phys 不可用，KO-1 在本机不可达（结束）\n");
		close(fd);
		return 20;
	}
	printf("  %-26s = %u\n", "  -> phys id", pa.id);

	memset(&va, 0, sizeof(va));
	va.size = SZ;
	va.pagesize = PG;
	r_virt = ioctl(fd, IOC_SPARSE_VIRT_ALLOC, &va);
	show("SPARSE_VIRT_ALLOC", r_virt);
	if (r_virt < 0) {
		printf("  => sparse virt 不可用，KO-1 在本机不可达（结束）\n");
		f.id = pa.id;
		ioctl(fd, IOC_SPARSE_PHYS_FREE, &f);
		close(fd);
		return 21;
	}
	printf("  %-26s = %u (gpuaddr=0x%llx flags=0x%llx)\n", "  -> virt id",
	       va.id, (unsigned long long)va.gpuaddr, (unsigned long long)va.flags);

	if (strcmp(stage, "alloc") == 0) {
		f.id = va.id;
		show("SPARSE_VIRT_FREE", ioctl(fd, IOC_SPARSE_VIRT_FREE, &f));
		f.id = pa.id;
		show("SPARSE_PHYS_FREE", ioctl(fd, IOC_SPARSE_PHYS_FREE, &f));
		close(fd);
		return 0;
	}

	/* 绑定：virt[0,4096) <- phys[0,4096)，最小几何、单页 */
	ret = (int)do_bind(fd, va.id, pa.id, KGSL_SPARSE_BIND, 0, 0, SZ);
	show("SPARSE_BIND", ret);
	if (ret < 0) {
		printf("  => 绑定失败，后续判定无意义（结束）\n");
		f.id = va.id;
		ioctl(fd, IOC_SPARSE_VIRT_FREE, &f);
		f.id = pa.id;
		ioctl(fd, IOC_SPARSE_PHYS_FREE, &f);
		close(fd);
		return 22;
	}

	if (strcmp(stage, "guard") == 0) {
		/* 正向对照：专用入口必须拒绝"有绑定"的释放 */
		f.id = pa.id;
		show("SPARSE_PHYS_FREE(bound)", ioctl(fd, IOC_SPARSE_PHYS_FREE, &f));
		show("SPARSE_UNBIND",
		     do_bind(fd, va.id, pa.id, KGSL_SPARSE_UNBIND, 0, 0, SZ));
		f.id = va.id;
		show("SPARSE_VIRT_FREE", ioctl(fd, IOC_SPARSE_VIRT_FREE, &f));
		f.id = pa.id;
		show("SPARSE_PHYS_FREE", ioctl(fd, IOC_SPARSE_PHYS_FREE, &f));
		close(fd);
		return 0;
	}

	if (strcmp(stage, "ko1") == 0) {
		/* KO-1：同一对象，改走通用释放路径 */
		struct gpumem_free_id g;
		memset(&g, 0, sizeof(g));
		g.id = pa.id;
		show("GPUMEM_FREE_ID(bound)", ioctl(fd, IOC_GPUMEM_FREE_ID, &g));
		/* 刻意不再触碰该 phys；virt 条目随 close() 释放 */
		close(fd);
		printf("  => 已按 id 释放被绑定的 phys（未触碰悬空映射）\n");
		return 0;
	}

	printf("unknown stage\n");
	close(fd);
	return 2;
}
