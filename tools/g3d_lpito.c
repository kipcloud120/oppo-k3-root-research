/* g3d_lpito.c — 零风险：核对本机 FUTEX_LOCK_PI 的超时语义（绝对 vs 相对 / 是否提前返回） */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define F_LOCK_PI 6
#define F_UNLOCK_PI 7
#define F_PRIV 128

static uint32_t *W;
static volatile int hold_done;
static double now_ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}

static long lock_pi_abs(uint32_t *u, int ms)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += ms / 1000;
	ts.tv_nsec += (long)(ms % 1000) * 1000000L;
	while (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
	return syscall(SYS_futex, u, F_LOCK_PI | F_PRIV, 0, &ts, NULL, 0);
}

static void *holder(void *a)
{
	(void)a;
	long r = syscall(SYS_futex, &W[0], F_LOCK_PI | F_PRIV, 0, NULL, NULL, 0);
	printf("holder LOCK_PI(F0) r=%ld errno=%d\n", r, errno);
	hold_done = 1;
	usleep(3000000);                    /* 持锁 3s */
	syscall(SYS_futex, &W[0], F_UNLOCK_PI | F_PRIV, 0, NULL, NULL, 0);
	printf("holder UNLOCK_PI(F0)\n");
	return NULL;
}

static void *waiter(void *a)
{
	(void)a;
	double t = now_ms();
	long r;
	errno = 0;
	r = lock_pi_abs(&W[0], 5000);       /* 绝对 5s；若实现正确应阻塞 ~3s 后成功 */
	printf("waiter LOCK_PI(F0, abs +5s) r=%ld errno=%d 耗时=%.1fms\n", r, errno, now_ms() - t);
	if (r == 0) syscall(SYS_futex, &W[0], F_UNLOCK_PI | F_PRIV, 0, NULL, NULL, 0);
	return NULL;
}

int main(void)
{
	pthread_t h, w;
	long r; int e; double t;
	W = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	/* case1: 持锁 3s，waiter 用 abs+5s 等 ⇒ 预期 ~3000ms 成功 */
	pthread_create(&h, NULL, holder, NULL);
	while (!hold_done) usleep(1000);
	pthread_create(&w, NULL, waiter, NULL);
	pthread_join(w, NULL);
	pthread_join(h, NULL);

	/* case2: 无人释放，waiter 用 abs+300ms ⇒ 预期 ~300ms 超时 */
	t = now_ms(); errno = 0;
	r = lock_pi_abs(&W[1], 300);
	e = errno;
	printf("case2 LOCK_PI(F1, abs +300ms) r=%ld errno=%d (%s) 耗时=%.1fms\n",
	       r, e, strerror(e), now_ms() - t);

	/* case3: 无人释放，NULL 超时 —— 只测 200ms 内是否返回（预期不返回） */
	printf("case3 略（NULL 超时会永久阻塞，不测）\n");
	return 0;
}
