/*
 * g3c_v6.c — GhostLock G-3c/C1「亚毫秒窗口」版（交接文档 §21.28）
 *
 * 与 v5 的唯一差别是时序，构造本身完全不变：
 *   v5 在 [10b] 之后才创建 W3 并 usleep(100000) ⇒ 帧死亡→走查间隔 114 ms ⇒ 悬垂槽被破坏 ⇒ panic。
 *   v6 把 W3 预置到 [10] 之前，删掉所有 sleep，帧死亡用无 syscall 忙轮询检测，
 *   走查前只做一次不 fsync 的 write() ⇒ 间隔 < 0.2 ms。
 *
 * 硬约束（不可违反）：
 *   - W 在 frame2 返回后**不得再发任何 syscall**（含 clock_gettime、sched_yield、unlock）。
 *     arm64 的 IRQ/异常入口使用当前任务内核栈，任何一次进内核都可能压坏那块已死的 syscall 帧。
 *   - main 负责所有时间测量与日志。
 *
 * 判据（§21.28.3，运行前已登记）：
 *   [12] == -EDEADLK      ⇒ 同路径重入同址 + [10] 定向写入 + 帧死后仍被解引用（C1 成立）
 *   [12] == 0 / 1         ⇒ 对齐失败（安全出口），C 与 O 整体弃用
 *   不返回 / 重启          ⇒ 推翻 IRQ 压栈推断，回到 §21.11 模型，停止同类实验
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

#define LOGPATH "/data/local/tmp/g3c6.log"

#define FUTEX_WAKE            1
#define FUTEX_LOCK_PI          6
#define FUTEX_UNLOCK_PI        7
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI  12
#define FUTEX_PRIVATE_FLAG   128

#define T1_MS   400
#define T2_MS  2500
#define T3_MS  8000

static int logfd = -1;

struct shared {
	uint32_t A, A2, A3, B_ring, B3, C, C2;
	volatile int w_holds_ring, w_holds_b3;
	volatile int o_holds_c, o_blocked_ring, o_parked;
	volatile int x_entered_c;
	volatile int w_waiting_a;
	volatile int w_ret1, w_err1, w_returned1;
	volatile int w2_waiting, w2_ret, w2_err, w2_returned;
	volatile int o2_holds_c2, o2_blocked_b3;
	volatile int x2_entered_c2;
	volatile int w_unlock_ret;
	volatile int w_tid, o_tid, o2_tid;
	volatile int w3_waiting, go_w3;
	volatile int done;
};

static struct shared *S;

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void lg_common(const char *fmt, va_list ap, int sync)
{
	char buf[400], line[480];
	int n;
	vsnprintf(buf, sizeof(buf), fmt, ap);
	n = snprintf(line, sizeof(line), "[%9.3fms] %s\n", now_ms(), buf);
	if (write(1, line, n) < 0) { }
	if (logfd >= 0 && write(logfd, line, n) < 0) { }
	if (sync && logfd >= 0)
		fsync(logfd);
}

static void lg(const char *fmt, ...)          /* 带 fsync：崩溃可保 */
{
	va_list ap;
	va_start(ap, fmt);
	lg_common(fmt, ap, 1);
	va_end(ap);
}

static void lgn(const char *fmt, ...)         /* 不 fsync：用于窗口内，~50us */
{
	va_list ap;
	va_start(ap, fmt);
	lg_common(fmt, ap, 0);
	va_end(ap);
}

static long futex(uint32_t *u, int op, uint32_t val, void *to,
		  uint32_t *u2, uint32_t val3)
{
	return syscall(SYS_futex, u, op, val, to, u2, val3);
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

/* 轮询（会 sleep，仅用于非时间敏感环节） */
static int wait_flag(volatile int *p, int ms)
{
	int i, n = ms / 2;
	for (i = 0; i < n; i++) {
		if (*p) return 1;
		usleep(2000);
	}
	return *p;
}

/* 无 syscall 忙轮询：只用 clock_gettime(vDSO) 做看门狗 */
static int spin_flag(volatile int *p, int ms)
{
	double t0 = now_ms();
	unsigned long i = 0;
	while (!*p) {
		if ((++i & 0x3FFF) == 0 && now_ms() - t0 > ms)
			return 0;
	}
	return 1;
}

static long lock_pi(uint32_t *u)
{
	return futex(u, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
}

static long unlock_pi(uint32_t *u)
{
	return futex(u, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
}

/* ---------------------------------------------------------------- W */
static void *thread_w(void *arg)
{
	struct timespec t1, t2;
	long r;

	(void)arg;
	r = lock_pi(&S->B_ring);
	if (r) { lg("W: LOCK_PI(B_ring) 失败 %ld errno=%d", r, errno); return NULL; }
	S->w_tid = (int)syscall(SYS_gettid);
	S->w_holds_ring = 1;
	r = lock_pi(&S->B3);
	if (r) { lg("W: LOCK_PI(B3) 失败 %ld errno=%d", r, errno); return NULL; }
	S->w_holds_b3 = 1;

	/* 两个绝对超时一次算好：frame1→frame2 之间不调 clock_gettime（vDSO 也不调） */
	abs_timeout(&t1, T1_MS);
	abs_timeout(&t2, T2_MS);

	while (!S->o_blocked_ring)
		__asm__ __volatile__("" ::: "memory");
	S->w_waiting_a = 1;
	errno = 0;
	r = futex(&S->A, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &t1, &S->C, 0);
	S->w_ret1 = (int)r;
	S->w_err1 = errno;
	S->w_returned1 = 1;

	/* 释放 B_ring ⇒ O 返回并停放（C 保持有主且不阻塞） */
	r = unlock_pi(&S->B_ring);
	S->w_unlock_ret = (int)r;

	/* 立即重入同路径：frame2 与 frame1 同址 */
	S->w2_waiting = 1;
	errno = 0;
	r = futex(&S->A2, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &t2, &S->C2, 0);
	S->w2_ret = (int)r;
	S->w2_err = errno;
	S->w2_returned = 1;

	/* 此后绝不进内核：不发 syscall、不解锁、不 yield */
	for (;;)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

/* ---------------------------------------------------------------- O */
static void *thread_o(void *arg)
{
	long r;
	(void)arg;
	r = lock_pi(&S->C);
	if (r) { lg("O: LOCK_PI(C) 失败 %ld errno=%d", r, errno); return NULL; }
	S->o_tid = (int)syscall(SYS_gettid);
	S->o_holds_c = 1;
	while (!S->w_holds_ring)
		__asm__ __volatile__("" ::: "memory");
	S->o_blocked_ring = 1;
	r = lock_pi(&S->B_ring);
	if (r) { lg("O: LOCK_PI(B_ring) 失败 %ld errno=%d", r, errno); return NULL; }
	S->o_parked = 1;
	for (;;)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

/* ---------------------------------------------------------------- X */
static void *thread_x(void *arg)
{
	(void)arg;
	while (!S->o_parked)
		__asm__ __volatile__("" ::: "memory");
	S->x_entered_c = 1;
	(void)lock_pi(&S->C);          /* 使 C 的 waiters 树非空 */
	for (;;)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

/* --------------------------------------------------------------- O2 */
static void *thread_o2(void *arg)
{
	long r;
	(void)arg;
	while (!S->w_holds_b3)
		__asm__ __volatile__("" ::: "memory");
	r = lock_pi(&S->C2);
	if (r) { lg("O2: LOCK_PI(C2) 失败 %ld errno=%d", r, errno); return NULL; }
	S->o2_tid = (int)syscall(SYS_gettid);
	S->o2_holds_c2 = 1;
	S->o2_blocked_b3 = 1;
	r = lock_pi(&S->B3);           /* 阻塞：owner = W ⇒ [10] 在此早退 */
	if (r) { lg("O2: LOCK_PI(B3) 失败 %ld errno=%d", r, errno); return NULL; }
	for (;;)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

/* --------------------------------------------------------------- X2 */
static void *thread_x2(void *arg)
{
	(void)arg;
	while (!S->o2_holds_c2)
		__asm__ __volatile__("" ::: "memory");
	S->x2_entered_c2 = 1;
	(void)lock_pi(&S->C2);
	for (;;)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

/* --------------------------------------------------------------- W3（预置） */
static void *thread_w3(void *arg)
{
	struct timespec t3;
	long r;
	(void)arg;
	while (!S->go_w3)
		__asm__ __volatile__("" ::: "memory");
	abs_timeout(&t3, T3_MS);
	S->w3_waiting = 1;
	errno = 0;
	r = futex(&S->A3, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &t3, &S->C2, 0);
	lg("W3: WAIT_REQUEUE_PI(A3→C2) 返回 %ld errno=%d", r, errno);
	return NULL;
}

/* --------------------------------------------------------------- main */
int main(void)
{
	pthread_t tw, to, tx, to2, tx2, tw3;
	long r;
	int e;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	lg("===== G3C-V6 start pid=%d (§21.28 亚毫秒窗口) =====", getpid());
	S = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (S == MAP_FAILED) { lg("mmap FAIL"); return 1; }
	memset(S, 0, 4096);

	pthread_create(&tw, NULL, thread_w, NULL);
	pthread_create(&to, NULL, thread_o, NULL);
	pthread_create(&to2, NULL, thread_o2, NULL);
	pthread_create(&tx, NULL, thread_x, NULL);
	pthread_create(&tx2, NULL, thread_x2, NULL);
	pthread_detach(tw); pthread_detach(to); pthread_detach(to2);
	pthread_detach(tx); pthread_detach(tx2);

	if (!wait_flag(&S->w_holds_ring, 3000) || !wait_flag(&S->w_holds_b3, 3000) ||
	    !wait_flag(&S->o_blocked_ring, 3000) || !wait_flag(&S->o2_blocked_b3, 3000) ||
	    !wait_flag(&S->w_waiting_a, 3000)) {
		lg("早期握手失败，终止"); _exit(2);
	}
	usleep(20000);

	/* [5] 装悬垂 */
	lg("[5] CMP_REQUEUE_PI(A→C,1)  (top_task=W, owner(B_ring)=W ⇒ 在 B_ring 早退)");
	errno = 0;
	r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C, 0);
	e = errno;
	lg("[5] → %ld errno=%d (%s)", r, e, strerror(e));
	if (!(r == -1 && e == EDEADLK)) { lg("[5] 未命中，终止"); _exit(3); }

	if (!wait_flag(&S->w_returned1, 4000)) { lg("[6] W 未从 frame1 返回，终止"); _exit(4); }
	lg("[6] W frame1 返回 %d errno=%d (%s)；UNLOCK_PI(B_ring)=%d；帧 1 已死",
	   S->w_ret1, S->w_err1, strerror(S->w_err1), S->w_unlock_ret);

	/* [7-9] 链条与 frame2 就位 */
	if (!wait_flag(&S->o_parked, 3000) || !wait_flag(&S->x_entered_c, 3000) ||
	    !wait_flag(&S->w2_waiting, 4000) || !wait_flag(&S->x2_entered_c2, 3000)) {
		lg("[7-9] 握手失败，终止"); _exit(5);
	}

	/* [9b] 预置 W3（v6 的关键改动：不在 [10b] 之后创建） */
	if (pthread_create(&tw3, NULL, thread_w3, NULL) != 0) {
		lg("[9b] W3 创建失败"); _exit(9);
	}
	pthread_detach(tw3);
	S->go_w3 = 1;
	if (!wait_flag(&S->w3_waiting, 3000)) { lg("[9b] W3 未进入等待，终止"); _exit(8); }
	lg("[9b] W3 已预置在 A3 上等待（C2 目标）");

	/* [10p] 无创前置断言：A2 上确有 requeue_pi waiter */
	{
		long pw;
		errno = 0;
		pw = futex(&S->A2, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
		if (pw == 0) { lg("[10p] A2 无 requeue_pi waiter，终止"); _exit(10); }
		lg("[10p] FUTEX_WAKE(A2,1) → %ld errno=%d (%s) (EINVAL=确有 waiter)", pw, errno, strerror(errno));
	}
	lg("[11d] 字值: A=%u A2=%u A3=%u C=%u C2=%u B3=%u Bring=%u | W=%d O=%d O2=%d",
	   S->A, S->A2, S->A3, S->C, S->C2, S->B3, S->B_ring, S->w_tid, S->o_tid, S->o2_tid);

	/* [10] 定向换向：写 waiter->lock=C2，仍在 B3 早退 */
	lg("[10] CMP_REQUEUE_PI(A2→C2,1)  (owner(B3)=W ⇒ 在 B3 早退；同时写 waiter->lock=C2)");
	errno = 0;
	r = futex(&S->A2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C2, 0);
	e = errno;
	lg("[10] → %ld errno=%d (%s)", r, e, strerror(e));
	if (!(r == -1 && e == EDEADLK)) {
		if (wait_flag(&S->w2_returned, 2000))
			lg("[10x] W frame2 已提前返回 %d errno=%d", S->w2_ret, S->w2_err);
		else
			lg("[10x] W frame2 仍在等待（未找到 waiter）");
		_exit(6);
	}

	/* ==== 窗口内：无 sleep 忙轮询帧 2 死亡，随即走查 ==== */
	if (!spin_flag(&S->w2_returned, 5000)) { lg("[10b] W 未从 frame2 返回，终止"); _exit(7); }

	{
		double tw0 = now_ms();
		lgn("[10b] 检测到 frame2 返回 %d errno=%d；窗口起点 t0",
		    S->w2_ret, S->w2_err);
		errno = 0;
		r = futex(&S->A3, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C2, 0);
		e = errno;
		lg("[12] → %ld errno=%d (%s)   窗口 = %.3f ms", r, e, strerror(e), now_ms() - tw0);
	}

	if (r == -1 && e == EDEADLK) {
		lg("verdict: **C1 成立** —— 槽内 lock==C2==orig_lock：同路径重入同址 + [10] 定向写入 + 帧死后仍被解引用");
	} else if (r >= 0) {
		lg("verdict: 对齐失败（安全出口）—— 帧 2 与帧 1 不同址或链条提前终止；C 与 O 须整体弃用");
	} else {
		lg("verdict: 其他 errno=%d (%s)", e, strerror(e));
	}
	_exit(0);
}
