/*
 * g3c_v7.c — 自适应版（交接文档 §21.28.8 的 v7 设计）
 *
 * 目的：在一次运行内先零风险判定"X2 是否真的排在 C2 的 PI 队列上"，
 *       再据此决定是否允许走查触碰悬垂槽。
 *
 * 探针原理（4.9 futex_wake()）：
 *        plist_for_each_entry_safe(this, next, &hb->chain, list)
 *                if (match_futex(&this->key, key)) {
 *                        if (this->pi_state || this->rt_waiter) { ret = -EINVAL; break; }
 *   ⇒ 某 futex 上有已入队的 PI/requeue_pi 等待者时，FUTEX_WAKE 返回 -EINVAL；
 *     无等待者返回 0。且该分支在唤醒任何东西之前 break，**零副作用**。
 *
 * 为什么这条判定是决定性的：
 *   4.9 futex.c:2568/2109 —— 普通 FUTEX_LOCK_PI 的等待者在阻塞期间持有 pi_state 引用。
 *   ⇒ 只要 C2 上确有已入队的 PI waiter，[10] 的 put_pi_state 不可能归零 ⇒ pi_state 不被释放
 *     ⇒ 槽内 lock 始终有效 ⇒ 走查天然安全。
 *   ⇒ 若探针返回 0（无人排队），则 [10] 会真的释放 pi_state，必须先用额外 waiter 保住 refcount
 *     才允许走查。
 *
 * 分支：
 *   A) 探针(C2) == -EINVAL  ⇒ 已受保护，**不解引用槽**，直接收工（零风险）
 *   B) 探针(C2) == 0        ⇒ 未受保护；补 X3/X4 两个 PI waiter 并二次断言通过后，
 *                              再执行 [10] → 帧 2 死 → [12]（唯一可能重启的分支）
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

#define LOGPATH "/data/local/tmp/g3c7.log"

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
	volatile int go_x3;
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

static void lg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	lg_common(fmt, ap, 1);
	va_end(ap);
}

static void lgn(const char *fmt, ...)
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

static int wait_flag(volatile int *p, int ms)
{
	int i, n = ms / 2;
	for (i = 0; i < n; i++) {
		if (*p) return 1;
		usleep(2000);
	}
	return *p;
}

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

/* 探针：返回 1 = 确有已入队 waiter（-EINVAL），0 = 无（返回 0），-1 = 其它 */
static int probe_waiters(uint32_t *u, int *raw_errno)
{
	long r;
	errno = 0;
	r = futex(u, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
	*raw_errno = errno;
	if (r == -1 && errno == EINVAL) return 1;
	if (r == 0) return 0;
	return -1;
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

	r = unlock_pi(&S->B_ring);
	S->w_unlock_ret = (int)r;

	S->w2_waiting = 1;
	errno = 0;
	r = futex(&S->A2, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &t2, &S->C2, 0);
	S->w2_ret = (int)r;
	S->w2_err = errno;
	S->w2_returned = 1;

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
	(void)lock_pi(&S->C);
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
	r = lock_pi(&S->B3);
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

/* ---------------------------------------------- X3/X4（分支 B 的 refcount 保险） */
static void *thread_x3(void *arg)
{
	(void)arg;
	while (!S->go_x3)
		__asm__ __volatile__("" ::: "memory");
	(void)lock_pi(&S->C2);
	for (;;)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

/* --------------------------------------------------------------- W3 */
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

int main(int argc, char **argv)
{
	pthread_t tw, to, tx, to2, tx2, tw3, tx3, tx4;
	long r;
	int e, pr, pe, got = 0, i;
	int live_mode = (argc > 1 && argv[1][0] == 'a');   /* A′：不等 frame2 死亡 */

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	lg("===== G3C-V7 start pid=%d mode=%s =====", getpid(), live_mode ? "A' (live frame)" : "adaptive");
	S = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (S == MAP_FAILED) { lg("mmap FAIL"); return 1; }
	memset(S, 0, 4096);

	pthread_create(&tw, NULL, thread_w, NULL);
	pthread_create(&to, NULL, thread_o, NULL);
	pthread_create(&to2, NULL, thread_o2, NULL);
	pthread_create(&tx, NULL, thread_x, NULL);
	pthread_create(&tx2, NULL, thread_x2, NULL);

	if (!wait_flag(&S->w_holds_ring, 3000) || !wait_flag(&S->w_holds_b3, 3000) ||
	    !wait_flag(&S->o_blocked_ring, 3000) || !wait_flag(&S->o2_blocked_b3, 3000) ||
	    !wait_flag(&S->w_waiting_a, 3000)) {
		lg("早期握手失败，终止"); _exit(2);
	}
	usleep(20000);

	/* [5] 装悬垂 */
	lg("[5] CMP_REQUEUE_PI(A→C,1)");
	errno = 0;
	r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C, 0);
	e = errno;
	lg("[5] → %ld errno=%d (%s)", r, e, strerror(e));
	if (!(r == -1 && e == EDEADLK)) { lg("[5] 未命中，终止"); _exit(3); }

	if (!wait_flag(&S->w_returned1, 4000)) { lg("[6] W 未从 frame1 返回，终止"); _exit(4); }
	lg("[6] W frame1 返回 %d errno=%d (%s)；UNLOCK_PI(B_ring)=%d；帧 1 已死",
	   S->w_ret1, S->w_err1, strerror(S->w_err1), S->w_unlock_ret);

	if (!wait_flag(&S->o_parked, 3000) || !wait_flag(&S->x_entered_c, 3000) ||
	    !wait_flag(&S->w2_waiting, 4000) || !wait_flag(&S->x2_entered_c2, 3000)) {
		lg("[7-9] 握手失败，终止"); _exit(5);
	}

	if (pthread_create(&tw3, NULL, thread_w3, NULL) != 0) { lg("W3 创建失败"); _exit(9); }
	S->go_w3 = 1;
	if (!wait_flag(&S->w3_waiting, 3000)) { lg("W3 未进入等待，终止"); _exit(8); }

	/* ===== 探针阶段（零风险）：最多轮询 300 ms 等待 X2 入队 ===== */
	for (i = 0; i < 60; i++) {
		pr = probe_waiters(&S->C2, &pe);
		if (pr == 1) { got = 1; break; }
		usleep(5000);
	}
	lg("[P2] 探针 C2：%s (raw errno=%d) 经过 %d 轮 → %s",
	   pr == 1 ? "EINVAL ⇒ 有已入队 PI waiter" : (pr == 0 ? "0 ⇒ 无 waiter" : "其它"),
	   pe, i + 1,
	   pr == 1 ? "pi_state 的 refcount 已受保护" : "refcount 未受保护");
	{
		int ce;
		int cr = probe_waiters(&S->C, &ce);
		lg("[P1] 探针 C ：%s (raw errno=%d)  —— 交叉对照 X 是否入队",
		   cr == 1 ? "EINVAL ⇒ 有已入队 PI waiter" : (cr == 0 ? "0 ⇒ 无 waiter" : "其它"), ce);
	}

	if (pr == 1) {
		/* ---- 分支 A：refcount 已受保护，默认不解引用槽，零风险收工 ---- */
		lg("branch: A —— X2 已入队 ⇒ [10] 的 put_pi_state 不可能归零 ⇒ pi_state 未被释放");
		if (!live_mode) {
			lg("verdict: W1 模型的前提不成立；v6 的 panic 需另一解释。按 §21.28.8 判据：本分支不动悬垂槽，收工。");
			lg("---- 请外部脚本核对 uptime 连续性 ----");
			_exit(0);
		}
		lg("A′：仍执行 [10]，但**不等 frame2 死亡**就发 [12] —— 走查将读到**活的** rt_waiter");
		goto do_walk;
	}

	/* ---- 分支 B：refcount 未受保护，补 waiter 保住 pi_state ---- */
	lg("branch: B —— 无已入队 waiter ⇒ [10] 会真的释放 C2 的 pi_state；先补 refcount 再走查");
	pthread_create(&tx3, NULL, thread_x3, NULL);
	pthread_create(&tx4, NULL, thread_x3, NULL);
	S->go_x3 = 1;
	got = 0;
	for (i = 0; i < 60; i++) {
		pr = probe_waiters(&S->C2, &pe);
		if (pr == 1) { got = 1; break; }
		usleep(5000);
	}
	lg("[P3] 补齐后二次断言 C2：%s (raw errno=%d) 经过 %d 轮",
	   pr == 1 ? "EINVAL ⇒ refcount 已受保护" : "仍无 waiter", pe, i + 1);
	if (!got) {
		lg("verdict: 补充 waiter 未能入队，构造异常；为避免踩着未保护的 pi_state 走查，终止（不解引用槽）");
		_exit(15);
	}

do_walk:
	/* [10] 定向换向 */
	lg("[11d] 字值: A=%u A2=%u A3=%u C=%u C2=%u B3=%u Bring=%u | W=%d O=%d O2=%d",
	   S->A, S->A2, S->A3, S->C, S->C2, S->B3, S->B_ring, S->w_tid, S->o_tid, S->o2_tid);
	lg("[10] CMP_REQUEUE_PI(A2→C2,1)");
	errno = 0;
	r = futex(&S->A2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C2, 0);
	e = errno;
	lg("[10] → %ld errno=%d (%s)", r, e, strerror(e));
	if (!(r == -1 && e == EDEADLK)) {
		if (wait_flag(&S->w2_returned, 2000))
			lg("[10x] W frame2 已提前返回 %d errno=%d", S->w2_ret, S->w2_err);
		else
			lg("[10x] W frame2 仍在等待");
		_exit(6);
	}

	if (live_mode) {
		/* A′：frame2 仍存活（剩余寿命约 2 s），立刻走查 ⇒ 读的是活 rt_waiter */
		double tw0 = now_ms();
		lgn("[A'] frame2 仍存活（w2_returned=%d），立刻 [12]", S->w2_returned);
		errno = 0;
		r = futex(&S->A3, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C2, 0);
		e = errno;
		lg("[12] → %ld errno=%d (%s)   窗口 = %.3f ms（帧存活）",
		   r, e, strerror(e), now_ms() - tw0);
	} else {
		if (!spin_flag(&S->w2_returned, 5000)) { lg("[10b] W 未从 frame2 返回，终止"); _exit(7); }
		{
			double tw0 = now_ms();
			lgn("[10b] 检测到 frame2 返回 %d errno=%d；窗口起点 t0", S->w2_ret, S->w2_err);
			errno = 0;
			r = futex(&S->A3, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C2, 0);
			e = errno;
			lg("[12] → %ld errno=%d (%s)   窗口(W2) = %.3f ms", r, e, strerror(e), now_ms() - tw0);
		}
	}

	if (r == -1 && e == EDEADLK)
		lg(live_mode ? "verdict(A'): **走查形态本身无问题** —— 读到活 rt_waiter 时 lock==C2==orig_lock，正常返回 -EDEADLK"
			     : "verdict: **C1 成立** —— refcount 保住 pi_state，槽内 lock==C2==orig_lock，换向+走查首次安全落地");
	else if (r >= 0)
		lg("verdict: 对齐失败（安全出口）");
	else
		lg("verdict: 其他 errno=%d (%s)", e, strerror(e));
	_exit(0);
}
