/*
 * g3c_steer.c — GhostLock G-3c / C1：三段式「装悬垂 → 定向换向 → 自验证」
 * 依据：交接文档 §20.5（第十轮，4.9 权威源码）
 *
 * 关键语义（4.9 rtmutex.c，已逐行核对）：
 *   - futex_requeue 把 W 的 q->rt_waiter 交给 rt_mutex_start_proxy_lock(lock, waiter, q->task)
 *     ⇒ task_blocks_on_rt_mutex 的 task/top_task = **被 requeue 的 waiter 的 task（W）**，
 *       不是 requeue 执行线程（main）。
 *   - task_blocks_on_rt_mutex 在走链前写 waiter->lock = lock / waiter->prio = task->prio
 *     （:976-977），并在释放 lock->wait_lock 后才走链（:1022-1024）。
 *   - rt_mutex_adjust_prio_chain 的死锁判据（:642）：
 *         lock == orig_lock  ||  rt_mutex_owner(lock) == top_task
 *     ⇒ 若链条上某把锁的 owner 是 W（= top_task），走查会在到达 W 的槽之前 -EDEADLK。
 *   - remove_waiter（:1076）清的是 current->pi_blocked_on（:1085），不是 waiter->task 的
 *     ⇒ requeue 线程是 main，W 的 pi_blocked_on 被留下（悬垂）。
 *
 * 三阶段：
 *   [A] 步 5：requeue A→C，O 阻塞在 W 持有的 B_ring ⇒ 在 B_ring 处 -EDEADLK（不到 W 的槽）
 *       ⇒ W->pi_blocked_on = &frame1.rt_waiter（lock=C）；W 400ms 超时早退，帧 1 死亡。
 *   [B] W 释放 B_ring 让 O 停放（持有 C），X 阻塞在 C 上（使 C 树非空）；W 立刻重入同一
 *       futex_wait_requeue_pi 路径（frame2，同址）。步 10：requeue A2→C2，O2 阻塞在 W
 *       持有的 B3 ⇒ 在 B3 处 -EDEADLK（仍不到 W 的槽），但 waiter->lock 已被写成 C2。
 *       W 1500ms 超时早退，帧 2 死亡 ⇒ 槽内 lock=C2 且悬垂指针留存。
 *   [C] 步 12：O2 仍阻塞于 B3。requeue A3→C2（被 requeue 的是 W3，top_task=W3≠W）
 *       ⇒ 链条 C2→O2→B3(W)→W→槽(lock=C2) ⇒ lock==orig_lock ⇒ -EDEADLK。
 *       判据：步 12 返回 -EDEADLK = C1 成功；返回 0/1 = 同址假设失败（安全出口）。
 *
 * 安全设计：
 *   - W 在 frame2 返回后只做内存写（设 flag）并纯用户态自旋，不发任何 syscall；
 *   - 每次 fsync 落盘；任何早期判定不符即 _exit；总超时由外部 timeout 控制。
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

#define LOGPATH "/data/local/tmp/g3c.log"

#define FUTEX_LOCK_PI          6
#define FUTEX_UNLOCK_PI        7
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI  12
#define FUTEX_PRIVATE_FLAG    128

#define T1_MS   400
#define T2_MS  2500
#define T3_MS  5000

static int logfd = -1;

struct shared {
	uint32_t A, A2, A3, B_ring, B3, C, C2;
	volatile int w_holds_ring, w_holds_b3;
	volatile int o_holds_c, o_blocked_ring, o_parked, o_got_ring;
	volatile int x_entered_c;
	volatile int w_waiting_a;
	volatile int w_ret1; volatile int w_err1; volatile int w_returned1;
	volatile int w2_waiting;
	volatile int w2_ret; volatile int w2_err; volatile int w2_returned;
	volatile int o2_holds_c2, o2_blocked_b3;
	volatile int x2_entered_c2;
	volatile int w_unlock_ret;
	volatile int w_tid, o2_tid, o_tid;
	volatile int w3_waiting;
	volatile int go_unlock_b3, w_b3_released, o2_got_b3;
	volatile int go_w3;
	volatile int mode_control;
	volatile int mode_probe, w_probe_ready, w2p_waiting;
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
	n = snprintf(line, sizeof(line), "[%9.1fms] %s\n", now_ms(), buf);
	if (write(1, line, n) < 0) { }
	if (logfd >= 0 && write(logfd, line, n) < 0) { }
	if (logfd >= 0) fsync(logfd);
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
	/* 必须循环归一化：>2000ms 的超时一次减法不够，会产出非法 timespec
	 * ⇒ 内核 timespec_valid() 失败 ⇒ futex 直接返回 -EINVAL（本轮实测踩中） */
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

	/* 两个绝对超时都在 frame1 之前算好：frame1/frame2 之间不调 clock_gettime */
	abs_timeout(&t1, T1_MS);
	abs_timeout(&t2, T2_MS);

	while (!S->o_blocked_ring)
		__asm__ __volatile__("" ::: "memory");
	S->w_waiting_a = 1;
	errno = 0;
	r = futex(&S->A, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0,
		  &t1, &S->C, 0);
	S->w_ret1 = (int)r;
	S->w_err1 = errno;
	S->w_returned1 = 1;

	/* 释放 B_ring，让 O 返回并停放（C 必须保持有主、且 O 不再阻塞） */
	r = unlock_pi(&S->B_ring);
	S->w_unlock_ret = (int)r;

	if (S->mode_probe) {              /* 探针模式：只需 W 释放 B_ring，不进 frame2 */
		S->w_probe_ready = 1;
		while (!S->done)
			__asm__ __volatile__("" ::: "memory");
	}

	/* **立即**重入同一路径：frame2 与 frame1 同址 */
	S->w2_waiting = 1;
	errno = 0;
	r = futex(&S->A2, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0,
		  &t2, &S->C2, 0);
	S->w2_ret = (int)r;
	S->w2_err = errno;
	S->w2_returned = 1;

	/* [12c] 对照模式：允许主线程让 W 释放 B3（此时已不需要保护槽内容） */
	while (!S->go_unlock_b3 && !S->done)
		__asm__ __volatile__("" ::: "memory");
	if (S->go_unlock_b3) {
		(void)unlock_pi(&S->B3);
		S->w_b3_released = 1;
	}

	/* 此后绝不发 syscall（避免复用那块内核栈槽） */
	while (!S->done)
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
	r = lock_pi(&S->B_ring);          /* 阻塞；W 超时后由 W 释放 */
	if (r) { lg("O: LOCK_PI(B_ring) 失败 %ld errno=%d", r, errno); return NULL; }
	S->o_got_ring = 1;
	S->o_parked = 1;                  /* 持有 C 停放，不再阻塞 */
	while (!S->done)
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
	(void)lock_pi(&S->C);             /* 永久阻塞：使 C 的 waiters 树非空 */
	while (!S->done)
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
	r = lock_pi(&S->B3);              /* 阻塞；owner = W ⇒ step10 在此早退 */
	if (r) { lg("O2: LOCK_PI(B3) 失败 %ld errno=%d", r, errno); return NULL; }
	S->o2_got_b3 = 1;                 /* [12c]：已获 B3 并停放（不再阻塞） */
	while (!S->done)
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
	(void)lock_pi(&S->C2);            /* 使 C2 的 waiters 树非空（阴性对照兜底） */
	while (!S->done)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

/* ------------------------------------------------- 探针 waiter W2（A2→C） */
static void *thread_w2p(void *arg)
{
	struct timespec t;
	long r;
	(void)arg;
	abs_timeout(&t, 3000);
	S->w2p_waiting = 1;
	errno = 0;
	r = futex(&S->A2, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &t, &S->C, 0);
	lg("W2p: WAIT_REQUEUE_PI(A2→C) 返回 %ld errno=%d", r, errno);
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
	r = futex(&S->A3, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0,
		  &t3, &S->C2, 0);
	lg("W3: WAIT_REQUEUE_PI(A3→C2) 返回 %ld errno=%d", r, errno);
	return NULL;
}

/* --------------------------------------------------------------- main */
int main(int argc, char **argv)
{
	pthread_t tw, to, tx, to2, tx2, tw3;
	int control = (argc > 1 && argv[1][0] == 'c');
	int probe   = (argc > 1 && argv[1][0] == 'p');
	long r;
	int e, verdict = 0;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	lg("===== G3C-STEER start pid=%d mode=%s =====", getpid(), probe ? "probe" : (control ? "12c-control" : "full"));
	S = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (S == MAP_FAILED) { lg("mmap FAIL"); return 1; }
	memset(S, 0, 4096);
	S->mode_control = control;
	S->mode_probe = probe;

	/* --- [A] 装悬垂 --- */
	pthread_create(&tw, NULL, thread_w, NULL);
	pthread_create(&to, NULL, thread_o, NULL);
	pthread_create(&to2, NULL, thread_o2, NULL);
	pthread_create(&tx, NULL, thread_x, NULL);
	pthread_create(&tx2, NULL, thread_x2, NULL);

	if (!wait_flag(&S->w_holds_ring, 3000) ||
	    !wait_flag(&S->w_holds_b3, 3000) ||
	    !wait_flag(&S->o_blocked_ring, 3000) ||
	    !wait_flag(&S->o2_blocked_b3, 3000) ||
	    !wait_flag(&S->w_waiting_a, 3000)) {
		lg("早期握手失败，终止");
		S->done = 1; _exit(2);
	}
	usleep(100000);

	lg("[5] CMP_REQUEUE_PI(A→C,1)  (top_task=W, owner(B_ring)=W ⇒ 应在 B_ring 早退)");
	errno = 0;
	r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C, 0);
	e = errno;
	lg("[5] → %ld errno=%d (%s)", r, e, strerror(e));
	if (!(r == -1 && e == EDEADLK)) { lg("[5] 未命中，终止"); S->done = 1; _exit(3); }

	if (!wait_flag(&S->w_returned1, 4000)) {
		lg("[6] W 未从 frame1 返回，终止"); S->done = 1; _exit(4);
	}
	lg("[6] W frame1 返回 %d errno=%d (%s) → 悬垂指针 lock=C，帧 1 已死",
	   S->w_ret1, S->w_err1, strerror(S->w_err1));
	lg("[6] W 中间 UNLOCK_PI(B_ring) 返回 %d", S->w_unlock_ret);

	/* --- [P] 探针模式：验证 [5] 的 -EDEADLK 是否释放了 C 的 pi_state --- */
	if (S->mode_probe) {
		pthread_t tw2p;
		lg("[P] 探针模式：让 W 释放 B_ring ⇒ O 停放 ⇒ 链条在 O 终止");
		if (!wait_flag(&S->w_probe_ready, 3000)) {
			lg("[P] W 未释放 B_ring，终止"); S->done = 1; _exit(20);
		}
		if (!wait_flag(&S->o_parked, 3000)) {
			lg("[P] O 未停放，终止"); S->done = 1; _exit(21);
		}
		usleep(100000);
		if (pthread_create(&tw2p, NULL, thread_w2p, NULL) != 0) {
			lg("[P] W2p 创建失败"); S->done = 1; _exit(22);
		}
		if (!wait_flag(&S->w2p_waiting, 3000)) {
			lg("[P] W2p 未进入等待，终止"); S->done = 1; _exit(23);
		}
		usleep(100000);
		errno = 0;
		r = futex(&S->A2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C, 0);
		e = errno;
		lg("[P] 空链条 CMP_REQUEUE_PI(A2→C) → %ld errno=%d (%s)", r, e, strerror(e));
		lg(r == 1 ? "[P] verdict: **返回 1 ⇒ 内核侧 owner(C)==NULL ⇒ [5] 的 -EDEADLK 释放了 C 的 pi_state**（根因确认）"
			  : (r == 0 ? "[P] verdict: 返回 0 ⇒ owner(C) 仍为 O ⇒ pi_state 未被释放（根因不成立）"
				    : "[P] verdict: 其他结果"));
		S->done = 1;
		_exit(0);
	}

	/* --- [B] 定向换向 --- */
	if (!wait_flag(&S->o_parked, 3000) ||
	    !wait_flag(&S->x_entered_c, 3000) ||
	    !wait_flag(&S->w2_waiting, 4000) ||
	    !wait_flag(&S->x2_entered_c2, 3000)) {
		lg("[7-9] 握手失败，终止"); S->done = 1; _exit(5);
	}
	usleep(100000);

	{
		long pw;
		errno = 0;
		pw = futex(&S->A2, 1 /* FUTEX_WAKE */ | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
		if (pw == 0) {
			lg("[10p] A2 上无 requeue_pi waiter（唤醒成功）→ 中止，避免误判");
			S->done = 1; _exit(10);
		}
		lg("[10p] 探测 FUTEX_WAKE(A2,1) → %ld errno=%d (%s)  (EINVAL=确有 requeue_pi waiter)",
		   pw, errno, strerror(errno));
		lg("[10p] 字值: A2=%u A=%u C=%u C2=%u | W.tid=%d O.tid=%d O2.tid=%d",
		   S->A2, S->A, S->C, S->C2, S->w_tid, S->o_tid, S->o2_tid);
	}
	lg("[10] CMP_REQUEUE_PI(A2→C2,1)  (owner(B3)=W ⇒ 应在 B3 早退；同时写 waiter->lock=C2)");
	errno = 0;
	r = futex(&S->A2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C2, 0);
	e = errno;
	lg("[10] → %ld errno=%d (%s)", r, e, strerror(e));
	if (!(r == -1 && e == EDEADLK)) {
		if (wait_flag(&S->w2_returned, 2000))
			lg("[10x] W frame2 已提前返回 %d errno=%d (%s) ← 说明它没排到 A2 的链上",
			   S->w2_ret, S->w2_err, strerror(S->w2_err));
		else
			lg("[10x] W frame2 仍在等待（未返回）← 说明 requeue 未找到 waiter，需查 key/桶");
		lg("[10] 未命中，终止");
		S->done = 1; _exit(6);
	}

	if (!wait_flag(&S->w2_returned, 5000)) {
		lg("[10b] W 未从 frame2 返回，终止"); S->done = 1; _exit(7);
	}
	lg("[10b] W frame2 返回 %d errno=%d (%s) → 槽内 lock=C2，帧 2 已死",
	   S->w2_ret, S->w2_err, strerror(S->w2_err));

	/* --- [B2] 诊断：不做任何槽解引用，只测 C2 的 requeue 机制是否仍健康 --- */
	lg("[11d] 字值: A=%u A2=%u A3=%u C=%u C2=%u B3=%u Bring=%u | W=%d O=%d O2=%d",
	   S->A, S->A2, S->A3, S->C, S->C2, S->B3, S->B_ring,
	   S->w_tid, S->o_tid, S->o2_tid);
	{
		long dr;
		errno = 0;
		dr = futex(&S->A2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C2, 0);
		lg("[11e] 空队列 CMP_REQUEUE_PI(A2→C2) → %ld errno=%d (%s)  (期望 0：C2 机制健康)",
		   dr, errno, strerror(errno));
		if (dr != 0) { lg("[11e] C2 requeue 机制异常，终止（不解引用槽）"); S->done = 1; _exit(11); }
	}

	/* --- [C] 自验证（或 [12c] 对照模式：切断 C2→O2→B3 链条，不走查、不解引用槽） --- */
	if (S->mode_control) {
		lg("[12c] 对照模式：让 W 释放 B3 ⇒ O2 获锁停放 ⇒ 链条在 O2 终止（无走查）");
		S->go_unlock_b3 = 1;
		if (!wait_flag(&S->w_b3_released, 3000) || !wait_flag(&S->o2_got_b3, 3000)) {
			lg("[12c] W 释放 B3 / O2 获锁 未完成，终止");
			S->done = 1; _exit(12);
		}
		usleep(100000);
		if (pthread_create(&tw3, NULL, thread_w3, NULL) != 0) {
			lg("[12c] W3 线程创建失败"); S->done = 1; _exit(13);
		}
		S->go_w3 = 1;
		if (!wait_flag(&S->w3_waiting, 3000)) {
			lg("[12c] W3 未进入等待，终止"); S->done = 1; _exit(14);
		}
		usleep(100000);
		errno = 0;
		r = futex(&S->A3, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C2, 0);
		e = errno;
		lg("[12c] CMP_REQUEUE_PI(A3→C2) → %ld errno=%d (%s)", r, e, strerror(e));
		lg(r >= 0 ? "[12c] verdict: **对照通过** —— 带真实 waiter 的 C2 requeue 不崩 ⇒ 崩溃只与"
			   "『解引用悬垂槽』相关（H1c 排除）"
			 : "[12c] verdict: 对照失败（H1c 可能成立）");
		S->done = 1;
		_exit(0);
	}
	if (pthread_create(&tw3, NULL, thread_w3, NULL) != 0) {
		lg("[12] W3 线程创建失败，终止"); S->done = 1; _exit(9);
	}
	S->go_w3 = 1;
	if (!wait_flag(&S->w3_waiting, 3000)) {
		lg("[12] W3 未进入等待，终止"); S->done = 1; _exit(8);
	}
	usleep(100000);
	lg("[12] CMP_REQUEUE_PI(A3→C2,1)  (top_task=W3≠W ⇒ 走查应抵达 W 的槽)");
	errno = 0;
	r = futex(&S->A3, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C2, 0);
	e = errno;
	lg("[12] → %ld errno=%d (%s)", r, e, strerror(e));

	if (r == -1 && e == EDEADLK) {
		lg("verdict: **C1 成功** —— 槽内 lock 已换向为 C2；同路径重入同址 + 定向改写均证实");
		verdict = 1;
	} else if (r >= 0) {
		lg("verdict: 对齐失败（槽内仍是 C 或未改写）—— 设备无损，需调整扫描窗口");
		verdict = 2;
	} else {
		lg("verdict: 其他 errno=%d (%s)", e, strerror(e));
		verdict = 3;
	}
	lg("---- 设备健康检查应由外部脚本执行（uptime/loadavg） ----");
	lg("结束 verdict=%d", verdict);
	S->done = 1;
	_exit(0);
}
