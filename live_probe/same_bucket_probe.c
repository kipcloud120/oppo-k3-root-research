/* same_bucket_probe.c - 不依赖 mm 知识的同桶性判定实验
 *
 * 原理：inc_futex 上有 256 个 waiter（桶 B）。若某 hit X 与 inc 同桶，
 * 则在 X 上再加 64 个 waiter 后，inc 的 WAKE 耗时应上升 ~25%（320/256）。
 * 若 X 在别的桶，inc 耗时不变。这从观测侧独立检验热量机制，绕开 G2 模型。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <time.h>
#include <inttypes.h>

#define PAGE 4096
#define REGION_PAGES 32768
#define REGION_SZ ((size_t)REGION_PAGES * PAGE)
#define CROWD 256
#define EXTRA 64
#define REPEAT 32
#define AVG_N 8
#define SCAN_LIMIT 20000

static volatile uint8_t *region;
static volatile uint32_t *inc_futex;
static volatile int g_stop = 0;
static uint64_t g_baseline;

static inline uint64_t rdtsc(void) {
    uint64_t v;
    __asm__ volatile("isb" ::: "memory");
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    __asm__ volatile("isb" ::: "memory");
    return v;
}
static int futex_op(uint32_t *u, int op, uint32_t val, const struct timespec *to) {
    return (int)syscall(SYS_futex, u, op, val, to, NULL, 0);
}

static volatile uint32_t *g_park_addr;   /* 附加 waiter 的停靠地址 */
static void *crowd_thread(void *arg) {
    (void)arg;
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    while (!g_stop) {
        futex_op((uint32_t *)inc_futex, FUTEX_WAIT_PRIVATE, *inc_futex, &ts);
        usleep(1000);
    }
    return NULL;
}
static void *park_thread(void *arg) {
    (void)arg;
    struct timespec ts = { .tv_sec = 30, .tv_nsec = 0 };
    while (!g_stop) {
        if (g_park_addr)
            futex_op((uint32_t *)g_park_addr, FUTEX_WAIT_PRIVATE, *g_park_addr, &ts);
        else
            usleep(5000);
    }
    return NULL;
}

static uint64_t measure(uint32_t *addr) {
    uint64_t s[REPEAT];
    for (int i = 0; i < REPEAT; i++) {
        uint64_t t0 = rdtsc();
        futex_op(addr, FUTEX_WAKE_PRIVATE, 1, NULL);
        uint64_t t1 = rdtsc();
        s[i] = t1 - t0;
    }
    for (int i = 0; i < REPEAT; i++)
        for (int j = i + 1; j < REPEAT; j++)
            if (s[j] < s[i]) { uint64_t x = s[i]; s[i] = s[j]; s[j] = x; }
    uint64_t sum = 0;
    for (int i = 0; i < AVG_N; i++) sum += s[i];
    return sum / AVG_N;
}

int main(void) {
    pthread_t tids[CROWD + EXTRA];
    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 2; }
    memset((void *)region, 0, REGION_SZ);
    inc_futex = (volatile uint32_t *)(region + 128);
    printf("region_base = %p  inc_futex = %p\n", (void *)region, (void *)inc_futex);

    for (int i = 0; i < CROWD; i++)
        pthread_create(&tids[i], NULL, crowd_thread, NULL);
    /* 预备池：先闲置 */
    for (int i = CROWD; i < CROWD + EXTRA; i++)
        pthread_create(&tids[i], NULL, park_thread, NULL);
    usleep(500000);

    uint64_t b1 = measure((uint32_t *)(region + PAGE));
    g_baseline = b1;
    uint64_t T0 = measure((uint32_t *)inc_futex);
    printf("baseline=%" PRIu64 " T0(inc,256 crowd)=%" PRIu64 "\n", g_baseline, T0);

    /* 找两个 hit */
    uint64_t hits[2]; int nh = 0;
    for (int i = 1; i < SCAN_LIMIT && nh < 2; i++) {
        uint32_t *addr = (uint32_t *)(region + (size_t)i * PAGE + ((i * 8) % PAGE));
        if (addr == (uint32_t *)inc_futex) continue;
        uint64_t t = measure(addr);
        if (t > g_baseline * 10) {
            hits[nh++] = (uint64_t)(uintptr_t)addr;
            printf("hit[%d] %p ticks=%" PRIu64 "\n", nh, (void *)(uintptr_t)hits[nh-1], t);
        }
    }
    if (nh < 2) { printf("only %d hits, abort\n", nh); return 1; }

    /* 在 X1 上加 64 个 waiter */
    g_park_addr = (volatile uint32_t *)hits[0];
    futex_op((uint32_t *)g_park_addr, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    usleep(800000);   /* 等全部停靠 */

    uint64_t T_inc = measure((uint32_t *)inc_futex);
    uint64_t T_x1  = measure((uint32_t *)(uintptr_t)hits[0]);
    uint64_t T_x2  = measure((uint32_t *)(uintptr_t)hits[1]);
    printf("after +64 waiters on X1:\n");
    printf("  inc = %" PRIu64 "  (T0=%" PRIu64 ", ratio %.3f)\n", T_inc, T0, (double)T_inc / T0);
    printf("  X1  = %" PRIu64 "  (ratio vs T0 %.3f)\n", T_x1, (double)T_x1 / T0);
    printf("  X2  = %" PRIu64 "  (ratio vs T0 %.3f)\n", T_x2, (double)T_x2 / T0);
    printf("expected if same-bucket: inc~1.25, X1~1.25, X2~1.25\n");
    printf("expected if X1 elsewhere: inc~1.00, X2~1.00, X1~0.25\n");

    /* 对照：64 waiter 挪到冷地址 Y */
    uint64_t Ty0 = measure((uint32_t *)(region + (size_t)30000 * PAGE + 64));
    g_park_addr = (volatile uint32_t *)(region + (size_t)30000 * PAGE + 64);
    futex_op((uint32_t *)g_park_addr, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    /* X1 的 64 个 waiter 退出等待需要唤醒 */
    futex_op((uint32_t *)(uintptr_t)hits[0], FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    usleep(800000);
    uint64_t Ty1 = measure((uint32_t *)(region + (size_t)30000 * PAGE + 64));
    uint64_t T_inc2 = measure((uint32_t *)inc_futex);
    printf("control: Y=%p ticks %" PRIu64 " -> %" PRIu64 " (self-heated ratio %.2f)\n",
           (void *)(region + (size_t)30000 * PAGE + 64), Ty0, Ty1,
           (double)Ty1 / (g_baseline ? g_baseline : 1));
    printf("inc after control = %" PRIu64 " (ratio vs T0 %.3f)\n", T_inc2, (double)T_inc2 / T0);

    g_stop = 1;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    futex_op((uint32_t *)g_park_addr, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    for (int i = 0; i < CROWD + EXTRA; i++) pthread_join(tids[i], NULL);
    munmap((void *)region, REGION_SZ);
    printf("cleanup done\n");
    return 0;
}
