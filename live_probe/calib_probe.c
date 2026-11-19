/* calib_probe.c - futex 桶热量机制标定（WAKE(0) 纯遍历，无唤醒污染）
 *
 * 参考实现 __measure 用 FUTEX_WAKE_PRIVATE val=0 —— 只遍历桶链，不唤醒。
 * 此前探针误用 val=1，测量值被"唤醒+上下文切换+重停靠争锁"污染。
 *
 * 标定矩阵（全部 WAKE(0)）：
 *   1. crowd 256 @ inc            -> T0 = f(256)
 *   2. 扫描得 3 个 hit
 *   3. +64 @ hit Xi (i=1..3)      -> T_inc（同桶应 +25% 量级）、T_Xi
 *   4. +64 @ inc                  -> f(320) 标定
 *   5. +64 @ 任意冷地址 Y1..Y3    -> T_inc（应回落 T0；若也升温则为全局机制）
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

static volatile uint32_t *g_park_addr;
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
        futex_op(addr, FUTEX_WAKE_PRIVATE, 0, NULL);   /* val=0: 纯遍历 */
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

static void park_on(uint64_t addr) {
    g_park_addr = (volatile uint32_t *)(uintptr_t)addr;
    usleep(600000);
}
static void unpark(void) {
    uint32_t *a = (uint32_t *)(uintptr_t)g_park_addr;
    g_park_addr = NULL;
    futex_op(a, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    usleep(300000);
}

int main(void) {
    pthread_t tids[CROWD + EXTRA];
    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 2; }
    memset((void *)region, 0, REGION_SZ);
    inc_futex = (volatile uint32_t *)(region + 128);
    printf("region_base=%p inc=%p\n", (void *)region, (void *)inc_futex);

    for (int i = 0; i < CROWD; i++)
        pthread_create(&tids[i], NULL, crowd_thread, NULL);
    for (int i = CROWD; i < CROWD + EXTRA; i++)
        pthread_create(&tids[i], NULL, park_thread, NULL);
    usleep(500000);

    g_baseline = measure((uint32_t *)(region + PAGE));
    uint64_t T0 = measure((uint32_t *)inc_futex);
    printf("baseline=%" PRIu64 "  T0=f(256)=%" PRIu64 "\n", g_baseline, T0);

    uint64_t hits[3]; int nh = 0;
    for (int i = 1; i < SCAN_LIMIT && nh < 3; i++) {
        uint32_t *addr = (uint32_t *)(region + (size_t)i * PAGE + ((i * 8) % PAGE));
        if (addr == (uint32_t *)inc_futex) continue;
        uint64_t t = measure(addr);
        if (t > g_baseline * 10 && t < T0 * 20) {   /* 排除异常值 */
            hits[nh++] = (uint64_t)(uintptr_t)addr;
            printf("hit[%d] %p ticks=%" PRIu64 "\n", nh, (void *)(uintptr_t)hits[nh-1], t);
        }
    }
    if (nh < 3) { printf("only %d hits\n", nh); }

    /* 标定 4：64 个 waiter 直接加到 inc 自己的桶 */
    park_on((uint64_t)(uintptr_t)inc_futex);
    uint64_t T_inc_self = measure((uint32_t *)inc_futex);
    printf("CALIB +64@inc: T_inc=%" PRIu64 " (expect f(320) if linear)\n", T_inc_self);
    unpark();

    /* 标定 3：逐个 hit */
    for (int i = 0; i < nh; i++) {
        park_on(hits[i]);
        uint64_t Ti = measure((uint32_t *)inc_futex);
        uint64_t Tx = measure((uint32_t *)(uintptr_t)hits[i]);
        printf("HIT%d +64: T_inc=%" PRIu64 " (vs T0 %.3f)  T_hit=%" PRIu64
               " (vs T0 %.3f)\n", i + 1, Ti, (double)Ti / T0, Tx, (double)Tx / T0);
        unpark();
        uint64_t Tr = measure((uint32_t *)(uintptr_t)hits[i]);
        printf("HIT%d unparked: T=%" PRIu64 "\n", i + 1, Tr);
    }

    /* 标定 5：3 个任意冷地址 */
    for (int k = 0; k < 3; k++) {
        uint64_t y = (uint64_t)(uintptr_t)(region + (size_t)(20000 + k * 111) * PAGE + 64);
        uint64_t Ty0 = measure((uint32_t *)(uintptr_t)y);
        park_on(y);
        uint64_t Ti = measure((uint32_t *)inc_futex);
        uint64_t Ty = measure((uint32_t *)(uintptr_t)y);
        printf("Y%d +64: y=%p y0=%" PRIu64 " T_inc=%" PRIu64 " (vs T0 %.3f) T_y=%" PRIu64 "\n",
               k + 1, (void *)(uintptr_t)y, Ty0, Ti, (double)Ti / T0, Ty);
        unpark();
    }

    /* 稳定性收尾 */
    uint64_t Tz = measure((uint32_t *)inc_futex);
    printf("final T_inc=%" PRIu64 " (T0=%" PRIu64 ")\n", Tz, T0);

    g_stop = 1;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    for (int i = 0; i < CROWD + EXTRA; i++) pthread_join(tids[i], NULL);
    munmap((void *)region, REGION_SZ);
    printf("cleanup done\n");
    return 0;
}
