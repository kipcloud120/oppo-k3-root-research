/* transfer2_probe.c - 桶模型 vs 静态热集 的最终判定
 *
 * 序列（每次都复测 6 个基准 hit 地址）：
 *   crowd@A -> 扫描得 hit 集 H
 *   pause(0 parked)   -> H 应冷（桶模型）/ 可能仍热（静态热集）
 *   resume@A          -> H 应热
 *   move to B(远页)   -> 桶模型: H 应冷、A 冷、B 热；静态模型: H 仍热
 *   move to C(更远页) -> 同上
 *   move back to A    -> H 应热
 * 修复了 transfer_probe 的迁移竞态：先改 g_crowd_addr 再 WAKE 旧地址。
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
#include <errno.h>
#include <inttypes.h>

#define PAGE 4096
#define REGION_PAGES 32768
#define REGION_SZ ((size_t)REGION_PAGES * PAGE)
#define CROWD 256
#define REPEAT 32
#define AVG_N 8
#define SCAN_LIMIT 20000
#define NHITS 6

static volatile uint8_t *region;
static volatile uint32_t *g_crowd_addr;
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
static void *crowd_thread(void *arg) {
    (void)arg;
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    while (!g_stop) {
        volatile uint32_t *a = g_crowd_addr;      /* 快照，防 pause 置 NULL 竞态 */
        if (a)
            futex_op((uint32_t *)a, FUTEX_WAIT_PRIVATE, *a, &ts);
        else
            usleep(5000);
        usleep(1000);
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

/* 迁移：先设新地址（waiter 醒来读到新值），再唤醒旧地址上的 waiter */
static void move_crowd(volatile uint32_t *newaddr, volatile uint32_t *oldaddr) {
    g_crowd_addr = newaddr;
    futex_op((uint32_t *)oldaddr, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    usleep(800000);
}
static void pause_crowd(void) {
    g_crowd_addr = NULL;
    futex_op((uint32_t *)(region + 128), FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    usleep(800000);
}

static void check_hits(const char *phase, uint64_t *hits, int nh) {
    printf("[%s]\n", phase);
    for (int i = 0; i < nh; i++) {
        uint64_t t = measure((uint32_t *)(uintptr_t)hits[i]);
        printf("  hit[%d] %p ticks=%" PRIu64 " %s\n", i + 1,
               (void *)(uintptr_t)hits[i], t,
               t > g_baseline * 10 ? "HOT" : "cold");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t tids[CROWD];
    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    memset((void *)region, 0, REGION_SZ);
    volatile uint32_t *A = (volatile uint32_t *)(region + 128);
    volatile uint32_t *B = (volatile uint32_t *)(region + 600 * PAGE + 128);
    volatile uint32_t *C = (volatile uint32_t *)(region + 1200 * PAGE + 128);
    g_crowd_addr = A;
    printf("region=%p A=%p B=%p C=%p\n", (void *)region, (void *)A, (void *)B, (void *)C);

    for (int i = 0; i < CROWD; i++) {
        if (pthread_create(&tids[i], NULL, crowd_thread, NULL) != 0) {
            printf("pthread_create FAIL at %d (%s)\n", i, strerror(errno));
            g_stop = 1;
            for (int k = 0; k < i; k++) pthread_join(tids[k], NULL);
            return 3;
        }
    }
    printf("threads created\n");
    usleep(500000);
    printf("waiters settled\n");
    g_baseline = measure((uint32_t *)(region + PAGE));
    printf("baseline=%" PRIu64 " A(crowd)=%" PRIu64 "\n", g_baseline,
           measure((uint32_t *)A));

    uint64_t hits[NHITS]; int nh = 0;
    for (int i = 1; i < SCAN_LIMIT && nh < NHITS; i++) {
        uint32_t *addr = (uint32_t *)(region + (size_t)i * PAGE + ((i * 8) % PAGE));
        if (addr == (uint32_t *)A) continue;
        uint64_t t = measure(addr);
        if (t > g_baseline * 10) {
            hits[nh++] = (uint64_t)(uintptr_t)addr;
            printf("hit[%d] %p ticks=%" PRIu64 "\n", nh, (void *)(uintptr_t)hits[nh-1], t);
        }
    }

    pause_crowd();
    check_hits("PAUSE (0 parked)", hits, nh);
    printf("  A=%" PRIu64 "\n", measure((uint32_t *)A));

    g_crowd_addr = A;
    usleep(800000);
    check_hits("RESUME @A", hits, nh);
    printf("  A=%" PRIu64 " B=%" PRIu64 " C=%" PRIu64 "\n",
           measure((uint32_t *)A), measure((uint32_t *)B), measure((uint32_t *)C));

    move_crowd(B, A);
    check_hits("MOVE -> B", hits, nh);
    printf("  A=%" PRIu64 " B=%" PRIu64 " C=%" PRIu64 "\n",
           measure((uint32_t *)A), measure((uint32_t *)B), measure((uint32_t *)C));

    move_crowd(C, B);
    check_hits("MOVE -> C", hits, nh);
    printf("  A=%" PRIu64 " B=%" PRIu64 " C=%" PRIu64 "\n",
           measure((uint32_t *)A), measure((uint32_t *)B), measure((uint32_t *)C));

    move_crowd(A, C);
    check_hits("MOVE back -> A", hits, nh);
    printf("  A=%" PRIu64 " B=%" PRIu64 " C=%" PRIu64 "\n",
           measure((uint32_t *)A), measure((uint32_t *)B), measure((uint32_t *)C));

    g_stop = 1;
    futex_op((uint32_t *)A, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    for (int i = 0; i < CROWD; i++) pthread_join(tids[i], NULL);
    munmap((void *)region, REGION_SZ);
    printf("cleanup done\n");
    return 0;
}
