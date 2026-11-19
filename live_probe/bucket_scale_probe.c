/* bucket_scale_probe.c — 判定 "hot == 同桶链遍历"（模型无关）
 *
 * 判据：
 *   若命中地址 H 与 inc 同桶，则 measure(H) 的成本 ∝ 该桶的 waiter 数（plist 全链遍历）。
 *   把 crowd 规模从 256 降到 64 再到 16，H 的耗时若按 ~4× 等比下降 ⇒ H 确实在 inc 的桶里。
 *   若不随 crowd 规模变化 ⇒ "hot" 另有机制，G1 的桶索引解释不成立。
 *
 * 编译：
 *   python -m ziglang cc -target aarch64-linux-musl -O2 -static -pthread -o live_probe/bucket_scale_probe live_probe/bucket_scale_probe.c
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
#include <inttypes.h>

#define PAGE          4096
#define REGION_PAGES  32768
#define REGION_SZ     ((size_t)REGION_PAGES * PAGE)
#define MAX_WAITERS   256
#define TARGET_ID     128
#define SCAN_PAGES    8192
#define NHITS         8
#define SETTLE_US     600000

static volatile uint8_t *region;
static volatile uint32_t *inc_futex;
static volatile int g_stop = 0;
static volatile int g_nwaiter = MAX_WAITERS;
static uint64_t g_hits[NHITS];
static int g_nhits = 0;

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
static uint64_t measure1(uint32_t *addr) {
    uint64_t t0 = rdtsc();
    futex_op(addr, FUTEX_WAKE_PRIVATE, 1, NULL);
    uint64_t t1 = rdtsc();
    return t1 - t0;
}
static uint64_t measure_med(uint32_t *addr, int n) {
    uint64_t s[32];
    if (n > 32) n = 32;
    for (int i = 0; i < n; i++) s[i] = measure1(addr);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (s[j] < s[i]) { uint64_t x = s[i]; s[i] = s[j]; s[j] = x; }
    return s[n / 2];
}

typedef struct { int idx; } arg_t;
static void *waiter(void *p) {
    int idx = ((arg_t *)p)->idx;
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    while (!g_stop) {
        if (idx >= g_nwaiter) { usleep(20000); continue; }
        futex_op((uint32_t *)inc_futex, FUTEX_WAIT_PRIVATE, *inc_futex, &ts);
        usleep(1000);
    }
    return NULL;
}

static void set_waiters(int n) {
    g_nwaiter = n;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    usleep(SETTLE_US);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t tids[MAX_WAITERS];
    arg_t args[MAX_WAITERS];

    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 2; }
    memset((void *)region, 0, REGION_SZ);
    inc_futex = (volatile uint32_t *)(region + TARGET_ID);
    printf("region=%p inc=%016" PRIx64 "\n", (void *)region, (uint64_t)(uintptr_t)inc_futex);

    for (int i = 0; i < MAX_WAITERS; i++) {
        args[i].idx = i;
        if (pthread_create(&tids[i], NULL, waiter, &args[i]) != 0) {
            printf("pthread_create FAIL %d\n", i);
            g_stop = 1;
            for (int k = 0; k < i; k++) pthread_join(tids[k], NULL);
            return 3;
        }
    }
    set_waiters(MAX_WAITERS);

    uint64_t baseline = measure_med((uint32_t *)(region + 2000 * PAGE), 16);
    printf("baseline=%" PRIu64 " inc(256)=%" PRIu64 "\n", baseline,
           measure_med((uint32_t *)inc_futex, 16));

    /* 找 hit：阈值放宽到 baseline*20（256 waiter 时应 >2000 ticks） */
    for (int i = 1; i < SCAN_PAGES && g_nhits < NHITS; i++) {
        uint32_t *addr = (uint32_t *)(region + (size_t)i * PAGE + ((i * 8) % PAGE));
        if (addr == (uint32_t *)inc_futex) continue;
        uint64_t t = measure_med(addr, 4);
        if (t > baseline * 20) {
            g_hits[g_nhits++] = (uint64_t)(uintptr_t)addr;
            printf("hit[%d] %p ticks=%" PRIu64 "\n", g_nhits, (void *)addr, t);
        }
    }
    printf("hits=%d\n", g_nhits);
    if (g_nhits == 0) { printf("FAIL: no hits\n"); goto cleanup; }

    /* 递减 crowd，复测同一批 hit 与 inc */
    const int levels[3] = { 256, 64, 16 };
    uint64_t m[3][NHITS], minc[3];
    for (int L = 0; L < 3; L++) {
        set_waiters(levels[L]);
        minc[L] = measure_med((uint32_t *)inc_futex, 8);
        for (int i = 0; i < g_nhits; i++)
            m[L][i] = measure_med((uint32_t *)(uintptr_t)g_hits[i], 8);
        printf("level n=%3d  inc=%" PRIu64 "\n", levels[L], minc[L]);
    }

    printf("\n%-3s %-14s %10s %10s %10s   r64/r16\n", "idx", "addr", "n=256", "n=64", "n=16");
    double sum_ratio = 0; int cnt = 0;
    for (int i = 0; i < g_nhits; i++) {
        double r = m[2][i] ? (double)m[1][i] / (double)m[2][i] : 0.0;
        printf("%-3d 0x%012" PRIx64 " %10" PRIu64 " %10" PRIu64 " %10" PRIu64 "   %.2f\n",
               i, g_hits[i], m[0][i], m[1][i], m[2][i], r);
        sum_ratio += r; cnt++;
    }
    printf("mean r64/r16 = %.2f （若为同桶遍历，期望 ≈ 4；若与 crowd 规模无关，期望 ≈ 1）\n",
           cnt ? sum_ratio / cnt : 0.0);
    printf("inc: n=256 %" PRIu64 "  n=64 %" PRIu64 "  n=16 %" PRIu64 "\n",
           minc[0], minc[1], minc[2]);

cleanup:
    set_waiters(MAX_WAITERS);
    g_stop = 1;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    for (int i = 0; i < MAX_WAITERS; i++) pthread_join(tids[i], NULL);
    munmap((void *)region, REGION_SZ);
    printf("cleanup done\n");
    return 0;
}
