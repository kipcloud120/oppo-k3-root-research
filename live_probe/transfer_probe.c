/* transfer_probe.c - 热量机制是否按桶键控的决定性实验
 *
 * 若 G1 信号是桶索引的：crowd 从 A 迁到 B 后，A 的旧 hit 应全部变冷，
 * 且新 hit 集合与旧集合不同（除非极小概率同桶）。
 * 若旧 hit 在迁移后仍高温：机制不按桶键控 -> KernelSnitch G1 前提不成立。
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
#define REPEAT 32
#define AVG_N 8
#define SCAN_LIMIT 20000
#define NHITS 6

static volatile uint8_t *region;
static volatile uint32_t *g_crowd_addr;   /* 堆积地址（可迁移） */
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
        futex_op((uint32_t *)g_crowd_addr, FUTEX_WAIT_PRIVATE, *g_crowd_addr, &ts);
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

int main(void) {
    pthread_t tids[CROWD];
    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    memset((void *)region, 0, REGION_SZ);
    g_crowd_addr = (volatile uint32_t *)(region + 128);
    printf("region=%p crowdA=%p\n", (void *)region, (void *)g_crowd_addr);

    for (int i = 0; i < CROWD; i++) pthread_create(&tids[i], NULL, crowd_thread, NULL);
    usleep(500000);
    g_baseline = measure((uint32_t *)(region + PAGE));
    uint64_t Ta = measure((uint32_t *)g_crowd_addr);
    printf("baseline=%" PRIu64 " crowdA=%" PRIu64 "\n", g_baseline, Ta);

    /* 阶段1: crowd@A 找 6 个 hit */
    uint64_t hits[NHITS]; int nh = 0;
    for (int i = 1; i < SCAN_LIMIT && nh < NHITS; i++) {
        uint32_t *addr = (uint32_t *)(region + (size_t)i * PAGE + ((i * 8) % PAGE));
        if (addr == (uint32_t *)g_crowd_addr) continue;
        uint64_t t = measure(addr);
        if (t > g_baseline * 10) {
            hits[nh++] = (uint64_t)(uintptr_t)addr;
            printf("hitA[%d] %p ticks=%" PRIu64 "\n", nh, (void *)(uintptr_t)hits[nh-1], t);
        }
    }
    FILE *out = fopen("/data/local/tmp/transfer_result.txt", "w");
    for (int i = 0; i < nh; i++) fprintf(out, "hitA %p\n", (void *)(uintptr_t)hits[i]);

    /* 阶段2: crowd 迁移到 B（不同页，同页内偏移） */
    volatile uint32_t *addrB = (volatile uint32_t *)(region + 8 * PAGE + 128);
    futex_op((uint32_t *)g_crowd_addr, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    g_crowd_addr = addrB;
    usleep(800000);
    uint64_t Tb = measure((uint32_t *)addrB);
    uint64_t Ta2 = measure((uint32_t *)(region + 128));
    printf("after move: crowdB=%" PRIu64 " oldA=%" PRIu64 " (baseline=%" PRIu64 ")\n",
           Tb, Ta2, g_baseline);

    /* 阶段3: 复测旧 hits */
    int stayed = 0;
    for (int i = 0; i < nh; i++) {
        uint64_t t = measure((uint32_t *)(uintptr_t)hits[i]);
        int hot = t > g_baseline * 10;
        if (hot) stayed++;
        printf("old hit[%d] ticks=%" PRIu64 " -> %s\n", i + 1, t, hot ? "STILL HOT" : "cold");
        fprintf(out, "oldhit %d %" PRIu64 " %d\n", i, t, hot);
    }
    printf("old hits still hot: %d/%d\n", stayed, nh);

    /* 阶段4: crowd@B 找新 hits，比较集合 */
    int nh2 = 0; int overlap = 0;
    for (int i = 1; i < SCAN_LIMIT && nh2 < NHITS; i++) {
        uint32_t *addr = (uint32_t *)(region + (size_t)i * PAGE + ((i * 8) % PAGE));
        if (addr == (uint32_t *)addrB) continue;
        uint64_t t = measure(addr);
        if (t > g_baseline * 10) {
            nh2++;
            int old = 0;
            for (int k = 0; k < nh; k++) if ((uint64_t)(uintptr_t)addr == hits[k]) old = 1;
            if (old) overlap++;
            printf("hitB[%d] %p ticks=%" PRIu64 "%s\n", nh2, (void *)addr, t,
                   old ? "  (was hitA!)" : "");
            fprintf(out, "hitB %p %d\n", (void *)addr, old);
        }
    }
    printf("new hits=%d, overlap with old=%d\n", nh2, overlap);
    fprintf(out, "summary stayed=%d nh=%d nh2=%d overlap=%d\n", stayed, nh, nh2, overlap);
    fclose(out);

    g_stop = 1;
    futex_op((uint32_t *)g_crowd_addr, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    for (int i = 0; i < CROWD; i++) pthread_join(tids[i], NULL);
    munmap((void *)region, REGION_SZ);
    printf("cleanup done\n");
    return 0;
}
