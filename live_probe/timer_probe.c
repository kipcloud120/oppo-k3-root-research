/*
 * timer_probe.c — 只读用户态计时探针（KernelSnitch 阶段0 硬前提验证）
 *
 * 安全边界：纯用户态。只用 mrs cntvct_el0 / clock_gettime / printf。
 * 不触碰内核、不 futex、不写文件、不做持久化。若 cntvct_el0 在 EL0 被 trap，
 * 进程会 SIGILL 崩溃——但这只影响本探针进程，不影响内核或设备。
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <inttypes.h>

static inline uint64_t read_cntvct(void) {
    uint64_t v;
    __asm__ volatile("isb" ::: "memory");
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    __asm__ volatile("isb" ::: "memory");
    return v;
}

static inline uint64_t read_cntfrq(void) {
    uint64_t f;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(f));
    return f;
}

static uint64_t ns_clock(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    printf("=== timer_probe (userland, read-only) ===\n");
    fflush(stdout);

    uint64_t frq = read_cntfrq();
    printf("cntfrq_el0 = %" PRIu64 " Hz\n", frq);
    fflush(stdout);

    /* 若 cntvct_el0 在 EL0 不可读，下面第一条 mrs 就 SIGILL */
    uint64_t t0 = read_cntvct();
    uint64_t c0 = ns_clock();
    printf("cntvct_el0 readable = YES, first = %" PRIu64 "\n", t0);
    fflush(stdout);

    /* 采样 8 次，观察 cntvct 步进与 clock_gettime 步进的一致性 */
    printf("\n%-4s %-22s %-22s %-12s\n", "i", "cntvct", "clock_gettime(ns)", "delta_cntvct");
    uint64_t prev = t0;
    for (int i = 0; i < 8; i++) {
        /* 制造一点用户态工作量：空循环 */
        volatile uint64_t spin = 0;
        for (int j = 0; j < 100000; j++) spin += j;
        uint64_t c = read_cntvct();
        uint64_t n = ns_clock();
        printf("%-4d %-22" PRIu64 " %-22" PRIu64 " %-12" PRIu64 "\n",
               i, c, n, c - prev);
        prev = c;
    }
    fflush(stdout);

    /* 判定精度：cntvct 频率即分辨率，clock_gettime 若在 vDSO 用 cntvct 则同精度 */
    uint64_t c_start = read_cntvct();
    uint64_t n_start = ns_clock();
    uint64_t c_end = read_cntvct();
    uint64_t n_end = ns_clock();
    printf("\nback-to-back: cntvct delta=%" PRIu64 ", clock delta=%" PRIu64 " ns\n",
           c_end - c_start, n_end - n_start);
    printf("=> if cntvct delta > 0 and clock in ns range, high-res timer available at EL0.\n");
    (void)c0;
    return 0;
}
