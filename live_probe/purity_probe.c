/* purity_probe.c — hit 集纯度甄别（P1）: 逐 hit 的 pause/resume 翻转测试
 *
 * 背景（v009 审核 + 本轮离线复核）
 *   e2e2 的 pausecheck 不是纯度 oracle：
 *     (a) measure() 用 FUTEX_WAKE_PRIVATE,val=1，对"他进程 waiter 正好落在该桶"的
 *         污染地址是破坏性的——第一次 WAKE 就把证据唤醒，随后 31 次复测自然变冷，
 *         地址被误判为 "real hit"（源码 live_probe/e2e2_probe.c:111,216）；
 *     (b) 他进程短命 waiter 在 300ms 窗口内消散，本身也会呈现"扫描热、暂停冷"。
 *
 * 本探针的判据（不用绝对计时，用"随本进程 crowd 状态翻转"这一因果关联）
 *   真 hit:  t_hot 高 且 t_cold 低，且在多轮独立翻转中稳定重复
 *   污染:    t_cold / t_hot 与该 hit 无稳定关联（随时序漂移）
 *   每轮只取"翻转后的第一个样本"，避免 WAKE(1) 的破坏性影响累积。
 *
 * 另附对照：inc 自身（必须恒热）、冷地址（必须恒冷）。
 *
 * 编译 / 运行：
 *   python -m ziglang cc -target aarch64-linux-musl -O2 -static -pthread -o live_probe/purity_probe live_probe/purity_probe.c
 *   MSYS_NO_PATHCONV=1 adb push live_probe/purity_probe /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/purity_probe
 *   adb shell /data/local/tmp/purity_probe
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <inttypes.h>

#define PAGE             4096
#define REGION_PAGES     65536
#define REGION_SZ        ((size_t)REGION_PAGES * PAGE)
#define WAITERS          256
#define TARGET_ID        128          /* 与 e2e2 一致: region+0x80 */
#define SCAN_PAGES       32768
#define MAX_HITS         64
#define ROUNDS           5
#define SETTLE_PAUSE_US  300000     /* 撤出 crowd 后等待 */
#define SETTLE_RESUME_US 1500000    /* 恢复 crowd 后等待：256 线程唤醒风暴需 1s+ 才能衰减，
                                       否则"迁回即热"只是风暴残留（transfer2 的混淆项） */
#define HOT_RATIO        5          /* 候选/对照 > 5 判热 */
#define COLD_RATIO       2          /* 候选/对照 <= 2 判冷 */

static volatile uint8_t *region;
static volatile uint32_t *inc_futex;
static volatile int g_stop = 0;
static volatile int g_pause = 0;
static uint64_t g_hits[MAX_HITS];
static int g_nhits = 0;
static uint64_t g_baseline;
static FILE *out;

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

/* 单次测量：只取一个样本。反复采样会因 WAKE(1) 的破坏性而系统性偏低。 */
static uint64_t measure1(uint32_t *addr) {
    uint64_t t0 = rdtsc();
    futex_op(addr, FUTEX_WAKE_PRIVATE, 1, NULL);
    uint64_t t1 = rdtsc();
    return t1 - t0;
}
/* 诊断用中位数（仅用于基线/inc 对照，不用于判据） */
static uint64_t measure_med(uint32_t *addr, int n) {
    uint64_t s[64];
    if (n > 64) n = 64;
    for (int i = 0; i < n; i++) s[i] = measure1(addr);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (s[j] < s[i]) { uint64_t x = s[i]; s[i] = s[j]; s[j] = x; }
    return s[n / 2];
}
/* 同轮成对测量：候选与对照背靠背，判据用比值，抵消全局漂移/唤醒风暴 */
static void pair_measure(uint32_t *cand, uint32_t *ctrl, uint64_t *tc, uint64_t *tk) {
    *tk = measure1(ctrl);
    *tc = measure1(cand);
}

static void *waiter_thread(void *arg) {
    (void)arg;
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    while (!g_stop) {
        if (g_pause) { usleep(20000); continue; }
        futex_op((uint32_t *)inc_futex, FUTEX_WAIT_PRIVATE, *inc_futex, &ts);
        usleep(1000);
    }
    return NULL;
}

static void pause_crowd(void) {
    g_pause = 1;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    usleep(SETTLE_PAUSE_US);
}
static void resume_crowd(void) {
    g_pause = 0;
    usleep(SETTLE_RESUME_US);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    out = fopen("/data/local/tmp/ks_purity_result.txt", "w");
    pthread_t tids[WAITERS];

    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 2; }
    memset((void *)region, 0, REGION_SZ);
    inc_futex = (volatile uint32_t *)(region + TARGET_ID);
    printf("region=%p inc=%016" PRIx64 "\n", (void *)region,
           (uint64_t)(uintptr_t)inc_futex);
    fprintf(out, "region %p\ninc %016" PRIx64 "\n", (void *)region,
            (uint64_t)(uintptr_t)inc_futex);

    for (int i = 0; i < WAITERS; i++)
        if (pthread_create(&tids[i], NULL, waiter_thread, NULL) != 0) {
            printf("pthread_create FAIL %d\n", i);
            g_stop = 1;
            for (int k = 0; k < i; k++) pthread_join(tids[k], NULL);
            return 3;
        }
    usleep(500000);

    /* 基线：远离 crowd 的空桶（空链走 hb_waiters_pending 快速路径） */
    g_baseline = measure_med((uint32_t *)(region + PAGE), 16);
    uint64_t inc_meas = measure_med((uint32_t *)inc_futex, 16);
    printf("baseline=%" PRIu64 " inc=%" PRIu64 " ratio=%.1fx\n",
           g_baseline, inc_meas, (double)inc_meas / (double)(g_baseline ? g_baseline : 1));
    fprintf(out, "baseline %" PRIu64 "\ninc_meas %" PRIu64 "\n", g_baseline, inc_meas);
    if (inc_meas < g_baseline * HOT_RATIO) {
        printf("FAIL: inc not hot, oracle dead this run\n");
        fprintf(out, "fail inc_not_hot\n");
        goto cleanup;
    }

    /* 复现 e2e2 的扫描（同 stride 同页偏移），收集 hit */
    int scanned = 0, all_hits = 0;
    for (int i = 1; i < SCAN_PAGES; i++) {
        uint32_t *addr = (uint32_t *)(region + (size_t)i * PAGE + ((i * 8) % PAGE));
        if (addr == (uint32_t *)inc_futex) continue;
        uint64_t t = measure_med(addr, 4);      /* 扫描阶段允许重复采样：只求"当时热" */
        scanned++;
        if (t > g_baseline * HOT_RATIO * 2) {
            all_hits++;
            if (g_nhits < MAX_HITS) g_hits[g_nhits++] = (uint64_t)(uintptr_t)addr;
        }
    }
    printf("scan %d candidates %d hits\n", scanned, all_hits);
    fprintf(out, "scan %d %d\n", scanned, all_hits);
    for (int i = 0; i < g_nhits; i++)
        fprintf(out, "hit %d %016" PRIx64 "\n", i, g_hits[i]);

    /* ---- 核心：逐 hit 翻转测试（同轮比值判据） ---- */
    uint32_t *ctrl = (uint32_t *)(region + (size_t)(SCAN_PAGES + 1000) * PAGE + 64);
    int genuine = 0, contaminated = 0, ambiguous = 0;
    for (int i = 0; i < g_nhits; i++) {
        uint32_t *h = (uint32_t *)(uintptr_t)g_hits[i];
        int hot_r = 0, cold_r = 0;
        for (int r = 0; r < ROUNDS; r++) {
            uint64_t hc, hk;
            pause_crowd();
            pair_measure(h, ctrl, &hc, &hk);        /* crowd 不在 */
            resume_crowd();
            uint64_t hh, hk2;
            pair_measure(h, ctrl, &hh, &hk2);       /* crowd 在，风暴已衰减 */
            int hot  = (hh > hk2 * HOT_RATIO);
            int cold = (hc <= hk * COLD_RATIO);
            hot_r += hot;
            cold_r += cold;
            fprintf(out, "toggle %d %016" PRIx64 " %d %" PRIu64 " %" PRIu64
                         " %" PRIu64 " %" PRIu64 " %d %d\n",
                    i, g_hits[i], r, hc, hk, hh, hk2, hot, cold);
            printf("  toggle[%d] r%d cold=%" PRIu64 "/%" PRIu64 " hot=%" PRIu64 "/%" PRIu64 "\n",
                   i, r, hc, hk, hh, hk2);
        }
        const char *v;
        if (hot_r == ROUNDS && cold_r == ROUNDS)            { v = "genuine";      genuine++; }
        else if (hot_r == 0 && cold_r == ROUNDS)            { v = "contaminated"; contaminated++; }
        else                                                { v = "ambiguous";    ambiguous++; }
        fprintf(out, "verdict %d %016" PRIx64 " %s hot=%d/%d cold=%d/%d\n",
                i, g_hits[i], v, hot_r, ROUNDS, cold_r, ROUNDS);
        printf("VERDICT[%d] %s hot=%d/%d cold=%d/%d\n", i, v, hot_r, ROUNDS, cold_r, ROUNDS);
    }
    fprintf(out, "summary %d %d %d\n", genuine, contaminated, ambiguous);
    printf("SUMMARY genuine=%d contaminated=%d ambiguous=%d (of %d)\n",
           genuine, contaminated, ambiguous, g_nhits);
    /* genuine 子集即纯净约束集：若 >=6 个，可用其重跑 G2（离线 max-match 直接吃这份 verdict 列表） */

cleanup:
    g_pause = 0;
    g_stop = 1;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    for (int i = 0; i < WAITERS; i++) pthread_join(tids[i], NULL);
    if (out) fclose(out);
    printf("cleanup done\n");
    return 0;
}
