/* e2e_predict_probe.c — 端到端预测命中率验证（同进程挂起式，HANDOVER §48.6-1）
 *
 * 背景：G2 已闭合（§48）。本探针把「恢复 mm → 预测必然同桶地址集 → 实测命中」
 *       做成同进程闭环：预测与实测使用同一 mm / 同一 region / 同一 crowd，
 *       且预测集与扫描 hit 集严格互斥（避免循环论证）。
 *
 * 流程：
 *   A) 自建 region(256MB) + 256 waiter crowd，扫描 32768 页收集 hit，
 *      逐 hit 翻转纯度甄别（2 轮），仅 genuine hit 以 "hit" 行落盘
 *      /data/local/tmp/ks_e2ep_result.txt（格式兼容 tools/g2_maxmatch.py）。
 *   B) 轮询 /data/local/tmp/ks_hold_ans.txt（最长 1 h），读回候选 mm；
 *      crowd 全程保持，进程不退出（同进程 ⇒ mm 不变）。
 *   C) 用候选 mm 复核全部 genuine hit（应 100% 同桶）；再在**未参与扫描**的
 *      地址中预测「必然同桶」集 WANT_PRED 个 + 等量冷地址对照，实测命中率。
 *
 * 判据（沿用 verify_probe.c / purity_probe.c）：
 *   hot  : cand 中值 > ctrl 中值 × 5
 *   cold : cand 中值 <= ctrl 中值 × 2
 *   预测 hot 命中率 >= 80% => MODEL+MM CONFIRMED；<= 20% => mm WRONG。
 *
 * 编译 / 运行（同 purity_probe）：
 *   python -m ziglang cc -target aarch64-linux-musl -O2 -static -pthread -o live_probe/e2e_predict_probe live_probe/e2e_predict_probe.c
 *   MSYS_NO_PATHCONV=1 adb push live_probe/e2e_predict_probe /data/local/tmp/
 *   adb shell /data/local/tmp/e2e_predict_probe
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
#define REGION_PAGES  65536
#define REGION_SZ     ((size_t)REGION_PAGES * PAGE)
#define WAITERS       256
#define TARGET_ID     128              /* inc = region+0x80，与 e2e2/purity 一致 */
#define HASHSIZE      2048
#define SCAN_PAGES    32768
#define MAX_HITS      48
#define ROUNDS        2                /* 翻转纯度甄别轮数（purity 用 5，此处压缩） */
#define WANT_PRED     32               /* 预测 hot 集规模（= 冷对照集规模） */
#define SETTLE_PAUSE_US  300000
#define SETTLE_RESUME_US 1500000
#define HOT_RATIO     5
#define COLD_RATIO    2
#define SCAN_HOT_MULT (HOT_RATIO * 2)  /* 扫描判热阈值：baseline × 10 */
#define POLL_SEC      3600
#define OUT_PATH  "/data/local/tmp/ks_e2ep_result.txt"
#define ANS_PATH  "/data/local/tmp/ks_hold_ans.txt"

static volatile uint8_t *region;
static volatile uint32_t *inc_futex;
static volatile int g_stop = 0;
static volatile int g_pause = 0;
static uint64_t g_hits[MAX_HITS];       /* 扫描到的原始 hit（含可能污染） */
static int g_nhits = 0;
static uint64_t g_genuine[MAX_HITS];    /* 翻转甄别后的纯净 hit */
static int g_ngenuine = 0;
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
/* 单次测量（purity 判据：反复采样会被 WAKE(1) 破坏性压低） */
static uint64_t measure1(uint32_t *addr) {
    uint64_t t0 = rdtsc();
    futex_op(addr, FUTEX_WAKE_PRIVATE, 1, NULL);
    return rdtsc() - t0;
}
static uint64_t measure_med(uint32_t *addr, int n) {
    uint64_t s[64];
    if (n > 64) n = 64;
    for (int i = 0; i < n; i++) s[i] = measure1(addr);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (s[j] < s[i]) { uint64_t x = s[i]; s[i] = s[j]; s[j] = x; }
    return s[n / 2];
}

static inline uint32_t rol32(uint32_t w, unsigned s) { return (w << s) | (w >> (32 - s)); }
/* 模型与 tools/g2_maxmatch.py（v3，§48 闭合版本）一致：
 * key = { mm_lo, mm_hi, page_lo, page_hi }，seed = va & 0xfff（私有路径无标志位） */
static uint32_t jhash2_4(const uint32_t *k, uint32_t initval) {
    uint32_t a, b, c;
    a = b = c = 0xdeadbeefu + 16u + initval;
    a += k[0]; b += k[1]; c += k[2];
    a -= c; a ^= rol32(c, 4);  c += b;
    b -= a; b ^= rol32(a, 6);  a += c;
    c -= b; c ^= rol32(b, 8);  b += a;
    a -= c; a ^= rol32(c, 16); c += b;
    b -= a; b ^= rol32(a, 19); a += c;
    c -= b; c ^= rol32(b, 4);  b += a;
    a += k[3];
    c ^= b; c -= rol32(b, 14);
    a ^= c; a -= rol32(c, 11);
    b ^= a; b -= rol32(a, 25);
    c ^= b; c -= rol32(b, 16);
    a ^= c; a -= rol32(c, 4);
    b ^= a; b -= rol32(a, 14);
    c ^= b; c -= rol32(b, 24);
    return c;
}
static uint32_t bucket_of(uint64_t va, uint64_t mm) {
    uint32_t k[4];
    k[0] = (uint32_t)mm;
    k[1] = (uint32_t)(mm >> 32);
    k[2] = (uint32_t)(va & ~0xfffULL);
    k[3] = (uint32_t)((va & ~0xfffULL) >> 32);
    return jhash2_4(k, (uint32_t)(va & 0xfff)) & (HASHSIZE - 1);
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

/* 候选 vs 固定对照：各采 nsamp 个单样本，返回中值比值判级（1=hot, 0=cold, -1=中间） */
static int judge_cand(uint32_t *cand, uint32_t *ctrl, int nsamp,
                      uint64_t *cm_out, uint64_t *km_out) {
    uint64_t cm[16], km[16];
    if (nsamp > 16) nsamp = 16;
    for (int i = 0; i < nsamp; i++) { km[i] = measure1(ctrl); cm[i] = measure1(cand); }
    for (int i = 0; i < nsamp; i++)
        for (int j = i + 1; j < nsamp; j++)
            if (cm[j] < cm[i]) { uint64_t x = cm[i]; cm[i] = cm[j]; cm[j] = x; }
    for (int i = 0; i < nsamp; i++)
        for (int j = i + 1; j < nsamp; j++)
            if (km[j] < km[i]) { uint64_t x = km[i]; km[i] = km[j]; km[j] = x; }
    *cm_out = cm[nsamp / 2];
    *km_out = km[nsamp / 2];
    if (*cm_out > *km_out * HOT_RATIO) return 1;
    if (*cm_out <= *km_out * COLD_RATIO) return 0;
    return -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    out = fopen(OUT_PATH, "w");
    if (!out) { perror("fopen out"); return 2; }
    pthread_t tids[WAITERS];

    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 2; }
    memset((void *)region, 0, REGION_SZ);
    inc_futex = (volatile uint32_t *)(region + TARGET_ID);
    uint64_t inc = (uint64_t)(uintptr_t)inc_futex;
    printf("region=%p inc=%016" PRIx64 "\n", (void *)region, inc);
    fprintf(out, "region %p\ninc %016" PRIx64 "\n", (void *)region, inc);

    for (int i = 0; i < WAITERS; i++)
        if (pthread_create(&tids[i], NULL, waiter_thread, NULL) != 0) {
            printf("pthread_create FAIL %d\n", i);
            g_stop = 1;
            for (int k = 0; k < i; k++) pthread_join(tids[k], NULL);
            return 3;
        }
    usleep(500000);

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

    /* ---- A1: 扫描收集 hit（stride 与 purity_probe 相同） ---- */
    int scanned = 0, all_hits = 0;
    for (int i = 1; i < SCAN_PAGES; i++) {
        uint32_t *addr = (uint32_t *)(region + (size_t)i * PAGE + ((i * 8) % PAGE));
        if (addr == (uint32_t *)inc_futex) continue;
        uint64_t t = measure_med(addr, 4);
        scanned++;
        if (t > g_baseline * SCAN_HOT_MULT) {
            all_hits++;
            if (g_nhits < MAX_HITS) g_hits[g_nhits++] = (uint64_t)(uintptr_t)addr;
        }
    }
    printf("scan %d candidates %d hits (kept %d)\n", scanned, all_hits, g_nhits);
    fprintf(out, "scan %d %d\n", scanned, all_hits);
    for (int i = 0; i < g_nhits; i++)
        fprintf(out, "scanhit %d %016" PRIx64 "\n", i, g_hits[i]);

    /* ---- A2: 逐 hit 翻转纯度甄别（2 轮；仅 genuine 作为约束集） ---- */
    uint32_t *ctrl = (uint32_t *)(region + (size_t)(SCAN_PAGES + 1000) * PAGE + 64);
    for (int i = 0; i < g_nhits; i++) {
        uint32_t *h = (uint32_t *)(uintptr_t)g_hits[i];
        int hot_r = 0, cold_r = 0;
        for (int r = 0; r < ROUNDS; r++) {
            uint64_t hc, hk, hh, hk2;
            pause_crowd();
            hk = measure1(ctrl); hc = measure1(h);
            resume_crowd();
            hk2 = measure1(ctrl); hh = measure1(h);
            int hot  = (hh > hk2 * HOT_RATIO);
            int cold = (hc <= hk * COLD_RATIO);
            hot_r += hot; cold_r += cold;
            fprintf(out, "toggle %d %016" PRIx64 " %d %" PRIu64 " %" PRIu64
                         " %" PRIu64 " %" PRIu64 " %d %d\n",
                    i, g_hits[i], r, hc, hk, hh, hk2, hot, cold);
        }
        const char *v;
        if (hot_r == ROUNDS && cold_r == ROUNDS)      { v = "genuine";      g_genuine[g_ngenuine++] = g_hits[i]; }
        else if (hot_r == 0 && cold_r == ROUNDS)      { v = "contaminated"; }
        else                                          { v = "ambiguous"; }
        fprintf(out, "verdict %d %016" PRIx64 " %s hot=%d/%d cold=%d/%d\n",
                i, g_hits[i], v, hot_r, ROUNDS, cold_r, ROUNDS);
        printf("VERDICT[%d] %s\n", i, v);
    }
    printf("SUMMARY genuine=%d of %d\n", g_ngenuine, g_nhits);
    fprintf(out, "summary %d %d\n", g_ngenuine, g_nhits);
    /* 约束集：g2_maxmatch.py 只解析 "hit" 行 —— 只放 genuine */
    for (int i = 0; i < g_ngenuine; i++)
        fprintf(out, "hit %d %016" PRIx64 "\n", i, g_genuine[i]);
    fflush(out);

    if (g_ngenuine < 8) {
        printf("FAIL: genuine hits %d < 8, not enough constraints\n", g_ngenuine);
        fprintf(out, "fail not_enough_constraints\n");
        goto cleanup;
    }

    /* ---- B: 挂起轮询候选 mm（crowd 保持在线，mm 不变） ---- */
    printf("WAITING for %s (up to %d s) ...\n", ANS_PATH, POLL_SEC);
    uint64_t mm = 0;
    for (int s = 0; s < POLL_SEC && !mm; s += 2) {
        usleep(2000000);
        FILE *f = fopen(ANS_PATH, "r");
        if (!f) continue;
        char buf[256];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = 0;
        fclose(f);
        char *p = strstr(buf, "mm");
        if (p) { p += 2; while (*p == ' ' || *p == '\t' || *p == '=') p++; }
        else p = buf;
        uint64_t v = strtoull(p, NULL, 16);
        if (v) {
            mm = v;
            unlink(ANS_PATH);
        }
    }
    if (!mm) {
        printf("TIMEOUT: no answer within %d s\n", POLL_SEC);
        fprintf(out, "fail poll_timeout\n");
        goto cleanup;
    }
    printf("GOT mm=%016" PRIx64 "\n", mm);
    fprintf(out, "answer mm %016" PRIx64 "\n", mm);

    /* ---- C1: 恢复自检——全部 genuine hit 在该 mm 下应与 inc 同桶 ---- */
    uint32_t b0 = bucket_of(inc, mm);
    int same = 0;
    for (int i = 0; i < g_ngenuine; i++)
        if (bucket_of(g_genuine[i], mm) == b0) same++;
    printf("RECOVER-CHECK %d/%d same-bucket (inc bucket=%u)\n", same, g_ngenuine, b0);
    fprintf(out, "recover_check %d %d %u\n", same, g_ngenuine, b0);

    /* ---- C2: 预测集（与扫描 hit 互斥）+ 冷对照集 ---- */
    uint64_t hotc[WANT_PRED], coldc[WANT_PRED];
    int nh = 0, nc = 0;
    for (int i = 1; i < REGION_PAGES && (nh < WANT_PRED || nc < WANT_PRED); i++) {
        for (int off = 8; off < PAGE && (nh < WANT_PRED || nc < WANT_PRED); off += 8) {
            uint64_t va = (uint64_t)(uintptr_t)(region + (size_t)i * PAGE + off);
            int is_hit = 0;
            for (int k = 0; k < g_nhits; k++)
                if (g_hits[k] == va) { is_hit = 1; break; }
            if (is_hit) continue;
            uint32_t b = bucket_of(va, mm);
            if (b == b0 && nh < WANT_PRED) hotc[nh++] = va;
            else if (b != b0 && nc < WANT_PRED) coldc[nc++] = va;
        }
    }
    printf("PREDICTED hot=%d cold=%d (bucket=%u)\n", nh, nc, b0);
    fprintf(out, "predicted hot %d cold %d\n", nh, nc);

    /* ---- C3: 实测。hot/cold 交替测量，控制漂移 ---- */
    int hot_n = 0, cold_n = 0, hot_amb = 0;
    for (int i = 0; i < nh; i++) {
        uint64_t cm, km;
        int j = judge_cand((uint32_t *)(uintptr_t)hotc[i], ctrl, 5, &cm, &km);
        if (j == 1) hot_n++; else if (j < 0) hot_amb++;
        if (i < 12) printf("  hot[%d] %012" PRIx64 " cand=%" PRIu64 " ctrl=%" PRIu64
                           " -> %s\n", i, hotc[i], cm, km,
                           j == 1 ? "HOT" : (j == 0 ? "cold" : "amb"));
        fprintf(out, "predhot %d %016" PRIx64 " %" PRIu64 " %" PRIu64 " %d\n",
                i, hotc[i], cm, km, j);
    }
    int fcold_n = 0, fhot_n = 0;
    for (int i = 0; i < nc; i++) {
        uint64_t cm, km;
        int j = judge_cand((uint32_t *)(uintptr_t)coldc[i], ctrl, 5, &cm, &km);
        if (j == 0) fcold_n++; else if (j == 1) fhot_n++;
        if (i < 12) printf("  cold[%d] %012" PRIx64 " cand=%" PRIu64 " ctrl=%" PRIu64
                           " -> %s\n", i, coldc[i], cm, km,
                           j == 0 ? "cold" : (j == 1 ? "HOT" : "amb"));
        fprintf(out, "predcold %d %016" PRIx64 " %" PRIu64 " %" PRIu64 " %d\n",
                i, coldc[i], cm, km, j);
    }
    /* oracle 存活复核 */
    uint64_t icm, ikm;
    int inc_j = judge_cand((uint32_t *)inc_futex, ctrl, 5, &icm, &ikm);
    printf("oracle inc -> %s (cand=%" PRIu64 " ctrl=%" PRIu64 ")\n",
           inc_j == 1 ? "HOT" : (inc_j == 0 ? "cold" : "amb"), icm, ikm);
    fprintf(out, "oracle_inc %d %" PRIu64 " %" PRIu64 "\n", inc_j, icm, ikm);

    double rate = nh ? 100.0 * hot_n / nh : 0.0;
    double frate = nc ? 100.0 * fhot_n / nc : 0.0;
    const char *verdict;
    if (inc_j != 1)                                   verdict = "ORACLE DEAD, INCONCLUSIVE";
    else if (hot_n * 10 >= nh * 8 && fcold_n == nc)   verdict = "MODEL+MM CONFIRMED";
    else if (hot_n * 10 <= nh * 2)                    verdict = "mm WRONG or MODEL WRONG";
    else                                              verdict = "INCONCLUSIVE";
    printf("VERDICT mm=%016" PRIx64 " predicted=%d hot=%d rate=%.1f%% "
           "amb=%d | coldcontrol=%d falsehot=%d frate=%.1f%% | recover=%d/%d => %s\n",
           mm, nh, hot_n, rate, hot_amb, nc, fhot_n, frate, same, g_ngenuine, verdict);
    fprintf(out, "VERDICT mm %016" PRIx64 " predicted %d hot %d rate %.1f "
                 "amb %d coldcontrol %d falsehot %d frate %.1f recover %d %d => %s\n",
            mm, nh, hot_n, rate, hot_amb, nc, fhot_n, frate, same, g_ngenuine, verdict);

cleanup:
    g_pause = 0;
    g_stop = 1;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    for (int i = 0; i < WAITERS; i++) pthread_join(tids[i], NULL);
    fflush(out);
    fclose(out);
    printf("cleanup done\n");
    return 0;
}
