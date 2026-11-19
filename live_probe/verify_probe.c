/* verify_probe.c — 给定候选 mm，用模型预测"应同桶"地址集，并在设备上实测其热度
 *
 * 用途（§47.8 第 1 条）：
 *   - 认证：若预测集绝大多数为 HOT，则候选 mm 被确认（G2 出解）。
 *   - 证伪：若所有候选都失败 → 哈希模型的输入取值有误，而不是"搜索空间不够"。
 *
 * 模型（与 tools/g2_maxmatch.py 一致，见 HANDOVER §47.3）：
 *   key = { mm, page_base, offset }，bucket = jhash2([mm_lo,mm_hi,page_lo,page_hi],4,offset) & (hs-1)
 *   注意：私有 futex 走 !fshared 快路径，offset 不带 FUT_OFF_MMSHARED 标志位。
 *
 * 用法（设备上）：
 *   ./verify_probe <mm_hex> [n]         # inc 与 region 由程序自身 mmap 决定（自洽）
 * 说明：为了让预测与实测使用同一 mm，本探针**自己创建 region 与 crowd**，
 *       因此 mm 必须是"本进程"的 mm 才可能命中；其价值在于验证模型而非搜索。
 *
 * 编译：
 *   python -m ziglang cc -target aarch64-linux-musl -O2 -static -pthread -o live_probe/verify_probe live_probe/verify_probe.c
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
#define TARGET_ID     128
#define HASHSIZE      2048
#define MAXC          512

static volatile uint8_t *region;
static volatile uint32_t *inc_futex;
static volatile int g_stop = 0;

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
static uint64_t measure_med(uint32_t *addr, int n) {
    uint64_t s[32];
    if (n > 32) n = 32;
    for (int i = 0; i < n; i++) {
        uint64_t t0 = rdtsc();
        futex_op(addr, FUTEX_WAKE_PRIVATE, 1, NULL);
        s[i] = rdtsc() - t0;
    }
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (s[j] < s[i]) { uint64_t x = s[i]; s[i] = s[j]; s[j] = x; }
    return s[n / 2];
}

static inline uint32_t rol32(uint32_t w, unsigned s) { return (w << s) | (w >> (32 - s)); }
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

static void *waiter(void *p) {
    (void)p;
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    while (!g_stop) {
        futex_op((uint32_t *)inc_futex, FUTEX_WAIT_PRIVATE, *inc_futex, &ts);
        usleep(1000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { printf("usage: %s <mm_hex> [n]\n", argv[0]); return 1; }
    uint64_t mm = strtoull(argv[1], NULL, 16);
    int want = (argc > 2) ? atoi(argv[2]) : 64;
    if (want > MAXC) want = MAXC;

    pthread_t tids[WAITERS];
    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 2; }
    memset((void *)region, 0, REGION_SZ);
    inc_futex = (volatile uint32_t *)(region + TARGET_ID);
    uint64_t inc = (uint64_t)(uintptr_t)inc_futex;
    printf("region=%p inc=%016" PRIx64 " mm_candidate=%016" PRIx64 "\n",
           (void *)region, inc, mm);

    /* 预测集：在 region 里找 bucket == bucket(inc) 的地址 */
    uint32_t b0 = bucket_of(inc, mm);
    printf("predicted bucket = %u\n", b0);
    uint64_t cands[MAXC]; int nc = 0;
    for (int i = 1; i < REGION_PAGES && nc < want; i++)
        for (int off = 8; off < PAGE && nc < want; off += 128) {
            uint64_t va = (uint64_t)(uintptr_t)(region + (size_t)i * PAGE + off);
            if (bucket_of(va, mm) == b0) cands[nc++] = va;
        }
    printf("predicted hot set: %d addresses\n", nc);
    if (nc == 0) { printf("(empty)\n"); return 0; }

    for (int i = 0; i < WAITERS; i++)
        if (pthread_create(&tids[i], NULL, waiter, NULL) != 0) {
            printf("pthread_create FAIL %d\n", i);
            g_stop = 1;
            for (int k = 0; k < i; k++) pthread_join(tids[k], NULL);
            return 3;
        }
    usleep(600000);

    uint64_t base = measure_med((uint32_t *)(region + 40000 * PAGE), 16);
    uint64_t ref  = measure_med((uint32_t *)inc_futex, 16);
    printf("baseline=%" PRIu64 " inc=%" PRIu64 " ratio=%.1fx\n",
           base, ref, (double)ref / (double)(base ? base : 1));

    int hot = 0;
    for (int i = 0; i < nc; i++) {
        uint64_t t = measure_med((uint32_t *)(uintptr_t)cands[i], 4);
        int h = (t > base * 10);
        hot += h;
        if (i < 12) printf("  cand[%d] 0x%012" PRIx64 " ticks=%" PRIu64 " %s\n",
                           i, cands[i], t, h ? "HOT" : "cold");
    }
    printf("VERDICT mm=%016" PRIx64 " predicted=%d hot=%d rate=%.1f%%  => %s\n",
           mm, nc, hot, 100.0 * hot / nc,
           (hot * 10 >= nc * 8) ? "MODEL+MM CONFIRMED" :
           (hot * 10 <= nc * 2) ? "mm WRONG or MODEL WRONG" : "INCONCLUSIVE");

    g_stop = 1;
    futex_op((uint32_t *)inc_futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL);
    for (int i = 0; i < WAITERS; i++) pthread_join(tids[i], NULL);
    munmap((void *)region, REGION_SZ);
    printf("cleanup done\n");
    return 0;
}
