/* perf_probe.c - P2 只读探针：uid 2000 下 perf_event_open 是否可用
 * 安全边界：仅 syscall 探测，不采样内核栈、不写内核、不持久化。
 * v008 §4.2 唯一"未定"项：perf_event_paranoid=3 时 uid 2000 能否 open。
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

static long try_open(struct perf_event_attr *a, const char *label)
{
    long fd = syscall(SYS_perf_event_open, a, 0 /*pid=self*/, -1 /*cpu=any*/,
                      -1, 0);
    if (fd < 0) {
        printf("%-46s DENIED errno=%d (%s)\n", label, errno, strerror(errno));
    } else {
        printf("%-46s OPENED fd=%ld\n", label, fd);
        close(fd);
    }
    return fd;
}

int main(void)
{
    /* paranoid=3（实测）——理论预期：全部 DENIED（>2 拒绝一切非特权 open） */
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);

    /* 1) 硬件 cpu-cycles，exclude_kernel=1（纯用户态） */
    a.type = PERF_TYPE_HARDWARE;
    a.config = PERF_COUNT_HW_CPU_CYCLES;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    try_open(&a, "HW cycles exclude_kernel=1");

    /* 2) 硬件 cpu-cycles，exclude_kernel=0（含内核，预期必拒） */
    a.exclude_kernel = 0;
    try_open(&a, "HW cycles exclude_kernel=0");

    /* 3) 软件 task-clock，exclude_kernel=1 */
    a.type = PERF_TYPE_SOFTWARE;
    a.config = PERF_COUNT_SW_TASK_CLOCK;
    a.exclude_kernel = 1;
    try_open(&a, "SW task-clock exclude_kernel=1");

    /* 4) 软件 cpu-clock + callchain（栈采样路径，若能 open 则看 max_stack） */
    a.type = PERF_TYPE_SOFTWARE;
    a.config = PERF_COUNT_SW_CPU_CLOCK;
    a.sample_period = 100000;
    a.sample_type = PERF_SAMPLE_CALLCHAIN;
    a.exclude_kernel = 1;
    try_open(&a, "SW cpu-clock + CALLCHAIN exclude_kernel=1");

    printf("done\n");
    return 0;
}
