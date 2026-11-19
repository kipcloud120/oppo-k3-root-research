/* spray_probe.c - P1 只读探针：K3 上 AF_UNIX skb 堆喷射生命周期可控性
 * 安全边界：纯用户态网络栈分配，不碰内核数据、不写、不持久化；
 * 全部对象在本进程内持有/释放，退出即归零。
 *
 * 判定目标（FEASIBILITY_v008.md §4.1 两个未定项）：
 *  1) 分配接口可用性与容量：unix_stream/dgram sendmsg -> sock_alloc_send_pskb
 *  2) 生命周期可控性：分配-停留-释放-重占 的确定性与耗时
 *
 * 尺寸推导（arm64 4.9, SKB_DATA_ALIGN=64, sizeof(skb_shared_info)=320）：
 *  payload 16064 -> data alloc 16384  = order-2（K3 mm slab 同阶）
 *  payload 32128 -> data alloc 32448 -> get_order=3 = 32768 = order-3（PCKM00 对照）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#define NSOCK      256
#define MAX_PKT_O2 48      /* 256*48*16KB = 192MB 上限 */
#define MAX_PKT_O3 24      /* 256*24*32KB = 192MB 上限 */
#define RCVBUF     (2*1024*1024)

static char payload[32768];

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* 一次喷射-停留-释放周期；返回成功分配的 skb 数 */
static long cycle(int payload_len, int max_pkt, const char *label, int cycle_no)
{
    int fds[NSOCK][2];
    long ok = 0, fail = 0, drained = 0;
    int i, j;
    double t0, t1, t2, t3;

    memset(payload, 0x41, sizeof(payload));

    t0 = now_ms();
    for (i = 0; i < NSOCK; i++) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds[i]) < 0) {
            /* 关闭已建 socket，本周期终止 */
            for (int k = 0; k < i; k++) { close(fds[k][0]); close(fds[k][1]); }
            printf("  %s cyc%d: socketpair exhausted at %d/%d (%s)\n",
                   label, cycle_no, i, NSOCK, strerror(errno));
            return -1;
        }
        setsockopt(fds[i][0], SOL_SOCKET, SO_RCVBUF,
                   (int[]){RCVBUF}, sizeof(int));
    }

    /* 喷射：每 socket 连发，直到达到 max_pkt 或失败 */
    for (i = 0; i < NSOCK; i++) {
        for (j = 0; j < max_pkt; j++) {
            ssize_t r = send(fds[i][0], payload, payload_len, MSG_DONTWAIT);
            if (r == (ssize_t)payload_len) ok++;
            else { fail++; break; }
        }
    }
    t1 = now_ms();

    /* 停留：对象保持分配状态 */
    usleep(200 * 1000);

    /* 释放：对端逐包 recv，直到 EAGAIN */
    for (i = 0; i < NSOCK; i++) {
        for (;;) {
            char sink[64];
            ssize_t r = recv(fds[i][1], sink, sizeof(sink), MSG_DONTWAIT);
            if (r < 0) break;
            drained++;
        }
    }
    t2 = now_ms();

    for (i = 0; i < NSOCK; i++) { close(fds[i][0]); close(fds[i][1]); }
    t3 = now_ms();

    printf("  %s cyc%d: alloc=%ld fail=%ld drain=%ld | spray=%.0fms "
           "hold=200ms drain=%.0fms close=%.0fms\n",
           label, cycle_no, ok, fail, drained,
           t1 - t0, t2 - t1, t3 - t2);
    return ok;
}

int main(void)
{
    long base, c, worst = 0, best = 0;

    printf("== P1 skb spray lifecycle probe (uid 2000) ==\n");

    /* order-2 路径：5 个周期测确定性 */
    printf("[A] payload=16064 (data alloc order-2, 16KB) x5 cycles\n");
    base = -1;
    for (int k = 1; k <= 5; k++) {
        c = cycle(16064, MAX_PKT_O2, "o2", k);
        if (c < 0) return 1;
        if (base < 0) base = c;
        if (c > best) best = c;
        if (c < worst || k == 1) worst = c;
    }
    printf("  o2 stability: base=%ld min=%ld max=%ld spread=%.2f%%\n",
           base, worst, best, 100.0 * (best - worst) / base);

    /* order-3 对照（PCKM00 原始阶数） */
    printf("[B] payload=32128 (data alloc order-3, 32KB) x2 cycles\n");
    for (int k = 1; k <= 2; k++) {
        if (cycle(32128, MAX_PKT_O3, "o3", k) < 0) return 1;
    }

    /* 碎片化压力：order-2 喷满后立刻再来一轮，测"释放后重占" */
    printf("[C] back-to-back re-occupancy (o2) x3, no settle time\n");
    base = -1;
    for (int k = 1; k <= 3; k++) {
        c = cycle(16064, MAX_PKT_O2, "re", k);
        if (c < 0) return 1;
        if (base < 0) base = c;
    }
    printf("  re-occupancy stability: base=%ld\n", base);

    printf("done\n");
    return 0;
}
