/*
 * frpc_ioctl_probe.c — FastRPC ioctl 表与 FMODE 门槛判定（零副作用）
 *
 * 要回答的唯一问题：
 *   shell 以 **O_RDONLY** 打开的 /dev/adsprpc-smd fd，其 ioctl 是否能进到具体 handler？
 *   （若驱动/闸门要求 FMODE_WRITE，会在 copy_from_user 之前就返回 EACCES/EPERM/EBADF）
 *
 * 方法：
 *   驱动的 adsprpc_ioctl 用 switch(cmd) 精确匹配，而 _IOWR/_IOW 宏把 sizeof(struct) 编进了
 *   cmd 的 size 位。所以不知道结构体大小时必须枚举 size —— 扫 nr × size × dir 的笛卡尔积，
 *   每个组合发一个 **arg = NULL** 的 ioctl：
 *       ENOTTY  → 该 (nr,size,dir) 在驱动里不存在（正常，绝大多数）
 *       其它     → 命中！NULL 指针会在 copy_from_user 第一步就 -EFAULT 返回
 *
 * 安全边界（硬约束，不可放宽）：
 *   - **跳过 nr = 5（INIT_ATTACH，_IO 无参）与 nr = 6（FINISH）**
 *   - **跳过所有 dir = _IO（无方向位）的组合** —— 无参命令不会因 NULL 而提前返回
 *   - 只对 O_RDONLY fd 发；不打开 -secure 节点
 *   - 全程不构造任何真实请求，不触碰 DSP
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define DEVPATH "/dev/adsprpc-smd"

/* 与内核 _IOC_* 一致的位域（arm64 通用） */
#define DIR_NONE 0u
#define DIR_WRITE 1u
#define DIR_READ  2u
#define DIR_RW    3u

static unsigned int mkcmd(unsigned int dir, unsigned int nr, unsigned int size)
{
	return (dir << 30) | (size << 16) | ((unsigned int)'R' << 8) | nr;
}

int main(void)
{
	static const unsigned int nrs[] = { 0, 1, 2, 3, 4, 7, 8, 9 };
	static const unsigned int dirs[] = { DIR_READ, DIR_WRITE, DIR_RW };
	int fd, i, j, k;
	int hits = 0, enotty = 0, other = 0;

	printf("===== FRPC-IOCTL-PROBE uid=%d =====\n", getuid());

	fd = open(DEVPATH, O_RDONLY);
	if (fd < 0) { printf("open(%s, O_RDONLY) 失败 errno=%d\n", DEVPATH, errno); return 1; }
	printf("open(%s, O_RDONLY) = fd %d（只读 fd，不加 O_RDWR）\n\n", DEVPATH, fd);

	for (i = 0; i < (int)(sizeof(nrs)/sizeof(nrs[0])); i++) {
		for (k = 0; k < (int)(sizeof(dirs)/sizeof(dirs[0])); k++) {
			for (j = 1; j <= 160; j++) {
				unsigned int cmd;
				int e;

				if (nrs[i] == 5 || nrs[i] == 6) continue;   /* 硬约束：不碰 */
				if (dirs[k] == DIR_NONE) continue;

				cmd = mkcmd(dirs[k], nrs[i], (unsigned int)j);
				errno = 0;
				ioctl(fd, cmd, NULL);
				e = errno;

				if (e == ENOTTY) { enotty++; continue; }
				hits++;
				if (e != EFAULT && e != EINVAL) other++;
				printf("  命中: nr=%u dir=%u size=%3d cmd=0x%08x -> %s\n",
				       nrs[i], dirs[k], j, cmd,
				       e == EFAULT ? "EFAULT(14)  ← NULL 参数在 copy_from_user 提前返回"
				     : e == EINVAL ? "EINVAL(22)  ← handler 已进入，参数校验失败"
				     : e == EACCES ? "EACCES(13)  ← 闸门拒绝"
				     : e == EPERM  ? "EPERM(1)    ← 能力/策略拒绝"
				     : e == EBADF  ? "EBADF(9)    ← fd 模式不符（FMODE_WRITE 门槛）"
				     : "其它");
			}
		}
	}

	printf("\n---- 汇总 ----\n");
	printf("  ENOTTY（未实现）: %d\n", enotty);
	printf("  命中（非 ENOTTY）: %d   其中非 EFAULT/EINVAL: %d\n", hits, other);
	if (hits == 0)
		printf("  >> 结论：只读 fd 上没有任何可命中的 ioctl ⇒ FastRPC 面对 shell **关闭**\n");
	else if (other == 0)
		printf("  >> 结论：**只读 fd 可进入 handler**（命中且均 EFAULT/EINVAL，未触碰 DSP）"
		       " ⇒ FMODE_WRITE 门槛不存在，FastRPC 面**开放**\n");
	else
		printf("  >> 结论：混合结果，见上表逐条判读\n");
	printf("===== done（未向 DSP 发送任何请求） =====\n");
	close(fd);
	return 0;
}
