/*
 * frpc_probe.c — FastRPC 面可达性探测（只读 / 零副作用）
 *
 * 目的：把 §5.2「第 4 名：/dev/adsprpc*，shell 可达性未测」这一条填上。
 *
 * 只做三件事，绝不向 DSP 发任何请求：
 *   1. open(O_RDONLY) / open(O_RDWR) —— 字符设备的 FMODE 门槛
 *   2. ioctl(fd, 0)               —— 未实现命令号。返回 ENOTTY 说明**已穿过 LSM 闸门**
 *                                    （SELinux 的 file_ioctl hook 在驱动之前，会返 EACCES/EPERM）
 *   3. 对 -secure 节点做同样的 open 试探（预期被 0640 挡住）
 *
 * 明确不做：FASTRPC_IOCTL_INIT / INVOKE / MMAP / FINISH —— 那些会真的创建 DSP 上下文，
 * 属于"对该面动手"，需单独授权。本程序只回答"能不能碰到驱动的 ioctl 入口"。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

static const char *errname(int e)
{
	static char b[64];
	switch (e) {
	case 0: return "OK";
	case EPERM: return "EPERM(1) SELinux/能力";
	case EACCES: return "EACCES(13) SELinux/权限";
	case ENOTTY: return "ENOTTY(25) 已到驱动但无该命令";
	case ENODEV: return "ENODEV(19)";
	case ENOSYS: return "ENOSYS(38)";
	case EFAULT: return "EFAULT(14)";
	case EINVAL: return "EINVAL(22)";
	}
	snprintf(b, sizeof(b), "errno=%d", e);
	return b;
}

static void probe(const char *path)
{
	int fd, e;
	char tag[64];

	printf("== %s ==\n", path);

	/* 1. O_RDONLY */
	errno = 0;
	fd = open(path, O_RDONLY);
	e = errno;
	printf("  open(O_RDONLY)      -> %d  %s\n", fd, errname(e));
	if (fd >= 0) {
		errno = 0;
		ioctl(fd, 0);
		e = errno;
		printf("  ioctl(fd, 0)        -> %s\n", errname(e));
		printf("  >> %s\n", (e == ENOTTY)
		       ? "结论：ioctl 已穿过 SELinux 闸门（驱动收到未实现命令）"
		       : (e == EACCES || e == EPERM)
		         ? "结论：SELinux 拒绝该 fd 上的 ioctl"
		         : "结论：其它返回，需按 errno 判读");
		close(fd);
	}

	/* 2. O_RDWR */
	errno = 0;
	fd = open(path, O_RDWR);
	e = errno;
	printf("  open(O_RDWR)        -> %d  %s\n", fd, errname(e));
	if (fd >= 0) {
		errno = 0;
		ioctl(fd, 0);
		e = errno;
		printf("  ioctl(fd, 0)        -> %s\n", errname(e));
		close(fd);
	}
	snprintf(tag, sizeof(tag), "  >> %s", "（O_RDWR 成功才意味着多数 FastRPC ioctl 的 FMODE_WRITE 门槛不存在）");
	printf("%s\n", tag);
	printf("\n");
}

int main(void)
{
	printf("===== FRPC-PROBE start uid=%d =====\n", getuid());
	probe("/dev/adsprpc-smd");
	probe("/dev/adsprpc-smd-secure");
	printf("===== done（未向 DSP 发送任何请求） =====\n");
	return 0;
}
