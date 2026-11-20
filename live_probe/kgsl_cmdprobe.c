/* kgsl_cmdprobe.c —— 验证 KGSL ioctl 命令字的 size 字段语义（差分测试，零副作用）
 *
 * 目标：证明 legacy 分派器按 (cmd>>16)&0x3fff 取"声明尺寸"，并与表项 size 严格相等；
 *       不相等时在调用 handler 之前返回 -EINVAL。
 *
 * 选用的处理器：kgsl_ioctl_device_getproperty（表项 cmd=0xc0180902，size=0x18）
 *   type=8 分支要求 sizebytes==16，随后 copy_to_user(value,...)；
 *   故意给 value=(void*)1 ⇒ handler 必然返回 -EFAULT(-14)。
 *   因此：-14 = handler 被执行（尺寸门放行）；-22 = 尺寸门先拒；其它值单独记录。
 *
 * 无 GPU 状态变更、无分配、无写入；只用非法用户指针触发 EFAULT。
 */
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct gp { unsigned type; unsigned pad; void *value; unsigned long sizebytes; };

static void one(int fd, unsigned cmd, unsigned type, void *val, unsigned long sb)
{
	struct gp g; long r;
	memset(&g, 0, sizeof g);
	g.type = type; g.value = val; g.sizebytes = sb;
	errno = 0; r = ioctl(fd, cmd, &g);
	printf("cmd=%#010x type=%u val=%p sb=%lu -> ret=%ld errno=%d(%s)\n",
	       cmd, type, val, sb, r, errno, r < 0 ? strerror(errno) : "ok");
}

int main(void)
{
	int fd = open("/dev/kgsl-3d0", O_RDWR);
	if (fd < 0) { printf("open failed errno=%d(%s)\n", errno, strerror(errno)); return 1; }
	printf("fd=%d pose=%d\n", fd, (int)lseek(fd, 0, SEEK_CUR));

	/* 基准：size=0x18（表项值），type=8，value 非法指向 1 → 期望 -EFAULT */
	one(fd, 0xc0180902u, 8, (void *)1, 16);
	/* 尺寸 +1 / -1：期望 -EINVAL（handler 之前被拒） */
	one(fd, 0xc0190902u, 8, (void *)1, 16);
	one(fd, 0xc0170902u, 8, (void *)1, 16);
	/* 尺寸放大到 0x20：期望 -EINVAL */
	one(fd, 0xc0200902u, 8, (void *)1, 16);
	/* 不存在的 nr：期望 -EINVAL/ENOTTY */
	one(fd, 0xc0180903u, 8, (void *)1, 16);
	one(fd, 0xc0180940u, 8, (void *)1, 16);
	/* 尺寸正确但 type 越界（7）：handler 应返回自身错误 */
	one(fd, 0xc0180902u, 7, (void *)1, 16);
	close(fd);
	return 0;
}
