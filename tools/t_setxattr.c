#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>
int main(void)
{
	char v[96];
	memset(v, 0, sizeof(v));
	int fd = open("/data/local/tmp/xa_test", O_CREAT|O_RDWR, 0600);
	printf("open=%d errno=%d\n", fd, errno);
	if (fd >= 0) { write(fd, "a", 1); close(fd); }
	int r = setxattr("/data/local/tmp/xa_test", "user.a", v, 96, 0);
	printf("setxattr(user.a,96)=%d errno=%d (%s)\n", r, errno, strerror(errno));
	char out[128]; 
	int g = getxattr("/data/local/tmp/xa_test", "user.a", out, sizeof(out));
	printf("getxattr=%d errno=%d (%s)\n", g, errno, strerror(errno));
	int r2 = setxattr("/data/local/tmp/xa_test", "security.a", v, 96, 0);
	printf("setxattr(security.a,96)=%d errno=%d (%s)\n", r2, errno, strerror(errno));
	return 0;
}
