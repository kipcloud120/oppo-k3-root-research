/*
 * surface_probe.c — shell 域攻击面普查（只测 open，绝不 write）
 *
 * 设计原则：open(path, O_WRONLY) 会触发 DAC + SELinux 的写权限检查，但**不产生任何状态变化**。
 * 因此"open 成功即代表可写"这一判定在信息量上等价于试写，而副作用为零。
 *
 * 四部分：
 *   A. /dev 扫描 —— 字符/块设备，测 O_RDONLY；对白名单子系统追加 O_WRONLY / O_RDWR
 *   B. /proc/sys 递归（深度 3）—— 测 O_WRONLY
 *   C. /sys/module/<mod>/parameters/<param> —— 测 O_WRONLY
 *   D. 精选 /sys 路径 —— 测 O_WRONLY
 *
 * 安全边界：跳过会因 open 本身产生副作用的节点（watchdog 会因 close 触发复位、
 * console/tty 会抢占控制台、mem/kmem 等）。O_NONBLOCK 用于避免阻塞式 open。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <glob.h>

static int n_rd = 0, n_wr = 0, n_dev = 0, n_sys = 0;

/* 绝不 open 的节点：open 本身即有副作用 */
static int hard_skip(const char *n)
{
	static const char *bad[] = {
		"watchdog", "console", "ptmx", "mem", "kmem", "kmsg", "log",
		"cpu_dma_latency", "vcs", "port", "fb0", "graphics", "tty", NULL
	};
	int i;
	for (i = 0; bad[i]; i++)
		if (strncmp(n, bad[i], strlen(bad[i])) == 0)
			return 1;
	return 0;
}

/* 允许做写打开的子系统（白名单，都是有明确句柄语义、open 无副作用的） */
static int rw_allow(const char *n)
{
	static const char *ok[] = {
		"kgsl", "ion", "dma_heap", "adsprpc", "ashmem", "binder",
		"qseecom", "qcedev", "qcrypto", "spcom", "glink", "hwrng",
		"genlock", "sync", "msm_", "video", "sde", "subsys", NULL
	};
	int i;
	for (i = 0; ok[i]; i++)
		if (strstr(n, ok[i]))
			return 1;
	return 0;
}

static int try_open(const char *path, int flags)
{
	int fd = open(path, flags | O_NONBLOCK | O_CLOEXEC);
	if (fd >= 0) { close(fd); return 1; }
	return 0;
}

static void scan_dev(void)
{
	DIR *d = opendir("/dev");
	struct dirent *e;
	char p[512];

	if (!d) { printf("[A] /dev 不可读\n"); return; }
	printf("[A] /dev 扫描（白名单子系统额外测写）\n");
	while ((e = readdir(d)) != NULL) {
		struct stat st;
		int r, w = 0, rw = 0;
		char line[600];

		if (e->d_name[0] == '.') continue;
		snprintf(p, sizeof(p), "/dev/%s", e->d_name);
		if (stat(p, &st) != 0) continue;
		if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) continue;
		if (hard_skip(e->d_name)) continue;
		n_dev++;

		r = try_open(p, O_RDONLY);
		if (rw_allow(e->d_name)) {
			w  = try_open(p, O_WRONLY);
			rw = try_open(p, O_RDWR);
		}
		if (!r && !w && !rw) continue;
		if (r) n_rd++;
		if (w || rw) { n_wr++; }
		snprintf(line, sizeof(line), "  %-28s %c%c%c  %04o", e->d_name,
			 r ? 'r' : '-', w ? 'w' : '-', rw ? 'R' : '-',
			 (unsigned)(st.st_mode & 07777));
		printf("%s\n", line);
	}
	closedir(d);
}

static void walk_proc_sys(const char *dir, int depth)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char p[512];

	if (!d || depth > 3) { if (d) closedir(d); return; }
	while ((e = readdir(d)) != NULL) {
		struct stat st;
		if (e->d_name[0] == '.') continue;
		snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
		if (lstat(p, &st) != 0) continue;
		if (S_ISDIR(st.st_mode)) {
			walk_proc_sys(p, depth + 1);
		} else if (S_ISREG(st.st_mode)) {
			n_sys++;
			if (try_open(p, O_WRONLY))
				printf("  WRITABLE %s\n", p);
		}
	}
	closedir(d);
}

static void scan_glob(const char *pat, const char *tag)
{
	glob_t g;
	size_t i;
	printf("%s\n", tag);
	if (glob(pat, 0, NULL, &g) != 0) { printf("  (无匹配)\n"); return; }
	for (i = 0; i < g.gl_pathc; i++) {
		n_sys++;
		if (try_open(g.gl_pathv[i], O_WRONLY))
			printf("  WRITABLE %s\n", g.gl_pathv[i]);
	}
	globfree(&g);
}

static void scan_list(const char **paths, const char *tag)
{
	int i;
	printf("%s\n", tag);
	for (i = 0; paths[i]; i++) {
		n_sys++;
		if (try_open(paths[i], O_WRONLY))
			printf("  WRITABLE %s\n", paths[i]);
	}
}

int main(void)
{
	static const char *syslist[] = {
		"/sys/kernel/tracing/current_tracer",
		"/sys/kernel/tracing/trace",
		"/sys/kernel/tracing/events/enable",
		"/proc/sys/kernel/kptr_restrict",
		"/proc/sys/kernel/dmesg_restrict",
		"/proc/sys/kernel/perf_event_paranoid",
		"/proc/sys/vm/drop_caches",
		"/sys/class/kgsl/kgsl-3d0/force_clk_on",
		"/sys/class/kgsl/kgsl-3d0/force_bus_on",
		"/sys/class/kgsl/kgsl-3d0/force_rail_on",
		"/sys/class/kgsl/kgsl-3d0/force_pwrscale",
		"/sys/class/kgsl/kgsl-3d0/gpuclk",
		"/sys/module/msm_performance/parameters/",
		"/sys/power/state",
		"/sys/power/wake_lock",
		"/proc/sysrq-trigger",
		NULL
	};

	printf("===== SURFACE-PROBE uid=%d =====\n", getuid());

	scan_dev();

	printf("\n[B] /proc/sys 递归（深度<=3）：仅列出可写项\n");
	walk_proc_sys("/proc/sys", 0);

	printf("\n");
	scan_glob("/sys/module/*/parameters/*", "[C] /sys/module/*/parameters/*：仅列出可写项");
	printf("\n");
	scan_list(syslist, "[D] 精选 /sys 与高危 /proc 节点");

	printf("\n---- 汇总 ----\n");
	printf("  /dev 设备节点（跳过危险项后）: %d，只读可开: %d，白名单内可写: %d\n",
	       n_dev, n_rd, n_wr);
	printf("  检查的 sysfs/procfs 项: %d\n", n_sys);
	printf("===== done（全程只 open，未 write 任何字节） =====\n");
	return 0;
}
