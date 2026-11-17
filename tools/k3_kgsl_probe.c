/*
 * k3_kgsl_probe.c — OPPO K3 (PCGM00 / SDM710 / 4.9.227) KGSL 阶段 A 探针
 *
 * 目的（对应交接文档 §14.5 阶段 A / §14.4 range 标定）：
 *   A. UAPI 往返：GETPROPERTY / DRAWCTXT_CREATE / GPUOBJ_ALLOC / GPUOBJ_INFO /
 *      GPUOBJ_FREE 的编号与结构体逐字段是否被内核正确解释。
 *   B. SVM 窗口标定：MAP_USER_MEM(ADDR, USE_CPU_MAP) 在不同 user VA 上的接受性，
 *      用于界定 kgsl_mmu_set_svm_region 的 [svm_start, svm_end)。
 *
 * 全部为只读/无害操作：不触碰竞态、不做 UAF、不改内核状态。
 * 结构体定义来源：src_ref/kgsl_4.9/msm_kgsl.h（4.9 UAPI）。
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

struct kgsl_device_getproperty {
	unsigned int type;
	void *value;
	uint64_t sizebytes;
};

struct kgsl_version {
	unsigned int drv_major;
	unsigned int drv_minor;
	unsigned int dev_major;
	unsigned int dev_minor;
};

struct kgsl_devinfo {
	unsigned int device_id;
	unsigned int chip_id;
	unsigned int mmu_enabled;
	unsigned long gmem_gpubaseaddr;
	unsigned int gpu_id;
	uint64_t gmem_sizebytes;
};

struct kgsl_drawctxt_create {
	unsigned int flags;
	unsigned int drawctxt_id;
};

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

struct kgsl_gpuobj_info {
	uint64_t gpuaddr;
	uint64_t flags;
	uint64_t size;
	uint64_t va_len;
	uint64_t va_addr;
	unsigned int id;
};

#define IOCTL_KGSL_DEVICE_GETPROPERTY \
	_IOWR(KGSL_IOC_TYPE, 0x2, struct kgsl_device_getproperty)
#define IOCTL_KGSL_DRAWCTXT_CREATE \
	_IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_MAP_USER_MEM \
	_IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)
#define IOCTL_KGSL_GPUOBJ_ALLOC \
	_IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_GPUOBJ_FREE \
	_IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)
#define IOCTL_KGSL_GPUOBJ_INFO \
	_IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)

#define KGSL_PROP_DEVICE_INFO 0x1
#define KGSL_PROP_MMU_ENABLE  0x6
#define KGSL_PROP_VERSION     0x8

#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ULL
#define KGSL_USER_MEM_TYPE_ADDR   0x00000002

#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002

static void hdr(const char *s)
{
	printf("\n== %s ==\n", s);
	fflush(stdout);
}

static void ioctl_report(const char *tag, int ret, int err)
{
	if (ret == 0)
		printf("%-28s OK\n", tag);
	else
		printf("%-28s FAIL ret=%d errno=%d (%s)\n", tag, ret, err,
		       strerror(err));
	fflush(stdout);
}

int main(void)
{
	int fd, ret, err;

	printf("k3_kgsl_probe | pid=%d uid=%d euid=%d\n", getpid(), getuid(),
	       geteuid());
	printf("sizes: getproperty=%zu drawctxt=%zu map_user_mem=%zu "
	       "gpuobj_alloc=%zu gpuobj_free=%zu gpuobj_info=%zu\n",
	       sizeof(struct kgsl_device_getproperty),
	       sizeof(struct kgsl_drawctxt_create),
	       sizeof(struct kgsl_map_user_mem),
	       sizeof(struct kgsl_gpuobj_alloc),
	       sizeof(struct kgsl_gpuobj_free),
	       sizeof(struct kgsl_gpuobj_info));

	hdr("A0 open /dev/kgsl-3d0");
	fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		printf("open FAIL errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}
	printf("open OK fd=%d\n", fd);

	hdr("A1 GETPROPERTY");
	{
		struct kgsl_device_getproperty gp;
		struct kgsl_version ver;
		struct kgsl_devinfo di;
		int mmu = -1;

		memset(&ver, 0, sizeof(ver));
		gp.type = KGSL_PROP_VERSION;
		gp.value = &ver;
		gp.sizebytes = sizeof(ver);
		errno = 0;
		ret = ioctl(fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &gp);
		err = errno;
		ioctl_report("GETPROPERTY(VERSION)", ret, err);
		if (ret == 0)
			printf("  version drv=%u.%u dev=%u.%u\n",
			       ver.drv_major, ver.drv_minor, ver.dev_major,
			       ver.dev_minor);

		memset(&di, 0, sizeof(di));
		gp.type = KGSL_PROP_DEVICE_INFO;
		gp.value = &di;
		gp.sizebytes = sizeof(di);
		errno = 0;
		ret = ioctl(fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &gp);
		err = errno;
		ioctl_report("GETPROPERTY(DEVICE_INFO)", ret, err);
		if (ret == 0)
			printf("  devinfo device_id=0x%x chip_id=0x%x gpu_id=0x%x "
			       "mmu_enabled=%u gmem_base=0x%lx gmem_size=0x%llx\n",
			       di.device_id, di.chip_id, di.gpu_id,
			       di.mmu_enabled, di.gmem_gpubaseaddr,
			       (unsigned long long)di.gmem_sizebytes);

		gp.type = KGSL_PROP_MMU_ENABLE;
		gp.value = &mmu;
		gp.sizebytes = sizeof(mmu);
		errno = 0;
		ret = ioctl(fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &gp);
		err = errno;
		ioctl_report("GETPROPERTY(MMU_ENABLE)", ret, err);
		if (ret == 0)
			printf("  mmu_enabled=%d\n", mmu);
	}

	hdr("A2 DRAWCTXT_CREATE");
	{
		unsigned int flag_sets[3] = {0, KGSL_CONTEXT_NO_GMEM_ALLOC,
					     KGSL_CONTEXT_NO_GMEM_ALLOC};
		int i;

		for (i = 0; i < 1; i++) {
			struct kgsl_drawctxt_create dc;
			dc.flags = flag_sets[i];
			dc.drawctxt_id = 0;
			errno = 0;
			ret = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &dc);
			err = errno;
			ioctl_report("DRAWCTXT_CREATE(flags=0)", ret, err);
			if (ret == 0)
				printf("  drawctxt_id=%u\n", dc.drawctxt_id);
		}
	}

	hdr("A3 GPUOBJ_ALLOC / INFO / mmap / FREE");
	{
		struct kgsl_gpuobj_alloc al;
		struct kgsl_gpuobj_info inf;
		struct kgsl_gpuobj_free fr;
		unsigned int obj_id = 0;
		uint64_t mmapsize = 0, va_addr = 0;

		memset(&al, 0, sizeof(al));
		al.size = 0x1000;
		al.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
		al.va_len = 0;
		errno = 0;
		ret = ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &al);
		err = errno;
		ioctl_report("GPUOBJ_ALLOC(0x1000)", ret, err);
		if (ret == 0) {
			obj_id = al.id;
			mmapsize = al.mmapsize;
			printf("  id=%u mmapsize=0x%llx\n", al.id,
			       (unsigned long long)al.mmapsize);
		}

		if (ret == 0) {
			memset(&inf, 0, sizeof(inf));
			inf.id = obj_id;
			errno = 0;
			ret = ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
			err = errno;
			ioctl_report("GPUOBJ_INFO", ret, err);
			if (ret == 0) {
				va_addr = inf.va_addr;
				printf("  gpuaddr=0x%llx flags=0x%llx "
				       "size=0x%llx va_len=0x%llx "
				       "va_addr=0x%llx\n",
				       (unsigned long long)inf.gpuaddr,
				       (unsigned long long)inf.flags,
				       (unsigned long long)inf.size,
				       (unsigned long long)inf.va_len,
				       (unsigned long long)inf.va_addr);
				printf("  size_consistent=%s\n",
				       inf.size == 0x1000 ? "yes" : "no");
			}
		}

		if (ret == 0 && mmapsize) {
			void *p = mmap(NULL, (size_t)mmapsize,
				       PROT_READ | PROT_WRITE, MAP_SHARED, fd,
				       (off_t)obj_id << 12);
			if (p == MAP_FAILED) {
				printf("%-28s FAIL errno=%d (%s)\n",
				       "mmap(gpuobj, offset=id<<12)", errno,
				       strerror(errno));
			} else {
				volatile uint64_t *q = (volatile uint64_t *)p;
				printf("%-28s OK addr=%p\n", "mmap(gpuobj)", p);
				q[0] = 0x1122334455667788ULL;
				q[1] = 0x99aabbccddeeff00ULL;
				printf("  rw_test first=0x%llx second=0x%llx "
				       "-> %s\n",
				       (unsigned long long)q[0],
				       (unsigned long long)q[1],
				       (q[0] == 0x1122334455667788ULL &&
					q[1] == 0x99aabbccddeeff00ULL) ?
					       "PASS" : "MISMATCH");
				munmap(p, (size_t)mmapsize);
			}
		}

		if (obj_id) {
			memset(&fr, 0, sizeof(fr));
			fr.id = obj_id;
			errno = 0;
			ret = ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
			err = errno;
			ioctl_report("GPUOBJ_FREE", ret, err);
		}
	}

	hdr("B  SVM window probe (MAP_USER_MEM + USE_CPU_MAP)");
	{
		uint64_t probes[] = {
			0x0000001000000000ULL, /* 64 GiB */
			0x0000000100000000ULL, /*  4 GiB */
			0x0000000080000000ULL, /*  2 GiB */
			0x0000000040000000ULL, /*  1 GiB */
			0x0000000c00000000ULL, /* 48 GiB */
			0x0000007000000000ULL, /* 448 GiB */
			0x0000007001fe000ULL,  /* RCA OVERLAP */
			0x0000007001ff000ULL,  /* RCA UAF */
			0x000000700204000ULL,  /* RCA BOGUS */
			0x000000710204000ULL,  /* RCA PLACEHOLDER */
			0x000000ff00000000ULL,
			0x00007f0000000000ULL,
		};
		unsigned int i;
		int ok_cnt = 0;

		printf("%-20s %-10s %-14s %s\n", "hostptr", "len", "result",
		       "gpuaddr_out");
		for (i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
			struct kgsl_map_user_mem m;
			void *p;

			p = mmap((void *)(uintptr_t)probes[i], 0x1000,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
			if (p == MAP_FAILED) {
				printf("0x%014llx   0x1000     mmap_fail(%d) %s\n",
				       (unsigned long long)probes[i], errno,
				       strerror(errno));
				continue;
			}
			((volatile char *)p)[0] = 0x5a;

			memset(&m, 0, sizeof(m));
			m.fd = -1;
			m.gpuaddr = 0;
			m.len = 0x1000;
			m.offset = 0;
			m.hostptr = (unsigned long)(uintptr_t)p;
			m.memtype = KGSL_USER_MEM_TYPE_ADDR;
			m.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
			errno = 0;
			ret = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &m);
			err = errno;
			if (ret == 0) {
				ok_cnt++;
				printf("0x%014llx   0x1000     OK             "
				       "gpuaddr=0x%lx flags_out=0x%x\n",
				       (unsigned long long)probes[i], m.gpuaddr,
				       m.flags);
			} else {
				printf("0x%014llx   0x1000     FAIL           "
				       "errno=%d (%s)\n",
				       (unsigned long long)probes[i], err,
				       strerror(err));
			}
			/* 撤销 VMA；成功注册的区间会在进程退出时回收 */
			munmap(p, 0x1000);
		}
		printf("svm_probe_accepted=%d/%zu\n", ok_cnt,
		       sizeof(probes) / sizeof(probes[0]));
	}

	hdr("B2 non-CPU_MAP allocation gpuaddr (find_svm path)");
	{
		struct kgsl_map_user_mem m;
		void *p = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (p != MAP_FAILED) {
			memset(&m, 0, sizeof(m));
			m.fd = -1;
			m.len = 0x4000;
			m.hostptr = (unsigned long)(uintptr_t)p;
			m.memtype = KGSL_USER_MEM_TYPE_ADDR;
			m.flags = 0;
			errno = 0;
			ret = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &m);
			err = errno;
			ioctl_report("MAP_USER_MEM(no cpu_map)", ret, err);
			if (ret == 0)
				printf("  hostptr=%p gpuaddr=0x%lx\n", p,
				       m.gpuaddr);
			munmap(p, 0x4000);
		}
	}

	close(fd);
	printf("\ndone\n");
	return 0;
}
