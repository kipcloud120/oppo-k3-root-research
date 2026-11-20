/*
 * kgsl_life_probe.c — KGSL 非 sparse 对象生命周期判定型探针（v12-K3）
 *
 * 目的（承接 HANDOVER §62.7）：验证 §61.5 的不变量 I4（id 只在 detach_process
 * 撤销、释放后不可再命中）在本机真值，以及 gpuobj_free 四分支的参数门解析。
 *
 * 安全边界（硬约束，改代码前先读 HANDOVER §62.1 / §61.6 / HANDOVER_RESUME §5）：
 *   1. 不提交任何 GPU 命令、不 mmap、不执行 IB；
 *   2. 不构造非法用户指针做 EFAULT 型写探测；
 *   3. alloc 尺寸固定 1 页 (4096)、flags=0（普通系统内存对象）；
 *   4. 每阶段独立进程；外层前后校验 boot_id / uptime，任一异常立即停。
 *
 * 判定：
 *   stage=param : 对不存在的 id 跑四条 free 分支 —— 期望全 EINVAL(22)，
 *                 证明分支解析正确、找不到对象时无异常 deref（纯参数门，零副作用）。
 *   stage=life  : alloc(4096) → GPUOBJ_FREE(flags=0) → 再次 FREE 同 id。
 *                 第二次期望 EINVAL(22)：若返回 0，则 I4 被推翻（id 未撤销 →
 *                 double-free 候选），这是本探针要证伪的核心命题。
 *                 全程不 mmap、不提交 GPU 命令，对象释放走正常 destroy 链。
 *
 * 命令字来自本机 ioctl 分派表（HANDOVER §61.3），不依赖目标 libc 的 _IOWR 展开。
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define IOC_GPUOBJ_ALLOC      0xc0300945UL
#define IOC_GPUOBJ_FREE       0x40200946UL
#define IOC_GPUMEM_FREE_ID    0xc0080935UL

#define KGSL_GPUOBJ_FREE_ON_EVENT 1ULL
#define KGSL_GPU_EVENT_TIMESTAMP  1U
#define KGSL_GPU_EVENT_FENCE      2U

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

struct kgsl_gpumem_free_id {
	unsigned int id;
	unsigned int pad;
};

/* kgsl_gpu_event_timestamp / fence 的最小载荷（仅 param 阶段用非法 fd/ctx，
 * 走不到回调；这里仅保证 copy_from_user 的 len 够用，不触发事件注册）。 */
struct kgsl_gpu_event_timestamp {
	unsigned int context_id;
	unsigned int timestamp;
};
struct kgsl_gpu_event_fence {
	int fd;
};

static const uint32_t BAD_ID = 0xdeadbeefU;
static int errs = 0;

static void expect(const char *what, long ret, int want_errno)
{
	int e = errno;
	int got = (ret < 0) ? e : 0;
	int ok = (got == want_errno);
	if (!ok)
		errs++;
	printf("  %-38s = %-3ld errno=%-3d want=%-3d  %s\n",
	       what, ret, got, want_errno, ok ? "OK" : "**MISMATCH**");
}

static long free_obj(int fd, uint64_t flags, uint32_t id, uint32_t type,
		     uint32_t len, void *priv)
{
	struct kgsl_gpuobj_free p;
	memset(&p, 0, sizeof(p));
	p.flags = flags;
	p.priv  = (uint64_t)(uintptr_t)priv;
	p.id    = id;
	p.type  = type;
	p.len   = len;
	return ioctl(fd, IOC_GPUOBJ_FREE, &p);
}

static int stage_param(int fd)
{
	struct kgsl_gpumem_free_id fid;
	struct kgsl_gpu_event_timestamp ts;
	struct kgsl_gpu_event_fence fe;
	long r;

	printf("-- stage=param: 不存在 id 的四分支参数门（期望全 EINVAL）--\n");

	memset(&ts, 0, sizeof(ts));
	ts.context_id = BAD_ID;
	ts.timestamp = 0;

	memset(&fe, 0, sizeof(fe));
	fe.fd = -1;

	/* flags=0 → 立即释放分支 → gpumem_free_entry → find_id_flags 失败 */
	r = free_obj(fd, 0, BAD_ID, 0, 0, NULL);
	expect("FREE flags=0 bad_id", r, EINVAL);

	/* flags=1,type=1(TIMESTAMP) → 先 copy_from_user(event) 再 ctx 查 → EINVAL */
	r = free_obj(fd, KGSL_GPUOBJ_FREE_ON_EVENT, BAD_ID,
		     KGSL_GPU_EVENT_TIMESTAMP, sizeof(ts), &ts);
	expect("FREE on_timestamp bad_id", r, EINVAL);

	/* flags=1,type=2(FENCE) → set_pend 后 copy fd → fd<0 → EINVAL 且 unwind pend */
	r = free_obj(fd, KGSL_GPUOBJ_FREE_ON_EVENT, BAD_ID,
		     KGSL_GPU_EVENT_FENCE, sizeof(fe), &fe);
	expect("FREE on_fence bad_id fd=-1", r, EINVAL);

	/* flags=1,type=3(非法) → default → EINVAL */
	r = free_obj(fd, KGSL_GPUOBJ_FREE_ON_EVENT, BAD_ID, 3, 0, NULL);
	expect("FREE bad_type=3", r, EINVAL);

	/* gpumem_free_id 不存在 id → EINVAL */
	memset(&fid, 0, sizeof(fid));
	fid.id = BAD_ID;
	r = ioctl(fd, IOC_GPUMEM_FREE_ID, &fid);
	expect("GPUMEM_FREE_ID bad_id", r, EINVAL);

	return errs;
}

static int stage_life(int fd)
{
	struct kgsl_gpuobj_alloc a;
	struct kgsl_gpumem_free_id fid;
	long r;
	uint32_t id;

	printf("-- stage=life: alloc → free → 再 free（验证 I4 id 撤销）--\n");

	memset(&a, 0, sizeof(a));
	a.size = 4096;
	a.flags = 0;
	a.va_len = 0;
	r = ioctl(fd, IOC_GPUOBJ_ALLOC, &a);
	if (r < 0) {
		printf("  GPUOBJ_ALLOC failed: errno=%d (%s) — 阶段跳过\n",
		       errno, strerror(errno));
		return 0; /* 分配门不可达不算失败，判定另行记录 */
	}
	id = a.id;
	printf("  GPUOBJ_ALLOC = %ld  id=%u mmapsize=%llu\n",
	       r, id, (unsigned long long)a.mmapsize);
	if (id == 0) {
		printf("  **id=0 异常，跳过后续**\n");
		return 0;
	}

	/* 第一次释放：flags=0 立即释放 */
	r = free_obj(fd, 0, id, 0, 0, NULL);
	expect("FREE #1 (flags=0)", r, 0);

	/* 第二次释放同一个 id：I4 成立则 EINVAL；返回 0 即 double-free 候选 */
	r = free_obj(fd, 0, id, 0, 0, NULL);
	expect("FREE #2 same id (I4)", r, EINVAL);

	/* 交叉验证：GPUMEM_FREE_ID 同 id 也应 EINVAL（两条通用路径共享 idr） */
	memset(&fid, 0, sizeof(fid));
	fid.id = id;
	r = ioctl(fd, IOC_GPUMEM_FREE_ID, &fid);
	expect("GPUMEM_FREE_ID same id (I4)", r, EINVAL);

	return errs;
}

int main(int argc, char **argv)
{
	const char *stage = (argc > 1) ? argv[1] : "param";
	int fd;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("== kgsl_life_probe stage=%s ==\n", stage);

	fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		printf("  open /dev/kgsl-3d0 failed: %s\n", strerror(errno));
		return 10;
	}
	printf("  open = %d\n", fd);

	errs = 0;
	if (!strcmp(stage, "param"))
		errs = stage_param(fd);
	else if (!strcmp(stage, "life"))
		errs = stage_life(fd);
	else {
		printf("  unknown stage: %s\n", stage);
		close(fd);
		return 11;
	}

	close(fd); /* 进程退出，内核侧无残留对象（全部已 free 或从未创建） */
	printf("  done. mismatches=%d\n", errs);
	return errs ? 1 : 0;
}
