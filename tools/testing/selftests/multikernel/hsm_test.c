// SPDX-License-Identifier: GPL-2.0-only
/* Execute the real HSM wrappers and polling macro with a fake clock/firmware. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define u64 uint64_t
#define ktime_t uint64_t
#define USEC_PER_SEC 1000000L
#define SBI_EXT_HSM 0x48534d
#define ENOTSUPP 524 /* Kernel-internal errno, not libc EOPNOTSUPP. */
#define pr_err(...) \
	do {        \
	} while (0)
#define might_sleep_if(x) ((void)(x))
static inline void barrier(void)
{
	__asm__ __volatile__("" ::: "memory");
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define cpu_relax() \
	do {        \
	} while (0)
static uint64_t clock_us;
#define ktime_get() clock_us
#define ktime_add_us(t, us) ((t) + (us))
#define ktime_compare(a, b) ((a) > (b))

static void usleep_range(unsigned long min, unsigned long max)
{
	assert(min && min <= max);
	clock_us += max;
}

#include "sbi-under-test.h"
#include "poll-under-test.h"

struct sbiret {
	long error, value;
};

static long error, status;
static unsigned int reads, stopped_after;
static unsigned long last_hart, last_entry, last_opaque;
static bool fenced;

static void local_flush_icache_all(void)
{
	fenced = true;
}

static struct sbiret sbi_ecall(unsigned long ext, unsigned long fid,
			       unsigned long a0, unsigned long a1,
			       unsigned long a2, unsigned long a3,
			       unsigned long a4, unsigned long a5)
{
	/* These paths must never issue SRST or legacy shutdown. */
	assert(ext == 0x48534d && !a3 && !a4 && !a5);
	if (fid == SBI_EXT_HSM_HART_STATUS) {
		assert(a0 == 65537 && !a1 && !a2);
		reads++;
		return (struct sbiret){
			.error = error,
			.value = stopped_after && reads >= stopped_after ?
					 1 :
					 status,
		};
	}
	if (fid == SBI_EXT_HSM_HART_STOP)
		assert(fenced && !a0 && !a1 && !a2);
	else
		assert(fid == SBI_EXT_HSM_HART_START);
	last_hart = a0;
	last_entry = a1;
	last_opaque = a2;
	return (struct sbiret){ .error = error };
}

#include "hsm-under-test.h"
#include "stopped-under-test.h"

int main(void)
{
	const struct {
		long firmware;
		int linux_errno;
	} errors[] = {
		{ -1, -EIO },	   { -2, -524 },      { -3, -EINVAL },
		{ -4, -EPERM },	   { -5, -EFAULT },   { -6, -EALREADY },
		{ -7, -EALREADY }, { -8, -EALREADY },
	};

	for (unsigned int i = 0; i < ARRAY_SIZE(errors); i++) {
		error = errors[i].firmware;
		assert(sbi_hsm_hart_start(65537, 0x80400000, 0x80600000) ==
		       errors[i].linux_errno);
		assert(last_hart == 65537 && last_entry == 0x80400000 &&
		       last_opaque == 0x80600000);
	}
	error = 0;
	assert(!sbi_hsm_hart_stop());

	status = 3; /* STOP_PENDING */
	stopped_after = 4;
	assert(!mk_riscv_hart_stopped(65537));
	assert(reads == 4 && clock_us > 0);

	stopped_after = 0;
	reads = 0;
	clock_us = 0;
	assert(mk_riscv_hart_stopped(65537) == -EBUSY);
	assert(clock_us >= 1000000 && clock_us <= 1001000);
	assert(reads > 1 && reads < 1100);

	status = 4; /* SUSPENDED is not safe to reclaim. */
	assert(mk_riscv_hart_stopped(65537) == -EBUSY);
	error = -4;
	assert(mk_riscv_hart_stopped(65537) == -EPERM);
	error = 0;
	status = 1;
	assert(!mk_riscv_hart_stopped(65537));
	puts("PASS: HSM physical addresses, error mapping and bounded STOP_PENDING");
	return 0;
}
