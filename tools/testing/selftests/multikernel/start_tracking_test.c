// SPDX-License-Identifier: GPL-2.0-only
/* Actual spawn/release, generic confirmation and CPU-set code. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define u64 unsigned long long
#include "types.h"
static bool allocation_fails;
#define GFP_KERNEL 0
#define kzalloc(n, flags) ((void)(flags), allocation_fails ? NULL : calloc(1, n))
#define kfree free
#define krealloc_array(p, n, size, flags) \
	((void)(flags), allocation_fails ? NULL : realloc(p, (n) * (size)))
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (a) : (b))
#define scnprintf snprintf
#define pr_err(...) do { } while (0)
#define WRITE_ONCE(x, value) ((x) = (value))
/* Firmware boundaries are deterministic here, not a memory-ordering proof. */
#define smp_mb() do { } while (0)
#define INVALID_HARTID (~0UL)
#define arch_cpu_physical_id(cpu) ((cpu) == 2 ? 65537UL : INVALID_HARTID)
#include "cpuset.h"
struct mk_riscv_spawn_context { unsigned long image_entry; };
struct mk_instance {
	bool resource_uncertain;
	struct mk_cpu_set *cpus, *cpus_on_slot;
	struct {
		struct mk_riscv_spawn_context *ctx;
		unsigned long ctx_phys, stub_phys;
		void *stub;
	} arch;
};
struct kimage { unsigned long start; struct { unsigned long fdt_addr; } arch; };
static struct mk_instance target;
static int prime_result, start_result, primes, starts;
static unsigned long busy_hart;
static int poll_result, polls;

static int mk_ipi_poll(void)
{
	polls++;
	return poll_result;
}

static int mk_riscv_prime_icache(unsigned long hart)
{
	assert(mk_cpu_set_contains(target.cpus_on_slot, hart));
	primes++;
	return prime_result;
}
static int sbi_hsm_hart_start(unsigned long hart, unsigned long entry, unsigned long opaque)
{
	assert(hart == 65537 && entry == 0x80400000 && opaque == 0x80600000);
	assert(mk_cpu_set_contains(target.cpus_on_slot, 9));
	starts++;
	return start_result;
}
static int mk_riscv_hart_stopped(unsigned long hart)
{
	return hart == busy_hart ? -EBUSY : 0;
}
int mk_arch_confirm_parked(struct mk_instance *instance, mk_phys_cpu_t cpu);
#include "confirm.h"
#include "start.h"

int main(void)
{
	struct mk_riscv_spawn_context ctx;
	struct kimage image = { .start = 0x80200000, .arch.fdt_addr = 0x80600000 };

	target.cpus = mk_cpu_set_alloc();
	assert(target.cpus);
	assert(!mk_cpu_set_add(target.cpus, 65537));
	assert(!mk_cpu_set_add(target.cpus, 9));
	target.arch.ctx = &ctx;
	target.arch.stub_phys = 0x80400000;
	target.arch.stub = &ctx;
	assert(!mk_arch_spawn_instance(&image, &target, 2));
	assert(starts == 1 && primes == 2 && ctx.image_entry == image.start);
	busy_hart = 9;
	assert(mk_arch_release_instance(&target) == -EBUSY);
	assert(mk_repark_instance_to_host(&target) == -EBUSY);
	assert(mk_repark_cpu_to_host(&target, 9) == -EBUSY);
	assert(mk_cpu_set_contains(target.cpus_on_slot, 9));
	assert(target.arch.ctx && target.cpus_on_slot);
	busy_hart = 0;
	target.resource_uncertain = true;
	assert(mk_arch_release_instance(&target) == -EBUSY);
	assert(target.arch.ctx && target.cpus_on_slot && !polls);
	target.resource_uncertain = false;
	poll_result = -EBUSY;
	assert(mk_arch_release_instance(&target) == -EBUSY);
	assert(target.arch.ctx && target.cpus_on_slot && polls == 1);
	poll_result = 0;
	assert(!mk_arch_release_instance(&target));
	assert(!target.arch.ctx && !target.cpus_on_slot);
	target.arch.ctx = &ctx;
	target.arch.stub_phys = 0x80400000;
	target.arch.stub = &ctx;
	allocation_fails = true;
	assert(mk_arch_spawn_instance(&image, &target, 2) == -ENOMEM);
	assert(starts == 1 && primes == 2);
	allocation_fails = false;
	prime_result = -EPERM;
	assert(mk_arch_spawn_instance(&image, &target, 2) == -EPERM);
	assert(mk_cpu_set_count(target.cpus_on_slot) == 2 && starts == 1);
	prime_result = 0;
	start_result = -EINVAL;
	assert(mk_arch_spawn_instance(&image, &target, 2) == -EINVAL);
	assert(mk_cpu_set_count(target.cpus_on_slot) == 2);
	assert(!mk_repark_cpu_to_instance(&target, 100009));
	assert(mk_cpu_set_contains(target.cpus_on_slot, 100009));
	assert(!mk_repark_cpu_to_host(&target, 100009));
	assert(!mk_cpu_set_contains(target.cpus_on_slot, 100009));
	assert(!mk_arch_release_instance(&target));
	mk_cpu_set_free(target.cpus);
	puts("PASS: all-hart tracking precedes start; CPU, resource and inbox uncertainty retain tracking");
	return 0;
}
