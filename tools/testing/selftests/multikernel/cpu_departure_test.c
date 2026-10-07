// SPDX-License-Identifier: GPL-2.0-only
/* CPUHP entry-point contract checks, not a live race reproduction. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define CONFIG_CPU_HOTPLUG_STATE_CONTROL 1
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
enum cpuhp_state {
	CPUHP_INVALID = -1,
	CPUHP_OFFLINE,
	CPUHP_DEPARTED,
	CPUHP_INTERMEDIATE,
	CPUHP_ONLINE,
};

struct cpuhp_cpu_state {
	enum cpuhp_state state;
	enum cpuhp_state target;
};

struct cpuhp_step {
	const char *name;
	struct { void *single; } startup, teardown;
	bool cant_stop;
};

struct device { unsigned int id; };
struct device_attribute { int unused; };

static const unsigned int nr_cpu_ids = 4;
static struct cpuhp_cpu_state cpuhp_state[4];
static struct device devices[4];
static bool possible[4], present[4], online[4], registered[4];
static bool device_locked, maps_locked, write_locked;
static int down_error, down_calls, offline_calls, up_calls, failures;
static int departing_cpu = -1;
static bool bad_down_state;
static int cpuhp_state_mutex;
static const char *scenario;

static struct cpuhp_step steps[] = {
	[CPUHP_OFFLINE] = { .name = "offline" },
#include "departure-step.h"
	[CPUHP_INTERMEDIATE] = { .name = "intermediate" },
	[CPUHP_ONLINE] = { .name = "online" },
};

#define per_cpu_ptr(ptr, cpu) (&(*(ptr))[cpu])
#define WARN_ON_ONCE(condition) (!!(condition))
#define WARN_ON(condition) (!!(condition))

static void check(bool condition, const char *reason)
{
	if (!condition) {
		fprintf(stderr, "FAIL: %s: %s\n", scenario, reason);
		failures++;
	}
}

static bool cpu_possible(unsigned int cpu)
{
	return cpu < nr_cpu_ids && possible[cpu];
}

static bool cpu_present(unsigned int cpu)
{
	return cpu < nr_cpu_ids && present[cpu];
}

static bool cpu_online(unsigned int cpu)
{
	return cpu < nr_cpu_ids && online[cpu];
}

static struct device *get_cpu_device(unsigned int cpu)
{
	return cpu < nr_cpu_ids && registered[cpu] ? &devices[cpu] : NULL;
}

static void lock_device_hotplug(void)
{
	check(!device_locked && !maps_locked, "device lock order");
	device_locked = true;
}

static void unlock_device_hotplug(void)
{
	check(device_locked && !maps_locked && !write_locked,
	      "device lock released last");
	device_locked = false;
}

static void cpu_maps_update_begin(void)
{
	check(device_locked && !maps_locked, "maps lock order");
	maps_locked = true;
}

static void cpu_maps_update_done(void)
{
	check(maps_locked && !write_locked, "maps lock balance");
	if (departing_cpu >= 0)
		check(!present[departing_cpu],
		      "presence withdrawn before releasing native serialization");
	maps_locked = false;
}

static void cpus_write_lock(void)
{
	check(maps_locked && !write_locked, "CPU write lock order");
	write_locked = true;
}

static void cpus_write_unlock(void)
{
	check(write_locked, "CPU write lock balance");
	write_locked = false;
}

static void set_cpu_present(unsigned int cpu, bool value)
{
	check(device_locked && maps_locked && write_locked,
	      "presence change excluded from native transitions");
	present[cpu] = value;
}

static int cpu_down_maps_locked(unsigned int cpu, enum cpuhp_state target)
{
	check(device_locked && maps_locked && !write_locked,
	      "teardown called without recursive CPU write locking");
	down_calls++;
	if (cpu >= nr_cpu_ids)
		return -EINVAL;
	if (down_error)
		return down_error;
	if (!bad_down_state) {
		online[cpu] = false;
		cpuhp_state[cpu].state = target;
		cpuhp_state[cpu].target = target;
		if (target == CPUHP_DEPARTED)
			departing_cpu = cpu;
	}
	return 0;
}

static void cpuhp_offline_cpu_device(unsigned int cpu)
{
	check(device_locked && maps_locked, "device bookkeeping within transaction");
	check(!cpu_present(cpu) && !cpu_online(cpu),
	      "withdrawn and offline before bookkeeping");
	check(get_cpu_device(cpu), "registered device required");
	offline_calls++;
}

static int kstrtoint(const char *buf, int base, int *value)
{
	char *end;

	*value = strtol(buf, &end, base);
	return *end ? -EINVAL : 0;
}

static int lock_device_hotplug_sysfs(void)
{
	lock_device_hotplug();
	return 0;
}

static void mutex_lock(int *lock) { }
static void mutex_unlock(int *lock) { }
static struct cpuhp_step *cpuhp_get_step(int state) { return &steps[state]; }

static int cpu_up(unsigned int cpu, enum cpuhp_state target)
{
	up_calls++;
	return 0;
}

#include "departure-production.h"

typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef u64 phys_addr_t;
typedef u64 mk_phys_cpu_t;
struct list_head { struct list_head *next, *prev; };
static struct list_head mk_hotplug_ops;
static int mk_hotplug_mutex, account_calls;

#define pr_err(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define GFP_KERNEL 0
/* Operation-log allocation is optional, unlike ownership accounting. */
#define kzalloc(size, flags) ((void)(size), (void)(flags), NULL)
#define for_each_present_cpu(cpu) \
	for ((cpu) = next_present(0); (unsigned int)(cpu) < nr_cpu_ids; \
	     (cpu) = next_present((cpu) + 1))

static unsigned int next_present(unsigned int cpu)
{
	while (cpu < nr_cpu_ids && !cpu_present(cpu))
		cpu++;
	return cpu;
}

static mk_phys_cpu_t arch_cpu_physical_id(unsigned int cpu)
{
	return 100 + cpu;
}

static void list_add_tail(struct list_head *entry, struct list_head *head) { }

static void mk_account_cpu_offline(mk_phys_cpu_t id)
{
	unsigned int cpu = id - 100;

	check(!cpu_present(cpu) && !cpu_online(cpu),
	      "ownership changed only after departure and withdrawal");
	account_calls++;
}

#include "departure-hotplug.h"

static void reset(const char *name)
{
	unsigned int cpu;

	scenario = name;
	check(!device_locked && !maps_locked && !write_locked,
	      "previous operation released all locks");
	down_calls = 0;
	offline_calls = 0;
	up_calls = 0;
	down_error = 0;
	departing_cpu = -1;
	account_calls = 0;
	bad_down_state = false;
	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		devices[cpu].id = cpu;
		possible[cpu] = true;
		present[cpu] = true;
		online[cpu] = true;
		registered[cpu] = true;
		cpuhp_state[cpu].state = CPUHP_ONLINE;
		cpuhp_state[cpu].target = CPUHP_ONLINE;
	}
}

static void expect_rejected(unsigned int cpu, int error)
{
	check(depart_cpu(cpu) == error, "eligibility error returned");
	check(!down_calls && !offline_calls, "ineligible CPU not handed off");
	check(!device_locked && !maps_locked && !write_locked,
	      "rejection released locks");
}

int main(void)
{
	static const int errors[] = { -EBUSY, -EOPNOTSUPP, -EIO };
	size_t i;

	reset("successful departure");
	check(depart_cpu(1) == 0, "success returned");
	check(!present[1] && !online[1], "CPU no longer present or online");
	check(cpuhp_state[1].state == CPUHP_DEPARTED, "departed state reached");
	check(down_calls == 1 && offline_calls == 1, "one departure and notification");

	reset("ordinary offline CPU");
	online[1] = false;
	cpuhp_state[1].state = CPUHP_OFFLINE;
	expect_rejected(1, -EINVAL);
	reset("intermediate CPUHP state");
	cpuhp_state[1].state = CPUHP_INTERMEDIATE;
	expect_rejected(1, -EINVAL);
	reset("CPU zero");
	expect_rejected(0, -EINVAL);
	reset("out-of-range CPU");
	expect_rejected(nr_cpu_ids, -EINVAL);
	reset("impossible CPU");
	possible[1] = false;
	expect_rejected(1, -EINVAL);
	reset("absent CPU");
	present[1] = false;
	expect_rejected(1, -EINVAL);
	reset("missing device");
	registered[1] = false;
	expect_rejected(1, -ENODEV);

	for (i = 0; i < ARRAY_SIZE(errors); i++) {
		reset("native teardown failure");
		down_error = errors[i];
		check(depart_cpu(1) == errors[i], "native errno preserved");
		check(present[1] && online[1] && !offline_calls,
		      "failed teardown did not withdraw presence or notify");
	}

	reset("unconfirmed departure state");
	bad_down_state = true;
	check(depart_cpu(1) == -EIO, "bad postcondition rejected");
	check(present[1] && !offline_calls, "no withdrawal on bad postcondition");

	reset("native target excludes departed");
	check(target_store(&devices[1], NULL, "1", 1) == -EINVAL,
	      "native target cannot donate a CPU");
	check(!down_calls && !up_calls, "rejected target never starts transition");

	reset("native offline target unchanged");
	check(target_store(&devices[1], NULL, "0", 1) == 1,
	      "ordinary offline target accepted");
	check(down_calls == 1 && cpuhp_state[1].state == CPUHP_OFFLINE,
	      "ordinary target still takes native offline path");
	reset("native online target unchanged");
	online[1] = false;
	cpuhp_state[1].state = CPUHP_OFFLINE;
	check(target_store(&devices[1], NULL, "3", 1) == 1,
	      "ordinary online target accepted");
	check(up_calls == 1, "ordinary target still takes native online path");

	reset("multikernel remove success");
	check(mk_do_cpu_remove(101) == 0, "removal succeeded");
	check(account_calls == 1, "successful removal updates ownership once");
	reset("multikernel remove rejects offline CPU");
	online[1] = false;
	cpuhp_state[1].state = CPUHP_OFFLINE;
	check(mk_do_cpu_remove(101) == -EINVAL, "offline removal rejected");
	check(!account_calls && !down_calls && present[1],
	      "offline removal preserves ownership and presence");
	reset("multikernel remove native failure");
	down_error = -EBUSY;
	check(mk_do_cpu_remove(101) == -EBUSY, "removal error propagated");
	check(!account_calls && present[1], "failed removal preserves ownership");
	check(!device_locked && !maps_locked && !write_locked,
	      "final operation released locks");
	if (failures)
		return EXIT_FAILURE;
	puts("PASS: CPU departure and native target contract checks (18 scenarios)");
	return EXIT_SUCCESS;
}
