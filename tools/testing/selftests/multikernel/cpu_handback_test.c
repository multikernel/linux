// SPDX-License-Identifier: GPL-2.0-only
/* Real CPUHP/MK entry points and CPU sets; no live CPU transition. */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef u64 phys_addr_t;
#include "handback-types.h"

#define GFP_KERNEL 0
#define NUMA_NO_NODE (-1)
#define KOBJ_ONLINE 1
#define WARN_ON_ONCE(condition) (!!(condition))
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_info(...) ((void)0)
#define per_cpu_ptr(ptr, cpu) (&(*(ptr))[cpu])
#define per_cpu(name, cpu) ((name)[cpu])
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))
/* Optional operation logging is deliberately not allocated in this fixture. */
#define kzalloc(size, flags) ((void)(size), (void)(flags), NULL)
#define krealloc_array(ptr, n, size, flags) \
	((void)(flags), fail_alloc ? NULL : realloc(ptr, (n) * (size)))

static bool fail_alloc;
#include "handback-set.h"

enum cpuhp_state {
	CPUHP_OFFLINE,
	CPUHP_DEPARTED,
	CPUHP_INTERMEDIATE,
	CPUHP_ONLINE
};

struct cpuhp_cpu_state {
	enum cpuhp_state state, target;
};

struct device {
	unsigned int id;
	bool offline, locked;
	int kobj;
};

struct cpu {
	struct device dev;
	bool hotpluggable;
};

struct list_head {
	struct list_head *next, *prev;
};

struct mk_instance {
	struct mk_cpu_set *cpus;
};

struct mk_pool {
	struct mk_cpu_set *cpus;
	bool cpus_lock;
};

static struct cpuhp_cpu_state cpuhp_state[4];
static struct cpu cpu_devices[4];
static const unsigned int nr_cpu_ids = 4;
static bool possible[4], present[4], online[4], registered[4];
static int nodes[4];
static bool device_hotplug_locked, maps_locked, write_locked;
static bool cpu_hotplug_disabled, bootable, partial_online, bad_success;
static bool initially_present;
static int mapped_cpu = 1;
static int native_error, node_error, registration_error;
static unsigned int native_calls, events, retargets, failures, scenarios;
static bool mk_overlay_mutex = true;
static int mk_hotplug_mutex;
static struct list_head mk_hotplug_ops;
static struct mk_cpu_set own_set, pool_set;
static struct mk_instance self = { .cpus = &own_set }, *mk_self = &self;
static struct mk_pool pool = { .cpus = &pool_set }, *mk_pool = &pool;
static const char *scenario;

static void check(bool condition, const char *why)
{
	if (!condition) {
		fprintf(stderr, "FAIL: %s: %s\n", scenario, why);
		failures++;
	}
}

#define lockdep_assert_held(lock) check(*(lock), "resource lock held")
static void mutex_lock(void *lock)
{
}

static void mutex_unlock(void *lock)
{
}

static bool *pool_lock(bool *lock)
{
	check(!*lock && !maps_locked,
	      "pool lock not nested with native bringup");
	*lock = true;
	return lock;
}

static void pool_unlock(bool **lock)
{
	check(**lock, "pool lock balanced");
	**lock = false;
}

#define guard(name) \
	bool *pool_guard_##name __attribute__((cleanup(pool_unlock))) = pool_lock

static bool cpu_possible(unsigned int cpu)
{
	return cpu < 4 && possible[cpu];
}

static bool cpu_present(unsigned int cpu)
{
	return cpu < 4 && present[cpu];
}

static bool cpu_online(unsigned int cpu)
{
	return cpu < 4 && online[cpu];
}

static int cpu_to_node(unsigned int cpu)
{
	return nodes[cpu];
}

static bool cpu_bootable(unsigned int cpu)
{
	return bootable;
}

static struct device *get_cpu_device(unsigned int cpu)
{
	return cpu < 4 && registered[cpu] ? &cpu_devices[cpu].dev : NULL;
}

static void lock_device_hotplug(void)
{
	check(!device_hotplug_locked && !maps_locked,
	      "device-hotplug lock order");
	device_hotplug_locked = true;
}

static void unlock_device_hotplug(void)
{
	check(device_hotplug_locked && !maps_locked,
	      "device-hotplug lock balance");
	device_hotplug_locked = false;
}

static void device_lock(struct device *dev)
{
	check(device_hotplug_locked && !dev->locked && !maps_locked,
	      "device lock order");
	dev->locked = true;
}

static void device_unlock(struct device *dev)
{
	check(dev->locked && !maps_locked, "device lock balance");
	dev->locked = false;
}

static void cpu_maps_update_begin(void)
{
	check(device_hotplug_locked && !maps_locked, "maps lock order");
	maps_locked = true;
}

static void cpu_maps_update_done(void)
{
	check(maps_locked && !write_locked, "maps lock balance");
	if (native_error && !online[1])
		check(present[1] == initially_present,
		      "failed handback restores original presence before unlock");
	maps_locked = false;
}

static void cpus_write_lock(void)
{
	check(maps_locked && !write_locked, "CPU write lock order");
	write_locked = true;
}

static void cpus_write_unlock(void)
{
	check(write_locked, "write lock balance");
	write_locked = false;
}

static void set_cpu_present(unsigned int cpu, bool value)
{
	check(device_hotplug_locked && maps_locked && write_locked,
	      "presence changed within native transaction");
	present[cpu] = value;
}

static int try_online_node(int node)
{
	return node_error;
}

static void cpu_device_update_node(struct device *dev, int from)
{
	check(device_hotplug_locked && dev->locked,
	      "NUMA bookkeeping serialized");
}

static int kobject_uevent(int *kobj, int action)
{
	check(device_hotplug_locked && maps_locked,
	      "online event within transaction");
	events++;
	return 0;
}

static int _cpu_up(unsigned int cpu, int frozen, enum cpuhp_state target)
{
	check(maps_locked && !write_locked && present[cpu],
	      "native bringup preconditions");
	check(!pool.cpus_lock && cpu_devices[cpu].dev.locked,
	      "native bringup holds device lock, not pool lock");
	check(mk_cpu_set_contains(own_set.nr ? &own_set : NULL, 101),
	      "local ownership reserved before bringup");
	check(mk_cpu_set_contains(&pool_set, 101),
	      "wake-slot membership preserved during bringup");
	native_calls++;
	if (native_error) {
		online[cpu] = partial_online;
		return native_error;
	}
	if (!bad_success) {
		online[cpu] = true;
		cpuhp_state[cpu].state = target;
		cpuhp_state[cpu].target = target;
	}
	return 0;
}

/* Original add_cpu path, to check the old caller without a kernel boot. */
static int device_online(struct device *dev)
{
	int ret;

	if (!dev)
		return -ENODEV;
	device_lock(dev);
	if (!cpu_possible(dev->id) || nodes[dev->id] == NUMA_NO_NODE ||
	    node_error) {
		ret = node_error ? node_error : -ENODEV;
		goto out;
	}
	cpu_maps_update_begin();
	if (cpu_hotplug_disabled)
		ret = -EBUSY;
	else if (!bootable)
		ret = -EPERM;
	else
		ret = _cpu_up(dev->id, 0, CPUHP_ONLINE);
	cpu_maps_update_done();
	if (!ret) {
		dev->offline = false;
		events++;
	}
out:
	device_unlock(dev);
	return ret;
}

static void cpuhp_online_cpu_device(unsigned int cpu);
#include "handback-native.h"

static int register_cpu(struct cpu *c, int cpu)
{
	check(device_hotplug_locked && !present[cpu],
	      "registration while absent and serialized");
	if (registration_error)
		return registration_error;
	registered[cpu] = true;
	return 0;
}

static unsigned int next_present(unsigned int cpu)
{
	while (cpu < nr_cpu_ids && !present[cpu])
		cpu++;
	return cpu;
}

#define for_each_present_cpu(cpu)                                       \
	for ((cpu) = next_present(0); (unsigned int)(cpu) < nr_cpu_ids; \
	     (cpu) = next_present((cpu) + 1))
static u64 arch_cpu_physical_id(unsigned int cpu)
{
	return 100 + cpu;
}

static int arch_cpu_from_physical_id(u64 id)
{
	return id == 101 ? mapped_cpu : -1;
}

static void mk_instance_ipi_retarget(struct mk_instance *instance)
{
	retargets++;
}

static void list_add_tail(struct list_head *entry, struct list_head *head)
{
}

#include "handback-hotplug.h"

static void reset(const char *name)
{
	unsigned int cpu;

	scenario = name;
	scenarios++;
	check(!device_hotplug_locked && !maps_locked && !write_locked &&
	      !pool.cpus_lock,
	      "previous locks released");
	free(own_set.ids);
	free(pool_set.ids);
	memset(&own_set, 0, sizeof(own_set));
	memset(&pool_set, 0, sizeof(pool_set));
	fail_alloc = false;
	check(!mk_cpu_set_add(&pool_set, 101), "seed pool set");
	for (cpu = 0; cpu < 4; cpu++) {
		possible[cpu] = true;
		present[cpu] = false;
		online[cpu] = false;
		registered[cpu] = true;
		cpu_devices[cpu].dev =
			(struct device){ .id = cpu, .offline = true };
		cpuhp_state[cpu].state = CPUHP_DEPARTED;
		cpuhp_state[cpu].target = CPUHP_DEPARTED;
		nodes[cpu] = 0;
	}
	native_error = 0;
	node_error = 0;
	registration_error = 0;
	native_calls = 0;
	events = 0;
	retargets = 0;
	partial_online = false;
	bad_success = false;
	cpu_hotplug_disabled = false;
	bootable = true;
	initially_present = false;
	mapped_cpu = 1;
}

static void rejected(int expected)
{
	check(mk_do_cpu_add(101, 0, 0) == expected,
	      "preflight error propagated");
	check(!native_calls && !present[1] && !online[1],
	      "no bringup or presence exposure");
	check(!mk_cpu_set_contains(&own_set, 101) &&
	      mk_cpu_set_contains(&pool_set, 101),
	      "known preflight rejection preserves original ownership");
}

int main(void)
{
	reset("successful handback");
	check(!mk_do_cpu_add(101, 0, 0), "successful return");
	check(present[1] && online[1] && native_calls == 1, "CPU online once");
	check(mk_cpu_set_contains(&own_set, 101) && retargets == 1,
	      "owned and retargeted");
	check(!cpu_devices[1].dev.offline && events == 1,
	      "device online event");
	reset("ownership allocation fails");
	fail_alloc = true;
	rejected(-ENOMEM);
	reset("CPU device registration fails");
	registered[1] = false;
	registration_error = -ENOMEM;
	rejected(-ENOMEM);
	reset("native hotplug disabled");
	cpu_hotplug_disabled = true;
	rejected(-EBUSY);
	reset("SMT policy rejects CPU");
	bootable = false;
	rejected(-EPERM);
	reset("NUMA node online fails");
	node_error = -ENOMEM;
	rejected(-ENOMEM);
	reset("invalid absent CPU state");
	cpuhp_state[1].state = CPUHP_INTERMEDIATE;
	rejected(-EINVAL);
	reset("native bringup fails after attempt");
	native_error = -EIO;
	check(mk_do_cpu_add(101, 0, 0) == -EIO, "native failure returned");
	check(!present[1] && !online[1], "absent mask restored");
	check(mk_cpu_set_contains(&own_set, 101) &&
	      !mk_cpu_set_contains(&pool_set, 101),
	      "uncertain CPU retained, not assignable");
	check(!events && !retargets, "failure not advertised as online");
	reset("attempted EBUSY is not retried");
	native_error = -EBUSY;
	check(mk_do_cpu_add(101, 0, 0) == -EBUSY && native_calls == 1,
	      "one native attempt");
	check(!mk_cpu_set_contains(&pool_set, 101),
	      "attempted EBUSY not mistaken for preflight");
	reset("incomplete rollback remains locally owned");
	native_error = -EIO;
	partial_online = true;
	check(mk_do_cpu_add(101, 0, 0) == -EIO, "incomplete rollback error");
	check(present[1] && online[1], "online CPU never marked absent");
	check(mk_cpu_set_contains(&own_set, 101) &&
	      !mk_cpu_set_contains(&pool_set, 101),
	      "incomplete rollback not assigned elsewhere");
	reset("native false success");
	bad_success = true;
	check(mk_do_cpu_add(101, 0, 0) == -EIO, "offline success rejected");
	check(!present[1] && !mk_cpu_set_contains(&pool_set, 101),
	      "false success retains safely");
	reset("never locally started CPU");
	cpuhp_state[1].state = CPUHP_OFFLINE;
	check(!mk_do_cpu_add(101, 0, 0), "OFFLINE enumerated CPU can join");
	check(native_calls == 1 && present[1] && online[1],
	      "first local bringup completed");
	reset("impossible logical CPU");
	possible[1] = false;
	registered[1] = false;
	rejected(-ENODEV);
	check(!registered[1], "impossible CPU not registered");
	reset("logical CPU outside possible map");
	mapped_cpu = nr_cpu_ids;
	rejected(-ENODEV);
	reset("missing NUMA mapping");
	nodes[1] = NUMA_NO_NODE;
	rejected(-ENODEV);
	reset("register absent enumerated CPU");
	registered[1] = false;
	check(!mk_do_cpu_add(101, 0, 0) && registered[1],
	      "registered and brought up");
	check(native_calls == 1 && present[1] && events == 1,
	      "registration precedes online");
	reset("owned CPU rejected before attempt");
	check(!mk_cpu_set_add(&own_set, 101), "seed ownership");
	cpu_hotplug_disabled = true;
	check(mk_do_cpu_add(101, 0, 0) == -EBUSY && !native_calls,
	      "preflight failed");
	check(mk_cpu_set_contains(&own_set, 101),
	      "preexisting ownership preserved");
	reset("present CPU fails native bringup");
	initially_present = true;
	present[1] = true;
	cpuhp_state[1].state = CPUHP_OFFLINE;
	native_error = -EIO;
	check(mk_do_cpu_add(101, 0, 0) == -EIO && present[1],
	      "original presence preserved");
	check(mk_cpu_set_contains(&own_set, 101) &&
	      !mk_cpu_set_contains(&pool_set, 101),
	      "failed present CPU retained");
	reset("already online CPU");
	present[1] = true;
	online[1] = true;
	cpuhp_state[1].state = CPUHP_ONLINE;
	cpu_devices[1].dev.offline = false;
	check(!mk_do_cpu_add(101, 0, 0), "idempotent return");
	check(!native_calls && !events && retargets == 1,
	      "no duplicate online event or bringup");
	check(!device_hotplug_locked && !maps_locked && !write_locked,
	      "final locks released");
	free(own_set.ids);
	free(pool_set.ids);
	printf("CPU handback: %u scenarios, %u failures\n", scenarios,
	       failures);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
