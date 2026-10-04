// SPDX-License-Identifier: GPL-2.0-only
/* Real last-reference callback; scheduler/resource-release boundaries modeled. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define pr_info(...) do { } while (0)
#define pr_err(...) do { } while (0)
#define MK_STATE_READY 1
struct kref { int unused; };
struct work_struct { void (*func)(struct work_struct *); };
struct mk_instance {
	struct kref refcount;
	struct work_struct release_work;
	void *host_tree, *cpus, *name;
	int state;
	void *kimage;
};
static unsigned int released, atomic_releases;
static bool atomic_context, mk_overlay_mutex;
static struct work_struct *queued;
#define mutex_lock(m) do { assert(!*(m)); *(m) = true; } while (0)
#define mutex_unlock(m) do { assert(*(m)); *(m) = false; } while (0)

static void release_resource(void *p)
{
	(void)p;
	released++;
	atomic_releases += atomic_context;
}
#define mk_instance_return_all_cpus(p) release_resource(p)
#define mk_instance_return_pci_devices(p) release_resource(p)
#define mk_instance_return_platform_devices(p) release_resource(p)
#define mk_instance_free_memory(p) release_resource(p)
#define mk_instance_free_boot_pages(p) release_resource(p)
#define mk_instance_track_dump(...) do { } while (0)
#define mk_cpu_set_free(p) release_resource(p)
#define kfree(p) release_resource(p)
#define schedule_work(p) do { assert(!queued); queued = (p); } while (0)
#define INIT_WORK(p, f) ((p)->func = (f))
#define synchronize_rcu() assert(!atomic_context && !mk_overlay_mutex)
static int mk_instance_prepare_destroy(struct mk_instance *p)
{
	release_resource(p);
	return 0;
}
static void mk_instance_retire_resources(struct mk_instance *p)
{
	mk_instance_return_pci_devices(p);
	mk_instance_return_platform_devices(p);
	mk_instance_free_memory(p);
}
#include "release-production.h"

int main(void)
{
	struct mk_instance instance = { .state = MK_STATE_READY };

	atomic_context = true;
	mk_instance_release(&instance.refcount);
	atomic_context = false;
	if (atomic_releases || released) {
		fprintf(stderr, "FAIL: last IPI reference reclaimed resources in atomic context\n");
		return 1;
	}
	assert(queued == &instance.release_work);
	queued->func(queued);
	assert(released == 9 && !mk_overlay_mutex);
	puts("Instance release: final IPI reference defers reclamation, PASS");
	return 0;
}
