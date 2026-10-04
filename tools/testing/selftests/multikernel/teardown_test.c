// SPDX-License-Identifier: GPL-2.0-only
/* Real destruction; firmware, kernfs drain and resource retirement injected. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <linux/list.h>

#define MK_STATE_READY 1
#define MK_STATE_LOADED 2
#define MK_STATE_ACTIVE 3
#define MK_STATE_FAILED 4
#define pr_err(...) do { } while (0)
struct kernfs_node { int unused; };
struct mk_instance {
	int id, state;
	const char *name;
	struct kernfs_node *kn;
	void *kimage;
	struct list_head list;
};
static bool mk_instance_mutex, mk_overlay_mutex = true;
static int mk_instance_idr;
static unsigned int ref_drops, retired, removed, locked_drains, checks, failures;
static int prepare_error;
#define lockdep_assert_held(m) assert(*(m))
#define mutex_lock(m) do { assert(!*(m)); *(m) = true; } while (0)
#define mutex_unlock(m) do { assert(*(m)); *(m) = false; } while (0)
#define idr_remove(p, id) ((void)(p), (void)(id), removed++)
#define mk_instance_idr_remove(id) idr_remove(&mk_instance_idr, id)
static void mk_instance_put(struct mk_instance *p) { ref_drops++; }
static void kernfs_remove(struct kernfs_node *kn)
{
	locked_drains += mk_instance_mutex;
}
static __attribute__((unused)) int mk_instance_prepare_destroy(struct mk_instance *p)
{
	assert(mk_overlay_mutex && !mk_instance_mutex);
	return prepare_error;
}
static __attribute__((unused)) void mk_instance_retire_resources(struct mk_instance *p)
{
	assert(mk_overlay_mutex && !mk_instance_mutex);
	retired++;
}
#include "destroy-production.h"

static void expect(const char *name, int got, int want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: %d != %d\n", name, got, want);
		failures++;
	}
}

static int destroy(struct mk_instance *p)
{
	/* The original API required the caller's registry lock. */
	int ret;

	mk_instance_mutex = true;
	ret = mk_instance_destroy(p);
	mk_instance_mutex = false;
	return ret;
}

int main(void)
{
	struct kernfs_node kn;
	struct mk_instance p = { .id = 7, .state = MK_STATE_ACTIVE, .name = "spawn", .kn = &kn };
	LIST_HEAD(instances);

	INIT_LIST_HEAD(&p.list);
	list_add(&p.list, &instances);
	expect("active destruction refused", destroy(&p), -EBUSY);
	p.state = MK_STATE_FAILED;
	expect("uncertain failure destruction refused", destroy(&p), -EBUSY);
	expect("uncertain record retained", removed, 0);
	if (removed) {
		INIT_LIST_HEAD(&instances);
		INIT_LIST_HEAD(&p.list);
		list_add(&p.list, &instances);
		p.kn = &kn;
		removed = ref_drops = 0;
	}
	p.state = MK_STATE_READY;
	prepare_error = -EBUSY;
	expect("failed stop/repark proof refuses destruction", destroy(&p), -EBUSY);
	expect("failed stop retains registry membership", removed, 0);
	expect("failed stop retains resources", retired, 0);
	expect("failed stop retains references", ref_drops, 0);
	if (removed) {
		INIT_LIST_HEAD(&instances);
		INIT_LIST_HEAD(&p.list);
		list_add(&p.list, &instances);
		p.kn = &kn;
		removed = ref_drops = 0;
	}
	prepare_error = 0;
	expect("confirmed destruction", destroy(&p), 0);
	expect("record unregistered once", removed, 1);
	expect("registry and kernfs references released", ref_drops, 2);
	expect("kernfs drains outside registry lock", locked_drains, 0);
	expect("resources reusable before overlay returns", retired, 1);
	printf("Teardown: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
