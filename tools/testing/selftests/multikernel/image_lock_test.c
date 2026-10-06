// SPDX-License-Identifier: GPL-2.0-only
/* Production image operations and overlay rollback, real host mutexes. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <linux/list.h>

#define u64 __u64
#define CONFIG_MULTIKERNEL 1
#define CONFIG_CRASH_DUMP 1
#define __user
#define kfree free
#define phys_to_virt(p) ((void *)(p))
#define WARN_ON_ONCE(x) (x)
#define pr_err(...) do { } while (0)
#define pr_warn(...) do { } while (0)
#define pr_info(...) do { } while (0)
#define pr_debug(...) do { } while (0)
#define kexec_dprintk(...) do { } while (0)
#define SYSCALL_DEFINE5(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) \
	static long name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5)

#include "image-types.h"

static atomic_uint checks, failures, resource_updates;
static _Thread_local unsigned int held;
static _Thread_local bool resource_thread;
static bool is_mk, permitted = true, allocation_fails;
static bool mapping_fails;
static unsigned int control_page_calls;
static unsigned int image_work_calls;
static const char *probe_at, *fail_at;
static bool probe_started, attempted, finished;
static pthread_t competitor;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static atomic_bool kexec_held;

static void expect(const char *name, int got, int want)
{
	atomic_fetch_add(&checks, 1);
	if (got != want) {
		fprintf(stderr, "FAIL %s: got %d, want %d\n", name, got, want);
		atomic_fetch_add(&failures, 1);
	}
}

enum { KEXEC_LOCK = 1, OVERLAY_LOCK = 2, REGISTRY_LOCK = 4 };
struct mutex { pthread_mutex_t native; unsigned int bit; };
static struct mutex mk_overlay_mutex = { PTHREAD_MUTEX_INITIALIZER, OVERLAY_LOCK };
static struct mutex mk_instance_mutex = { PTHREAD_MUTEX_INITIALIZER, REGISTRY_LOCK };
#define rcu_read_lock() do { assert(!(held & 8)); held |= 8; } while (0)
#define rcu_read_unlock() do { assert(held & 8); held &= ~8U; } while (0)
#define kref_get_unless_zero(p) (references++, true)

static void mutex_lock(struct mutex *m)
{
	expect("lock order", held & ~(m->bit - 1), 0);
	if (resource_thread && m == &mk_overlay_mutex) {
		assert(!pthread_mutex_lock(&gate));
		attempted = true;
		assert(!pthread_cond_broadcast(&changed));
		assert(!pthread_mutex_unlock(&gate));
	}
	assert(!pthread_mutex_lock(&m->native));
	held |= m->bit;
}

static void mutex_unlock(struct mutex *m)
{
	expect("unlock held mutex", !!(held & m->bit), 1);
	expect("reverse unlock order", held & ~(2 * m->bit - 1), 0);
	held &= ~m->bit;
	assert(!pthread_mutex_unlock(&m->native));
}

static struct mutex *scoped_lock(struct mutex *m)
{
	mutex_lock(m);
	return m;
}

static void scoped_unlock(struct mutex **m)
{
	if (*m) {
		mutex_unlock(*m);
		*m = NULL;
	}
}

#define scoped_guard(kind, m) \
	for (struct mutex *scope_##kind __attribute__((cleanup(scoped_unlock))) = \
	     scoped_lock(m); scope_##kind; scoped_unlock(&scope_##kind))
#define lockdep_assert_held(m) expect("lockdep assertion", !!(held & (m)->bit), 1)

static bool kexec_trylock(void)
{
	bool unlocked = false;

	if (!atomic_compare_exchange_strong(&kexec_held, &unlocked, true))
		return false;
	expect("kexec acquired first", held, 0);
	held |= KEXEC_LOCK;
	return true;
}

static void kexec_unlock(void)
{
	expect("resource lock released before kexec", held, KEXEC_LOCK);
	held &= ~KEXEC_LOCK;
	atomic_store(&kexec_held, false);
}

struct kimage;
struct mk_instance {
	int id;
	const char *name;
	enum mk_instance_state state;
	struct mk_cpu_set *cpus;
	struct kimage *kimage;
	void *ipi_data;
	unsigned long ipi_phys;
};
struct kexec_segment {
	void *kbuf, *buf;
	size_t bufsz, memsz;
	unsigned long mem;
};
struct kimage {
	int type, file_mode, mk_id;
	struct mk_instance *mk_instance;
	unsigned long nr_segments, start, head, control_page;
	struct kexec_segment segment[1];
	void *control_code_page, *swap_page;
	struct list_head control_pages;
};
static struct mk_instance target;
static struct mk_instance self, *mk_self = &self;
static struct kimage *kexec_image, *kexec_crash_image;
static struct { unsigned long start; } crashk_res;
static unsigned int references;
static int mk_instance_idr, kexec_file_dbg_print;
static char image_bytes[16], ring[16], control_page;
static mk_phys_cpu_t cpu_id = 65537;
static struct mk_cpu_set cpus = { .nr = 1, .cap = 1, .ids = &cpu_id };

static void *resource_operation(void *unused);

static void wait_for(bool *condition)
{
	struct timespec deadline;

	assert(!clock_gettime(CLOCK_REALTIME, &deadline));
	deadline.tv_sec += 10;
	while (!*condition)
		assert(!pthread_cond_timedwait(&changed, &gate, &deadline));
}

static int stage(const char *name)
{
	image_work_calls++;
	expect("image work holds kexec lock", !!(held & KEXEC_LOCK), 1);
	expect("no image work under registry lock", !!(held & REGISTRY_LOCK), 0);
	expect("MK work holds resource lock", !!(held & OVERLAY_LOCK), is_mk);
	if (probe_at && !probe_started && !strcmp(probe_at, name)) {
		probe_started = true;
		assert(!pthread_create(&competitor, NULL, resource_operation, NULL));
		assert(!pthread_mutex_lock(&gate));
		wait_for(&attempted);
		/* Without exclusion, let the contender finish to prove overlap. */
		if (!(held & OVERLAY_LOCK))
			wait_for(&finished);
		expect("overlay cannot mutate during MK image work",
		       atomic_load(&resource_updates), 0);
		assert(!pthread_mutex_unlock(&gate));
	}
	return fail_at && !strcmp(fail_at, name) ? -EIO : 0;
}

static struct mk_instance *idr_find(int *idr, int id)
{
	return id == target.id ? &target : NULL;
}
static void mk_instance_put(struct mk_instance *instance)
{
	if (!instance)
		return;
	assert(references);
	references--;
}
#define mk_instance_track_dump(...) do { } while (0)

static void mk_kimage_free(struct kimage *image, void *addr, size_t size)
{
	stage("free-segment");
}
static void kimage_file_post_load_cleanup(struct kimage *image)
{
	stage("free-buffer");
}
static int arch_cpu_from_physical_id(mk_phys_cpu_t cpu)
{
	return !mapping_fails && cpu == cpu_id ? 1 : -EINVAL;
}
static int mk_instance_confirm_parked(struct mk_instance *instance) { return stage("confirm"); }
static int kimage_load_segment(struct kimage *image, unsigned int i) { return stage("copy"); }
static int mk_manifest_finalize(struct kimage *image) { return stage("manifest"); }
static unsigned int host_ring_drops;
static __attribute__((unused)) void mk_ipi_ring_drop_pending(void)
{
	host_ring_drops++;
	stage("reset-ring");
}
static void mk_instance_ipi_deactivate(struct mk_instance *instance)
{
	stage("deactivate");
	instance->ipi_data = NULL;
}
static void mk_instance_ipi_publish(struct mk_instance *instance)
{
	stage("publish-ring");
	instance->ipi_data = ring;
}
static void mk_instance_ipi_reset(struct mk_instance *instance)
{
	stage("reset-instance-ring");
}
static int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance, int cpu)
{
	return stage("start");
}
/* PCI operations are boundary probes, not device emulation. */
static int mk_pciback_lend(struct mk_instance *instance) { return stage("lend"); }
static void mk_pciback_unlend(struct mk_instance *instance) { stage("unlend"); }
#include "image-instance.h"
#include "image-core.h"

static int kimage_free(struct kimage *image)
{
	int ret;

	if (!image)
		return 0;
	if (image->type == KEXEC_TYPE_MULTIKERNEL) {
		ret = kimage_can_free_multikernel(image);
		if (ret)
			return ret;
	}
	stage("free-image");
	if (image->type == KEXEC_TYPE_MULTIKERNEL)
		kimage_free_multikernel(image);
	else
		kimage_file_post_load_cleanup(image);
	free(image);
	return 0;
}
static struct kimage *do_kimage_alloc_init(void)
{
	struct kimage *image;

	stage("allocate");
	if (allocation_fails)
		return NULL;
	image = calloc(1, sizeof(*image));
	assert(image);
	INIT_LIST_HEAD(&image->control_pages);
	return image;
}
static int mk_instance_alloc_boot_pages(struct mk_instance *instance)
{
	return stage("boot-pages");
}
static int kimage_file_prepare_segments(struct kimage *image, int fd, int initrd,
				       const char *cmdline, unsigned long len, unsigned int flags)
{
	image->nr_segments = 1;
	image->segment[0].kbuf = image_bytes;
	image->segment[0].mem = (unsigned long)image_bytes;
	image->segment[0].memsz = sizeof(image_bytes);
	return stage("read-image");
}
static int sanity_check_segment_list(struct kimage *image) { return stage("validate"); }
#define KEXEC_CONTROL_PAGE_SIZE 4096
#define get_order(size) 0
static void *kimage_alloc_control_pages(struct kimage *image, unsigned int order)
{
	return stage(control_page_calls++ ? "swap-page" : "control-page") ?
		NULL : &control_page;
}
static void kimage_free_page_list(struct list_head *pages) { stage("free-pages"); }
static bool kexec_load_permitted(int type) { return permitted; }
static int machine_kexec_prepare(struct kimage *image) { return stage("prepare"); }
static int kimage_crash_copy_vmcoreinfo(struct kimage *image) { return stage("vmcore"); }
static int kexec_calculate_store_digests(struct kimage *image) { return stage("digest"); }
static void kimage_terminate(struct kimage *image) { stage("terminate"); }
static int kexec_post_load(struct kimage *image, unsigned long flags)
{
	return stage("post-load");
}
static void kimage_remove_from_list(struct kimage *image) { stage("remove-list"); }
static void kimage_add_to_list(struct kimage *image) { stage("publish"); }
static void kimage_update_compat_pointers(struct kimage *image, int type)
{
	if (type == KEXEC_TYPE_CRASH)
		kexec_crash_image = image;
	else
		kexec_image = image;
}
#define xchg(p, value) ({ __typeof__(*(p)) old = *(p); *(p) = (value); old; })
static void arch_kexec_unprotect_crashkres(void) { stage("unprotect"); }
static void arch_kexec_protect_crashkres(void) { stage("protect"); }
#include "image-file.h"

struct kernfs_node { void *priv; struct kernfs_node *parent; };
static struct kernfs_node overlay_root, *mk_overlay_root_kn = &overlay_root;
static struct kernfs_node *kernfs_get_parent(struct kernfs_node *kn)
{
	return kn->parent;
}
static void kernfs_put(struct kernfs_node *kn) { }
static void kernfs_remove_self(struct kernfs_node *kn) { }
static int mk_overlay_parse_and_rollback(struct mk_overlay_tx *tx, void *data)
{
	lockdep_assert_held(&mk_overlay_mutex);
	mutex_lock(&mk_instance_mutex);
	atomic_fetch_add(&resource_updates, 1);
	mutex_unlock(&mk_instance_mutex);
	return 0;
}
#include "image-overlay.h"

static void *resource_operation(void *unused)
{
	struct mk_overlay_tx *tx = calloc(1, sizeof(*tx));
	struct list_head transactions;
	struct kernfs_node kn = { .priv = tx, .parent = &overlay_root };

	assert(tx);
	resource_thread = true;
	INIT_LIST_HEAD(&transactions);
	list_add(&tx->list, &transactions);
	expect("competing overlay succeeds after release", mk_overlay_rmdir(&kn), 0);
	expect("resource thread releases all locks", held, 0);
	assert(!pthread_mutex_lock(&gate));
	finished = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	return NULL;
}

static const unsigned long mk_flags = KEXEC_MULTIKERNEL | KEXEC_MK_ID(2);

static void reset(bool multikernel)
{
	assert(!held && !atomic_load(&kexec_held));
	free(target.kimage);
	free(kexec_image);
	free(kexec_crash_image);
	kexec_image = kexec_crash_image = NULL;
	target = (struct mk_instance) {
		.id = 2, .name = "spawn", .state = MK_STATE_READY, .cpus = &cpus,
		.ipi_phys = (unsigned long)ring,
	};
	cpus.nr = 1;
	references = 0;
	is_mk = multikernel;
	permitted = true;
	mapping_fails = false;
	control_page_calls = 0;
	image_work_calls = 0;
	allocation_fails = probe_started = attempted = finished = false;
	probe_at = fail_at = NULL;
	atomic_store(&resource_updates, 0);
}

static void finish_probe(void)
{
	expect("requested overlap probe reached", probe_started, 1);
	assert(!pthread_join(competitor, NULL));
	expect("overlay progresses after image operation", atomic_load(&resource_updates), 1);
	expect("operation releases all locks", held, 0);
}

int main(void)
{
	static const char * const load_stages[] = { "allocate", "copy", "publish" };
	static const char * const fail_stages[] = {
		"boot-pages", "read-image", "validate", "prepare", "vmcore",
		"digest", "copy", "post-load", "control-page", "swap-page"
	};
	static const char * const exec_fail_stages[] = { "confirm", "copy", "manifest", "start" };
	unsigned int i;

	for (i = 0; i < sizeof(load_stages) / sizeof(*load_stages); i++) {
		reset(true);
		probe_at = load_stages[i];
		expect("MK load", kexec_file_load(0, 0, 0, NULL, mk_flags), 0);
		finish_probe();
		expect("load publishes complete image", target.kimage != NULL, 1);
		expect("published image pins instance", references, 1);
	}
	for (i = 0; i < sizeof(fail_stages) / sizeof(*fail_stages); i++) {
		int error = i >= 8 ? -ENOMEM : -EIO;

		reset(true);
		fail_at = fail_stages[i];
		probe_at = "free-buffer";
		expect("failed load", kexec_file_load(0, 0, 0, NULL, mk_flags), error);
		finish_probe();
		expect("failed image not published", target.kimage != NULL, 0);
		expect("failed load releases reference", references, 0);
	}
	reset(true);
	expect("setup unload", kexec_file_load(0, 0, 0, NULL, mk_flags), 0);
	probe_at = "free-segment";
	expect("MK unload", kexec_file_load(0, 0, 0, NULL, mk_flags | KEXEC_FILE_UNLOAD), 0);
	finish_probe();
	expect("unload clears image", target.kimage != NULL, 0);
	expect("unload releases reference", references, 0);

	reset(true);
	expect("setup active unload", kexec_file_load(0, 0, 0, NULL, mk_flags), 0);
	target.state = MK_STATE_ACTIVE;
	expect("active unload rejected", kexec_file_load(0, 0, 0, NULL,
	       mk_flags | KEXEC_FILE_UNLOAD), -EBUSY);
	expect("active unload retains image", target.kimage != NULL, 1);
	expect("active unload retains reference", references, 1);
	target.state = MK_STATE_FAILED;
	fail_at = "confirm";
	expect("uncertain failed unload rejected", kexec_file_load(0, 0, 0, NULL,
	       mk_flags | KEXEC_FILE_UNLOAD), -EIO);
	expect("failed confirmation retains image", target.kimage != NULL, 1);
	expect("failed confirmation retains reference", references, 1);
	fail_at = NULL;
	expect("confirmed failed start can unload", kexec_file_load(0, 0, 0, NULL,
	       mk_flags | KEXEC_FILE_UNLOAD), 0);
	expect("confirmed unload releases reference", references, 0);

	reset(true);
	expect("setup exec", kexec_file_load(0, 0, 0, NULL, mk_flags), 0);
	probe_at = "start";
	expect("MK exec", multikernel_kexec_by_id(2), 0);
	finish_probe();
	expect("spawn state published", target.state, MK_STATE_ACTIVE);
	expect("exec never rewinds or discards shared host receive traffic", host_ring_drops, 0);
	/* ACTIVE must be settled by halt, not by an execution request. */
	image_work_calls = 0;
	expect("active exec rejected", multikernel_kexec_by_id(2), -EBUSY);
	expect("active exec does no confirmation or image work", image_work_calls, 0);
	expect("active exec retains state", target.state, MK_STATE_ACTIVE);
	expect("active exec retains image", !!target.kimage, 1);
	expect("active exec retains reference", references, 1);
	expect("active exec releases all locks", held, 0);

	for (i = 0; i < sizeof(exec_fail_stages) / sizeof(*exec_fail_stages); i++) {
		reset(true);
		expect("setup failed exec", kexec_file_load(0, 0, 0, NULL, mk_flags), 0);
		fail_at = probe_at = exec_fail_stages[i];
		expect("failed exec", multikernel_kexec_by_id(2), -EIO);
		finish_probe();
		expect("failed exec retains non-reusable state after start", target.state,
		       !strcmp(exec_fail_stages[i], "start") ? MK_STATE_FAILED : MK_STATE_LOADED);
	}
	reset(true);
	expect("setup invalid CPU exec", kexec_file_load(0, 0, 0, NULL, mk_flags), 0);
	cpus.nr = 0;
	expect("empty CPU assignment", multikernel_kexec_by_id(2), -EINVAL);
	cpus.nr = 1;
	mapping_fails = true;
	expect("CPU mapping failure", multikernel_kexec_by_id(2), -EINVAL);
	expect("CPU errors release all locks", held, 0);

	reset(true);
	expect("unknown exec ID", multikernel_kexec_by_id(3), -EINVAL);
	expect("unknown load ID", kexec_file_load(0, 0, 0, NULL,
	       KEXEC_MULTIKERNEL | KEXEC_MK_ID(3)), -ENOENT);
	expect("zero ID", kexec_file_load(0, 0, 0, NULL, KEXEC_MULTIKERNEL), -EINVAL);
	expect("missing unload image", kexec_file_load(0, 0, 0, NULL,
	       mk_flags | KEXEC_FILE_UNLOAD), -ENOENT);
	allocation_fails = true;
	expect("allocation failure", kexec_file_load(0, 0, 0, NULL, mk_flags), -ENOMEM);
	expect("allocation failure releases lookup reference", references, 0);
	expect("error paths release all locks", held, 0);
	allocation_fails = false;
	atomic_store(&kexec_held, true);
	expect("busy file load", kexec_file_load(0, 0, 0, NULL, mk_flags), -EBUSY);
	expect("busy exec", multikernel_kexec_by_id(2), -EBUSY);
	expect("busy path never takes resource lock", held, 0);
	atomic_store(&kexec_held, false);
	permitted = false;
	expect("unprivileged load", kexec_file_load(0, 0, 0, NULL, mk_flags), -EPERM);
	permitted = true;
	expect("MK crash combination rejected", kexec_file_load(0, 0, 0, NULL,
	       mk_flags | KEXEC_FILE_ON_CRASH), -EINVAL);
	expect("invalid flags rejected", kexec_file_load(0, 0, 0, NULL, 1UL << 31), -EINVAL);

	reset(false);
	expect("normal load", kexec_file_load(0, 0, 0, NULL, 0), 0);
	expect("normal unload", kexec_file_load(0, 0, 0, NULL, KEXEC_FILE_UNLOAD), 0);
	expect("normal load releases locks", held, 0);
	fail_at = "prepare";
	expect("failed normal load", kexec_file_load(0, 0, 0, NULL, 0), -EIO);
	expect("failed normal load releases locks", held, 0);
	reset(false);
	expect("crash load", kexec_file_load(0, 0, 0, NULL, KEXEC_FILE_ON_CRASH), 0);
	expect("crash unload", kexec_file_load(0, 0, 0, NULL,
	       KEXEC_FILE_ON_CRASH | KEXEC_FILE_UNLOAD), 0);
	expect("crash load releases locks", held, 0);
	fail_at = "prepare";
	expect("failed crash load", kexec_file_load(0, 0, 0, NULL, KEXEC_FILE_ON_CRASH), -EIO);
	expect("failed crash load releases locks", held, 0);
	reset(false);
	printf("image locking: %u checks, %u failures\n",
	       atomic_load(&checks), atomic_load(&failures));
	return atomic_load(&failures) ? EXIT_FAILURE : EXIT_SUCCESS;
}
