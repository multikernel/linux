// SPDX-License-Identifier: GPL-2.0-only
/* Actual senders; injected transport, native hotplug and grant bookkeeping. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define CONFIG_PHYS_ADDR_T_64BIT
#include <linux/types.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>

#define u64 __u64
#include "resource-types.h"
#define MK_STATE_ACTIVE 2
#define MK_STATE_LOADED 1
#define MK_STATE_FAILED 3
#define PFN_PHYS(pfn) ((pfn) << 12)
#define pr_warn(...) do { } while (0)
#define pr_err(...) do { } while (0)
#define pr_info(...) do { } while (0)
#define strscpy(dst, src, len) snprintf(dst, len, "%s", src)
#define lockdep_assert_held(m) assert(*(m))
struct mk_instance {
	int id, state;
	bool resource_uncertain, pci_devices_valid;
	struct list_head list, pci_devices;
};

struct mk_pci_device {
	u16 domain;
	u8 bus, slot, func;
	struct list_head list;
};

#define PCI_SLOT(fn) ((fn) >> 3)
#define PCI_FUNC(fn) ((fn) & 7)
static LIST_HEAD(mk_instance_list);
static struct mk_pci_device grant;
static struct mk_instance self = { .id = 0 }, target;
static struct mk_instance *mk_self = &self;
static void *mk_pool;
static bool mk_overlay_mutex = true;
static bool mk_instance_mutex;

static bool *lock(bool *held)
{
	assert(mk_overlay_mutex && !*held);
	*held = true;
	return held;
}

static void unlock(bool **held)
{
	assert(**held);
	**held = false;
}

#define guard(kind) bool *held_##kind __attribute__((cleanup(unlock))) = lock
#include "resource-ownership.h"
struct pci_dev { u16 vendor, device; void *bus; };
static struct pci_dev device = { .vendor = 0x1234, .device = 0x5678 };
struct mk_pending_msg { int live; };
static struct mk_pending_msg request;
static int send_error, wait_error, alloc_error, reserve_error, release_error;
static int lend_error, references, publishes, lends, resets;
static bool owned, removal_reserved, lent, absent_device, owned_at_lend;
static bool owned_at_publish;
static bool pool_owned;
static unsigned int detaches;
static unsigned int checks, failures;
enum operation { MEM_ADD, MEM_REMOVE, DEVICE_ADD, DEVICE_REMOVE };

static void expect(const char *why, int got, int want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: %d != %d\n", why, got, want);
		failures++;
	}
}

static struct mk_instance *mk_instance_find(int id)
{
	assert(id == target.id);
	references++;
	return &target;
}

static void mk_instance_put(struct mk_instance *instance)
{
	assert(instance == &target && references == 1);
	references--;
}

static int reserve(void)
{
	if (reserve_error)
		return reserve_error;
	if (owned)
		return -EBUSY;
	owned = true;
	return 0;
}

static int release(void)
{
	assert(owned);
	if (release_error)
		return release_error;
	owned = false;
	return 0;
}

static void range(phys_addr_t start, size_t size)
{
	assert(start == PFN_PHYS(0x40000ULL) && size == PFN_PHYS(32ULL));
}

static int mk_instance_add_memory_region(struct mk_instance *p, phys_addr_t start,
					 size_t size)
{
	range(start, size);
	return reserve();
}

static int mk_instance_remove_memory_region(struct mk_instance *p, phys_addr_t start,
					    size_t size)
{
	range(start, size);
	return release();
}

static int mk_instance_begin_memory_removal(struct mk_instance *p, phys_addr_t start,
					    size_t size)
{
	range(start, size);
	assert(owned && !removal_reserved);
	if (reserve_error)
		return reserve_error;
	removal_reserved = true;
	return 0;
}

static void mk_instance_finish_memory_removal(struct mk_instance *p, phys_addr_t start,
					      size_t size)
{
	range(start, size);
	assert(owned && removal_reserved);
	owned = false;
	removal_reserved = false;
}

static void mk_instance_abort_memory_removal(struct mk_instance *p, phys_addr_t start,
					     size_t size)
{
	range(start, size);
	assert(owned && removal_reserved);
	removal_reserved = false;
}

static int mk_instance_add_pci_device(struct mk_instance *p, u16 dom, u8 bus, u8 fn)
{
	int ret;

	assert(dom == 0x8001 && bus == 2 && fn == 3);
	ret = reserve();
	if (!ret)
		list_add(&grant.list, &p->pci_devices);
	return ret;
}

static int mk_instance_remove_pci_device(struct mk_instance *p, u16 dom, u8 bus, u8 fn)
{
	int ret = release();

	if (!ret)
		list_del_init(&grant.list);
	return ret;
}

static int mk_pciback_lend_one(struct mk_instance *p, u16 dom, u8 bus, u8 fn)
{
	lends++;
	owned_at_lend = owned;
	if (!lend_error)
		lent = true;
	return lend_error;
}

static void mk_pciback_unlend_one(struct mk_instance *p, u16 dom, u8 bus, u8 fn)
{
	resets++;
	lent = false;
}

static struct pci_dev *pci_get_domain_bus_and_slot(u16 dom, u8 bus, u8 fn)
{
	return absent_device ? NULL : &device;
}

static void pci_dev_put(struct pci_dev *p) { }
static void mk_pci_bus_describe(void *bus, struct mk_pci_bus_desc *desc) { }
static struct mk_pending_msg *mk_msg_pending_add(u32 type, u32 op, u64 id)
{
	assert(!request.live);
	assert(id == (op == MK_RES_MEM_ADD || op == MK_RES_MEM_REMOVE ?
		      0x40000ULL : 0x80010203ULL));
	if (alloc_error)
		return ERR_PTR(alloc_error);
	request.live = 1;
	return &request;
}

static u64 mk_msg_pending_id(struct mk_pending_msg *p) { return 17; }
static void mk_msg_pending_cancel(struct mk_pending_msg *p)
{
	assert(p->live && !publishes);
	p->live = 0;
}

static int mk_send_message_id(int id, u32 type, u32 op, u64 msg_id,
			      void *payload, size_t size)
{
	assert(request.live && msg_id == 17);
	if (send_error)
		return send_error;
	publishes++;
	owned_at_publish = owned;
	return 0;
}

static int mk_msg_pending_wait(struct mk_pending_msg *p, int timeout)
{
	assert(p->live && publishes == 1);
	p->live = 0;
	return wait_error;
}

/* Local native paths are not exercised by this remote ownership fixture. */
#define mk_do_mem_add(...) (-EOPNOTSUPP)
#define mk_do_mem_remove(...) (-EOPNOTSUPP)
#define mk_pool_device_remove(...) (-EOPNOTSUPP)
#define mk_do_device_add(...) (-EOPNOTSUPP)
#define mk_manifest_phys() 0
#define mk_pcifront_adopt_function(...) (-EOPNOTSUPP)

static int mk_do_device_remove(u16 dom, u8 bus, u8 fn)
{
	detaches++;
	return 0;
}

static int mk_root_add_pci_device(u16 dom, u8 bus, u8 fn, const char *alias)
{
	pool_owned = true;
	return 0;
}

#include "resource-production.h"

static void reset(enum operation op)
{
	guard(mutex)(&mk_instance_mutex);

	assert(mk_overlay_mutex && !references && !request.live);
	target = (struct mk_instance) { .id = 2, .state = MK_STATE_ACTIVE,
		.pci_devices_valid = true };
	INIT_LIST_HEAD(&mk_instance_list);
	INIT_LIST_HEAD(&target.pci_devices);
	INIT_LIST_HEAD(&self.pci_devices);
	list_add(&target.list, &mk_instance_list);
	list_add(&self.list, &mk_instance_list);
	grant = (struct mk_pci_device) { .domain = 0x8001, .bus = 2, .slot = 0, .func = 3 };
	INIT_LIST_HEAD(&grant.list);
	if (op == DEVICE_REMOVE)
		list_add(&grant.list, &target.pci_devices);
	pool_owned = false;
	detaches = 0;
	send_error = 0;
	wait_error = 0;
	alloc_error = 0;
	reserve_error = 0;
	release_error = 0;
	lend_error = 0;
	publishes = 0;
	lends = 0;
	resets = 0;
	owned = op == MEM_REMOVE || op == DEVICE_REMOVE;
	lent = op == DEVICE_REMOVE;
	removal_reserved = false;
	absent_device = false;
	owned_at_lend = false;
	owned_at_publish = false;
}

static int run(enum operation op)
{
	switch (op) {
	case MEM_ADD:
		return mk_send_mem_add(2, 0x40000, 32, 0, 0);
	case MEM_REMOVE:
		return mk_send_mem_remove(2, 0x40000, 32);
	case DEVICE_ADD:
		return mk_send_device_add(2, 0x8001, 2, 3, "test", 0);
	case DEVICE_REMOVE:
		return mk_send_device_remove(2, 0x8001, 2, 3);
	}
	assert(false);
	return -EINVAL;
}

int main(void)
{
	const int errors[] = { -ETIMEDOUT, -EIO, -EBUSY };
	enum operation op;
	unsigned int i;

	for (op = MEM_ADD; op <= DEVICE_REMOVE; op++) {
		for (i = 0; i < ARRAY_SIZE(errors); i++) {
			reset(op);
			wait_error = errors[i];
			expect("published failure returned", run(op), errors[i]);
			expect("published failure retains ownership", owned, true);
			expect("published failure quarantines instance",
			       target.resource_uncertain, true);
			if (op == MEM_REMOVE)
				expect("late removal cannot race allocation",
				       removal_reserved, true);
			if (op >= DEVICE_ADD) {
				expect("late probe/removal retains lending", lent, true);
				expect("uncertain device never reset", resets, 0);
				expect("pool insertion cannot bypass retained grant",
				       mk_pool_device_add(0x8001, 2, 3, NULL), -EBUSY);
				expect("quarantined device not detached locally", detaches, 0);
				expect("quarantined device unavailable for another grant",
				       pool_owned, false);
			}
			/* A late worker can now finish; another grant must still fail. */
			expect("competing reservation rejected", reserve(), -EBUSY);
			if (target.resource_uncertain) {
				expect("quarantined request rejected", run(op), -EBUSY);
				expect("no new publication", publishes, 1);
			}
		}
		for (i = 0; i < 2; i++) {
			reset(op);
			if (i)
				send_error = -ENOSPC;
			else
				alloc_error = -ENOMEM;
			expect("unpublished error returned", run(op), i ? -ENOSPC : -ENOMEM);
			expect("unpublished error restores grant",
			       owned, op == MEM_REMOVE || op == DEVICE_REMOVE);
			expect("unpublished remove reservation undone", removal_reserved, false);
			expect("unpublished request never quarantined",
			       target.resource_uncertain, false);
			expect("unpublished request absent", publishes, 0);
		}
		reset(op);
		expect("normal request succeeds", run(op), 0);
		expect("ownership precedes publication", owned_at_publish, true);
		expect("normal request leaves expected owner",
		       owned, op == MEM_ADD || op == DEVICE_ADD);
		if (op == DEVICE_ADD)
			expect("ownership precedes lend", owned_at_lend, true);
		reset(op);
		target.resource_uncertain = true;
		target.state = MK_STATE_LOADED;
		expect("state change cannot clear quarantine", run(op), -EBUSY);
		expect("quarantined state publishes nothing", publishes, 0);
	}
	reset(DEVICE_ADD);
	reserve_error = -ENOENT;
	expect("unowned device rejected", run(DEVICE_ADD), -ENOENT);
	expect("unowned device never lent", lends, 0);
	expect("unowned device never published", publishes, 0);
	reset(DEVICE_ADD);
	lend_error = -EIO;
	expect("lend failure returned", run(DEVICE_ADD), -EIO);
	expect("lend failure restores grant", owned, false);
	reset(DEVICE_ADD);
	absent_device = true;
	expect("missing device returned", run(DEVICE_ADD), -ENODEV);
	expect("missing device restores grant", owned, false);
	expect("missing device unlent", lent, false);
	for (op = MEM_ADD; op <= DEVICE_REMOVE; op++) {
		if (op == MEM_REMOVE)
			continue;
		reset(op);
		release_error = -EBUSY;
		if (op != DEVICE_REMOVE)
			send_error = -ENOSPC;
		expect("failed grant cleanup returned", run(op), -EBUSY);
		expect("failed grant cleanup retains owner", owned, true);
		expect("failed grant cleanup quarantined", target.resource_uncertain, true);
	}
	assert(mk_overlay_mutex && !references && !request.live);
	reset(DEVICE_REMOVE);
	expect("ordinary live grant also blocks pool insertion",
	       mk_pool_device_add(0x8001, 2, 3, NULL), -EBUSY);
	expect("different domain is a different function",
	       mk_pool_device_add(0x8002, 2, 3, NULL), 0);
	expect("different bus is a different function",
	       mk_pool_device_add(0x8001, 3, 3, NULL), 0);
	expect("different function is a different device",
	       mk_pool_device_add(0x8001, 2, 4, NULL), 0);
	reset(DEVICE_ADD);
	self.pci_devices_valid = true;
	list_add(&grant.list, &self.pci_devices);
	expect("self pool entry does not imply another owner",
	       mk_pool_device_add(0x8001, 2, 3, NULL), 0);
	printf("Resource transfers: %u checks, %u failures (transport/native operations modeled)\n",
	       checks, failures);
	return failures ? 1 : 0;
}
