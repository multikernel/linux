// SPDX-License-Identifier: GPL-2.0-only
/* Actual request/retirement functions; PCI, workqueue and RCU boundaries modeled. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/list.h>

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
#define GFP_ATOMIC 0
#define MK_MSG_PCI 1
#define MK_PCI_CFG_ACK 2
#define PCIBIOS_DEVICE_NOT_FOUND 0x86
#define kzalloc(n, flags) calloc(1, n)
#define kfree free
#define lockdep_assert_held(p) ((void)(p))

struct mk_shared_data;
struct mk_instance {
	int id;
	atomic_int refs;
	struct mk_shared_data *ipi_data;
};
struct pci_bus { int number; };
struct pci_dev { struct pci_bus *bus; int devfn, dev; };
struct mk_pci_cfg_payload { int sender_instance_id, result; u16 domain; u8 bus, devfn; u32 val; };
struct work_struct { void (*fn)(struct work_struct *); };
struct mk_pciback_dev {
	struct list_head list;
	atomic_int ref;
	struct mk_instance *instance;
	struct pci_dev *pdev;
	pthread_mutex_t io_lock;
	bool revoked;
};
struct mk_pciback_work {
	struct work_struct work;
	struct mk_pci_cfg_payload req;
	u32 subtype;
	struct mk_pciback_dev *dev;
};
static LIST_HEAD(mk_pciback_devs);
static pthread_mutex_t mk_pciback_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mk_instance old = { .id = 7, .refs = 1 };
static struct mk_instance replacement = { .id = 7, .refs = 1 };
static struct mk_instance self = { .id = 0, .refs = 1 };
static struct mk_instance *mk_self = &self, *lookup = &old, *answer_to;
static struct pci_bus bus = { 2 };
static struct pci_dev pdev = { .bus = &bus, .devfn = 3 };
static struct work_struct *queued;
static bool nested = true;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool hold_access, entered, release_access, retiring, io_active, reset_during_io;
static _Thread_local bool retire_thread;
static unsigned int accesses, resets, failures;
static u32 config_value;

static void mutex_lock(pthread_mutex_t *p)
{
	if (retire_thread && p != &mk_pciback_lock) {
		assert(!pthread_mutex_lock(&gate));
		retiring = true;
		assert(!pthread_cond_broadcast(&changed));
		assert(!pthread_mutex_unlock(&gate));
	}
	assert(!pthread_mutex_lock(p));
}
static void mutex_unlock(pthread_mutex_t *p) { assert(!pthread_mutex_unlock(p)); }
static pthread_mutex_t *lock(pthread_mutex_t *p) { mutex_lock(p); return p; }
static void unlock(pthread_mutex_t **p)
{
	if (*p) {
		mutex_unlock(*p);
		*p = NULL;
	}
}
#define guard(kind) pthread_mutex_t *held_##kind __attribute__((cleanup(unlock))) = lock
#define scoped_guard(kind, p) \
	for (pthread_mutex_t *scope __attribute__((cleanup(unlock))) = lock(p); scope; unlock(&scope))
#define INIT_WORK(w, f) ((w)->fn = (f))
static void schedule_work(struct work_struct *w) { assert(!queued); queued = w; }
static struct mk_instance *mk_instance_find(int id)
{
	if (!lookup || lookup->id != id)
		return NULL;
	lookup->refs++;
	return lookup;
}
static void mk_instance_get(struct mk_instance *p) { p->refs++; }
static void mk_instance_put(struct mk_instance *p) { assert(p->refs > 1); p->refs--; }
#define refcount_inc(p) (++*(p))
#define refcount_dec_and_test(p) (!--*(p))
#define pm_runtime_put(p) ((void)(p))
#define pci_dev_put(p) ((void)(p))
#define pci_domain_nr(p) 0
#define mk_manifest_phys() nested
static void mk_send_message_to(struct mk_instance *p, int type, int subtype,
			       void *data, size_t len)
{
	answer_to = p;
}
static void mk_pciback_do(struct mk_pciback_dev *d, u32 subtype,
			 struct mk_pci_cfg_payload *req)
{
	assert(!pthread_mutex_lock(&gate));
	accesses++;
	config_value = req->val;
	req->result = 0;
	io_active = entered = true;
	assert(!pthread_cond_broadcast(&changed));
	while (hold_access && !release_access)
		assert(!pthread_cond_wait(&changed, &gate));
	io_active = false;
	assert(!pthread_mutex_unlock(&gate));
}
static int pci_reset_function(struct pci_dev *p)
{
	assert(!pthread_mutex_lock(&gate));
	resets++;
	reset_during_io |= io_active;
	retiring = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	return 0;
}
#define pci_clear_master(p) ((void)(p))
#include "pciback-production.h"

#define CHECK(cond, why) do { if (!(cond)) { failures++; fprintf(stderr, "FAIL: %s\n", why); } } while (0)
static struct mk_pci_cfg_payload request = { .sender_instance_id = 7, .bus = 2, .devfn = 3 };
static void lend(struct mk_instance *p)
{
	struct mk_pciback_dev *d = calloc(1, sizeof(*d));

	assert(d);
	d->ref = 1;
	d->instance = p;
	d->pdev = &pdev;
	assert(!pthread_mutex_init(&d->io_lock, NULL));
	mk_instance_get(p);
	list_add(&d->list, &mk_pciback_devs);
}
static void *run_work(void *arg)
{
	struct work_struct *work = queued;

	assert(work);
	queued = NULL;
	work->fn(work);
	return NULL;
}
static void *retire(void *arg)
{
	retire_thread = true;
	mk_pciback_unlend(&old);
	return NULL;
}

#define MK_IPI_RING_SIZE 8
#define MK_MAX_DATA_SIZE 64
#define pr_warn_once(...) do { } while (0)
#define rcu_read_lock() do { } while (0)
#define rcu_read_unlock() do { } while (0)
#define rcu_dereference(p) (p)
#define atomic_read(p) (*(p))
/* Controlled arrivals model publication; this fixture does not test barriers. */
#define smp_load_acquire(p) (*(p))
#define this_cpu_read(p) (p)
#define this_cpu_write(p, v) ((p) = (v))
#define raw_spin_lock_irqsave(m, flags) do { (flags) = 0; mutex_lock(m); } while (0)
#define raw_spin_unlock_irqrestore(m, flags) do { (void)(flags); mutex_unlock(m); } while (0)
struct mk_ipi_data {
	size_t data_size;
	unsigned long type;
	char buffer[MK_MAX_DATA_SIZE];
};

struct mk_shared_data {
	struct {
		unsigned int head, tail;
		struct mk_ipi_data entries[MK_IPI_RING_SIZE];
	} ring;
};

typedef void (*mk_ipi_callback_t)(struct mk_ipi_data *, void *);
struct mk_ipi_handler {
	unsigned long ipi_type;
	mk_ipi_callback_t callback;
	void *context;
	struct mk_ipi_handler *next;
};

static struct mk_shared_data inbox;
static struct mk_ipi_handler *mk_handlers;
static pthread_mutex_t mk_drain_lock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool mk_draining;
static unsigned int peer_callbacks, releases, append_valid, append_invalid;
static int recursive_result;
static bool reenter;

static void enqueue(unsigned long type, size_t size)
{
	unsigned int head = inbox.ring.head;
	unsigned int next = (head + 1) % MK_IPI_RING_SIZE;
	struct mk_ipi_data *slot = &inbox.ring.entries[head];

	assert(next != inbox.ring.tail && !slot->data_size);
	slot->type = type;
	memcpy(slot->buffer, &request, sizeof(request));
	slot->data_size = size;
	inbox.ring.head = next;
}

static void atomic_set_release(unsigned int *p, unsigned int value)
{
	assert(p == &inbox.ring.tail);
	assert(!inbox.ring.entries[*p].data_size);
	*p = value;
	releases++;
	if (append_invalid) {
		append_invalid--;
		enqueue(9, MK_MAX_DATA_SIZE + 1);
	}
}

bool mk_ipi_in_drain(void);
#include "pciback-ring.h"
#include "pciback-poll-api.h"
static int poll_result(void)
{
#ifdef POLL_HAS_RESULT
	return mk_ipi_poll();
#else
	mk_ipi_poll();
	return 0;
#endif
}

static void pci_message(struct mk_ipi_data *slot, void *ctx)
{
	struct mk_pci_cfg_payload req;

	assert(mk_draining);
	memcpy(&req, slot->buffer, sizeof(req));
	mk_pciback_request(&req, 1);
}

static void peer_message(struct mk_ipi_data *slot, void *ctx)
{
	assert(mk_draining);
	peer_callbacks++;
	if (append_valid) {
		append_valid--;
		enqueue(9, 1);
	}
	if (reenter)
		recursive_result = poll_result();
}

static void reset_ring(void)
{
	static struct mk_ipi_handler peer = { .ipi_type = 9, .callback = peer_message };
	static struct mk_ipi_handler pci = {
		.ipi_type = MK_MSG_PCI, .callback = pci_message, .next = &peer,
	};

	assert(!mk_draining && !queued && list_empty(&mk_pciback_devs));
	memset(&inbox, 0, sizeof(inbox));
	self.ipi_data = &inbox;
	mk_handlers = &pci;
	peer_callbacks = 0;
	releases = 0;
	append_valid = 0;
	append_invalid = 0;
	reenter = false;
	answer_to = NULL;
	accesses = 0;
	resets = 0;
	nested = true;
}

static void ring_retirement(void)
{
	reset_ring();
	lookup = &old;
	lend(&old);
	enqueue(MK_MSG_PCI, sizeof(request));
	enqueue(9, 1);
	CHECK(!poll_result(), "queued old PCI request dispatched before retirement");
	CHECK(queued && peer_callbacks == 1, "retirement preserves another peer's message");
	mk_pciback_unlend(&old);
	lookup = &replacement;
	lend(&replacement);
	run_work(NULL);
	CHECK(!accesses && !answer_to, "old ring request cannot reach replacement grant or inbox");
	mk_pciback_unlend(&replacement);

	reset_ring();
	lookup = &old;
	lend(&old);
	enqueue(9, 0);
	enqueue(MK_MSG_PCI, sizeof(request));
	CHECK(poll_result() == -EBUSY, "unpublished slot must refuse retirement");
	CHECK(!releases && !queued && !resets, "blocked prefix must not skip or retire a grant");
	CHECK(inbox.ring.head == 2 && !inbox.ring.tail, "blocked shared ring remains intact");
	inbox.ring.entries[0].data_size = 1;
	CHECK(!poll_result(), "late publication allows bounded retry");
	CHECK(peer_callbacks == 1 && queued, "late publication preserves FIFO dispatch");
	mk_pciback_unlend(&old);
	run_work(NULL);
	CHECK(!accesses && !answer_to, "retired late work cannot execute or reply");

	reset_ring();
	enqueue(9, 1);
	enqueue(9, 0);
	enqueue(9, 1);
	CHECK(poll_result() == -EBUSY && releases == 1 && peer_callbacks == 1,
	      "completed prefix does not hide a later unpublished slot");
	CHECK(inbox.ring.tail == 1 && inbox.ring.head == 3,
	      "partial drain retains blocked and following slots");
	inbox.ring.entries[1].data_size = 1;
	CHECK(!poll_result() && releases == 3 && peer_callbacks == 3,
	      "retry does not dispatch the completed prefix twice");

	reset_ring();
	inbox.ring.head = MK_IPI_RING_SIZE - 2;
	inbox.ring.tail = MK_IPI_RING_SIZE - 2;
	enqueue(9, 1);
	enqueue(9, 1);
	enqueue(9, 1);
	CHECK(!poll_result() && inbox.ring.tail == 1 && peer_callbacks == 3,
	      "snapshot retirement handles wraparound");

	reset_ring();
	enqueue(9, 1);
	enqueue(9, 1);
	append_valid = MK_IPI_RING_SIZE * 2;
	CHECK(!poll_result() && peer_callbacks == 2 && releases == 2,
	      "new peer traffic cannot extend the retirement snapshot");
	CHECK(inbox.ring.tail != inbox.ring.head, "new peer messages remain queued");
	append_valid = 0;
	CHECK(!poll_result() && peer_callbacks == 4 && releases == 4,
	      "next drain processes new peer traffic exactly once");

	reset_ring();
	enqueue(9, MK_MAX_DATA_SIZE + 1);
	enqueue(9, MK_MAX_DATA_SIZE + 1);
	append_invalid = MK_IPI_RING_SIZE * 2;
	CHECK(!poll_result() && releases == 2 && !peer_callbacks,
	      "malformed peer traffic also obeys the snapshot bound");

#ifdef POLL_HAS_RESULT
	reset_ring();
	enqueue(9, 1);
	reenter = true;
	CHECK(!poll_result() && recursive_result == -EBUSY,
	      "callback reentry refuses recursive consumer locking");
#endif
	reset_ring();
	self.ipi_data = NULL;
	CHECK(!poll_result(), "no initialized inbox has nothing to retire");
	CHECK(old.refs == 1 && replacement.refs == 1, "ring dispatch pins are released");
}

int main(void)
{
	pthread_t worker, reclaimer;

	/* A queued request cannot acquire a replacement grant with the same ID/BDF. */
	lend(&old);
	mk_pciback_request(&request, 1);
	mk_pciback_unlend(&old);
	lookup = &replacement;
	lend(&replacement);
	run_work(NULL);
	CHECK(!accesses, "retired queued request must not access a replacement grant");
	CHECK(!answer_to, "revoked work must not send an ACK into a later boot");
	mk_pciback_unlend(&replacement);
	CHECK(old.refs == 1 && replacement.refs == 1, "queued pins released exactly once");

	/* Negative replies have no config work and never queue an ID lookup. */
	lookup = &old;
	mk_pciback_request(&request, 1);
	lookup = &replacement;
	CHECK(!queued && answer_to == &old, "negative reply must not defer an instance ID lookup");

	lookup = &old;
	lend(&old);
	hold_access = true;
	entered = retiring = false;
	mk_pciback_request(&request, 1);
	assert(!pthread_create(&worker, NULL, run_work, NULL));
	assert(!pthread_mutex_lock(&gate));
	while (!entered)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_create(&reclaimer, NULL, retire, NULL));
	assert(!pthread_mutex_lock(&gate));
	while (!retiring)
		assert(!pthread_cond_wait(&changed, &gate));
	CHECK(!reset_during_io, "device reset must wait for admitted config access");
	release_access = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_join(worker, NULL));
	assert(!pthread_join(reclaimer, NULL));
	CHECK(old.refs == 1 && list_empty(&mk_pciback_devs), "retirement releases all request pins");
	/* Deferred and interrupt-context writes must preserve the request's value. */
	hold_access = false;
	request.val = 0x1234abcd;
	lend(&old);
	mk_pciback_request(&request, 1);
	run_work(NULL);
	CHECK(config_value == request.val, "deferred config write preserves its value");
	nested = false;
	request.val = 0x4321dcba;
	mk_pciback_request(&request, 1);
	CHECK(!queued && config_value == request.val, "direct config write preserves its value");
	mk_pciback_unlend_one(&old, 0, 2, 3);
	CHECK(old.refs == 1 && list_empty(&mk_pciback_devs), "single-device retirement releases pins");
	ring_retirement();
	if (failures)
		return 1;
	puts("PCI/ring lifetime: PASS (config, IRQ and workqueue modeled)");
	return 0;
}
