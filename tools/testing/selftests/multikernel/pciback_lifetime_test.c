// SPDX-License-Identifier: GPL-2.0-only
/* Actual request/retirement functions; PCI, workqueue and RCU boundaries modeled. */
#include <assert.h>
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

struct mk_instance { int id; atomic_int refs; };
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
static struct mk_instance old = { 7, 1 }, replacement = { 7, 1 }, self = { 0, 1 };
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
	if (failures)
		return 1;
	puts("PCI backend lifetime: 4 scenarios PASS (modeled config/workqueue boundaries)");
	return 0;
}
