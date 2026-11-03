// SPDX-License-Identifier: GPL-2.0-only
/* Actual transaction lifetime functions; resource effects and kernfs modeled. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/list.h>
#include <linux/err.h>

struct kernfs_node {
	void *priv;
	struct kernfs_node *parent;
	bool active, drained;
};

#include "overlay-types.h"
static struct kernfs_node root, node, *mk_overlay_root_kn = &root;
static LIST_HEAD(mk_overlay_tx_list);
static int mk_overlay_next_id;
static bool mk_overlay_mutex;
static int directory_error, files_error, apply_error, rollback_error;
static unsigned int effects, inverse_calls, frees, checks, failures;
#define pr_info(...) do { } while (0)
#define pr_err(...) do { } while (0)
#define GFP_KERNEL 0
#define kzalloc(n, flags) ((void)(flags), calloc(1, n))
#define atomic_inc_return(p) (++*(p))
static void expect(const char *why, int got, int want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: %d != %d\n", why, got, want);
		failures++;
	}
}

static bool *lock(bool *p)
{
	assert(!*p);
	*p = true;
	return p;
}

static void unlock(bool **p)
{
	if (*p) {
		assert(**p);
		**p = false;
		*p = NULL;
	}
}

#define guard(kind) bool *held_##kind __attribute__((cleanup(unlock))) = lock
#define scoped_guard(kind, p) \
	for (bool *held_##kind __attribute__((cleanup(unlock))) = lock(p); \
	     held_##kind; unlock(&held_##kind))
static void *kmemdup(const void *p, size_t size, int flags)
{
	void *copy = malloc(size);

	assert(copy);
	memcpy(copy, p, size);
	return copy;
}

static void kfree(void *p)
{
	if (p == node.priv) {
		expect("drain readers before freeing transaction",
		       !node.active || node.drained, true);
		node.priv = NULL;
	}
	frees++;
	free(p);
}

static struct kernfs_node *kernfs_create_dir(struct kernfs_node *parent,
					     const char *name, int mode, void *priv)
{
	assert(mk_overlay_mutex);
	if (directory_error)
		return ERR_PTR(directory_error);
	node = (struct kernfs_node) { .priv = priv, .parent = parent };
	return &node;
}

static void kernfs_remove(struct kernfs_node *kn)
{
	assert(!kn->active);
	kn->drained = true;
}

static void kernfs_remove_self(struct kernfs_node *kn)
{
	assert(!mk_overlay_mutex && kn->priv);
	assert(((struct mk_overlay_tx *)kn->priv)->status == MK_OVERLAY_TX_REMOVED);
	kn->drained = true;
}

static void kernfs_activate(struct kernfs_node *kn) { kn->active = true; }
static struct kernfs_node *kernfs_get_parent(struct kernfs_node *kn) { return kn->parent; }
static void kernfs_put(struct kernfs_node *kn) { }
static void mk_overlay_parse_metadata(struct mk_overlay_tx *tx, const void *blob) { }
static int mk_overlay_create_tx_files(struct mk_overlay_tx *tx) { return files_error; }
static int mk_overlay_parse_and_apply(struct mk_overlay_tx *tx, const void *blob)
{
	assert(mk_overlay_mutex);
	expect("create inactive record before resource effects",
	       node.priv == tx && !node.active, true);
	/* One resource succeeds, then the second can fail or time out. */
	effects++;
	return apply_error;
}

static int mk_overlay_parse_and_rollback(struct mk_overlay_tx *tx, const void *blob)
{
	assert(mk_overlay_mutex);
	inverse_calls++;
	return rollback_error;
}

#include "overlay-production.h"

static void reset(void)
{
	struct mk_overlay_tx *tx, *next;

	assert(!mk_overlay_mutex);
	/* Dispose fixture objects only; production must retain these transactions. */
	list_for_each_entry_safe(tx, next, &mk_overlay_tx_list, list) {
		list_del(&tx->list);
		free(tx->dtbo_data);
		free(tx);
	}
	node = (struct kernfs_node) { 0 };
	directory_error = 0;
	files_error = 0;
	apply_error = 0;
	rollback_error = 0;
	effects = 0;
	inverse_calls = 0;
	frees = 0;
}

int main(void)
{
	struct mk_overlay_tx *tx;
	int i;

	for (i = 0; i < 2; i++) {
		reset();
		if (i)
			files_error = -ENOMEM;
		else
			directory_error = -ENOMEM;
		expect("metadata allocation error returned", mk_overlay_apply("test", 5), -ENOMEM);
		expect("metadata allocation failure has no effects", effects, 0);
		expect("unapplied record freed", frees, 2);
	}
	reset();
	apply_error = -ETIMEDOUT;
	expect("failed transaction has inspectable ID", mk_overlay_apply("test", 5) > 0, true);
	tx = node.priv;
	assert(tx);
	expect("failed apply remains visible", tx->status, MK_OVERLAY_TX_FAILED);
	expect("failed apply cannot inverse unexecuted operations",
	       mk_overlay_rmdir(&node), -EBUSY);
	if (node.priv) {
		expect("failed transaction still retained", !list_empty(&mk_overlay_tx_list), true);
		expect("repeat removal still refused", mk_overlay_rmdir(&node), -EBUSY);
	}
	expect("failed apply never runs inverse", inverse_calls, 0);
	expect("failed apply never freed", frees, 0);
	reset();
	assert(mk_overlay_apply("test", 5) > 0);
	rollback_error = -EIO;
	expect("partial rollback failure returned", mk_overlay_rmdir(&node), -EIO);
	assert(node.priv);
	expect("partial rollback retained", ((struct mk_overlay_tx *)node.priv)->status,
	       MK_OVERLAY_TX_FAILED);
	rollback_error = 0;
	expect("partial inverse cannot run again", mk_overlay_rmdir(&node), -EBUSY);
	expect("partial inverse only attempted once", inverse_calls, 1);
	expect("failed rollback never freed", frees, 0);
	reset();
	assert(mk_overlay_apply("test", 5) > 0);
	expect("normal removal succeeds", mk_overlay_rmdir(&node), 0);
	expect("normal removal inverses once", inverse_calls, 1);
	expect("normal removal drains and frees", frees, 2);
	expect("normal removal unlinks transaction", list_empty(&mk_overlay_tx_list), true);
	reset();
	printf("Overlay retention: %u checks, %u failures (resource effects/kernfs modeled)\n",
	       checks, failures);
	return failures ? 1 : 0;
}
