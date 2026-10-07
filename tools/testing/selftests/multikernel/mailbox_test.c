// SPDX-License-Identifier: GPL-2.0-only
/* Extracted mailbox writers, with a bounded simulated reader and timeout. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint32_t u32;
typedef unsigned long phys_addr_t;
#include "mailbox-states.h"
#define USEC_PER_SEC 1000000
#define virt_to_phys(p) ((unsigned long)(p))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
/* Baseline extraction only; this single-threaded fixture models no barriers. */
#define smp_wmb() ((void)0)
/* Baseline extraction only; no hardware memory-order claim. */
#define smp_store_release(p, v) (*(p) = (v))
#define pr_err(...) ((void)0)

struct mk_spawn_context {
	unsigned long identity_cr3, kernel_entry, trampoline_virt,
		trampoline_phys;
	unsigned long park_phys, park_cr3, gs_base, stack;
	u32 flags, ready, target_apic_id;
};

static struct {
	struct {
		unsigned long cr3;
		struct mk_spawn_context *slot;
	} arch;
} pool, *mk_pool = &pool;

static struct mk_spawn_context *mk_own_context(void)
{
	return pool.arch.slot;
}

static unsigned int failures, checks;
static unsigned int outcome;
static bool ack_at_deadline;

static u32 test_cmpxchg(u32 *p, u32 old, u32 value)
{
	u32 seen;

	if (ack_at_deadline && old == MK_SLOT_ACK) {
		*p = MK_SLOT_ACK;
		ack_at_deadline = false;
	}
	seen = *p;
	if (seen == old)
		*p = value;
	return seen;
}

#define cmpxchg(p, old, value) test_cmpxchg(p, old, value)
#define xchg(p, value) __atomic_exchange_n(p, value, __ATOMIC_SEQ_CST)
/* Simulate only the reader state, not kernel execution or elapsed wall time. */
#define read_poll_timeout(op, val, cond, delay, timeout, sleep, arg) \
	({                                                           \
		(void)(delay);                                       \
		(void)(timeout);                                     \
		(void)(sleep);                                       \
		(arg) = outcome;                                     \
		(val) = op(arg);                                     \
		(cond) ? 0 : -ETIMEDOUT;                             \
	})
#include "mailbox-production.h"

static void expect(const char *name, bool pass)
{
	checks++;
	if (!pass) {
		fprintf(stderr, "FAIL: %s\n", name);
		failures++;
	}
}

int main(void)
{
	struct mk_spawn_context slot = { .ready = MK_SLOT_BUSY };
	int ret;

	outcome = MK_SLOT_ACK;
	ret = mk_slot_wake(&slot, 17, "ACK");
	expect("consume ACK before reuse", !ret && slot.ready == MK_SLOT_IDLE);
	slot.ready = MK_SLOT_BUSY;
	outcome = MK_SLOT_PENDING;
	ret = mk_slot_wake(&slot, 17, "unclaimed timeout");
	expect("pending timeout quarantines instead of revoking",
	       ret == -ETIMEDOUT && slot.ready == MK_SLOT_QUARANTINED);
	slot.ready = MK_SLOT_BUSY;
	outcome = MK_SLOT_BUSY;
	ret = mk_slot_wake(&slot, 17, "claimed timeout");
	expect("stalled reader cannot authorize reuse",
	       ret == -ETIMEDOUT && slot.ready == MK_SLOT_QUARANTINED);
	slot.ready = MK_SLOT_BUSY;
	outcome = MK_SLOT_BUSY;
	ack_at_deadline = true;
	ret = mk_slot_wake(&slot, 17, "ACK wins timeout race");
	expect("completed ACK wins timeout race",
	       !ret && slot.ready == MK_SLOT_IDLE);
	slot.ready = MK_SLOT_QUARANTINED;
	slot.kernel_entry = 0x1234;
	mk_set_spawn_context(&slot, 1, 2, 3, 4, 5);
	expect("context setup cannot reset quarantine",
	       slot.ready == MK_SLOT_QUARANTINED &&
		       slot.kernel_entry == 0x1234);
	slot.ready = MK_SLOT_BUSY;
	mk_set_spawn_context(&slot, 1, 2, 3, 4, 5);
	expect("context setup cannot overwrite another owner",
	       slot.ready == MK_SLOT_BUSY && slot.kernel_entry == 0x1234);
	slot.ready = MK_SLOT_IDLE;
	mk_set_spawn_context(&slot, 1, 2, 3, 4, 5);
	expect("idle setup returns mailbox to idle",
	       slot.ready == MK_SLOT_IDLE && slot.kernel_entry == 2);
	expect("publisher reserves idle",
	       !mk_slot_begin(&slot) && slot.ready == MK_SLOT_BUSY);
	expect("second publisher rejected", mk_slot_begin(&slot) == -EBUSY);
	slot.ready = MK_SLOT_QUARANTINED;
	expect("quarantine rejects a publisher", mk_slot_begin(&slot) == -EIO);
	pool.arch.slot = &slot;
	{
		struct mk_spawn_context remote = { .ready = MK_SLOT_BUSY };

		slot.ready = MK_SLOT_IDLE;
		outcome = MK_SLOT_PENDING;
		ret = mk_slot_wake(&remote, 17, "remote timeout");
		expect("remote uncertainty pins local park resources",
		       ret == -ETIMEDOUT &&
			       remote.ready == MK_SLOT_QUARANTINED &&
			       slot.ready == MK_SLOT_QUARANTINED);
	}
	printf("Mailbox writer: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
