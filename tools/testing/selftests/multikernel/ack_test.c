// SPDX-License-Identifier: GPL-2.0-only
/* See README.ack: real pending/dispatch code, deterministic kernel boundaries. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/list.h>

/* tools/ uses uint64_t; production printk formats use the kernel's __u64. */
#define u64 __u64
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define kzalloc(n, flags) ((void)(flags), calloc(1, n))
#define kmalloc(n, flags) ((void)(flags), malloc(n))
#define kfree free
#define pr_err(...) fprintf(stderr, __VA_ARGS__)
#define pr_warn(...) fprintf(stderr, __VA_ARGS__)
#define pr_info(...) do { } while (0)
#define pr_debug(...) do { } while (0)
#define DEFINE_SPINLOCK(name) bool name
#define spin_lock_irqsave(lock, flags) \
	do { assert(!*(lock)); *(lock) = true; (flags) = 0; } while (0)
#define spin_unlock_irqrestore(lock, flags) \
	do { assert(*(lock)); *(lock) = false; (void)(flags); } while (0)
#define msecs_to_jiffies(ms) (ms)

struct completion {
	unsigned int done;
};

static void (*at_timeout)(void);
static void (*at_completion)(void);

static void init_completion(struct completion *c)
{
	c->done = 0;
}

static void complete(struct completion *c)
{
	c->done++;
}

static unsigned long wait_for_completion_timeout(struct completion *c,
						 unsigned long timeout)
{
	if (c->done) {
		c->done--;
		if (at_completion) {
			void (*hook)(void) = at_completion;

			at_completion = NULL;
			hook();
		}
		return timeout ? timeout : 1;
	}
	/* Inject an ACK after timeout is decided, before pending list removal. */
	if (at_timeout) {
		void (*hook)(void) = at_timeout;

		at_timeout = NULL;
		hook();
	}
	return 0;
}

#include "ack-types.h"

static struct mk_ipi_data sent;

/* Transport boundary: capture real mk_send_message() output for replay. */
static int multikernel_send_ipi_data(int instance_id, void *data,
				     size_t size, unsigned long type)
{
	assert(size <= sizeof(sent.buffer));
	sent.type = type;
	sent.data_size = size;
	memcpy(sent.buffer, data, size);
	return 0;
}

#include "ack-messaging.h"

/* These non-ACK branches must never execute in this test. */
static int unexpected_request(void *payload, u32 len)
{
	abort();
}

#define mk_handle_cpu_add unexpected_request
#define mk_handle_cpu_remove unexpected_request
#define mk_handle_mem_add unexpected_request
#define mk_handle_mem_remove unexpected_request
#define mk_handle_device_add unexpected_request
#define mk_handle_device_remove unexpected_request

struct work_struct {
	void (*func)(struct work_struct *work);
};

static void unexpected_work(struct work_struct *work)
{
	abort();
}

#define INIT_WORK(work, fn) ((work)->func = (fn))
#define schedule_work(work) ((void)(work), abort())
#define mk_shutdown_work_fn unexpected_work
#define mk_halted_work_fn unexpected_work

#include "ack-resource.h"
#include "ack-system.h"

static int failures;

static void expect(const char *kind, const char *name, int got, int want)
{
	if (got != want) {
		fprintf(stderr, "FAIL %s: %s: got %d, want %d\n",
			kind, name, got, want);
		failures++;
	} else {
		printf("PASS %s: %s\n", kind, name);
	}
}

static struct mk_pending_msg *pending(u32 type, u32 op)
{
	struct mk_pending_msg *p = mk_msg_pending_add(type, op, 65537);

	assert(p);
	return p;
}

static int finish(struct mk_pending_msg *p)
{
	int result = mk_msg_pending_wait(p, 0);

	assert(list_empty(&mk_pending_msgs));
	assert(!mk_pending_msgs_lock);
	return result;
}

static void dispatch(struct mk_ipi_data *data)
{
	struct mk_msg_type_handler handler = {
		.msg_type = data->type,
		.msg_handler = data->type == MK_MSG_SYSTEM ?
			mk_system_msg_handler : mk_resource_msg_handler,
	};

	mk_message_type_ipi_callback(data, &handler);
}

static void reply(u32 type, u32 op, u64 resource, int result, u64 id, bool short_ack)
{
	struct mk_resource_ack ack = {
		.operation = op, .result = result, .resource_id = resource,
	};
	struct mk_ipi_data data = { .sender_cpu = 7, .type = type };
	struct mk_message *msg = (struct mk_message *)data.buffer;

	msg->msg_type = type;
	msg->msg_subtype = type == MK_MSG_SYSTEM ? MK_SYS_SHUTDOWN_ACK : MK_RES_ACK;
	msg->msg_id = id;
	msg->payload_len = sizeof(ack) - short_ack;
	memcpy(msg->payload, &ack, sizeof(ack));
	data.data_size = sizeof(*msg) + msg->payload_len;
	dispatch(&data);
}

static void cpu_ack(void)
{
	reply(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, 0, 0, false);
}

static void cpu_error_ack(void)
{
	reply(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, -EIO, 0, false);
}

static unsigned int callbacks;

static void count_callback(u32 type, u32 subtype, void *payload, u32 len, void *ctx)
{
	callbacks++;
}

static void completion_regressions(void)
{
	struct mk_pending_msg *p;
	struct mk_ipi_data data = { .type = MK_MSG_RESOURCE };
	struct mk_message *msg = (struct mk_message *)data.buffer;
	struct mk_msg_type_handler handler = {
		.msg_type = MK_MSG_RESOURCE, .msg_handler = count_callback,
	};

	/* A completion token is consumed by the waiter, not by duplicates. */
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	cpu_ack();
	cpu_error_ack();
	expect("REGRESSION", "duplicate must preserve first success", finish(p), 0);
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	cpu_error_ack();
	cpu_ack();
	expect("REGRESSION", "duplicate must preserve first error", finish(p), -EIO);
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	cpu_ack();
	at_completion = cpu_error_ack;
	expect("REGRESSION", "duplicate after waiter consumes token", finish(p), 0);

	p = pending(MK_MSG_SYSTEM, MK_SYS_SHUTDOWN);
	reply(MK_MSG_SYSTEM, MK_RES_CPU_ADD, 65537, 0, 0, false);
	expect("REGRESSION", "shutdown operation mismatch", finish(p), -ETIMEDOUT);

	/* Reject a confused outer/inner family before calling any handler. */
	msg->msg_type = MK_MSG_SYSTEM;
	msg->payload_len = 0;
	data.data_size = sizeof(*msg);
	mk_message_type_ipi_callback(&data, &handler);
	expect("REGRESSION", "outer/inner family mismatch", callbacks, 0);
	callbacks = 0;
	msg->msg_type = MK_MSG_RESOURCE;
	mk_message_type_ipi_callback(&data, &handler);
	expect("REGRESSION", "matching family reaches handler", callbacks, 1);
}

static void regressions(void)
{
	const struct {
		const char *name;
		u32 type, op;
	} stale[] = {
		{ "delayed CPU_ADD A must not complete B", MK_MSG_RESOURCE, MK_RES_CPU_ADD },
		{ "delayed CPU_REMOVE A must not complete B", MK_MSG_RESOURCE, MK_RES_CPU_REMOVE },
		{ "delayed SHUTDOWN A must not complete B", MK_MSG_SYSTEM, MK_SYS_SHUTDOWN },
	};
	struct mk_pending_msg *p;
	u64 old_id;
	size_t i;

	/* Fix: allocate and echo distinct request IDs, then match them. */
	for (i = 0; i < ARRAY_SIZE(stale); i++) {
		p = pending(stale[i].type, stale[i].op);
		assert(!mk_send_message(1, stale[i].type, stale[i].op, NULL, 0));
		old_id = ((struct mk_message *)sent.buffer)->msg_id;
		assert(finish(p) == -ETIMEDOUT);
		p = pending(stale[i].type, stale[i].op);
		assert(!mk_send_message(1, stale[i].type, stale[i].op, NULL, 0));
		reply(stale[i].type, stale[i].op, 65537, 0, old_id, false);
		expect("REGRESSION", stale[i].name, finish(p), -ETIMEDOUT);
	}

	/* Proposed contract, not the baseline protocol: zero cannot authorize. */
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	cpu_ack();
	expect("REGRESSION", "zero msg_id must not authorize", finish(p), -ETIMEDOUT);
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	reply(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, 0, 42, false);
	expect("REGRESSION", "unissued msg_id must not authorize", finish(p), -ETIMEDOUT);

}

static void characterizations(void)
{
	const struct {
		const char *name;
		u32 type, op;
		u64 resource;
		bool short_ack;
	} reject[] = {
		{ "resource operation mismatch", MK_MSG_RESOURCE, MK_RES_CPU_REMOVE, 65537, false },
		{ "resource ID mismatch", MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65538, false },
		{ "short resource ACK", MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, true },
	};
	struct mk_pending_msg *p;
	size_t i;

	/* Isolate type: the system ACK handler would also normalize operation. */
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	mk_msg_pending_complete(MK_MSG_SYSTEM, MK_RES_CPU_ADD, 65537, 0);
	expect("CHARACTERIZATION", "message type mismatch", finish(p), -ETIMEDOUT);

	/* Breaks if matching loses a tuple check or short-ACK validation. */
	for (i = 0; i < ARRAY_SIZE(reject); i++) {
		p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
		reply(reject[i].type, reject[i].op, reject[i].resource,
		      0, 0, reject[i].short_ack);
		expect("CHARACTERIZATION", reject[i].name, finish(p), -ETIMEDOUT);
	}
	p = pending(MK_MSG_SYSTEM, MK_SYS_SHUTDOWN);
	reply(MK_MSG_SYSTEM, MK_SYS_SHUTDOWN, 65537, 0, 0, true);
	expect("CHARACTERIZATION", "short shutdown ACK", finish(p), -ETIMEDOUT);

	/* Breaks if wait forgets cleanup, ignores completion or changes its result. */
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	expect("CHARACTERIZATION", "timeout removes pending A", finish(p), -ETIMEDOUT);
	cpu_ack(); /* Late reply after free, with no replacement: must be harmless. */
	assert(list_empty(&mk_pending_msgs));
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	expect("CHARACTERIZATION", "ACK after cleanup is not saved for B", finish(p), -ETIMEDOUT);
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	at_timeout = cpu_ack;
	expect("CHARACTERIZATION", "ACK after timeout decision still cleans up",
	       finish(p), -ETIMEDOUT);
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	cpu_ack();
	cpu_ack();
	expect("CHARACTERIZATION", "identical duplicate returns success", finish(p), 0);
	cpu_ack(); /* Also harmless after a successful wait frees the request. */
	assert(list_empty(&mk_pending_msgs));
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	reply(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, -EIO, 0, false);
	expect("CHARACTERIZATION", "matching error is returned", finish(p), -EIO);
}

int main(int argc, char **argv)
{
	if (argc > 2 || (argc == 2 && strcmp(argv[1], "regression") &&
			strcmp(argv[1], "characterization") &&
			strcmp(argv[1], "completion"))) {
		fprintf(stderr, "usage: ack_test [regression|characterization|completion]\n");
		return 2;
	}
	if (argc == 1 || !strcmp(argv[1], "regression") ||
	    !strcmp(argv[1], "completion"))
		completion_regressions();
	if (argc == 1 || !strcmp(argv[1], "regression"))
		regressions();
	if (argc == 1 || !strcmp(argv[1], "characterization"))
		characterizations();
	return failures ? 1 : 0;
}
