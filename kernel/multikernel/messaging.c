// SPDX-License-Identifier: GPL-2.0-only
/*
 * Multikernel Messaging System
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * The multikernel messaging layer on top of IPI infrastructure
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/err.h>
#include <linux/limits.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/multikernel.h>

/* Pending message tracking for request-response pattern */
struct mk_pending_msg {
	u64 msg_id;                 /* Nonzero, never reused during this kernel boot */
	u32 msg_type;               /* Message type (e.g., MK_MSG_RESOURCE) */
	u32 operation;              /* Operation subtype (e.g., MK_RES_CPU_ADD) */
	u64 resource_id;            /* Resource identifier (physical CPU ID, PFN, etc.) */
	int result;                 /* Operation result */
	bool completed;             /* First reply wins, even after the waiter wakes */
	struct completion done;     /* Completion for waiting */
	struct list_head list;      /* List linkage */
};

static LIST_HEAD(mk_pending_msgs);
static DEFINE_RAW_SPINLOCK(mk_pending_msgs_lock);
static u64 mk_last_msg_id;

/* Per-type message handler registry */
struct mk_msg_type_handler {
	u32 msg_type;
	struct mk_ipi_handler *ipi_handler;
	mk_msg_handler_t msg_handler;
	void *context;
	struct mk_msg_type_handler *next;
};

static struct mk_msg_type_handler *mk_msg_type_handlers;
/*
 * Process-context writers only. Callbacks use their immutable type_handler,
 * never this registry or its mutex, and must not register/unregister handlers.
 * Writers must not hold callback-owned locks while waiting for retirement.
 */
static DEFINE_MUTEX(mk_msg_type_handlers_lock);
static bool mk_messaging_initialized;
static bool mk_messaging_accepting;

/**
 * mk_message_type_ipi_callback - IPI callback to handle incoming messages for a specific type
 * @data: IPI data containing the message
 * @ctx: Context containing the message handler info
 */
static void mk_message_type_ipi_callback(struct mk_ipi_data *data, void *ctx)
{
	struct mk_msg_type_handler *type_handler = (struct mk_msg_type_handler *)ctx;
	struct mk_message *msg;
	u32 msg_type, msg_subtype;
	void *payload;
	u32 payload_len;

	if (!type_handler || !type_handler->msg_handler) {
		pr_warn("Multikernel message received but no handler registered\n");
		return;
	}

	/* Verify this matches our expected message type */
	if (data->type != type_handler->msg_type) {
		pr_warn("Multikernel message type mismatch: expected 0x%x, got 0x%x\n",
			type_handler->msg_type, data->type);
		return;
	}

	/* Ensure we have at least a message header */
	if (data->data_size < sizeof(struct mk_message)) {
		pr_warn("Multikernel message too small: %zu bytes\n", data->data_size);
		return;
	}

	msg = (struct mk_message *)data->buffer;
	if (msg->msg_type != data->type)
		return;

	/* Validate message structure */
	if (msg->payload_len > (data->data_size - sizeof(struct mk_message))) {
		pr_warn("Multikernel message payload length invalid: %u > %zu\n",
			msg->payload_len, data->data_size - sizeof(struct mk_message));
		return;
	}

	msg_type = msg->msg_type;
	msg_subtype = msg->msg_subtype;
	payload = msg->payload_len > 0 ? msg->payload : NULL;
	payload_len = msg->payload_len;

	pr_debug("Multikernel message received: type=0x%x, subtype=0x%x, len=%u from CPU %llu\n",
		 msg_type, msg_subtype, payload_len, data->sender_cpu);

	/* Call the registered handler for this message type */
	type_handler->msg_handler(msg_type, msg_subtype, msg->msg_id,
				  payload, payload_len, type_handler->context);
}

/*
 * Pending message tracking for request-response pattern
 */

/**
 * mk_msg_pending_add - Register a pending operation awaiting response
 * @msg_type: Message type
 * @operation: Operation subtype
 * @resource_id: Resource identifier
 *
 * Returns a pending message, or ERR_PTR(-ENOMEM/-EOVERFLOW).
 * The requester must consume it exactly once with wait or cancel.
 */
struct mk_pending_msg *mk_msg_pending_add(u32 msg_type, u32 operation, u64 resource_id)
{
	struct mk_pending_msg *pending;
	unsigned long flags;

	pending = kzalloc(sizeof(*pending), GFP_KERNEL);
	if (!pending)
		return ERR_PTR(-ENOMEM);

	pending->msg_type = msg_type;
	pending->operation = operation;
	pending->resource_id = resource_id;
	pending->result = -ETIMEDOUT;  /* Default to timeout */
	init_completion(&pending->done);

	raw_spin_lock_irqsave(&mk_pending_msgs_lock, flags);
	/* IDs are boot-local: exhaustion must fail, never wrap into an old ID. */
	if (mk_last_msg_id == U64_MAX) {
		raw_spin_unlock_irqrestore(&mk_pending_msgs_lock, flags);
		kfree(pending);
		return ERR_PTR(-EOVERFLOW);
	}
	pending->msg_id = ++mk_last_msg_id;
	list_add(&pending->list, &mk_pending_msgs);
	raw_spin_unlock_irqrestore(&mk_pending_msgs_lock, flags);

	return pending;
}

u64 mk_msg_pending_id(const struct mk_pending_msg *pending)
{
	return pending->msg_id;
}

/* Local cleanup only: does not cancel a request already delivered to a peer. */
void mk_msg_pending_cancel(struct mk_pending_msg *pending)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&mk_pending_msgs_lock, flags);
	list_del(&pending->list);
	raw_spin_unlock_irqrestore(&mk_pending_msgs_lock, flags);
	kfree(pending);
}

/**
 * mk_msg_pending_complete - Mark a pending operation as complete
 * @msg_type: Message type
 * @operation: Operation subtype
 * @resource_id: Resource identifier
 * @msg_id: Nonzero request ID echoed by the responder
 * @result: Operation result (0 = success, negative = error)
 *
 * Called by response handlers to wake up waiting thread
 */
void mk_msg_pending_complete(u32 msg_type, u32 operation, u64 resource_id,
			     u64 msg_id, int result)
{
	struct mk_pending_msg *pending;
	unsigned long flags;

	raw_spin_lock_irqsave(&mk_pending_msgs_lock, flags);
	list_for_each_entry(pending, &mk_pending_msgs, list) {
		if (pending->msg_id == msg_id &&
		    pending->msg_type == msg_type &&
		    pending->operation == operation &&
		    pending->resource_id == resource_id) {
			if (!pending->completed) {
				pending->result = result;
				pending->completed = true;
				complete(&pending->done);
			}
			break;
		}
	}
	raw_spin_unlock_irqrestore(&mk_pending_msgs_lock, flags);
}

/**
 * mk_msg_pending_wait - Wait for pending operation to complete
 * @pending: Pending message structure
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns operation result (0 = success, negative = error or timeout)
 */
int mk_msg_pending_wait(struct mk_pending_msg *pending, unsigned long timeout_ms)
{
	unsigned long timeout = msecs_to_jiffies(timeout_ms);
	unsigned long flags;
	unsigned long completed;
	int result;

	completed = wait_for_completion_timeout(&pending->done, timeout);
	if (!completed)
		pr_err("Timeout waiting for operation 0x%x on resource %llu\n",
		       pending->operation, pending->resource_id);

	/* A reply arriving after the wait timed out cannot undo the timeout. */
	raw_spin_lock_irqsave(&mk_pending_msgs_lock, flags);
	result = completed ? pending->result : -ETIMEDOUT;
	list_del(&pending->list);
	raw_spin_unlock_irqrestore(&mk_pending_msgs_lock, flags);
	kfree(pending);

	return result;
}

/**
 * mk_build_and_send - Build a message for an ID or referenced instance
 * @instance_id: Target multikernel instance ID
 * @instance: Referenced target, or NULL for an ID lookup
 * @msg_type: Message type identifier
 * @subtype: Message subtype
 * @msg_id: Request ID, or zero for an uncorrelated message
 * @payload: Pointer to payload data (can be NULL)
 * @payload_len: Length of payload data
 *
 * Returns 0 on success, negative error code on failure
 */
static int mk_build_and_send(int instance_id, struct mk_instance *instance,
			     u32 msg_type, u32 subtype, u64 msg_id, void *payload,
			     u32 payload_len)
{
	struct mk_message *msg;
	size_t total_size;
	int ret;

	/* Calculate total message size */
	total_size = sizeof(struct mk_message) + payload_len;

	/* Check if message fits in IPI buffer */
	if (total_size > MK_MAX_DATA_SIZE) {
		pr_err("Multikernel message too large: %zu > %d bytes\n",
		       total_size, MK_MAX_DATA_SIZE);
		return -EMSGSIZE;
	}

	/* Allocate temporary buffer for message */
	msg = kzalloc(total_size, GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;

	/* Fill in message header */
	msg->msg_type = msg_type;
	msg->msg_subtype = subtype;
	msg->msg_id = msg_id;
	msg->payload_len = payload_len;

	/* Copy payload if provided */
	if (payload && payload_len > 0)
		memcpy(msg->payload, payload, payload_len);

	/* Send via IPI using the message type as IPI type */
	if (instance)
		ret = multikernel_send_ipi_data_to(instance, msg, total_size,
						   msg_type);
	else
		ret = multikernel_send_ipi_data(instance_id, msg, total_size,
						msg_type);

	/* Clean up temporary buffer */
	kfree(msg);

	if (ret < 0) {
		pr_err("Failed to send multikernel message: %d\n", ret);
		return ret;
	}

	pr_debug("Multikernel message sent: type=0x%x, subtype=0x%x, len=%u to instance %d\n",
		 msg_type, subtype, payload_len, instance_id);

	return 0;
}

int mk_send_message_id(int instance_id, u32 msg_type, u32 subtype, u64 msg_id,
		       void *payload, u32 payload_len)
{
	return mk_build_and_send(instance_id, NULL, msg_type, subtype, msg_id,
				 payload, payload_len);
}

int mk_send_message(int instance_id, u32 msg_type, u32 subtype,
		    void *payload, u32 payload_len)
{
	return mk_send_message_id(instance_id, msg_type, subtype, 0,
				  payload, payload_len);
}
EXPORT_SYMBOL(mk_send_message);

int mk_send_message_to(struct mk_instance *instance, u32 msg_type, u32 subtype,
		       void *payload, u32 payload_len)
{
	return mk_build_and_send(instance->id, instance, msg_type, subtype, 0,
				 payload, payload_len);
}
EXPORT_SYMBOL(mk_send_message_to);

/* On the requester's stack until the answer is in, or given up on */
struct mk_sync_request {
	struct list_head list;
	u64 seq;
	void *answer;
	u32 answer_len;
	bool done;
};

static LIST_HEAD(mk_sync_requests);
static DEFINE_RAW_SPINLOCK(mk_sync_requests_lock);
static atomic64_t mk_sync_seq;

u64 mk_request_seq(void)
{
	return atomic64_inc_return(&mk_sync_seq);
}
EXPORT_SYMBOL_GPL(mk_request_seq);

/**
 * mk_request_sync - Send a request to an instance and wait for its answer
 * @to: Instance to ask, a reference held by the caller
 * @msg_type: Message type
 * @subtype: Message subtype
 * @seq: Value from mk_request_seq(), also carried in @payload
 * @payload: Request
 * @payload_len: Length of @payload
 * @answer: Where the answer is copied
 * @answer_len: Size of @answer
 * @timeout_us: How long to wait
 *
 * Callable with interrupts off: the doorbell may never be taken here, so
 * the wait drains the ring itself. Not from a message handler, which
 * already holds the drain.
 *
 * Returns 0 once the answer is in @answer, -ETIMEDOUT, or another
 * negative error code if the request could not be sent.
 */
int mk_request_sync(struct mk_instance *to, u32 msg_type, u32 subtype, u64 seq,
		    void *payload, u32 payload_len, void *answer, u32 answer_len,
		    unsigned int timeout_us)
{
	struct mk_sync_request r = {
		.seq = seq,
		.answer = answer,
		.answer_len = answer_len,
	};
	ktime_t deadline;
	int ret;

	if (WARN_ON_ONCE(mk_ipi_in_drain()))
		return -EDEADLK;

	scoped_guard(raw_spinlock_irqsave, &mk_sync_requests_lock)
		list_add(&r.list, &mk_sync_requests);

	ret = mk_send_message_to(to, msg_type, subtype, payload, payload_len);
	deadline = ktime_add_us(ktime_get(), timeout_us);
	/* Pairs with mk_request_answer(): the answer is copied in before done */
	while (!ret && !smp_load_acquire(&r.done)) {
		mk_ipi_poll();
		if (ktime_after(ktime_get(), deadline))
			ret = -ETIMEDOUT;
		else
			udelay(1);
	}

	/* Off the list before the stack frame goes: a late answer finds nothing */
	scoped_guard(raw_spinlock_irqsave, &mk_sync_requests_lock)
		list_del(&r.list);

	return r.done ? 0 : ret;
}
EXPORT_SYMBOL_GPL(mk_request_sync);

/**
 * mk_request_answer - Hand an answer to the request waiting for it
 * @seq: The request's sequence number
 * @answer: The answer
 * @answer_len: Its length
 *
 * Called from the handler of the answer message. An answer nobody waits
 * for any more is dropped.
 */
void mk_request_answer(u64 seq, const void *answer, u32 answer_len)
{
	struct mk_sync_request *r;

	guard(raw_spinlock_irqsave)(&mk_sync_requests_lock);

	list_for_each_entry(r, &mk_sync_requests, list) {
		if (r->seq != seq)
			continue;
		memcpy(r->answer, answer, min(answer_len, r->answer_len));
		/* The answer must be visible to a waiter that sees done */
		smp_store_release(&r->done, true);
		return;
	}
}
EXPORT_SYMBOL_GPL(mk_request_answer);

/**
 * mk_register_msg_handler - Register handler for specific message type
 * @msg_type: Message type to handle
 * @handler: Handler function
 * @ctx: Context pointer passed to handler
 *
 * Process context only, never from a callback or with callback-owned locks held.
 * Returns 0 on success, negative error code on failure
 */
int mk_register_msg_handler(u32 msg_type, mk_msg_handler_t handler, void *ctx)
{
	struct mk_msg_type_handler *type_handler;
	int ret;

	if (!handler)
		return -EINVAL;
	if (WARN_ON_ONCE(in_interrupt()))
		return -EWOULDBLOCK;

	mutex_lock(&mk_msg_type_handlers_lock);
	if (!mk_messaging_accepting) {
		ret = -ESHUTDOWN;
		goto unlock;
	}

	/* Check if handler for this type already exists */
	for (type_handler = mk_msg_type_handlers; type_handler; type_handler = type_handler->next) {
		if (type_handler->msg_type == msg_type) {
			pr_warn("Handler for message type 0x%x already registered\n", msg_type);
			ret = -EEXIST;
			goto unlock;
		}
	}

	/* Allocate new type handler entry */
	type_handler = kzalloc(sizeof(*type_handler), GFP_KERNEL);
	if (!type_handler) {
		ret = -ENOMEM;
		goto unlock;
	}

	type_handler->msg_type = msg_type;
	type_handler->msg_handler = handler;
	type_handler->context = ctx;

	/* Register IPI handler for this message type */
	type_handler->ipi_handler = multikernel_register_handler(mk_message_type_ipi_callback,
									 type_handler, msg_type);
	if (!type_handler->ipi_handler) {
		pr_err("Failed to register IPI handler for message type 0x%x\n", msg_type);
		kfree(type_handler);
		ret = -ENOMEM;
		goto unlock;
	}

	/* Add to type handler list */
	type_handler->next = mk_msg_type_handlers;
	mk_msg_type_handlers = type_handler;

	pr_debug("Registered multikernel message handler for type 0x%x\n", msg_type);
	ret = 0;
unlock:
	mutex_unlock(&mk_msg_type_handlers_lock);
	return ret;
}
EXPORT_SYMBOL(mk_register_msg_handler);

/**
 * mk_unregister_msg_handler - Unregister message handler
 * @msg_type: Message type to unregister
 * @handler: Handler function to remove
 *
 * Process context only, never from a callback or with callback-owned locks held.
 * Drains entered callbacks before the caller may release its context.
 * Returns 0 on success, negative error code on failure
 */
int mk_unregister_msg_handler(u32 msg_type, mk_msg_handler_t handler)
{
	struct mk_msg_type_handler **pp, *type_handler;
	int found = 0;

	if (!handler)
		return -EINVAL;
	if (WARN_ON_ONCE(in_interrupt()))
		return -EWOULDBLOCK;

	mutex_lock(&mk_msg_type_handlers_lock);
	pp = &mk_msg_type_handlers;
	while ((type_handler = *pp) != NULL) {
		if (type_handler->msg_type == msg_type && type_handler->msg_handler == handler) {
			*pp = type_handler->next;
			found = 1;
			break;
		}
		pp = &type_handler->next;
	}

	if (found) {
		/* Keep same-type insertion excluded until old callbacks have returned. */
		if (type_handler->ipi_handler) {
			multikernel_unregister_handler(type_handler->ipi_handler);
		}
		kfree(type_handler);
		mutex_unlock(&mk_msg_type_handlers_lock);
		pr_debug("Unregistered multikernel message handler for type 0x%x\n", msg_type);
		return 0;
	}

	mutex_unlock(&mk_msg_type_handlers_lock);
	return -ENOENT;
}
EXPORT_SYMBOL(mk_unregister_msg_handler);

/**
 * mk_messaging_init - Initialize the messaging system
 *
 * Called during multikernel initialization to set up message handling
 * Returns 0 on success, negative error code on failure
 */
int __init mk_messaging_init(void)
{
	mutex_lock(&mk_msg_type_handlers_lock);
	if (mk_messaging_initialized) {
		mutex_unlock(&mk_msg_type_handlers_lock);
		return -EALREADY;
	}
	mk_messaging_initialized = true;
	mk_messaging_accepting = true;
	mutex_unlock(&mk_msg_type_handlers_lock);

	/* No global IPI handler needed anymore - handlers are registered per message type */
	pr_info("Multikernel messaging system initialized\n");
	return 0;
}

/**
 * mk_messaging_cleanup - Cleanup the messaging system
 *
 * Process context only; no callback-owned locks may be held.
 * Closes registration permanently, then drains entered callbacks.
 */
void mk_messaging_cleanup(void)
{
	struct mk_msg_type_handler *type_handler, *next;

	if (WARN_ON_ONCE(in_interrupt()))
		return;

	/* Clean up all registered message type handlers */
	mutex_lock(&mk_msg_type_handlers_lock);
	mk_messaging_initialized = true;
	mk_messaging_accepting = false;
	type_handler = mk_msg_type_handlers;
	mk_msg_type_handlers = NULL;

	/* The mutex is never callback-owned; concurrent cleanup also waits here. */
	while (type_handler) {
		next = type_handler->next;

		/* Unregister IPI handler */
		if (type_handler->ipi_handler) {
			multikernel_unregister_handler(type_handler->ipi_handler);
		}

		kfree(type_handler);
		type_handler = next;
	}
	mutex_unlock(&mk_msg_type_handlers_lock);

	pr_info("Multikernel messaging system cleaned up\n");
}
