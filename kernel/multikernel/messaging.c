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
#include <linux/multikernel.h>

/* Pending message tracking for request-response pattern */
struct mk_pending_msg {
	u32 msg_type;               /* Message type (e.g., MK_MSG_RESOURCE) */
	u32 operation;              /* Operation subtype (e.g., MK_RES_CPU_ADD) */
	u32 resource_id;            /* Resource identifier (CPU ID, PFN, etc.) */
	int result;                 /* Operation result */
	struct completion done;     /* Completion for waiting */
	struct list_head list;      /* List linkage */
};

static LIST_HEAD(mk_pending_msgs);
static DEFINE_SPINLOCK(mk_pending_msgs_lock);

/* Per-type message handler registry */
struct mk_msg_type_handler {
	u32 msg_type;
	struct mk_ipi_handler *ipi_handler;
	mk_msg_handler_t msg_handler;
	void *context;
	struct mk_msg_type_handler *next;
};

static struct mk_msg_type_handler *mk_msg_type_handlers;
static raw_spinlock_t mk_msg_type_handlers_lock = __RAW_SPIN_LOCK_UNLOCKED(mk_msg_type_handlers_lock);

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

	pr_debug("Multikernel message received: type=0x%x, subtype=0x%x, len=%u from CPU %d\n",
		 msg_type, msg_subtype, payload_len, data->sender_cpu);

	/* Call the registered handler for this message type */
	type_handler->msg_handler(msg_type, msg_subtype, payload, payload_len, type_handler->context);
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
 * Returns pointer to pending message structure, or NULL on failure
 */
struct mk_pending_msg *mk_msg_pending_add(u32 msg_type, u32 operation, u32 resource_id)
{
	struct mk_pending_msg *pending;
	unsigned long flags;

	pending = kzalloc(sizeof(*pending), GFP_KERNEL);
	if (!pending)
		return NULL;

	pending->msg_type = msg_type;
	pending->operation = operation;
	pending->resource_id = resource_id;
	pending->result = -ETIMEDOUT;  /* Default to timeout */
	init_completion(&pending->done);

	spin_lock_irqsave(&mk_pending_msgs_lock, flags);
	list_add(&pending->list, &mk_pending_msgs);
	spin_unlock_irqrestore(&mk_pending_msgs_lock, flags);

	return pending;
}

/**
 * mk_msg_pending_complete - Mark a pending operation as complete
 * @msg_type: Message type
 * @operation: Operation subtype
 * @resource_id: Resource identifier
 * @result: Operation result (0 = success, negative = error)
 *
 * Called by response handlers to wake up waiting thread
 */
void mk_msg_pending_complete(u32 msg_type, u32 operation, u32 resource_id, int result)
{
	struct mk_pending_msg *pending;
	unsigned long flags;

	spin_lock_irqsave(&mk_pending_msgs_lock, flags);
	list_for_each_entry(pending, &mk_pending_msgs, list) {
		if (pending->msg_type == msg_type &&
		    pending->operation == operation &&
		    pending->resource_id == resource_id) {
			pending->result = result;
			complete(&pending->done);
			break;
		}
	}
	spin_unlock_irqrestore(&mk_pending_msgs_lock, flags);
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
	int result;

	if (!wait_for_completion_timeout(&pending->done, timeout)) {
		pr_err("Timeout waiting for operation 0x%x on resource %u\n",
		       pending->operation, pending->resource_id);
		result = -ETIMEDOUT;
	} else {
		result = pending->result;
	}

	/* Remove from list and free */
	spin_lock_irqsave(&mk_pending_msgs_lock, flags);
	list_del(&pending->list);
	spin_unlock_irqrestore(&mk_pending_msgs_lock, flags);
	kfree(pending);

	return result;
}

/**
 * mk_send_message - Send a message to another multikernel instance
 * @instance_id: Target multikernel instance ID
 * @msg_type: Message type identifier
 * @subtype: Message subtype
 * @payload: Pointer to payload data (can be NULL)
 * @payload_len: Length of payload data
 *
 * Returns 0 on success, negative error code on failure
 */
int mk_send_message(int instance_id, u32 msg_type, u32 subtype,
		    void *payload, u32 payload_len)
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
	msg->msg_id = 0; /* Could be enhanced with unique IDs later */
	msg->payload_len = payload_len;

	/* Copy payload if provided */
	if (payload && payload_len > 0)
		memcpy(msg->payload, payload, payload_len);

	/* Send via IPI using the message type as IPI type */
	ret = multikernel_send_ipi_data(instance_id, msg, total_size, msg_type);

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
EXPORT_SYMBOL(mk_send_message);

/**
 * mk_register_msg_handler - Register handler for specific message type
 * @msg_type: Message type to handle
 * @handler: Handler function
 * @ctx: Context pointer passed to handler
 *
 * Returns 0 on success, negative error code on failure
 */
int mk_register_msg_handler(u32 msg_type, mk_msg_handler_t handler, void *ctx)
{
	struct mk_msg_type_handler *type_handler;
	unsigned long flags;

	if (!handler)
		return -EINVAL;

	/* Check if handler for this type already exists */
	raw_spin_lock_irqsave(&mk_msg_type_handlers_lock, flags);
	for (type_handler = mk_msg_type_handlers; type_handler; type_handler = type_handler->next) {
		if (type_handler->msg_type == msg_type) {
			raw_spin_unlock_irqrestore(&mk_msg_type_handlers_lock, flags);
			pr_warn("Handler for message type 0x%x already registered\n", msg_type);
			return -EEXIST;
		}
	}
	raw_spin_unlock_irqrestore(&mk_msg_type_handlers_lock, flags);

	/* Allocate new type handler entry */
	type_handler = kzalloc(sizeof(*type_handler), GFP_KERNEL);
	if (!type_handler)
		return -ENOMEM;

	type_handler->msg_type = msg_type;
	type_handler->msg_handler = handler;
	type_handler->context = ctx;

	/* Register IPI handler for this message type */
	type_handler->ipi_handler = multikernel_register_handler(mk_message_type_ipi_callback,
									 type_handler, msg_type);
	if (!type_handler->ipi_handler) {
		pr_err("Failed to register IPI handler for message type 0x%x\n", msg_type);
		kfree(type_handler);
		return -ENOMEM;
	}

	/* Add to type handler list */
	raw_spin_lock_irqsave(&mk_msg_type_handlers_lock, flags);
	type_handler->next = mk_msg_type_handlers;
	mk_msg_type_handlers = type_handler;
	raw_spin_unlock_irqrestore(&mk_msg_type_handlers_lock, flags);

	pr_debug("Registered multikernel message handler for type 0x%x\n", msg_type);
	return 0;
}
EXPORT_SYMBOL(mk_register_msg_handler);

/**
 * mk_unregister_msg_handler - Unregister message handler
 * @msg_type: Message type to unregister
 * @handler: Handler function to remove
 *
 * Returns 0 on success, negative error code on failure
 */
int mk_unregister_msg_handler(u32 msg_type, mk_msg_handler_t handler)
{
	struct mk_msg_type_handler **pp, *type_handler;
	unsigned long flags;
	int found = 0;

	if (!handler)
		return -EINVAL;

	raw_spin_lock_irqsave(&mk_msg_type_handlers_lock, flags);
	pp = &mk_msg_type_handlers;
	while ((type_handler = *pp) != NULL) {
		if (type_handler->msg_type == msg_type && type_handler->msg_handler == handler) {
			*pp = type_handler->next;
			found = 1;
			break;
		}
		pp = &type_handler->next;
	}
	raw_spin_unlock_irqrestore(&mk_msg_type_handlers_lock, flags);

	if (found) {
		/* Unregister the IPI handler */
		if (type_handler->ipi_handler) {
			multikernel_unregister_handler(type_handler->ipi_handler);
		}
		kfree(type_handler);
		pr_debug("Unregistered multikernel message handler for type 0x%x\n", msg_type);
		return 0;
	}

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
	/* No global IPI handler needed anymore - handlers are registered per message type */
	pr_info("Multikernel messaging system initialized\n");
	return 0;
}

/**
 * mk_messaging_cleanup - Cleanup the messaging system
 *
 * Called during multikernel cleanup
 */
void mk_messaging_cleanup(void)
{
	struct mk_msg_type_handler *type_handler, *next;
	unsigned long flags;

	/* Clean up all registered message type handlers */
	raw_spin_lock_irqsave(&mk_msg_type_handlers_lock, flags);
	type_handler = mk_msg_type_handlers;
	mk_msg_type_handlers = NULL;
	raw_spin_unlock_irqrestore(&mk_msg_type_handlers_lock, flags);

	while (type_handler) {
		next = type_handler->next;

		/* Unregister IPI handler */
		if (type_handler->ipi_handler) {
			multikernel_unregister_handler(type_handler->ipi_handler);
		}

		kfree(type_handler);
		type_handler = next;
	}

	pr_info("Multikernel messaging system cleaned up\n");
}
