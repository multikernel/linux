// SPDX-License-Identifier: GPL-2.0-only
/* Extracted messaging code; pthread-controlled, non-native IRQ/RCU boundary. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

typedef uint32_t u32;
typedef uint64_t u64;
#define __init
#define GFP_KERNEL 0
#define EXPORT_SYMBOL(x)
#define pr_warn(...) do { } while (0)
#define pr_err(...) do { } while (0)
#define pr_info(...) do { } while (0)
#define pr_debug(...) do { } while (0)
#define WARN_ON_ONCE(x) (!!(x))
static _Thread_local bool interrupt_context;
#define in_interrupt() interrupt_context
static _Thread_local unsigned int role;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool blocked, backend_first, backend_second, hold_register, release_register;
static bool callback_entered, release_callback, grace_entered;
static bool retirement_done, register_done, early_free;
static unsigned int live_handlers, readers;
static int allocation_fail_after = -1;
static void *entered_context;

typedef pthread_mutex_t raw_spinlock_t;
#define __RAW_SPIN_LOCK_UNLOCKED(n) PTHREAD_MUTEX_INITIALIZER
#define DEFINE_MUTEX(n) pthread_mutex_t n = PTHREAD_MUTEX_INITIALIZER
static void writer_lock(pthread_mutex_t *lock)
{
	int ret = pthread_mutex_trylock(lock);

	if (ret == EBUSY) {
		assert(!pthread_mutex_lock(&gate));
		if (role == 2) {
			blocked = true;
			assert(!pthread_cond_broadcast(&changed));
		}
		assert(!pthread_mutex_unlock(&gate));
		ret = pthread_mutex_lock(lock);
	}
	assert(!ret);
}
#define mutex_lock(m) writer_lock(m)
#define mutex_unlock(m) assert(!pthread_mutex_unlock(m))
#define raw_spin_lock_irqsave(m, flags) \
	do { (flags) = 0; writer_lock(m); } while (0)
#define raw_spin_unlock_irqrestore(m, flags) \
	do { (void)(flags); mutex_unlock(m); } while (0)

static void *kzalloc(size_t size, int flags)
{
	(void)flags;
	if (allocation_fail_after == 0)
		return NULL;
	if (allocation_fail_after > 0)
		allocation_fail_after--;
	return calloc(1, size);
}

static void kfree(void *ptr)
{
	assert(!pthread_mutex_lock(&gate));
	if (ptr == entered_context && readers)
		early_free = true;
	assert(!pthread_mutex_unlock(&gate));
	free(ptr);
}

struct mk_message { u32 msg_type, msg_subtype; u64 msg_id; u32 payload_len; char payload[]; };
struct mk_ipi_data { u32 type; size_t data_size; void *buffer; u64 sender_cpu; };
typedef void (*mk_msg_handler_t)(u32, u32, u64, void *, u32, void *);
struct mk_ipi_handler {
	void (*callback)(struct mk_ipi_data *, void *);
	void *context;
};

static struct mk_ipi_handler *multikernel_register_handler(
	void (*callback)(struct mk_ipi_data *, void *), void *ctx, unsigned int type)
{
	struct mk_ipi_handler *handler = kzalloc(sizeof(*handler), GFP_KERNEL);

	(void)type;
	if (!handler)
		return NULL;
	handler->callback = callback;
	handler->context = ctx;
	assert(!pthread_mutex_lock(&gate));
	if (role == 1) {
		backend_first = true;
		assert(!pthread_cond_broadcast(&changed));
	}
	if (role == 2) {
		backend_second = true;
		assert(!pthread_cond_broadcast(&changed));
	}
	while (role == 1 && hold_register && !release_register)
		assert(!pthread_cond_wait(&changed, &gate));
	live_handlers++;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	return handler;
}

static void multikernel_unregister_handler(struct mk_ipi_handler *handler)
{
	assert(!interrupt_context);
	assert(!pthread_mutex_lock(&gate));
	grace_entered = true;
	assert(!pthread_cond_broadcast(&changed));
	/* Modeled unlink/grace period, not a native RCU implementation. */
	while (readers)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(live_handlers);
	live_handlers--;
	assert(!pthread_mutex_unlock(&gate));
	kfree(handler);
}

#include "registry-production.h"

static int failures;
#define CHECK(expr, text) do { \
	if (!(expr)) { \
		fprintf(stderr, "FAIL: %s\n", text); \
		failures++; \
	} \
} while (0)

static void callback(u32 type, u32 subtype, u64 id, void *payload, u32 len, void *ctx)
{
	assert(type == 17 && subtype == 2 && id == 3 && !payload && !len && ctx == &readers);
	assert(!pthread_mutex_lock(&gate));
	callback_entered = true;
	assert(!pthread_cond_broadcast(&changed));
	while (!release_callback)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!pthread_mutex_unlock(&gate));
}

struct operation { int result; bool cleanup; };
static void *register_thread(void *arg)
{
	struct operation *op = arg;

	role = op->cleanup ? 1 : 2;
	op->result = mk_register_msg_handler(17, callback, &readers);
	assert(!pthread_mutex_lock(&gate));
	register_done = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	return NULL;
}

static void *retire_thread(void *arg)
{
	struct operation *op = arg;

	if (op->cleanup)
		mk_messaging_cleanup();
	else
		op->result = mk_unregister_msg_handler(17, callback);
	assert(!pthread_mutex_lock(&gate));
	retirement_done = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	return NULL;
}

static void *dispatch_thread(void *arg)
{
	struct mk_ipi_handler *handler = arg;
	struct mk_message msg = { .msg_type = 17, .msg_subtype = 2, .msg_id = 3 };
	struct mk_ipi_data data = { .type = 17, .data_size = sizeof(msg), .buffer = &msg };

	assert(!pthread_mutex_lock(&gate));
	readers++;
	entered_context = handler->context;
	assert(!pthread_mutex_unlock(&gate));
	interrupt_context = true;
	handler->callback(&data, handler->context);
	interrupt_context = false;
	assert(!pthread_mutex_lock(&gate));
	readers--;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	return NULL;
}

static void duplicate_case(void)
{
	pthread_t first, second;
	struct operation a = { .cleanup = true }, b = { 0 };

	assert(!mk_messaging_init());
	hold_register = true;
	assert(!pthread_create(&first, NULL, register_thread, &a));
	/* First writer reached backend registration, before production insertion. */
	assert(!pthread_mutex_lock(&gate));
	while (!backend_first)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_create(&second, NULL, register_thread, &b));
	assert(!pthread_mutex_lock(&gate));
	while (!blocked && !backend_second)
		assert(!pthread_cond_wait(&changed, &gate));
	release_register = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_join(first, NULL));
	assert(!pthread_join(second, NULL));
	CHECK(a.result == 0 && b.result == -EEXIST && live_handlers == 1,
	      "same-type concurrent registration must have exactly one success");
	mk_messaging_cleanup();
}

static void retirement_case(bool cleanup)
{
	pthread_t receive, retire, insert;
	struct operation removal = { .cleanup = cleanup }, registration = { 0 };
	bool overlapped;

	assert(!mk_messaging_init());
	assert(!mk_register_msg_handler(17, callback, &readers));
	assert(!pthread_create(&receive, NULL, dispatch_thread, mk_msg_type_handlers->ipi_handler));
	assert(!pthread_mutex_lock(&gate));
	while (!callback_entered)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_create(&retire, NULL, retire_thread, &removal));
	assert(!pthread_mutex_lock(&gate));
	while (!grace_entered)
		assert(!pthread_cond_wait(&changed, &gate));
	CHECK(!retirement_done && readers == 1 && !early_free,
	      "entered callback context must survive retirement");
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_create(&insert, NULL, register_thread, &registration));
	assert(!pthread_mutex_lock(&gate));
	while (!blocked && !backend_second && !register_done)
		assert(!pthread_cond_wait(&changed, &gate));
	overlapped = backend_second;
	release_callback = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_join(receive, NULL));
	assert(!pthread_join(retire, NULL));
	assert(!pthread_join(insert, NULL));
	CHECK(!overlapped && !early_free, "new same-type registration must wait for old callback retirement");
	if (cleanup) {
		CHECK(registration.result == -ESHUTDOWN && !mk_msg_type_handlers && !live_handlers,
		      "cleanup must close admission and leave no surviving registration");
		CHECK(mk_register_msg_handler(18, callback, NULL) == -ESHUTDOWN,
		      "registration after completed cleanup must fail");
	} else {
		CHECK(removal.result == 0 && registration.result == 0 && live_handlers == 1,
		      "registration may succeed after unregister has drained the callback");
	}
	mk_messaging_cleanup();
}

static void cleanup_case(void) { retirement_case(true); }
static void unregister_case(void) { retirement_case(false); }

static void *second_cleanup_thread(void *arg)
{
	role = 2;
	return retire_thread(arg);
}

static void concurrent_cleanup_case(void)
{
	pthread_t receive, first, second;
	struct operation a = { .cleanup = true }, b = { .cleanup = true };

	assert(!mk_messaging_init());
	assert(!mk_register_msg_handler(17, callback, &readers));
	assert(!pthread_create(&receive, NULL, dispatch_thread, mk_msg_type_handlers->ipi_handler));
	assert(!pthread_mutex_lock(&gate));
	while (!callback_entered)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_create(&first, NULL, retire_thread, &a));
	assert(!pthread_mutex_lock(&gate));
	while (!grace_entered)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_create(&second, NULL, second_cleanup_thread, &b));
	assert(!pthread_mutex_lock(&gate));
	while (!blocked && !retirement_done)
		assert(!pthread_cond_wait(&changed, &gate));
	CHECK(!retirement_done, "every concurrent cleanup must wait for callback retirement");
	release_callback = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_join(receive, NULL));
	assert(!pthread_join(first, NULL));
	assert(!pthread_join(second, NULL));
	CHECK(!live_handlers && !mk_msg_type_handlers && !early_free,
	      "concurrent cleanup retires each handler exactly once");
}

static void admission_case(void)
{
	CHECK(mk_register_msg_handler(17, callback, NULL) == -ESHUTDOWN,
	      "registration before init must fail");
	mk_messaging_cleanup();
	CHECK(mk_messaging_init() < 0, "cleanup must prevent a later init reopening admission");
	CHECK(mk_register_msg_handler(18, callback, NULL) == -ESHUTDOWN,
	      "initialization cannot reopen cleaned-up messaging");
	mk_messaging_cleanup();
}

static void errors_case(void)
{
	assert(!mk_messaging_init());
	CHECK(mk_messaging_init() < 0, "initialization must open admission only once");
	CHECK(mk_register_msg_handler(17, NULL, NULL) == -EINVAL, "null registration handler");
	CHECK(mk_unregister_msg_handler(17, NULL) == -EINVAL, "null removal handler");
	CHECK(mk_unregister_msg_handler(17, callback) == -ENOENT, "missing handler");
	allocation_fail_after = 0;
	CHECK(mk_register_msg_handler(17, callback, NULL) == -ENOMEM, "entry allocation failure");
	allocation_fail_after = 1;
	CHECK(mk_register_msg_handler(17, callback, NULL) == -ENOMEM, "IPI allocation failure");
	allocation_fail_after = -1;
	CHECK(!mk_register_msg_handler(17, callback, &readers), "retry after allocation failure");
	CHECK(mk_register_msg_handler(17, callback, NULL) == -EEXIST, "duplicate handler");
	CHECK(!mk_unregister_msg_handler(17, callback) && !live_handlers, "successful retirement");
	mk_messaging_cleanup();
}

static void context_case(void)
{
	assert(!mk_messaging_init());
	assert(!mk_register_msg_handler(17, callback, &readers));
	interrupt_context = true;
	CHECK(mk_register_msg_handler(18, callback, NULL) == -EWOULDBLOCK,
	      "interrupt-context registration must be rejected");
	CHECK(mk_unregister_msg_handler(17, callback) == -EWOULDBLOCK,
	      "interrupt-context unregister must be rejected");
	mk_messaging_cleanup();
	CHECK(live_handlers == 1 && mk_msg_type_handlers,
	      "interrupt-context cleanup must leave the live registry untouched");
	interrupt_context = false;
	assert(!mk_unregister_msg_handler(17, callback));
	mk_messaging_cleanup();
}

int main(void)
{
	void (*cases[])(void) = { duplicate_case, cleanup_case, unregister_case,
		concurrent_cleanup_case, admission_case, errors_case, context_case };
	unsigned int i, failed = 0;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int status;
		pid_t child = fork();

		assert(child >= 0);
		if (!child) {
			alarm(10);
			cases[i]();
			exit(failures ? 1 : 0);
		}
		assert(waitpid(child, &status, 0) == child);
		if (!WIFEXITED(status) || WEXITSTATUS(status))
			failed++;
	}
	if (failed) {
		fprintf(stderr, "Messaging registry: %u/7 scenarios failed\n", failed);
		return 1;
	}
	puts("Messaging registry: 7 scenarios PASS (non-native IRQ/RCU boundaries)");
	return 0;
}
