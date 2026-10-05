// SPDX-License-Identifier: GPL-2.0-only
/* Extracted host mktty paths; controlled, non-native IRQ/scheduler boundaries. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <unistd.h>

typedef uint32_t u32;
typedef unsigned int __poll_t;
typedef int poll_table;
#define __user
#define MK_MAX_DATA_SIZE 32
#define GFP_KERNEL 0
#define pr_info(...) do { } while (0)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define kzalloc(n, flags) calloc(1, n)
#define kmalloc(n, flags) malloc(n)
#define copy_from_user(dst, src, n) (memcpy(dst, src, n), 0)
#define put_user(c, p) (*(p) = (c), 0)
static atomic_uint snapshots;
#define READ_ONCE(p) (atomic_fetch_add(&snapshots, 1), __atomic_load_n(&(p), __ATOMIC_RELAXED))
#define WRITE_ONCE(p, v) do { \
	assert(holds_connections && irq_disabled); \
	__atomic_store_n(&(p), (v), __ATOMIC_RELAXED); \
} while (0)

struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_for_each_entry(p, h, m) \
	for (struct list_head *cursor = (h)->next; cursor != (h) && \
	     ((p) = container_of(cursor, __typeof__(*(p)), m), 1); cursor = cursor->next)
static void list_add(struct list_head *node, struct list_head *head)
{
	node->next = head->next;
	node->prev = head;
	head->next->prev = node;
	head->next = node;
}
static void list_del(struct list_head *node)
{
	node->prev->next = node->next;
	node->next->prev = node->prev;
}

typedef pthread_mutex_t spinlock_t;
#define DEFINE_SPINLOCK(n) spinlock_t n = PTHREAD_MUTEX_INITIALIZER
static spinlock_t *connections_lock;
static _Thread_local bool irq_disabled, in_callback, holds_connections;
static bool inject_irq;
static unsigned int irq_hazards;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool callback_entered, release_callback, removal_blocked;
static bool pause_callback, race_selection;
static unsigned int selecting;
static atomic_uint freed;

static void spin_lock(spinlock_t *lock)
{
	int ret = pthread_mutex_trylock(lock);

	if (ret == EBUSY) {
		assert(!pthread_mutex_lock(&gate));
		if (lock == connections_lock && !in_callback) {
			removal_blocked = true;
			assert(!pthread_cond_broadcast(&changed));
		}
		assert(!pthread_mutex_unlock(&gate));
		ret = pthread_mutex_lock(lock);
	}
	assert(!ret);
	if (lock == connections_lock) {
		holds_connections = true;
		/* A same-CPU hardIRQ at this checkpoint would reacquire this lock. */
		if (inject_irq && !irq_disabled && !in_callback)
			irq_hazards++;
	}
}
static void spin_unlock(spinlock_t *lock)
{
	if (lock == connections_lock)
		holds_connections = false;
	assert(!pthread_mutex_unlock(lock));
}
#define spin_lock_init(p) assert(!pthread_mutex_init(p, NULL))
#define spin_lock_irqsave(p, flags) \
	do { (flags) = irq_disabled; irq_disabled = true; spin_lock(p); } while (0)
#define spin_unlock_irqrestore(p, flags) \
	do { spin_unlock(p); irq_disabled = (flags); } while (0)
#define lockdep_assert_held(p) assert(holds_connections && (p) == connections_lock)

typedef struct { int initialized; } wait_queue_head_t;
#define init_waitqueue_head(p) ((p)->initialized = 1)
#define wait_event_interruptible(w, condition) ((condition) ? 0 : -EINTR)
static void wake_up_interruptible(wait_queue_head_t *wait)
{
	assert(wait->initialized && in_callback && holds_connections && irq_disabled);
	if (!pause_callback)
		return;
	assert(!pthread_mutex_lock(&gate));
	callback_entered = true;
	assert(!pthread_cond_broadcast(&changed));
	while (!release_callback)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!atomic_load(&freed));
	assert(!pthread_mutex_unlock(&gate));
}

struct inode { int unused; };
struct file { void *private_data; int f_flags; };
static void poll_wait(struct file *file, wait_queue_head_t *wait, poll_table *table)
{
	assert(!holds_connections && wait->initialized);
}

static void kfree(void *ptr)
{
	assert(!holds_connections);
	if (ptr)
		atomic_fetch_add(&freed, 1);
	free(ptr);
}

static int kstrtoint(const char *str, int base, int *value)
{
	char *end;
	long parsed = strtol(str, &end, base);

	assert(!holds_connections && !irq_disabled);
	if (end == str || (*end && strcmp(end, "\n")))
		return -EINVAL;
	*value = parsed;
	return 0;
}

struct mk_instance { int id; };
static struct mk_instance instances[] = { { 1 }, { 2 } };
static struct mk_instance *mk_instance_find(int id)
{
	assert(!holds_connections && !irq_disabled);
	if (id < 1 || id > 2)
		return NULL;
	if (race_selection) {
		assert(!pthread_mutex_lock(&gate));
		selecting++;
		assert(!pthread_cond_broadcast(&changed));
		while (selecting < 2)
			assert(!pthread_cond_wait(&changed, &gate));
		assert(!pthread_mutex_unlock(&gate));
	}
	return &instances[id - 1];
}
static void mk_instance_put(struct mk_instance *instance)
{
	assert(instance && !holds_connections);
}

struct mk_ipi_data { void *buffer; size_t data_size; };
static unsigned int sends;
static int expected_target;
static int multikernel_send_ipi_data(int id, void *buf, size_t size, u32 type)
{
	assert(id == expected_target && !holds_connections && !irq_disabled);
	assert(buf && size >= 16 && type);
	sends++;
	return 0;
}

#include "mktty-production.h"

static int failures;
#define CHECK(expr, text) do { \
	if (!(expr)) { \
		fprintf(stderr, "FAIL: %s\n", text); \
		failures++; \
	} \
} while (0)

static void deliver(int id)
{
	struct mktty_message msg = { .type = MKTTY_MSG_OUTPUT, .console_id = id,
		.len = 1, .data = { 'x' } };
	struct mk_ipi_data data = { .buffer = &msg, .data_size = 17 };

	in_callback = true;
	irq_disabled = true;
	mktty_host_ipi_handler(&data, NULL);
	irq_disabled = false;
	in_callback = false;
}

static void irq_case(void)
{
	struct file file = { 0 };

	inject_irq = true;
	assert(!mktty_host_open(NULL, &file));
	assert(!mktty_host_release(NULL, &file));
	CHECK(!irq_hazards, "open/release list locks must exclude same-CPU hardIRQ reentry");
	CHECK(atomic_load(&freed) == 2 && mktty_host_conns.next == &mktty_host_conns,
	      "release must unlink before freeing connection and RX buffer");
}

static void *receive_thread(void *unused) { deliver(1); return NULL; }
static void *release_thread(void *file) { mktty_host_release(NULL, file); return NULL; }

static void lifetime_case(void)
{
	struct file file = { 0 };
	pthread_t receive, remove;

	assert(!mktty_host_open(NULL, &file));
	assert(mktty_host_write(&file, "1\n", 2, NULL) == 2);
	pause_callback = true;
	assert(!pthread_create(&receive, NULL, receive_thread, NULL));
	assert(!pthread_mutex_lock(&gate));
	while (!callback_entered)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_create(&remove, NULL, release_thread, &file));
	assert(!pthread_mutex_lock(&gate));
	while (!removal_blocked)
		assert(!pthread_cond_wait(&changed, &gate));
	CHECK(!atomic_load(&freed), "release must wait for callback's connection use");
	release_callback = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_join(receive, NULL));
	assert(!pthread_join(remove, NULL));
	CHECK(atomic_load(&freed) == 2, "release frees only after callback unlocks");
	pause_callback = false;
	deliver(1);
	CHECK(atomic_load(&freed) == 2, "callback after release must find no connection");
}

struct selection { struct file *file; const char *id; ssize_t result; };
static void *select_thread(void *arg)
{
	struct selection *selection = arg;

	selection->result = mktty_host_write(selection->file, selection->id, 2, NULL);
	return NULL;
}

static void target_case(void)
{
	struct file file = { 0 };
	struct selection a = { .file = &file, .id = "1\n" };
	struct selection b = { .file = &file, .id = "2\n" };
	pthread_t first, second;
	struct mktty_host_conn *conn;
	char input[MKTTY_MAX_DATA + 1] = { 'a' }, output;
	unsigned int reads_before;

	assert(!mktty_host_open(NULL, &file));
	race_selection = true;
	assert(!pthread_create(&first, NULL, select_thread, &a));
	assert(!pthread_create(&second, NULL, select_thread, &b));
	assert(!pthread_join(first, NULL));
	assert(!pthread_join(second, NULL));
	race_selection = false;
	conn = file.private_data;
	CHECK((a.result == 2 && b.result == -EISCONN && conn->instance_id == 1) ||
	      (b.result == 2 && a.result == -EISCONN && conn->instance_id == 2),
	      "competing first writes must publish one immutable connection target");
	expected_target = conn->instance_id;
	reads_before = snapshots;
	CHECK(mktty_host_write(&file, input, sizeof(input), NULL) == sizeof(input) && sends == 2,
	      "all data-write chunks use the selected target");
	CHECK(snapshots == reads_before + 1, "data write must snapshot target once");
	deliver(expected_target);
	reads_before = snapshots;
	CHECK(mktty_host_poll(&file, NULL) & EPOLLIN, "poll observes received byte");
	CHECK(mktty_host_read(&file, &output, 1, NULL) == 1 && output == 'x', "read receives callback byte");
	CHECK(snapshots == reads_before + 2, "read/poll must use marked target reads");
	assert(!mktty_host_release(NULL, &file));
}

static void validation_case(void)
{
	struct file file = { .f_flags = O_NONBLOCK };
	char output;

	assert(!mktty_host_open(NULL, &file));
	CHECK(mktty_host_read(&file, &output, 1, NULL) == -ENOTCONN, "unconnected read");
	CHECK(mktty_host_poll(&file, NULL) == (EPOLLOUT | EPOLLWRNORM), "unconnected poll");
	CHECK(mktty_host_write(&file, "0\n", 2, NULL) == -EINVAL, "invalid target");
	CHECK(mktty_host_write(&file, "3\n", 2, NULL) == -ENODEV, "missing target");
	CHECK(((struct mktty_host_conn *)file.private_data)->instance_id == -1,
	      "failed selection leaves connection unpublished");
	CHECK(mktty_host_write(&file, "1\n", 2, NULL) == 2, "selection after failure");
	CHECK(mktty_host_read(&file, &output, 1, NULL) == -EAGAIN, "connected nonblocking read");
	assert(!mktty_host_release(NULL, &file));
}

int main(void)
{
	void (*cases[])(void) = { irq_case, lifetime_case, target_case, validation_case };
	unsigned int i, failed = 0;

	connections_lock = &mktty_host_conns_lock;
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
		fprintf(stderr, "mktty lifetime: %u/4 scenarios failed\n", failed);
		return 1;
	}
	puts("mktty lifetime: 4 scenarios PASS (non-native IRQ/scheduler boundaries)");
	return 0;
}
