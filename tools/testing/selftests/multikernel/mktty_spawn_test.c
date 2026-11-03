// SPDX-License-Identifier: GPL-2.0-only
/* Actual MKTTY RX/worker functions; deterministic kernel API boundaries. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned char u8;
typedef int spinlock_t;
typedef int raw_spinlock_t;
#define MK_MAX_DATA_SIZE 4096
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
static bool in_irq, irq_disabled;
static unsigned int raw_depth, bad_context, calls, refs;
static unsigned long long reported_drops;
static unsigned char delivered[65536];
static size_t delivered_size, insert_limit = 65536;
static size_t flip_pending;
static void (*insert_hook)(void);
#define raw_spin_lock_init(p) (*(p) = 0)
#define raw_spin_lock_irqsave(p, flags) \
	do {                            \
		assert(!*(p));          \
		*(p) = 1;               \
		raw_depth++;            \
		(flags) = irq_disabled; \
		irq_disabled = true;    \
	} while (0)
#define raw_spin_unlock_irqrestore(p, flags) \
	do {                                 \
		assert(*(p));                \
		*(p) = 0;                    \
		raw_depth--;                 \
		irq_disabled = (flags);      \
	} while (0)
#define pr_warn_ratelimited(fmt, count)        \
	do {                                   \
		assert(!in_irq && !raw_depth); \
		reported_drops += (count);     \
	} while (0)

/* kfifo is a boundary, not an alternative implementation of the driver. */
struct fifo {
	unsigned char data[16384];
	unsigned int in, out;
};
#define DEFINE_KFIFO(name, type, size) struct fifo name
#define kfifo_len(f) ((f)->in - (f)->out)
#define kfifo_is_empty(f) (!kfifo_len(f))
#define kfifo_reset(f)                  \
	do {                            \
		assert(raw_depth);      \
		(f)->in = (f)->out = 0; \
	} while (0)
static unsigned int
	__attribute__((unused)) kfifo_in(struct fifo *f, const void *data,
					 unsigned int n)
{
	unsigned int i;
	assert(raw_depth);
	n = min_t(unsigned int, n, sizeof(f->data) - kfifo_len(f));
	for (i = 0; i < n; i++)
		f->data[f->in++ % sizeof(f->data)] = ((const u8 *)data)[i];
	return n;
}
static unsigned int __attribute__((unused))
kfifo_out(struct fifo *f, void *data, unsigned int n)
{
	unsigned int i;
	assert(raw_depth);
	n = min_t(unsigned int, n, kfifo_len(f));
	for (i = 0; i < n; i++)
		((u8 *)data)[i] = f->data[f->out++ % sizeof(f->data)];
	return n;
}

struct work_struct {
	void (*fn)(struct work_struct *);
	bool pending, running;
};
#define DECLARE_WORK(name, func) struct work_struct name = { .fn = func }
static struct work_struct *queued;
static unsigned int runs;
static bool __attribute__((unused)) schedule_work(struct work_struct *work)
{
	bool fresh = !work->pending;
	assert(raw_depth); /* enqueued before releasing admission/lifetime protection */
	work->pending = true;
	queued = work;
	return fresh;
}
static void __attribute__((unused)) cancel_work_sync(struct work_struct *work)
{
	assert(!in_irq && !raw_depth && !work->running);
	work->pending = false;
}
static void run_one(void)
{
	struct work_struct *work = queued;
	assert(work && work->pending && !work->running);
	work->pending = false;
	work->running = true;
	runs++;
	work->fn(work);
	work->running = false;
}
static void drain(void)
{
	unsigned int limit = 32;
	while (queued && queued->pending) {
		assert(limit--);
		run_one();
	}
}

struct tty_struct {
	int index;
} tty;
struct tty_port {
	bool open;
};
static void mktty_spawn_shutdown(struct tty_port *port);
static void tty_port_hangup(struct tty_port *port)
{
	port->open = false;
	mktty_spawn_shutdown(port);
}
static void __attribute__((unused)) tty_ldisc_flush(struct tty_struct *t)
{
	assert(t == &tty && !refs && !in_irq && !raw_depth);
	flip_pending = 0;
}
static struct tty_struct *tty_port_tty_get(struct tty_port *port)
{
	calls++;
	if (in_irq || raw_depth || irq_disabled)
		bad_context++;
	if (!port->open)
		return NULL;
	refs++;
	return &tty;
}
static int tty_insert_flip_string(struct tty_port *port, const void *data,
				  size_t size)
{
	if (in_irq || raw_depth || irq_disabled)
		bad_context++;
	assert(refs && port->open);
	size = min_t(size_t, size, insert_limit);
	assert(delivered_size + size <= sizeof(delivered));
	memcpy(delivered + delivered_size, data, size);
	delivered_size += size;
	flip_pending += size;
	if (insert_hook) {
		void (*hook)(void) = insert_hook;
		insert_hook = NULL;
		hook();
	}
	return size;
}
static void tty_flip_buffer_push(struct tty_port *port)
{
	assert(refs);
}
static void tty_kref_put(struct tty_struct *t)
{
	assert(t == &tty && refs);
	refs--;
}
struct mk_ipi_data {
	void *buffer;
	size_t data_size;
};
#include "spawn-production.h"

static int failures;
#define CHECK(c, msg)                                       \
	do {                                                \
		if (!(c)) {                                 \
			fprintf(stderr, "FAIL: %s\n", msg); \
			failures++;                         \
		}                                           \
	} while (0)
static void open_port(void)
{
	raw_spin_lock_init(&mktty_spawn.lock);
	mktty_spawn.port.open = true;
	assert(!mktty_spawn_activate(&mktty_spawn.port, &tty));
}
static void send_bytes(unsigned int n, char value, unsigned int received)
{
	struct mktty_message msg = { .type = MKTTY_MSG_INPUT, .len = n };
	struct mk_ipi_data data = { .buffer = &msg,
				    .data_size = received + 16 };
	assert(n <= sizeof(msg.data));
	memset(msg.data, value, n);
	in_irq = irq_disabled = true;
	mktty_spawn_ipi_handler(&data, NULL);
	in_irq = irq_disabled = false;
	memset(msg.data, '!', n); /* transport immediately reuses its payload */
}
static void context_case(void)
{
	open_port();
	send_bytes(3, 'a', 3);
	send_bytes(2, 'b', 2);
	CHECK(!calls && !delivered_size,
	      "hard IPI must only copy, not call TTY");
	drain();
	CHECK(!bad_context && !refs && delivered_size == 5 &&
		      !memcmp(delivered, "aaabb", 5),
	      "worker must deliver owned bytes in order in process context");
	CHECK(runs == 1, "pending receives should coalesce into one worker");
}
static void truncated_case(void)
{
	open_port();
	send_bytes(2, 'a', 1);
	drain();
	CHECK(!calls && !delivered_size,
	      "truncated payload must not be queued");
}
static void shutdown_case(void)
{
	open_port();
	send_bytes(3, 'x', 3);
	mktty_spawn_shutdown(&mktty_spawn.port);
	drain();
	CHECK(!delivered_size,
	      "shutdown must cancel queued old-session delivery");
	send_bytes(2, 'y', 2);
	drain();
	CHECK(!delivered_size, "inactive session must not admit receive work");
	assert(!mktty_spawn_activate(&mktty_spawn.port, &tty));
	send_bytes(1, 'z', 1);
	drain();
	CHECK(delivered_size == 1 && delivered[0] == 'z',
	      "reopen must not inherit old input");
}
static void overflow_case(void)
{
	unsigned int i;
	open_port();
	for (i = 0; i < 5; i++)
		send_bytes(4000, 'q', 4000);
	drain();
	CHECK(delivered_size == 16384 && reported_drops == 3616,
	      "FIFO must bound and account overflow");
	send_bytes(7, 'r', 7);
	drain();
	CHECK(delivered_size == 16391 &&
		      !memcmp(delivered + 16384, "rrrrrrr", 7),
	      "FIFO wrap must preserve later input");
}
static void inject_receive(void)
{
	send_bytes(2, 'b', 2);
}
static void running_case(void)
{
	open_port();
	insert_hook = inject_receive;
	send_bytes(3, 'a', 3);
	drain();
	CHECK(delivered_size == 5 && !memcmp(delivered, "aaabb", 5) && !refs,
	      "receive during delivery must not lose work or references");
	insert_limit = 1;
	send_bytes(4, 'c', 4);
	drain();
	CHECK(delivered_size == 6 && reported_drops == 3,
	      "short TTY insert must account undelivered bytes");
}
static void hangup_case(void)
{
	open_port();
	send_bytes(3, 'x', 3);
	drain();
	assert(flip_pending == 3);
	mktty_spawn_hangup(&tty);
	CHECK(!flip_pending,
	      "hangup must flush bytes inserted before RX worker drainage");
	open_port();
	send_bytes(1, 'z', 1);
	drain();
	CHECK(flip_pending == 1,
	      "new session must not inherit old flip-buffer bytes");
}
int main(void)
{
	void (*cases[])(void) = { context_case,	 truncated_case, shutdown_case,
				  overflow_case, running_case,	 hangup_case };
	unsigned int i, bad = 0;
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int status;
		pid_t child = fork();
		assert(child >= 0);
		if (!child) {
			alarm(5);
			cases[i]();
			exit(failures != 0);
		}
		assert(waitpid(child, &status, 0) == child);
		bad += !WIFEXITED(status) || WEXITSTATUS(status);
	}
	printf("mktty spawn: %u/6 scenarios %s (substituted kernel boundaries)\n",
	       bad ? bad : 6, bad ? "FAIL" : "PASS");
	return bad != 0;
}
