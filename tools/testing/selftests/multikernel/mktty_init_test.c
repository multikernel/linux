// SPDX-License-Identifier: GPL-2.0-only
/* Real initialization/unwind/cleanup; substitute registration APIs only. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
typedef uint64_t u64;
typedef int raw_spinlock_t;
#define pr_info(...) do { } while (0)
#define pr_warn(...) do { } while (0)
#define TTY_DRIVER_RESET_TERMIOS 1
#define TTY_DRIVER_REAL_RAW 2
#define TTY_DRIVER_TYPE_CONSOLE 3
#define B115200 1
#define CS8 2
#define CREAD 4
#define HUPCL 8
#define CLOCAL 16
#define IS_ERR(p) ((intptr_t)(p) < 0)
#define PTR_ERR(p) ((intptr_t)(p))
#define raw_spin_lock_init(p) (*(p) = 0)
#define raw_spin_lock_irqsave(p, flags) do { assert(!*(p)); *(p) = 1; (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(p, flags) do { assert(*(p)); *(p) = 0; (void)(flags); } while (0)
struct tty_port { void *ops; };
struct termios { unsigned int c_cflag; } tty_std_termios;
struct tty_driver { const char *driver_name, *name; int type; struct termios init_termios; } driver;
struct mk_ipi_handler { int unused; } handler;
struct mk_ipi_data;
struct { int id; } self, *mk_self = &self;
static int mktty_host_miscdev, mktty_spawn_console, mktty_spawn_ops, mktty_spawn_port_ops;
static bool fail_handler, fail_register, fail_alloc, misc_live, handler_live;
static bool allocated, registered, port_live, console_live, drain_expected, drained;
static int misc_register(void *p) { misc_live = true; return 0; }
static void misc_deregister(void *p) { assert(misc_live); misc_live = false; }
static void mktty_host_ipi_handler(struct mk_ipi_data *p, void *ctx) { }
static void mktty_spawn_ipi_handler(struct mk_ipi_data *p, void *ctx) { }
static struct mk_ipi_handler *multikernel_register_handler(void (*fn)(struct mk_ipi_data *, void *), void *ctx, unsigned int type)
{
    if (fail_handler) return NULL;
    handler_live = true;
    return &handler;
}
static void multikernel_unregister_handler(struct mk_ipi_handler *h)
{
    assert(h == &handler && handler_live);
    handler_live = false;
}
static struct tty_driver *tty_alloc_driver(int count, int flags)
{
    if (fail_alloc) return (void *)(intptr_t)-ENOMEM;
    allocated = true;
    return &driver;
}
static void tty_port_init(struct tty_port *p) { port_live = true; }
static void tty_port_destroy(struct tty_port *p)
{
    assert(port_live && !handler_live && (!drain_expected || drained));
    port_live = false;
}
static void tty_set_operations(struct tty_driver *d, void *ops) { }
static void tty_port_link_device(struct tty_port *p, struct tty_driver *d, int n) { }
static int tty_register_driver(struct tty_driver *d)
{
    if (fail_register) return -EIO;
    registered = true;
    return 0;
}
static void tty_unregister_driver(struct tty_driver *d) { assert(registered); registered = false; }
static void tty_driver_kref_put(struct tty_driver *d) { assert(allocated && !registered); allocated = false; }
static void register_console(void *c) { assert(!console_live); console_live = true; }
static void unregister_console(void *c) { assert(console_live); console_live = false; }
static void mktty_spawn_shutdown(struct tty_port *p) { assert(!handler_live); drained = true; }
#include "init-production.h"
static int failures;
#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } } while (0)
static void host_failure(void)
{
    fail_handler = true;
    CHECK(mktty_host_init() == -ENOMEM, "host handler failure must fail init");
    CHECK(!misc_live && !handler_live, "host init failure must undo misc registration");
}
static void spawn_failure(void)
{
    self.id = 1;
    fail_handler = true;
    console_live = mktty_console_registered = true; /* independent early console */
    CHECK(mktty_spawn_init() == -ENOMEM, "spawn handler failure must fail init");
    CHECK(!allocated && !registered && !port_live && !mktty_spawn_driver,
          "spawn handler failure must undo driver and port publication");
    CHECK(console_live && mktty_console_registered, "failed late init must preserve existing early console");
}
static void earlier_failure(void)
{
    self.id = 1;
    fail_alloc = true;
    CHECK(mktty_spawn_init() == -ENOMEM && !allocated && !port_live, "allocation failure must not publish port");
    fail_alloc = false;
    fail_register = true;
    CHECK(mktty_spawn_init() == -EIO && !allocated && !registered && !port_live,
          "driver registration failure must unwind allocation and port");
}
static void cleanup_case(void)
{
    CHECK(!mktty_host_init(), "host init success");
    mktty_host_cleanup();
    CHECK(!misc_live && !handler_live, "host cleanup must unregister both interfaces");
    self.id = 1;
    CHECK(!mktty_spawn_init(), "spawn init success");
    drain_expected = true;
    mktty_spawn.rx_enabled = true;
    mktty_spawn_cleanup();
    CHECK(mktty_spawn.stopping && !mktty_spawn.rx_enabled && drained &&
          !port_live && !registered && !allocated && !console_live,
          "spawn cleanup must close admission and drain before destroying port");
}
int main(void)
{
    void (*cases[])(void) = { host_failure, spawn_failure, earlier_failure, cleanup_case };
    unsigned int i, bad = 0;
    for (i = 0; i < 4; i++) {
        int status;
        pid_t child = fork();
        assert(child >= 0);
        if (!child) { cases[i](); exit(failures != 0); }
        assert(waitpid(child, &status, 0) == child);
        bad += !WIFEXITED(status) || WEXITSTATUS(status);
    }
    printf("mktty init: %u/4 scenarios %s (substituted registration APIs)\n", bad ? bad : 4, bad ? "FAIL" : "PASS");
    return bad != 0;
}
