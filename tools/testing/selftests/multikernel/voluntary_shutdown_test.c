// SPDX-License-Identifier: GPL-2.0-only
/* Real shutdown admission/notification functions; controlled kernel edges. */
#include <assert.h>
#include <stdbool.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef uint64_t u64;
#define __init
#define __noreturn __attribute__((noreturn))
#define pr_info(...) \
	do {         \
	} while (0)
#define pr_err(...) \
	do {        \
	} while (0)
#define MK_MSG_SYSTEM 1
#define MK_SYS_SHUTDOWN 2
#define MK_SYS_SHUTDOWN_ACK 3
#define MK_SYS_HALTED 4
/* These stubs model publication order, not hardware memory ordering. */
#define smp_store_release(p, v) (*(p) = (v))
#define smp_load_acquire(p) (*(p))

enum { SYSTEM_RUNNING, SYSTEM_HALT, SYSTEM_POWER_OFF, SYSTEM_RESTART };
static int system_state = SYSTEM_RUNNING;
static bool panic_now, kexec_in_progress, mk_overlay_mutex;
static void *mk_boot_context;
static int panic_timeout;
static struct {
	void (*halt)(void);
	void (*power_off)(void);
	void (*restart)(char *);
	void (*emergency_restart)(void);
} machine_ops;
static struct {
	void (*stop_this_cpu)(void);
} smp_ops;
static bool native_hotplug_disabled;
static unsigned int notices, remote_parks, failures;
static jmp_buf parked;
static struct {
	int id;
} self = { 7 }, *mk_self = &self;
struct mk_resource_ack {
	u32 operation, result;
	u64 resource_id;
};
struct syscore_ops {
	void (*shutdown)(void *);
};
struct syscore {
	const struct syscore_ops *ops;
};
static struct syscore *registered;

static void expect(const char *name, bool ok)
{
	if (!ok) {
		fprintf(stderr, "FAIL %s\n", name);
		failures++;
	}
}

static inline bool panic_in_progress(void)
{
	return panic_now;
}
static inline bool mutex_trylock(bool *lock)
{
	if (*lock)
		return false;
	*lock = true;
	return true;
}

static inline void register_syscore(struct syscore *ops)
{
	registered = ops;
}

static int mk_send_message_id(int target, u32 type, u32 subtype, u64 id,
			      const void *data, u32 len)
{
	const struct mk_resource_ack *ack = data;

	expect("HALTED wire tuple", target == 0 && type == MK_MSG_SYSTEM &&
					    subtype == MK_SYS_HALTED &&
					    id == 0 && len == sizeof(*ack) &&
					    ack->operation == MK_SYS_SHUTDOWN &&
					    ack->result == 0 &&
					    ack->resource_id == 7);
	expect("notice has native CPUHP barrier", native_hotplug_disabled);
	expect("notice excludes controllers", mk_overlay_mutex);
	notices++;
	return 0;
}

static void __noreturn mk_enter_pool_state(void *data)
{
	longjmp(parked, 1);
}
static void smp_call_function(void (*fn)(void *), void *data, int wait)
{
	expect("remote nonwaiting park",
	       fn == mk_enter_pool_state && !data && !wait);
	remote_parks++;
}

#include "voluntary-production.h"

int main(int argc, char **argv)
{
	const char *mode;
	bool qualified, spawn;

	assert(argc == 2);
	mode = argv[1];
	spawn = strcmp(mode, "host") != 0;
	mk_boot_context = spawn ? &self : NULL;
	expect("reboot init", mk_spawn_reboot_init() == 0);
	expect("shutdown preparation registered only in spawn",
	       !!registered == spawn);
	if (!spawn)
		return failures ? 1 : 0;
	system_state = SYSTEM_HALT;
	if (!strcmp(mode, "poweroff"))
		system_state = SYSTEM_POWER_OFF;
	if (!strcmp(mode, "restart"))
		system_state = SYSTEM_RESTART;
	if (!strcmp(mode, "running"))
		system_state = SYSTEM_RUNNING;
	panic_now = !strcmp(mode, "panic");
	kexec_in_progress = !strcmp(mode, "kexec");
	mk_overlay_mutex = !strcmp(mode, "busy");
	qualified = !strcmp(mode, "halt") || !strcmp(mode, "poweroff") ||
		    !strcmp(mode, "restart");
	if (strcmp(mode, "direct")) {
		/* Normal reboot has already run migrate_to_reboot_cpu(). */
		native_hotplug_disabled = true;
		if (registered)
			registered->ops->shutdown(NULL);
	}
	if (!strcmp(mode, "panic-late"))
		panic_now = true;
	if (!strcmp(mode, "kexec-late"))
		kexec_in_progress = true;
	if (!setjmp(parked)) {
		if (panic_now || !strcmp(mode, "direct"))
			machine_ops.emergency_restart();
		else if (!strcmp(mode, "restart"))
			machine_ops.restart(NULL);
		else if (!strcmp(mode, "poweroff"))
			machine_ops.power_off();
		else
			machine_ops.halt();
	}
	expect("local stop retains remote parking", remote_parks == 1);
	expect("only qualified normal exit sends HALTED",
	       notices == (unsigned int)qualified);
	printf("voluntary shutdown %s: %u failures\n", mode, failures);
	return failures ? 1 : 0;
}
