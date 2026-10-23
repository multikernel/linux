// SPDX-License-Identifier: GPL-2.0-only
/* Actual startup/state functions; architecture and PCI hardware are modeled. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

enum mk_instance_state { MK_STATE_READY, MK_STATE_LOADED, MK_STATE_ACTIVE,
	MK_STATE_FAILED };
struct mk_instance {
	enum mk_instance_state state;
	int id;
	int *ipi_data;
};
struct kimage { int unused; };
static int lend_error, start_error, starts, unlends, failures;
static enum mk_instance_state state_at_start, state_at_unlend;
#define pr_debug(...) do { } while (0)
#define pr_info(...) do { } while (0)
#define pr_err(...) do { } while (0)
#define mk_instance_track_dump(...) do { } while (0)
#define lockdep_assert_held(...) do { } while (0)
#define mk_instance_ipi_reset(instance) (*(instance)->ipi_data = 0)

static int mk_pciback_lend(struct mk_instance *instance)
{
	(void)instance;
	return lend_error;
}

static void mk_pciback_unlend(struct mk_instance *instance)
{
	state_at_unlend = instance->state;
	unlends++;
}

static int mk_arch_spawn_instance(struct kimage *image,
				  struct mk_instance *instance, int cpu)
{
	(void)image;
	assert(cpu == 3);
	starts++;
	state_at_start = instance->state;
	return start_error;
}

#include "start-production.h"

#define CHECK(cond, why) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", why); failures++; } \
} while (0)

int main(void)
{
	int ring = 1;
	struct mk_instance instance = { .state = MK_STATE_LOADED, .ipi_data = &ring };
	struct kimage image = { 0 };

	lend_error = -ENOMEM;
	CHECK(mk_instance_start(&instance, &image, 3) == -ENOMEM,
	      "return lend failure");
	CHECK(!starts && instance.state == MK_STATE_LOADED,
	      "lend failure cannot start or mark the instance executing");
	lend_error = 0;
	start_error = -EIO;
	CHECK(mk_instance_start(&instance, &image, 3) == -EIO,
	      "return architecture failure");
	CHECK(state_at_start == MK_STATE_ACTIVE,
	      "potential execution must be recorded before architecture start");
	CHECK(instance.state == MK_STATE_FAILED && !unlends,
	      "partial start retains device reservations while execution is uncertain");

	instance.state = MK_STATE_ACTIVE;
	mk_instance_set_state(&instance, MK_STATE_FAILED);
	CHECK(!unlends, "FAILED alone cannot reset or release devices");
	/* Caller supplies CPU/work settlement before publishing LOADED. */
	mk_instance_set_state(&instance, MK_STATE_LOADED);
	CHECK(unlends == 1, "settled failure retires previously lent devices");
	CHECK(state_at_unlend == MK_STATE_FAILED,
	      "PCI retirement completes before publishing reusable state");
	start_error = 0;
	CHECK(!mk_instance_start(&instance, &image, 3), "successful start");
	CHECK(instance.state == MK_STATE_ACTIVE && state_at_start == MK_STATE_ACTIVE,
	      "successful start preserves potential-execution state");
	mk_instance_set_state(&instance, MK_STATE_LOADED);
	CHECK(unlends == 2, "settled ordinary shutdown retires devices");
	if (failures)
		return 1;
	puts("Startup lifetime: PASS (modeled architecture/PCI; caller settlement assumed)");
	return 0;
}
