// SPDX-License-Identifier: GPL-2.0-only
/* Execute extracted unprivileged reader instructions, not a kernel park loop. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define BIT(n) (1U << (n))
#include "mailbox-context.h"

#ifdef EMIT_OFFSETS
#define EMIT(member)                               \
	printf("#define MK_CTX_" #member " %zu\n", \
	       offsetof(struct mk_spawn_context, member))
int main(void)
{
	EMIT(ready);
	EMIT(target_apic_id);
	EMIT(flags);
	EMIT(identity_cr3);
	EMIT(self_phys);
	EMIT(kernel_entry);
	EMIT(trampoline_phys);
	EMIT(gs_base);
	EMIT(stack);
	EMIT(secondary_trampoline_phys);
	EMIT(spawn_cr3);
	printf("#define MK_CTX_bp %zu\n", sizeof(struct mk_spawn_context));
	printf("#define MK_SLOT_PENDING %u\n", MK_SLOT_PENDING);
	printf("#define MK_SLOT_BUSY %u\n", MK_SLOT_BUSY);
	printf("#define MK_SLOT_ACK %u\n", MK_SLOT_ACK);
	printf("#define MK_SPAWN_F_REPARK %u\n", MK_SPAWN_F_REPARK);
	printf("#define MK_SPAWN_F_SECONDARY %u\n", MK_SPAWN_F_SECONDARY);
	return 0;
}
#else
extern int mailbox_read(struct mk_spawn_context *ctx, unsigned long cpu);
extern void mailbox_capture(void);
unsigned long observed[6];

int main(void)
{
	struct mk_spawn_context ctx = {
		.ready = MK_SLOT_PENDING,
		.target_apic_id = 17,
		.identity_cr3 = 0x1000,
		.self_phys = 0x2000,
		.kernel_entry = 0x3000,
		.trampoline_phys = (unsigned long)mailbox_capture,
	};
	unsigned int state, checks = 0;

	assert(sizeof(ctx) == 144);
	assert(mailbox_read(&ctx, 17) == 1 && ctx.ready == MK_SLOT_ACK);
	assert(observed[0] == 0x1000 && observed[1] == 0x2090 &&
	       observed[2] == 0x3000);
	assert(observed[3] == (unsigned long)mailbox_capture);
	checks++;
	ctx.ready = MK_SLOT_PENDING;
	ctx.flags = MK_SPAWN_F_SECONDARY;
	ctx.gs_base = 0x4000;
	ctx.stack = 0x5000;
	ctx.secondary_trampoline_phys = (unsigned long)mailbox_capture;
	ctx.spawn_cr3 = 0x6000;
	assert(mailbox_read(&ctx, 17) == 1 && ctx.ready == MK_SLOT_ACK);
	assert(observed[0] == 0x1000 && observed[1] == 0x3000 &&
	       observed[2] == 0x4000);
	assert(observed[3] == 0x5000 &&
	       observed[4] == (unsigned long)mailbox_capture);
	assert(observed[5] == 0x6000);
	checks++;
	ctx.ready = MK_SLOT_PENDING;
	memset(observed, 0, sizeof(observed));
	assert(!mailbox_read(&ctx, 99) && ctx.ready == MK_SLOT_PENDING &&
	       !observed[0]);
	checks++;
	for (state = MK_SLOT_IDLE; state <= MK_SLOT_QUARANTINED; state++) {
		if (state == MK_SLOT_PENDING)
			continue;
		ctx.ready = state;
		assert(!mailbox_read(&ctx, 17) && ctx.ready == state &&
		       !observed[0]);
		checks++;
	}
	printf("Mailbox reader: %u unprivileged assembly checks passed\n",
	       checks);
	return 0;
}
#endif
