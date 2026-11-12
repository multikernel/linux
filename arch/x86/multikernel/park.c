// SPDX-License-Identifier: GPL-2.0-only
/*
 * The park table
 *
 * Every CPU of the machine has one cell, where it waits whenever no
 * kernel runs on it. The first kernel builds the table and every later
 * kernel inherits it, including a successor that took over from its
 * host, so a parked CPU is always in the same place: handing it to
 * another kernel is bookkeeping, and any kernel can tell whether it is
 * parked, however many generations ago it was parked, by reading the
 * cell's state, which only the CPU itself writes.
 *
 * The table is in every kernel's direct map. The code page is entered
 * there, and the page table it switches to maps the code at the direct
 * map addresses kernels use: the creator's own, and the default base
 * every spawn kernel has.
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc.
 */

#include <linux/init.h>
#include <linux/iopoll.h>
#include <linux/mm.h>
#include <linux/multikernel.h>
#include <linux/overflow.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <asm/apic.h>
#include <asm/cpufeature.h>
#include <asm/multikernel.h>

typedef void (*mk_cell_park_fn)(unsigned long park_cr3, unsigned long cell_phys,
				unsigned long code_phys, unsigned long mwait_usable);

static struct mk_park_table *mk_park;
static struct mk_ident_pgtable *mk_park_pgt;	/* set only on the creator */
static phys_addr_t mk_park_boot_phys;

static u64 mk_park_word(u32 state, u32 cmd)
{
	return (u64)cmd << 32 | state;
}

static size_t mk_park_header_size(unsigned int nr_cells)
{
	return PAGE_ALIGN(struct_size(mk_park, apic_id, nr_cells));
}

static int mk_park_index(u32 apic_id)
{
	unsigned int i;

	if (!mk_park)
		return -ENODEV;

	for (i = 0; i < mk_park->nr_cells; i++) {
		if (mk_park->apic_id[i] == apic_id)
			return i;
	}
	return -ENOENT;
}

static struct mk_park_cell *mk_park_cell(int index)
{
	return (struct mk_park_cell *)__va(mk_park->cells_phys) + index;
}

static int mk_park_code_exec(phys_addr_t code_phys)
{
	unsigned long va = (unsigned long)__va(code_phys);
	int rc;

	rc = set_memory_ro(va, 1);
	if (!rc)
		rc = set_memory_x(va, 1);
	return rc;
}

/**
 * mk_park_table_create() - Build the park table, on the first kernel
 *
 * Called when pool parking is set up. A kernel that inherited a table
 * from its parent keeps using that one.
 */
int mk_park_table_create(void)
{
	size_t code = mk_cell_park_end - mk_cell_park_start;
	unsigned int nr = num_possible_cpus(), i = 0;
	struct mk_ident_pgtable *pgt;
	struct mk_park_table *t;
	size_t hdr, size;
	phys_addr_t phys;
	int cpu, rc;

	lockdep_assert_held(&mk_park_lock);

	if (mk_park)
		return 0;
	if (WARN_ON_ONCE(code > PAGE_SIZE))
		return -E2BIG;

	hdr = mk_park_header_size(nr);
	size = hdr + (1 + nr + MK_PARK_PGTABLE_PAGES) * PAGE_SIZE;
	phys = multikernel_alloc(size, NUMA_NO_NODE);
	if (!phys)
		return -ENOMEM;
	rc = mk_pool_map(phys, size);
	if (rc)
		goto err_free;

	t = __va(phys);
	memset(t, 0, size);
	t->magic = MK_PARK_MAGIC;
	t->version = MK_PARK_VERSION;
	t->nr_cells = nr;
	t->size = size;
	t->code_phys = phys + hdr;
	t->cells_phys = t->code_phys + PAGE_SIZE;
	for_each_possible_cpu(cpu)
		t->apic_id[i++] = arch_cpu_physical_id(cpu);
	memcpy(__va(t->code_phys), mk_cell_park_start, code);

	pgt = mk_build_arena_pgtable(__va(t->cells_phys + nr * PAGE_SIZE),
				     MK_PARK_PGTABLE_PAGES);
	if (IS_ERR(pgt)) {
		rc = PTR_ERR(pgt);
		goto err_unmap;
	}
	rc = mk_ident_map_range(pgt, phys, phys + size);
	if (!rc)
		rc = mk_add_trampoline_mapping(pgt, (unsigned long)__va(t->code_phys),
					       t->code_phys);
	if (!rc)
		rc = mk_add_trampoline_mapping(pgt,
					       mk_default_page_offset() + t->code_phys,
					       t->code_phys);
	if (!rc)
		rc = mk_park_code_exec(t->code_phys);
	if (rc)
		goto err_pgt;
	t->park_cr3 = mk_get_identity_cr3(pgt);

	mk_park = t;
	mk_park_pgt = pgt;
	pr_info("mk_park: park table at %pa, %u cells\n", &phys, nr);
	return 0;

err_pgt:
	mk_free_identity_pgtable(pgt);
err_unmap:
	mk_pool_unmap(phys, size);
err_free:
	multikernel_free(phys, size);
	return rc;
}

/**
 * mk_park_table_destroy() - Return the park table to the pool
 *
 * Only the kernel that built the table frees it, and only while no CPU
 * waits in it; the next pool parking setup builds it again. An
 * inherited table is not this kernel's to free.
 *
 * Returns 0 if freed or there was nothing to free, -EBUSY otherwise.
 */
int mk_park_table_destroy(void)
{
	unsigned long code_va;
	phys_addr_t phys;
	unsigned int i;
	size_t size;

	lockdep_assert_held(&mk_park_lock);

	if (!mk_park_pgt)
		return 0;

	for (i = 0; i < mk_park->nr_cells; i++) {
		if (READ_ONCE(mk_park_cell(i)->state) == MK_PARK_PARKED)
			return -EBUSY;
	}

	code_va = (unsigned long)__va(mk_park->code_phys);
	WARN_ON_ONCE(set_memory_nx(code_va, 1) || set_memory_rw(code_va, 1));
	mk_free_identity_pgtable(mk_park_pgt);
	mk_park_pgt = NULL;

	phys = __pa(mk_park);
	size = mk_park->size;
	mk_park = NULL;
	mk_pool_unmap(phys, size);
	multikernel_free(phys, size);
	pr_info("mk_park: released the park table\n");
	return 0;
}

/* The table this spawn kernel's parent gave it, attached at early_initcall */
void mk_park_table_set_boot(phys_addr_t phys)
{
	mk_park_boot_phys = phys;
}

static int __init mk_park_table_attach(void)
{
	phys_addr_t phys = mk_park_boot_phys;
	struct mk_park_table *t;
	int rc;

	if (!phys)
		return 0;

	rc = mk_pool_map(phys, PAGE_SIZE);
	if (rc)
		return rc;
	t = __va(phys);
	if (t->magic != MK_PARK_MAGIC || t->version != MK_PARK_VERSION) {
		pr_err("mk_park: table at %pa is magic %#x version %u, not %u: CPUs cannot park\n",
		       &phys, t->magic, t->version, MK_PARK_VERSION);
		return -EINVAL;
	}

	rc = mk_pool_map(phys, t->size);
	if (!rc)
		rc = mk_park_code_exec(t->code_phys);
	if (rc)
		return rc;

	mk_park = t;
	pr_info("mk_park: inherited the park table at %pa, %u cells\n",
		&phys, t->nr_cells);
	return 0;
}
early_initcall(mk_park_table_attach);

phys_addr_t mk_park_table_phys(void)
{
	return mk_park ? __pa(mk_park) : 0;
}

phys_addr_t mk_park_code_phys(void)
{
	return mk_park ? mk_park->code_phys : 0;
}

bool mk_park_table_uses(phys_addr_t start, size_t size)
{
	phys_addr_t phys = mk_park_table_phys();

	return phys && phys < start + size && start < phys + mk_park->size;
}

/* The table as one base,size pair, for kernels that must leave it alone */
int mk_park_table_regions(u64 *pairs, int max)
{
	if (!mk_park)
		return 0;
	if (max < 1)
		return -E2BIG;

	pairs[0] = mk_park_table_phys();
	pairs[1] = mk_park->size;
	return 1;
}

/**
 * mk_park_dispatch() - Send a parked CPU on its way
 * @apic_id: The CPU
 * @cmd: MK_PARK_CMD_BOOT or MK_PARK_CMD_SECONDARY
 * @args: Its arguments, see the command definitions
 * @nargs: How many
 *
 * Publishes only to a CPU whose cell reads PARKED, and waits for it to
 * claim the command. On timeout the command is revoked; a CPU that
 * claims it first goes ahead.
 *
 * Returns 0 once the CPU left its cell, -EBUSY if it was not parked,
 * -ETIMEDOUT if it never claimed the command.
 */
int mk_park_dispatch(u32 apic_id, u32 cmd, const u64 *args, unsigned int nargs)
{
	u64 idle = mk_park_word(MK_PARK_PARKED, MK_PARK_CMD_NONE);
	u64 published = mk_park_word(MK_PARK_PARKED, cmd);
	struct mk_park_cell *cell;
	int index, ret;
	u64 word;

	index = mk_park_index(apic_id);
	if (index < 0)
		return index;
	if (WARN_ON_ONCE(nargs > ARRAY_SIZE(cell->arg)))
		return -EINVAL;
	cell = mk_park_cell(index);

	/* The cmpxchg orders the arguments before the command */
	memcpy(cell->arg, args, nargs * sizeof(*args));
	if (cmpxchg(&cell->word, idle, published) != idle) {
		pr_err("mk_park: CPU (APIC %u) is not parked\n", apic_id);
		return -EBUSY;
	}

	ret = read_poll_timeout(READ_ONCE, word, word != published, 10,
				USEC_PER_SEC, false, cell->word);
	if (ret && cmpxchg(&cell->word, published, idle) != published)
		ret = 0;
	if (ret)
		pr_err("mk_park: CPU (APIC %u) did not claim command %u\n",
		       apic_id, cmd);
	return ret;
}

/* Wait for a CPU to reach its cell: 0 once parked, -ETIMEDOUT if not */
int mk_park_wait(u32 apic_id)
{
	int index = mk_park_index(apic_id);
	u32 state;

	if (index < 0)
		return index;

	return read_poll_timeout(READ_ONCE, state, state == MK_PARK_PARKED, 10,
				 USEC_PER_SEC, false, mk_park_cell(index)->state);
}

/* Whether this CPU has a cell to park in */
bool mk_park_ready(void)
{
	return mk_park_index(read_apic_id()) >= 0;
}

/* Park this CPU in its cell; returns only if it has none */
void mk_park_this_cpu(void)
{
	int index = mk_park_index(read_apic_id());
	mk_cell_park_fn park;

	if (index < 0)
		return;

	park = (mk_cell_park_fn)__va(mk_park->code_phys);
	park(mk_park->park_cr3, mk_park->cells_phys + index * PAGE_SIZE,
	     mk_park->code_phys, boot_cpu_has(X86_FEATURE_MWAIT));
}
