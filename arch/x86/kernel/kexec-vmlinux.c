// SPDX-License-Identifier: GPL-2.0-only
/*
 * ELF vmlinux loader for kexec
 *
 * This handles loading uncompressed ELF vmlinux kernels for kexec,
 * particularly for multikernel use cases where we want to avoid
 * the complications of the bzImage decompressor.
 */

#define pr_fmt(fmt)	"kexec-vmlinux: " fmt

#include <linux/string.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/slab.h>
#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/libfdt.h>
#include <linux/efi.h>
#include <linux/of_fdt.h>
#include <linux/random.h>
#include <linux/multikernel.h>

#include <asm/bootparam.h>
#include <asm/setup.h>
#include <asm/crash.h>
#include <asm/efi.h>
#include <asm/e820/api.h>
#include <asm/kexec-bzimage64.h>
#include <asm/page_types.h>

#define MAX_ELFCOREHDR_STR_LEN	30	/* elfcorehdr=0x<64bit-value> */
#define MAX_DMCRYPTKEYS_STR_LEN	31	/* dmcryptkeys=0x<64bit-value> */

#define MIN_PURGATORY_ADDR	0x3000
#define MIN_BOOTPARAM_ADDR	0x3000
#define MIN_KERNEL_LOAD_ADDR	0x100000
#define MIN_INITRD_LOAD_ADDR	0x1000000
#define RNG_SEED_LENGTH		512

struct vmlinux_data {
	void *bootparams_buf;
	void *kernel_buf;
	bool kernel_buf_from_pool;      /* True if kernel_buf is from multikernel pool */
	bool bootparams_buf_from_pool;  /* True if bootparams_buf is from multikernel pool */
};

/*
 * Information extracted from ELF kernel
 */
struct elf_kernel_info {
	const Elf64_Ehdr *ehdr;
	unsigned long entry;        /* Entry point address (used by regular kexec) */
	unsigned long multikernel_entry; /* Physical offset from load base (from PT_NOTE) */
	int phnum;                  /* Number of program headers */
	unsigned long load_addr;    /* Lowest load address */
	unsigned long load_size;    /* Total size needed */
	unsigned long reloc_offset; /* Offset to relocation data */
	unsigned long reloc_size;   /* Size of relocation data */
};

/*
 * Find multikernel entry point from PT_NOTE section.
 * Looks for note with name "Linux" and type 0x4d4b ('MK').
 */
static unsigned long find_multikernel_entry_note(const void *buf, size_t len,
						 const Elf64_Ehdr *ehdr)
{
	const Elf64_Phdr *phdrs = buf + ehdr->e_phoff;
	int i;

	for (i = 0; i < ehdr->e_phnum; i++) {
		const Elf64_Phdr *phdr = &phdrs[i];
		const void *ptr, *end;

		if (phdr->p_type != PT_NOTE)
			continue;
		if (phdr->p_offset + phdr->p_filesz > len)
			continue;

		ptr = buf + phdr->p_offset;
		end = ptr + phdr->p_filesz;

		while (ptr + sizeof(Elf64_Nhdr) <= end) {
			const Elf64_Nhdr *nhdr = ptr;
			size_t note_size = sizeof(*nhdr) +
					   ALIGN(nhdr->n_namesz, 4) +
					   ALIGN(nhdr->n_descsz, 4);

			if (ptr + note_size > end)
				break;

			if (nhdr->n_type == 0x4d4b &&
			    nhdr->n_namesz == 6 &&
			    nhdr->n_descsz == sizeof(u64) &&
			    !memcmp(ptr + sizeof(*nhdr), "Linux", 6)) {
				u64 entry = *(u64 *)(ptr + sizeof(*nhdr) +
						     ALIGN(nhdr->n_namesz, 4));
				pr_info("multikernel: entry=0x%llx\n", entry);
				return entry;
			}
			ptr += note_size;
		}
	}
	return 0;
}

/*
 * Parse ELF kernel and extract key information
 */
static int kexec_parse_elf_kernel(const void *kernel_buf, unsigned long kernel_len,
				  struct elf_kernel_info *info)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Phdr *phdr;
	int i;

	if (kernel_len < sizeof(Elf64_Ehdr)) {
		pr_err("Kernel buffer too small for ELF header\n");
		return -EINVAL;
	}

	ehdr = (const Elf64_Ehdr *)kernel_buf;

	/* Verify ELF magic */
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		pr_err("Invalid ELF magic\n");
		return -EINVAL;
	}

	/* Verify 64-bit ELF */
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		pr_err("Not a 64-bit ELF\n");
		return -ENOEXEC;
	}

	/* Verify x86-64 */
	if (ehdr->e_machine != EM_X86_64) {
		pr_err("Not an x86-64 ELF\n");
		return -ENOEXEC;
	}

	if (ehdr->e_phoff + (ehdr->e_phnum * sizeof(Elf64_Phdr)) > kernel_len) {
		pr_err("Program headers extend beyond kernel buffer\n");
		return -EINVAL;
	}

	info->ehdr = ehdr;
	info->entry = ehdr->e_entry;
	info->phnum = ehdr->e_phnum;
	info->load_addr = ULONG_MAX;
	info->load_size = 0;
	info->reloc_offset = 0;
	info->reloc_size = 0;

	/*
	 * For multikernel: Find multikernel_startup_64 entry offset from PT_NOTE section.
	 * PT_NOTE contains physical offset from load base, not virtual address.
	 * This is the canonical way and survives symbol stripping.
	 */
	info->multikernel_entry = find_multikernel_entry_note(kernel_buf, kernel_len, ehdr);
	if (!info->multikernel_entry) {
		pr_err("multikernel_startup_64 entry offset not found in PT_NOTE\n");
		return -ENOEXEC;
	}

	pr_info("Multikernel entry offset: 0x%lx\n", info->multikernel_entry);

	/* Find lowest load address and calculate total memory needed */
	phdr = (const Elf64_Phdr *)(kernel_buf + ehdr->e_phoff);
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			unsigned long seg_end, seg_size;

			if (phdr[i].p_paddr < info->load_addr)
				info->load_addr = phdr[i].p_paddr;

			seg_end = phdr[i].p_paddr + phdr[i].p_memsz;
			seg_size = seg_end - info->load_addr;
			if (seg_size > info->load_size)
				info->load_size = seg_size;
		}
	}

	if (info->load_addr == ULONG_MAX) {
		pr_err("No PT_LOAD segments found\n");
		return -ENOEXEC;
	}

	pr_info("ELF kernel: entry=0x%lx load_addr=0x%lx size=0x%lx\n",
		info->entry, info->load_addr, info->load_size);

	return 0;
}

/*
 * Load ELF PT_LOAD segments into memory
 */
static int kexec_load_elf_segments(struct kimage *image, const void *kernel_buf,
				   unsigned long kernel_len,
				   struct elf_kernel_info *info,
				   unsigned long *kernel_load_addr_out,
				   void **kernel_buf_out)
{
	const Elf64_Phdr *phdr;
	struct kexec_buf kbuf = {
		.image = image,
		.buf_max = ULONG_MAX,
		.top_down = false
	};
	unsigned long kernel_load_addr;
	void *kernel_dest;
	int i, ret;

	/* Allocate contiguous buffer for all PT_LOAD segments */
	kbuf.bufsz = info->load_size;
	kbuf.memsz = info->load_size;
	kbuf.buf_align = SZ_2M;  /* 2MB alignment for huge pages */
	kbuf.buf_min = MIN_KERNEL_LOAD_ADDR;
	kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;

	/*
	 * For multikernel, kexec_add_buffer() will automatically allocate from
	 * the instance pool via kexec_alloc_multikernel() -> mk_kimage_alloc().
	 *
	 * For regular kexec, we need to allocate the buffer ourselves first.
	 */
	if (image->type != KEXEC_TYPE_MULTIKERNEL) {
		kbuf.buffer = kvzalloc(kbuf.bufsz, GFP_KERNEL);
		if (!kbuf.buffer)
			return -ENOMEM;
	}

	ret = kexec_add_buffer(&kbuf);
	if (ret) {
		if (image->type != KEXEC_TYPE_MULTIKERNEL)
			kvfree(kbuf.buffer);
		return ret;
	}

	kernel_load_addr = kbuf.mem;
	kernel_dest = kbuf.buffer;

	pr_info("Loading kernel segments to 0x%lx (buffer=%px, size=0x%lx)\n",
		kernel_load_addr, kernel_dest, info->load_size);

	/* Load each PT_LOAD segment */
	phdr = (const Elf64_Phdr *)(kernel_buf + info->ehdr->e_phoff);
	for (i = 0; i < info->ehdr->e_phnum; i++) {
		unsigned long offset;
		void *dest;

		if (phdr[i].p_type != PT_LOAD)
			continue;

		/* Calculate offset from base load address */
		offset = phdr[i].p_paddr - info->load_addr;
		dest = kernel_dest + offset;

		pr_info("  PT_LOAD[%d]: paddr=0x%llx offset=0x%lx filesz=0x%llx memsz=0x%llx\n",
			 i, phdr[i].p_paddr, offset, phdr[i].p_filesz, phdr[i].p_memsz);

		/* Copy segment data */
		if (phdr[i].p_filesz > 0)
			memcpy(dest, kernel_buf + phdr[i].p_offset, phdr[i].p_filesz);

		/* Zero BSS (memsz > filesz) */
		if (phdr[i].p_memsz > phdr[i].p_filesz) {
			unsigned long bss_size = phdr[i].p_memsz - phdr[i].p_filesz;
			memset(dest + phdr[i].p_filesz, 0, bss_size);
		}
	}

	*kernel_load_addr_out = kernel_load_addr;
	if (kernel_buf_out)
		*kernel_buf_out = kbuf.buffer;
	return 0;
}

/*
 * Probe function - check if this is a valid ELF vmlinux
 */
static int vmlinux_probe(const char *buf, unsigned long len)
{
	const Elf64_Ehdr *ehdr;

	if (len < sizeof(Elf64_Ehdr))
		return -ENOEXEC;

	ehdr = (const Elf64_Ehdr *)buf;

	/* Verify ELF magic */
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		return -ENOEXEC;

	/* Verify 64-bit ELF */
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		return -ENOEXEC;

	/* Verify x86-64 */
	if (ehdr->e_machine != EM_X86_64)
		return -ENOEXEC;

	/* Verify executable */
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		return -ENOEXEC;

	pr_debug("Detected valid ELF vmlinux\n");
	return 0;
}

/*
 * Setup e820 memory map for multikernel spawn kernel
 */
static int setup_e820_entries_multikernel(struct kimage *image, struct boot_params *params)
{
	struct mk_instance *instance = image->mk_instance;
	struct mk_memory_region *region;
	unsigned int nr_e820_entries = 0;
	int i;

	/*
	 * Only include the assigned memory pool regions for multikernel spawn.
	 * Don't include first 1MB - multikernel doesn't use real-mode trampoline
	 * and including unmapped low memory causes sparse_init() to fail.
	 *
	 * The spawn kernel uses e820__memory_setup_multikernel() which accepts
	 * any number of entries without fallback to legacy BIOS memory probing.
	 */
	if (instance && !list_empty(&instance->memory_regions)) {
		list_for_each_entry(region, &instance->memory_regions, list) {
			if (nr_e820_entries >= E820_MAX_ENTRIES_ZEROPAGE) {
				pr_warn("Too many e820 entries, truncating\n");
				break;
			}

			params->e820_table[nr_e820_entries].addr = region->res.start;
			params->e820_table[nr_e820_entries].size = resource_size(&region->res);
			params->e820_table[nr_e820_entries].type = E820_TYPE_RAM;
			nr_e820_entries++;
		}
	}

	params->e820_entries = nr_e820_entries;

	pr_info("Final multikernel e820 map has %d total entries:\n",
		nr_e820_entries);
	for (i = 0; i < nr_e820_entries; i++) {
		pr_info("  e820[%d]: 0x%llx-0x%llx type=%d\n", i,
			params->e820_table[i].addr,
			params->e820_table[i].addr + params->e820_table[i].size,
			params->e820_table[i].type);
	}

	return 0;
}

/*
 * Load function - load ELF vmlinux and setup boot parameters
 */
static void *vmlinux_load(struct kimage *image, char *kernel,
			  unsigned long kernel_len, char *initrd,
			  unsigned long initrd_len, char *cmdline,
			  unsigned long cmdline_len)
{
	struct elf_kernel_info elf_info;
	struct boot_params *params;
	struct vmlinux_data *ldata;
	struct kexec_entry64_regs regs64;
	void *stack;
	unsigned long kernel_load_addr = 0, initrd_load_addr = 0, bootparam_load_addr = 0;
	unsigned long params_cmdline_sz, efi_map_offset, efi_map_sz;
	unsigned long efi_setup_data_offset;
	struct kexec_buf kbuf = { .image = image, .buf_max = ULONG_MAX,
				  .top_down = true };
	struct kexec_buf pbuf = { .image = image, .buf_min = MIN_PURGATORY_ADDR,
				  .buf_max = ULONG_MAX, .top_down = true };
	bool params_from_pool = false;  /* Track if params switched to pool */
	int ret;

	pr_info("Loading ELF vmlinux (type=%d)\n", image->type);

	/* Parse ELF headers */
	ret = kexec_parse_elf_kernel(kernel, kernel_len, &elf_info);
	if (ret) {
		pr_err("Failed to parse ELF kernel: %d\n", ret);
		return ERR_PTR(ret);
	}

	/* Load purgatory only for non-multikernel (multikernel jumps directly to kernel) */
	if (image->type != KEXEC_TYPE_MULTIKERNEL) {
		ret = kexec_load_purgatory(image, &pbuf);
		if (ret) {
			pr_err("Loading purgatory failed\n");
			return ERR_PTR(ret);
		}
		kexec_dprintk("Loaded purgatory at 0x%lx\n", pbuf.mem);
	} else {
		pr_info("Skipping purgatory for multikernel (direct kernel entry)\n");
	}

	/* Allocate boot_params + cmdline + EFI data */
	efi_map_sz = efi_get_runtime_map_size();
	params_cmdline_sz = sizeof(struct boot_params) + cmdline_len +
				MAX_ELFCOREHDR_STR_LEN;
	if (image->dm_crypt_keys_addr)
		params_cmdline_sz += MAX_DMCRYPTKEYS_STR_LEN;
	params_cmdline_sz = ALIGN(params_cmdline_sz, 16);
	kbuf.bufsz = params_cmdline_sz + ALIGN(efi_map_sz, 16) +
				sizeof(struct setup_data) +
				sizeof(struct efi_setup_data) +
				sizeof(struct setup_data) +
				RNG_SEED_LENGTH;

#ifdef CONFIG_OF_FLATTREE
	if (image->force_dtb && initial_boot_params)
		kbuf.bufsz += sizeof(struct setup_data) +
			      fdt_totalsize(initial_boot_params);
#endif

	if (IS_ENABLED(CONFIG_IMA_KEXEC))
		kbuf.bufsz += sizeof(struct setup_data) +
			      sizeof(struct ima_setup_data);

	if (IS_ENABLED(CONFIG_KEXEC_HANDOVER))
		kbuf.bufsz += sizeof(struct setup_data) +
			      sizeof(struct kho_data);

	params = kvzalloc(kbuf.bufsz, GFP_KERNEL);
	if (!params)
		return ERR_PTR(-ENOMEM);

	efi_map_offset = params_cmdline_sz;
	efi_setup_data_offset = efi_map_offset + ALIGN(efi_map_sz, 16);

	/* Setup basic boot_params header for ELF kernel */
	memset(&params->hdr, 0, sizeof(params->hdr));
	params->hdr.type_of_loader = 0x0D << 4;  /* kexec loader */
	params->hdr.boot_flag = 0xAA55;
	params->hdr.header = 0x53726448;          /* "HdrS" */
	params->hdr.version = 0x020F;             /* Protocol 2.15 */
	params->hdr.loadflags = LOADED_HIGH | CAN_USE_HEAP | KEEP_SEGMENTS;
	params->hdr.xloadflags = XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G;

	kbuf.buffer = params;
	kbuf.memsz = kbuf.bufsz;
	kbuf.buf_align = 16;
	kbuf.buf_min = MIN_BOOTPARAM_ADDR;
	ret = kexec_add_buffer(&kbuf);
	if (ret)
		goto out_free_params;
	bootparam_load_addr = kbuf.mem;

	/*
	 * For multikernel, kexec_add_buffer() allocates from the instance pool
	 * and copies the original params data there, then replaces kbuf.buffer
	 * with the pool allocation. We must use the pool buffer for all further
	 * modifications (like e820 setup), not the original kvzalloc buffer.
	 * Free the original buffer since it's no longer needed.
	 */
	if (image->type == KEXEC_TYPE_MULTIKERNEL && kbuf.buffer != params) {
		void *orig_params = params;
		params = kbuf.buffer;
		params_from_pool = true;
		kvfree(orig_params);
		pr_info("Multikernel: switched params from %px to pool buffer %px\n",
			orig_params, params);
	}

	kexec_dprintk("Loaded boot_param at 0x%lx\n", bootparam_load_addr);

	/* Allocate loader specific data early so we can track allocated buffers */
	ldata = kzalloc(sizeof(struct vmlinux_data), GFP_KERNEL);
	if (!ldata) {
		ret = -ENOMEM;
		goto out_free_params;
	}

	/* Load ELF kernel segments */
	ret = kexec_load_elf_segments(image, kernel, kernel_len, &elf_info,
				      &kernel_load_addr, &ldata->kernel_buf);
	if (ret) {
		pr_err("Failed to load ELF segments: %d\n", ret);
		kfree(ldata);
		goto out_free_params;
	}

	/* For multikernel, kernel_buf points to __va() of pool memory, not kvmalloc */
	ldata->kernel_buf_from_pool = (image->type == KEXEC_TYPE_MULTIKERNEL);

	pr_info("ELF kernel loaded: kernel_load_addr=0x%lx buf=%px\n",
		kernel_load_addr, ldata->kernel_buf);

	/* Load initrd if present */
	if (initrd) {
		kbuf.buffer = initrd;
		kbuf.bufsz = kbuf.memsz = initrd_len;
		kbuf.buf_align = PAGE_SIZE;
		kbuf.buf_min = MIN_INITRD_LOAD_ADDR;
		kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
		ret = kexec_add_buffer(&kbuf);
		if (ret) {
			kvfree(ldata->kernel_buf);
			kfree(ldata);
			goto out_free_params;
		}
		initrd_load_addr = kbuf.mem;

		kexec_dprintk("Loaded initrd at 0x%lx\n", initrd_load_addr);
		setup_initrd(params, initrd_load_addr, initrd_len);
	}

	setup_cmdline(image, params, bootparam_load_addr,
		      sizeof(struct boot_params), cmdline, cmdline_len);

	if (image->type == KEXEC_TYPE_MULTIKERNEL) {
		/*
		 * Multikernel: PT_NOTE contains offset from __START_KERNEL_map.
		 * Subtract load_addr (first segment's p_paddr) to get offset
		 * within the loaded image.
		 */
		unsigned long offset = elf_info.multikernel_entry - elf_info.load_addr;
		unsigned long entry_phys = kernel_load_addr + offset;

		/* Store physical entry point and boot_params */
		image->mk_kernel_entry = entry_phys;
		image->mk_boot_params = bootparam_load_addr;

		/*
		 * Set pool bounds for page table isolation.
		 * Use the instance's memory regions to determine the full range.
		 * This ensures boot_params and other allocations are covered.
		 */
		if (image->mk_instance && !list_empty(&image->mk_instance->memory_regions)) {
			struct mk_memory_region *region;
			unsigned long min_addr = ULONG_MAX;
			unsigned long max_addr = 0;

			list_for_each_entry(region, &image->mk_instance->memory_regions, list) {
				unsigned long start = region->res.start;
				unsigned long end = region->res.end + 1; /* resource.end is inclusive */

				if (start < min_addr)
					min_addr = start;
				if (end > max_addr)
					max_addr = end;
			}

			image->multikernel_pool_start = min_addr;
			image->multikernel_pool_end = max_addr;
		} else {
			/* Fallback: use kernel image bounds only */
			image->multikernel_pool_start = kernel_load_addr;
			image->multikernel_pool_end = kernel_load_addr + elf_info.load_size;
		}

		pr_info("Multikernel: entry=0x%lx boot_params=0x%lx pool=0x%lx-0x%lx\n",
			entry_phys, bootparam_load_addr,
			image->multikernel_pool_start, image->multikernel_pool_end);

		image->start = bootparam_load_addr;
	} else {
		/* Normal kexec: Setup purgatory regs for entry */
		ret = kexec_purgatory_get_set_symbol(image, "entry64_regs", &regs64,
						     sizeof(regs64), 1);
		if (ret) {
			kvfree(ldata->kernel_buf);
			kfree(ldata);
			goto out_free_params;
		}

		regs64.rbx = 0; /* Bootstrap Processor */
		regs64.rsi = bootparam_load_addr;
		regs64.rip = elf_info.entry;

		stack = kexec_purgatory_get_symbol_addr(image, "stack_end");
		if (IS_ERR(stack)) {
			pr_err("Could not find address of symbol stack_end\n");
			ret = -EINVAL;
			kvfree(ldata->kernel_buf);
			kfree(ldata);
			goto out_free_params;
		}
		regs64.rsp = (unsigned long)stack;

		ret = kexec_purgatory_get_set_symbol(image, "entry64_regs", &regs64,
						     sizeof(regs64), 0);
		if (ret) {
			kvfree(ldata->kernel_buf);
			kfree(ldata);
			goto out_free_params;
		}
	}

	/* Set image->start for normal kexec (multikernel already set mk_kernel_entry above) */
	if (image->type != KEXEC_TYPE_MULTIKERNEL) {
		image->start = pbuf.mem;
	}

	ret = setup_boot_parameters(image, params, bootparam_load_addr,
				    efi_map_offset, efi_map_sz,
				    efi_setup_data_offset);
	if (ret) {
		kvfree(ldata->kernel_buf);
		kfree(ldata);
		goto out_free_params;
	}

	/*
	 * Set hardware_subarch AFTER setup_boot_parameters() because
	 * setup_boot_parameters() overwrites it with the host's value.
	 */
	if (image->type == KEXEC_TYPE_MULTIKERNEL)
		params->hdr.hardware_subarch = X86_SUBARCH_MULTIKERNEL;

	/* For multikernel, setup custom e820 map */
	if (image->type == KEXEC_TYPE_MULTIKERNEL) {
		ret = setup_e820_entries_multikernel(image, params);
		if (ret) {
			kvfree(ldata->kernel_buf);
			kfree(ldata);
			goto out_free_params;
		}
	}

	ldata->bootparams_buf = params;
	ldata->bootparams_buf_from_pool = params_from_pool;

	return ldata;

out_free_params:
	/* Only free params if it's not from multikernel pool */
	if (!params_from_pool)
		kvfree(params);
	return ERR_PTR(ret);
}

/*
 * Cleanup function - called after various segments have been loaded
 */
static int vmlinux_cleanup(void *loader_data)
{
	struct vmlinux_data *ldata = loader_data;

	if (!ldata)
		return 0;

	/* Only free bootparams_buf if it's not from multikernel pool */
	if (ldata->bootparams_buf && !ldata->bootparams_buf_from_pool) {
		kvfree(ldata->bootparams_buf);
	}
	ldata->bootparams_buf = NULL;

	/* Only free kernel_buf if it's not from multikernel pool */
	if (ldata->kernel_buf && !ldata->kernel_buf_from_pool) {
		kvfree(ldata->kernel_buf);
	}
	ldata->kernel_buf = NULL;

	/* Note: ldata itself is freed by kimage_file_post_load_cleanup */
	return 0;
}

const struct kexec_file_ops kexec_vmlinux_ops = {
	.probe = vmlinux_probe,
	.load = vmlinux_load,
	.cleanup = vmlinux_cleanup,
};
