/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_KEXEC_BZIMAGE64_H
#define _ASM_KEXEC_BZIMAGE64_H

struct boot_params;
struct kimage;

extern const struct kexec_file_ops kexec_bzImage64_ops;

int setup_initrd(struct boot_params *params,
		 unsigned long initrd_load_addr, unsigned long initrd_len);
int setup_cmdline(struct kimage *image, struct boot_params *params,
		  unsigned long bootparams_load_addr,
		  unsigned long cmdline_offset, char *cmdline,
		  unsigned long cmdline_len);
int setup_boot_parameters(struct kimage *image, struct boot_params *params,
			  unsigned long params_load_addr,
			  unsigned int efi_map_offset, unsigned int efi_map_sz,
			  unsigned int setup_data_offset);

#endif  /* _ASM_KEXE_BZIMAGE64_H */
