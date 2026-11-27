/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPILINUX_KEXEC_H
#define _UAPILINUX_KEXEC_H

/* kexec system call -  It loads the new kernel to boot into.
 * kexec does not sync, or unmount filesystems so if you need
 * that to happen you need to do that yourself.
 */

#include <linux/ioctl.h>
#include <linux/types.h>

/* kexec flags for different usage scenarios */
#define KEXEC_ON_CRASH		0x00000001
#define KEXEC_PRESERVE_CONTEXT	0x00000002
#define KEXEC_UPDATE_ELFCOREHDR	0x00000004
#define KEXEC_CRASH_HOTPLUG_SUPPORT 0x00000008
#define KEXEC_ARCH_MASK		0xffff0000

/*
 * Kexec file load interface flags.
 * KEXEC_FILE_UNLOAD : Unload already loaded kexec/kdump image.
 * KEXEC_FILE_ON_CRASH : Load/unload operation belongs to kdump image.
 * KEXEC_FILE_NO_INITRAMFS : No initramfs is being loaded. Ignore the initrd
 *                           fd field.
 * KEXEC_FILE_FORCE_DTB : Force carrying over the current boot's DTB to the new
 *                        kernel on x86. This is already the default behavior on
 *                        some other architectures, like ARM64 and PowerPC.
 * KEXEC_FILE_MULTIKERNEL : Load a multikernel spawn image for the instance
 *                          whose id is in KEXEC_FILE_MK_ID_MASK, instead of
 *                          an image to reboot into. Returns a file descriptor
 *                          for the instance, see KEXEC_MK_IOC_* below.
 * KEXEC_FILE_MK_OPEN : With KEXEC_FILE_MULTIKERNEL, load nothing and only
 *                      return a file descriptor for the instance. The
 *                      kernel and initrd fds and the command line are
 *                      ignored. In a spawn kernel, the id of its host
 *                      gives a descriptor that takes KEXEC_MK_IOC_FENCE
 *                      and nothing else.
 *
 * The upper half is a destination field apart from the flags: the
 * multikernel flag and the instance id.
 */
#define KEXEC_FILE_UNLOAD	0x00000001
#define KEXEC_FILE_ON_CRASH	0x00000002
#define KEXEC_FILE_NO_INITRAMFS	0x00000004
#define KEXEC_FILE_DEBUG	0x00000008
#define KEXEC_FILE_NO_CMA	0x00000010
#define KEXEC_FILE_FORCE_DTB	0x00000020
#define KEXEC_FILE_MK_OPEN	0x00000040

#define KEXEC_FILE_MK_ID_SHIFT	16
#define KEXEC_FILE_MK_ID_MASK	0x7fff0000
#define KEXEC_FILE_MK_ID(id)	(((id) << KEXEC_FILE_MK_ID_SHIFT) & KEXEC_FILE_MK_ID_MASK)
#define KEXEC_FILE_GET_MK_ID(flags)	\
	(((flags) & KEXEC_FILE_MK_ID_MASK) >> KEXEC_FILE_MK_ID_SHIFT)
#define KEXEC_FILE_MULTIKERNEL	0x80000000

/*
 * Operations on the file descriptor of a multikernel instance. The
 * descriptor is a handle: closing it does nothing to the instance.
 */

#define KEXEC_MK_START_MAY_FENCE	0x00000001	/* this run may fence us */

struct kexec_mk_start {
	__u32 flags;		/* KEXEC_MK_START_* */
	__u32 timeout_ms;	/* how long to wait for the boot, 0 = do not wait */
	__u64 cmdline;		/* command line for this run, or 0 */
	__u32 cmdline_len;	/* its length, with the terminating NUL */
	__u32 pad;
};

#define KEXEC_MK_HALT_FORCE	0x00000001	/* stop its CPUs, ask nothing */

struct kexec_mk_halt {
	__u32 flags;		/* KEXEC_MK_HALT_* */
	__u32 timeout_ms;	/* how long to wait, 0 = do not wait */
};

#define KEXEC_MK_STATE_READY	0	/* resources reserved, no image */
#define KEXEC_MK_STATE_LOADED	1	/* image loaded, not running */
#define KEXEC_MK_STATE_STARTING	2	/* dispatched, has not reported in */
#define KEXEC_MK_STATE_ACTIVE	3	/* running */

#define KEXEC_MK_STOP_NONE	0	/* never ran, or is running */
#define KEXEC_MK_STOP_EXITED	1	/* its init process exited */
#define KEXEC_MK_STOP_POWEROFF	2	/* it powered off, halted or restarted */
#define KEXEC_MK_STOP_PANIC	3	/* it panicked and said so */
#define KEXEC_MK_STOP_HALTED	4	/* it shut down because it was asked to */
#define KEXEC_MK_STOP_FORCED	5	/* it was force halted */

#define KEXEC_MK_INFO_F_EXIT_STATUS	0x00000001	/* exit_status is valid */

struct kexec_mk_info {
	__u32 size;		/* in: sizeof the caller's struct */
	__u32 state;		/* KEXEC_MK_STATE_* */
	__u64 run;		/* starts so far; 0 = never started */
	__u32 stop_reason;	/* KEXEC_MK_STOP_*, of the last run */
	__s32 exit_status;	/* wait status of its init process */
	__u32 flags;		/* KEXEC_MK_INFO_F_* */
	__u32 pad;
};

#define KEXEC_MK_INFO_SIZE_VER0	32

struct kexec_mk_cmdline {
	__u64 buf;		/* where to copy the command line, or 0 */
	__u32 len;		/* in: size of buf; out: length with the NUL */
	__u32 flags;		/* none yet, must be 0 */
};

#define KEXEC_MK_IOC_MAGIC	0xB9

#define KEXEC_MK_IOC_START	_IOW(KEXEC_MK_IOC_MAGIC, 1, struct kexec_mk_start)
#define KEXEC_MK_IOC_HALT	_IOW(KEXEC_MK_IOC_MAGIC, 2, struct kexec_mk_halt)
#define KEXEC_MK_IOC_INFO	_IOWR(KEXEC_MK_IOC_MAGIC, 3, struct kexec_mk_info)
#define KEXEC_MK_IOC_CMDLINE	_IOWR(KEXEC_MK_IOC_MAGIC, 5, struct kexec_mk_cmdline)
/*
 * On the descriptor of the host only: stop every CPU this kernel does not
 * own and take the machine over. EPERM unless this run was started with
 * KEXEC_MK_START_MAY_FENCE, ETIMEDOUT if a CPU never stopped.
 */
#define KEXEC_MK_IOC_FENCE	_IO(KEXEC_MK_IOC_MAGIC, 6)

/* These values match the ELF architecture values.
 * Unless there is a good reason that should continue to be the case.
 */
#define KEXEC_ARCH_DEFAULT ( 0 << 16)
#define KEXEC_ARCH_386     ( 3 << 16)
#define KEXEC_ARCH_68K     ( 4 << 16)
#define KEXEC_ARCH_PARISC  (15 << 16)
#define KEXEC_ARCH_X86_64  (62 << 16)
#define KEXEC_ARCH_PPC     (20 << 16)
#define KEXEC_ARCH_PPC64   (21 << 16)
#define KEXEC_ARCH_IA_64   (50 << 16)
#define KEXEC_ARCH_ARM     (40 << 16)
#define KEXEC_ARCH_S390    (22 << 16)
#define KEXEC_ARCH_SH      (42 << 16)
#define KEXEC_ARCH_MIPS_LE (10 << 16)
#define KEXEC_ARCH_MIPS    ( 8 << 16)
#define KEXEC_ARCH_AARCH64 (183 << 16)
#define KEXEC_ARCH_RISCV   (243 << 16)
#define KEXEC_ARCH_LOONGARCH	(258 << 16)

/* The artificial cap on the number of segments passed to kexec_load. */
#define KEXEC_SEGMENT_MAX 16

#ifndef __KERNEL__
/*
 * This structure is used to hold the arguments that are used when
 * loading  kernel binaries.
 */
struct kexec_segment {
	const void *buf;
	__kernel_size_t bufsz;
	const void *mem;
	__kernel_size_t memsz;
};

#endif /* __KERNEL__ */

#endif /* _UAPILINUX_KEXEC_H */
