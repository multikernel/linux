// SPDX-License-Identifier: GPL-2.0-only
/*
 * kexec for multikernel: the image of a spawn kernel
 *
 * A multikernel image is loaded into the memory pool of its instance instead
 * of being staged for a reboot, and it is booted next to this kernel, any
 * number of times. User space drives the instance through a file descriptor
 * that kexec_file_load() returns.
 */

#define pr_fmt(fmt)	"kexec_multikernel: " fmt

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ima.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/mm.h>
#include <linux/multikernel.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include <asm/setup.h>

#include "kexec_internal.h"

int kexec_alloc_multikernel(struct kexec_buf *kbuf)
{
	void *virt_addr;
	phys_addr_t phys_addr;

	virt_addr = mk_kimage_alloc(kbuf->image, kbuf->memsz, kbuf->buf_align,
				    kbuf->buf_min, kbuf->buf_max);
	if (!virt_addr) {
		pr_info("Failed to allocate %lu bytes from multikernel instance pool (align=0x%lx, min=0x%lx, max=0x%lx)\n",
			kbuf->memsz, kbuf->buf_align, kbuf->buf_min, kbuf->buf_max);
		return -ENOMEM;
	}

	phys_addr = virt_to_phys(virt_addr);

	if (kimage_is_destination_range(kbuf->image, phys_addr, phys_addr + kbuf->memsz - 1)) {
		pr_info("Multikernel allocation conflicts with existing segments: 0x%llx+0x%lx\n",
			 (unsigned long long)phys_addr, kbuf->memsz);
		mk_kimage_free(kbuf->image, virt_addr, kbuf->memsz);
		return -EBUSY;
	}

	/*
	 * Only pick the destination here. The caller's buffer stays the
	 * source, and kimage_load_segment() copies it in, exactly like
	 * ordinary kexec. Keeping the two apart is what lets an instance be
	 * booted more than once: booting consumes the destination copy, so
	 * every spawn re-runs the copy from the pristine source.
	 */
	kbuf->mem = phys_addr;

	pr_info("Allocated %lu bytes from multikernel pool at 0x%llx\n",
		 kbuf->memsz, (unsigned long long)phys_addr);

	return 0;
}

int kimage_load_multikernel_segment(struct kimage *image, int idx)
{
	/* For multikernel we simply copy the data from
	 * user space to it's destination.
	 * We do things a page at a time for the sake of kmap.
	 */
	struct kexec_segment *segment = &image->segment[idx];
	unsigned long maddr;
	size_t ubytes, mbytes;
	int result;
	unsigned char __user *buf = NULL;
	unsigned char *kbuf = NULL;

	result = 0;
	if (image->file_mode)
		kbuf = segment->kbuf;
	else
		buf = segment->buf;
	ubytes = segment->bufsz;
	mbytes = segment->memsz;
	maddr = segment->mem;
	while (mbytes) {
		char *ptr;
		size_t uchunk, mchunk;
		unsigned long page_addr = maddr & PAGE_MASK;
		unsigned long page_offset = maddr & ~PAGE_MASK;

		/* Use memremap to map the physical address */
		ptr = memremap(page_addr, PAGE_SIZE, MEMREMAP_WB);
		if (!ptr) {
			pr_err("Failed to memremap memory at 0x%lx\n", page_addr);
			result = -ENOMEM;
			goto out;
		}

		/* Adjust pointer to the offset within the page */
		ptr += page_offset;

		/* Calculate chunk sizes */
		mchunk = min_t(size_t, mbytes, PAGE_SIZE - page_offset);
		uchunk = min(ubytes, mchunk);

		/* Zero the trailing part of the page if needed */
		if (mchunk > uchunk) {
			/* Zero the trailing part of the page */
			memset(ptr + uchunk, 0, mchunk - uchunk);
		}

		if (uchunk) {
			/* For file based kexec, source pages are in kernel memory */
			if (image->file_mode)
				memcpy(ptr, kbuf, uchunk);
			else
				result = copy_from_user(ptr, buf, uchunk);
			ubytes -= uchunk;
			if (image->file_mode)
				kbuf += uchunk;
			else
				buf += uchunk;
		}

		/* Clean up */
		memunmap(ptr - page_offset);
		if (result) {
			result = -EFAULT;
			goto out;
		}
		maddr  += mchunk;
		mbytes -= mchunk;

		cond_resched();
	}
out:
	return result;
}

static int mk_id_from_flags(unsigned long flags)
{
	int mk_id = KEXEC_FILE_GET_MK_ID(flags);

	if (mk_id <= 0) {
		pr_err("Invalid multikernel ID %d\n", mk_id);
		return -EINVAL;
	}
	return mk_id;
}

/*
 * Tie a new image to the instance named in @flags. The image holds a
 * reference on the instance until kimage_free_multikernel().
 */
int kimage_init_multikernel(struct kimage *image, unsigned long flags)
{
	struct mk_instance *instance;
	int mk_id, ret;

	mk_id = mk_id_from_flags(flags);
	if (mk_id < 0)
		return mk_id;

	instance = mk_instance_find(mk_id);
	if (!instance) {
		pr_err("No multikernel instance found with ID %d\n", mk_id);
		return -ENOENT;
	}

	if (instance->kimage) {
		pr_err("Multikernel instance %d already has an associated kimage\n", mk_id);
		ret = -EBUSY;
		goto out_put;
	}

	/*
	 * A CPU of the previous run may still execute in the memory the new
	 * image is about to be copied into.
	 */
	ret = mk_instance_confirm_parked(instance);
	if (ret) {
		pr_err("Multikernel instance %d still has running CPUs, refusing to load\n",
		       mk_id);
		goto out_put;
	}

	ret = mk_instance_alloc_manifest(instance);
	if (ret)
		goto out_put;

	image->type = KEXEC_TYPE_MULTIKERNEL;
	image->mk_instance = instance;
	image->mk_id = mk_id;
	return 0;

out_put:
	mk_instance_put(instance);
	return ret;
}

static int kexec_mk_getfd(struct mk_instance *instance);

/*
 * Make a completely loaded image visible to start, unload and IPI, and
 * return a file descriptor for its instance. On an error the image is still
 * the caller's to free.
 *
 * Its load-time buffers are not freed here as they are for other images: an
 * instance is booted more than once and re-copies its segments from them on
 * every start, so they live until kimage_free_multikernel().
 */
int kimage_publish_multikernel(struct kimage *image)
{
	struct mk_instance *instance = image->mk_instance;
	int fd;

	fd = kexec_mk_getfd(instance);
	if (fd < 0)
		return fd;

	instance->kimage = image;
	if (instance->ipi_phys)
		instance->ipi_data = phys_to_virt(instance->ipi_phys);
	mk_instance_set_state(instance, MK_STATE_LOADED);
	return fd;
}

static void kimage_unpublish_multikernel(struct kimage *image)
{
	struct mk_instance *instance = image->mk_instance;

	if (instance->kimage != image)
		return;

	/* No kernel left to read the ring */
	instance->ipi_data = NULL;
	instance->kimage = NULL;
	mk_instance_set_state(instance, MK_STATE_READY);
}

/* Hand the image of a stopped instance to the caller, which frees it */
int kimage_unload_multikernel(unsigned long flags, struct kimage **rimage)
{
	struct mk_instance *instance;
	struct kimage *image;
	int mk_id;

	mk_id = mk_id_from_flags(flags);
	if (mk_id < 0)
		return mk_id;

	instance = mk_instance_find(mk_id);
	image = instance ? instance->kimage : NULL;
	/* The image holds a reference of its own */
	mk_instance_put(instance);
	if (!image) {
		pr_err("No loaded kernel found for multikernel instance %d\n", mk_id);
		return -ENOENT;
	}

	/* Its segments hold the kernel that is running there */
	if (READ_ONCE(image->mk_instance->state) == MK_STATE_ACTIVE) {
		pr_err("Multikernel instance %d is running, halt it before unloading\n",
		       mk_id);
		return -EBUSY;
	}

	pr_info("Unloading kernel from multikernel instance %d\n", mk_id);
	/* Under the kexec lock, so that no start or ioctl finds it once freed */
	kimage_unpublish_multikernel(image);
	*rimage = image;
	return 0;
}

/* Give the destinations of the segments from @first on back to the instance pool */
void kimage_free_mk_segments(struct kimage *image, unsigned long first)
{
	unsigned long i;

	for (i = first; i < image->nr_segments; i++)
		mk_kimage_free(image, phys_to_virt(image->segment[i].mem),
			       image->segment[i].memsz);
}

/*
 * Release what a multikernel image holds: its segments in the instance pool,
 * its load-time buffers and its reference on the instance. Also unwinds a
 * load that failed before the image was published.
 */
void kimage_free_multikernel(struct kimage *image)
{
	struct mk_instance *instance = image->mk_instance;

	kimage_free_mk_segments(image, 0);

	/* Load-time buffers were kept as the source for each spawn */
	kimage_file_post_load_cleanup(image);

	kimage_unpublish_multikernel(image);
	mk_instance_put(instance);
	image->mk_instance = NULL;
}

/*
 * Boot the image loaded for @instance. A @cmdline replaces the one the
 * image was loaded with, for this run only. It becomes the instance's once
 * the run has started, and stays the caller's on an error.
 */
static int multikernel_kexec(struct mk_instance *instance, char *cmdline,
			     unsigned long cmdline_len)
{
	unsigned long last_cmdline_len;
	char *last_cmdline;
	struct kimage *mk_image;
	int mk_id = instance->id;
	int cpu = -1;
	int i, rc;

	if (!kexec_trylock())
		return -EBUSY;

	if (!mk_instance_alive(instance)) {
		rc = -ENODEV;
		goto unlock;
	}

	mk_image = instance->kimage;
	if (!mk_image) {
		pr_err("No multikernel image loaded for instance %d\n", mk_id);
		rc = -ENOEXEC;
		goto unlock;
	}

	if (READ_ONCE(instance->state) == MK_STATE_ACTIVE) {
		rc = -EBUSY;
		goto unlock;
	}

	if (!mk_cpu_set_empty(instance->cpus)) {
		mk_phys_cpu_t phys_cpu = mk_cpu_set_first(instance->cpus);

		/* Only a CPU this kernel booted has a logical number */
		cpu = arch_cpu_from_physical_id(phys_cpu);
		if (cpu < 0 && !mk_arch_cpu_unclaimed(phys_cpu)) {
			pr_err("Physical CPU %llu not found in logical CPU map\n", phys_cpu);
			rc = -EINVAL;
			goto unlock;
		}
		pr_info("multikernel kexec: using physical CPU %llu (logical %d), %u CPUs assigned\n",
			phys_cpu, cpu, mk_cpu_set_count(instance->cpus));
	} else {
		pr_err("No CPU assignment found for multikernel instance %d - CPU assignment is required\n",
		       mk_id);
		rc = -EINVAL;
		goto unlock;
	}

	/*
	 * Every CPU of a previous run must be parked before the image is
	 * rewritten underneath it. A CPU still executing the old image
	 * when it is overwritten faults with interrupts disabled and takes
	 * the machine down, console included.
	 */
	rc = mk_instance_confirm_parked(instance);
	if (rc) {
		pr_err("Instance %d still has running CPUs, refusing to reload its image\n",
		       mk_id);
		goto unlock;
	}

	/*
	 * Booting consumes the image: the spawn kernel writes its .data and
	 * patches its own text, so the copy in instance memory is spent once
	 * it has run. Re-copy it from the source buffers kept at load time,
	 * so every spawn starts from a pristine kernel.
	 */
	for (i = 0; i < mk_image->nr_segments; i++) {
		if (WARN_ON_ONCE(!mk_image->segment[i].kbuf)) {
			pr_err("Instance %d segment %d lost its source buffer\n",
			       mk_id, i);
			rc = -EINVAL;
			goto unlock;
		}

		rc = kimage_load_segment(mk_image, i);
		if (rc) {
			pr_err("Failed to reload segment %d of instance %d: %d\n",
			       i, mk_id, rc);
			goto unlock;
		}
	}

	rc = mk_manifest_finalize(mk_image);
	if (rc) {
		pr_err("Instance %d has no boot tree, refusing to start it: %d\n",
		       mk_id, rc);
		goto unlock;
	}
	pr_info("Manifest finalized for multikernel instance\n");

	last_cmdline = instance->cmdline;
	last_cmdline_len = instance->cmdline_len;
	instance->cmdline = cmdline;
	instance->cmdline_len = cmdline_len;

	rc = mk_instance_start(instance, mk_image);
	if (rc) {
		/* No run began, so the last one is still the last */
		instance->cmdline = last_cmdline;
		instance->cmdline_len = last_cmdline_len;
	} else {
		kfree(last_cmdline);
	}

unlock:
	kexec_unlock();
	return rc;
}

static long kexec_mk_ioctl_start(struct file *file, void __user *uarg)
{
	struct mk_instance *instance = file->private_data;
	struct kexec_mk_start start;
	char *cmdline = NULL;
	long ret;

	if (copy_from_user(&start, uarg, sizeof(start)))
		return -EFAULT;
	if (start.flags || start.pad)
		return -EINVAL;
	if (!start.cmdline != !start.cmdline_len)
		return -EINVAL;

	if (start.cmdline) {
		if (start.cmdline_len > COMMAND_LINE_SIZE)
			return -E2BIG;

		cmdline = memdup_user(u64_to_user_ptr(start.cmdline),
				      start.cmdline_len);
		if (IS_ERR(cmdline))
			return PTR_ERR(cmdline);
		if (cmdline[start.cmdline_len - 1] != '\0') {
			kfree(cmdline);
			return -EINVAL;
		}

		ima_kexec_cmdline_file(file, cmdline, start.cmdline_len - 1);
	}

	/* Nothing reports a finished boot yet, so timeout_ms has nothing to bound */
	ret = multikernel_kexec(instance, cmdline, start.cmdline_len);
	if (ret)
		kfree(cmdline);
	return ret;
}

static long kexec_mk_ioctl_halt(struct mk_instance *instance,
				void __user *uarg)
{
	struct kexec_mk_halt halt;

	if (copy_from_user(&halt, uarg, sizeof(halt)))
		return -EFAULT;
	if (halt.flags & ~KEXEC_MK_HALT_FORCE)
		return -EINVAL;

	if (halt.flags & KEXEC_MK_HALT_FORCE)
		return mk_instance_force_halt(instance);

	return mk_instance_halt(instance, halt.timeout_ms);
}

static u32 kexec_mk_state(struct mk_instance *instance)
{
	switch (READ_ONCE(instance->state)) {
	case MK_STATE_ACTIVE:
		return KEXEC_MK_STATE_ACTIVE;
	case MK_STATE_LOADED:
		return KEXEC_MK_STATE_LOADED;
	default:
		return KEXEC_MK_STATE_READY;
	}
}

static long kexec_mk_ioctl_info(struct mk_instance *instance,
				void __user *uarg)
{
	struct kexec_mk_info info = {};
	u32 usize;

	if (get_user(usize, (u32 __user *)uarg))
		return -EFAULT;
	if (usize < KEXEC_MK_INFO_SIZE_VER0)
		return -EINVAL;

	info.size = sizeof(info);
	info.state = kexec_mk_state(instance);

	if (copy_to_user(uarg, &info, min_t(size_t, usize, sizeof(info))))
		return -EFAULT;
	return 0;
}

static long kexec_mk_ioctl_cmdline(struct mk_instance *instance,
				   void __user *uarg)
{
	struct kexec_mk_cmdline __user *ucmd = uarg;
	struct kexec_mk_cmdline cmd;
	struct kimage *image;
	char *copy = NULL;
	u32 len = 1;
	long ret = 0;

	if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
		return -EFAULT;
	if (cmd.flags)
		return -EINVAL;

	/* An unload frees the image, command line included */
	if (!kexec_trylock())
		return -EBUSY;
	image = instance->kimage;
	if (!image) {
		ret = -ENOEXEC;
	} else if (image->cmdline_buf_len) {
		len = image->cmdline_buf_len;
		copy = kmemdup(image->cmdline_buf, len, GFP_KERNEL);
		if (!copy)
			ret = -ENOMEM;
	}
	kexec_unlock();
	if (ret)
		return ret;

	if (put_user(len, &ucmd->len))
		ret = -EFAULT;
	else if (cmd.len < len)
		ret = -EMSGSIZE;
	else if (copy_to_user(u64_to_user_ptr(cmd.buf), copy ? copy : "", len))
		ret = -EFAULT;

	kfree(copy);
	return ret;
}

static long kexec_mk_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct mk_instance *instance = file->private_data;
	void __user *uarg = (void __user *)arg;

	if (!mk_instance_alive(instance))
		return -ENODEV;

	switch (cmd) {
	case KEXEC_MK_IOC_START:
		return kexec_mk_ioctl_start(file, uarg);
	case KEXEC_MK_IOC_HALT:
		return kexec_mk_ioctl_halt(instance, uarg);
	case KEXEC_MK_IOC_INFO:
		return kexec_mk_ioctl_info(instance, uarg);
	case KEXEC_MK_IOC_CMDLINE:
		return kexec_mk_ioctl_cmdline(instance, uarg);
	default:
		return -ENOTTY;
	}
}

static int kexec_mk_release(struct inode *inode, struct file *file)
{
	mk_instance_put(file->private_data);
	return 0;
}

static const struct file_operations kexec_mk_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= kexec_mk_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.release	= kexec_mk_release,
	.llseek		= noop_llseek,
};

/* The fd holds the instance, not its image or its run: see release */
static int kexec_mk_getfd(struct mk_instance *instance)
{
	int fd;

	mk_instance_get(instance);
	fd = anon_inode_getfd("[mk-instance]", &kexec_mk_fops, instance,
			      O_RDWR | O_CLOEXEC);
	if (fd < 0)
		mk_instance_put(instance);
	return fd;
}

/*
 * Open an instance that exists, with or without an image. A descriptor
 * names an instance this kernel spawned: there is none for this kernel
 * itself or for its host.
 */
int kimage_open_multikernel(unsigned long flags)
{
	struct mk_instance *instance;
	int fd;

	instance = mk_instance_find(KEXEC_FILE_GET_MK_ID(flags));
	if (!instance)
		return -ENOENT;

	if (instance == mk_self || instance == host_instance)
		fd = -EINVAL;
	else
		fd = kexec_mk_getfd(instance);

	mk_instance_put(instance);
	return fd;
}
