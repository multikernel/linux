// SPDX-License-Identifier: GPL-2.0-only
/*
 * kexec for multikernel: the image of a spawn kernel
 *
 * A multikernel image is loaded into the memory pool of its instance instead
 * of being staged for a reboot, and it is booted next to this kernel, any
 * number of times.
 */

#define pr_fmt(fmt)	"kexec_multikernel: " fmt

#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/mm.h>
#include <linux/multikernel.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

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

/*
 * Make a completely loaded image visible to start, unload and IPI.
 *
 * Its load-time buffers are not freed here as they are for other images: an
 * instance is booted more than once and re-copies its segments from them on
 * every start, so they live until kimage_free_multikernel().
 */
void kimage_publish_multikernel(struct kimage *image)
{
	struct mk_instance *instance = image->mk_instance;

	instance->kimage = image;
	if (instance->ipi_phys)
		instance->ipi_data = phys_to_virt(instance->ipi_phys);
	mk_instance_set_state(instance, MK_STATE_LOADED);
}

/* Hand the image of a stopped instance to the caller, which frees it */
int kimage_unload_multikernel(unsigned long flags, struct kimage **rimage)
{
	struct kimage *image;
	int mk_id;

	mk_id = mk_id_from_flags(flags);
	if (mk_id < 0)
		return mk_id;

	image = kimage_find_by_id(mk_id);
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
	*rimage = image;
	return 0;
}

/*
 * Release what a multikernel image holds: its segments in the instance pool,
 * its load-time buffers and its reference on the instance. Also unwinds a
 * load that failed before the image was published.
 */
void kimage_free_multikernel(struct kimage *image)
{
	struct mk_instance *instance = image->mk_instance;
	unsigned long i;

	for (i = 0; i < image->nr_segments; i++)
		mk_kimage_free(image, phys_to_virt(image->segment[i].mem),
			       image->segment[i].memsz);

	/* Load-time buffers were kept as the source for each spawn */
	kimage_file_post_load_cleanup(image);

	if (instance->kimage == image) {
		/* No kernel left to read the ring */
		instance->ipi_data = NULL;
		instance->kimage = NULL;
		mk_instance_set_state(instance, MK_STATE_READY);
	}
	mk_instance_put(instance);
	image->mk_instance = NULL;
}

/*
 * Find a multikernel image by ID using mk_instance lookup
 */
struct kimage *kimage_find_by_id(int mk_id)
{
	struct mk_instance *instance;
	struct kimage *image = NULL;

	if (mk_id <= 0)
		return NULL;

	/* Use mk_instance system to find the associated kimage */
	instance = mk_instance_find(mk_id);
	if (instance) {
		image = instance->kimage;
		mk_instance_put(instance); /* Release reference from find */
	}

	return image;
}

int multikernel_kexec_by_id(int mk_id)
{
	struct kimage *mk_image;
	struct mk_instance *instance;
	int cpu = -1;
	int i, rc;

	if (!kexec_trylock())
		return -EBUSY;

	mk_image = kimage_find_by_id(mk_id);
	if (!mk_image) {
		pr_err("No multikernel image found with ID %d\n", mk_id);
		rc = -EINVAL;
		goto unlock;
	}

	instance = mk_image->mk_instance;
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

	rc = mk_instance_start(instance, mk_image);

unlock:
	kexec_unlock();
	return rc;
}
