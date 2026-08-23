# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for multikernel support
#

obj-y += core.o cpuset.o mem.o contig.o kernfs.o dts.o instance_dt.o manifest.o ipi.o messaging.o overlay.o hotplug.o baseline.o
obj-$(CONFIG_PCI) += pci.o pci_control.o pci_iommu.o pci_inventory.o

# DMA-BUF heap for multikernel memory allocation
obj-$(CONFIG_DMABUF_HEAPS) += dma_heap.o

# Add libfdt include path for device tree parsing
CFLAGS_dts.o = -I $(srctree)/scripts/dtc/libfdt
CFLAGS_overlay.o = -I $(srctree)/scripts/dtc/libfdt
CFLAGS_baseline.o = -I $(srctree)/scripts/dtc/libfdt
