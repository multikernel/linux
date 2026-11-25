# SPDX-License-Identifier: GPL-2.0
#
# Makefile for multikernel spawn support
#

obj-y += spawn.o park.o smp.o direct_boot.o head_64.o e820.o iommu.o
obj-$(CONFIG_X86_MCE_AMD) += fault.o
obj-$(CONFIG_DMAR_TABLE) += dmar.o
obj-$(CONFIG_AMD_IOMMU) += amd_vi.o
