# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for multikernel support
#

obj-y += core.o mem.o kernfs.o dts.o kho.o ipi.o

# Add libfdt include path for device tree parsing
CFLAGS_dts.o = -I $(srctree)/scripts/dtc/libfdt
