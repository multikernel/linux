# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for multikernel support
#

obj-y += core.o mem.o kernfs.o dts.o kho.o ipi.o messaging.o overlay.o

# Add libfdt include path for device tree parsing
CFLAGS_dts.o = -I $(srctree)/scripts/dtc/libfdt
CFLAGS_overlay.o = -I $(srctree)/scripts/dtc/libfdt
