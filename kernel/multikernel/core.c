// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/multikernel.h>

static int __init multikernel_init(void)
{
	pr_info("Multikernel support initialized\n");
	return 0;
}

/* Initialize multikernel after core kernel subsystems are ready */
subsys_initcall(multikernel_init);
