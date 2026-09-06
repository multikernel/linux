// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 */
#include <linux/kernel.h>
#include <linux/multikernel.h>
#include <uapi/linux/multikernel_virtio.h>

static_assert(sizeof(struct mk_virtio_queue) == 64);
static_assert(sizeof(struct mk_virtio_entry) == MK_VIRTIO_ENTRY_SIZE);
static_assert(sizeof(struct mk_virtio_table) == 4096);
static_assert(offsetof(struct mk_virtio_entry, config) == 128);
static_assert(offsetof(struct mk_virtio_entry, queues) == 384);
