#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-vsock-rx.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^#define MK_VSOCK_MAX_PKT_SIZE/ { print }
     /^struct mk_vsock \{/ { copy = 1 }
     /^static struct mk_vsock mk_vsock_dev;/ { print }
     /^static void mk_vsock_(rx_work|ipi_handler)\(/ { copy = 1 }
     /^static (int __init|void __exit) mk_vsock_transport_(init|exit)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/net/vmw_vsock/mk_transport.c" > "$build/vsock-production.h"
awk '/^struct virtio_vsock_hdr \{/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/include/uapi/linux/virtio_vsock.h" > "$build/vsock-wire.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/vsock_rx_test.c" -o "$build/vsock_rx_test"
"$build/vsock_rx_test"
