#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-resource-transfer.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^#define MK_MSG_IO / { copy = 1 }
     /^\/\* Opaque type/ { copy = 0 }
     copy { print }' "$src/include/linux/multikernel.h" > "$build/resource-types.h"
awk '/^bool mk_pci_device_assigned\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/resource-ownership.h"
awk '/^int mk_pool_device_add\(/ { copy = 1 }
     /^int mk_send_(mem|device)_(add|remove)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/hotplug.c" \
     > "$build/resource-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror \
    -Wno-unused-parameter -I"$build" -I"$src/tools/include" \
    "$test_dir/resource_transfer_test.c" -o "$build/resource_transfer_test"
"$build/resource_transfer_test"
