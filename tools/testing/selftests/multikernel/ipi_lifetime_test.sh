#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-ipi-lifetime.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM

awk '/^struct mk_ipi_handler \{/ { copy = 1 }
     copy { print }
     copy && /^};/ { copy = 0 }' "$src/include/linux/multikernel.h" \
     > "$build/ipi-handler.h"
awk '/^static struct mk_ipi_handler / { print }
     /^static raw_spinlock_t mk_handlers_lock/ { print }
     /^static inline unsigned int mk_ring_idx\(/ { copy = 1 }
     /^struct mk_ipi_handler \*multikernel_register_handler\(/ { copy = 1 }
     /^void multikernel_unregister_handler\(/ { copy = 1 }
     /^static (void|int) mk_ipi_drain_ring\(void\)$/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/ipi.c" \
     > "$build/ipi-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -pthread -Wall -Wextra -Werror \
    -I"$build" "$test_dir/ipi_lifetime_test.c" -o "$build/ipi_lifetime_test"
"$build/ipi_lifetime_test"
