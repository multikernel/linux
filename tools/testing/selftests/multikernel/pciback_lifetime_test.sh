#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-pciback-lifetime.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static struct mk_pciback_dev \*mk_pciback_find\(/ { copy = 1 }
     /^static void mk_pciback_(put|answer|work_fn|defer|request|free)\(/ { copy = 1 }
     /^void mk_pciback_unlend(_one)?\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/pciback.c" > "$build/pciback-production.h"
awk '/^static inline unsigned int mk_ring_idx\(/ { copy = 1 }
     /^static (void|int) mk_ipi_drain_ring\(void\)$/ { copy = 1 }
     /^static (void|int) multikernel_interrupt_handler\(void\)$/ { copy = 1 }
     /^bool mk_ipi_in_drain\(void\)$/ { copy = 1 }
     /^(void|int) mk_ipi_poll\(void\)$/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/ipi.c" > "$build/pciback-ring.h"
# Permit regression runs on the old void API: it cannot report blocked retirement.
awk '/^int mk_ipi_poll\(void\)$/ { print "#define POLL_HAS_RESULT 1" }' \
    "$src/kernel/multikernel/ipi.c" > "$build/pciback-poll-api.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -pthread -Wall -Wextra -Werror \
    -Wno-unused-parameter -I"$build" -I"$src/tools/include" \
    "$test_dir/pciback_lifetime_test.c" -o "$build/pciback_lifetime_test"
timeout 15 "$build/pciback_lifetime_test"
