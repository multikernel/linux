#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-mailbox-lifetime.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^#define MK_SLOT_/ { print }' "$src/arch/x86/include/asm/multikernel.h" \
    > "$build/mailbox-states.h"
awk '/^static bool mk_slot_idle\(/ { copy = 1 }
     /^int mk_(arch_release_instance|repark_instance_to_host|pool_park_teardown)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/x86/multikernel/spawn.c" > "$build/lifetime-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/mailbox_lifetime_test.c" -o "$build/mailbox_lifetime_test"
"$build/mailbox_lifetime_test"
