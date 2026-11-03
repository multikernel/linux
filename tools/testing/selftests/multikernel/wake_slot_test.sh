#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-wake-slot.XXXXXX")
trap 'rm -r -- "$build"' EXIT HUP INT TERM
awk '/^static struct mk_spawn_context \*mk_wake_slot\(/ ||
     /^static void mk_put_wake_slot\(/ ||
     /^int multikernel_wakeup_secondary_cpu_64\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/x86/multikernel/spawn.c" > "$build/wake-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/wake_slot_test.c" -o "$build/wake_slot_test"
"$build/wake_slot_test"
