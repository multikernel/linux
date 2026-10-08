#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-mailbox.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^#define MK_SLOT_/ { print }' "$src/arch/x86/include/asm/multikernel.h" \
    > "$build/mailbox-states.h"
awk '/^static (int|bool|void) mk_slot_(begin|idle|quarantine)\(/ { copy = 1 }
     /^(void|int) mk_set_spawn_context\(/ { copy = 1 }
     /^static int mk_slot_wake\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/x86/multikernel/spawn.c" > "$build/mailbox-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror \
    -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable \
    -I"$build" "$test_dir/mailbox_test.c" -o "$build/mailbox_test"
"$build/mailbox_test"
