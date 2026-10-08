#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-mailbox-reader.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
case $(uname -m) in x86_64) ;; *) echo 'SKIP: x86-64 userspace assembly test'; exit 4 ;; esac
awk '/^#define MK_(SLOT_|SPAWN_F_)/ { print }
     /^struct mk_spawn_context \{/ { copy = 1 }
     copy && /struct boot_params bp;/ { print "};"; exit }
     copy { print }' "$src/arch/x86/include/asm/multikernel.h" > "$build/mailbox-context.h"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -DEMIT_OFFSETS -I"$build" \
    "$test_dir/mailbox_reader_test.c" -o "$build/offsets"
"$build/offsets" > "$build/mailbox-offsets.h"
# Execute the unprivileged primary/secondary dispatch from the real park loop.
# Omit privileged repark, monitor, CR3 and descriptor-table setup entirely.
awk '/^\.Lpark_pending:/ { copy = 1 }
     /^\.Lpark_repark:/ { copy = 0 }
     /^\.Lpark_wrong_target:/ { copy = 1 }
     /^SYM_CODE_END/ { copy = 0 }
     copy && !/ANNOTATE_RETPOLINE_SAFE/ { print }' \
     "$src/arch/x86/multikernel/direct_boot.S" > "$build/mailbox-reader.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -I"$build" \
    "$test_dir/mailbox_reader_test.c" "$test_dir/mailbox_reader_test.S" \
    -o "$build/mailbox_reader_test"
"$build/mailbox_reader_test"
