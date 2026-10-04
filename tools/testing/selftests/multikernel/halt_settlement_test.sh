#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-halt-settlement.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static (void|int) mk_instance_settle_halted\(/ { copy = 1 }
     /^struct mk_halted_work \{/ { copy = 1 }
     /^static void mk_halted_work_fn\(/ { copy = 1 }
     /^int multikernel_(force_)?halt_by_id\(/ { copy = 1 }
     copy { print }
     copy && /^};?/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/halt-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/halt_settlement_test.c" -o "$build/halt_settlement_test"
"$build/halt_settlement_test"
