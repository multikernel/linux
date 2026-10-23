#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-riscv-remove-walk.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static void __meminit remove_(pud|p4d)_mapping\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/mm/init.c" > "$build/remove-walk-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -I"$build" \
    "$test_dir/riscv_remove_walk_test.c" -o "$build/riscv_remove_walk_test"
"$build/riscv_remove_walk_test"
