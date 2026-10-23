#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-riscv-map-size.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static uintptr_t __meminit best_map_size\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/mm/init.c" > "$build/map-size-production.h"
for enabled in 0 1; do
    ${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror \
        -DCONFIG_MULTIKERNEL="$enabled" -I"$build" \
        "$test_dir/riscv_map_size_test.c" -o "$build/riscv_map_size_test"
    "$build/riscv_map_size_test"
done
