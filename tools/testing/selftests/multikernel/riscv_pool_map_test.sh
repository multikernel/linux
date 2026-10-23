#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-riscv-pool.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
sed '/^#include /d' "$src/arch/riscv/mm/multikernel.c" > "$build/pool-map-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-function \
    -Wno-unused-parameter -I"$build" "$test_dir/riscv_pool_map_test.c" -o "$build/riscv_pool_map_test"
"$build/riscv_pool_map_test"
