#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-pool-return.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^bool mk_pool_cpus_returned\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" > "$build/pool-return.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable -I"$build" \
    "$test_dir/pool_return_test.c" -o "$build/pool_return_test"
"$build/pool_return_test"
