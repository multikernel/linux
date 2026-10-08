#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-teardown.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^int mk_instance_destroy\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/kernfs.c" \
     > "$build/destroy-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" -I"$src/tools/include" "$test_dir/teardown_test.c" -o "$build/teardown_test"
"$build/teardown_test"
