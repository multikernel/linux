#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-memory-teardown.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
if [ -n "${MK_CORE_REV:-}" ]; then
    revision=$(git -C "$src" rev-parse --verify "$MK_CORE_REV^{commit}")
    git -C "$src" show "$revision:kernel/multikernel/core.c" > "$build/core-input.c"
    input="$build/core-input.c"
else
    input="$src/kernel/multikernel/core.c"
fi
awk '/^void mk_instance_free_memory\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$input" > "$build/memory-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -I"$build" \
    -I"$src/tools/include" "$test_dir/memory_teardown_test.c" -o "$build/memory_teardown_test"
"$build/memory_teardown_test"
