#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-start-lifetime.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^void mk_instance_set_state\(/ { copy = 1 }
     /^int mk_instance_start\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/start-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror \
    -I"$build" "$test_dir/start_lifetime_test.c" -o "$build/start_lifetime_test"
"$build/start_lifetime_test"
