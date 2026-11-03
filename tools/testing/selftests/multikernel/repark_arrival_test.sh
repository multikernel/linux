#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-repark-arrival.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static int mk_publish_repark\(/ || /^int mk_repark_cpu_to_host\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/x86/multikernel/spawn.c" > "$build/repark-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -I"$build" \
    "$test_dir/repark_arrival_test.c" -o "$build/repark_arrival_test"
"$build/repark_arrival_test"
