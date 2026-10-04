#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-host-target.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static int __init mk_restore_host_instance\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/instance_dt.c" > "$build/host-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -I"$build" \
    "$test_dir/host_target_test.c" -o "$build/host_target_test"
"$build/host_target_test"
