#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-instance-lookup.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^struct mk_instance \*mk_instance_find\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/lookup-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -I"$build" \
    "$test_dir/instance_lookup_test.c" -o "$build/instance_lookup_test"
"$build/instance_lookup_test"
