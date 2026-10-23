#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-pciback-lifetime.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static struct mk_pciback_dev \*mk_pciback_find\(/ { copy = 1 }
     /^static void mk_pciback_(put|answer|work_fn|defer|request|free)\(/ { copy = 1 }
     /^void mk_pciback_unlend(_one)?\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/pciback.c" > "$build/pciback-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -pthread -Wall -Wextra -Werror \
    -Wno-unused-parameter -I"$build" -I"$src/tools/include" \
    "$test_dir/pciback_lifetime_test.c" -o "$build/pciback_lifetime_test"
timeout 15 "$build/pciback_lifetime_test"
