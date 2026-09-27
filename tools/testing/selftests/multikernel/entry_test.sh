#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-entry.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static int mk_riscv_setup_instance\(/ ||
     /^int mk_arch_(prepare_instance|manifest_chosen)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/multikernel/spawn.c" > "$build/prepare.h"
awk '/^static int sbi_spawn_cpu_entry\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/kernel/cpu_ops_sbi.c" > "$build/secondary.h"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" -I"$src/scripts/dtc/libfdt" \
    "$test_dir/entry_test.c" "$src"/scripts/dtc/libfdt/*.c -o "$build/test"
"$build/test"
