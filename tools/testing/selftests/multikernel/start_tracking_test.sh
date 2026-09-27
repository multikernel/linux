#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-start-tracking.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^typedef u64 mk_phys_cpu_t;/ { copy = 1 }
     copy && /^\/\*\*/ { exit }
     copy { print }' "$src/include/linux/multikernel.h" > "$build/types.h"
sed '/^#include /d' "$src/kernel/multikernel/cpuset.c" > "$build/cpuset.h"
awk '/^int mk_instance_confirm_parked\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" > "$build/confirm.h"
awk '/^static int mk_riscv_track_cpu\(/ ||
     /^int mk_arch_(spawn_instance|release_instance|confirm_parked)\(/ ||
     /^int mk_repark_(instance_to_host|cpu_to_instance|cpu_to_host)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/multikernel/spawn.c" > "$build/start.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/start_tracking_test.c" -o "$build/test"
"$build/test"
