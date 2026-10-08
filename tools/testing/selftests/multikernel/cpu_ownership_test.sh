#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Compile production CPU sets, transfers, senders and x86 handoff functions.
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-cpu-ownership.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM

awk '/^typedef u64 mk_phys_cpu_t;/ { copy = 1 }
     /^\/\*\*$/ && copy && seen { exit }
     copy { print; seen = 1 }' "$src/include/linux/multikernel.h" \
     > "$build/cpu-types.h"
awk '/^#define MK_MSG_IO / { copy = 1 }
     /^\/\* Opaque type/ { copy = 0 }
     copy { print }' "$src/include/linux/multikernel.h" >> "$build/cpu-types.h"
sed '/^#include /d' "$src/kernel/multikernel/cpuset.c" > "$build/cpu-set.h"
awk '/^void mk_instance_ipi_retarget\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/ipi.c" \
     > "$build/cpu-retarget.h"
awk '/^int mk_instance_(transfer|return)_cpus\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/cpu-transfer.h"
awk '/^int mk_instance_confirm_parked\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/cpu-confirm.h"
awk '/^static struct mk_cpu_set \*mk_slot_set\(/ { copy = 1 }
     /^static int mk_(publish_repark|repark_to_instance)\(/ { copy = 1 }
     /^int mk_(spawn_cpu|arch_confirm_parked)\(/ { copy = 1 }
     /^int mk_repark_cpu_to_(instance|host)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/x86/multikernel/spawn.c" \
     > "$build/cpu-x86.h"
awk '/^int mk_(send|pool)_cpu_(add|remove)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/hotplug.c" \
     > "$build/cpu-send.h"

${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" -I"$src/tools/include" "$test_dir/cpu_ownership_test.c" \
    -o "$build/cpu_ownership_test"
"$build/cpu_ownership_test"
