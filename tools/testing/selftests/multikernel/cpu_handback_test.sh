#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-cpu-handback.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM

awk '/^int (add_cpu|reclaim_cpu)\(/ { copy = 1 }
     /^static void cpuhp_online_cpu_device\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/cpu.c" > "$build/handback-native.h"
awk '/^struct mk_hotplug_op \{/ { copy = 1 }
     /^static void mk_account_cpu_online\(/ { copy = 1 }
     /^static int mk_(cpu_to_logical|do_cpu_add)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/hotplug.c" \
     > "$build/handback-hotplug.h"
awk '/^typedef u64 mk_phys_cpu_t;/ { copy = 1 }
     /^\/\*\*$/ && copy && seen { exit }
     copy { print; seen = 1 }' "$src/include/linux/multikernel.h" \
     > "$build/handback-types.h"
awk '/^static int mk_cpu_set_index\(/ { copy = 1 }
     /^(bool|int) mk_cpu_set_(contains|reserve|add|del)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/cpuset.c" \
     > "$build/handback-set.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror \
    -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable \
    -Wno-sign-compare -I"$build" \
    "$test_dir/cpu_handback_test.c" -o "$build/cpu_handback_test"
"$build/cpu_handback_test"
