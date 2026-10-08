#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-cpu-departure.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM

# Compile the real CPUHP entry points, with native teardown replaced at its
# maps-locked boundary. No live CPUs or sysfs controls are touched.
awk '/^static int cpu_down\(/ { copy = 1 }
     /^int depart_cpu\(/ { copy = 1 }
     /^static ssize_t target_store\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/cpu.c" \
     > "$build/departure-production.h"
awk '/^\t\[CPUHP_DEPARTED\] = \{/ { copy = 1 }
     copy { print }
     copy && /^\t},/ { exit }' "$src/kernel/cpu.c" \
     > "$build/departure-step.h"
awk '/^struct mk_hotplug_op \{/ { copy = 1 }
     /^static int mk_cpu_to_logical\(/ { copy = 1 }
     /^static int mk_do_cpu_remove\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/hotplug.c" \
     > "$build/departure-hotplug.h"

${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror \
    -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare -I"$build" \
    "$test_dir/cpu_departure_test.c" -o "$build/cpu_departure_test"
"$build/cpu_departure_test"
