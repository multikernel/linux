#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-shutdown.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static void (default_power_off|mk_spawn_stop)\(/ ||
     /^void machine_(restart|halt|power_off)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/kernel/reset.c" > "$build/under-test.h"
awk '/^machine_crash_shutdown\(/ { print "void"; copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/kernel/machine_kexec.c" > "$build/crash.h"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-function \
    -I"$build" "$test_dir/shutdown_test.c" -o "$build/test"
"$build/test"
