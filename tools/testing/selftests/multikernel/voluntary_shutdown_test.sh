#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-voluntary-shutdown.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM

awk '/^static void __noreturn mk_notify_down_and_park\(/ { copy = 1 }
     /^void __noreturn mk_halt_to_pool\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/voluntary-production.h"
awk '/^static bool mk_halt_quiesced;/ { print }
     /^static void mk_halt_shutdown_prepare\(/ { copy = 1 }
     /^static (const struct syscore_ops|struct syscore) mk_halt_syscore/ { copy = 1 }
     /^static void __noreturn mk_(machine_halt|machine_restart|stop_this_cpu)\(/ { copy = 1 }
     /^static int __init mk_spawn_reboot_init\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/x86/multikernel/spawn.c" \
     >> "$build/voluntary-production.h"

${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/voluntary_shutdown_test.c" -o "$build/test"
result=0
# A separate process represents a fresh kernel, including its static permit.
for scenario in direct halt poweroff restart panic panic-late kexec kexec-late busy running host; do
    "$build/test" "$scenario" || result=1
done
exit "$result"
