#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-boot-order.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static int mk_spawn_panic_notify\(/ { copy = 1 }
     /^static struct notifier_block mk_spawn_panic_notifier / { copy = 1 }
     /^void __init setup_arch\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/kernel/setup.c" > "$build/setup.h"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function \
    -I"$build" "$test_dir/boot_order_test.c" -o "$build/test"
"$build/test"
