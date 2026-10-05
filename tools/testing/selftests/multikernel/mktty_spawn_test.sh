#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-mktty-spawn.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^#define MKTTY_/ { print }
     /^struct mktty_(message|spawn_state) \{/ { copy = 1 }
     /^static struct mktty_spawn_state mktty_spawn;/ { print }
     /^static (DECLARE_WORK|DEFINE_KFIFO)\(mktty_spawn_rx/ { print }
     /^static void mktty_spawn_receive_work\(struct work_struct \*work\);/ { print; next }
     /^static (int|void) mktty_spawn_(activate|shutdown|hangup|ipi_handler|receive_work|report_drops)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/drivers/tty/mktty.c" > "$build/spawn-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/mktty_spawn_test.c" -o "$build/mktty_spawn_test"
"$build/mktty_spawn_test"
