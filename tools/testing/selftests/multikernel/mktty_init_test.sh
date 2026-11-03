#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-mktty-init.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^#define MKTTY_/ { print }
     /^struct mktty_spawn_state \{/ { copy = 1 }
     /^static (struct mk_ipi_handler \*mktty_(host|spawn)_handler;|struct tty_driver \*mktty_spawn_driver;|struct mktty_spawn_state mktty_spawn;|bool mktty_console_registered;)/ { print }
     /^static (int|void) mktty_(host|spawn)_(init|cleanup)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/drivers/tty/mktty.c" > "$build/init-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/mktty_init_test.c" -o "$build/mktty_init_test"
"$build/mktty_init_test"
