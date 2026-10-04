#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-mktty-lifetime.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^#define MKTTY_/ { print }
     /^struct mktty_(message|host_conn) \{/ { copy = 1 }
     /^static LIST_HEAD\(mktty_host_conns\);/ { print }
     /^static DEFINE_SPINLOCK\(mktty_host_conns_lock\);/ { print }
     /^static struct mktty_host_conn \*mktty_find_conn\(/ { copy = 1 }
     /^static (int|ssize_t|__poll_t|void) mktty_host_(open|release|read|write|poll|ipi_handler)\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/drivers/tty/mktty.c" \
     > "$build/mktty-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -pthread -Wall -Wextra -Werror \
    -Wno-unused-parameter -Wno-sign-compare \
    -I"$build" "$test_dir/mktty_lifetime_test.c" \
    -o "$build/mktty_lifetime_test"
"$build/mktty_lifetime_test"
