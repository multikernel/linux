#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-overlay-retention.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^enum mk_overlay_tx_status \{/ { copy = 1 }
     /^struct mk_overlay_tx \{/ { copy = 1 }
     copy { print }
     copy && /^};/ { copy = 0 }' "$src/kernel/multikernel/overlay.c" > "$build/overlay-types.h"
awk '/^static int mk_overlay_apply\(/ { copy = 1 }
     /^int mk_overlay_rmdir\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/overlay.c" > "$build/overlay-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror \
    -Wno-unused-parameter -I"$build" -I"$src/tools/include" \
    "$test_dir/overlay_retention_test.c" -o "$build/overlay_retention_test"
"$build/overlay_retention_test"
