#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-ipi-writer.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static inline unsigned int mk_ring_idx\(/ { copy = 1 }
     /^int multikernel_send_ipi_data\(/ { copy = 1 }
     /^void mk_instance_ipi_(reset|publish|deactivate)\(/ { copy = 1 }
     /^static void mk_ipi_drain_ring\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/ipi.c" \
     > "$build/writer-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -I"$build" \
    "$test_dir/ipi_writer_test.c" -o "$build/ipi_writer_test"
"$build/ipi_writer_test"
