#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-kernfs-snapshot.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^static int root_device_tree_seq_show\(/ ||
     /^static ssize_t instance_device_tree_read\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/kernfs.c" \
     > "$build/kernfs-snapshot-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror \
    -Wno-unused-parameter -Wno-sign-compare -pthread -I"$build" \
    "$test_dir/kernfs_snapshot_test.c" -o "$build/kernfs_snapshot_test"
timeout 15 "$build/kernfs_snapshot_test"
