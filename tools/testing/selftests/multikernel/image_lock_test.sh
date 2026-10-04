#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-image-lock.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM

awk '/^typedef u64 mk_phys_cpu_t;/ { copy = 1 }
     /^\/\*\*$/ && copy && seen { exit }
     copy { print; seen = 1 }' "$src/include/linux/multikernel.h" \
     > "$build/image-types.h"
awk '/^enum mk_instance_state \{/ { copy = 1 }
     copy { print }
     copy && /^};/ { copy = 0 }' "$src/include/linux/multikernel.h" \
     >> "$build/image-types.h"
awk '/^#define KEXEC_/ { print }' "$src/include/uapi/linux/kexec.h" \
     >> "$build/image-types.h"
awk '/^#define KEXEC_TYPE_/ { print }
     /^#define KEXEC_FILE_FLAGS/ { copy = 1 }
     copy { print }
     copy && !/\\$/ { copy = 0 }' "$src/include/linux/kexec.h" \
     >> "$build/image-types.h"
awk '/^enum mk_overlay_tx_status \{/ { copy = 1 }
     /^struct mk_overlay_tx \{/ { copy = 1 }
     copy { print }
     copy && /^};/ { copy = 0 }' "$src/kernel/multikernel/overlay.c" \
     >> "$build/image-types.h"
awk '/^void mk_instance_set_state\(/ { copy = 1 }
     /^struct mk_instance \*mk_instance_find\(/ { copy = 1 }
     /^int mk_instance_set_kexec_active\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/image-instance.h"
awk '/^void kimage_free_multikernel\(/ { copy = 1 }
     /^struct kimage \*kimage_find_by_id\(/ { copy = 1 }
     /^int multikernel_kexec_by_id\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/kexec_core.c" \
     > "$build/image-core.h"
awk '/^static int$/ { candidate = $0; next }
     /^kimage_file_alloc_init\(/ { print candidate; copy = 1 }
     /^SYSCALL_DEFINE5\(kexec_file_load,/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/kexec_file.c" \
     > "$build/image-file.h"
awk '/^int mk_overlay_rmdir\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/overlay.c" \
     > "$build/image-overlay.h"

${CC:-cc} ${CFLAGS:-} -std=gnu11 -pthread -Wall -Wextra -Werror \
    -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-sign-compare \
    -I"$build" -I"$src/tools/include" "$test_dir/image_lock_test.c" \
    -o "$build/image_lock_test"
timeout 45 "$build/image_lock_test"
