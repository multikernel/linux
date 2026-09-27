#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Compile verbatim production definitions; no kernel build or generated sources
# are kept in the worktree. The regression mode intentionally fails on baseline.
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-ack.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM

awk '/^#define MK_MAX_DATA_SIZE / { print }
     /^struct mk_ipi_data \{/ { copy = 1 }
     copy { print }
     copy && /^};/ { copy = 0 }
     /^#define MK_MSG_IO / { types = 1 }
     /^\/\* Opaque type/ { types = 0 }
     types { print }' "$src/include/linux/multikernel.h" > "$build/ack-types.h"

# Kernel top-level definitions end with a brace in column zero. Missing or
# incompatible definitions cause a compile failure, never a substitute model.
awk '/^struct mk_(pending_msg|msg_type_handler) \{/ { copy = 1 }
     /^static (LIST_HEAD|DEFINE_SPINLOCK)\(mk_pending_msgs/ { print }
     /^(struct mk_pending_msg \*|void |int )mk_msg_pending_/ { copy = 1 }
     /^static void mk_message_type_ipi_callback\(/ { copy = 1 }
     /^int mk_send_message\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/messaging.c" \
     > "$build/ack-messaging.h"
awk '/^static void mk_resource_msg_handler\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/hotplug.c" \
     > "$build/ack-resource.h"
awk '/^struct mk_(shutdown_work|halted_work) \{/ { copy = 1 }
     /^static void mk_system_msg_handler\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/ack-system.h"

${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" -I"$src/tools/include" "$test_dir/ack_test.c" -o "$build/ack_test"
"$build/ack_test" "$@"
