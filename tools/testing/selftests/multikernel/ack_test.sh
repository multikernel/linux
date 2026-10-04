#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Compile verbatim production definitions; no kernel build or generated sources
# are kept in the worktree. See README.ack for historical RED evidence/limits.
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
     /^static u64 mk_last_msg_id;/ { print }
     /^(struct mk_pending_msg \*|void |int |u64 )mk_msg_pending_/ { copy = 1 }
     /^static void mk_message_type_ipi_callback\(/ { copy = 1 }
     /^int mk_send_message(_id)?\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/messaging.c" \
     > "$build/ack-messaging.h"
awk '/^struct mk_(cpu|mem|device)_hotplug_work \{/ { copy = 1 }
     /^static DEFINE_(RAW_)?SPINLOCK\(mk_cpu_hotplug_lock\);/ { print }
     /^static struct workqueue_struct \*mk_cpu_hotplug_wq;/ { print }
     /^static (bool mk_hotplug_accepting|unsigned int mk_hotplug_inflight)/ { print }
     /^static DECLARE_WAIT_QUEUE_HEAD\(mk_hotplug_wait\);/ { print }
     /^static int mk_queue_hotplug_work\(/ { copy = 1 }
     /^static (void|bool) mk_hotplug_(work_done|idle)\(/ { copy = 1 }
     /^void mk_hotplug_quiesce\(/ { copy = 1 }
     /^static int mk_queue_cpu_work\(/ { copy = 1 }
     /^static void mk_(cpu|mem|device)_(add|remove)_work_fn\(/ { copy = 1 }
     /^(static )?int mk_handle_(cpu|mem|device)_(add|remove)\(/ { copy = 1 }
     /^static void mk_resource_msg_handler\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/hotplug.c" \
     > "$build/ack-resource.h"
awk '/^struct mk_(shutdown_work|halted_work) \{/ { copy = 1 }
     /^static void __noreturn mk_notify_down_and_park\(/ { copy = 1 }
     /^void __noreturn mk_halt_to_pool\(/ { copy = 1 }
     /^static void mk_shutdown_work_fn\(/ { copy = 1 }
     /^static void mk_system_msg_handler\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/ack-system.h"

${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" -I"$src/tools/include" "$test_dir/ack_test.c" -o "$build/ack_test"
"$build/ack_test" "$@"
