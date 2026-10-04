#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-cpu-work.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM

awk '/^#define MK_MSG_IO / { copy = 1 }
     /^\/\* Opaque type/ { copy = 0 }
     copy { print }' "$src/include/linux/multikernel.h" > "$build/work-types.h"
awk '/^struct mk_hotplug_op \{/ { copy = 1 }
     /^static DEFINE_MUTEX\(mk_hotplug_mutex\);/ { print }
     /^static LIST_HEAD\(mk_hotplug_ops\);/ { print }
     /^static DEFINE_(RAW_)?SPINLOCK\(mk_cpu_hotplug_lock\);/ { print }
     /^static struct workqueue_struct \*mk_cpu_hotplug_wq;/ { print }
     /^static (bool mk_hotplug_accepting|unsigned int mk_hotplug_inflight)/ { print }
     /^static DECLARE_WAIT_QUEUE_HEAD\(mk_hotplug_wait\);/ { print }
     /^static (int|struct workqueue_struct \*)mk_cpu_hotplug_/ { copy = 1 }
     /^static int mk_queue_cpu_work\(/ { copy = 1 }
     /^static int mk_queue_hotplug_work\(/ { copy = 1 }
     /^static (void|bool) mk_hotplug_(work_done|idle)\(/ { copy = 1 }
     /^void mk_hotplug_quiesce\(/ { copy = 1 }
     /^struct mk_(cpu|mem|device)_hotplug_work \{/ { copy = 1 }
     /^static void mk_(cpu|mem|device)_(add|remove)_work_fn\(/ { copy = 1 }
     /^(static )?int mk_handle_(cpu|mem|device)_(add|remove)\(/ { copy = 1 }
     /^int __init mk_hotplug_init\(/ { copy = 1 }
     /^void mk_hotplug_cleanup\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/hotplug.c" \
     > "$build/work-production.h"
awk '/^struct mk_shutdown_work \{/ { copy = 1 }
     /^static void __noreturn mk_notify_down_and_park\(/ { copy = 1 }
     /^static void mk_shutdown_work_fn\(/ { copy = 1 }
     /^static int __init multikernel_init\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/core.c" \
     > "$build/work-shutdown.h"

${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" -I"$src/tools/include" "$test_dir/cpu_work_test.c" \
    -o "$build/cpu_work_test"
"$build/cpu_work_test"
