#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=$(CDPATH= cd -- "$test_dir/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-messaging-registry.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
awk '/^struct mk_msg_type_handler \{/ { copy = 1 }
     /^static struct mk_msg_type_handler \*mk_msg_type_handlers;/ { print }
     /^static raw_spinlock_t mk_msg_type_handlers_lock/ { print }
     /^static DEFINE_MUTEX\(mk_msg_type_handlers_lock\);/ { print }
     /^static bool mk_messaging_/ { print }
     /^static void mk_message_type_ipi_callback\(/ { copy = 1 }
     /^int mk_(un)?register_msg_handler\(/ { copy = 1 }
     /^int __init mk_messaging_init\(/ { copy = 1 }
     /^void mk_messaging_cleanup\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/kernel/multikernel/messaging.c" \
     > "$build/registry-production.h"
${CC:-cc} ${CFLAGS:-} -std=gnu11 -pthread -Wall -Wextra -Werror \
    -I"$build" "$test_dir/messaging_registry_test.c" -o "$build/messaging_registry_test"
"$build/messaging_registry_test"
