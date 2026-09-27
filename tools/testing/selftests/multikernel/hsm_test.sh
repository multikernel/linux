#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Run the production HSM code with controlled firmware results.
set -eu
ulimit -c 0
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-hsm.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM

awk '/^enum sbi_(ext_hsm_fid|hsm_hart_state) / { copy = 1 }
     /^#define SBI_(ERR_|SUCCESS)/ { print }
     /^static inline int sbi_err_map_linux_errno\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/include/asm/sbi.h" > "$build/sbi-under-test.h"
awk '/^#define (poll_timeout_us|read_poll_timeout)\(/ { copy = 1 }
     copy { print }
     copy && !/\\$/ { copy = 0 }' "$src/include/linux/iopoll.h" > "$build/poll-under-test.h"
awk '/^(static )?int sbi_hsm_(err_map_linux_errno|hart_start|hart_stop|hart_get_status)\(/ {
         copy = 1
     }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/kernel/cpu_ops_sbi.c" > "$build/hsm-under-test.h"
awk '/^#define MK_HSM_/ { print }
     /^static int mk_riscv_hart_stopped\(/ { copy = 1 }
     copy { print }
     copy && /^}/ { copy = 0 }' "$src/arch/riscv/multikernel/spawn.c" \
    > "$build/stopped-under-test.h"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$build" "$test_dir/hsm_test.c" -o "$build/hsm_test"
"$build/hsm_test"
