.. SPDX-License-Identifier: GPL-2.0

RISC-V lifecycle and entry cache maintenance
==========================================

The #23--#25 series requires SBI HSM and supervisor-mode rv64 multikernel
kernels. It does not provide the #26 Image loader, #27 boot-tree CPU/intc
description or #28 parent doorbell/panic-notification transport. Generic
controller serialization and confirmed-stop retirement are separate master
prerequisites. Force-stop is unsupported on RISC-V and must fail closed.

Both host and spawn must use kernels with ``CONFIG_BUILTIN_DTB=n`` and
``CONFIG_RISCV_BOOT_SPINWAIT=n``; Kconfig excludes multikernel otherwise.
A built-in DTB replaces the supplied manifest before spawn detection, leaving
host-wide reset setup enabled. Spinwait boot rejects physical hart IDs beyond
``NR_CPUS`` and can leave a hart waiting in Image memory instead of HART_STOP.
Ordered SBI HSM boot avoids that physical-ID bound. These checks constrain
kernel builds, not arbitrary foreign Images loaded by the host.

The host owns two adjacent control pages for the instance lifetime: a mutable
entry record followed by immutable entry code. Before each start, the host
copies the Image and writes the current entry, then publishes those stores
before HART_START. The copied stub executes fence.i, finds the preceding page
from its PC, reads the entry and jumps without modifying a0 (physical hartid)
or a1 (primary boot tree or secondary SBI boot data). The code uses neither an
embedded mutable entry immediate nor an absolute relocation target.

A fence.i at the start of a newly copied code page alone is insufficient: the
first instruction fetch can see an earlier occupant of that physical page.
Every assigned hart first runs mk_riscv_entry_fence_stop in immutable, reserved
host text, executes fence.i and HART_STOP. The host confirms STOPPED before
starting the copied stub. Linux pool entry also fences before HART_STOP. This
is a first-fetch priming handshake, not an assumption that a stopped hart can
service a remote-fence request. Host text must stay reserved and unchanged.

Using SBI's opaque argument for an entry record would put that record in a1;
an alternative must recover the boot-tree/secondary argument before entry and
still avoid fetching recycled code before a local fence.i. The adjacent-page
design preserves the firmware boot arguments directly. Secondary entry updates
the record through memremap, so a no-map control reservation need not be in the
spawn linear map. The child must reserve all host-owned control pages (#27).

On the modern foundation, a1 names the execution-time 256KB instance manifest,
not a separate load-time clone of the host DTB. Manifest and ring pages are
persistent host allocations outside the Image grant. #27 must emit assigned
hart/intc nodes, initrd/boot arguments and the required no-map reservations in
that boot tree. Reclaim is allowed only after every assigned/tracked hart is
confirmed stopped. A timeout, failed query or STOP_PENDING cannot authorize
reuse; a STOPPED observation does not cancel outstanding remote start work.

Requested and voluntary shutdown, reboot and panic stop local harts with HSM;
spawn reset must never reach SRST or legacy shutdown. With panic_timeout=0,
the spawn panic notifier halts immediately rather than leaving the panic CPU
in the generic infinite wait loop. With a nonzero timeout, the notifier returns
to the generic panic path: positive values delay restart, while negative values
restart without that delay. The spawn restart override stops locally in either
case; it must not reset the host. Parent notification is a separate #28 concern.
An unexpected HART_STOP return leaves a local wait loop, so the host must fail
confirmation and retain resources. Ring reset is not a remote-work retirement
protocol and does not supply #7/session guarantees. Matched revisions and fresh
QEMU/OpenSBI failure and replacement tests remain release gates.
