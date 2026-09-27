.. SPDX-License-Identifier: GPL-2.0-only

ACK regression and characterization (development evidence)
=========================================================

From the repository root, with a host C compiler and awk:

  sh tools/testing/selftests/multikernel/ack_test.sh
  sh tools/testing/selftests/multikernel/ack_test.sh regression
  sh tools/testing/selftests/multikernel/ack_test.sh characterization
  sh tools/testing/selftests/multikernel/ack_test.sh completion

The completion mode isolates duplicate-result immutability (including after
the waiter consumes its completion token), shutdown-operation validation and
outer/inner message-family validation. It is not proof of request-ID matching.

At baseline 347841a29a940f0e4f0079ef51956d8cb4ddd3fe, the first two commands
exit 1. Eight REGRESSION assertions fail; this is intentional evidence of
missing safeguards, NOT an expected-failure wrapper or a passing test suite.
The characterization-only command exits 0 with ten CHARACTERIZATION passes.
An invalid argument exits 2. CC can select another host compiler.

What actually runs
------------------

The script extracts complete definitions verbatim from the current checkout:

* messaging.c: pending structure/list/lock, mk_msg_pending_add/complete/wait,
  mk_send_message, handler structure and mk_message_type_ipi_callback.
* hotplug.c: the complete mk_resource_msg_handler.
* core.c: the complete mk_system_msg_handler and its work structures.
* multikernel.h: complete message/IPI/payload types and protocol constants.

The repository's tools/include/linux/list.h supplies the list implementation.
Allocation, spinlocks, completions, transport and logging are host boundaries.
The u64 alias uses kernel __u64 so production printk formats remain valid with
host stdio; tools/ otherwise uses uint64_t, which is unsigned long on this host.
Non-ACK resource requests and system work scheduling abort if reached. Their
workers, ownership transitions and actual hotplug/parking are NOT simulated.

The stale tests register A, capture its ID from the real send encoder, time it
out and free it, register/send B with the same tuple, and inject A's success ACK
through both real dispatch layers. Only the transport is replaced. Request
payloads are empty because no remote worker runs: this tests the encoder's ID,
not request validation or the remote operation. ACK payloads are complete.
The baseline encoder emits zero; the dispatch path discards even nonzero IDs.

The completion boundary consumes a completion token if present, including for
a zero timeout; otherwise it immediately reports timeout. A single hook injects
an ACK after timeout is decided but before pending removal. This is a controlled
interleaving, NOT a real timer, threaded race test, kernel memory-ordering proof,
transport-delay measurement or hardware/runtime qualification. Identical and
conflicting duplicate replies are injected before the waiter reads the result.

What the expectations mean
--------------------------

REGRESSION assertions specify the proposed safe behavior:

* Delayed A ACK must not complete B (CPU add, CPU remove, shutdown). Fix requires
  distinct request identity carried through send/dispatch/worker/reply/matching.
* A conflicting duplicate must preserve the first success/error. Fix requires
  one terminal result under the pending lock, not just adding an ID comparison.
* Zero and an unissued nonzero ID must not authorize a pending operation. These
  are proposed correlation requirements, not existing wire promises. Rejecting
  zero alone cannot fix stale replies; upgraded sends and echoed IDs are needed.
* Shutdown ACK with a different operation must not complete shutdown. The
  existing handler hardcodes MK_SYS_SHUTDOWN instead of checking ack.operation.

CHARACTERIZATION assertions cover existing tuple mismatch/short-ACK rejection,
timeout cleanup, late ACK with no pending entry, the timeout/removal boundary,
identical duplicates and propagation of a matching error. They do not establish
safe correlation. Removing tuple/length checks, leaving a timed-out entry linked,
carrying a reply into a future waiter, ignoring completion, or losing an error
would break the corresponding check. Assertions also require the pending list
to be empty and unlocked after every wait. A correct future correlation change
must update fixtures/API calls to send genuine request IDs; do not invert the
regression assertions or label baseline failures as passes.

This test does not exercise requester restart, peer identity, older-peer remote
execution, CPU ownership or actual parking. Those are source-trace/proposal
items in the task report, not claims supported by these host checks. No wire
policy or production code is changed. The test is deliberately standalone and
not registered as a passing kernel selftest target.
