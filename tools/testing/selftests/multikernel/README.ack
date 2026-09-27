.. SPDX-License-Identifier: GPL-2.0-only

ACK correlation checks
======================

From the repository root, with a host C compiler and awk:

  sh tools/testing/selftests/multikernel/ack_test.sh

Optional modes: regression, characterization, completion, workers, failure.
Each selected mode must exit 0; an invalid argument exits 2. CC and CFLAGS
select the compiler and instrumentation, for example:

  CC=clang CFLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer' \
    sh tools/testing/selftests/multikernel/ack_test.sh

What actually runs
------------------

The runner extracts complete definitions verbatim from the current checkout:
pending allocation/ID/completion/wait/cancel, message encoder and dispatch,
resource dispatch and all six receive handlers/workers, system dispatch and
shutdown worker/notification/parking entry. The repository's tools/ list and
error-pointer helpers are used. No alternate implementation of this logic is
compiled. Production changes that break extraction fail compilation.

Allocation, spinlocks, completions, transport, work scheduling, hardware
mutation and final CPU parking are deterministic host boundaries. No real CPU,
memory or PCI ownership transition occurs. The six sending resource helpers
and multikernel_halt_by_id are checked by source review and kernel builds, not
executed by this harness. Cancellation tests cover the pending/encoder APIs,
not those callers' resource rollback behavior.

Checks include:

* Delayed CPU add/remove and shutdown ACK A cannot complete retry B.
* IDs and type/operation/resource must all match; zero is not a pending ID.
* Conflicting duplicates preserve the first result, even after the waiter
  consumes its completion token. A wait that reported timeout stays timed out
  if an ACK arrives before list removal.
* Real workers retain IDs after the receive buffer is overwritten, echo both
  zero and full-width nonzero IDs, preserve results and route replies to the
  requester. Allocated-ID round trips pass through both real dispatch layers.
* Allocation/send failures, cancellation before/after completion, concurrent
  outstanding same-tuple requests, the last u64 ID and exhaustion are checked.
* Voluntary HALTED and the uncorrelated sender retain their zero-ID behavior.
* PCI add/remove ACKs match requester keys for domains 0x8000 and 0xffff;
  signed promotion must not sign-extend the worker's u64 resource key.

This is controlled interleaving, not a threaded race, kernel memory-ordering,
transport-delay, boot or physical-runtime test. Pending entries must be removed
and the lock released after wait/cancel. Sanitizers can check local memory use
but do not qualify these substituted kernel boundaries.

Protocol limits
---------------

The existing header and payload layouts are unchanged. Qualify matched-revision
host/spawn kernels; differing configurations are allowed, mixed revisions are
not qualified. Legacy zero-ID requests still execute and echo zero, but their
replies cannot satisfy a new pending request. An old responder can execute a
new request and return an unusable zero-ID ACK: rejecting it is not rollback.

IDs are unique only during one requester kernel lifetime. They are not peer
authentication or session identity. Requester restart with surviving peers,
queued work across restart, remote cancellation, CPU ownership recovery and
safe image/ring reclamation require separate work. A shutdown ACK means the
peer is about to park, not proof that all its CPUs have stopped.

Known baseline sanitizer failure
--------------------------------

Full UBSan with -fno-sanitize-recover=undefined reports unaligned resource/ACK
payload access: mk_message.payload starts at offset 20 on rv64/x86_64 while
several payload structs require 8-byte alignment. Reproduced with the original
characterization test at 11efe070fdd57c9e3f71218c92989697723f9a84 (before these
fixes). Do not report full UBSan as passing, or change the wire layout to hide
it. A wire-preserving alignment fix is a separate follow-up.

Historical RED evidence: the original test at 11efe070 (on upstream 347841a29a94)
failed eight regression assertions and passed ten characterizations. Worker
echo tests additionally reproduced loss of nonzero IDs in all seven workers
before ID plumbing. These are not expected-failure wrappers; current logical
checks and ASan must pass.
