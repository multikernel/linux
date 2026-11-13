.. SPDX-License-Identifier: GPL-2.0

======================
Multikernel on RISC-V
======================

Everything in ``usage.rst``, ``device-tree.rst`` and ``overlays.rst``
applies unchanged. This document covers what is different below that
interface, what a platform has to provide, and what a spawn kernel needs
on its command line.

Requirements
============

- SBI firmware with the HSM and IPI extensions, as OpenSBI has. All harts
  must be in the OpenSBI domain the host boots in; see `OpenSBI Domains`_.
- An IMSIC for MSIs, if an instance is to have PCI devices with
  interrupts. A machine with only a PLIC or an APLIC in direct mode gives
  its instances PCI devices without interrupts.
- ``CONFIG_MULTIKERNEL=y`` on a 64-bit kernel, which on RISC-V needs
  ``CONFIG_KEXEC_FILE`` and ``CONFIG_HOTPLUG_CPU``. An instance is loaded
  from an ``Image`` file with ``kexec_file_load()``, not from a
  ``vmlinux``.

Both the host and a spawn boot from a device tree.

Harts
=====

Firmware holds the pool. A pool hart is a hart in the SBI HSM ``STOPPED``
state: it executes nothing, and there is no park loop, mailbox or page
table in memory. The host moves a hart into the pool by offlining it,
and starts a spawn with one ``HART_START`` call, which enters S-mode with
the MMU off, the hart ID in ``a0`` and the opaque argument in ``a1``. The
spawn brings up its other harts with the stock SBI enable method. The
host learns that a hart has left from ``HART_STATUS``, and refuses to load
a new image over one that is not ``STOPPED``. Physical CPU IDs in the
multikernel trees are hart IDs.

**Instruction caches.** RISC-V has no remote instruction cache
invalidation, the kernel's entry code does not execute ``fence.i`` and
OpenSBI does not on ``HART_START``. A hart that ran an earlier image can
therefore fetch stale instructions of it after a new image was loaded at
the same address. Every hart a multikernel kernel starts, the boot hart
of a spawn and the spawn's own secondaries alike, enters through a small
stub in the host's kernel text that executes ``fence.i`` and then jumps to
the real entry. The stub stays put for as long as the host runs, so it
can never be stale itself, and the spawn learns its address from the
``multikernel,hart-entry`` property in ``/chosen``.

**Going down.** Stock RISC-V halts, powers off and reboots through SBI
SRST, which acts on the whole machine, and leaves stopped harts in a WFI
loop inside the kernel image. A spawn kernel that halts, reboots or
panics stops every one of its harts with ``HART_STOP`` instead, so the
host keeps running and can start the harts again. A spawn's
``panic_timeout`` is -1 for the same reason.

**Force halt** is best effort. RISC-V has no S-mode NMI, so the host
marks the instance as being halted and rings the doorbell of each of its
harts; a hart that takes the interrupt stops itself. A hart that spins
with interrupts masked stays out of reach, and the instance cannot be
started again until the machine is rebooted. The SBI Supervisor Software
Events extension, once Linux supports it, is the way to reach such a
hart.

The Boot Tree
=============

A RISC-V kernel reads its memory, its harts and their local interrupt
controllers from the tree in ``a1`` before any multikernel code runs, so
the instance tree of ``device-tree.rst`` and the boot protocol's tree are
one and the same. The host rebuilds it on every start, from the
instance's current resources, and adds to the instance tree:

``/memory@<base>``
    One node per range of the instance's memory.

``/cpus``
    The host's own hart nodes, copied as they are: the ISA string, MMU
    type and cache block sizes describe the hart as firmware set it up.
    The instance's own harts come first, the boot hart leading, followed
    by every other hart of the machine. A kernel can only ever online a
    hart it enumerated at boot; the ones the instance does not own are
    possible but not present until they are hot-added.

The supervisor level IMSIC
    Copied from the host's tree, when it has one.

``/chosen``
    ``bootargs``, the initrd and the seeds from the ``kexec_file_load()``
    call, next to the multikernel properties, ``multikernel,hart-entry``
    and ``linux,pci-probe-only``: BARs and bridge windows remain the
    host's to assign.

There is no UART node. ``earlycon=sbi`` gives a spawn boot messages
through the firmware console where SBI has the debug console extension
(SBI 2.0), or the kernel the legacy console (``CONFIG_RISCV_SBI_V01``).
Otherwise give it an explicit ``earlycon``, for example
``earlycon=uart8250,mmio,0x10000000 keep_bootcon`` on QEMU's ``virt``
machine, which polls the host's UART without taking its interrupt.

Interrupts
==========

The **doorbell** of the message ring is an SBI IPI, a supervisor software
interrupt on the target hart, whatever provides the kernels' own IPIs.
Where the IMSIC provides them, the software interrupt is taken for the
doorbell alone. Where an ACLINT SSWI device provides them, the software
interrupt is already its own and a kernel has no doorbell; it says so at
boot.

The PLIC and the APLIC exist once and stay with the host: their
priority, enable and target registers for one source sit next to those
of sources other kernels use, and the APLIC's domain configuration is
global. The boot tree describes neither, and a spawn has no wired
interrupts.

An IMSIC has one interrupt file per hart, and an MSI is a write into the
file of the hart it targets. A spawn's IMSIC driver only programs the
files of the harts it brings online, so the spawn owns the MSIs of its
PCI devices outright and composes the messages itself.

Devices
=======

Platform devices
    Not supported, as their interrupts are wired. An instance that has
    platform devices fails to start.

PCI devices
    The root buses above an instance's devices appear as pcifront
    bridges with the devices as their only children. INTx is not
    available. MSIs go to the spawn's own IMSIC files, which every bridge
    has as its MSI domain. Unbind the host's driver before the instance
    is started, and bind it again once the instance is stopped if the
    host should use the device.

IOMMU
    Not supported yet. A spawn hands physical addresses to its devices,
    and their DMA is unrestricted.

OpenSBI Domains
===============

OpenSBI can partition a machine into domains, each with its own harts
and memory, and boot a separate kernel in each. That is a static
partition, which a multikernel does not need: the host's pool already
divides the harts and memory, and can do so again while the machine
runs. OpenSBI fails ``HART_START`` and ``HART_STATUS`` on a hart of
another domain, so a spawn only works within the domain of its host. A
kernel that meets such a hart says that it is outside its OpenSBI
domain. Leave every hart in the root domain, which is OpenSBI's default
when the tree has no ``opensbi-domains`` node.

Testing under QEMU
==================

``qemu-system-riscv64 -M virt`` with its default OpenSBI exercises all of
the above except MSIs, which need ``-M virt,aia=aplic-imsic``. A spawn
needs no disk: an initramfs is enough.
