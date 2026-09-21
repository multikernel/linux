.. SPDX-License-Identifier: GPL-2.0

=====================
Multikernel on arm64
=====================

Everything in ``usage.rst``, ``device-tree.rst`` and ``overlays.rst``
applies unchanged. This document covers what is different below that
interface, what a platform has to provide, and what the host and a spawn
kernel need on their command lines.

Requirements
============

- PSCI 0.2 or later (``CPU_ON``, ``CPU_OFF``, ``AFFINITY_INFO``), as any
  SBSA server and QEMU's ``virt`` machine have. Spin-table platforms are
  not supported.
- A GICv3. MSIs for PCI devices of an instance need an ITS behind those
  devices; a machine may have any number of them.
- ``CONFIG_MULTIKERNEL=y``, which on arm64 needs ``CONFIG_KEXEC_FILE`` and
  ``CONFIG_HOTPLUG_CPU``. An instance is loaded from an ``Image`` file with
  ``kexec_file_load()``, not from a ``vmlinux``.

The host may have booted from a device tree or from UEFI and ACPI. A
spawn kernel always boots from a device tree.

CPUs
====

Firmware holds the pool. A pool CPU is a CPU in the PSCI ``OFF`` state: it
executes nothing, and there is no park loop or mailbox in memory. The
host moves a CPU into the pool by offlining it, a spawn is started with
``CPU_ON`` at its Image's entry point with the device tree address as the
context ID, and it brings up its other CPUs with the stock PSCI enable
method. Physical CPU IDs in the multikernel trees are MPIDR affinity
values.

A spawn kernel that halts, reboots or panics turns every one of its CPUs
off, instead of leaving them in a WFI loop inside an image the host is
about to overwrite. The host learns that a CPU has left from
``AFFINITY_INFO``, and refuses to load a new image over one that has not.

**Force halt** sends the stop IPI to each CPU of the instance. A spawn
kernel booted with ``irqchip.gicv3_pseudo_nmi=1`` (and built with
``CONFIG_ARM64_PSEUDO_NMI``) takes it as an NMI, so it reaches a CPU that
spins with interrupts masked. Without pseudo-NMIs it is an ordinary
interrupt and such a CPU stays out of reach; the instance then cannot be
started again until the machine is rebooted. SDEI is not used yet.

The Boot Tree
=============

An arm64 kernel reads its memory, its CPUs and its interrupt controller
from the tree in ``x0`` long before any multikernel code runs, so the
instance tree of ``device-tree.rst`` and the boot protocol's tree are one
and the same on arm64. The host rebuilds it on every start, from the
instance's current resources, and adds to the instance tree:

``/memory@<base>``
    One node per range of the instance's memory.

``/cpus``
    ``enable-method = "psci"`` nodes for the instance's own CPUs, the boot
    CPU first, followed by every other CPU of the machine. A kernel can
    only ever online a CPU it enumerated at boot; the ones the instance
    does not own are possible but not present until they are hot-added.

``/psci``, ``/timer``, the GICv3 node
    Copied from the host's tree, or written from the FADT, GTDT and MADT
    on an ACPI host.

``/chosen``
    ``bootargs``, the initrd and the seeds from the ``kexec_file_load()``
    call, next to the multikernel properties, and
    ``linux,pci-probe-only``: BARs and bridge windows remain the host's to
    assign.

There is no UART node. For boot messages give the spawn an explicit
``earlycon``, for example ``earlycon=pl011,mmio32,0x9000000 keep_bootcon``
on QEMU's ``virt`` machine, which polls the host's UART without taking
its interrupt.

Interrupts
==========

The GIC distributor exists once and stays with the host. The GIC node of
a boot tree carries:

``multikernel,tenant``
    The GICv3 driver leaves the distributor alone: it only checks that it
    is enabled with affinity routing, and initialises the redistributors
    and CPU interfaces of its own CPUs.

``multikernel,spis = <first count> ...``
    The SPIs the instance may map, as SPI numbers. Everything else fails
    with ``-EPERM``.

The **doorbell** of the message ring is SGI 7. All eight non-secure SGIs
are in use on arm64, so with ``CONFIG_MULTIKERNEL`` it takes the place of
the KGDB roundup IPI, and KGDB falls back to its generic roundup.

Devices
=======

Platform devices
    Granted by ``device-name``, the name under
    ``/sys/bus/platform/devices``, for instance ``a003e00.virtio_mmio``.
    The host copies the device's node into the boot tree and grants its
    SPIs, so this takes a host that booted from a device tree, and a
    device whose node refers to no clocks, resets, power domains or pin
    controllers, which stay with the host. Unbind the host's driver first;
    that also disables the SPIs on the host's side.

PCI devices
    The root buses above an instance's devices appear as
    ``pci-host-ecam-generic`` bridges with the devices as their only
    children. INTx is not available. MSIs go through the host's ITSs: the
    boot tree has a ``multikernel,gic-v3-its`` node, the spawn asks the
    host over the message ring to map each vector, and the host answers
    with the LPI that will arrive and the doorbell address to program into
    the device. The host picks the ITS behind each device, so nothing about
    the machine's ITSs appears in the tree. It drops the mappings when the
    instance halts. A root bus with no ITS behind it gets no ``msi-map``,
    and its devices no interrupts.
    Unbind the host's driver before the instance is started, and bind it
    again once the instance is stopped if the host should use the device.

IOMMU
    The SMMU stays with the host and is not described to a spawn, which
    hands physical addresses to its devices. While an instance runs, each
    of its PCI devices behind an SMMU is attached to a domain that maps
    exactly the instance's memory, and the doorbell of the ITS behind that
    device, onto itself. It
    follows memory that is added or removed at run time. A device without
    an IOMMU has unrestricted DMA.

Testing under QEMU
==================

``qemu-system-aarch64 -M virt,gic-version=3`` exercises all of the above
with its built-in PSCI; ``secure=on,virtualization=on`` with TF-A as the
firmware does so against real EL3 firmware and enters the kernels at EL2;
``iommu=smmuv3`` with ``iommu_platform=on,disable-legacy=on`` on a virtio
PCI device puts that device behind an SMMU. A spawn needs no disk: an
initramfs is enough.
