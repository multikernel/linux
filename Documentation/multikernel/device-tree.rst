.. SPDX-License-Identifier: GPL-2.0

==========================
Multikernel Device Trees
==========================

Overview
========

Multikernel describes every kernel's share of the machine as a device tree.
Three trees exist, with one shape between them:

* **The baseline**: a request, written once by user space to
  ``/sys/fs/multikernel/device_tree``, naming what this kernel gives to
  the pool it manages.
* **The pool tree**: what ``/sys/fs/multikernel/device_tree`` reads back on
  a kernel that manages a pool, generated from live kernel state.
* **The instance tree**: what ``/sys/fs/multikernel/instances/<name>/device_tree``
  reads back for an instance, and, with a ``/chosen`` node added, the tree a
  spawn kernel boots from.

A spawn kernel is a device tree platform. Its tree is unflattened into the
OF core like a tree from a bootloader, so its PCI root buses are created
from the host bridge nodes, every bus and device below binds to its node
with ``pci_set_of_node()``, the devices it may probe are the ones with a
node, its ``/aliases`` are real aliases, and ``/chosen`` carries the boot
handoff the way ``linux,initrd-start`` or ``kaslr-seed`` would. The
flattened copy is kept at ``/sys/firmware/fdt`` and the unflattened tree
at ``/sys/firmware/devicetree/base``, as on any such platform.

The Baseline
============

The baseline is a set of allocation requests: memory sizes per NUMA node,
physical CPU ids, and devices this kernel hands to the pool. It is applied
exactly once; afterwards the pool is changed through overlays (see
``overlays.rst``)::

    /dts-v1/;
    / {
        compatible = "multikernel-v1";
        resources {
            cpus = <0x0 0x1  0x0 0x2  0x0 0x3>;     /* physical ids, u64 each */
            memory@0 {
                size = <0x0 0x20000000>;            /* 512MB, page aligned */
                numa-node-id = <0>;                 /* optional */
            };
            devices {
                pci_0000_09_00_0 {
                    device-type = "pci";
                    pci-id = "0000:09:00.0";
                    vendor-id = <0x1af4>;
                    device-id = <0x1041>;
                };
                serial_console {
                    device-type = "platform";
                    device-name = "serial8250";
                };
            };
        };
        aliases {
            enp9s0 = "/resources/devices/pci_0000_09_00_0";
        };
    };

A memory request names a size and optionally a node; the pool picks the
chunk. A PCI device is identified by its address in ``pci-id``; the node
name is free. An ``/aliases`` entry pointing at a device node gives the
device its stable name (see Naming below). A platform device is named by
``device-name`` or ``acpi-hid``.

The Pool Tree
=============

On a kernel that manages a pool, ``/sys/fs/multikernel/device_tree`` reads
back the pool::

    / {
        compatible = "multikernel-v1";
        #address-cells = <2>;
        #size-cells = <2>;
        id = <0>;
        resources {
            cpus = <0x0 0x1  0x0 0x2  0x0 0x3>;     /* every pool member */
            cpus-available = <0x0 0x2  0x0 0x3>;    /* the free subset */
            memory@59a00000 {
                device_type = "memory";
                reg = <0x0 0x59a00000  0x0 0x20000000>;
                numa-node-id = <0>;
            };
            devices { ... };                        /* platform devices only */
        };
        aliases {
            enp9s0 = "/pci@0/pci@3,0/pci@0,0";
        };
        pci@0 { ... };                              /* see Devices below */
    };

``cpus`` lists every CPU the pool owns, including CPUs lent to instances;
``cpus-available`` lists the free ones. There is one ``memory@<base>`` node
per pool chunk in the standard memory node form. Free pool PCI devices
appear under their host bridge.

The Instance Tree
=================

``/sys/fs/multikernel/instances/<name>/device_tree`` reads back what an
instance owns. The root is the instance, named by ``model``::

    / {
        compatible = "multikernel-v1";
        model = "web";
        #address-cells = <2>;
        #size-cells = <2>;
        id = <1>;
        resources {
            memory-base = <0x0 0x59a08000>;
            memory-bytes = <0x0 0x8000000>;
            cpus = <0x0 0x2  0x0 0x3>;
            devices { ... };                        /* platform devices only */
        };
        aliases {
            enp9s0 = "/pci@0/pci@3,0/pci@0,0";
        };
        pci@0 { ... };
    };

Devices
=======

PCI devices are described where the devicetree PCI bus binding puts them:
under the bus they sit on. One node per root bus the instance reaches,
then one node per bridge on the way down, then the device as a leaf::

    pci@0 {
        compatible = "multikernel,pci-host-bridge";
        device_type = "pci";
        #address-cells = <3>;
        #size-cells = <2>;
        linux,pci-domain = <0>;
        bus-range = <0x0 0xff>;
        reg = <0x0 0xb0000000  0x0 0x10000000>;    /* ECAM window, when known */
        ranges = <0x01000000 0x0 0x0  0x0 0x0  0x0 0xcf8      /* I/O */
                  0x02000000 0x0 0x80000000  0x0 0x80000000  0x0 0x30000000
                  ...>;
        pci@3,0 {                                   /* a bridge on the path */
            device_type = "pci";
            #address-cells = <3>;
            #size-cells = <2>;
            reg = <0x00001800 0 0 0 0>;             /* bus 0, device 3, fn 0 */
            bus-range = <0x9 0x9>;
            pci@0,0 {                               /* the device */
                reg = <0x00090000 0 0 0 0>;         /* bus 9, device 0, fn 0 */
                vendor-id = <0x1af4>;
                device-id = <0x1041>;
            };
        };
    };

The unit address of a device or bridge is ``device,function`` in hex and
its ``reg`` encodes bus, device and function in the first cell as the
binding prescribes, so ``pci_set_of_node()`` finds it by devfn under its
bus. ``ranges`` uses the standard 7-cell PCI encoding. ``reg`` on a host
bridge is its ECAM window; a spawn kernel installs it so that any domain
and extended config space are reachable, and falls back to port ``0xCF8``
for domain 0 without one.

The path down comes from the bus structures of the kernel that writes the
tree, so a device that has been detached from that kernel is still placed
correctly.

Platform devices stay under ``/resources/devices`` as nodes with
``device-type = "platform"`` and ``device-name`` or ``acpi-hid``.

Naming
======

A PCI device's identity is its address; names are ``/aliases`` entries, as
the devicetree specification defines them. An alias is the name the device
has in the kernel that owns it: ``enp9s0`` for a network interface. Aliases
are authored in the baseline (or a ``device-add`` to the pool carrying an
``alias`` property) and follow the device into every instance tree and boot
tree.

In a spawn kernel a network device is renamed to its alias when it
registers, found from the node its device is bound to through the OF alias
table, so it keeps the name it had on the host without any user space
involved. Block devices are not renamed: their controller numbering within
an instance is already stable, and their identity across kernels is what
``/dev/disk/by-path`` (the PCI address, unchanged in the spawn) and
``PARTUUID`` are for.

The Boot Tree
=============

A spawn kernel boots from its instance tree. The host generates the tree
into the manifest page at exec time, so it reflects the instance's
resources at the moment it starts, with a ``/chosen`` node carrying what
only the boot handoff knows::

    chosen {
        multikernel,pool-cpus = <...>;              /* CPUs it may receive later, u64 each */
        multikernel,ipi-buffer = <0x0 0x7800000>;   /* its message ring */
        multikernel,ipi-pages = <65>;
        multikernel,host-ipi-buffer = <...>;        /* the host's ring */
        multikernel,host-ipi-pages = <...>;
        multikernel,host-ipi-cpu = <...>;           /* physical doorbell CPU, u64 */
    };

On x86 the ``SETUP_MULTIKERNEL`` setup_data entry points at the page and
names it as the boot DTB; the pointer rather than a copy is what lets the
tree be finished at exec rather than at load. The kernel unflattens it
before parsing its SMP configuration, so CPU registration, the rings and
everything else read the tree through the usual ``of_*`` helpers.

What a spawn does with its tree:

* creates a PCI root bus per ``multikernel,pci-host-bridge`` node, with
  the node's bus range, windows and ECAM;
* probes a PCI slot only when the bus's node has a child at that devfn,
  which admits the bridges on the path and nothing else on the shared
  fabric, and registers a platform device only when a
  ``/resources/devices`` node names it;
* binds every bus and device to its node, so ``dev->of_node`` is set as on
  any devicetree platform;
* names network devices from ``/aliases``.

The pool-CPUs list registers every CPU the instance might be handed later,
because a kernel can only online a CPU whose physical id it enumerated at
boot.
