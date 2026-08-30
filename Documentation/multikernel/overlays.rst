.. SPDX-License-Identifier: GPL-2.0

================================
Multikernel Device Tree Overlays
================================

Overview
========

The device tree overlay subsystem adjusts multikernel resources at runtime
without a reboot. Each overlay is a transaction that can be applied and rolled
back as a unit.

Overlays can:

* **Resize the pool**: move memory, CPUs and PCI devices between the kernel
  that manages the pool and the pool itself
* **Create and destroy instances**
* **Move resources**: hand pool resources to an instance and take them back
* **Combine operations**: several fragments in one transaction

Filesystem Layout
=================

The overlay subsystem lives at ``/sys/fs/multikernel/overlays/``::

    /sys/fs/multikernel/
     ├── device_tree                 # This kernel's pool, see Read-back below
     ├── instances/                  # Runtime kernel instances
     └── overlays/                   # Overlay subsystem
          ├── new                    # Control file: write DTBO here
          ├── tx_101/                # Applied overlay transaction
          │    ├── id                # Transaction ID: "101"
          │    ├── status            # "applied" | "failed" | "removed"
          │    ├── instance          # Target path of the first fragment
          │    ├── resources         # Optional mk,resources description
          │    └── dtbo              # Original overlay blob (binary)
          └── tx_102/
               └── ...

Overlay Format
==============

Fragments and Targets
---------------------

A transaction is a device tree overlay holding any number of fragments. Every
fragment names what it modifies with the standard ``target-path`` property and
carries its operations under ``__overlay__``:

``target-path = "/resources"``
    The pool this kernel manages. Accepted only by a kernel that has been
    given a baseline; any other kernel rejects the fragment with ``-EPERM``.

``target-path = "/instances/<name>"``
    An existing instance, looked up by name. The name must not be empty and
    must not contain ``/``. A spawn kernel modifies itself through its own
    name here.

``target-path = "/instances"``
    The instance namespace: ``instance-create`` and ``instance-remove``.

Any other target path is rejected with ``-EINVAL``.

Operations Read From the Target
-------------------------------

Operation names describe what happens to the target, so the same name means
different work depending on the fragment it sits in:

.. list-table::
   :header-rows: 1

   * - Operation
     - Under ``/resources``
     - Under ``/instances/<name>``
   * - ``memory-add``
     - Grow the pool by a new chunk
     - Give an existing range to the instance
   * - ``memory-remove``
     - Shrink the pool, returning a chunk to this kernel
     - Take a range back from the instance
   * - ``cpu-add``
     - Move a CPU of this kernel into the pool
     - Give a free pool CPU to the instance
   * - ``cpu-remove``
     - Return a free pool CPU to this kernel
     - Take a CPU back from the instance
   * - ``device-add``
     - Move a PCI device of this kernel into the pool
     - Give a free pool device to the instance
   * - ``device-remove``
     - Return a free pool device to this kernel
     - Take a device back from the instance

Operation Sections
------------------

**instance-create** (under ``/instances``)
    Creates a new kernel instance.

    Properties:
      - ``instance-name``: instance name (string, no ``/``)
      - ``id``: instance ID (u32, optional, auto-allocated when absent)

    Subnodes:
      - ``resources``: initial allocation for the instance

    ``resources`` properties:
      - ``memory-bytes``: amount of pool memory to give the instance (u64)
      - ``cpus``: physical CPU IDs to give the instance (array of u64)
      - ``numa-nodes``: NUMA nodes to allocate the memory from (array of u32,
        optional). Only the first entry is used; the memory comes from that
        node's pool chunks, or from any node when the property is absent.

    Example::

        instance-create {
            instance-name = "my-kernel";
            id = <1>;
            resources {
                memory-bytes = <0x0 0x40000000>;    /* 1GB */
                cpus = <0x0 0x4  0x0 0x5  0x0 0x6>;
                numa-nodes = <0>;
            };
        };

**instance-remove** (under ``/instances``)
    Destroys an instance.

    Properties:
      - ``instance-name``: instance name (string)

**memory-add**
    Subnodes are ``memory@N`` items. Under ``/resources`` an item is a
    request, since the pool picks the base:

      - ``size``: chunk size in bytes (u64, non-zero, page aligned)
      - ``numa-node-id``: NUMA node (u32, optional, any node when absent)
      - ``reg`` is rejected here

    Under ``/instances/<name>`` an item names an existing range:

      - ``reg``: <addr-hi addr-lo size-hi size-lo> (u64 address, u64 size)
      - ``numa-node-id``: NUMA node (u32, optional)
      - ``mem-type``: memory type (u32, optional)

**memory-remove**
    Subnodes are ``memory@N`` items naming an existing range in both cases:

      - ``reg``: <addr-hi addr-lo size-hi size-lo>

    Under ``/resources`` the base and size must match a whole pool chunk as
    reported by the root ``device_tree``.

**cpu-add**, **cpu-remove**
    Subnodes are ``cpu@N`` items:

      - ``reg``: physical CPU ID (u64, or a single u32 cell)
      - ``numa-node-id``: NUMA node (u32, optional)
      - ``flags``: CPU flags (u32, optional)

**device-add**, **device-remove**
    Subnodes are ``pci@N`` items:

      - ``pci-id``: "DDDD:BB:SS.F" (string)
      - ``alias``: stable name for the device tree ``/aliases`` node, such
        as "nvme0" (string, optional, ``device-add`` to the pool only)
      - ``driver``: driver to bind (string, optional, ``device-add`` to an
        instance only)
      - ``flags``: device flags (u32, optional)

Ordering
--------

Fragments are processed in ascending order of their unit address:
``fragment@0``, ``fragment@1``, and so on. Within a fragment, operations run
in this order so that a resource is released by its source before its
destination acquires it:

1. ``instance-create``
2. ``memory-remove``
3. ``memory-add``
4. ``cpu-remove``
5. ``cpu-add``
6. ``device-remove``
7. ``device-add``
8. ``instance-remove``

A ``/resources`` fragment runs ``memory-remove`` after ``cpu-remove`` and
``device-remove`` instead, so resources leave the pool in the order CPU,
device, memory and join it in the order memory, CPU, device:

1. ``cpu-remove``
2. ``device-remove``
3. ``memory-remove``
4. ``memory-add``
5. ``cpu-add``
6. ``device-add``

The host park area that every pool CPU runs on is allocated from pool
memory, and the kernel can only release it once those CPUs have come back.
Taking the CPUs first lets a single fragment return every CPU and remove
every chunk, which empties the pool and allows a new baseline to be
applied. A ``memory-remove`` that would strand parked CPUs fails with
``-EBUSY``. The area is built again in whatever memory the pool has left,
or by whichever chunk next gives it some, so a pool that has memory can
always park a CPU.

Rollback (``rmdir`` on the transaction directory) walks both orders in
reverse and sends the inverse of each operation.

Two cases cannot be undone exactly and are logged as warnings rather than
failing the rollback:

* ``instance-remove``: the destroyed instance's configuration is not kept.
  Re-create it with a new ``instance-create`` overlay.
* ``/resources memory-add``: the pool chose the chunk base at grow time and
  the overlay never recorded it, so no chunk can be identified for a shrink.

Rolling back ``/resources memory-remove`` regrows the pool by the same size.
The new chunk has a different base, because the old range went back to the
page allocator. A host park area released along the way is rebuilt inside
the new chunk, so the restored pool can park CPUs again.

Root Device Tree Read-back
==========================

``/sys/fs/multikernel/device_tree`` is generated from live kernel state. In a
kernel that manages a pool, its ``/resources`` node describes the pool::

    / {
        compatible = "multikernel-v1";
        #address-cells = <2>;
        #size-cells = <2>;
        id = <0>;
        resources {
            cpus = <...>;                       /* every pool member */
            cpus-available = <...>;             /* the free subset */

            memory@100000000 {
                device_type = "memory";
                reg = <0x1 0x00000000  0x0 0x40000000>;
                numa-node-id = <0>;
            };
        };
        aliases { ... };
        pci@0 { ... };                          /* free pool PCI devices */
    };

``cpus`` lists every CPU the pool owns, including CPUs currently lent to
instances; ``cpus-available`` lists only the free ones. There is one
``memory@<base>`` node per pool chunk, in the standard memory node form, and
its ``reg`` is what a ``/resources memory-remove`` item must name. Free pool
PCI devices are described under their host bridge in the devicetree PCI bus
binding, and ``/aliases`` names them; the ``pci-id`` a ``device-add`` or
``device-remove`` item must name is the address encoded in a device node's
``reg``. See ``device-tree.rst`` for the full layout.

Examples
========

Growing the Pool and Moving a Host CPU Into It
----------------------------------------------

::

    /dts-v1/;
    /plugin/;

    / {
        fragment@0 {
            target-path = "/resources";
            __overlay__ {
                memory-add {
                    memory@0 {
                        size = <0x0 0x40000000>;        /* 1GB */
                        numa-node-id = <0>;
                    };
                };

                cpu-add {
                    cpu@20 { reg = <0x0 0x14>; };
                    cpu@21 { reg = <0x0 0x15>; };
                };
            };
        };
    };

Apply it::

    dtc -O dtb -o grow_pool.dtbo -@ grow_pool.dts
    cat grow_pool.dtbo > /sys/fs/multikernel/overlays/new

    cat /sys/fs/multikernel/overlays/tx_101/status
    # applied

Handing Pool Resources to an Instance
-------------------------------------

::

    /dts-v1/;
    /plugin/;

    / {
        fragment@0 {
            target-path = "/instances/database";
            __overlay__ {
                memory-add {
                    memory@0 {
                        reg = <0x1 0x00000000  0x0 0x40000000>;
                        numa-node-id = <0>;
                    };
                };

                cpu-add {
                    cpu@20 { reg = <0x0 0x14>; numa-node-id = <0>; };
                    cpu@21 { reg = <0x0 0x15>; numa-node-id = <0>; };
                };

                device-add {
                    pci@0 {
                        pci-id = "0000:65:00.0";
                        driver = "vfio-pci";
                    };
                };
            };
        };
    };

The CPUs and the device must be free in the pool, and the memory range must
lie inside a pool chunk. Roll the whole transaction back with::

    rmdir /sys/fs/multikernel/overlays/tx_102

Creating an Instance and Feeding It in One Transaction
------------------------------------------------------

Fragments run in unit-address order, so the instance exists by the time the
second fragment refers to it::

    /dts-v1/;
    /plugin/;

    / {
        fragment@0 {
            target-path = "/instances";
            __overlay__ {
                instance-create {
                    instance-name = "compute";
                    id = <3>;
                    resources {
                        memory-bytes = <0x0 0x10000000>;    /* 256MB */
                        cpus = <0x0 0x8>;
                    };
                };
            };
        };

        fragment@1 {
            target-path = "/instances/compute";
            __overlay__ {
                cpu-add {
                    cpu@9  { reg = <0x0 0x9>;  numa-node-id = <1>; };
                    cpu@10 { reg = <0x0 0xa>;  numa-node-id = <1>; };
                };
            };
        };
    };

Transaction Metadata
====================

::

    cat /sys/fs/multikernel/overlays/tx_101/id
    # 101

    cat /sys/fs/multikernel/overlays/tx_101/status
    # applied | failed | removed | pending

    cat /sys/fs/multikernel/overlays/tx_101/instance
    # /resources          (target path of the first fragment)

    cat /sys/fs/multikernel/overlays/tx_101/resources
    # value of the optional mk,resources property at the overlay root

The original blob stays readable at ``tx_101/dtbo``.

Error Handling
==============

A failed overlay still creates a transaction with ``status = failed``; check
``dmesg`` for the reason and ``rmdir`` the directory to clear it.

**Pool target on a kernel without a pool**
    ``-EPERM``. Only a kernel that was given a baseline manages a pool.

**Unsupported target-path**
    ``-EINVAL``. Use ``/resources``, ``/instances`` or ``/instances/<name>``.

**Instance not found**
    ``-ENOENT`` from a ``/instances/<name>`` fragment. Create it first or fix
    the name.

**Resource not free in the pool**
    ``-EBUSY``. The CPU or device is lent to an instance; take it back first.

**Invalid resource specification**
    ``-EINVAL``. ``size`` must be 8 bytes, non-zero and page aligned; ``reg``
    must be 16 bytes; ``numa-node-id`` must be 4 bytes and a valid node.

**Instance active or loading**
    Rollback cannot destroy a running instance. Stop it first.

See Also
========

* The trees themselves: ``Documentation/multikernel/device-tree.rst``
* Linux device tree documentation: ``Documentation/devicetree/``
* Overlay notes: ``Documentation/devicetree/overlay-notes.rst``
* Device tree compiler: ``dtc(1)``
