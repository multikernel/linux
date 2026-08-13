===================================
Multikernel Kernfs Interface Usage
===================================

Overview
========

The multikernel kernfs interface provides a clean, user-friendly way to manage multikernel instances through the filesystem. The interface is located at ``/sys/fs/multikernel/`` and supports automatic instance creation from multikernel device trees.

Architecture
============

::

    /sys/fs/multikernel/
    ├── device_tree         # Root-level DTB upload (write-only)
    └── instances/          # Instance directory
        ├── web-server/     # Instance created from DTB
        │   ├── id          # Instance ID (read-only)
        │   ├── status      # Instance status (read-only)
        │   └── device_tree_source  # Instance DTB in DTS format (read-only)
        ├── database/       # Another instance
        │   ├── id
        │   ├── status
        │   └── device_tree_source
        └── ...

Workflow
========

Phase 1: Instance Creation (Automatic from DTB)
------------------------------------------------

1. **Create Multikernel Device Tree**

   Create a device tree with multiple instances:

   .. code-block:: dts

      /dts-v1/;
      / {
          compatible = "multikernel-v1";

          instances {
              web-server {
                  id = <1>;
                  resources {
                      cpus = <1>;
                      memory-bytes = <0x20000000>;   // 512MB
                      llc-way-mask = <0x0000ffff>;  // Lower half of LLC ways
                  };
              };

              database {
                  id = <2>;
                  resources {
                      cpus = <2 3>;
                      memory-bytes = <0x40000000>;   // 1GB
                  };
              };
          };
      };

2. **Upload Multikernel DTB**

   .. code-block:: bash

      # Compile device tree to binary format
      dtc -O dtb -o multikernel.dtb multikernel.dts

      # Upload DTB to create instances automatically
      cat multikernel.dtb > /sys/fs/multikernel/device_tree

   This automatically:

   - Validates DTB format and multikernel-v1 compatibility
   - Parses each instance in the ``/instances`` node
   - Creates instance directories under ``instances/``
   - Reserves memory and CPU resources for each instance
   - Updates each instance status to "ready"

3. **Check Created Instances**

   .. code-block:: bash

      # List created instances
      ls /sys/fs/multikernel/instances/
      # Output: database  web-server

      # Check instance details
      cat /sys/fs/multikernel/instances/web-server/id
      # Output: 1

      cat /sys/fs/multikernel/instances/web-server/status
      # Output: ready

      # View instance device tree
      cat /sys/fs/multikernel/instances/web-server/device_tree_source
      # Output: DTS format showing the instance configuration

Phase 2: Kernel Loading (Kexec Integration)
--------------------------------------------

1. **Load Kernel Image**

   .. code-block:: bash

      # Load kernel for instance ID 1 (web-server)
      kexec_file_load(..., KEXEC_MULTIKERNEL | KEXEC_MK_ID(1))

   This:

   - Finds pre-reserved resources for instance ID 1
   - Creates kimage using pre-allocated memory and CPU resources
   - Updates status to "loading" → "active"
   - Preserves instance DTB for KHO (Kexec HandOver) restoration

2. **Instance DTB Preservation**

   The multikernel system automatically preserves each instance's device tree during kexec for restoration in the spawn kernel. The spawn kernel will:

   - Detect multikernel KHO data during early boot
   - Restore the instance's DTB and recreate the instance structure
   - Re-reserve the same memory and CPU resources

Device Tree Format
==================

Multikernel DTB Structure
--------------------------

The multikernel device tree uses the ``/instances`` structure with ``multikernel-v1`` compatibility:

.. code-block:: dts

    /dts-v1/;
    / {
        compatible = "multikernel-v1";

        instances {
            web-server {
                id = <1>;
                resources {
                    cpus = <1>;                      // CPU ID 1
                    memory-bytes = <0x20000000>;     // 512MB
                    llc-way-mask = <0x0000ffff>;     // resctrl L3 CBM
                };
            };

            database {
                id = <2>;
                resources {
                    cpus = <2 3>;                    // CPU IDs 2 and 3
                    memory-bytes = <0x40000000>;     // 1GB
                };
            };

            load-balancer {
                id = <3>;
                resources {
                    cpus = <0>;                      // CPU ID 0
                    memory-bytes = <0x10000000>;     // 256MB
                };
            };
        };
    };

Per-Instance DTB Format
-----------------------

When viewing an instance's ``device_tree_source``, it appears in per-instance format:

.. code-block:: dts

    /dts-v1/;

    /web-server {
        compatible = "multikernel-v1";
        id = <1>;
        resources {
            cpus = <1>;
            memory-bytes = <0x20000000>; // 512 MB
            llc-way-mask = <0x0000ffff>;
        };
    };

Resource Properties
-------------------

- **cpus**: Array of CPU IDs to assign to this instance
- **memory-bytes**: Memory size in bytes (must be page-aligned)
- **llc-way-mask**: Optional 32-bit resctrl L3 capacity bitmask. The baseline
  value defines the LLC ways available to the multikernel pool; every instance
  value must be a non-zero, non-overlapping subset of that pool.
- **id**: Unique instance identifier used for kexec operations

LLC Way Isolation
-----------------

``llc-way-mask`` uses the same bit numbering as the L3 CBM in a resctrl
``schemata`` file.  Mount resctrl before applying a baseline that contains an
LLC mask, and keep it mounted while any LLC-partitioned instance exists.  For
example::

    mkdir -p /dev/resctrl
    mount -t resctrl none /dev/resctrl

The baseline mask is the pool reserved for spawn kernels.  Multikernel assigns
the complementary supported mask to the host's default resctrl group.  For a
16-way LLC, this reserves the upper half for multikernel and leaves the lower
half to the host::

    /dts-v1/;
    / {
        compatible = "multikernel-v1";
        resources {
            cpus = <0x0 0x1>;
            memory-base = /bits/ 64 <0x100000000>;
            memory-bytes = /bits/ 64 <0x40000000>;
            llc-way-mask = <0xff00>;
        };
    };

An instance then requests a non-overlapping subset of ``0xff00``.  The host
allocates a resctrl CLOSID, programs the mask on every L3 domain, and records
the CLOSID in the generated instance DTB.  ``linux,resctrl-closid`` is internal
host-generated metadata and must not be supplied in an input DTB.  A spawn
kernel inherits that CLOSID and does not reset the package-wide CAT registers.
Mounting resctrl inside a spawn kernel is rejected because those registers are
shared with its parent.

The system validates that:

- CPU IDs are valid and available
- Memory requests don't exceed available multikernel pool
- LLC way masks stay within the baseline pool and don't overlap another instance
- Instance IDs are unique
- All values are properly aligned

Instance States
===============

- **empty**: Instance created but no resources allocated yet
- **ready**: DTB processed, resources reserved, ready for kexec
- **loading**: Kernel being loaded via kexec
- **active**: Kernel running in this instance
- **failed**: Error occurred during any phase

Interface Restrictions
======================

The new kernfs interface has the following restrictions:

- **No manual instance creation**: Use ``mkdir`` under ``instances/`` is disabled
- **No direct DTB upload to instances**: Instances don't have writable ``device_tree`` files
- **Centralized DTB management**: All instances must be created via the root ``device_tree`` file
- **Read-only instance files**: All instance attributes are read-only for consistency
