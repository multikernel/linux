.. SPDX-License-Identifier: GPL-2.0

====================================
Multikernel Device Tree Overlays
====================================

Overview
========

The Device Tree overlay subsystem enables dynamic resource adjustments for
multikernel instances at runtime without requiring system reboot. Changes are
applied through standard Device Tree overlays and can be rolled back safely.

Overlays can be used to:

* **Create new instances**: Define and instantiate new kernel instances
* **Adjust memory**: Add or remove memory regions from instances
* **Adjust CPUs**: Migrate CPUs between instances
* **Combine operations**: Perform multiple changes atomically

Key Features
------------

* **Transaction-based**: Each overlay is tracked as an independent transaction
* **Atomic updates**: Overlays are applied as single atomic operations
* **Reversible**: Any overlay can be removed by deleting its transaction directory
* **Safe**: Failed overlays don't affect system stability
* **Ordered execution**: Operations execute in a predictable order

Filesystem Layout
=================

The overlay subsystem is accessible at ``/sys/fs/multikernel/overlays/``::

    /sys/fs/multikernel/
     ├── device_tree                 # Baseline system configuration
     ├── instances/                  # Runtime kernel instances
     └── overlays/                   # Overlay subsystem
          ├── new                    # Control file: write DTBO here
          ├── tx_101/                # Applied overlay transaction
          │    ├── id                # Transaction ID: "101"
          │    ├── status            # "applied" | "failed" | "removed"
          │    ├── instance          # Affected instance name
          │    ├── resources         # Affected resources
          │    └── dtbo              # Original overlay blob (binary)
          └── tx_102/
               └── ...

Overlay Format
==============

Multikernel overlays follow a specific structure with operation sections that
describe resource changes. The overlay format includes:

Basic Structure
---------------

A multikernel overlay consists of::

    /multikernel-v1/;

    / {
        fragment@0 {
            target-path = "/";
            __overlay__ {
                instance-create {
                    instance-name = "<instance-name>";
                    id = <instance-id>;
                    resources {
                        memory-bytes = <size>;
                        cpus = <cpu-list>;
                    };
                };
                memory-add { ... };
                cpu-add { ... };
                /* ... other operations ... */
            };
        };
    };

Operation Sections
------------------

Operations are placed directly inside the ``__overlay__`` node. Each operation
section describes a specific type of resource change.

**instance-create**
    Creates a new kernel instance. Contains all instance configuration directly.

    Properties:
      - ``instance-name``: Instance name (string)
      - ``id``: Instance ID (u32)

    Subnodes:
      - ``resources``: Resource allocation for the instance
          - ``memory-bytes``: Initial memory size (u32)
          - ``cpus``: Initial CPU list (array of u32)

    Example::

        instance-create {
            instance-name = "my-kernel";
            id = <1>;
            resources {
                memory-bytes = <0x40000000>;  /* 1GB */
                cpus = <4 5 6>;
            };
        };

**memory-add**
    Adds memory regions to an instance.

    Properties:
      - ``mk,instance``: Target instance name (string)

    Subnodes:
      - ``region@N``: Memory region definition
          - ``reg``: <addr-hi addr-lo size-hi size-lo> (u64 address + u64 size)
          - ``numa-node``: NUMA node ID (u32, optional)
          - ``mem-type``: Memory type (u32, optional)

    Example::

        memory-add {
            mk,instance = "database";
            region@0 {
                reg = <0x0 0x80000000  0x0 0x40000000>;  /* 1GB at 2GB */
                numa-node = <0>;
            };
        };

**memory-remove**
    Removes memory regions from an instance.

    Properties:
      - ``mk,instance``: Target instance name (string)

    Subnodes:
      - ``region@N``: Memory region to remove
          - ``reg``: <addr-hi addr-lo size-hi size-lo>

    Example::

        memory-remove {
            mk,instance = "database";
            region@0 {
                reg = <0x0 0x80000000  0x0 0x40000000>;  /* Remove 1GB */
            };
        };

**cpu-add**
    Adds CPUs to an instance.

    Properties:
      - ``mk,instance``: Target instance name (string)

    Subnodes:
      - ``cpu@N``: CPU definition
          - ``reg``: Physical CPU ID (u32)
          - ``numa-node``: NUMA node ID (u32, optional)
          - ``flags``: CPU flags (u32, optional)

    Example::

        cpu-add {
            mk,instance = "database";
            cpu@16 { reg = <16>; numa-node = <0>; };
            cpu@17 { reg = <17>; numa-node = <0>; };
        };

**cpu-remove**
    Removes CPUs from an instance.

    Properties:
      - ``mk,instance``: Target instance name (string)

    Subnodes:
      - ``cpu@N``: CPU to remove
          - ``reg``: Physical CPU ID (u32)

    Example::

        cpu-remove {
            mk,instance = "database";
            cpu@8 { reg = <8>; };
        };

Operation Ordering
------------------

Operations are executed in a specific order to ensure safe resource migration:

1. **instance-create** - Create new instances first
2. **memory-remove** - Remove memory from source
3. **memory-add** - Add memory to destination
4. **cpu-remove** - Remove CPUs from source
5. **cpu-add** - Add CPUs to destination

When an overlay is rolled back (via ``rmdir``), operations are reversed:

1. **cpu-add** → cpu-remove
2. **cpu-remove** → cpu-add
3. **memory-add** → memory-remove
4. **memory-remove** → memory-add
5. **instance-create** → destroy instance

Usage
=====

Creating a New Instance
-----------------------

To create a new instance with resources using an overlay:

1. Create the overlay file::

    /multikernel-v1/;

    / {
        fragment@0 {
            target-path = "/";
            __overlay__ {
                instance-create {
                    instance-name = "webserver";
                    id = <2>;
                    resources {
                        memory-bytes = <0x40000000>;  /* 1GB */
                        cpus = <4 5>;
                    };
                };
            };
        };
    };

2. Compile and apply::

    dtc -O dtb -o create_webserver.dtbo -@ create_webserver.dts
    cat create_webserver.dtbo > /sys/fs/multikernel/overlays/new

3. Verify the instance was created::

    ls /sys/fs/multikernel/instances/
    # Output shows: webserver

    cat /sys/fs/multikernel/instances/webserver/id
    # Output: 2

Adding Resources to an Instance
--------------------------------

To add memory and CPUs to an existing instance:

1. Create the overlay::

    /multikernel-v1/;

    / {
        fragment@0 {
            target-path = "/";
            __overlay__ {
                memory-add {
                    mk,instance = "database";
                    region@0 {
                        reg = <0x0 0x100000000  0x0 0x80000000>;  /* 2GB */
                        numa-node = <0>;
                    };
                };

                cpu-add {
                    mk,instance = "database";
                    cpu@16 { reg = <16>; numa-node = <0>; };
                    cpu@17 { reg = <17>; numa-node = <0>; };
                    cpu@18 { reg = <18>; numa-node = <0>; };
                    cpu@19 { reg = <19>; numa-node = <0>; };
                };
            };
        };
    };

2. Compile and apply::

    dtc -O dtb -o add_resources.dtbo -@ add_resources.dts
    cat add_resources.dtbo > /sys/fs/multikernel/overlays/new

Migrating Resources Between Instances
--------------------------------------

To move memory from one instance to another:

1. Create the overlay::

    /multikernel-v1/;

    / {
        fragment@0 {
            target-path = "/";
            __overlay__ {
                memory-remove {
                    mk,instance = "database";
                    region@0 {
                        reg = <0x0 0x80000000  0x0 0x40000000>;
                    };
                };

                memory-add {
                    mk,instance = "analytics";
                    region@0 {
                        reg = <0x0 0x80000000  0x0 0x40000000>;
                        numa-node = <0>;
                    };
                };
            };
        };
    };

2. Apply the overlay - the memory will be atomically moved.

Creating Instance with Additional Resources
--------------------------------------------

You can create an instance with initial resources and add more in the same overlay:

1. Create the overlay::

    /multikernel-v1/;

    / {
        fragment@0 {
            target-path = "/";
            __overlay__ {
                instance-create {
                    instance-name = "compute";
                    id = <3>;
                    resources {
                        memory-bytes = <0x10000000>;  /* Initial: 256MB */
                        cpus = <8>;                    /* Initial: CPU 8 */
                    };
                };

                /* Add more resources beyond initial allocation */
                memory-add {
                    mk,instance = "compute";
                    region@0 {
                        reg = <0x0 0x200000000  0x0 0xF0000000>;  /* +3.75GB */
                        numa-node = <1>;
                    };
                };

                cpu-add {
                    mk,instance = "compute";
                    cpu@9  { reg = <9>;  numa-node = <1>; };
                    cpu@10 { reg = <10>; numa-node = <1>; };
                    cpu@11 { reg = <11>; numa-node = <1>; };
                };
            };
        };
    };

2. Result: Instance created with 256MB + 3.75GB = 4GB total, CPUs 8-11.

Applying an Overlay
-------------------

The basic workflow for applying any overlay:

1. Compile the overlay to binary format::

    dtc -O dtb -o myoverlay.dtbo -@ myoverlay.dts

2. Apply the overlay::

    cat myoverlay.dtbo > /sys/fs/multikernel/overlays/new

    ls /sys/fs/multikernel/overlays/
    # Output: new  tx_101

    cat /sys/fs/multikernel/overlays/tx_101/status
    # Output: applied

Removing an Instance
--------------------

To remove an instance created via overlay, simply roll back the transaction::

    rmdir /sys/fs/multikernel/overlays/tx_101

This will automatically destroy the instance if it was created by that overlay.

**Note**: The instance must not be active or loading. Stop the instance first
if needed.

Viewing Overlay Information
---------------------------

Each transaction provides metadata about the overlay:

**Transaction ID**::

    cat /sys/fs/multikernel/overlays/tx_101/id
    # Output: 101

**Status**::

    cat /sys/fs/multikernel/overlays/tx_101/status
    # Possible values: applied, failed, removed, pending

**Affected Instance**::

    cat /sys/fs/multikernel/overlays/tx_101/instance
    # Output: database

**Resource Description**::

    cat /sys/fs/multikernel/overlays/tx_101/resources
    # Output: cpu:16-19

**Original Overlay Blob**::

    # Binary file containing the original DTBO
    ls -lh /sys/fs/multikernel/overlays/tx_101/dtbo

Rolling Back an Overlay
-----------------------

To undo an applied overlay, simply remove its transaction directory::

    rmdir /sys/fs/multikernel/overlays/tx_101

This will:

* Reverse all operations in opposite order
* Return memory to source instances
* Restore CPUs to original instances
* Destroy instances created by the overlay (if any)
* Remove the transaction directory

**Important**: Instances being removed must not be active or in loading state.
Stop them first if necessary.

Error Handling
==============

Handling Failed Overlays
-------------------------

If an overlay fails to apply, a transaction is still created with
``status = failed``::

    cat broken.dtbo > /sys/fs/multikernel/overlays/new
    # Check kernel log for error details: dmesg | tail

    cat /sys/fs/multikernel/overlays/tx_102/status
    # Output: failed

    # Remove the failed transaction
    rmdir /sys/fs/multikernel/overlays/tx_102

Common Errors
-------------

**Instance Already Exists**
    Attempting to create an instance that already exists::

        # Error: instance 'webserver' already exists
        # Solution: Choose a different name or remove the existing instance

**Instance Not Found**
    Operations targeting a non-existent instance::

        # Error: instance 'database' not found
        # Solution: Create the instance first or check the name

**Instance Active/Loading**
    Attempting to remove an active or loading instance during rollback::

        # Error: Cannot remove active instance
        # Solution: Stop the instance before rolling back

**Invalid Resource Specification**
    Malformed memory addresses or CPU IDs::

        # Error: Invalid reg property
        # Solution: Check DTB format and address/size encoding

Testing
=======

Basic Functionality Test
------------------------

Test creating and removing an instance:

1. Create a test overlay::

    /multikernel-v1/;

    / {
        fragment@0 {
            target-path = "/";
            __overlay__ {
                instance-create {
                    instance-name = "test-instance";
                    id = <99>;
                    resources {
                        memory-bytes = <0x10000000>;  /* 256MB */
                        cpus = <1>;
                    };
                };
            };
        };
    };

2. Compile and apply::

    dtc -O dtb -o test_create.dtbo -@ test_create.dts
    cat test_create.dtbo > /sys/fs/multikernel/overlays/new

3. Verify::

    ls /sys/fs/multikernel/instances/
    # Should show: test-instance

    cat /sys/fs/multikernel/instances/test-instance/id
    # Should show: 99

4. Remove::

    ls /sys/fs/multikernel/overlays/tx_*
    rmdir /sys/fs/multikernel/overlays/tx_*

5. Verify removal::

    ls /sys/fs/multikernel/instances/
    # test-instance should be gone

Resource Migration Test
------------------------

Test moving resources between instances:

1. Create two instances (database and analytics)
2. Apply an overlay to move memory from database to analytics
3. Verify resources were transferred
4. Roll back to restore original configuration


See Also
========

* Linux Device Tree documentation: ``Documentation/devicetree/``
* Overlay notes: ``Documentation/devicetree/overlay-notes.rst``
* Device Tree compiler: ``dtc(1)``
