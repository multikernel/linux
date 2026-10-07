#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Evaluate real x86 Kconfig; compile affected objects, not a guest runtime.
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-cpu-hotplug-config.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
configure()
{
    make -s -C "$src" ARCH=x86_64 O="$build" "$1"
}
configure x86_64_defconfig
"$src/scripts/config" --file "$build/.config" \
    -e KEXEC_FILE -e CONTIG_ALLOC -e MEMORY_HOTPLUG -e MEMORY_HOTREMOVE -e MULTIKERNEL
configure olddefconfig
grep -qx 'CONFIG_MULTIKERNEL=y' "$build/.config"
grep -qx 'CONFIG_HOTPLUG_CPU=y' "$build/.config"
cp "$build/.config" "$build/supported.config"
"$src/scripts/config" --file "$build/.config" -d SMP -d HOTPLUG_CPU -e MULTIKERNEL
configure olddefconfig
grep -qx '# CONFIG_SMP is not set' "$build/.config"
if grep -qx 'CONFIG_MULTIKERNEL=y' "$build/.config"; then
    echo 'FAIL: UP configuration permits multikernel without CPU hotplug'
    exit 1
fi
make -s -C "$src" ARCH=x86_64 O="$build" -j2 kernel/cpu.o drivers/base/cpu.o
echo 'PASS: UP excludes multikernel; ordinary CPU objects compile'
cp "$build/supported.config" "$build/.config"
"$src/scripts/config" --file "$build/.config" -e SMP -e MULTIKERNEL
configure olddefconfig
grep -qx 'CONFIG_MULTIKERNEL=y' "$build/.config"
grep -qx 'CONFIG_HOTPLUG_CPU=y' "$build/.config"
make -s -C "$src" ARCH=x86_64 O="$build" -j2 kernel/multikernel/hotplug.o
echo 'PASS: SMP/hotplug restores multikernel; resource-hotplug object compiles'
