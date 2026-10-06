#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Actual Kconfig evaluation; no guest boot or unsafe reset is attempted.
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${MK_SOURCE:-$(CDPATH= cd -- "$test_dir/../../../.." && pwd)}
build=$(mktemp -d "${TMPDIR:-/tmp}/mk-riscv-config.XXXXXX")
trap 'rm -rf -- "$build"' EXIT HUP INT TERM
configure()
{
    make -s -C "$src" ARCH=riscv LLVM=1 O="$build" "$1"
}
require_mk()
{
    grep -qx 'CONFIG_ARCH_SUPPORTS_MULTIKERNEL=y' "$build/.config"
    grep -qx 'CONFIG_MULTIKERNEL=y' "$build/.config"
}
configure defconfig
"$src/scripts/config" --file "$build/.config" \
    -e KEXEC_FILE -e HOTPLUG_CPU -e CONTIG_ALLOC \
    -e MEMORY_HOTPLUG -e MEMORY_HOTREMOVE -e MULTIKERNEL \
    -d BUILTIN_DTB -d RISCV_BOOT_SPINWAIT
configure olddefconfig
require_mk
cp "$build/.config" "$build/supported.config"
failures=0
for option in BUILTIN_DTB RISCV_BOOT_SPINWAIT; do
    cp "$build/supported.config" "$build/.config"
    "$src/scripts/config" --file "$build/.config" -e NONPORTABLE -e "$option"
    if [ "$option" = BUILTIN_DTB ]; then
        dtb=sifive/hifive-unmatched-a00
        test -f "$src/arch/riscv/boot/dts/$dtb.dts"
        "$src/scripts/config" --file "$build/.config" \
            --set-str BUILTIN_DTB_NAME "$dtb"
    fi
    configure olddefconfig
    grep -qx "CONFIG_$option=y" "$build/.config"
    if grep -qx 'CONFIG_ARCH_SUPPORTS_MULTIKERNEL=y' "$build/.config" ||
       grep -qx 'CONFIG_MULTIKERNEL=y' "$build/.config"; then
        printf 'FAIL: %s permits multikernel\n' "$option"
        failures=$((failures + 1))
    else
        printf 'PASS: %s excludes multikernel\n' "$option"
    fi
    "$src/scripts/config" --file "$build/.config" -d "$option" -e MULTIKERNEL
    configure olddefconfig
    require_mk
    printf 'PASS: disabling %s restores multikernel\n' "$option"
done
test "$failures" = 0
