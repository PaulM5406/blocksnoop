#!/bin/bash
# Set up kernel headers for BCC on Docker Desktop (LinuxKit kernel)
# The running kernel may differ from the installed headers package.

RUNNING_KERNEL=$(uname -r)
BUILD_DIR="/lib/modules/${RUNNING_KERNEL}/build"

if [ ! -d "$BUILD_DIR" ]; then
    # Find installed arch-specific headers (first match)
    ARCH_HEADERS=$(ls -d /usr/src/linux-headers-*-arm64 2>/dev/null | head -1)
    COMMON_HEADERS=$(ls -d /usr/src/linux-headers-*-common 2>/dev/null | head -1)

    if [ -z "$ARCH_HEADERS" ] && [ -z "$COMMON_HEADERS" ]; then
        # Try amd64
        ARCH_HEADERS=$(ls -d /usr/src/linux-headers-*-amd64 2>/dev/null | head -1)
    fi

    if [ -n "$ARCH_HEADERS" ] || [ -n "$COMMON_HEADERS" ]; then
        mkdir -p "/lib/modules/${RUNNING_KERNEL}"
        ln -sf "${ARCH_HEADERS}" "$BUILD_DIR"

        # Merge common includes into the arch-specific tree
        if [ -n "$COMMON_HEADERS" ] && [ -n "$ARCH_HEADERS" ]; then
            # Symlink common include dirs not present in arch-specific
            for dir in "$COMMON_HEADERS"/include/*/; do
                name=$(basename "$dir")
                if [ ! -e "$ARCH_HEADERS/include/$name" ]; then
                    ln -sf "$dir" "$ARCH_HEADERS/include/$name"
                fi
            done

            # Symlink arch-specific asm headers
            ARCH=$(uname -m)
            case "$ARCH" in
                aarch64) KARCH="arm64" ;;
                x86_64)  KARCH="x86" ;;
                *)       KARCH="$ARCH" ;;
            esac

            if [ ! -e "$ARCH_HEADERS/include/asm" ]; then
                ln -sf "$COMMON_HEADERS/arch/$KARCH/include/asm" "$ARCH_HEADERS/include/asm"
            fi
            # uapi/asm is also needed
            if [ ! -e "$ARCH_HEADERS/include/uapi/asm" ]; then
                mkdir -p "$ARCH_HEADERS/include/uapi"
                ln -sf "$COMMON_HEADERS/arch/$KARCH/include/uapi/asm" "$ARCH_HEADERS/include/uapi/asm"
            fi
        fi
    fi
fi

exec "$@"
