ROOT := $(abspath $(CURDIR)/..)
CLANG ?= clang
CC ?= cc
PKG_CONFIG ?= pkg-config
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
BPF_TARGET_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
BPF_TARGET_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
BPF_TARGET_ARCH := arm64
else ifeq ($(UNAME_M),armv7l)
BPF_TARGET_ARCH := arm
else
$(error Unsupported BPF target architecture: $(UNAME_M))
endif

BPF_SOURCE := $(ROOT)/blocksnoop/bpf/core_blockdetect.bpf.c
LOADER_SOURCE := $(CURDIR)/blocksnoop_ebpf.c
OUT_DIR ?=

ifeq ($(OUT_DIR),)
BPF_OBJECT := $(ROOT)/blocksnoop/bpf/core_blockdetect.bpf.o
LOADER := $(CURDIR)/blocksnoop-ebpf
else
BPF_OBJECT := $(OUT_DIR)/core_blockdetect.bpf.o
LOADER := $(OUT_DIR)/blocksnoop-ebpf
endif

# Multiarch distributions keep asm/types.h below this directory. The program
# itself uses no architecture-specific registers, so the emitted BPF object is
# portable across the supported host architectures.
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -I$(ROOT)/blocksnoop/bpf -I/usr/include/$(UNAME_M)-linux-gnu
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)
LOADER_CPPFLAGS ?=

.PHONY: all clean test

all: $(BPF_OBJECT) $(LOADER)

$(BPF_OBJECT): $(BPF_SOURCE) $(ROOT)/blocksnoop/bpf/core_types.h
	mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LOADER): $(LOADER_SOURCE)
	mkdir -p $(dir $@)
	$(CC) -O2 -g -Wall -Wextra -Werror $(LOADER_CPPFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

test: $(LOADER)
	python3 tests/test_cli.py $(LOADER)

clean:
	rm -f $(BPF_OBJECT) $(LOADER)
