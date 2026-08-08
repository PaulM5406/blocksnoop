/*
 * Minimal kernel types needed by the CO-RE tracepoint program.
 *
 * The program intentionally does not dereference any kernel structure: all
 * state comes from BPF helpers and maps.  Keeping this header small means the
 * resulting object has no kernel-layout dependency while clang still emits
 * BTF (`-g`) for libbpf to validate at load time.
 */
#ifndef BLOCKSNOOP_CORE_TYPES_H
#define BLOCKSNOOP_CORE_TYPES_H

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#endif
