# blocksnoop CO-RE collector

`blocksnoop-ebpf` is a small Linux sidecar for the Python CLI. It traces the
gap between an epoll syscall return and the next epoll syscall entry for one
TGID/TID in the collector's PID namespace. The eBPF object is compiled once;
it contains no kernel-structure reads, so libbpf can load the same BTF-enabled
object across supported Linux kernels.

Build on Linux with libbpf development headers and clang:

```sh
make -C native
```

The loader supports three stable relative layouts: the repository
(`native/blocksnoop-ebpf` next to `blocksnoop/bpf/`), an installed Python
package (`blocksnoop/native/` next to `blocksnoop/bpf/`), or an object
co-located with the binary. Deployments can always make the location explicit
with `--bpf-object PATH` or `BLOCKSNOOP_BPF_OBJECT`.

## Protocol v1

The parent invokes:

```sh
blocksnoop-ebpf --protocol-version 1 --pid PID --tid TID --threshold-ns N
```

Standard output is exclusively one JSON object per line. Every record has
`"version": 1` and a `type` of:

- `ready`: collector attached; includes `pid`, `tid`, `threshold_ns`, and the
  enabled `tracepoints`.
- `event`: `start_ns`, `end_ns`, `pid`, and `tid` for an epoll gap.
- `lost`: lost event `count` and a `source` of `perf_buffer` or `kernel`.
- `fatal`: unrecoverable startup/runtime error with a `message`.

The loader checks tracefs before loading and disables both programs for every
absent epoll tracepoint. It requires at least one complete enter/exit pair.

`make -C native test` only tests CLI argument validation and help; it does not
load eBPF or need privileges.
