# blocksnoop CO-RE collector

`blocksnoop-ebpf` is a small Linux sidecar for the Python CLI. It traces the
gap between an epoll syscall return and the next epoll syscall entry for one
TGID/TID in the target's PID namespace. The eBPF object is compiled once;
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

## Protocol v2

The parent invokes:

```sh
blocksnoop-ebpf --protocol-version 2 --pid PID --tid TID \
  --pidns-dev DEV --pidns-ino INO --threshold-ns N
```

Standard output is exclusively one JSON object per line. Every record has
`"version": 2` and a `type` of:

- `ready`: collector attached; includes namespace-local `pid` and `tid`,
  `pidns_dev`, `pidns_ino`, `threshold_ns`, and the enabled `tracepoints`.
- `event`: `start_ns`, `end_ns`, namespace-local `pid` and `tid`, plus the
  target `pidns_dev` and `pidns_ino` for an epoll gap.
- `lost`: lost event `count`, `source: "perf_buffer"`, and the target
  namespace identity. It is emitted solely from libbpf's `PERF_RECORD_LOST`
  callback, so a dropped event is never counted twice.
- `fatal`: unrecoverable startup/runtime error with a `message`.

The Python parent resolves a host-visible target PID/TID through `/proc` before
starting the sidecar. The native loader then configures the target namespace
device/inode and the eBPF program filters with
`bpf_get_ns_current_pid_tgid()`. Resolution failure is fatal: the Core backend
never broadens the filter or silently falls back to BCC.

The loader checks tracefs before loading and disables both programs for every
absent epoll tracepoint. It requires at least one complete enter/exit pair.

`make -C native test` only tests CLI argument validation and help; it does not
load eBPF or need privileges.
