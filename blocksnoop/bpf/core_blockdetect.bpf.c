// SPDX-License-Identifier: GPL-2.0
/* CO-RE epoll-gap detector. See native/README.md for the wire protocol. */
#include "core_types.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct detector_config {
    __u32 target_tgid;
    __u32 target_tid;
    __u64 threshold_ns;
    __u64 pidns_dev;
    __u64 pidns_ino;
};

struct blocking_event {
    __u64 start_ns;
    __u64 end_ns;
    __u32 pid;
    __u32 tid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct detector_config);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} callback_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0);
    /* PERF_EVENT_ARRAY has u32 CPU-index keys and u32 perf-event FDs. */
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

static __always_inline struct detector_config *get_config(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&config, &key);
}

static __always_inline int is_target(struct detector_config *cfg, __u32 *tid)
{
    struct bpf_pidns_info pidns = {};

    if (bpf_get_ns_current_pid_tgid(cfg->pidns_dev, cfg->pidns_ino, &pidns,
                                    sizeof(pidns)) != 0)
        return 0;
    *tid = pidns.pid;
    return pidns.tgid == cfg->target_tgid && *tid == cfg->target_tid;
}

static __always_inline int on_epoll_exit(void *ctx)
{
    struct detector_config *cfg = get_config();
    __u32 tid;
    __u64 timestamp;

    if (!cfg || !is_target(cfg, &tid))
        return 0;

    timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&callback_start, &tid, &timestamp, BPF_ANY);
    return 0;
}

static __always_inline int on_epoll_enter(void *ctx)
{
    struct detector_config *cfg = get_config();
    struct blocking_event event = {};
    __u64 *start_ns;
    __u64 now;
    __u32 tid;

    if (!cfg || !is_target(cfg, &tid))
        return 0;

    start_ns = bpf_map_lookup_elem(&callback_start, &tid);
    if (!start_ns)
        return 0;

    now = bpf_ktime_get_ns();
    if (now - *start_ns > cfg->threshold_ns) {
        event.start_ns = *start_ns;
        event.end_ns = now;
        event.pid = cfg->target_tgid;
        event.tid = cfg->target_tid;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                              sizeof(event));
    }

    bpf_map_delete_elem(&callback_start, &tid);
    return 0;
}

#define EPOLL_PROBES(name) \
SEC("tracepoint/syscalls/sys_exit_" #name) \
int handle_exit_##name(void *ctx) \
{ \
    return on_epoll_exit(ctx); \
} \
SEC("tracepoint/syscalls/sys_enter_" #name) \
int handle_enter_##name(void *ctx) \
{ \
    return on_epoll_enter(ctx); \
}

EPOLL_PROBES(epoll_wait)
EPOLL_PROBES(epoll_pwait)
EPOLL_PROBES(epoll_pwait2)

char LICENSE[] SEC("license") = "GPL";
