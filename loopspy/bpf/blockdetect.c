#include <uapi/linux/ptrace.h>

// sigset_t is needed by BCC-generated struct for epoll_pwait tracepoint args.
// Only included when __EPOLL_SYSCALL__ is epoll_pwait or epoll_pwait2.
#ifdef __NEEDS_SIGSET_T__
typedef struct { unsigned long sig[1]; } sigset_t;
#endif

struct event_t {
    u64 start_ns;
    u64 end_ns;
    u32 pid;
    u32 tid;
};

BPF_HASH(callback_start, u32, u64);
BPF_PERF_OUTPUT(events);

// Hook 1: epoll syscall returns → callbacks about to run
TRACEPOINT_PROBE(syscalls, sys_exit___EPOLL_SYSCALL__) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (tgid != __TARGET_TGID__)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    callback_start.update(&tid, &ts);
    return 0;
}

// Hook 2: entering epoll syscall → callbacks done
TRACEPOINT_PROBE(syscalls, sys_enter___EPOLL_SYSCALL__) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (tgid != __TARGET_TGID__)
        return 0;

    u64 *tsp = callback_start.lookup(&tid);
    if (!tsp)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 delta = now - *tsp;

    if (delta > __THRESHOLD_NS__) {
        struct event_t evt = {};
        evt.start_ns = *tsp;
        evt.end_ns = now;
        evt.pid = tgid;
        evt.tid = tid;
        events.perf_submit(args, &evt, sizeof(evt));
    }

    callback_start.delete(&tid);
    return 0;
}
