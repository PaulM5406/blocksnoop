// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * blocksnoop-ebpf -- CO-RE epoll-gap collector.
 *
 * stdout is deliberately reserved for the versioned NDJSON protocol. Human
 * diagnostics (including libbpf errors) go to stderr so a Python parent can
 * consume stdout without a fragile log parser.
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BLOCKSNOOP_PROTOCOL_VERSION 2
#define PERF_BUFFER_PAGES 64
#define EPOLL_VARIANT_COUNT 3

struct detector_config {
    uint32_t target_tgid;
    uint32_t target_tid;
    uint64_t threshold_ns;
    uint64_t pidns_dev;
    uint64_t pidns_ino;
};

struct blocking_event {
    uint64_t start_ns;
    uint64_t end_ns;
    uint32_t pid;
    uint32_t tid;
};

struct epoll_variant {
    const char *name;
    const char *exit_tracepoint;
    const char *enter_tracepoint;
    const char *exit_program;
    const char *enter_program;
    bool enabled;
};

static volatile sig_atomic_t stopping;

static void on_signal(int signum)
{
    (void)signum;
    stopping = 1;
}

static void usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage: %s --protocol-version 2 --pid PID --tid TID --pidns-dev DEV "
            "--pidns-ino INO --threshold-ns N "
            "[--bpf-object FILE]\n"
            "\n"
            "CO-RE epoll-gap collector. stdout is NDJSON protocol version 2.\n"
            "\n"
            "Required:\n"
            "  --protocol-version 2  Protocol version expected by the parent\n"
            "  --pid PID             Target process ID in its PID namespace\n"
            "  --tid TID             Target thread ID in its PID namespace\n"
            "  --pidns-dev DEV       Target PID namespace st_dev\n"
            "  --pidns-ino INO       Target PID namespace st_ino\n"
            "  --threshold-ns N      Minimum callback gap in nanoseconds\n"
            "\n"
            "Optional:\n"
            "  --bpf-object FILE     Path to core_blockdetect.bpf.o\n"
            "  -h, --help            Show this help\n",
            program);
}

static void emit_fatal(const char *message)
{
    /* All current messages are controlled by this binary, not user input. */
    printf("{\"version\":%d,\"type\":\"fatal\",\"message\":\"%s\"}\n",
           BLOCKSNOOP_PROTOCOL_VERSION, message);
    fflush(stdout);
}

static void emit_ready(const struct detector_config *config,
                       const struct epoll_variant variants[EPOLL_VARIANT_COUNT])
{
    bool first = true;
    size_t i;

    printf("{\"version\":%d,\"type\":\"ready\",\"pid\":%u,"
           "\"tid\":%u,\"pidns_dev\":%llu,\"pidns_ino\":%llu,"
           "\"threshold_ns\":%llu,\"tracepoints\":[",
           BLOCKSNOOP_PROTOCOL_VERSION, config->target_tgid, config->target_tid,
           (unsigned long long)config->pidns_dev,
           (unsigned long long)config->pidns_ino,
           (unsigned long long)config->threshold_ns);
    for (i = 0; i < EPOLL_VARIANT_COUNT; i++) {
        if (!variants[i].enabled)
            continue;
        printf("%s\"%s\"", first ? "" : ",", variants[i].name);
        first = false;
    }
    printf("]}\n");
    fflush(stdout);
}

static void emit_event(const struct blocking_event *event,
                       const struct detector_config *config)
{
    printf("{\"version\":%d,\"type\":\"event\",\"start_ns\":%llu,"
           "\"end_ns\":%llu,\"pid\":%u,\"tid\":%u,"
           "\"pidns_dev\":%llu,\"pidns_ino\":%llu}\n",
           BLOCKSNOOP_PROTOCOL_VERSION,
           (unsigned long long)event->start_ns,
           (unsigned long long)event->end_ns, event->pid, event->tid,
           (unsigned long long)config->pidns_dev,
           (unsigned long long)config->pidns_ino);
    fflush(stdout);
}

static void emit_lost(uint64_t count, const char *source,
                      const struct detector_config *config)
{
    printf("{\"version\":%d,\"type\":\"lost\",\"count\":%llu,"
           "\"source\":\"%s\",\"pidns_dev\":%llu,"
           "\"pidns_ino\":%llu}\n",
           BLOCKSNOOP_PROTOCOL_VERSION, (unsigned long long)count, source,
           (unsigned long long)config->pidns_dev,
           (unsigned long long)config->pidns_ino);
    fflush(stdout);
}

static int parse_u32(const char *value, uint32_t *result)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno || !value[0] || *end || parsed == 0 || parsed > UINT32_MAX)
        return -1;
    *result = (uint32_t)parsed;
    return 0;
}

static int parse_u64(const char *value, uint64_t *result)
{
    char *end = NULL;
    unsigned long long parsed;

    if (!value[0] || value[0] == '-' || value[0] == '+')
        return -1;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno || *end)
        return -1;
    *result = (uint64_t)parsed;
    return 0;
}

static bool tracepoint_exists(const char *name)
{
    const char *roots[] = {
        "/sys/kernel/tracing/events/syscalls",
        "/sys/kernel/debug/tracing/events/syscalls",
    };
    char path[PATH_MAX];
    size_t i;

    for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        if (snprintf(path, sizeof(path), "%s/sys_enter_%s/format", roots[i], name) >=
            (int)sizeof(path))
            continue;
        if (access(path, R_OK) == 0) {
            if (snprintf(path, sizeof(path), "%s/sys_exit_%s/format", roots[i], name) >=
                (int)sizeof(path))
                return false;
            return access(path, R_OK) == 0;
        }
    }
    return false;
}

static int default_bpf_object(const char *argv0, char *path, size_t path_size)
{
    const char *from_env = getenv("BLOCKSNOOP_BPF_OBJECT");
    char executable[PATH_MAX];
    char directory[PATH_MAX];
    const char *suffixes[] = {
        "/../blocksnoop/bpf/core_blockdetect.bpf.o", /* repository layout */
        "/../bpf/core_blockdetect.bpf.o",            /* installed package */
        "/core_blockdetect.bpf.o",                   /* co-located binary */
    };
    char *last_slash;
    ssize_t length;
    size_t i;

    if (from_env && from_env[0]) {
        if (snprintf(path, path_size, "%s", from_env) >= (int)path_size)
            return -1;
        return 0;
    }

    length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (length < 0) {
        if (snprintf(directory, sizeof(directory), "%s", argv0) >=
            (int)sizeof(directory))
            return -1;
        last_slash = strrchr(directory, '/');
        if (!last_slash)
            return -1;
        *last_slash = '\0';
    } else {
        executable[length] = '\0';
        last_slash = strrchr(executable, '/');
        if (!last_slash)
            return -1;
        *last_slash = '\0';
        if (snprintf(directory, sizeof(directory), "%s", executable) >=
            (int)sizeof(directory))
            return -1;
    }

    for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        if (snprintf(path, path_size, "%s%s", directory, suffixes[i]) >=
            (int)path_size)
            continue;
        if (access(path, R_OK) == 0)
            return 0;
    }
    return -1;
}

static void handle_sample(void *ctx, int cpu, void *data, __u32 size)
{
    const struct blocking_event *event = data;
    const struct detector_config *config = ctx;

    (void)cpu;
    /*
     * Some perf/libbpf combinations report trailing record alignment bytes
     * (for example 28 bytes for this 24-byte payload). The first bytes are
     * still exactly struct blocking_event; reject only genuinely truncated
     * payloads.
     */
    if (size < sizeof(*event)) {
        fprintf(stderr, "blocksnoop-ebpf: truncated event (%u bytes, need %zu)\n",
                size, sizeof(*event));
        return;
    }
    emit_event(event, config);
}

static void handle_lost(void *ctx, int cpu, __u64 count)
{
    const struct detector_config *config = ctx;

    (void)cpu;
    emit_lost(count, "perf_buffer", config);
}

int main(int argc, char **argv)
{
    static const struct option options[] = {
        {"protocol-version", required_argument, NULL, 'V'},
        {"pid", required_argument, NULL, 'p'},
        {"tid", required_argument, NULL, 't'},
        {"pidns-dev", required_argument, NULL, 'd'},
        {"pidns-ino", required_argument, NULL, 'i'},
        {"threshold-ns", required_argument, NULL, 'n'},
        {"bpf-object", required_argument, NULL, 'b'},
        {"help", no_argument, NULL, 'h'},
        {},
    };
    struct epoll_variant variants[EPOLL_VARIANT_COUNT] = {
        {"epoll_wait", "sys_exit_epoll_wait", "sys_enter_epoll_wait",
         "handle_exit_epoll_wait", "handle_enter_epoll_wait", false},
        {"epoll_pwait", "sys_exit_epoll_pwait", "sys_enter_epoll_pwait",
         "handle_exit_epoll_pwait", "handle_enter_epoll_pwait", false},
        {"epoll_pwait2", "sys_exit_epoll_pwait2", "sys_enter_epoll_pwait2",
         "handle_exit_epoll_pwait2", "handle_enter_epoll_pwait2", false},
    };
    struct bpf_object *object = NULL;
    struct perf_buffer *perf_buffer = NULL;
    struct bpf_link *links[EPOLL_VARIANT_COUNT * 2] = {};
    struct bpf_map *map;
    struct detector_config config = {};
    char default_object[PATH_MAX];
    const char *object_path = NULL;
    uint32_t protocol_version = 0;
    bool have_pid = false;
    bool have_tid = false;
    bool have_pidns_dev = false;
    bool have_pidns_ino = false;
    bool have_threshold = false;
    int option;
    int enabled_count = 0;
    int link_count = 0;
    int possible_cpu_count;
    int error = 1;
    size_t i;

    setvbuf(stdout, NULL, _IONBF, 0);
    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (option) {
        case 'V':
            if (parse_u32(optarg, &protocol_version) != 0) {
                fprintf(stderr, "blocksnoop-ebpf: invalid --protocol-version\n");
                return 2;
            }
            break;
        case 'p':
            if (parse_u32(optarg, &config.target_tgid) != 0) {
                fprintf(stderr, "blocksnoop-ebpf: invalid --pid\n");
                return 2;
            }
            have_pid = true;
            break;
        case 't':
            if (parse_u32(optarg, &config.target_tid) != 0) {
                fprintf(stderr, "blocksnoop-ebpf: invalid --tid\n");
                return 2;
            }
            have_tid = true;
            break;
        case 'd':
            if (parse_u64(optarg, &config.pidns_dev) != 0 ||
                config.pidns_dev == 0) {
                fprintf(stderr, "blocksnoop-ebpf: invalid --pidns-dev\n");
                return 2;
            }
            have_pidns_dev = true;
            break;
        case 'i':
            if (parse_u64(optarg, &config.pidns_ino) != 0 ||
                config.pidns_ino == 0) {
                fprintf(stderr, "blocksnoop-ebpf: invalid --pidns-ino\n");
                return 2;
            }
            have_pidns_ino = true;
            break;
        case 'n':
            if (parse_u64(optarg, &config.threshold_ns) != 0) {
                fprintf(stderr, "blocksnoop-ebpf: invalid --threshold-ns\n");
                return 2;
            }
            have_threshold = true;
            break;
        case 'b':
            object_path = optarg;
            break;
        case 'h':
            usage(stdout, argv[0]);
            return 0;
        default:
            usage(stderr, argv[0]);
            return 2;
        }
    }

    if (optind != argc || protocol_version != BLOCKSNOOP_PROTOCOL_VERSION ||
        !have_pid || !have_tid || !have_pidns_dev || !have_pidns_ino ||
        !have_threshold) {
        usage(stderr, argv[0]);
        return 2;
    }
    if (!object_path) {
        if (default_bpf_object(argv[0], default_object, sizeof(default_object)) != 0) {
            emit_fatal("could not determine the BPF object path");
            return 1;
        }
        object_path = default_object;
    }

    for (i = 0; i < EPOLL_VARIANT_COUNT; i++) {
        variants[i].enabled = tracepoint_exists(variants[i].name);
        enabled_count += variants[i].enabled;
    }
    if (enabled_count == 0) {
        emit_fatal("no supported epoll tracepoint pair is available");
        return 1;
    }

    object = bpf_object__open_file(object_path, NULL);
    if (libbpf_get_error(object)) {
        object = NULL;
        emit_fatal("could not open BPF object");
        goto cleanup;
    }
    for (i = 0; i < EPOLL_VARIANT_COUNT; i++) {
        struct bpf_program *exit_program =
            bpf_object__find_program_by_name(object, variants[i].exit_program);
        struct bpf_program *enter_program =
            bpf_object__find_program_by_name(object, variants[i].enter_program);

        if (!exit_program || !enter_program) {
            emit_fatal("BPF object is missing an epoll tracepoint program");
            goto cleanup;
        }
        if (!variants[i].enabled) {
            bpf_program__set_autoload(exit_program, false);
            bpf_program__set_autoload(enter_program, false);
        }
    }
    /*
     * Unlike a generated skeleton, this raw libbpf loader must size a
     * PERF_EVENT_ARRAY itself. A zero max_entries value reaches the kernel
     * unchanged and fails with EINVAL instead of being auto-sized.
     */
    map = bpf_object__find_map_by_name(object, "events");
    if (!map) {
        emit_fatal("BPF object is missing the events map");
        goto cleanup;
    }
    possible_cpu_count = libbpf_num_possible_cpus();
    if (possible_cpu_count <= 0) {
        emit_fatal("could not determine the number of possible CPUs");
        goto cleanup;
    }
    if (bpf_map__set_max_entries(map, (uint32_t)possible_cpu_count) != 0) {
        emit_fatal("could not size the perf events map for available CPUs");
        goto cleanup;
    }
    if (bpf_object__load(object) != 0) {
        emit_fatal("could not load BPF object (root/CAP_BPF may be required)");
        goto cleanup;
    }

    map = bpf_object__find_map_by_name(object, "config");
    if (!map || bpf_map_update_elem(bpf_map__fd(map), &(uint32_t){0}, &config,
                                    BPF_ANY) != 0) {
        emit_fatal("could not configure BPF object");
        goto cleanup;
    }
    map = bpf_object__find_map_by_name(object, "events");
    if (!map) {
        emit_fatal("BPF object is missing the events map");
        goto cleanup;
    }
    perf_buffer = perf_buffer__new(bpf_map__fd(map), PERF_BUFFER_PAGES,
                                   handle_sample, handle_lost, &config, NULL);
    if (libbpf_get_error(perf_buffer)) {
        perf_buffer = NULL;
        emit_fatal("could not create perf buffer");
        goto cleanup;
    }
    for (i = 0; i < EPOLL_VARIANT_COUNT; i++) {
        struct bpf_program *exit_program;
        struct bpf_program *enter_program;

        if (!variants[i].enabled)
            continue;
        exit_program = bpf_object__find_program_by_name(object, variants[i].exit_program);
        enter_program = bpf_object__find_program_by_name(object, variants[i].enter_program);
        links[link_count] = bpf_program__attach_tracepoint(exit_program, "syscalls",
                                                           variants[i].exit_tracepoint);
        if (libbpf_get_error(links[link_count])) {
            links[link_count] = NULL;
            emit_fatal("could not attach an epoll exit tracepoint");
            goto cleanup;
        }
        link_count++;
        links[link_count] = bpf_program__attach_tracepoint(enter_program, "syscalls",
                                                           variants[i].enter_tracepoint);
        if (libbpf_get_error(links[link_count])) {
            links[link_count] = NULL;
            emit_fatal("could not attach an epoll enter tracepoint");
            goto cleanup;
        }
        link_count++;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    emit_ready(&config, variants);
    while (!stopping) {
        error = perf_buffer__poll(perf_buffer, 250);
        if (error < 0 && error != -EINTR) {
            emit_fatal("perf buffer polling failed");
            goto cleanup;
        }
    }
    error = 0;

cleanup:
    for (i = 0; i < (size_t)link_count; i++)
        bpf_link__destroy(links[i]);
    perf_buffer__free(perf_buffer);
    bpf_object__close(object);
    return error == 0 ? 0 : 1;
}
