# blocksnoop

Detect blocking calls in Python asyncio event loops using eBPF + py-spy.

blocksnoop attaches to a running Python process (or launches one) and reports every time the event loop is blocked longer than a configurable threshold — with the Python stack trace that caused it.

## How it works

```
eBPF (kernel)          py-spy (userspace)
  │ monitors               │ samples Python
  │ epoll gaps              │ stacks periodically
  └──────────┐   ┌─────────┘
             ▼   ▼
          Correlator
             │
             ▼
       Reporter → sinks (console, JSON, file)
```

1. An **eBPF probe** hooks `epoll_wait` syscalls and measures the time between returns (callback start) and the next entry (callback end). If the gap exceeds the threshold, it emits an event.
2. A **py-spy sampler** runs in a background thread, periodically capturing Python stack traces into a ring buffer.
3. The **correlator** enriches each blocking event with the closest matching Python stack.
4. The **reporter** fans out events to one or more output sinks.

## Requirements

- Linux with eBPF support (kernel 4.15+)
- Root privileges (for eBPF and py-spy)
- [BCC (BPF Compiler Collection)](https://github.com/iovisor/bcc)
- [py-spy](https://github.com/benfred/py-spy)
- Python 3.12+

## Installation

```bash
pip install blocksnoop
```

Or for development:

```bash
git clone git@github.com:PaulM5406/blocksnoop.git
cd blocksnoop
uv sync --all-extras --dev
```

## Usage

### Attach to a running process

```bash
sudo blocksnoop <PID>
sudo blocksnoop -t 50 <PID>          # 50ms threshold (default: 100ms)
sudo blocksnoop --tid 1234 <PID>     # monitor specific thread
```

### Launch and monitor a process

```bash
sudo blocksnoop -- python app.py
sudo blocksnoop -t 50 -- python app.py
```

### Output modes

```bash
# Human-readable to stderr (default)
sudo blocksnoop -- python app.py

# JSON lines to stdout (for piping to jq, etc.)
sudo blocksnoop --json -- python app.py

# Structured JSON to file (for Datadog/Fluentd/CloudWatch)
sudo blocksnoop --log-file /var/log/blocksnoop/events.json --service my-api --env production -- python app.py

# Combine: console to terminal + JSON to file
sudo blocksnoop --log-file /var/log/blocksnoop/events.json --service my-api -- python app.py
```

### Example output

Human-readable:

```
[   1.23s] #1   BLOCKED     302.1ms  tid=1234
  Python stack (most recent call last):
    app.py:7 in blocking_io
    app.py:13 in main

[   2.05s] #2   BLOCKED     298.5ms  tid=1234
  Python stack (most recent call last):
    app.py:7 in blocking_io
    app.py:13 in main

--- blocksnoop session ---
Duration: 8.0s
Blocking events detected: 2
```

JSON (`--json`):

```json
{"event_number": 1, "timestamp_s": 1.23, "duration_ms": 302.1, "pid": 5678, "tid": 1234, "python_stack": [{"function": "blocking_io", "file": "app.py", "line": 7}, {"function": "main", "file": "app.py", "line": 13}], "level": "warning"}
```

### CLI reference

```
blocksnoop [OPTIONS] [PID] [-- COMMAND ...]

Options:
  -t, --threshold FLOAT   Blocking threshold in ms (default: 100)
  --tid INT               Thread ID to monitor (default: main thread)
  --json                  JSON lines output to stdout
  --log-file PATH         Write structured JSON to file for log aggregators
  --service NAME          Service name for structured logs (default: blocksnoop)
  --env ENV               Environment tag for structured logs
  --no-color              Disable ANSI colors in terminal output
```

## Docker

blocksnoop requires kernel access, so Docker containers need `--privileged` and `--pid=host`:

```yaml
# docker-compose.yml
services:
  blocksnoop:
    build: .
    privileged: true
    pid: host
```

```bash
docker compose run --rm blocksnoop blocksnoop -t 100 -- python app.py
```

## Kubernetes

blocksnoop uses eBPF which operates at the kernel level, so you run it on the **node**, not inside the application container. The target process just needs to be visible from the host PID namespace.

### Ephemeral debug container (recommended)

Attach directly to a running pod with an ephemeral container:

```bash
# Find the pod
kubectl get pods -l app=my-api

# Attach an ephemeral debug container with the required privileges
kubectl debug -it my-api-pod-7b8c9d \
  --image=blocksnoop:latest \
  --target=my-api \
  -- sh
```

> The `--target` flag shares the process namespace with the app container, so you can see its PIDs.

Inside the debug container, find the Python process and attach:

```bash
# Find the Python PID
ps aux | grep python

# Attach blocksnoop
blocksnoop -t 50 <PID>

# Or with structured logging
blocksnoop --json -t 50 <PID>
```

This requires the ephemeral container to run as privileged. Your cluster must allow it (via PodSecurityPolicy, PodSecurityAdmission, or equivalent).

### DaemonSet sidecar

For continuous monitoring, deploy blocksnoop as a DaemonSet that monitors processes on each node:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: blocksnoop
spec:
  selector:
    matchLabels:
      app: blocksnoop
  template:
    metadata:
      labels:
        app: blocksnoop
    spec:
      hostPID: true
      containers:
        - name: blocksnoop
          image: blocksnoop:latest
          command: ["blocksnoop", "--json", "--log-file", "/var/log/blocksnoop/events.json", "--service", "my-api", "--env", "production", "-t", "100"]
          securityContext:
            privileged: true
          volumeMounts:
            - name: logs
              mountPath: /var/log/blocksnoop
            - name: debugfs
              mountPath: /sys/kernel/debug
      volumes:
        - name: logs
          hostPath:
            path: /var/log/blocksnoop
        - name: debugfs
          hostPath:
            path: /sys/kernel/debug
```

The log file at `/var/log/blocksnoop/events.json` can be tailed by Datadog Agent, Fluentd, or any log collector running on the node.

### Node shell (quick one-off)

For a quick check without building images:

```bash
# SSH into the node (or use a node shell tool)
kubectl node-shell <node-name>

# Install blocksnoop
pip install blocksnoop

# Find the Python process (hostPID shows all processes)
ps aux | grep python

# Attach
blocksnoop -t 50 <PID>
```

## Development

```bash
# Install dependencies
uv sync --all-extras --dev

# Run unit tests
uv run --extra dev pytest tests/ -v --ignore=tests/integration

# Run integration tests (requires Docker)
uv run --extra dev pytest -m docker tests/integration/ -v

# Lint and format
ruff check blocksnoop/ tests/
ruff format blocksnoop/ tests/

# Type check
ty check blocksnoop/
```

## License

MIT
