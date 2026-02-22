# loopspy

Detect blocking calls in Python asyncio event loops using eBPF + py-spy.

loopspy attaches to a running Python process (or launches one) and reports every time the event loop is blocked longer than a configurable threshold — with the Python stack trace that caused it.

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
pip install loopspy
```

Or for development:

```bash
git clone git@github.com:PaulM5406/loopspy.git
cd loopspy
uv sync --all-extras --dev
```

## Usage

### Attach to a running process

```bash
sudo loopspy <PID>
sudo loopspy -t 50 <PID>          # 50ms threshold (default: 100ms)
sudo loopspy --tid 1234 <PID>     # monitor specific thread
```

### Launch and monitor a process

```bash
sudo loopspy -- python app.py
sudo loopspy -t 50 -- python app.py
```

### Output modes

```bash
# Human-readable to stderr (default)
sudo loopspy -- python app.py

# JSON lines to stdout (for piping to jq, etc.)
sudo loopspy --json -- python app.py

# Structured JSON to file (for Datadog/Fluentd/CloudWatch)
sudo loopspy --log-file /var/log/loopspy/events.json --service my-api --env production -- python app.py

# Combine: console to terminal + JSON to file
sudo loopspy --log-file /var/log/loopspy/events.json --service my-api -- python app.py
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

--- loopspy session ---
Duration: 8.0s
Blocking events detected: 2
```

JSON (`--json`):

```json
{"event_number": 1, "timestamp_s": 1.23, "duration_ms": 302.1, "pid": 5678, "tid": 1234, "python_stack": [{"function": "blocking_io", "file": "app.py", "line": 7}, {"function": "main", "file": "app.py", "line": 13}], "level": "warning"}
```

### CLI reference

```
loopspy [OPTIONS] [PID] [-- COMMAND ...]

Options:
  -t, --threshold FLOAT   Blocking threshold in ms (default: 100)
  --tid INT               Thread ID to monitor (default: main thread)
  --json                  JSON lines output to stdout
  --log-file PATH         Write structured JSON to file for log aggregators
  --service NAME          Service name for structured logs (default: loopspy)
  --env ENV               Environment tag for structured logs
  --no-color              Disable ANSI colors in terminal output
```

## Docker

loopspy requires kernel access, so Docker containers need `--privileged` and `--pid=host`:

```yaml
# docker-compose.yml
services:
  loopspy:
    build: .
    privileged: true
    pid: host
```

```bash
docker compose run --rm loopspy loopspy -t 100 -- python app.py
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
ruff check loopspy/ tests/
ruff format loopspy/ tests/

# Type check
ty check loopspy/
```

## License

MIT
