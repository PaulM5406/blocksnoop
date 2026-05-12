#!/usr/bin/env bash
# Reproduce + verify the cross-mount-namespace Austin attach scenario.
#
# Spins up two containers:
#   - target: a Python sleeper, on a *read-only* rootfs (mimics hardened prod).
#   - blocksnoop: oloapm/blocksnoop:latest, sharing the target's PID namespace,
#     privileged so it can setns into the target's mount namespace.
#
# Asserts that Austin produces samples — which is what fails before the
# fd-passing nsenter wrapper fix (Austin would log
# "Cannot determine the version of the Python interpreter.").
#
# Requires: docker, CAP_SYS_ADMIN (i.e. local docker, not rootless).

set -euo pipefail

IMAGE_BLOCKSNOOP="${IMAGE_BLOCKSNOOP:-oloapm/blocksnoop:latest}"
IMAGE_TARGET="${IMAGE_TARGET:-python:3.11-slim}"
TARGET_NAME="blocksnoop-cross-ns-target-$$"
SNOOP_NAME="blocksnoop-cross-ns-snoop-$$"

cleanup() {
    docker rm -f "$TARGET_NAME" "$SNOOP_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/4] starting target ($IMAGE_TARGET) on read-only rootfs..."
docker run -d --rm \
    --name "$TARGET_NAME" \
    --read-only \
    --tmpfs /tmp:ro \
    "$IMAGE_TARGET" \
    python -c "import time; [time.sleep(0.01) for _ in iter(int, 1)]" \
    >/dev/null

# Give the interpreter a moment to settle.
sleep 1

echo "[2/4] resolving target PID inside its own ns..."
TARGET_PID="$(docker inspect -f '{{.State.Pid}}' "$TARGET_NAME")"
echo "      host PID = $TARGET_PID"

echo "[3/4] attaching blocksnoop ($IMAGE_BLOCKSNOOP), threshold=50ms, 10s..."
LOG_FILE="$(mktemp)"
docker run --rm \
    --name "$SNOOP_NAME" \
    --pid="container:$TARGET_NAME" \
    --privileged \
    -v /sys/kernel/debug:/sys/kernel/debug \
    "$IMAGE_BLOCKSNOOP" \
    timeout 10 blocksnoop -t 50 --json "$TARGET_PID" \
    >"$LOG_FILE" 2>&1 || true

echo "[4/4] checking output..."
if grep -q "Cannot determine the version" "$LOG_FILE"; then
    echo "FAIL: Austin couldn't resolve Python — fd-passing wrapper not active." >&2
    cat "$LOG_FILE" >&2
    exit 1
fi
if grep -q "Austin has not produced any samples" "$LOG_FILE"; then
    echo "FAIL: Austin produced zero samples." >&2
    cat "$LOG_FILE" >&2
    exit 1
fi
if ! grep -qE "Austin samples|\"stack\":" "$LOG_FILE"; then
    echo "FAIL: no evidence of Austin samples in output." >&2
    cat "$LOG_FILE" >&2
    exit 1
fi

echo "PASS: Austin sampled the target across mount namespaces."
rm -f "$LOG_FILE"
