"""
Example: FastAPI server with accidental blocking calls.

This simulates a realistic web app where developers accidentally use
synchronous operations inside async handlers, blocking the event loop.

Run with:
    docker compose run --rm loopspy loopspy -t 50 -- python examples/fastapi_server.py
"""

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time


# ---------------------------------------------------------------------------
# In-memory SQLite — real sync I/O that loopspy should NOT flag (fast enough)
# ---------------------------------------------------------------------------

_db = sqlite3.connect(":memory:")
_db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
_db.execute("CREATE TABLE logs  (id INTEGER PRIMARY KEY, message TEXT, ts REAL)")
for i in range(1, 100):
    _db.execute("INSERT INTO users VALUES (?, ?, ?)", (i, f"user_{i}", f"user_{i}@example.com"))
_db.commit()


def quick_db_lookup(user_id: int) -> dict:
    """Fast sync DB read — under threshold, should NOT be flagged."""
    row = _db.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,)).fetchone()
    if row:
        return {"id": row[0], "name": row[1], "email": row[2]}
    return {"id": user_id, "name": "unknown", "email": ""}


def quick_log_insert(message: str) -> None:
    """Fast sync DB write — under threshold, should NOT be flagged."""
    _db.execute("INSERT INTO logs (message, ts) VALUES (?, ?)", (message, time.time()))
    _db.commit()


def quick_json_serialize(data: dict) -> str:
    """Fast sync JSON serialization — under threshold, should NOT be flagged."""
    return json.dumps(data)


def quick_validate_email(email: str) -> bool:
    """Fast sync regex validation — under threshold, should NOT be flagged."""
    return bool(re.match(r"^[\w.+-]+@[\w-]+\.[\w.]+$", email))


def quick_read_config() -> dict:
    """Fast sync file read — under threshold, should NOT be flagged."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, b'{"debug": false, "max_connections": 100}')
    os.close(fd)
    with open(path) as f:
        data = json.load(f)
    os.unlink(path)
    return data


# ---------------------------------------------------------------------------
# Slow blocking operations — these SHOULD be flagged by loopspy
# ---------------------------------------------------------------------------

def slow_db_query(user_id: int) -> dict:
    """Simulates a blocking database call (e.g. remote PostgreSQL over network)."""
    time.sleep(0.2)
    return {"id": user_id, "name": f"user_{user_id}", "email": f"user_{user_id}@example.com"}


def slow_hash_password(password: str) -> str:
    """CPU-heavy password hashing that blocks the loop."""
    result = password.encode()
    for _ in range(200_000):
        result = hashlib.sha256(result).digest()
    return result.hex()


def slow_write_log(message: str) -> None:
    """Blocking file write (simulates synchronous logging to remote syslog)."""
    time.sleep(0.05)


def slow_http_call(url: str) -> dict:
    """Simulates a blocking HTTP request (e.g. requests.get instead of httpx)."""
    time.sleep(0.3)
    return {"status": 200, "body": f"response from {url}"}


# ---------------------------------------------------------------------------
# Async handlers — mix of fast sync (OK) and slow sync (BUG)
# ---------------------------------------------------------------------------

async def handle_login(user_id: int, password: str) -> dict:
    """Handler with both fast and slow sync calls."""
    # These are fine — fast sync operations
    cached_user = quick_db_lookup(user_id)
    quick_log_insert(f"login attempt: {user_id}")
    valid = quick_validate_email(cached_user["email"])

    # These are bugs — blocking calls
    user = slow_db_query(user_id)            # BUG: slow remote DB
    hashed = slow_hash_password(password)     # BUG: CPU-heavy sync
    slow_write_log(f"login success: {user_id}")  # BUG: blocking I/O
    return {"user": user["name"], "token": hashed[:16], "valid_email": valid}


async def handle_get_profile(user_id: int) -> dict:
    """Handler with fast local DB + slow remote HTTP."""
    # Fast — local SQLite lookup
    cached = quick_db_lookup(user_id)
    payload = quick_json_serialize(cached)

    # Slow — remote calls
    user = slow_db_query(user_id)
    friends = slow_http_call(f"http://api.internal/friends/{user_id}")  # BUG
    return {"user": user, "friends": friends, "cached_size": len(payload)}


async def handle_healthcheck() -> dict:
    """Healthcheck with fast config read + slow log write."""
    config = quick_read_config()  # fast
    slow_write_log("healthcheck ping")  # BUG: blocking I/O
    return {"status": "ok", "debug": config.get("debug")}


# ---------------------------------------------------------------------------
# Simulated request loop (replaces uvicorn for this demo)
# ---------------------------------------------------------------------------

async def simulate_requests() -> None:
    """Simulate incoming HTTP requests in a loop."""
    request_id = 0
    while True:
        request_id += 1
        kind = request_id % 3

        if kind == 0:
            result = await handle_login(request_id, "s3cret!")
            print(f"[req {request_id}] POST /login → {json.dumps(result)}")
        elif kind == 1:
            result = await handle_get_profile(request_id)
            print(f"[req {request_id}] GET /profile → {json.dumps(result)}")
        else:
            result = await handle_healthcheck()
            print(f"[req {request_id}] GET /health → {json.dumps(result)}")

        await asyncio.sleep(0.3)  # gap between requests


async def main() -> None:
    print("=== Simulated FastAPI server (with blocking bugs) ===")
    print("loopspy should flag: slow_db_query, slow_hash_password,")
    print("  slow_write_log, slow_http_call")
    print("loopspy should NOT flag: quick_db_lookup, quick_log_insert,")
    print("  quick_json_serialize, quick_validate_email, quick_read_config\n")
    await simulate_requests()


if __name__ == "__main__":
    asyncio.run(main())
