"""
Example: FastAPI server with accidental blocking calls.

This simulates a realistic web app where developers accidentally use
synchronous operations inside async handlers, blocking the event loop.

Each handler has three categories of code:
  - FAST SYNC: quick in-memory ops (SQLite, JSON, regex) — not flagged
  - ASYNC I/O: non-blocking via to_thread (I/O-bound only) — not flagged
  - SLOW SYNC (BUG): blocking calls on the event loop — FLAGGED by blocksnoop

Note on to_thread and the GIL:
  to_thread() only helps for I/O-bound work (network, disk, sleep) because
  the thread releases the GIL while waiting. For CPU-bound Python code
  (hash loops, compression), to_thread() does NOT help — the GIL prevents
  the event loop thread from running. Those remain as bugs.

Run with:
    docker compose run --rm blocksnoop blocksnoop -t 50 -- python examples/fastapi_server.py
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
# In-memory SQLite — real sync I/O that blocksnoop should NOT flag (fast enough)
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
# Slow blocking helpers — the underlying work that needs wrapping
# ---------------------------------------------------------------------------

def _slow_db_query(user_id: int) -> dict:
    """Simulates a blocking database call (e.g. remote PostgreSQL over network)."""
    time.sleep(0.2)
    return {"id": user_id, "name": f"user_{user_id}", "email": f"user_{user_id}@example.com"}


def _slow_hash_password(password: str) -> str:
    """CPU-heavy password hashing."""
    result = password.encode()
    for _ in range(200_000):
        result = hashlib.sha256(result).digest()
    return result.hex()


def _slow_write_log(message: str) -> None:
    """Blocking file write (simulates synchronous logging to remote syslog)."""
    time.sleep(0.05)


def _slow_http_call(url: str) -> dict:
    """Simulates a blocking HTTP request (e.g. requests.get instead of httpx)."""
    time.sleep(0.3)
    return {"status": 200, "body": f"response from {url}"}


# ---------------------------------------------------------------------------
# CORRECT async wrappers — to_thread() for I/O-bound work only
# ---------------------------------------------------------------------------
# to_thread() releases the GIL during I/O waits (network, disk, sleep),
# so these wrappers genuinely unblock the event loop.
# CPU-bound work (like _slow_hash_password) is NOT wrapped here because
# to_thread() would still hold the GIL and block the event loop.

async def async_db_query(user_id: int) -> dict:
    """Correct: offloads I/O-bound DB call to a thread."""
    return await asyncio.to_thread(_slow_db_query, user_id)


async def async_write_log(message: str) -> None:
    """Correct: offloads I/O-bound file write to a thread."""
    await asyncio.to_thread(_slow_write_log, message)


async def async_http_call(url: str) -> dict:
    """Correct: offloads I/O-bound HTTP to a thread (real fix: use httpx/aiohttp)."""
    return await asyncio.to_thread(_slow_http_call, url)


# ---------------------------------------------------------------------------
# Async handlers — mix of fast sync (OK), async (OK), and slow sync (BUG)
# ---------------------------------------------------------------------------

async def handle_login(user_id: int, password: str) -> dict:
    """Handler with fast sync, correct async, AND buggy slow sync."""
    # Fast sync — OK
    cached_user = quick_db_lookup(user_id)
    quick_log_insert(f"login attempt: {user_id}")
    valid = quick_validate_email(cached_user["email"])

    # Correct async — OK, uses to_thread
    await async_write_log(f"login start: {user_id}")

    # BUG: blocking calls directly on the event loop
    user = _slow_db_query(user_id)             # BUG: I/O-bound, should use async_db_query
    hashed = _slow_hash_password(password)      # BUG: CPU-bound, to_thread won't help (GIL)
    _slow_write_log(f"login success: {user_id}")  # BUG: I/O-bound, should use async_write_log
    return {"user": user["name"], "token": hashed[:16], "valid_email": valid}


async def handle_get_profile(user_id: int) -> dict:
    """Handler with one correct async call and one buggy sync call."""
    # Fast sync — OK
    cached = quick_db_lookup(user_id)
    payload = quick_json_serialize(cached)

    # Correct async — OK, uses to_thread
    user = await async_db_query(user_id)

    # BUG: blocking HTTP call directly on the event loop
    friends = _slow_http_call(f"http://api.internal/friends/{user_id}")  # BUG
    return {"user": user, "friends": friends, "cached_size": len(payload)}


async def handle_healthcheck() -> dict:
    """Healthcheck: fast config read + correct async log."""
    config = quick_read_config()  # fast sync — OK
    await async_write_log("healthcheck ping")  # correct async — OK
    return {"status": "ok", "debug": config.get("debug")}


async def handle_search(query: str) -> dict:
    """Fully correct handler — no blocking calls at all."""
    # Fast sync — OK
    clean_query = re.sub(r"[^\w\s]", "", query)

    # Correct async — OK
    results = await async_db_query(hash(clean_query) % 99 + 1)
    await async_write_log(f"search: {clean_query}")

    # Async sleep simulating async cache TTL wait
    await asyncio.sleep(0.01)
    return {"query": clean_query, "results": results}


# ---------------------------------------------------------------------------
# Simulated request loop (replaces uvicorn for this demo)
# ---------------------------------------------------------------------------

async def simulate_requests() -> None:
    """Simulate incoming HTTP requests in a loop."""
    request_id = 0
    while True:
        request_id += 1
        kind = request_id % 4

        if kind == 0:
            result = await handle_login(request_id, "s3cret!")
            print(f"[req {request_id}] POST /login → {json.dumps(result)}")
        elif kind == 1:
            result = await handle_get_profile(request_id)
            print(f"[req {request_id}] GET /profile → {json.dumps(result)}")
        elif kind == 2:
            result = await handle_healthcheck()
            print(f"[req {request_id}] GET /health → {json.dumps(result)}")
        else:
            result = await handle_search("async python")
            print(f"[req {request_id}] GET /search → {json.dumps(result)}")

        await asyncio.sleep(0.3)  # gap between requests


async def main() -> None:
    print("=== Simulated FastAPI server (with blocking bugs) ===")
    print("FLAGGED:     _slow_db_query, _slow_hash_password (CPU, GIL), _slow_write_log, _slow_http_call")
    print("NOT FLAGGED: quick_* (fast sync), async_db_query/async_write_log/async_http_call (to_thread, I/O)\n")
    await simulate_requests()


if __name__ == "__main__":
    asyncio.run(main())
