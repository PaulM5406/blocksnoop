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
import sqlite3
import time


# ---------------------------------------------------------------------------
# Fake "database" and "external service" helpers (no real deps needed)
# ---------------------------------------------------------------------------

def sync_db_query(user_id: int) -> dict:
    """Simulates a blocking database call (e.g. synchronous ORM query)."""
    # In real code this might be: db.session.query(User).get(user_id)
    time.sleep(0.2)
    return {"id": user_id, "name": f"user_{user_id}", "email": f"user_{user_id}@example.com"}


def sync_hash_password(password: str) -> str:
    """CPU-heavy password hashing that blocks the loop."""
    # Simulates bcrypt / argon2 in sync mode
    result = password.encode()
    for _ in range(200_000):
        result = hashlib.sha256(result).digest()
    return result.hex()


def sync_write_log(message: str) -> None:
    """Blocking file write (simulates synchronous logging to disk)."""
    time.sleep(0.05)


def sync_http_call(url: str) -> dict:
    """Simulates a blocking HTTP request (e.g. requests.get instead of httpx)."""
    time.sleep(0.3)
    return {"status": 200, "body": f"response from {url}"}


# ---------------------------------------------------------------------------
# Async handlers — each has a subtle blocking mistake
# ---------------------------------------------------------------------------

async def handle_login(user_id: int, password: str) -> dict:
    """Handler that accidentally hashes passwords synchronously."""
    user = sync_db_query(user_id)        # BUG: blocking DB call
    hashed = sync_hash_password(password) # BUG: CPU-heavy sync call
    sync_write_log(f"login: {user_id}")   # BUG: blocking file write
    return {"user": user["name"], "token": hashed[:16]}


async def handle_get_profile(user_id: int) -> dict:
    """Handler that calls a sync HTTP client."""
    user = sync_db_query(user_id)
    friends = sync_http_call(f"http://api.internal/friends/{user_id}")  # BUG
    return {"user": user, "friends": friends}


async def handle_healthcheck() -> dict:
    """Even the healthcheck blocks — a common real-world mistake."""
    sync_write_log("healthcheck ping")
    return {"status": "ok"}


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
    print("loopspy should detect blocking calls in the handlers.\n")
    await simulate_requests()


if __name__ == "__main__":
    asyncio.run(main())
