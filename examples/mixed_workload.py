"""
Example: Async workers with a mix of correct and incorrect patterns.

Each worker demonstrates three categories:
  - FAST SYNC: quick in-memory ops (SQLite, JSON, regex) — not flagged
  - ASYNC I/O: non-blocking via to_thread (I/O-bound only) — not flagged
  - SLOW SYNC (BUG): blocking calls on the event loop — FLAGGED by blocksnoop

Note on to_thread and the GIL:
  to_thread() only helps for I/O-bound work (network, disk, sleep) because
  the thread releases the GIL while waiting. For CPU-bound Python code
  (hash loops, compression), to_thread() does NOT help — the GIL prevents
  the event loop thread from running. Those remain as bugs.

Run with:
    docker compose run --rm blocksnoop blocksnoop -t 50 -- python examples/mixed_workload.py
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
# ASYNC I/O: to_thread() for I/O-bound work only
# ---------------------------------------------------------------------------
# to_thread() releases the GIL during I/O waits (network, disk, sleep),
# so these wrappers genuinely unblock the event loop.
# CPU-bound work (like slow_hash_token) is NOT wrapped here because
# to_thread() would still hold the GIL and block the event loop.


async def fetch_data_async(item_id: int) -> dict:
    """Correct: uses async sleep to simulate async I/O."""
    await asyncio.sleep(0.05)
    return {"id": item_id, "data": f"item_{item_id}"}


async def process_batch_async(items: list[int]) -> list[dict]:
    """Correct: concurrent async gathering."""
    return await asyncio.gather(*(fetch_data_async(i) for i in items))


def _blocking_db_write(query: str) -> dict:
    """The underlying I/O-bound blocking work."""
    time.sleep(0.2)
    return {"rows": 42, "query": query}


async def async_db_write(query: str) -> dict:
    """Correct: offloads I/O-bound DB write to a thread."""
    return await asyncio.to_thread(_blocking_db_write, query)


def _blocking_notify(channel: str, message: str) -> None:
    """The underlying I/O-bound blocking work."""
    time.sleep(0.1)


async def async_notify(channel: str, message: str) -> None:
    """Correct: offloads I/O-bound notification to a thread."""
    await asyncio.to_thread(_blocking_notify, channel, message)


# ---------------------------------------------------------------------------
# FAST SYNC: real sync code that is fast enough to NOT trigger blocksnoop
# ---------------------------------------------------------------------------

_db = sqlite3.connect(":memory:")
_db.execute("CREATE TABLE cache (key TEXT PRIMARY KEY, value TEXT)")
_db.commit()


def quick_cache_get(key: str) -> str | None:
    """Fast sync cache lookup — should NOT be flagged."""
    row = _db.execute("SELECT value FROM cache WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def quick_cache_set(key: str, value: str) -> None:
    """Fast sync cache write — should NOT be flagged."""
    _db.execute("INSERT OR REPLACE INTO cache (key, value) VALUES (?, ?)", (key, value))
    _db.commit()


def quick_hash_md5(data: str) -> str:
    """Fast sync hash — should NOT be flagged."""
    return hashlib.md5(data.encode()).hexdigest()


def quick_parse_payload(raw: str) -> dict:
    """Fast sync JSON parse + regex — should NOT be flagged."""
    data = json.loads(raw)
    data["clean_id"] = re.sub(r"[^a-zA-Z0-9]", "", str(data.get("id", "")))
    return data


def quick_write_temp_file(content: str) -> str:
    """Fast sync file write — should NOT be flagged."""
    fd, path = tempfile.mkstemp(suffix=".tmp")
    os.write(fd, content.encode())
    os.close(fd)
    os.unlink(path)
    return path


# ---------------------------------------------------------------------------
# SLOW SYNC: blocking operations that SHOULD be caught by blocksnoop
# ---------------------------------------------------------------------------


def slow_read_from_db(query: str) -> dict:
    """Blocking: synchronous database read (e.g. psycopg2 without async)."""
    time.sleep(0.2)
    return {"rows": 42, "query": query}


def slow_hash_token(token: str) -> str:
    """Blocking: CPU-heavy token hashing — to_thread won't help (GIL)."""
    result = token.encode()
    for _ in range(300_000):
        result = hashlib.sha256(result).digest()
    return result.hex()[:16]


def slow_compress(data: str) -> bytes:
    """Blocking: CPU-heavy compression — to_thread won't help (GIL)."""
    result = data.encode()
    for _ in range(200_000):
        result = hashlib.sha256(result).digest()
    return result


def slow_call_payment_api(amount: float) -> dict:
    """Blocking: synchronous HTTP call to payment provider."""
    time.sleep(0.35)
    return {"status": "ok", "amount": amount}


def slow_write_audit_log(entry: str) -> None:
    """Blocking: synchronous file append for audit trail."""
    time.sleep(0.1)


# ---------------------------------------------------------------------------
# Workers that mix all three categories
# ---------------------------------------------------------------------------


async def ingest_worker() -> None:
    """Fetches data async, does fast sync processing, then blocks on slow DB."""
    while True:
        # Async — OK
        items = await process_batch_async([1, 2, 3])
        print(f"[ingest] fetched {len(items)} items (async)")

        # Fast sync — OK
        payload = json.dumps({"items": items, "id": "batch-001"})
        parsed = quick_parse_payload(payload)
        checksum = quick_hash_md5(payload)
        quick_cache_set(f"ingest:{checksum}", payload)
        quick_write_temp_file(payload)
        print(f"[ingest] processed locally: checksum={checksum[:8]} (fast sync, OK)")

        # Async I/O — OK, uses to_thread (I/O-bound, releases GIL)
        await async_notify("ingest", f"batch ready: {len(payload)} bytes")
        print(f"[ingest] notified (async I/O, OK)")

        # Slow sync — FLAGGED
        compressed = slow_compress(payload)  # BUG: CPU-bound, GIL blocks loop
        print(f"[ingest] compressed {len(compressed)} bytes (sync, BLOCKING)")

        result = slow_read_from_db("INSERT INTO events ...")  # BUG: I/O-bound
        print(f"[ingest] wrote {result['rows']} rows (sync, BLOCKING)")

        await asyncio.sleep(0.8)


async def auth_worker() -> None:
    """Does fast cache check, correct async DB, then blocks on CPU-heavy hash."""
    while True:
        await asyncio.sleep(1.0)

        # Fast sync — OK
        cached = quick_cache_get("auth:last-token")
        quick_cache_set("auth:attempts", str(time.time()))
        print(f"[auth] cache check: {'hit' if cached else 'miss'} (fast sync, OK)")

        # Async I/O — OK, uses to_thread (I/O-bound, releases GIL)
        await async_db_write("UPDATE sessions SET last_seen = NOW()")
        print("[auth] updated session (async I/O, OK)")

        # Slow sync — FLAGGED
        token = slow_hash_token("user-session-abc123")  # BUG: CPU-bound, GIL blocks loop
        quick_cache_set("auth:last-token", token)
        print(f"[auth] hashed token -> {token} (sync, BLOCKING)")


async def payment_worker() -> None:
    """Does fast validation, correct async notification, then blocks on API."""
    while True:
        await asyncio.sleep(1.2)

        # Fast sync — OK
        order = {"id": "ORD-12345", "amount": 99.99, "currency": "EUR"}
        order_json = json.dumps(order)
        valid_id = bool(re.match(r"^ORD-\d+$", order["id"]))
        quick_write_temp_file(order_json)
        print(f"[payment] validated order {order['id']}: {valid_id} (fast sync, OK)")

        # Async I/O — OK, uses to_thread (I/O-bound, releases GIL)
        await async_notify("payments", f"processing {order['id']}")
        print("[payment] notified (async I/O, OK)")

        # Slow sync — FLAGGED
        resp = slow_call_payment_api(99.99)  # BUG: I/O-bound
        print(f"[payment] charged {resp['amount']} (sync, BLOCKING)")

        slow_write_audit_log(f"payment {resp['amount']}")  # BUG: I/O-bound
        print("[payment] audit log written (sync, BLOCKING)")


async def main() -> None:
    print("=== Mixed workload: 3 async workers with different blocking bugs ===")
    print("FLAGGED:     slow_read_from_db (I/O), slow_hash_token (CPU/GIL), slow_compress (CPU/GIL),")
    print("             slow_call_payment_api (I/O), slow_write_audit_log (I/O)")
    print("NOT FLAGGED: quick_* (fast sync), async_db_write/async_notify (to_thread, I/O), fetch_data_async\n")
    await asyncio.gather(
        ingest_worker(),
        auth_worker(),
        payment_worker(),
    )


if __name__ == "__main__":
    asyncio.run(main())
