"""
Example: Async worker with a mix of correct and incorrect patterns.

Some tasks correctly use asyncio, others accidentally block.
Fast sync operations (JSON, regex, in-memory DB) should NOT be flagged.

Run with:
    docker compose run --rm loopspy loopspy -t 50 -- python examples/mixed_workload.py
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
# GOOD: properly async operations
# ---------------------------------------------------------------------------


async def fetch_data_async(item_id: int) -> dict:
    """Correct: uses async sleep to simulate async I/O."""
    await asyncio.sleep(0.05)
    return {"id": item_id, "data": f"item_{item_id}"}


async def process_batch_async(items: list[int]) -> list[dict]:
    """Correct: concurrent async gathering."""
    return await asyncio.gather(*(fetch_data_async(i) for i in items))


# ---------------------------------------------------------------------------
# FAST SYNC: real sync code that is fast enough to NOT trigger loopspy
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
# SLOW SYNC: blocking operations that SHOULD be caught by loopspy
# ---------------------------------------------------------------------------


def slow_read_from_db(query: str) -> dict:
    """Blocking: synchronous database read (e.g. psycopg2 without async)."""
    time.sleep(0.2)
    return {"rows": 42, "query": query}


def slow_hash_token(token: str) -> str:
    """Blocking: CPU-heavy token hashing on the event loop."""
    result = token.encode()
    for _ in range(300_000):
        result = hashlib.sha256(result).digest()
    return result.hex()[:16]


def slow_call_payment_api(amount: float) -> dict:
    """Blocking: synchronous HTTP call to payment provider."""
    time.sleep(0.35)
    return {"status": "ok", "amount": amount}


def slow_write_audit_log(entry: str) -> None:
    """Blocking: synchronous file append for audit trail."""
    time.sleep(0.1)


# ---------------------------------------------------------------------------
# Workers that mix fast sync, async, and slow sync
# ---------------------------------------------------------------------------


async def ingest_worker() -> None:
    """Fetches data async, does fast sync processing, then blocks on slow DB."""
    while True:
        items = await process_batch_async([1, 2, 3])
        print(f"[ingest] fetched {len(items)} items (async)")

        # Fast sync — should NOT be flagged
        payload = json.dumps({"items": items, "id": "batch-001"})
        parsed = quick_parse_payload(payload)
        checksum = quick_hash_md5(payload)
        quick_cache_set(f"ingest:{checksum}", payload)
        quick_write_temp_file(payload)
        print(f"[ingest] processed locally: checksum={checksum[:8]} (fast sync, OK)")

        # Slow sync — SHOULD be flagged
        result = slow_read_from_db("INSERT INTO events ...")  # blocks!
        print(f"[ingest] wrote {result['rows']} rows (sync, BLOCKING)")

        await asyncio.sleep(0.8)


async def auth_worker() -> None:
    """Does fast cache check, then blocks on CPU-heavy hashing."""
    while True:
        await asyncio.sleep(1.0)

        # Fast sync — should NOT be flagged
        cached = quick_cache_get("auth:last-token")
        quick_cache_set("auth:attempts", str(time.time()))
        print(f"[auth] cache check: {'hit' if cached else 'miss'} (fast sync, OK)")

        # Slow sync — SHOULD be flagged
        token = slow_hash_token("user-session-abc123")  # blocks!
        quick_cache_set("auth:last-token", token)
        print(f"[auth] hashed token -> {token} (sync, BLOCKING)")


async def payment_worker() -> None:
    """Does fast validation, then blocks on remote API + audit log."""
    while True:
        await asyncio.sleep(1.2)

        # Fast sync — should NOT be flagged
        order = {"id": "ORD-12345", "amount": 99.99, "currency": "EUR"}
        order_json = json.dumps(order)
        valid_id = bool(re.match(r"^ORD-\d+$", order["id"]))
        quick_write_temp_file(order_json)
        print(f"[payment] validated order {order['id']}: {valid_id} (fast sync, OK)")

        # Slow sync — SHOULD be flagged
        resp = slow_call_payment_api(99.99)  # blocks!
        print(f"[payment] charged {resp['amount']} (sync, BLOCKING)")

        slow_write_audit_log(f"payment {resp['amount']}")  # blocks!
        print("[payment] audit log written (sync, BLOCKING)")


async def main() -> None:
    print("=== Mixed workload: 3 async workers with different blocking bugs ===")
    print("loopspy should flag: slow_read_from_db, slow_hash_token,")
    print("  slow_call_payment_api, slow_write_audit_log")
    print("loopspy should NOT flag: quick_cache_get, quick_cache_set,")
    print("  quick_hash_md5, quick_parse_payload, quick_write_temp_file\n")
    await asyncio.gather(
        ingest_worker(),
        auth_worker(),
        payment_worker(),
    )


if __name__ == "__main__":
    asyncio.run(main())
