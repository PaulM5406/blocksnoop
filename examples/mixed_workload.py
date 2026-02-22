"""
Example: Async worker with a mix of correct and incorrect patterns.

Some tasks correctly use asyncio, others accidentally block.
Useful for verifying that loopspy only flags the blocking ones.

Run with:
    docker compose run --rm loopspy loopspy -t 50 -- python examples/mixed_workload.py
"""

import asyncio
import hashlib
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
# BAD: blocking operations that will be caught by loopspy
# ---------------------------------------------------------------------------


def sync_read_from_db(query: str) -> dict:
    """Blocking: synchronous database read (e.g. psycopg2 without async)."""
    time.sleep(0.2)
    return {"rows": 42, "query": query}


def sync_hash_token(token: str) -> str:
    """Blocking: CPU-heavy token hashing on the event loop."""
    result = token.encode()
    for _ in range(300_000):
        result = hashlib.sha256(result).digest()
    return result.hex()[:16]


def sync_call_payment_api(amount: float) -> dict:
    """Blocking: synchronous HTTP call to payment provider."""
    time.sleep(0.35)
    return {"status": "ok", "amount": amount}


def sync_write_audit_log(entry: str) -> None:
    """Blocking: synchronous file append for audit trail."""
    time.sleep(0.1)


# ---------------------------------------------------------------------------
# Workers that mix good and bad patterns
# ---------------------------------------------------------------------------


async def ingest_worker() -> None:
    """Fetches data correctly, then blocks on DB write."""
    while True:
        items = await process_batch_async([1, 2, 3])
        print(f"[ingest] fetched {len(items)} items (async)")

        result = sync_read_from_db("INSERT INTO events ...")  # blocks!
        print(f"[ingest] wrote {result['rows']} rows (sync, BLOCKING)")

        await asyncio.sleep(0.8)


async def auth_worker() -> None:
    """Hashes tokens synchronously — CPU-bound block."""
    while True:
        await asyncio.sleep(1.0)
        token = sync_hash_token("user-session-abc123")  # blocks!
        print(f"[auth] hashed token → {token} (sync, BLOCKING)")


async def payment_worker() -> None:
    """Calls payment API synchronously, then writes audit log."""
    while True:
        await asyncio.sleep(1.2)
        resp = sync_call_payment_api(99.99)  # blocks!
        print(f"[payment] charged {resp['amount']} (sync, BLOCKING)")

        sync_write_audit_log(f"payment {resp['amount']}")  # blocks!
        print("[payment] audit log written (sync, BLOCKING)")


async def main() -> None:
    print("=== Mixed workload: 3 async workers with different blocking bugs ===")
    print("loopspy should flag: sync_read_from_db, sync_hash_token,")
    print("  sync_call_payment_api, sync_write_audit_log\n")
    await asyncio.gather(
        ingest_worker(),
        auth_worker(),
        payment_worker(),
    )


if __name__ == "__main__":
    asyncio.run(main())
