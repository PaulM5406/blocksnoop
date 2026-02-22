"""
Example: Async worker with a mix of correct and incorrect patterns.

Some tasks correctly use asyncio, others accidentally block.
Useful for verifying that loopspy only flags the blocking ones.

Run with:
    docker compose run --rm loopspy loopspy --json -t 50 -- python examples/mixed_workload.py
"""

import asyncio
import time
import json


# ---------------------------------------------------------------------------
# GOOD: properly async operations
# ---------------------------------------------------------------------------

async def fetch_data_async(item_id: int) -> dict:
    """Correct: uses async sleep to simulate async I/O."""
    await asyncio.sleep(0.1)
    return {"id": item_id, "data": f"item_{item_id}"}


async def process_batch_async(items: list[int]) -> list[dict]:
    """Correct: concurrent async gathering."""
    return await asyncio.gather(*(fetch_data_async(i) for i in items))


# ---------------------------------------------------------------------------
# BAD: blocking operations that will be caught by loopspy
# ---------------------------------------------------------------------------

def sync_serialize(data: list[dict]) -> str:
    """Blocking: CPU-heavy JSON serialization of a large payload."""
    # Simulate serializing a huge response
    big_payload = data * 500
    return json.dumps(big_payload)


def sync_write_to_disk(path: str, content: str) -> None:
    """Blocking: synchronous file write."""
    time.sleep(0.15)


def sync_compress(data: str) -> bytes:
    """Blocking: CPU-heavy compression."""
    result = data.encode()
    for _ in range(100_000):
        result = bytes(b ^ 0xAA for b in result[:64])
    time.sleep(0.1)
    return result


# ---------------------------------------------------------------------------
# Main loop: alternates good and bad patterns
# ---------------------------------------------------------------------------

async def worker() -> None:
    cycle = 0
    while True:
        cycle += 1

        # Good: async data fetch
        items = await process_batch_async([1, 2, 3, 4, 5])
        print(f"[cycle {cycle}] Fetched {len(items)} items (async, non-blocking)")

        # Bad: sync serialization + disk write
        serialized = sync_serialize(items)        # blocks!
        sync_write_to_disk("/tmp/out.json", serialized)  # blocks!
        print(f"[cycle {cycle}] Wrote {len(serialized)} bytes (sync, BLOCKING)")

        # Bad every 3rd cycle: compression
        if cycle % 3 == 0:
            sync_compress(serialized)             # blocks!
            print(f"[cycle {cycle}] Compressed (sync, BLOCKING)")

        await asyncio.sleep(0.5)


async def main() -> None:
    print("=== Mixed workload: async fetches + sync writes ===")
    print("loopspy should flag sync_serialize, sync_write_to_disk, sync_compress\n")
    await worker()


if __name__ == "__main__":
    asyncio.run(main())
