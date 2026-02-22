import asyncio


def cpu_heavy():
    """Simulate CPU-bound work that blocks the event loop."""
    total = 0
    for i in range(5_000_000):
        total += i * i
    return total


async def main():
    while True:
        print("About to block the event loop with CPU work...")
        cpu_heavy()
        await asyncio.sleep(0.5)


if __name__ == "__main__":
    asyncio.run(main())
