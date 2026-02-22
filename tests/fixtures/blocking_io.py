import asyncio
import time


def blocking_io():
    """Simulate blocking I/O that blocks the event loop."""
    time.sleep(0.3)


async def main():
    while True:
        print("About to block the event loop with sync I/O...")
        blocking_io()
        await asyncio.sleep(0.5)


if __name__ == "__main__":
    asyncio.run(main())
