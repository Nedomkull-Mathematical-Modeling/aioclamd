"""Container HEALTHCHECK: exercises aioclamd against the local clamd.

Wraps the call in asyncio.wait_for() explicitly because ClamdAsyncClient's
own `timeout` constructor argument is currently a no-op (it is stored but
never applied) -- see the project's security review for details.
"""
import asyncio
import sys

from aioclamd import ClamdAsyncClient


async def main() -> int:
    client = ClamdAsyncClient("127.0.0.1", 3310)
    try:
        pong = await asyncio.wait_for(client.ping(), timeout=5)
    except Exception:
        return 1
    return 0 if pong == "PONG" else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
