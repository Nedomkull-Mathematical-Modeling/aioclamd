import asyncio
import base64
import pathlib
from io import BytesIO

import pytest

from aioclamd import (
    BufferTooLongError,
    ClamdAsyncClient,
    ClamdConnectionError,
    ConnectionTimeoutError,
)

pytest_plugins = ("pytest_asyncio",)


@pytest.fixture()
def eicar():
    yield BytesIO(
        base64.b64decode(
            b"WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNU"
            b"QU5EQVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n"
        )
    )


@pytest.mark.asyncio
async def test_ping():
    clamd = ClamdAsyncClient()
    assert await clamd.ping() == "PONG"


@pytest.mark.asyncio
async def test_version():
    clamd = ClamdAsyncClient()
    assert (await clamd.version()).startswith("ClamAV")


@pytest.mark.asyncio
async def test_scan_filesystem():
    clamd = ClamdAsyncClient()
    assert (await clamd.scan("/etc/clamav/clamd.conf")).get(
        "/etc/clamav/clamd.conf"
    ) == ("OK", None)


@pytest.mark.asyncio
async def test_contscan_filesystem():
    clamd = ClamdAsyncClient()
    result = await clamd.contscan("/etc/")
    assert result
    assert all(
        status == "ERROR" and "Access denied" in reason
        for status, reason in result.values()
    )


@pytest.mark.asyncio
async def test_multiscan_filesystem():
    clamd = ClamdAsyncClient()
    result = await clamd.multiscan("/etc/")
    assert result
    assert all(
        status == "ERROR" and "Access denied" in reason
        for status, reason in result.values()
    )


@pytest.mark.asyncio
async def test_instream_eicar(eicar):
    clamd = ClamdAsyncClient()
    result = await clamd.instream(eicar)
    status, virus_name = result["stream"]
    assert status == "FOUND"
    assert "eicar" in virus_name.lower()


@pytest.mark.asyncio
async def test_instream_this_file():
    clamd = ClamdAsyncClient()
    assert await clamd.instream(BytesIO(pathlib.Path(__file__).read_bytes())) == {
        "stream": ("OK", None)
    }


@pytest.mark.asyncio
async def test_instream_max_size_enforced():
    clamd = ClamdAsyncClient()
    buffer = BytesIO(b"x" * 4096)
    with pytest.raises(BufferTooLongError):
        await clamd.instream(buffer, max_size=1024)


@pytest.mark.asyncio
async def test_scan_rejects_embedded_newline():
    clamd = ClamdAsyncClient()
    with pytest.raises(ValueError):
        await clamd.scan("/etc/clamav/clamd.conf\nPING")


@pytest.mark.asyncio
async def test_ping_connection_error():
    # Nothing listens on this port, so the connection should be refused.
    clamd = ClamdAsyncClient("127.0.0.1", 1)
    with pytest.raises(ClamdConnectionError):
        await clamd.ping()


@pytest.mark.asyncio
async def test_ping_times_out_on_unresponsive_server():
    async def handle(reader, writer):
        # Read the command but never reply, simulating a hung/malicious peer.
        await reader.read(1024)
        await asyncio.sleep(10)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        clamd = ClamdAsyncClient("127.0.0.1", port, timeout=0.2)
        with pytest.raises(ConnectionTimeoutError):
            await clamd.ping()


@pytest.mark.asyncio
async def test_instream_times_out_on_unresponsive_server():
    async def handle(reader, writer):
        # Accept the connection but never read or reply, simulating a hang
        # partway through a stream upload.
        await asyncio.sleep(10)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        clamd = ClamdAsyncClient("127.0.0.1", port, timeout=0.2)
        with pytest.raises(ConnectionTimeoutError):
            await clamd.instream(BytesIO(b"x" * 10))


@pytest.mark.asyncio
async def test_instream_buffer_too_long_from_server():
    # Simulates clamd's own StreamMaxLength rejection, independent of the
    # client-side `max_size` cap: a fake server that drains the whole
    # length-prefixed stream, then replies with clamd's literal overflow
    # message.
    async def handle(reader, writer):
        await reader.readline()  # the "INSTREAM" command line
        while True:
            size = int.from_bytes(await reader.readexactly(4), "big")
            if size == 0:
                break
            await reader.readexactly(size)
        writer.write(b"INSTREAM size limit exceeded. ERROR\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        clamd = ClamdAsyncClient("127.0.0.1", port)
        with pytest.raises(BufferTooLongError):
            await clamd.instream(BytesIO(b"x" * 2048))
