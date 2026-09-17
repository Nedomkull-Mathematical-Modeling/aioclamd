import asyncio
import re
import struct
from importlib.metadata import PackageNotFoundError, version
from typing import BinaryIO, Optional, Union

try:
    __version__ = version("aioclamd")
except PackageNotFoundError:
    __version__ = ""

scan_response = re.compile(
    r"^(?P<path>.*): ((?P<virus>.+) )?(?P<status>(FOUND|OK|ERROR))$"
)

# clamd responses are short status lines; this bounds how much a slow or
# malicious peer can make us buffer before we give up.
_MAX_RESPONSE_SIZE = 64 * 1024


class ClamdError(Exception):
    """Base exception for aioclamd"""


class ResponseError(ClamdError):
    """Class for errors when parsing response."""


class BufferTooLongError(ResponseError):
    """
    Class for errors with clamd using INSTREAM with a buffer
    length > StreamMaxLength in /etc/clamav/clamd.conf, or exceeding
    the `max_size` passed to ``instream``.
    """


class ClamdConnectionError(ClamdError):
    """Class for errors communication with clamd"""


class ConnectionTimeoutError(ClamdConnectionError):
    """Raised when a call exceeds ClamdAsyncClient's configured `timeout`."""


def _parse_response(msg):
    """
    parses responses for SCAN, CONTSCAN, MULTISCAN and STREAM commands.
    """
    try:
        return scan_response.match(msg).group("path", "virus", "status")
    except AttributeError:
        raise ResponseError(msg.rsplit("ERROR", 1)[0])


def _check_arg_is_safe(command: str, arg: str) -> None:
    """
    clamd's protocol is newline-terminated; an embedded newline or carriage
    return in a command argument (e.g. a caller-supplied file path) would
    otherwise inject an additional line into the same session.
    """
    if "\n" in arg or "\r" in arg:
        raise ValueError(
            f"Argument to {command} must not contain newline characters: {arg!r}"
        )


class _AsyncClamdNetworkSocket:
    """This class is a context manager helper to make Clamd calls.

    The socket can be used for only one call,
    so it has to be closed and a new one opened for all requests.
    Use it like this:

    .. code-block::

        async with _AsyncClamdNetworkSocket(host, port) as socket:
            socket.basic_command("PING")

    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3310,
    ):
        """Initialize the _AsyncClamdNetworkSocket

        host (string) : hostname or ip address
        port (int) : TCP port
        """

        self.host = host
        self.port = port

        self.reader: Union[asyncio.StreamReader, None] = None
        self.writer: Union[asyncio.StreamWriter, None] = None

    async def __aenter__(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port
            )
        except Exception as e:
            raise ClamdConnectionError(
                f"Error connecting to {self.host}:{self.port}"
            ) from e
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception as e:  # noqa
            pass

    async def basic_command(self, command):
        """
        Send a command to the clamav server, and return the reply.
        """
        await self.send_command(command)
        response = (await self.recv_response()).rsplit("ERROR", 1)
        if len(response) > 1:
            raise ResponseError(response[0])
        else:
            return response[0]

    async def send_command(self, cmd, *args):
        """
        `man clamd` recommends to prefix commands with z, but we will use \n
        terminated strings, as python<->clamd has some problems with \0x00
        """
        cmd_to_send = f"n{cmd}{' ' + ' '.join(args) if args else ''}\n".encode("utf-8")
        self.writer.write(cmd_to_send)
        await self.writer.drain()

    async def recv_response(self) -> str:
        """Receive data from clamd, bounded to _MAX_RESPONSE_SIZE bytes."""
        try:
            chunks = []
            total = 0
            while True:
                chunk = await self.reader.read(4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_RESPONSE_SIZE:
                    raise ResponseError(
                        f"Response from {self.host}:{self.port} exceeded the "
                        f"maximum accepted size of {_MAX_RESPONSE_SIZE} bytes"
                    )
                chunks.append(chunk)
            return b"".join(chunks).decode("utf-8").strip()
        except ResponseError:
            raise
        except Exception as e:
            raise ClamdConnectionError("Error while reading from socket") from e


class ClamdAsyncClient:
    """
    Class for using clamd through a network socket.
    """

    def __init__(
        self, host: str = "127.0.0.1", port: int = 3310, timeout: float = None
    ):
        """Initialize the AsyncClamdNetworkSocket

        host (string) : hostname or ip address
        port (int) : TCP port
        timeout (float or None) : overall timeout in seconds for each call
            (covers connecting, sending and receiving). Raises
            ConnectionTimeoutError if exceeded. None (default) means no
            timeout is enforced.
        """

        self.host = host
        self.port = port
        self.timeout = timeout

    async def _run(self, coro):
        """Await `coro`, applying self.timeout if one is configured."""
        if self.timeout is None:
            return await coro
        try:
            return await asyncio.wait_for(coro, timeout=self.timeout)
        except asyncio.TimeoutError as e:
            raise ConnectionTimeoutError(
                f"Timed out after {self.timeout}s communicating with "
                f"{self.host}:{self.port}"
            ) from e

    async def instream(
        self, buffer: BinaryIO, max_size: Optional[int] = None
    ) -> dict:
        """Scan a buffer

        buff (filelikeobj): buffer to scan
        max_size (int or None): if set, raise BufferTooLongError once more
            than this many bytes have been read from `buffer`, instead of
            relying solely on clamd's own StreamMaxLength enforcement.

        return:
          - (dict): ``{filename1: ("virusname", "status")}``

        May raise :
          - BufferTooLongError: if the buffer size exceeds clamd limits or
            the given max_size
          - ConnectionError: in case of communication problem
          - ConnectionTimeoutError: if the call exceeds self.timeout

        """

        async def _call():
            async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
                await socket.send_command("INSTREAM")

                # MUST be < StreamMaxLength in /etc/clamav/clamd.conf
                chunk_size = 1024
                sent = 0
                chunk = await asyncio.to_thread(buffer.read, chunk_size)
                while chunk:
                    sent += len(chunk)
                    if max_size is not None and sent > max_size:
                        raise BufferTooLongError(
                            f"Buffer exceeded the client-side max_size of "
                            f"{max_size} bytes"
                        )
                    size = struct.pack(b"!L", len(chunk))
                    socket.writer.write(size + chunk)
                    await socket.writer.drain()
                    chunk = await asyncio.to_thread(buffer.read, chunk_size)

                socket.writer.write(struct.pack(b"!L", 0))
                await socket.writer.drain()

                result = await socket.recv_response()

                if len(result) > 0:
                    if result == "INSTREAM size limit exceeded. ERROR":
                        raise BufferTooLongError(result)

                    filename, reason, status = _parse_response(result)
                    return {filename: (status, reason)}

        return await self._run(_call())

    async def _file_system_scan(self, command, file):
        """Scan a file or directory given by filename using multiple threads
        (faster on SMP machines). Do not stop on error or virus found.
        Scan with archive support enabled.

        file (string): filename or directory (MUST BE ABSOLUTE PATH !)

        return:
          - (dict): {filename1: ('FOUND', 'virusname'),
                     filename2: ('ERROR', 'reason')}

        """
        _check_arg_is_safe(command, file)

        async def _call():
            async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
                await socket.send_command(command, file)
                dr = {}
                response = await socket.recv_response()
                for result in response.split("\n"):
                    if result:
                        filename, reason, status = _parse_response(result)
                        dr[filename] = (status, reason)

                return dr

        return await self._run(_call())

    # Convenience methods

    async def ping(self):
        async def _call():
            async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
                return await socket.basic_command("PING")

        return await self._run(_call())

    async def version(self):
        async def _call():
            async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
                return await socket.basic_command("VERSION")

        return await self._run(_call())

    async def reload(self):
        async def _call():
            async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
                return await socket.basic_command("RELOAD")

        return await self._run(_call())

    async def shutdown(self):
        """Force Clamd to shutdown and exit"""

        async def _call():
            async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
                return await socket.basic_command("SHUTDOWN")

        return await self._run(_call())

    async def scan(self, file):
        return await self._file_system_scan("SCAN", file)

    async def contscan(self, file):
        return await self._file_system_scan("CONTSCAN", file)

    async def multiscan(self, file):
        return await self._file_system_scan("MULTISCAN", file)
