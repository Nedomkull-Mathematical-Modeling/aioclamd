# aioclamd

This package is an asynchronous version of the pleasant package 
[`python-clamd`](https://github.com/graingert/python-clamd). It has the same external
API, only all methods are coroutines and all communication is handled 
asynchronously using the ``asyncio`` framework.

The `ClamdAsyncClient` connects to a [ClamAV](https://www.clamav.net/) antivirus instance and scans
files and data for malicious threats. This package does not bundle ClamAV in any way,
so a running instance of the `clamd` deamon is required.

## Installation

```
pip install aioclamd
```

## Usage

To scan a file (on the system where ClamAV is installed):

```python
import asyncio

from aioclamd import ClamdAsyncClient

async def main(host, port):
    clamd = ClamdAsyncClient(host, port)
    print(await clamd.scan('/etc/clamav/clamd.conf'))

asyncio.run(main("127.0.0.1", 3310))

# Output:
# {'/etc/clamav/clamd.conf': ('OK', None)}
```

To scan a data stream:

```python
import asyncio
import base64
from io import BytesIO

from aioclamd import ClamdAsyncClient

EICAR = BytesIO(
    base64.b64decode(
        b"WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNU"
        b"QU5EQVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n"
    )
)

async def main(host, port):
    clamd = ClamdAsyncClient(host, port)
    print(await clamd.instream(EICAR))

asyncio.run(main("127.0.0.1", 3310))

# Output:
# {'stream': ('FOUND', 'Win.Test.EICAR_HDB-1')}
```

## Development

This repo ships a `Dockerfile` that bundles a `clamd` instance together with
this package itself, for local development and integration testing:

```powershell
docker build -t aioclamd-dev .
docker run --rm -p 127.0.0.1:3310:3310 aioclamd-dev
```

**Only ever publish the port to loopback (`127.0.0.1:3310:3310`), never to
`0.0.0.0` or a public interface.** clamd's TCP protocol is unauthenticated
and unencrypted by design (this is documented upstream ClamAV behavior, not
specific to this image) -- treat it as safe only on loopback or within a
fully trusted internal network, never across an untrusted network.

Alternatively, if you just want a bare `clamd` without the packaged client,
the official upstream image works standalone:

```powershell
docker run -p 3310:3310 --rm clamav/clamav
```
