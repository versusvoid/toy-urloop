# Toy urloop

Minimal (inefficient) implementation of
[asyncio event loop](https://docs.python.org/3/library/asyncio-eventloop.html#asyncio-event-loop)
using Linux [io_uring API](https://unixism.net/loti/what_is_io_uring.html).
Adds basic support for asynchronous file I/O (open, read, close).
