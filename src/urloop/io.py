import asyncio
import functools
import os
import locale
import codecs
import collections
import collections.abc
import resource


async def open(file: str, mode='r', encoding=None, errors=None):
    if 'b' in mode:
        raise NotImplementedError

    flags = _open_flags_from_mode(mode)
    loop = asyncio.get_running_loop()
    fd = await loop.openat(None, file, flags)
    return AsyncTextIO(fd, encoding, errors)


def _open_flags_from_mode(mode: str) -> int:
    readable = False
    writable = False
    flags = 0
    if 'x' in mode:
        flags |= os.O_EXCL | os.O_CREAT
    elif 'r' in mode:
        readable = True
    elif 'w' in mode:
        writable = True
        flags |= os.O_CREAT | os.O_TRUNC
    elif 'a' in mode:
        writable = True
        flags |= os.O_APPEND | os.O_CREAT
    elif '+' in mode:
        writable = True
        readable = True

    if writable and readable:
        flags |= os.O_RDWR
    elif writable:
        flags |= os.O_WRONLY
    else:
        assert readable
        flags |= os.O_RDONLY

    return flags


class AsyncTextIO:
    _leftover_chunk: str | None

    def __init__(self, fd: int, encoding=None, errors=None):
        self._fd = fd

        encoding = encoding or locale.getpreferredencoding(False)
        codec_info = codecs.lookup(encoding)

        errors = errors or 'strict'
        self._decoder = codec_info.incrementaldecoder(errors)

        self._buffer = bytearray(resource.getpagesize())
        self._leftover_chunk = None
        self._eof = False

    def fileno(self) -> int:
        return self._fd

    async def read(self, size: int = -1) -> str:
        if size < 0:
            return await self._read(lambda chunks: False)

        return await self._read(functools.partial(self._size_predicate, size))

    async def _read(self, predicate) -> str:
        '''
        reads data from file until `predicate` is satisfied

        `predicate` is responsible for splitting unused data in last chunk
        and saving it to self._leftover_chunk
        '''
        chunks = []
        finished = False

        if self._leftover_chunk:
            chunks.append(self._leftover_chunk)
            self._leftover_chunk = None
            finished = predicate(chunks)

        loop = asyncio.get_running_loop()
        while not finished:
            num_bytes = await loop.read(self, self._buffer)
            part = memoryview(self._buffer)[:num_bytes]
            chunk = self._decoder.decode(part, num_bytes == 0)

            if num_bytes == 0 and not chunks and not chunk:
                self._eof = True
                return ''

            chunks.append(chunk)
            finished = predicate(chunks)
            if num_bytes == 0:
                break

        return ''.join(chunks)

    def _size_predicate(self, size: int, chunks: list[str]) -> bool:
        ready_length = sum(len(c) for c in chunks)

        if ready_length > size:
            diff = ready_length - size
            last_chunk_new_length = len(chunks[-1]) - diff
            self._leftover_chunk = chunks[-1][last_chunk_new_length:]
            chunks[-1] = chunks[-1][:last_chunk_new_length]
            ready_length = size

        return ready_length == size

    def _line_predicate(self, chunks: list[str]) -> bool:
        i = chunks[-1].find('\n')
        if i == -1:
            return False

        if i + 1 < len(chunks[-1]):
            self._leftover_chunk = chunks[-1][i + 1:]
        chunks[-1] = chunks[-1][:i + 1]

        return True

    async def readline(self) -> str:
        return await self._read(self._line_predicate)

    def __aiter__(self):
        return self

    def readlines(self) -> collections.abc.AsyncIterable[str]:
        return self

    async def __anext__(self) -> str:
        if self._eof:
            raise StopAsyncIteration
        return await self.readline()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        try:
            await self.close()
        except:
            pass

    async def close(self):
        loop = asyncio.get_running_loop()
        await loop.close_file(self)
