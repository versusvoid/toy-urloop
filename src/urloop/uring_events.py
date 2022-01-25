import collections
import errno
import functools
import socket
import warnings
import weakref
import logging
import select
import fcntl
import os
import ssl

from asyncio import base_events
from asyncio import constants
from asyncio import events
from asyncio import futures
from asyncio import protocols
from asyncio import sslproto
from asyncio import transports
from asyncio import trsock

from . import io_uring


__all__ = 'URingEventLoop', 'URingEventLoopPolicy'

logger = logging.getLogger(__name__)

with open('/proc/sys/fs/pipe-max-size') as f:
    _PIPE_MAX_SIZE = int(f.read())


def _check_ssl_socket(sock):
    if isinstance(sock, ssl.SSLSocket):
        raise TypeError('Socket cannot be of type SSLSocket')


def _make_os_error(result: int) -> OSError:
    assert result < 0, result
    return OSError(-result, os.strerror(-result))


class URingEventLoop(base_events.BaseEventLoop):
    ''' io_uring event loop '''

    _selector: io_uring.IOURing
    _self_pipe_read_end: int
    _self_pipe_write_end: int

    def __init__(self):
        super().__init__()

        '''
        NOTE: it's better create io_uring in disabled state (IORING_SETUP_R_DISABLED)
        and enable it in run_forever()
        '''
        self._selector = io_uring.IOURing()
        self._transports = weakref.WeakValueDictionary()
        self._io_callbacks = {}
        self._make_self_pipe()

    def _make_socket_transport(self, sock, protocol, waiter=None, *, extra=None, server=None):
        return _URingSocketTransport(self, sock, protocol, waiter, extra, server)

    def _make_ssl_transport(
        self,
        rawsock,
        protocol,
        sslcontext,
        waiter=None,
        *,
        server_side=False,
        server_hostname=None,
        extra=None,
        server=None,
        ssl_handshake_timeout=constants.SSL_HANDSHAKE_TIMEOUT,
    ):
        ssl_protocol = sslproto.SSLProtocol(
            self,
            protocol,
            sslcontext,
            waiter,
            server_side,
            server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout,
        )
        _URingSocketTransport(self, rawsock, ssl_protocol, extra=extra, server=server)
        return ssl_protocol._app_transport

    def close(self):
        if self.is_running():
            raise RuntimeError('Cannot close a running event loop')
        if self.is_closed():
            return
        super().close()
        self._selector.close_ring()
        self._selector = None
        self._close_self_pipe()
        self._io_callbacks.clear()

    def _close_self_pipe(self):
        os.close(self._self_pipe_read_end)
        self._self_pipe_read_end = None
        os.close(self._self_pipe_write_end)
        self._self_pipe_write_end = None

    def _make_self_pipe(self):
        self._self_pipe_read_end, self._self_pipe_write_end = os.pipe2(os.O_NONBLOCK)
        buf = bytearray(16)
        self._read(self._self_pipe_read_end, buf, self._on_read_from_self, buf)

    def _on_read_from_self(self, buf, result):
        self._read(self._self_pipe_read_end, buf, self._on_read_from_self, buf)
        assert result > 0, result

    def _write_to_self(self):
        write_end = self._self_pipe_write_end
        if write_end is None:
            return

        try:
            os.write(write_end, b'\0')
        except OSError:
            if self._debug:
                logger.debug('Fail to write a null byte into the self-pipe', exc_info=True)

    def _start_serving(self, protocol_factory, sock, *args):
        sock.setblocking(False)
        self._poll_add(
            sock,
            select.POLLIN,
            self._on_accept_avaiable,
            protocol_factory,
            sock,
            *args,
        )

    def _on_accept_avaiable(self, protocol_factory, sock, sslcontext, server, backlog, ssl_handshake_timeout, result):
        try:
            assert result >= 0, result

            for _ in range(backlog):
                conn, addr = sock.accept()
                if self._debug:
                    logger.debug('%r got a new connection from %r: %r', server, addr, conn)
                accept = self._process_accepted_connection(
                    conn,
                    addr,
                    protocol_factory,
                    sslcontext,
                    server,
                    ssl_handshake_timeout,
                )
                self.create_task(accept)
        except (BlockingIOError, InterruptedError, ConnectionAbortedError):
            # Early exit because the socket accept buffer is empty.
            pass
        finally:
            self._start_serving(protocol_factory, sock, sslcontext, server, backlog, ssl_handshake_timeout)

    async def _process_accepted_connection(self, conn, addr, protocol_factory, sslcontext, server, ssl_handshake_timeout):
        extra = {'peername': addr}
        protocol = None
        transport = None
        try:
            protocol = protocol_factory()
            waiter = self.create_future()
            if sslcontext:
                transport = self._make_ssl_transport(
                    conn,
                    protocol,
                    sslcontext,
                    waiter=waiter,
                    server_side=True,
                    extra=extra,
                    server=server,
                    ssl_handshake_timeout=ssl_handshake_timeout,
                )
            else:
                transport = self._make_socket_transport(conn, protocol, waiter=waiter, extra=extra, server=server)

            try:
                await waiter
            except BaseException:
                transport.close()
                raise
                # It's now up to the protocol to handle the connection.
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            if self._debug:
                context = {
                    'message': 'Error on transport creation for incoming connection',
                    'exception': exc,
                }
                if protocol is not None:
                    context['protocol'] = protocol
                if transport is not None:
                    context['transport'] = transport
                self.call_exception_handler(context)

    def _ensure_fd_no_transport(self, fileobj):
        fd = fileobj
        if not isinstance(fd, int):
            fd = fileobj.fileno()

        try:
            transport = self._transports[fd]
        except KeyError:
            pass
        else:
            if not transport.is_closing():
                raise RuntimeError(f'File descriptor {fd!r} is used by transport {transport!r}')

    async def sock_connect(self, sock, address):
        _check_ssl_socket(sock)
        if sock.family != socket.AF_UNIX:
            resolved = await self._ensure_resolved(address, family=sock.family, proto=sock.proto, loop=self)
            _, _, _, _, address = resolved[0]

        return await self._simple_request(self._selector.connect, sock, address)

    async def sock_accept(self, sock):
        _check_ssl_socket(sock)
        fut = self.create_future()
        self._accept(sock, self._on_accept, fut)
        return await fut

    def _on_accept(self, fut, result, addr):
        if fut.done():
            return

        if result < 0:
            fut.set_exception(_make_os_error(-result))
        else:
            fut.set_result((socket.socket(fileno=result), addr))

    async def _sendfile_native(self, transp, file, offset, count):
        del self._transports[transp._sock_fd]
        resume_reading = transp.is_reading()
        transp.pause_reading()
        await transp._make_empty_waiter()
        try:
            return await self.sock_sendfile(transp._sock, file, offset, count, fallback=False)
        finally:
            transp._reset_empty_waiter()
            if resume_reading:
                transp.resume_reading()
            self._transports[transp._sock_fd] = transp

    async def _sock_sendfile_native(self, sock, file, offset, count):
        '''
        sendfile implemented as two linked splices:
        1) file -> pipe
        2) pipe -> sock

        NOTE: base_events.BaseEventLoop with debug enabled checks `sock` to be non-blocking
        and will fail as we don't make it non-blocking after accept()
        '''
        read_end, write_end = os.pipe()
        fcntl.fcntl(write_end, fcntl.F_SETPIPE_SZ, _PIPE_MAX_SIZE)

        fut = self.create_future()
        self._make_sendfile_requests(sock, file, offset, count, 0, read_end, write_end, fut)

        return await fut

    def _make_sendfile_requests(self, sock, file, offset, count, total_sent, read_end, write_end, fut):
        if count is None:
            length = 2**31
        else:
            '''
            `count` may be larger than 2**32 (4GiB),
            clamping transfer length to 2**31 in such cases
            '''
            length = min(count, 2**31)

        args = sock, file, offset, count, total_sent, read_end, write_end, fut

        self._request(
            self._selector.splice,
            (file, offset, write_end, None, length, 0, True),
            self._on_sendfile_splice_file2pipe,
            args,
        )
        '''
        NOTE: It would be a fatal error if we ran out of SQE at this point.
        Correct implementation must provide API to allocate all the SQEs in chain simultaneously
        '''
        self._request(
            self._selector.splice,
            (read_end, None, sock, None, length, 0),
            self._on_sendfile_splice_pipe2sock,
            args,
        )

    def _on_sendfile_splice_file2pipe(
        self,
        sock,
        file,
        offset: int,
        count: int | None,
        total_sent: int,
        read_end: int,
        write_end: int,
        fut,
        result: int,
    ):
        if result < 0:
            self._finish_sendfile(fut, result, file, offset, total_sent, read_end, write_end)
            return

        if result == 0:
            ''' EOF reading from file, closing pipe write-end to unblock pipe2sock splice '''
            self._close(write_end, None)

    def _on_sendfile_splice_pipe2sock(
        self,
        sock,
        file,
        offset: int,
        count: int | None,
        total_sent: int,
        read_end: int,
        write_end: int,
        fut,
        result: int,
    ):
        if result == -errno.ECANCELED:
            ''' error in file2pipe splice, it will be reported from _on_sendfile_splice_file2pipe '''
            return

        if result > 0:
            offset += result
            total_sent += result
            if count is not None:
                count -= result

        if fut.done():
            return self._finish_sendfile(fut, result, file, offset, total_sent, read_end, write_end)

        if result < 0:
            return self._finish_sendfile(fut, result, file, offset, total_sent, read_end, write_end)

        if result == 0:
            ''' write_end already closed from _on_sendfile_splice_file2pipe '''
            return self._finish_sendfile(fut, result, file, offset, total_sent, read_end, None)

        if count is not None and count <= 0:
            return self._finish_sendfile(fut, result, file, offset, total_sent, read_end, write_end)

        self._make_sendfile_requests(sock, file, offset, count, total_sent, read_end, write_end, fut)

    def _finish_sendfile(self, fut, result, file, offset, total_sent, read_end, write_end):
        if not fut.done():
            if result < 0:
                fut.set_exception(_make_os_error(result))
            else:
                fut.set_result(total_sent)

        if total_sent > 0:
            os.lseek(file.fileno(), offset, os.SEEK_SET)

        self._close(read_end, None)
        if write_end:
            self._close(write_end, None)

    def _process_events(self, event_list):
        for key, args in event_list:
            callback = self._io_callbacks.pop(key, None)
            if callback:
                self._call_soon(callback, args, None)

    def _stop_serving(self, sock):
        self._poll_remove(sock, self._on_serving_removed, sock)

    def _on_serving_removed(self, sock, result):
        self._close(sock, None)

    # ================== io_uring specific api ==================

    def _request(self, uring_method, args: tuple, callback, callback_args) -> int:
        key = uring_method(*args)

        if callback:
            callback = functools.partial(callback, *callback_args)
            self._io_callbacks[key] = callback

        return key

    def _read(self, fileobj, buf: bytearray, callback, *args) -> int:
        return self._request(self._selector.read, (fileobj, buf), callback, args)

    def _recv(self, sock: socket.socket, buf: bytearray, flags: int, callback, *args) -> int:
        return self._request(self._selector.recv, (sock, buf, flags), callback, args)

    def _send(self, sock: socket.socket, buf, flags: int, callback, *args) -> int:
        return self._request(self._selector.send, (sock, buf, flags), callback, args)

    def _accept(self, sock: socket.socket, callback, *args) -> int:
        return self._request(self._selector.accept, (sock,), callback, args)

    def _poll_add(self, fileobj, events: int, callback, *args) -> int:
        return self._request(self._selector.poll_add, (fileobj, events), callback, args)

    def _poll_remove(self, fileobj, callback, *args) -> int:
        return self._request(self._selector.poll_remove, (fileobj,), callback, args)

    def _cancel(self, key: int, callback, *args) -> int:
        return self._request(self._selector.cancel, (key,), callback, args)

    def _close(self, fileobj, callback, *args) -> int:
        if isinstance(fileobj, socket.socket):
            fileobj = fileobj.detach()

        return self._request(self._selector.close, (fileobj,), callback, args)

    def _shutdown(self, fileobj, how: int, callback, *args) -> int:
        return self._request(self._selector.close, (fileobj, how), callback, args)

    async def _simple_request(self, uring_method, *args) -> int:
        fut = self.create_future()
        self._request(uring_method, args, self._on_simple_result, (fut,))
        return await fut

    def _on_simple_result(self, fut, result):
        if fut.done():
            return

        if result < 0:
            fut.set_exception(_make_os_error(result))
        else:
            fut.set_result(result)

    async def openat(self, dirfd: int | None, path: str, flags: int, mode: int = 644) -> int:
        return await self._simple_request(self._selector.openat, dirfd, path, flags, mode)

    async def read(self, fileobj, buf: bytearray) -> int:
        return await self._simple_request(self._selector.read, fileobj, buf)

    async def close_file(self, fileobj) -> int:
        return await self._simple_request(self._selector.close, fileobj)


''' Transports are mostly copy from asyncio.selector_events '''
class _URingTransport(transports._FlowControlMixin, transports.Transport):

    max_size = 256 * 1024  # Buffer size passed to recv().

    _buffer_factory = bytearray  # Constructs initial value for self._buffer.

    # Attribute used in the destructor: it must be set even if the constructor
    # is not called (see _URingSslTransport which may start by raising an
    # exception)
    _sock = None

    _extra: dict[str, object]
    _loop: URingEventLoop
    _protocol: protocols.BaseProtocol

    def __init__(self, loop: URingEventLoop, sock: socket.socket, protocol, extra=None, server=None):
        super().__init__(extra, loop)

        self._extra['socket'] = trsock.TransportSocket(sock)
        try:
            self._extra['sockname'] = sock.getsockname()
        except OSError:
            self._extra['sockname'] = None
        if 'peername' not in self._extra:
            try:
                self._extra['peername'] = sock.getpeername()
            except socket.error:
                self._extra['peername'] = None

        self._sock = sock
        self._sock_fd = sock.fileno()
        self._recv_key = None
        self._recv_buffer = None
        self._send_key = None
        self._send_queue = collections.deque()

        self.set_protocol(protocol)

        self._server = server
        self._conn_lost = 0  # Set when call to connection_lost scheduled.
        self._closing = False  # Set when close() called.
        if self._server is not None:
            self._server._attach()
        loop._transports[self._sock_fd] = self

    def set_protocol(self, protocol):
        self._protocol = protocol
        self._protocol_connected = True

    def get_protocol(self):
        return self._protocol

    def is_closing(self):
        return self._closing

    def close(self):
        if self._closing:
            return

        self._closing = True
        self._cancel_recv()
        if not self._send_queue:
            self._conn_lost += 1
            self._cancel_send()
            self._loop.call_soon(self._call_connection_lost, None)

    def _cancel_recv(self):
        if self._recv_key is not None:
            self._loop._cancel(self._recv_key, None)
            self._recv_key = None

    def _cancel_send(self):
        if self._send_key is not None:
            self._loop._cancel(self._send_key, None)
            self._send_key = None

    def __del__(self, _warn=warnings.warn):
        if self._sock is not None:
            _warn(f'unclosed transport {self!r}', ResourceWarning, source=self)
            self._sock.close()

    def abort(self):
        self._force_close(None)

    def _fatal_error(self, exc, message='Fatal error on transport'):
        # Should be called from exception handler only.
        if isinstance(exc, OSError):
            if self._loop.get_debug():
                logger.debug('%r: %s', self, message, exc_info=True)
        else:
            self._loop.call_exception_handler({
                'message': message,
                'exception': exc,
                'transport': self,
                'protocol': self._protocol,
            })
        self._force_close(exc)

    def _force_close(self, exc):
        if self._conn_lost:
            return

        self._cancel_send()
        self._send_queue.clear()

        if not self._closing:
            self._closing = True
            self._cancel_recv()

        self._conn_lost += 1
        self._loop.call_soon(self._call_connection_lost, exc)

    def _call_connection_lost(self, exc):
        try:
            if self._protocol_connected:
                self._protocol.connection_lost(exc)
        finally:
            # TODO close through io_uring
            self._loop._close(self._sock, None)
            self._sock = None
            self._protocol = None
            self._loop = None
            server = self._server
            if server is not None:
                server._detach()
                self._server = None

    def get_write_buffer_size(self):
        return sum(len(buf) for buf in self._send_queue)

    def _recv(self):
        if self._closing:
            return

        '''
        NOTE: it's extremely inefficient to keep read buffer for every connection
        The better way is to provide limited number of buffers to io_uring
        and set IOSQE_BUFFER_SELECT flag on recv
        '''
        if self._recv_buffer is None:
            self._recv_buffer = self._buffer_factory(self.max_size)

        self._recv_key = self._loop._recv(self._sock, self._recv_buffer, 0, self._on_recv)

    def _on_recv(self, result):
        self._recv_key = None


class _URingSocketTransport(_URingTransport):

    _start_tls_compatible = True
    _sendfile_compatible = constants._SendfileMode.TRY_NATIVE

    def __init__(self, loop, sock, protocol, waiter=None, extra=None, server=None):
        self._on_recv_cb = None
        super().__init__(loop, sock, protocol, extra, server)
        self._eof = False
        self._paused = False
        self._empty_waiter = None

        # Disable the Nagle algorithm -- small writes will be
        # sent without waiting for the TCP ACK.  This generally
        # decreases the latency (in some cases significantly.)
        base_events._set_nodelay(self._sock)

        self._loop.call_soon(self._protocol.connection_made, self)
        # only start recving when connection_made() has been called
        self._loop.call_soon(self._recv)
        if waiter is not None:
            # only wake up the waiter when connection_made() has been called
            self._loop.call_soon(futures._set_result_unless_cancelled, waiter, None)

    def set_protocol(self, protocol):
        if isinstance(protocol, protocols.BufferedProtocol):
            self._on_recv_cb = self._on_recv__get_buffer
        else:
            self._on_recv_cb = self._on_recv__data_received

        super().set_protocol(protocol)

    def is_reading(self):
        return not self._paused and not self._closing

    def pause_reading(self):
        if self._closing or self._paused:
            return
        self._paused = True
        self._cancel_recv()
        if self._loop.get_debug():
            logger.debug('%r pauses reading', self)

    def resume_reading(self):
        if self._closing or not self._paused:
            return
        self._paused = False
        self._recv()
        if self._loop.get_debug():
            logger.debug('%r resumes reading', self)

    def _on_recv(self, result):
        super()._on_recv(result)

        if self._conn_lost:
            return

        if result == -errno.ECANCELED:
            return

        if result < 0:
            self._fatal_error(_make_os_error(result), 'Fatal read error on socket transport')
            return

        if result == 0:
            self._on_recv__on_eof()
            return

        try:
            self._on_recv_cb(result)
        finally:
            self._recv()

    def _on_recv__get_buffer(self, result):
        try:
            buf = self._protocol.get_buffer(result)
            if not len(buf):
                raise RuntimeError('get_buffer() returned an empty buffer')
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._fatal_error(exc, 'Fatal error: protocol.get_buffer() call failed.')
            return

        buf[0:result] = self._recv_buffer[0:result]

        try:
            self._protocol.buffer_updated(result)
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._fatal_error(exc, 'Fatal error: protocol.buffer_updated() call failed.')

    def _on_recv__data_received(self, result):
        try:
            self._protocol.data_received(self._recv_buffer[:result])
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._fatal_error(exc, 'Fatal error: protocol.data_received() call failed.')

    def _on_recv__on_eof(self):
        if self._loop.get_debug():
            logger.debug('%r received EOF', self)

        try:
            keep_open = self._protocol.eof_received()
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._fatal_error(exc, 'Fatal error: protocol.eof_received() call failed.')
            return

        if not keep_open:
            self.close()

    def write(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f'data argument must be a bytes-like object, not {type(data).__name__!r}')
        if self._eof:
            raise RuntimeError('Cannot call write() after write_eof()')
        if self._empty_waiter is not None:
            raise RuntimeError('unable to write; sendfile is in progress')
        if not data:
            return

        if self._conn_lost:
            if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                logger.warning('socket.send() raised exception.')
            self._conn_lost += 1
            return

        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)

        '''
        NOTE: also inefficient to copy and send every write() separately
        '''
        sending = bool(self._send_queue)
        self._send_queue.append(data)
        if not sending:
            self._send_key = self._loop._send(self._sock, data, 0, self._on_send, data)

        self._maybe_pause_protocol()

    def _on_send(self, buffer, result):
        self._send_key = None
        if self._conn_lost:
            return

        if result == -errno.ECANCELED:
            return

        if result < 0:
            exc = _make_os_error(result)
            self._fatal_error(exc, 'Fatal write error on socket transport')
            if self._empty_waiter is not None:
                self._empty_waiter.set_exception(exc)

            return

        from_queue = self._send_queue.popleft()
        assert from_queue is buffer
        next_buffer = None
        if result < len(buffer):
            next_buffer = buffer[result:]
            self._send_queue.appendleft(next_buffer)
        elif self._send_queue:
            next_buffer = next(iter(self._send_queue))

        self._maybe_resume_protocol()
        if next_buffer:
            self._send_key = self._loop._send(self._sock, next_buffer, 0, self._on_send, next_buffer)
            return

        if self._empty_waiter is not None:
            self._empty_waiter.set_result(None)
        if self._closing:
            self._call_connection_lost(None)
        elif self._eof:
            self._loop._shutdown(self._sock, socket.SHUT_WR, None)

    def write_eof(self):
        if self._closing or self._eof:
            return

        self._eof = True
        if not self._send_queue:
            self._loop._shutdown(self._sock, socket.SHUT_WR, None)

    def can_write_eof(self):
        return True

    def _call_connection_lost(self, exc):
        super()._call_connection_lost(exc)
        if self._empty_waiter is not None:
            self._empty_waiter.set_exception(ConnectionError('Connection is closed by peer'))

    def _make_empty_waiter(self):
        if self._empty_waiter is not None:
            raise RuntimeError('Empty waiter is already set')

        self._empty_waiter = self._loop.create_future()
        if not self._send_queue:
            self._empty_waiter.set_result(None)

        return self._empty_waiter

    def _reset_empty_waiter(self):
        self._empty_waiter = None


class URingEventLoopPolicy(events.BaseDefaultEventLoopPolicy):
    _loop_factory = URingEventLoop

