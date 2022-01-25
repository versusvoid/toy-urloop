import ctypes
import enum
import resource
import os
import mmap
import time
import io
import errno
import socket
import struct
import collections
import collections.abc


libc = ctypes.CDLL('libc.so.6', use_errno=True)
libc.syscall.restype = ctypes.c_long

u8 = ctypes.c_uint8
u16 = ctypes.c_uint16
s32 = ctypes.c_int32
u32 = ctypes.c_uint32
s64 = ctypes.c_int64
u64 = ctypes.c_uint64
uint = ctypes.c_uint
pVoid = ctypes.c_void_p
_kernel_rwf_t = ctypes.c_int
sa_family_t = ctypes.c_ushort


def _get_fd(fileobj) -> int:
    if isinstance(fileobj, int):
        return fileobj
    return fileobj.fileno()


def _make_sockaddr(sock: socket.socket | int, addr=None) -> ctypes.Structure:
    if isinstance(sock, int):
        sock = socket.socket(fileno=sock)

    if sock.family == socket.AF_INET:
        return _make_sockaddr_in(addr)

    raise NotImplementedError


class _SockaddrIN(ctypes.Structure):
    sin_family: int
    sin_port: int
    sin_addr: int

    _fields_ = [
        ('sin_family', sa_family_t),
        ('sin_port', u16),
        ('sin_addr', u32),
        ('__pad', u8 * (16 - ctypes.sizeof(sa_family_t) - ctypes.sizeof(u16) - ctypes.sizeof(u32))),
    ]


def _make_sockaddr_in(addr) -> _SockaddrIN:
    if addr is None:
        return _SockaddrIN()

    assert isinstance(addr, tuple) and len(addr) == 2
    host, port = addr
    sin_addr = struct.unpack('I', socket.inet_aton(host))[0]
    sin_port = socket.htons(port)

    return _SockaddrIN(socket.AF_INET, sin_port, sin_addr)


def _parse_sockaddr(sock: socket.socket | int, addr):
    if isinstance(sock, int):
        sock = socket.socket(fileno=sock)

    if sock.family == socket.AF_INET:
        return _parse_sockaddr_in(addr)

    raise NotImplementedError


def _parse_sockaddr_in(addr: _SockaddrIN) -> tuple[str, int]:
    address_bytes = struct.pack('I', addr.sin_addr)
    address = '.'.join(str(byte) for byte in address_bytes)
    port = socket.ntohs(addr.sin_port)

    return address, port


class _KernelTimespec(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_longlong),  # seconds
        ('tv_nsec', ctypes.c_longlong),  # nanoseconds
    ]

    @staticmethod
    def from_float(seconds: float):
        integer_seconds = int(seconds)
        ''' limiting precision to microseconds '''
        microseconds = int((seconds - integer_seconds) * 10**6)
        return _KernelTimespec(integer_seconds, microseconds * 10**3)


def _buffer_pointer(buffer: bytearray) -> pVoid:
    return pVoid(ctypes.addressof(u32.from_buffer(buffer)))


class _IOSQRingOffsets(ctypes.Structure):
    head: int
    tail: int
    ring_mask: int
    ring_entries: int
    array: int

    _fields_ = [
        ('head', u32),
        ('tail', u32),
        ('ring_mask', u32),
        ('ring_entries', u32),
        ('flags', u32),
        ('dropped', u32),
        ('array', u32),
        ('resv', u32 * 3),
    ]


class _IOCQRingOffsets(ctypes.Structure):
    head: int
    tail: int
    ring_mask: int
    ring_entries: int
    cqes: int

    _fields_ = [
        ('head', u32),
        ('tail', u32),
        ('ring_mask', u32),
        ('ring_entries', u32),
        ('overflow', u32),
        ('cqes', u32),
        ('flags', u32),
        ('resv', u32 * 3),
    ]


class _IOURingParams(ctypes.Structure):
    sq_entries: int
    cq_entries: int
    features: int
    sq_off: _IOSQRingOffsets
    cq_off: _IOCQRingOffsets

    _fields_ = [
        ('sq_entries', u32),
        ('cq_entries', u32),
        ('flags', u32),
        ('sq_thread_cpu', u32),
        ('sq_thread_idle', u32),
        ('features', u32),
        ('wq_fd', u32),
        ('resv', u32 * 3),
        ('sq_off', _IOSQRingOffsets),
        ('cq_off', _IOCQRingOffsets),
    ]


def _syscall(*args):
    result = libc.syscall(*args)
    if result == -1:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def _io_uring_setup(entries: u32, params: _IOURingParams):
    return _syscall(425, entries, ctypes.byref(params))


def _io_uring_register(fd: int, opcode: uint, arg: pVoid, nr_args: uint):
    return _syscall(426, uint(fd), opcode, arg, nr_args)


def _io_uring_enter(fd: int, to_submit: u32, min_complete: u32, flags: u32, argp, argz: ctypes.c_size_t):
    return _syscall(426, uint(fd), to_submit, min_complete, flags, argp, argz)


class Operations(enum.IntEnum):
    IORING_OP_NOP = 0
    IORING_OP_READV = 1
    IORING_OP_WRITEV = 2
    IORING_OP_FSYNC = 3
    IORING_OP_READ_FIXED = 4
    IORING_OP_WRITE_FIXED = 5
    IORING_OP_POLL_ADD = 6
    IORING_OP_POLL_REMOVE = 7
    IORING_OP_SYNC_FILE_RANGE = 8
    IORING_OP_SENDMSG = 9
    IORING_OP_RECVMSG = 10
    IORING_OP_TIMEOUT = 11
    IORING_OP_TIMEOUT_REMOVE = 12
    IORING_OP_ACCEPT = 13
    IORING_OP_ASYNC_CANCEL = 14
    IORING_OP_LINK_TIMEOUT = 15
    IORING_OP_CONNECT = 16
    IORING_OP_FALLOCATE = 17
    IORING_OP_OPENAT = 18
    IORING_OP_CLOSE = 19
    IORING_OP_FILES_UPDATE = 20
    IORING_OP_STATX = 21
    IORING_OP_READ = 22
    IORING_OP_WRITE = 23
    IORING_OP_FADVISE = 24
    IORING_OP_MADVISE = 25
    IORING_OP_SEND = 26
    IORING_OP_RECV = 27
    IORING_OP_OPENAT2 = 28
    IORING_OP_EPOLL_CTL = 29
    IORING_OP_SPLICE = 30
    IORING_OP_PROVIDE_BUFFERS = 31
    IORING_OP_REMOVE_BUFFERS = 32
    IORING_OP_TEE = 33
    IORING_OP_SHUTDOWN = 34
    IORING_OP_RENAMEAT = 35
    IORING_OP_UNLINKAT = 36
    IORING_OP_MKDIRAT = 37
    IORING_OP_SYMLINKAT = 38
    IORING_OP_LINKAT = 39


class RegisterOperations(enum.Enum):
    IORING_REGISTER_BUFFERS = 0
    IORING_UNREGISTER_BUFFERS = 1
    IORING_REGISTER_FILES = 2
    IORING_UNREGISTER_FILES = 3
    IORING_REGISTER_EVENTFD = 4
    IORING_UNREGISTER_EVENTFD = 5
    IORING_REGISTER_FILES_UPDATE = 6
    IORING_REGISTER_EVENTFD_ASYNC = 7
    IORING_REGISTER_PROBE = 8
    IORING_REGISTER_PERSONALITY = 9
    IORING_UNREGISTER_PERSONALITY = 10
    IORING_REGISTER_RESTRICTIONS = 11
    IORING_REGISTER_ENABLE_RINGS = 12

    # extended with tagging
    IORING_REGISTER_FILES2 = 13
    IORING_REGISTER_FILES_UPDATE2 = 14
    IORING_REGISTER_BUFFERS2 = 15
    IORING_REGISTER_BUFFERS_UPDATE = 16

    # set/clear io-wq thread affinities
    IORING_REGISTER_IOWQ_AFF = 17
    IORING_UNREGISTER_IOWQ_AFF = 18

    # set/get max number of io-wq workers
    IORING_REGISTER_IOWQ_MAX_WORKERS = 19


class Features(enum.IntFlag):
    IORING_FEAT_SINGLE_MMAP = (1 << 0)
    IORING_FEAT_NODROP = (1 << 1)
    IORING_FEAT_SUBMIT_STABLE = (1 << 2)
    IORING_FEAT_RW_CUR_POS = (1 << 3)
    IORING_FEAT_CUR_PERSONALITY = (1 << 4)
    IORING_FEAT_FAST_POLL = (1 << 5)
    IORING_FEAT_POLL_32BITS  = (1 << 6)
    IORING_FEAT_SQPOLL_NONFIXED = (1 << 7)
    IORING_FEAT_EXT_ARG = (1 << 8)
    IORING_FEAT_NATIVE_WORKERS = (1 << 9)
    IORING_FEAT_RSRC_TAGS = (1 << 10)


class _EnterFlags(enum.IntFlag):
    IORING_ENTER_GETEVENTS =(1 << 0)
    IORING_ENTER_SQ_WAKEUP =(1 << 1)
    IORING_ENTER_SQ_WAIT = (1 << 2)
    IORING_ENTER_EXT_ARG = (1 << 3)


class _Offsets(enum.IntEnum):
    IORING_OFF_SQ_RING = 0
    IORING_OFF_CQ_RING = 0x8000000
    IORING_OFF_SQES = 0x10000000


class _IOURingCQE(ctypes.Structure):
    _fields_ = [
        ('user_data', u64),
        ('res', s32),
        ('flags', u32),
    ]


class _SQEFlags(enum.IntFlag):
    # use fixed fileset
    IOSQE_FIXED_FILE = (1 << 1)
    # issue after inflight IO
    IOSQE_IO_DRAIN = (1 << 2)
    # links next sqe
    IOSQE_IO_LINK = (1 << 3)
    # like LINK, but stronger
    IOSQE_IO_HARDLINK = (1 << 4)
    # always go async
    IOSQE_ASYNC = (1 << 5)
    # select buffer from sqe->buf_group
    IOSQE_BUFFER_SELECT = (1 << 6)


class _SQEUnion1(ctypes.Union):
    _fields_ = [
        ('off', u64),  # offset into file
        ('addr2', u64),
    ]


class _SQEUnion2(ctypes.Union):
    _fields_ = [
        ('addr', u64),  # pointer to buffer or iovecs
        ('splice_off_in', u64),
    ]


class _SQEUnion3(ctypes.Union):
    _fields_ = [
        ('rw_flags', _kernel_rwf_t),
        ('fsync_flags', u32),
        ('poll_events', u16),  # compatibility
        ('poll32_events', u32),  # word-reversed for BE
        ('sync_range_flags', u32),
        ('msg_flags', u32),
        ('timeout_flags', u32),
        ('accept_flags', u32),
        ('cancel_flags', u32),
        ('open_flags', u32),
        ('statx_flags', u32),
        ('fadvise_advice', u32),
        ('splice_flags', u32),
        ('rename_flags', u32),
        ('unlink_flags', u32),
        ('hardlink_flags', u32),
    ]


class _SQEUnion4(ctypes.Union):
    _fields_ = [
        # index into fixed buffers, if used
        ('buf_index', u16),
        # for grouped buffer selection
        ('buf_group', u16),
    ]


assert ctypes.sizeof(_SQEUnion4) == ctypes.sizeof(u16)


class _SQEUnion5(ctypes.Union):
    _fields_ = [
        ('splice_fd_in', s32),
        ('file_index', u32),
    ]


class _IOURingSQE(ctypes.Structure):
    _anonymous_ = ('union1', 'union2', 'union3', 'union4', 'union5')

    _fields_ = [
        ('opcode', u8),  # type of operation for this sqe
        ('flags', u8),  # IOSQE_ flags
        ('ioprio', u16),  # ioprio for the request
        ('fd', s32),  # file descriptor to do IO on

        ('union1', _SQEUnion1),
        ('union2', _SQEUnion2),

        ('len', u32),  # buffer size or number of iovecs

        ('union3', _SQEUnion3),

        ('user_data', u64),  # data to be passed back at completion time

        ('union4', _SQEUnion4),

        ('personality', u16),  # personality to use, if used

        ('union5', _SQEUnion5),

        ('__pad2', u64 * 2),
    ]


class _IOURingGeteventsArgs(ctypes.Structure):
    _fields_ = [
        ('sigmask', u64),
        ('sigmask_sz', u32),
        ('pad', u32),
        ('ts', u64),
    ]

    @staticmethod
    def from_timespec(timespec: _KernelTimespec):
        return _IOURingGeteventsArgs(ts=ctypes.addressof(timespec))


class _SubmissionQueue:
    head: u32
    tail: u32
    ring_mask: u32
    ring_entries: u32
    flags: u32
    dropped: u32

    def __init__(self, ring_fd: int, params: _IOURingParams):
        self._mmap =  mmap.mmap(
            length=params.sq_off.array + params.sq_entries * ctypes.sizeof(u32),
            prot=(mmap.PROT_READ | mmap.PROT_WRITE),
            flags=(mmap.MAP_SHARED | mmap.MAP_POPULATE),
            fileno=ring_fd,
            offset=_Offsets.IORING_OFF_SQ_RING,
        )
        for key in self.__annotations__:
            setattr(self, key, u32.from_buffer(self._mmap, getattr(params.sq_off, key)))

        self.array = (u32 * params.sq_entries).from_buffer(self._mmap, params.sq_off.array)

    def close(self):
        for key in self.__annotations__:
            delattr(self, key)
        del self.array

        self._mmap.close()


class _CompletionQueue:
    head: u32
    tail: u32
    ring_mask: u32
    ring_entries: u32
    overflow: u32
    flags: u32

    def __init__(self, ring_fd: int, params: _IOURingParams):
        self._mmap =  mmap.mmap(
            length=params.cq_off.cqes + params.cq_entries * ctypes.sizeof(_IOURingCQE),
            prot=(mmap.PROT_READ | mmap.PROT_WRITE),
            flags=(mmap.MAP_SHARED | mmap.MAP_POPULATE),
            fileno=ring_fd,
            offset=_Offsets.IORING_OFF_CQ_RING,
        )
        for key in self.__annotations__:
            setattr(self, key, u32.from_buffer(self._mmap, getattr(params.cq_off, key)))

        self.cqes = (_IOURingCQE * params.cq_entries).from_buffer(self._mmap, params.cq_off.cqes)

    def close(self):
        for key in self.__annotations__:
            delattr(self, key)
        del self.cqes

        self._mmap.close()


class IOURing:
    _ring_fd: int
    _submission_queue: _SubmissionQueue
    _completion_queue: _CompletionQueue
    _submission_queue_entries_mmap: mmap.mmap

    def __init__(self, entries: int | None = None):
        if entries is None:
            entries = resource.getrlimit(resource.RLIMIT_NOFILE)[0]

        self._params = _IOURingParams()
        self._ring_fd = _io_uring_setup(u32(entries), self._params)
        assert self._params.features & Features.IORING_FEAT_EXT_ARG, 'no EXT_ARG'

        self._submission_queue = _SubmissionQueue(self._ring_fd, self._params)
        self._completion_queue = _CompletionQueue(self._ring_fd, self._params)

        self._submission_queue_entries_mmap = mmap.mmap(
            length=self._params.sq_entries * ctypes.sizeof(_IOURingSQE),
            prot=(mmap.PROT_READ | mmap.PROT_WRITE),
            flags=(mmap.MAP_SHARED | mmap.MAP_POPULATE),
            fileno=self._ring_fd,
            offset=_Offsets.IORING_OFF_SQES,
        )
        self._submission_queue_entries = (_IOURingSQE * self._params.sq_entries).from_buffer(
            self._submission_queue_entries_mmap,
        )

        self._sq_head = 0
        self._sq_tail = 0
        self._requests = {}
        self._next_key = 0

    def _get_sqe(self) -> _IOURingSQE:
        head = self._submission_queue.head.value
        num_entries = self._submission_queue.ring_entries.value
        mask = self._submission_queue.ring_mask.value

        if self._sq_tail - head >= num_entries:
            raise RuntimeError('sq overflow')

        result = self._submission_queue_entries[self._sq_tail & mask]
        self._sq_tail += 1
        return result

    def _flush_sq(self) -> int:
        num_entries = self._sq_tail - self._sq_head
        if num_entries == 0:
            return num_entries

        mask = self._submission_queue.ring_mask.value
        kernel_tail = self._submission_queue.tail.value

        while self._sq_head < self._sq_tail:
            self._submission_queue.array[kernel_tail & mask] = self._sq_head & mask
            kernel_tail += 1
            self._sq_head += 1

        self._submission_queue.tail.value = kernel_tail

        return num_entries

    def _get_cqes(self) -> dict[int, int]:
        head = self._completion_queue.head.value
        tail = self._completion_queue.tail.value
        mask = self._completion_queue.ring_mask.value

        result = {}
        for i in range(head, tail):
            entry = self._completion_queue.cqes[i & mask]
            result[entry.user_data] = entry.res

        self._completion_queue.head.value = tail
        return result

    def select(self, timeout: float | None):
        num_entries = self._flush_sq()
        if timeout is None:
            ''' waiting indefinitely '''
            result = _io_uring_enter(
                self._ring_fd,
                u32(num_entries),
                min_complete=u32(1),
                flags=u32(_EnterFlags.IORING_ENTER_GETEVENTS),
                argp=pVoid(0),
                argz=ctypes.c_size_t(0),
            )
        elif num_entries > 0 or timeout > 0:
            timespec = _KernelTimespec.from_float(timeout)
            args = _IOURingGeteventsArgs.from_timespec(timespec)

            ''' waiting anything for `timeout` seconds '''
            try:
                result = _io_uring_enter(
                    self._ring_fd,
                    u32(num_entries),
                    min_complete=u32(1),
                    flags=u32(_EnterFlags.IORING_ENTER_EXT_ARG | _EnterFlags.IORING_ENTER_GETEVENTS),
                    argp=ctypes.byref(args),
                    argz=ctypes.c_size_t(ctypes.sizeof(args)),
                )
            except OSError as e:
                if e.errno != errno.ETIME:
                    raise
                result = num_entries
        else:
            ''' nothing to submit and no time to wait '''
            result = 0

        assert result == num_entries, f'{result=} {num_entries=}'

        entries = self._get_cqes()
        return [
            self._make_result(key, result)
            for key, result in entries.items()
        ]

    def _make_result(self, key: int, operation_result: int):
        operation, fileobj, params = self._requests.pop(key)
        result = (operation_result,)

        if operation == Operations.IORING_OP_ACCEPT:
            addr = None
            if operation_result > 0:
                addr = _parse_sockaddr(fileobj, params[0])
            result = (operation_result, addr)

        return key, result

    def _fill_sqe(
        self,
        opcode: Operations,
        fileobj,
        key: int,
        *,
        buffer: bytearray | None = None,
        addr: int = 0,
        length: int | None = None,
        offset_or_addrlen: int = 0,
        flags: int = 0,
        splice_fileobj_in = 0,
        link: bool = False,
    ):
        sqe = self._get_sqe()
        sqe.opcode = opcode
        sqe.fd = _get_fd(fileobj)
        sqe.off = offset_or_addrlen
        if buffer is not None:
            sqe.addr = _buffer_pointer(buffer).value

            '''
            in e.g. openat `buffer` is null-terminated string
            and sqe.len has other semantic
            '''
            if length is None:
                length = len(buffer)
        else:
            sqe.addr = addr
            if length is None:
                length = 0

        assert 0 <= length < 2**32
        sqe.len = length

        sqe.msg_flags = flags
        sqe.user_data = key
        sqe.splice_fd_in = _get_fd(splice_fileobj_in)

        sqe.flags = 0
        if link:
            sqe.flags = _SQEFlags.IOSQE_IO_LINK

    def _request(self, operation: Operations, fileobj, preserve_objects: tuple, **kwargs) -> int:
        '''
        preserve_objects - objects need to be kept alive during io_uring operation
        '''
        if 'buffer' in kwargs:
            if isinstance(kwargs['buffer'], bytes):
                '''
                NOTE: there is no way to obtain data pointer from bytes object
                so such redundant copy is required
                '''
                kwargs['buffer'] = bytearray(kwargs['buffer'])

            preserve_objects = (*preserve_objects, kwargs['buffer'])

        key = self._next_key
        self._next_key += 1
        self._fill_sqe(operation, fileobj, key, **kwargs)

        self._requests[key] = (operation, fileobj, preserve_objects)

        return key

    def recv(self, sock: socket.socket | int, buffer: bytearray, flags: int = 0) -> int:
        return self._request(Operations.IORING_OP_RECV, sock, (), buffer=buffer, flags=flags)

    def send(self, sock: socket.socket | int, buffer: bytes | bytearray, flags: int = 0) -> int:
        return self._request(Operations.IORING_OP_SEND, sock, (), buffer=buffer, flags=flags)

    def connect(self, sock: socket.socket | int, address) -> int:
        sockaddr = _make_sockaddr(sock, address)
        return self._request(
            Operations.IORING_OP_CONNECT,
            sock,
            (sockaddr,),
            addr=ctypes.addressof(sockaddr),
            offset_or_addrlen=ctypes.sizeof(sockaddr),
        )

    def accept(self, sock: socket.socket | int, flags: int = 0) -> int:
        sockaddr = _make_sockaddr(sock)
        return self._request(
            Operations.IORING_OP_ACCEPT,
            sock,
            (sockaddr,),
            addr=ctypes.addressof(sockaddr),
            offset_or_addrlen=ctypes.sizeof(sockaddr),
            flags=flags,
        )

    def poll_add(self, fileobj, events: int) -> int:
        assert events != 0
        '''
        NOTE: if there is already POLL_ADD on this fd
        new SQE should be issued with IORING_POLL_UPDATE_EVENTS flag
        '''
        return self._request(Operations.IORING_OP_POLL_ADD, fileobj, (), flags=events)

    def poll_remove(self, fileobj) -> int:
        return self._request(Operations.IORING_OP_POLL_REMOVE, fileobj, ())

    def cancel(self, key: int) -> int | None:
        if key not in self._requests:
            return

        return self._request(Operations.IORING_OP_ASYNC_CANCEL, -1, (), addr=key)

    def splice(
        self,
        fileobj_in,
        offset_in: int | None,
        fileobj_out,
        offset_out: int | None,
        length: int,
        flags: int = 0,
        link: bool = False,
    ) -> int:
        if offset_in is None:
            offset_in = -1

        if offset_out is None:
            offset_out = -1

        return self._request(
            Operations.IORING_OP_SPLICE,
            fileobj_out,
            (fileobj_out,),
            addr=offset_in,
            offset_or_addrlen=offset_out,
            length=length,
            flags=flags,
            splice_fileobj_in=fileobj_in,
            link=link,
        )

    def openat(self, dirfd: int | None, path: str, flags: int, mode: int) -> int:
        if dirfd is None:
            dirfd = -100  # AT_FDCWD

        buffer = bytearray(path, 'utf8')
        buffer.append(0)
        return self._request(
            Operations.IORING_OP_OPENAT,
            dirfd,
            (),
            buffer=buffer,
            length=mode,
            flags=flags,
        )

    def read(self, fileobj, buffer: bytearray) -> int:
        '''
        NOTE: IORING_OP_READ is actually pread(2),
        and offset=-1 tells kernel to use and update current file position
        '''
        return self._request(Operations.IORING_OP_READ, fileobj, (), buffer=buffer, offset_or_addrlen=-1)

    def close(self, fileobj) -> int:
        return self._request(Operations.IORING_OP_CLOSE, fileobj, ())

    def shutdown(self, fileobj, how: int) -> int:
        return self._request(Operations.IORING_OP_SHUTDOWN, fileobj, (), length=how)

    def close_ring(self):
        self._submission_queue.close()
        self._submission_queue = None

        self._completion_queue.close()
        self._completion_queue = None

        del self._submission_queue_entries
        self._submission_queue_entries_mmap.close()
        self._submission_queue_entries_mmap = None

        os.close(self._ring_fd)
        self._ring_fd = None
