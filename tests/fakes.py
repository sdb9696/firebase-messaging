import asyncio
import struct
from unittest.mock import patch

# When support for cpython older than 3.11 is dropped
# async_timeout can be replaced with asyncio.timeout
from async_timeout import timeout as asyncio_timeout

from firebase_messaging.fcmpushclient import MCS_MESSAGE_TAG, MCS_VERSION, FcmPushClient
from firebase_messaging.proto.checkin_pb2 import AndroidCheckinResponse
from firebase_messaging.proto.mcs_pb2 import LoginResponse


class FakeMcsEndpoint:
    def __init__(self):
        # self.connection_mock = patch(
        #    "asyncio.open_connection", side_effect=self.open_connection, autospec=True
        # )
        # self.connection_mock.start()
        self.client_writer = self.FakeWriter()
        self.client_reader = self.FakeReader()

    def close(self):
        # self.connection_mock.stop()
        pass

    async def open_connection(self, *_, **__):
        # Queues should be created on the loop that will be accessing them
        self.client_writer = self.FakeWriter()
        self.client_reader = self.FakeReader()
        return self.client_reader, self.client_writer

    async def put_message(self, message):
        await self.client_reader.put_message(message)

    async def put_error(self, error):
        await self.client_reader.put_error(error)

    async def get_message(self):
        return await self.client_writer.get_message()

    class FakeReader:
        def __init__(self):
            self.queue = asyncio.Queue()
            self.lock = asyncio.Lock()

        async def readexactly(self, size):
            if size == 0:
                return b""
            val = await self.queue.get()
            if isinstance(val, BaseException):
                raise val
            else:
                for _ in range(1, size):
                    val += await self.queue.get()
                return val

        async def put_message(self, message):
            include_version = isinstance(message, LoginResponse)
            packet = FcmPushClient._make_packet(message, include_version)
            async with self.lock:
                for p in packet:
                    b = bytes([p])
                    await self.queue.put(b)

        async def put_error(self, error):
            async with self.lock:
                await self.queue.put(error)

    class FakeWriter:
        def __init__(self):
            self.queue = asyncio.Queue()
            self.buf = ""
            self.lock = asyncio.Lock()

        def write(self, buffer):
            for i in buffer:
                b = bytes([i])
                self.queue.put_nowait(b)

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

        async def get_bytes(self, size):
            async with self.lock:
                val = b""
                for _ in range(size):
                    val += await self.queue.get()
                return val

        async def get_message(self, timeout=2):
            async with asyncio_timeout(timeout):
                r = await self.get_bytes(1)
                (b,) = struct.unpack("B", r)
                if b == MCS_VERSION:  # first message
                    r = await self.get_bytes(1)
                    (b,) = struct.unpack("B", r)
                tag = b
                size = await self._read_varint32()
                msgstr = await self.get_bytes(size)
                msg_class = next(
                    iter([c for c, t in MCS_MESSAGE_TAG.items() if t == tag])
                )
                msg = msg_class()
                msg.ParseFromString(msgstr)
                return msg

        # protobuf variable length integers are encoded in base 128
        # each byte contains 7 bits of the integer and the msb is set if there's
        # more. pretty simple to implement
        async def _read_varint32(self):
            res = 0
            shift = 0
            while True:
                r = await self.get_bytes(1)
                (b,) = struct.unpack("B", r)
                res |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
            return res
