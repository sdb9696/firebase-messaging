import asyncio
import json
import logging
import struct
import time
from base64 import urlsafe_b64decode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_private_key

from .decrypt import decrypt as http_decrypt
from .fcm import fcm_register
from .gcm import gcm_check_in, gcm_register
from .proto.mcs_pb2 import (  # pylint: disable=no-name-in-module
    Close,
    DataMessageStanza,
    HeartbeatAck,
    HeartbeatPing,
    IqStanza,
    LoginRequest,
    LoginResponse,
    StreamErrorStanza,
)


class PushReceiver:
    _logger = logging.getLogger("push_receiver")

    MIN_RESET_INTERVAL_SECS = 5 * 60
    MAX_SILENT_INTERVAL_SECS = 60 * 60
    MCS_VERSION = 41

    PACKET_BY_TAG = [
        HeartbeatPing,
        HeartbeatAck,
        LoginRequest,
        LoginResponse,
        Close,
        "MessageStanza",
        "PresenceStanza",
        IqStanza,
        DataMessageStanza,
        "BatchPresenceStanza",
        StreamErrorStanza,
        "HttpRequest",
        "HttpResponse",
        "BindAccountRequest",
        "BindAccountResponse",
        "TalkMetadata",
    ]

    last_reset = 0

    HOST = "mtalk.google.com"
    PORT = 5228

    def __init__(
        self,
        credentials,
        credentials_updated_callback=None,
        received_persistent_ids=None,
    ):
        """
        initializes the receiver

        credentials: credentials object returned by register()
        received_persistent_ids: any persistent id's you already received.
                                                         array of strings
        """

        self.credentials = credentials
        self.credentials_updated_callback = credentials_updated_callback
        self.persistent_ids = received_persistent_ids if received_persistent_ids else []
        self.reader = None
        self.writer = None
        self.do_listen = False

    async def __read(self, size):
        buf = b""
        while len(buf) < size:
            # buf += self.socket.recv(size - len(buf))
            r = await self.reader.read(size - len(buf))
            buf += r
        return buf

    # protobuf variable length integers are encoded in base 128
    # each byte contains 7 bits of the integer and the msb is set if there's
    # more. pretty simple to implement

    async def __read_varint32(self):
        res = 0
        shift = 0
        while True:
            r = await self.__read(1)
            (b,) = struct.unpack("B", r)
            res |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return res

    def __encode_varint32(self, x):
        res = bytearray([])
        while x != 0:
            b = x & 0x7F
            x >>= 7
            if x != 0:
                b |= 0x80
            res.append(b)
        return bytes(res)

    async def __send(self, packet):
        header = bytearray([self.MCS_VERSION, self.PACKET_BY_TAG.index(type(packet))])
        self._logger.debug("Packet to send:\n%s", packet)
        payload = packet.SerializeToString()
        buf = bytes(header) + self.__encode_varint32(len(payload)) + payload
        self.writer.write(buf)
        await self.writer.drain()

    async def __recv(self, first=False):
        try:
            if first:
                r = await self.__read(2)
                version, tag = struct.unpack("BB", r)
                self._logger.debug("version %s", version)
                if version < self.MCS_VERSION and version != 38:
                    raise RuntimeError(
                        "protocol version {} unsupported".format(version)
                    )
            else:
                r = await self.__read(1)
                (tag,) = struct.unpack("B", r)
            size = await self.__read_varint32()
        except OSError as e:
            self._logger.debug("Read error: %s", e)
            return None
        self._logger.debug(
            "Received message with tag %s (%s), size %s",
            tag,
            self.PACKET_BY_TAG[tag],
            size,
        )
        if size >= 0:
            buf = await self.__read(size)
            packet_class = self.PACKET_BY_TAG[tag]
            payload = packet_class()
            payload.ParseFromString(buf)
            self._logger.debug("Receive payload:\n%s", payload)
            return payload
        return None

    def __app_data_by_key(self, p, key, blow_shit_up=True):
        for x in p.app_data:
            if x.key == key:
                return x.value
        if blow_shit_up:
            raise RuntimeError("couldn't find in app_data {}".format(key))
        return None

    async def __login(self):
        # self.__open()
        try:
            android_id = self.credentials["gcm"]["androidId"]
            req = LoginRequest()
            req.adaptive_heartbeat = False
            req.auth_service = 2
            req.auth_token = self.credentials["gcm"]["securityToken"]
            req.id = "chrome-63.0.3234.0"
            req.domain = "mcs.android.com"
            req.device_id = "android-%x" % int(android_id)
            req.network_type = 1
            req.resource = android_id
            req.user = android_id
            req.use_rmq2 = True
            req.setting.add(name="new_vc", value="1")
            req.received_persistent_id.extend(self.persistent_ids)
            await self.__send(req)
            # await asyncio.sleep(1)
            login_response = await self.__recv(first=True)
            self._logger.debug("Received login response:\n%s", login_response)
        except Exception as ex:
            self._logger.error("Received an exception logging in%s", ex)

    async def __reset(self):
        now = time.time()
        time_since_last_reset = now - self.last_reset
        if time_since_last_reset < self.MIN_RESET_INTERVAL_SECS:
            self._logger.debug("%ss since last reset attempt.", time_since_last_reset)
            await asyncio.sleep(self.MIN_RESET_INTERVAL_SECS - time_since_last_reset)
        self.last_reset = now
        self._logger.debug("Reestablishing connection")

        self.writer.close()
        await self.writer.wait_closed()

        self.reader, self.writer = await asyncio.open_connection(
            host=self.HOST, port=self.PORT, ssl=True
        )
        self._logger.debug("Re-connected to ssl socket")

        await self.__login()

    def __handle_data_message(self, p, callback, obj):
        crypto_key = self.__app_data_by_key(p, "crypto-key")[3:]  # strip dh=
        salt = self.__app_data_by_key(p, "encryption")[5:]  # strip salt=
        crypto_key = urlsafe_b64decode(crypto_key.encode("ascii"))
        salt = urlsafe_b64decode(salt.encode("ascii"))
        der_data = self.credentials["keys"]["private"]
        der_data = urlsafe_b64decode(der_data.encode("ascii") + b"========")
        secret = self.credentials["keys"]["secret"]
        secret = urlsafe_b64decode(secret.encode("ascii") + b"========")
        privkey = load_der_private_key(
            der_data, password=None, backend=default_backend()
        )
        decrypted = http_decrypt(
            p.raw_data,
            salt=salt,
            private_key=privkey,
            dh=crypto_key,
            version="aesgcm",
            auth_secret=secret,
        )
        self._logger.debug("Received data message %s: %s", p.persistent_id, decrypted)
        callback(obj, json.loads(decrypted.decode("utf-8")), p)
        return p.persistent_id

    async def __handle_ping(self, p):
        self._logger.debug(
            "Responding to ping: Stream ID: %s, Last: %s, Status: %s",
            p.stream_id,
            p.last_stream_id_received,
            p.status,
        )
        req = HeartbeatAck()
        req.stream_id = p.stream_id + 1
        req.last_stream_id_received = p.stream_id
        req.status = p.status
        await self.__send(req)

    async def listen(self, callback, obj=None):
        """
        listens for push notifications

        callback(obj, notification, data_message): called on notifications
        obj: optional arbitrary value passed to callback
        """
        self.reader, self.writer = await asyncio.open_connection(
            host=self.HOST, port=self.PORT, ssl=True
        )
        self._logger.debug("connected to ssl socket")

        try:
            await self.__login()

            while self.do_listen:
                try:
                    p = await self.__recv()
                    if isinstance(p, DataMessageStanza):
                        msg_id = self.__handle_data_message(p, callback, obj)
                        self.persistent_ids.append(msg_id)
                    elif isinstance(p, HeartbeatPing):
                        await self.__handle_ping(p)
                    elif isinstance(p, IqStanza):
                        pass
                    elif p is None or isinstance(p, Close):
                        await self.__reset()
                    else:
                        self._logger.debug("Unexpected message type %s.", type(p))
                except ConnectionResetError:
                    self._logger.debug("Connection Reset: Reconnecting")
                    await self.__login()
        except Exception as ex:
            self._logger.error("Unknown error %s", ex)
        finally:
            self.writer.close()
            await self.writer.wait_closed()

    def start_listener(self, callback, obj=None):
        self.do_listen = True
        asyncio.create_task(self.listen(callback, obj))

    def stop_listener(self):
        self.do_listen = False

    def register(self, sender_id, app_id):
        """register gcm and fcm tokens for sender_id"""
        subscription = gcm_register(app_id=app_id)
        if subscription is None:
            raise RuntimeError(
                "Unable to establish subscription with Google Cloud Messaging."
            )
        self._logger.debug("GCM subscription: %s", subscription)
        fcm = fcm_register(sender_id=sender_id, token=subscription["token"])
        self._logger.debug("FCM registration: %s", fcm)
        res = {"gcm": subscription}
        res.update(fcm)
        self._logger.debug("Credential: %s", res)
        return res

    def connect(self, sender_id, app_id):
        if self.credentials:
            gcm_check_in(sender_id, self.credentials["fcm"]["token"])
        else:
            self.credentials = self.register(sender_id, app_id)
