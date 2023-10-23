import asyncio
import functools
import json
import logging
import struct
import time
import traceback
from base64 import urlsafe_b64decode
from ssl import SSLError
from threading import Thread
from typing import Any, Callable, Optional, List
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_private_key
from google.protobuf.json_format import MessageToJson
from http_ece import decrypt as http_decrypt

from .const import (
    MCS_HOST,
    MCS_MESSAGE_TAG,
    MCS_PORT,
    MCS_SELECTIVE_ACK_ID,
    MCS_VERSION,
)
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
    SelectiveAck,
)


_logger = logging.getLogger(__name__)


@dataclass
class FcmPushClientConfig:  # pylint:disable=too-many-instance-attributes
    """Class to provide configuration to
    :class:`firebase_messaging.FcmPushClientConfig`.FcmPushClient."""

    server_heartbeat_interval: Optional[int] = None
    """Time in seconds to request the server to send heartbeats"""

    client_heartbeat_interval: Optional[int] = None
    """Time in seconds to send heartbeats to the server"""

    send_selective_acknowledgements: bool = True
    """True to send selective acknowledgements for each message received.
        Currently if false the client does not send any acknowlegements."""

    connection_retry_count: int = 5
    """Number of times to retry the connection before giving up."""

    start_seconds_before_retry_connect: float = 3
    """Time in seconds to wait before attempting to retry
        the connection after failure."""

    reset_interval: float = 1
    """Time in seconds to wait between resets after errors or disconnection."""

    heartbeat_ack_timeout: float = 5
    """Time in seconds to wait for a heartbeat ack before resetting."""

    abort_on_sequential_error_count: Optional[int] = 3
    """Number of sequential errors of the same time to wait before aborting.
        If set to None the client will not abort."""

    monitor_interval: float = 1
    """Time in seconds for the monitor task to fire and check for heartbeats,
        stale connections and shut down of the main event loop."""

    log_warn_limit: Optional[int] = 5
    """Number of times to log specific warning messages before going silent for
        a specific warning type."""

    log_debug_verbose: bool = False
    """Set to True to log all message info including tokens."""


class FcmPushClient:  # pylint:disable=too-many-instance-attributes
    """Client that connects to Firebase Cloud Messaging and receives messages.

    :param credentials: credentials object returned by register()
    :param credentials_updated_callback: callback when new credentials are
        created to allow client to store them
    :param received_persistent_ids: any persistent id's you already received.
    :param config: configuration class of
        :class:`firebase_messaging.FcmPushClientConfig`
    """

    def __init__(
        self,
        *,
        credentials: Optional[dict] = None,
        credentials_updated_callback: Optional[Callable[[str], None]] = None,
        received_persistent_ids: Optional[List[str]] = None,
        config: Optional[FcmPushClientConfig] = None,
    ):
        """Initializes the receiver."""
        self.credentials = credentials
        self.credentials_updated_callback = credentials_updated_callback
        self.persistent_ids = received_persistent_ids if received_persistent_ids else []
        self.config = config if config else FcmPushClientConfig()
        if self.config.log_debug_verbose:
            _logger.setLevel(logging.DEBUG)

        self.reader = None
        self.writer = None
        self.do_listen = False
        self.logged_in = False
        self.sequential_error_counters = {}
        self.log_warn_counters = {}

        # reset variables
        self.input_stream_id = 0
        self.last_input_stream_id_reported = -1
        self.first_message = True
        self.last_login_time = None
        self.last_message_time = None

        self.reset_lock = asyncio.Lock()
        self.stopping_lock = asyncio.Lock()

        self.is_resetting = False
        self.is_stopping = False
        self.tasks = None

        self.loop = None
        self.main_loop = None
        self.fcm_thread = None

        self.app_id = None
        self.sender_id = None

    def _msg_str(self, msg):
        if self.config.log_debug_verbose:
            return type(msg).__name__ + "\n" + MessageToJson(msg, indent=4)
        return type(msg).__name__

    def _log_verbose(self, msg: str, *args):
        if self.config.log_debug_verbose:
            _logger.debug(msg, *args)

    def _log_warn_with_limit(self, msg: str, *args):
        if msg not in self.log_warn_counters:
            self.log_warn_counters[msg] = 0
        if (
            self.config.log_warn_limit
            and self.config.log_warn_limit > self.log_warn_counters[msg]
        ):
            self.log_warn_counters[msg] += 1
            _logger.warning(msg, *args)

    async def _do_writer_close(self):
        try:
            if self.loop and self.writer and self.loop.is_running():
                self.writer.close()
                await self.writer.wait_closed()
        except OSError as e:
            _logger.debug("%s Error while trying to close writer", type(e).__name__)

    async def _reset(self):
        if self.reset_lock.locked() or not self.do_listen:
            return

        async with self.reset_lock:
            _logger.debug("Resetting connection")
            try:
                self.is_resetting = True
                self.logged_in = False
                now = time.time()
                time_since_last_login = now - self.last_login_time
                if time_since_last_login < self.config.reset_interval:
                    _logger.debug(
                        "%ss since last reset attempt.", time_since_last_login
                    )
                    await asyncio.sleep(
                        self.config.reset_interval - time_since_last_login
                    )

                await self._do_writer_close()

                _logger.debug("Reestablishing connection")
                if not await self._connect_with_retry():
                    _logger.error(
                        "Unable to connect to MCS endpoint "
                        + "after %s tries, shutting down"
                    )
                    self._terminate()
                    return
                _logger.debug("Re-connected to ssl socket")

                await self._login()
            finally:
                self.is_resetting = False

    # protobuf variable length integers are encoded in base 128
    # each byte contains 7 bits of the integer and the msb is set if there's
    # more. pretty simple to implement
    async def _read_varint32(self):
        res = 0
        shift = 0
        while True:
            r = await self.reader.readexactly(1)
            (b,) = struct.unpack("B", r)
            res |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return res

    @staticmethod
    def _encode_varint32(x):
        if x == 0:
            return bytes(bytearray([0]))

        res = bytearray([])
        while x != 0:
            b = x & 0x7F
            x >>= 7
            if x != 0:
                b |= 0x80
            res.append(b)
        return bytes(res)

    @staticmethod
    def _make_packet(msg, include_version):
        tag = MCS_MESSAGE_TAG[type(msg)]
        if include_version:
            header = bytearray([MCS_VERSION, tag])
        else:
            header = bytearray([tag])

        payload = msg.SerializeToString()
        buf = bytes(header) + FcmPushClient._encode_varint32(len(payload)) + payload
        return buf

    async def _send_msg(self, msg):
        self._log_verbose("Sending packet to server: %s", self._msg_str(msg))

        buf = FcmPushClient._make_packet(msg, self.first_message)
        self.writer.write(buf)
        await self.writer.drain()

    async def _receive_msg(self):
        if self.first_message:
            r = await self.reader.readexactly(2)
            version, tag = struct.unpack("BB", r)
            if version < MCS_VERSION and version != 38:
                raise RuntimeError("protocol version {} unsupported".format(version))
            self.first_message = False
        else:
            r = await self.reader.readexactly(1)
            (tag,) = struct.unpack("B", r)
        size = await self._read_varint32()

        self._log_verbose(
            "Received message with tag %s and size %s",
            tag,
            size,
        )

        if not size >= 0:
            self._log_warn_with_limit("Unexpected message size %s", size)
            return None

        buf = await self.reader.readexactly(size)

        msg_class = next(iter([c for c, t in MCS_MESSAGE_TAG.items() if t == tag]))
        if not msg_class:
            self._log_warn_with_limit("Unexpected message tag %s", tag)
            return None
        if isinstance(msg_class, str):
            self._log_warn_with_limit("Unconfigured message class %s", msg_class)
            return None

        payload = msg_class()
        payload.ParseFromString(buf)
        self._log_verbose("Received payload: %s", self._msg_str(payload))

        return payload

    async def _login(self):
        now = time.time()
        self.input_stream_id = 0
        self.last_input_stream_id_reported = -1
        self.first_message = True
        self.last_login_time = now

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
            if (
                self.config.server_heartbeat_interval
                and self.config.server_heartbeat_interval > 0
            ):
                req.heartbeat_stat.ip = ""
                req.heartbeat_stat.timeout = True
                req.heartbeat_stat.interval_ms = (
                    1000 * self.config.server_heartbeat_interval
                )

            await self._send_msg(req)
            _logger.debug("Sent login request")
        except Exception as ex:
            _logger.error("Received an exception logging in: %s", ex)
            if self._try_increment_error_count("login"):
                await self._reset()

    @staticmethod
    def _decrypt_raw_data(credentials, crypto_key, salt, raw_data):
        crypto_key = urlsafe_b64decode(crypto_key.encode("ascii"))
        salt = urlsafe_b64decode(salt.encode("ascii"))
        der_data = credentials["keys"]["private"]
        der_data = urlsafe_b64decode(der_data.encode("ascii") + b"========")
        secret = credentials["keys"]["secret"]
        secret = urlsafe_b64decode(secret.encode("ascii") + b"========")
        privkey = load_der_private_key(
            der_data, password=None, backend=default_backend()
        )
        decrypted = http_decrypt(
            raw_data,
            salt=salt,
            private_key=privkey,
            dh=crypto_key,
            version="aesgcm",
            auth_secret=secret,
        )
        return decrypted

    def _app_data_by_key(self, p, key):
        for x in p.app_data:
            if x.key == key:
                return x.value

        raise RuntimeError("couldn't find in app_data {}".format(key))

    def _handle_data_message(self, callback, p, obj):
        _logger.debug(
            "Received data message Stream ID: %s, Last: %s, Status: %s",
            p.stream_id,
            p.last_stream_id_received,
            p.status,
        )

        crypto_key = self._app_data_by_key(p, "crypto-key")[3:]  # strip dh=
        salt = self._app_data_by_key(p, "encryption")[5:]  # strip salt=
        subtype = self._app_data_by_key(p, "subtype")
        if subtype != self.app_id:
            self._log_warn_with_limit(
                "Subtype %s in data message does not match"
                + "app id client was registered with %s",
                subtype,
                self.app_id,
            )
        decrypted = self._decrypt_raw_data(
            self.credentials, crypto_key, salt, p.raw_data
        )
        decrypted_json = json.loads(decrypted.decode("utf-8"))
        self._log_verbose(
            "Decrypted data for message %s is: %s", p.persistent_id, decrypted_json
        )
        if self.main_loop and self.main_loop.is_running():
            if callback:
                on_error = functools.partial(self._try_increment_error_count, "notify")
                self.main_loop.call_soon_threadsafe(
                    functools.partial(
                        FcmPushClient._wrapped_callback,
                        self.loop,
                        on_error,
                        callback,
                        decrypted_json,
                        p,
                        obj,
                    )
                )
        else:
            _logger.debug("Main loop no longer running, terminating FcmClient")
            self._terminate()

    def _new_input_stream_id_available(self):
        return self.last_input_stream_id_reported != self.input_stream_id

    def _get_input_stream_id(self):
        self.last_input_stream_id_reported = self.input_stream_id
        return self.input_stream_id

    async def _handle_ping(self, p):
        _logger.debug(
            "Received heartbeat ping, sending ack: Stream ID: %s, Last: %s, Status: %s",
            p.stream_id,
            p.last_stream_id_received,
            p.status,
        )
        req = HeartbeatAck()

        if self._new_input_stream_id_available():
            req.last_stream_id_received = self._get_input_stream_id()

        await self._send_msg(req)

    async def _handle_iq(self, p):
        if not p.extension:
            self._log_warn_with_limit(
                "Unexpected IqStanza id received with no extension", str(p)
            )
            return
        if p.extension.id not in (12, 13):
            self._log_warn_with_limit(
                "Unexpected extension id received: %s", p.extension.id
            )
            return

    async def _send_selective_ack(self, persistent_id):
        iqs = IqStanza()
        iqs.type = IqStanza.IqType.SET
        iqs.id = ""
        # iqs.extension = Extension()
        iqs.extension.id = MCS_SELECTIVE_ACK_ID
        sa = SelectiveAck()
        sa.id.extend([persistent_id])
        iqs.extension.data = sa.SerializeToString()
        _logger.debug("Sending selective ack for message id %s", persistent_id)
        await self._send_msg(iqs)

    async def _send_heartbeat(self):
        req = HeartbeatPing()

        if self._new_input_stream_id_available():
            req.last_stream_id_received = self._get_input_stream_id()

        await self._send_msg(req)
        _logger.debug("Sent heartbeat ping")

    def _terminate(self):
        self.do_listen = False
        current_task = asyncio.current_task()
        for task in self.tasks:
            if (
                current_task != task and not task.done()
            ):  # cancel return if task is done so no need to check
                task.cancel()

    async def _do_monitor(self):
        while self.do_listen:
            await asyncio.sleep(self.config.monitor_interval)

            if not self.main_loop or not self.main_loop.is_running():
                _logger.debug("Main loop no longer running, terminating FcmClient")
                self._terminate()
                return

            if self.logged_in and self.config.client_heartbeat_interval:
                now = time.time()
                if (
                    self.last_message_time + self.config.client_heartbeat_interval < now
                    and not self.is_resetting
                ):
                    await self._send_heartbeat()
                    await asyncio.sleep(self.config.heartbeat_ack_timeout)
                    now = time.time()
                    if (
                        self.last_message_time + self.config.client_heartbeat_interval
                        < now
                        and self.do_listen
                    ):
                        await self._reset()

    def _try_increment_error_count(self, error_type: str):
        if error_type not in self.sequential_error_counters:
            self.sequential_error_counters[error_type] = 0

        self.sequential_error_counters[error_type] += 1

        if (
            self.config.abort_on_sequential_error_count
            and self.sequential_error_counters[error_type]
            >= self.config.abort_on_sequential_error_count
        ):
            _logger.error(
                "Shutting down push receiver due to "
                + f"{self.sequential_error_counters[error_type]} sequential"
                + f" errors of type {error_type}"
            )
            self._terminate()
            return False
        return True

    async def _handle_message(self, msg, callback, obj):
        self.last_message_time = time.time()
        self.input_stream_id += 1

        if isinstance(msg, Close):
            self._log_warn_with_limit("Server sent Close message, resetting")
            if self._try_increment_error_count("connection"):
                await self._reset()
            return

        if isinstance(msg, LoginResponse):
            if str(msg.error):
                _logger.error("Received login error response: %s", msg)
                if self._try_increment_error_count("login"):
                    await self._reset()
            else:
                _logger.info("Succesfully logged in to MCS endpoint")
                self.sequential_error_counters["login"] = 0
                self.logged_in = True
                self.persistent_ids = []
            return

        if isinstance(msg, DataMessageStanza):
            self._handle_data_message(callback, msg, obj)
            self.persistent_ids.append(msg.persistent_id)
            if self.config.send_selective_acknowledgements:
                await self._send_selective_ack(msg.persistent_id)
        elif isinstance(msg, HeartbeatPing):
            await self._handle_ping(msg)
        elif isinstance(msg, HeartbeatAck):
            _logger.debug("Received heartbeat ack: %s", msg)
        elif isinstance(msg, IqStanza):
            pass
        else:
            self._log_warn_with_limit("Unexpected message type %s.", type(msg).__name__)
        # Reset error count if a read has been succesful
        self.sequential_error_counters["read"] = 0
        self.sequential_error_counters["connection"] = 0

    @staticmethod
    async def _open_connection(host, port, ssl):
        return await asyncio.open_connection(host=host, port=port, ssl=ssl)

    async def _connect(self):
        try:
            self.reader, self.writer = await self._open_connection(
                host=MCS_HOST, port=MCS_PORT, ssl=True
            )
            _logger.debug("Connected to MCS endpoint (%s,%s)", MCS_HOST, MCS_PORT)
            return True
        except OSError as oex:
            _logger.error(
                "Could not connected to MCS endpoint (%s,%s): %s",
                MCS_HOST,
                MCS_PORT,
                oex,
            )
            return False

    async def _connect_with_retry(self):
        trycount = 0
        connected = False
        while (
            trycount < self.config.connection_retry_count
            and not connected
            and self.do_listen
        ):
            trycount += 1
            connected = await self._connect()
            if not connected:
                sleep_time = (
                    self.config.start_seconds_before_retry_connect * trycount * trycount
                )
                _logger.info(
                    "Could not connect to MCS Endpoint on "
                    + "try %s, sleeping for %s seconds",
                    trycount,
                    sleep_time,
                )
                await asyncio.sleep(sleep_time)
        if not connected:
            _logger.error(
                "Unable to connect to MCS endpoint after %s tries, aborting", trycount
            )
        return connected

    async def _listen(self, callback, obj=None):  # pylint: disable=too-many-branches
        """
        listens for push notifications

        callback(obj, notification, data_message): called on notifications
        obj: optional arbitrary value passed to callback
        """

        if not await self._connect_with_retry():
            return

        try:
            await self._login()

            while self.do_listen and self.loop.is_running():
                if not self.main_loop or not self.main_loop.is_running():
                    _logger.debug("Main loop no longer running, terminating FcmClient")
                    self._terminate()
                    return
                try:
                    if self.is_resetting:
                        await asyncio.sleep(1)
                    elif msg := await self._receive_msg():
                        await self._handle_message(msg, callback, obj)

                except OSError as osex:
                    if (
                        isinstance(osex, (ConnectionResetError, TimeoutError, SSLError))
                        and self.is_resetting
                    ):
                        if (
                            isinstance(osex, SSLError)  # pylint: disable=no-member
                            and osex.reason != "APPLICATION_DATA_AFTER_CLOSE_NOTIFY"
                        ):
                            self._log_warn_with_limit(
                                "Unexpected SSLError reason during reset of %s",
                                osex.reason,
                            )
                        else:
                            self._log_verbose(
                                "Expected read error during reset: %s",
                                type(osex).__name__,
                            )
                    else:
                        _logger.error("Unexpected exception during read: %s", osex)
                        if self._try_increment_error_count("connection"):
                            await self._reset()

        except asyncio.CancelledError as cex:
            raise cex
        except Exception as ex:
            _logger.error(
                "Unknown error: %s, shutting down FcmPushClient.\n%s",
                ex,
                traceback.format_exc(),
            )
            self._terminate()
        finally:
            await self._do_writer_close()

    def _signal_handler(self):
        self.disconnect()

    async def _run_tasks(self, callback, obj):
        try:
            self.tasks = [
                asyncio.create_task(self._listen(callback, obj)),
                asyncio.create_task(self._do_monitor()),
            ]
            return await asyncio.gather(*self.tasks, return_exceptions=True)
        except Exception as ex:
            _logger.error("Unexpected error running FcmPushClient: %s", ex)

    def _start_connection(self, callback, obj):
        self.do_listen = True
        self.loop = asyncio.new_event_loop()

        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._run_tasks(callback, obj))
        _logger.info("FCMClient has shutdown")

    @staticmethod
    def _wrapped_callback(
        fcm_client_loop, on_error, callback, notification, msg, obj
    ):  # pylint: disable=too-many-arguments
        # Should be running on main loop

        try:
            callback(notification, msg.persistent_id, obj)
        except Exception as ex:
            _logger.error("Unexpected exception calling notification callback: %s", ex)
            fcm_client_loop.call_soon_threadsafe(on_error)

    def checkin(self, sender_id: int, app_id: str) -> str:
        """Check in if you have credentials otherwise register as a new client.

        :param sender_id: sender id identifying push service you are connecting to.
        :param app_id: identifier for your application.
        :return: The FCM token which is used to identify you with the push end
            point application.
        """
        self.sender_id = sender_id
        self.app_id = app_id
        if self.credentials:
            gcm_response = gcm_check_in(
                self.credentials["gcm"]["androidId"],
                self.credentials["gcm"]["securityToken"],
                log_debug_verbose=self.config.log_debug_verbose,
            )
            if gcm_response:
                return self.credentials["fcm"]["token"]

        self.credentials = self.register(sender_id, app_id)
        if self.credentials_updated_callback:
            self.credentials_updated_callback(self.credentials)

        return self.credentials["fcm"]["token"]

    def connect(
        self, callback: Optional[Callable[[dict, str, Optional[Any]], None]], obj=None
    ):
        """Connect to FCM and start listening for push
            messages on a seperate service thread.

        :param callback: Optional callback to call when a message is received.
            Will callback on the loop used to start the connection.
            Callback expects parameters of:
            dict: which will be a decrypted dictionary of the war payload.\n
            persistent_id: unique message identifier from the FCM server.\n
            obj: returns the arbitrary object if supplied to this function.
        :param obj: Arbitrary object to be returned in the callback.
        """
        self.main_loop = asyncio.get_running_loop()

        self.fcm_thread = Thread(
            target=self._start_connection, args=[callback, obj], daemon=True
        )
        self.fcm_thread.start()

    async def _stop_connection(self):
        if self.stopping_lock.locked() or self.is_stopping:
            return

        async with self.stopping_lock:
            try:
                self.is_stopping = True

                self.do_listen = False

                for task in self.tasks:
                    if not task.done():
                        task.cancel()

            finally:
                self.is_stopping = False

    def disconnect(self):
        """Disconnects from FCM and shuts down the service thread."""
        if self.loop and self.loop.is_running() and self.fcm_thread.is_alive():
            _logger.debug("Shutting down FCMClient")
            asyncio.run_coroutine_threadsafe(self._stop_connection(), self.loop)

            self.loop = None

    def register(self, sender_id: int, app_id: str) -> dict:
        """Register gcm and fcm tokens for sender_id.
            Typically you would
            call checkin instead of register which does not do a full registration
            if credentials are present

        :param sender_id: sender id identifying push service you are connecting to.
        :param app_id: identifier for your application.
        :return: The dict containing all credentials.
        """
        self.sender_id = sender_id
        self.app_id = app_id
        subscription = gcm_register(
            app_id=app_id, log_debug_verbose=self.config.log_debug_verbose
        )
        if subscription is None:
            raise RuntimeError(
                "Unable to establish subscription with Google Cloud Messaging."
            )
        self._log_verbose("GCM subscription: %s", subscription)
        fcm = fcm_register(
            sender_id=sender_id,
            token=subscription["token"],
            log_debug_verbose=self.config.log_debug_verbose,
        )
        self._log_verbose("FCM registration: %s", fcm)
        res = {"gcm": subscription}
        res.update(fcm)
        self._log_verbose("Credential: %s", res)
        _logger.info("Registered with FCM")
        return res

    async def _send_data_message(self, raw_data, persistent_id):
        dms = DataMessageStanza()
        dms.persistent_id = persistent_id
        dms.data = raw_data
        # Not supported yet

    def send_message(self, raw_data, persistent_id):
        """Not implemented, does nothing atm."""
        asyncio.run_coroutine_threadsafe(
            self._send_data_message(raw_data, persistent_id), self.loop
        )

    def __del__(self):
        if self.loop and self.loop.is_running():
            self.disconnect()
