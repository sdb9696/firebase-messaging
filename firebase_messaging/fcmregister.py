import asyncio
import logging
import os
from base64 import urlsafe_b64encode
from typing import Any, Callable, Dict, Optional, Union

from aiohttp import ClientSession
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.json_format import MessageToDict, MessageToJson

from .const import (
    FCM_SEND_URL,
    FCM_SUBSCRIBE_URL,
    GCM_CHECKIN_URL,
    GCM_REGISTER_URL,
    GCM_SERVER_KEY_B64,
)
from .proto.android_checkin_pb2 import (
    DEVICE_CHROME_BROWSER,
    AndroidCheckinProto,
    ChromeBuildProto,
)
from .proto.checkin_pb2 import (
    AndroidCheckinRequest,
    AndroidCheckinResponse,
)

_logger = logging.getLogger(__name__)


class FcmRegister:
    def __init__(
        self,
        credentials: Optional[dict] = None,
        credentials_updated_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        *,
        http_client_session: Optional[ClientSession] = None,
        log_debug_verbose: bool = False,
    ):
        self.credentials = credentials
        self.credentials_updated_callback = credentials_updated_callback

        self._log_debug_verbose = log_debug_verbose

        self._http_client_session = http_client_session
        self._local_session: Optional[ClientSession] = None

        self.app_id: Optional[str] = None
        self.sender_id: Optional[int] = None

    def _get_checkin_payload(
        self, android_id: Optional[int] = None, security_token: Optional[int] = None
    ) -> AndroidCheckinRequest:
        chrome = ChromeBuildProto()
        chrome.platform = ChromeBuildProto.Platform.PLATFORM_LINUX  # 3
        chrome.chrome_version = "63.0.3234.0"
        chrome.channel = ChromeBuildProto.Channel.CHANNEL_STABLE  # 1

        checkin = AndroidCheckinProto()
        checkin.type = DEVICE_CHROME_BROWSER  # 3
        checkin.chrome_build.CopyFrom(chrome)

        payload = AndroidCheckinRequest()
        payload.user_serial_number = 0
        payload.checkin.CopyFrom(checkin)
        payload.version = 3
        if android_id and security_token:
            payload.id = int(android_id)
            payload.security_token = int(security_token)

        return payload

    async def gcm_check_in(
        self,
        android_id: Optional[int] = None,
        security_token: Optional[int] = None,
        log_debug_verbose: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        perform check-in request

        android_id, security_token can be provided if we already did the initial
        check-in

        returns dict with android_id, security_token and more
        """

        payload = self._get_checkin_payload(android_id, security_token)

        if log_debug_verbose:
            _logger.debug("GCM check in payload:\n%s", payload)

        retries = 3
        acir = None
        content = None
        for try_num in range(retries):
            try:
                async with self._session.post(
                    url=GCM_CHECKIN_URL,
                    headers={"Content-Type": "application/x-protobuf"},
                    data=payload.SerializeToString(),
                    timeout=2,
                ) as resp:
                    if resp.status == 200:
                        acir = AndroidCheckinResponse()
                        content = await resp.read()
                        break
                    else:
                        text = await resp.text()
                if acir and content:
                    break
                else:
                    _logger.warning(
                        "GCM checkin failed on attempt %s out "
                        + "of %s with status: %s, %s",
                        try_num + 1,
                        retries,
                        resp.status,
                        text,
                    )
                # retry without android id and security_token
                payload = self._get_checkin_payload()
                await asyncio.sleep(1)
            except Exception as e:
                _logger.warning(
                    "Error during gcm checkin post attempt %s out of %s",
                    try_num + 1,
                    retries,
                    exc_info=e,
                )
                await asyncio.sleep(1)

        if not acir or not content:
            _logger.error("Unable to checkin to gcm after %s retries", retries)
            return None
        acir.ParseFromString(content)

        if log_debug_verbose:
            msg = MessageToJson(acir, indent=4)
            _logger.debug("GCM check in response (raw):\n%s", msg)

        return MessageToDict(acir)

    async def gcm_register(
        self, app_id: str, retries: int = 5, log_debug_verbose: bool = False
    ) -> Optional[Dict[str, str]]:
        """
        obtains a gcm token

        app_id: app id as an integer
        retries: number of failed requests before giving up

        returns {"token": "...", "appId": 123123, "androidId":123123,
                        "securityToken": 123123}
        """
        # contains android_id, security_token and more
        chk = await self.gcm_check_in(log_debug_verbose=log_debug_verbose)
        if not chk:
            raise RuntimeError("Unable to register and check in to gcm")
        if log_debug_verbose:
            _logger.debug("GCM check in response %s", chk)
        body = {
            "app": "org.chromium.linux",
            "X-subtype": app_id,
            "device": chk["androidId"],
            # "sender": urlsafe_base64(GCM_SERVER_KEY),
            "sender": GCM_SERVER_KEY_B64,
        }
        if log_debug_verbose:
            _logger.debug("GCM Registration request: %s", body)

        auth = "AidLogin {}:{}".format(chk["androidId"], chk["securityToken"])
        last_error: Optional[Union[str, Exception]] = None
        for try_num in range(retries):
            try:
                async with self._session.post(
                    url=GCM_REGISTER_URL,
                    headers={"Authorization": auth},
                    data=body,
                    timeout=2,
                ) as resp:
                    response_text = await resp.text()
                if "Error" in response_text:
                    _logger.warning(
                        "GCM register request attempt %s out of %s has failed with %s",
                        try_num + 1,
                        retries,
                        response_text,
                    )
                    last_error = response_text
                    await asyncio.sleep(1)
                    continue
                token = response_text.split("=")[1]
                # get only the fields we need from the check in response
                chkfields = {k: chk[k] for k in ["androidId", "securityToken"]}
                res = {"token": token, "appId": app_id}
                res.update(chkfields)
                return res
            except Exception as e:
                last_error = e
                _logger.warning(
                    "Error during gcm auth request attempt %s out of %s",
                    try_num + 1,
                    retries,
                    exc_info=e,
                )
                await asyncio.sleep(1)

        errorstr = f"Unable to complete gcm auth request after {retries} tries"
        if isinstance(last_error, Exception):
            _logger.error(errorstr, exc_info=last_error)
        else:
            errorstr += f", last error was {last_error}"
            _logger.error(errorstr)
        return None

    async def fcm_register(
        self,
        sender_id: int,
        token: str,
        retries: int = 5,
        log_debug_verbose: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        generates key pair and obtains a fcm token

        sender_id: sender id as an integer
        token: the subscription token in the dict returned by gcm_register

        returns {"keys": keys, "fcm": {...}}
        """
        # I used this analyzer to figure out how to slice the asn1 structs
        # https://lapo.it/asn1js
        # first byte of public key is skipped for some reason
        # maybe it's always zero

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        serialized_private = private_key.private_bytes(
            encoding=serialization.Encoding.DER,  # asn1
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        keys = {
            "public": urlsafe_b64encode(serialized_public[26:]).decode(
                "ascii"
            ),  # urlsafe_base64(serialized_public[26:]),
            "private": urlsafe_b64encode(serialized_private).decode("ascii"),
            "secret": urlsafe_b64encode(os.urandom(16)).decode("ascii"),
        }
        data = {
            "authorized_entity": sender_id,
            "endpoint": f"{FCM_SEND_URL}/{token}",
            "encryption_key": keys["public"],
            "encryption_auth": keys["secret"],
        }
        if log_debug_verbose:
            _logger.debug("FCM registration data: %s", data)

        for try_num in range(retries):
            try:
                async with self._session.post(
                    url=FCM_SUBSCRIBE_URL,
                    data=data,
                    timeout=2,
                ) as resp:
                    fcm = await resp.json()
                return {"keys": keys, "fcm": fcm}
            except Exception as e:
                _logger.error(  # pylint: disable=duplicate-code
                    "Error during fmc register request attempt %s out of %s",
                    try_num + 1,
                    retries,
                    exc_info=e,
                )
                await asyncio.sleep(1)
        return None

    async def checkin(self, sender_id: int, app_id: str) -> Dict[str, Any]:
        """Check in if you have credentials otherwise register as a new client.

        :param sender_id: sender id identifying push service you are connecting to.
        :param app_id: identifier for your application.
        :return: The FCM token which is used to identify you with the push end
            point application.
        """
        self.sender_id = sender_id
        self.app_id = app_id
        if self.credentials:
            gcm_response = await self.gcm_check_in(
                self.credentials["gcm"]["androidId"],
                self.credentials["gcm"]["securityToken"],
                log_debug_verbose=self._log_debug_verbose,
            )
            if gcm_response:
                return self.credentials

        self.credentials = await self.register(sender_id, app_id)
        if self.credentials_updated_callback:
            self.credentials_updated_callback(self.credentials)

        return self.credentials

    async def register(self, sender_id: int, app_id: str) -> Dict:
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
        subscription = await self.gcm_register(
            app_id=app_id, log_debug_verbose=self._log_debug_verbose
        )
        if subscription is None:
            raise RuntimeError(
                "Unable to establish subscription with Google Cloud Messaging."
            )
        self._log_verbose("GCM subscription: %s", subscription)
        fcm = await self.fcm_register(
            sender_id=sender_id,
            token=subscription["token"],
            log_debug_verbose=self._log_debug_verbose,
        )
        if not fcm:
            raise RuntimeError("Unable to register with fcm")
        self._log_verbose("FCM registration: %s", fcm)
        res: Dict[str, Any] = {"gcm": subscription}
        res.update(fcm)
        self._log_verbose("Credential: %s", res)
        _logger.info("Registered with FCM")
        return res

    def _log_verbose(self, msg: str, *args: object) -> None:
        if self._log_debug_verbose:
            _logger.debug(msg, *args)

    @property
    def _session(self) -> ClientSession:
        if self._http_client_session:
            return self._http_client_session
        if self._local_session is None:
            self._local_session = ClientSession()
        return self._local_session

    async def close(self) -> None:
        """Close aiohttp session."""
        session = self._local_session
        self._local_session = None
        if session:
            await session.close()
