import logging
import time
from typing import Optional

import requests
from google.protobuf.json_format import MessageToDict, MessageToJson

from .const import GCM_CHECKIN_URL, GCM_REGISTER_URL, GCM_SERVER_KEY_B64
from .proto.android_checkin_pb2 import (  # pylint: disable=no-name-in-module
    AndroidCheckinProto,
    ChromeBuildProto,
)
from .proto.checkin_pb2 import (  # pylint: disable=no-name-in-module
    AndroidCheckinRequest,
    AndroidCheckinResponse,
)

_logger = logging.getLogger(__name__)


def _get_checkin_payload(
    android_id: Optional[int] = None, security_token: Optional[int] = None
):
    chrome = ChromeBuildProto()
    chrome.platform = 3
    chrome.chrome_version = "63.0.3234.0"
    chrome.channel = 1

    checkin = AndroidCheckinProto()
    checkin.type = 3
    checkin.chrome_build.CopyFrom(chrome)

    payload = AndroidCheckinRequest()
    payload.user_serial_number = 0
    payload.checkin.CopyFrom(checkin)
    payload.version = 3
    if android_id and security_token:
        payload.id = int(android_id)
        payload.security_token = int(security_token)

    return payload


def gcm_check_in(
    android_id: Optional[int] = None,
    security_token: Optional[int] = None,
    log_debug_verbose=False,
):
    """
    perform check-in request

    android_id, security_token can be provided if we already did the initial
    check-in

    returns dict with android_id, security_token and more
    """

    payload = _get_checkin_payload(android_id, security_token)

    if log_debug_verbose:
        _logger.debug("GCM check in payload:\n%s", payload)

    retries = 3
    acir = None
    for try_num in range(retries):
        try:
            resp = requests.post(
                url=GCM_CHECKIN_URL,
                headers={"Content-Type": "application/x-protobuf"},
                data=payload.SerializeToString(),
                timeout=2,
            )
            if resp.status_code == 200:
                acir = AndroidCheckinResponse()
            else:
                _logger.warning(
                    "GCM checkin failed on attempt %s out of %s with status: %s, %s",
                    try_num + 1,
                    retries,
                    resp.status_code,
                    resp.text,
                )
                # retry without android id and security_token
                payload = _get_checkin_payload()
                time.sleep(1)
        except Exception as e:
            _logger.warning(
                "Error during gcm checkin post attempt %s out of %s",
                try_num + 1,
                retries,
                exc_info=e,
            )
            time.sleep(1)

    if not acir:
        _logger.error("Unable to checkin to gcm after %s retries", retries)
        return None

    acir.ParseFromString(resp.content)

    if log_debug_verbose:
        msg = MessageToJson(acir, indent=4)
        _logger.debug("GCM check in response (raw):\n%s", msg)

    return MessageToDict(acir)


def gcm_register(app_id: str, retries=5, log_debug_verbose=False):
    """
    obtains a gcm token

    app_id: app id as an integer
    retries: number of failed requests before giving up

    returns {"token": "...", "appId": 123123, "androidId":123123,
                     "securityToken": 123123}
    """
    # contains android_id, security_token and more
    chk = gcm_check_in(log_debug_verbose=log_debug_verbose)

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
    last_error = None
    for try_num in range(retries):
        try:
            resp = requests.post(
                url=GCM_REGISTER_URL,
                headers={"Authorization": auth},
                data=body,
                timeout=2,
            )
            resp_data = resp.text
            if "Error" in resp_data:
                _logger.warning(
                    "GCM register request attempt %s out of %s has failed with %s",
                    try_num + 1,
                    retries,
                    resp_data,
                )
                last_error = resp_data
                time.sleep(1)
                continue
            token = resp_data.split("=")[1]
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
            time.sleep(1)

    errorstr = f"Unable to complete gcm auth request after {retries} tries"
    if isinstance(last_error, Exception):
        _logger.error(errorstr, exc_info=last_error)
    else:
        errorstr += f", last error was {last_error}"
        _logger.error(errorstr)
    return None
