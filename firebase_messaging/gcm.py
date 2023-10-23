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
    if android_id:
        payload.id = int(android_id)
    if security_token:
        payload.security_token = int(security_token)

    if log_debug_verbose:
        _logger.debug("GCM check in payload:\n%s", payload)

    resp = requests.post(
        url=GCM_CHECKIN_URL,
        headers={"Content-Type": "application/x-protobuf"},
        data=payload.SerializeToString(),
        timeout=2,
    )
    acir = AndroidCheckinResponse()
    if resp.status_code != 200:
        _logger.error("GCM check failed: %s", resp.text)
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
    for try_num in range(retries):
        # resp_data = request(req, retries)
        try:
            resp = requests.post(
                url=GCM_REGISTER_URL,
                headers={"Authorization": auth},
                data=body,
                timeout=2,
            )
            resp_data = resp.text
            if "Error" in resp_data:
                _logger.error(
                    "GCM register request attempt %s out of %s has failed with %s",
                    try_num + 1,
                    retries,
                    resp_data,
                )
                time.sleep(1)
                continue
            token = resp_data.split("=")[1]
            # get only the fields we need from the check in response
            chkfields = {k: chk[k] for k in ["androidId", "securityToken"]}
            res = {"token": token, "appId": app_id}
            res.update(chkfields)
            return res
        except Exception as e:
            _logger.error(
                "Error during gmc auth request attempt %s out of %s",
                try_num + 1,
                retries,
                exc_info=e,
            )
            time.sleep(1)

    return None
