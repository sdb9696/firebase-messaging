import logging
import time
from requests import Request

from google.protobuf.json_format import MessageToDict

from .proto.android_checkin_pb2 import (  # pylint: disable=no-name-in-module
    AndroidCheckinProto,
    ChromeBuildProto,
)
from .proto.checkin_pb2 import (  # pylint: disable=no-name-in-module
    AndroidCheckinRequest,
    AndroidCheckinResponse,
)
from .utils import request, urlsafe_base64

REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
CHECKIN_URL = "https://android.clients.google.com/checkin"
SERVER_KEY = (
    b"\x04\x33\x94\xf7\xdf\xa1\xeb\xb1\xdc\x03\xa2\x5e\x15\x71\xdb\x48\xd3"
    + b"\x2e\xed\xed\xb2\x34\xdb\xb7\x47\x3a\x0c\x8f\xc4\xcc\xe1\x6f\x3c"
    + b"\x8c\x84\xdf\xab\xb6\x66\x3e\xf2\x0c\xd4\x8b\xfe\xe3\xf9\x76\x2f"
    + b"\x14\x1c\x63\x08\x6a\x6f\x2d\xb1\x1a\x95\xb0\xce\x37\xc0\x9c\x6e"
)

__log = logging.getLogger("push_receiver")


def gcm_check_in(android_id=None, security_token=None):
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

    __log.debug("GCM check in payload:\n%s", payload)
    req = Request(
        "POST",
        url=CHECKIN_URL,
        headers={"Content-Type": "application/x-protobuf"},
        data=payload.SerializeToString(),
    )
    resp_data = request(req)
    resp = AndroidCheckinResponse()
    resp.ParseFromString(resp_data)
    __log.debug("GCM check in response (raw):\n%s", resp)
    return MessageToDict(resp)


def gcm_register(app_id, retries=5):
    """
    obtains a gcm token

    app_id: app id as an integer
    retries: number of failed requests before giving up

    returns {"token": "...", "appId": 123123, "androidId":123123,
                     "securityToken": 123123}
    """
    # contains android_id, security_token and more
    chk = gcm_check_in()
    __log.debug("GCM check in response %s", chk)
    body = {
        "app": "org.chromium.linux",
        "X-subtype": app_id,
        "device": chk["androidId"],
        "sender": urlsafe_base64(SERVER_KEY),
    }
    __log.debug("GCM Registration request: %s", body)
    auth = "AidLogin {}:{}".format(chk["androidId"], chk["securityToken"])
    req = Request("POST", url=REGISTER_URL, headers={"Authorization": auth}, data=body)
    for _ in range(retries):
        resp_data = request(req, retries)
        if b"Error" in resp_data:
            err = resp_data.decode("utf-8")
            __log.error("Register request has failed with %s", err)
            time.sleep(1)
            continue
        token = resp_data.decode("utf-8").split("=")[1]
        chkfields = {k: chk[k] for k in ["androidId", "securityToken"]}
        res = {"token": token, "appId": app_id}
        res.update(chkfields)
        return res
    return None
