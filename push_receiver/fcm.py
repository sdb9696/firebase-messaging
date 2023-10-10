import json
import logging
import os
from base64 import b64encode
from requests import Request

from oscrypto.asymmetric import generate_pair

from .utils import request, urlsafe_base64

FCM_SUBSCRIBE = "https://fcm.googleapis.com/fcm/connect/subscribe"
FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send"

__log = logging.getLogger("push_receiver")


def fcm_register(sender_id, token, retries=5):
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
    public, private = generate_pair("ec", curve=str("secp256r1"))

    if __log.isEnabledFor(logging.DEBUG):
        __log.debug(  # pylint: disable=logging-fstring-interpolation
            f"# public: {b64encode(public.asn1.dump())}"
        )
        __log.debug(  # pylint: disable=logging-fstring-interpolation
            f"# private: {b64encode(private.asn1.dump())}"
        )

    keys = {
        "public": urlsafe_base64(public.asn1.dump()[26:]),
        "private": urlsafe_base64(private.asn1.dump()),
        "secret": urlsafe_base64(os.urandom(16)),
    }
    data = {
        "authorized_entity": sender_id,
        "endpoint": "{}/{}".format(FCM_ENDPOINT, token),
        "encryption_key": keys["public"],
        "encryption_auth": keys["secret"],
    }
    __log.debug("FCM registration data: %s", data)
    req = Request("POST", url=FCM_SUBSCRIBE, data=data)
    resp_data = request(req, retries)
    return {"keys": keys, "fcm": json.loads(resp_data.decode("utf-8"))}
