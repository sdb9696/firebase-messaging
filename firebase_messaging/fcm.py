import logging
import os
import time
from base64 import urlsafe_b64encode

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .const import FCM_SEND_URL, FCM_SUBSCRIBE_URL

_logger = logging.getLogger(__name__)


def fcm_register(sender_id, token, retries=5, log_debug_verbose=False):
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
            resp = requests.post(
                url=FCM_SUBSCRIBE_URL,
                data=data,
                timeout=2,
            )
            fcm = resp.json()
            return {"keys": keys, "fcm": fcm}
        except Exception as e:
            _logger.error(  # pylint: disable=duplicate-code
                "Error during fmc register request attempt %s out of %s",
                try_num + 1,
                retries,
                exc_info=e,
            )
            time.sleep(1)
    return None
