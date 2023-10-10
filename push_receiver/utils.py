import logging
import time
from base64 import urlsafe_b64encode
import requests


__log = logging.getLogger("push_receiver")


def request(req, retries=5):
    session = requests.Session()
    for _ in range(retries):
        try:
            prep = req.prepare()
            resp = session.send(prep)
            return resp.content
        except Exception as e:
            __log.debug("error during request", exc_info=e)
            time.sleep(1)
    return None


def urlsafe_base64(data):
    """
    base64-encodes data with -_ instead of +/ and removes all = padding.
    also strips newlines

    returns a string
    """
    res = urlsafe_b64encode(data).replace(b"=", b"")
    return res.replace(b"\n", b"").decode("ascii")
