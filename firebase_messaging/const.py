"""Constants module."""

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

GCM_REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
GCM_CHECKIN_URL = "https://android.clients.google.com/checkin"
GCM_SERVER_KEY_BIN = (
    b"\x04\x33\x94\xf7\xdf\xa1\xeb\xb1\xdc\x03\xa2\x5e\x15\x71\xdb\x48\xd3"
    + b"\x2e\xed\xed\xb2\x34\xdb\xb7\x47\x3a\x0c\x8f\xc4\xcc\xe1\x6f\x3c"
    + b"\x8c\x84\xdf\xab\xb6\x66\x3e\xf2\x0c\xd4\x8b\xfe\xe3\xf9\x76\x2f"
    + b"\x14\x1c\x63\x08\x6a\x6f\x2d\xb1\x1a\x95\xb0\xce\x37\xc0\x9c\x6e"
)
# urlsafe b64 encoding of the binary key with = padding removed
GCM_SERVER_KEY_B64 = (
    "BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoM"
    + "j8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4"
)

FCM_SUBSCRIBE_URL = "https://fcm.googleapis.com/fcm/connect/subscribe"
FCM_SEND_URL = "https://fcm.googleapis.com/fcm/send"

MCS_VERSION = 41
MCS_HOST = "mtalk.google.com"
MCS_PORT = 5228
MCS_SELECTIVE_ACK_ID = 12
MCS_STREAM_ACK_ID = 13

# MCS Message Types and Tags
MCS_MESSAGE_TAG = {
    HeartbeatPing: 0,
    HeartbeatAck: 1,
    LoginRequest: 2,
    LoginResponse: 3,
    Close: 4,
    "MessageStanza": 5,
    "PresenceStanza": 6,
    IqStanza: 7,
    DataMessageStanza: 8,
    "BatchPresenceStanza": 9,
    StreamErrorStanza: 10,
    "HttpRequest": 11,
    "HttpResponse": 12,
    "BindAccountRequest": 13,
    "BindAccountResponse": 14,
    "TalkMetadata": 15,
}
