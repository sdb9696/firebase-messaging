"""The tests for the Ring platform."""
import pytest
import logging
import asyncio
import requests_mock
from unittest.mock import MagicMock
from firebase_messaging import FcmPushClient
from firebase_messaging.proto.mcs_pb2 import *
from tests.conftest import load_fixture_as_msg, load_fixture_as_dict
from http_ece import encrypt
from base64 import urlsafe_b64decode, standard_b64encode
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend



def test_register(requests_mock):
    pr = FcmPushClient(credentials=None)
    pr.checkin(1234, 4321)

async def test_no_disconnect(logged_in_push_client, fake_mcs_endpoint, mocker, caplog):

    
    pr = await logged_in_push_client(None, None, supress_disconnect=True)

    pr.__del__()
    await asyncio.sleep(0.1)
    assert len([record for record in caplog.records if record.levelname == "ERROR"]) == 0

    assert "FCMClient has shutdown" in [record.message for record in caplog.records if record.levelname == "INFO"] 


async def test_login(logged_in_push_client, fake_mcs_endpoint, mocker, caplog):

    pr = await logged_in_push_client(None, None)
    await asyncio.sleep(0.1)

    assert len([record for record in caplog.records if record.levelname == "ERROR"]) == 0
    assert "Succesfully logged in to MCS endpoint" in [record.message for record in caplog.records if record.levelname == "INFO"]    

@pytest.mark.parametrize("callback_loop", [None, "loop"], ids=["no_cb_loop_param", "cb_loop_param"])
async def test_data_message_receive(logged_in_push_client, fake_mcs_endpoint, mocker, caplog, callback_loop):

    notification = None
    persistent_id = None
    callback_obj = None
    cb_loop = None
    def on_msg(ntf, psid, obj=None):
        nonlocal notification
        nonlocal persistent_id
        nonlocal callback_obj
        nonlocal cb_loop
        notification = ntf
        persistent_id = psid
        callback_obj = obj
        cb_loop = asyncio.get_running_loop()

    credentials = load_fixture_as_dict("credentials.json")
    obj = "Foobar"
    cb_loop_param = asyncio.get_running_loop() if callback_loop else None
    pr = await logged_in_push_client(credentials, on_msg, obj, cb_loop_param)

    dms = load_fixture_as_msg("data_message_stanza.json", DataMessageStanza)
    await fake_mcs_endpoint.put_message(dms)
    msg = await fake_mcs_endpoint.get_message()
    assert isinstance(msg, IqStanza)
    await asyncio.sleep(0.1)
    assert len([record for record in caplog.records if record.levelname == "ERROR"]) == 0
    
    assert notification == {'foo': 'bar'}
    assert persistent_id == dms.persistent_id
    assert obj == callback_obj

    if callback_loop:
        assert cb_loop == asyncio.get_running_loop()
    else:
        assert cb_loop == pr.listen_event_loop
    

async def test_connection_reset(logged_in_push_client, fake_mcs_endpoint, mocker):
    #ConnectionResetError, TimeoutError, SSLError
    pr = await logged_in_push_client(None, None, abort_on_sequential_error_count=3, reset_interval=0.1)

    mocker.patch.object(FcmPushClient, "_reset", wraps=pr._reset)

    assert pr._reset.call_count == 0
    close = load_fixture_as_msg("close.json", Close)
    
    await fake_mcs_endpoint.put_error(ConnectionResetError())  
    
    await asyncio.sleep(0.1)
    assert pr._reset.call_count == 1
    
    msg = await fake_mcs_endpoint.get_message()
    assert isinstance(msg, LoginRequest)
    
@pytest.mark.parametrize("error_count", [1,2,3,6])
async def test_terminate(logged_in_push_client, fake_mcs_endpoint, mocker, error_count, caplog):
    #ConnectionResetError, TimeoutError, SSLError
    pr = await logged_in_push_client(None, None, abort_on_sequential_error_count=error_count, reset_interval=0)

    mocker.patch.object(FcmPushClient, "_reset", wraps=pr._reset)
    mocker.patch.object(FcmPushClient, "_terminate", wraps=pr._terminate)

    assert pr._reset.call_count == 0

    for i in range(1,error_count + 1):
        await fake_mcs_endpoint.put_error(ConnectionResetError())

        await asyncio.sleep(0.1)
        # client should reset while it gets errors < abort_on_sequential_error_count then it should terminate
        if i < error_count:
            assert pr._reset.call_count == i
            assert pr._terminate.call_count == 0
            msg = await fake_mcs_endpoint.get_message()
            assert isinstance(msg, LoginRequest)
        else:
            assert pr._reset.call_count == i - 1
            assert pr._terminate.call_count == 1


async def test_heartbeat_receive(logged_in_push_client, fake_mcs_endpoint, caplog):

    pr = await logged_in_push_client(None, None)

    ping = load_fixture_as_msg("heartbeat_ping.json", HeartbeatPing)
    await fake_mcs_endpoint.put_message(ping)

    msg = await fake_mcs_endpoint.get_message()
    assert isinstance(msg, HeartbeatAck)
    
    assert len([record for record in caplog.records if record.levelname == "ERROR"]) == 0

async def test_heartbeat_send(logged_in_push_client, fake_mcs_endpoint, mocker, caplog):

    pr : FcmPushClient = await logged_in_push_client(None, None)

    ping = load_fixture_as_msg("heartbeat_ping.json", HeartbeatPing)
    ack = load_fixture_as_msg("heartbeat_ack.json", HeartbeatAck)
    await pr._send_heartbeat()

    ping_msg = await fake_mcs_endpoint.get_message()

    await fake_mcs_endpoint.put_message(ack)
    await asyncio.sleep(0.1)
    assert isinstance(ping_msg, HeartbeatPing)
    
    assert len([record.message for record in caplog.records if record.levelname == "DEBUG" and "Received heartbeat ack" in record.message] ) == 1


async def test_decrypt():
    def get_app_data_by_key(msg, key):
        for x in msg.app_data:
            if x.key == key:
                return x.value
            
    def set_app_data_by_key(msg, key, value):
        for x in msg.app_data:
            if x.key == key:
                x.value = value
            
    dms = load_fixture_as_msg("data_message_stanza.json", DataMessageStanza)
    credentials = load_fixture_as_dict("credentials.json")
    raw_data = b'{ "foo" : "bar" }'
    salt_str = get_app_data_by_key(dms, "encryption")[5:]
    salt = urlsafe_b64decode(salt_str.encode("ascii"))

    
    # Random key pair
    sender_pub = 'BAGEFtID7WlmwzQ9pbjdRYAhfPe7Z8lA3ZGIPUh0SE3ikoY2PIrWUP0rmhpE4Kl8ImgMUDjKWrz0WmtLxORIHuw'
    
    sender_pri_der = urlsafe_b64decode('MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwSUpDfIqdJG3XVkn7t1GExHuW3gsqD4-J525w-rnCIihRANCAAQBhBbSA-1pZsM0PaW43UWAIXz3u2fJQN2RiD1IdEhN4pKGNjyK1lD9K5oaROCpfCJoDFA4ylq89FprS8TkSB7s'.encode("ascii") + b"========")
    sender_privkey = load_der_private_key(
            sender_pri_der, password=None, backend=default_backend()
        )

    sender_sec = urlsafe_b64decode(credentials["keys"]["secret"].encode("ascii") + b"========") 
    receiver_pub_key = urlsafe_b64decode(credentials["keys"]["public"].encode("ascii") + b"=")
    raw_data_encrypted = encrypt(
            raw_data,
            salt=salt,
            private_key=sender_privkey,
            dh=receiver_pub_key,
            version="aesgcm",
            auth_secret=sender_sec,
        )
    b64encode = standard_b64encode(raw_data_encrypted)
    set_app_data_by_key(dms, "crypto-key", "dh=" + sender_pub)

    raw_data_decrypted = FcmPushClient._decrypt_raw_data(credentials, sender_pub + "=", salt_str, raw_data_encrypted)

    assert raw_data_decrypted == raw_data

    

