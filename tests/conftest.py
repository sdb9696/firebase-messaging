"""Test configuration for the Ring platform."""
import pytest
import requests_mock
import threading
import os
import select
from unittest.mock import MagicMock, DEFAULT, Mock, patch
import asyncio
import time
import logging
import ssl as ssl_lib
import socket
from google.protobuf.json_format import Parse as JsonParse
from firebase_messaging.proto.mcs_pb2 import LoginResponse
from firebase_messaging.proto.checkin_pb2 import *
from firebase_messaging.fcmpushclient import MCS_VERSION, MCS_MESSAGE_TAG, FcmPushClient, FcmPushClientConfig
from tests.fakes import *
import json


def load_fixture(filename):
    """Load a fixture."""
    path = os.path.join(os.path.dirname(__file__), "fixtures", filename)
    with open(path) as fdp:
        return fdp.read()
    
def load_fixture_as_dict(filename):
    """Load a fixture."""
    return json.loads(load_fixture(filename))

def load_fixture_as_msg(filename, msg_class):
    """Load a fixture."""
    msg = msg_class()
    JsonParse(load_fixture(filename), msg)
    return msg
    
                
@pytest.fixture()
async def fake_mcs_endpoint():
    #async with McsEndpoint() as ep:
    ep = FakeMcsEndpoint() 
    yield ep
    
    ep.close()
    

@pytest.fixture(params=[None, "loop"], ids=["loop_created", "loop_provided"])
async def logged_in_push_client(request, fake_mcs_endpoint, mocker, caplog):

    clients = {}
    caplog.set_level(logging.DEBUG)

    listen_loop = asyncio.get_running_loop() if request.param else None
    async def _logged_in_push_client(credentials, msg_callback, callback_obj = None, callback_loop=None, *, supress_disconnect=False, **config_kwargs):

        config = FcmPushClientConfig(**config_kwargs)
        pr = FcmPushClient(credentials=credentials, config=config)
        pr.checkin(1234, 4321)

        cb_loop = asyncio.get_running_loop() if callback_loop else None
        pr.start(msg_callback, callback_obj, listen_event_loop=listen_loop, callback_event_loop=cb_loop)

        msg = await fake_mcs_endpoint.get_message()
        lr = load_fixture_as_msg("login_response.json", LoginResponse)
        await fake_mcs_endpoint.put_message(lr)
        clients[pr] = supress_disconnect

        tc = 1 if listen_loop else 2
        assert len(threading.enumerate()) == tc
        if listen_loop:
            assert pr.listen_event_loop == asyncio.get_running_loop()
        else:
            assert pr.listen_event_loop != asyncio.get_running_loop()
        return pr

    yield _logged_in_push_client
    
    for k, v in clients.items():
        if not v:
            k.stop()

# setting the fixture name to requests_mock allows other
# tests to pull in request_mock and append uris
@pytest.fixture(autouse=True, name="requests_mock")
def requests_mock_fixture():
    with requests_mock.Mocker() as mock:
        mock.post(
            "https://android.clients.google.com/checkin", 
            content = load_fixture_as_msg("android_checkin_response.json", AndroidCheckinResponse).SerializeToString()
        )
        mock.post(
            'https://android.clients.google.com/c2dm/register3', 
            text=load_fixture("gcm_register_response.txt"),
        )
        mock.post(
            'https://fcm.googleapis.com/fcm/connect/subscribe', 
            json=load_fixture_as_dict("fcm_register_response.json"),

        ) 
        yield mock

