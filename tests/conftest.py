"""Test configuration for the Ring platform."""

import asyncio
import json
import logging
import os
import threading
from unittest.mock import patch

import pytest
from aioresponses import CallbackResult, aioresponses
from google.protobuf.json_format import Parse as JsonParse

from firebase_messaging.fcmpushclient import (
    FcmPushClient,
    FcmPushClientConfig,
    FcmRegisterConfig,
)
from firebase_messaging.proto.checkin_pb2 import AndroidCheckinResponse
from firebase_messaging.proto.mcs_pb2 import LoginResponse
from tests.fakes import FakeMcsEndpoint


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
    fmce = FakeMcsEndpoint()

    async def _mock_open_conn(*_, **__):
        return fmce.client_reader, fmce.client_writer

    with patch("asyncio.open_connection", side_effect=_mock_open_conn, autospec=True):
        yield fmce

    fmce.close()


@pytest.fixture()
async def logged_in_push_client(request, fake_mcs_endpoint, mocker, caplog):
    clients = {}
    caplog.set_level(logging.DEBUG)

    async def _logged_in_push_client(
        msg_callback,
        credentials,
        *,
        callback_obj=None,
        supress_disconnect=False,
        **config_kwargs,
    ):
        config = FcmPushClientConfig(**config_kwargs)
        fcm_config = FcmRegisterConfig("project-1234", "bar", "foobar", "foobar")
        pr = FcmPushClient(
            msg_callback,
            fcm_config,
            credentials,
            None,
            callback_context=callback_obj,
            config=config,
        )
        await pr.checkin_or_register()

        await pr.start()

        await fake_mcs_endpoint.get_message()
        lr = load_fixture_as_msg("login_response.json", LoginResponse)
        await fake_mcs_endpoint.put_message(lr)
        clients[pr] = supress_disconnect

        return pr

    yield _logged_in_push_client

    for k, v in clients.items():
        if not v:
            await k.stop()


@pytest.fixture(autouse=True, name="aioresponses_mock")
def aioresponses_mock_fixture():
    with aioresponses() as mock:
        mock.post(
            "https://android.clients.google.com/checkin",
            body=load_fixture_as_msg(
                "android_checkin_response.json", AndroidCheckinResponse
            ).SerializeToString(),
        )
        mock.post(
            "https://android.clients.google.com/c2dm/register3",
            body=load_fixture("gcm_register_response.txt"),
        )
        mock.post(
            "https://firebaseinstallations.googleapis.com/v1/projects/project-1234/installations",
            payload=load_fixture_as_dict("fcm_install_response.json"),
        )
        mock.post(
            "https://fcmregistrations.googleapis.com/v1/projects/project-1234/registrations",
            payload=load_fixture_as_dict("fcm_register_response.json"),
        )
        yield mock
