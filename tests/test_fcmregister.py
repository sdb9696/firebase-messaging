from unittest.mock import AsyncMock

import pytest

from firebase_messaging import FcmRegisterConfig, FcmRegistrationError
from firebase_messaging.const import GCM_REGISTER_URL
from firebase_messaging.fcmregister import FcmRegister

GCM_OPTIONS = {"androidId": "123", "securityToken": "456"}


async def test_phone_registration_error_is_not_retried(aioresponses_mock, mocker):
    aioresponses_mock.clear()
    aioresponses_mock.post(
        GCM_REGISTER_URL, body="Error=PHONE_REGISTRATION_ERROR", repeat=True
    )
    sleep = mocker.patch("firebase_messaging.fcmregister.asyncio.sleep", AsyncMock())
    register = FcmRegister(FcmRegisterConfig("project", "app", "key", "sender"))

    try:
        with pytest.raises(FcmRegistrationError) as error:
            await register.gcm_register(GCM_OPTIONS)
    finally:
        await register.close()

    assert error.value.stage == "gcm_register"
    assert error.value.code == "PHONE_REGISTRATION_ERROR"
    assert error.value.retryable is False
    assert len(aioresponses_mock.requests) == 1
    assert len(next(iter(aioresponses_mock.requests.values()))) == 1
    sleep.assert_not_awaited()


async def test_retryable_provider_error_retains_details_after_retries(
    aioresponses_mock, mocker
):
    aioresponses_mock.clear()
    aioresponses_mock.post(
        GCM_REGISTER_URL, body="Error=SERVICE_NOT_AVAILABLE", repeat=True
    )
    sleep = mocker.patch("firebase_messaging.fcmregister.asyncio.sleep", AsyncMock())
    register = FcmRegister(FcmRegisterConfig("project", "app", "key", "sender"))

    try:
        with pytest.raises(FcmRegistrationError) as error:
            await register.gcm_register(GCM_OPTIONS)
    finally:
        await register.close()

    assert error.value.stage == "gcm_register"
    assert error.value.code == "SERVICE_NOT_AVAILABLE"
    assert error.value.retryable is True
    assert len(next(iter(aioresponses_mock.requests.values()))) == 4
    assert sleep.await_count == 3
