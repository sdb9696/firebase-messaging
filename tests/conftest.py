"""Test configuration for the Ring platform."""
import pytest
import requests_mock



# setting the fixture name to requests_mock allows other
# tests to pull in request_mock and append uris
@pytest.fixture(autouse=True, name="requests_mock")
def requests_mock_fixture():
    with requests_mock.Mocker() as mock:
        mock.post(
            "https://android.clients.google.com/checkin", 
            content = b'\x08\x01\x18\x8d\xf7\x96\xd0\xb119\xb2[M\x83#\t\x01NA\xd8\xdc\xfd\xc7X{\xb8\x07Z\x1fM0mOUxOA6n8WQKri541rkWWluFugsRgb\xf7\x01ABFEt1WlxZM7sJbV2-xwt7mAJmKcP-I1R-Rpx9djK5M83hp7Id_O0qvy8NyrV4hs3-9WaS5kZyNvHmbH6Vy0BkAqRYn2iNF_AM3_Fu49p7Mk_rHNJcTAhe3wlP7vWYyncJF-vxxiigLugrAGHnVR0qbO1xsHS11Qc-r1-N-oho8XfxcoXPQ9cKwIAGnsKENlIwHUUu00EFC6eiBkoGzWc0ziN59FiMl7Wl9VaVuP1PnyebZ3KHH98IQ'

        )
        mock.post(
            'https://android.clients.google.com/c2dm/register3', 
            content = b'token=fSEvUy8-GCM-TOKEN-TmBDd6',
        )
        mock.post(
            'https://fcm.googleapis.com/fcm/connect/subscribe', 
            content = b'{\n  "token": "f8Xvk--FCM-TOKEN-JQdI5-MJb1pvxv",\n  "pushSet": "dd7axIZz--FCM-PUSHSET--LKCAcknrMkHvg9Z8qG-"\n}\n',

        ) 
        yield mock
