"""The tests for the Ring platform."""
import pytest


import requests_mock

from push_receiver import PushReceiver


def test_register(requests_mock):
    pr = PushReceiver(None)
    pr.connect(1234, 4321)
