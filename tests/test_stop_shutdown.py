"""Regression tests for FcmPushClient.stop() clean shutdown.

Reproduces the Home Assistant symptom: a _listen task parked on
reader.readexactly() that stop() cancels-without-awaiting and without closing
the socket, so the caller sees a task that "could not be canceled after
shutdown". No FCM servers required — a loopback socket pair stands in for the
push connection.

Run:  cd firebase-messaging && . .venv/bin/activate && python -m tests.test_stop_shutdown
"""

from __future__ import annotations

import asyncio
import time

from firebase_messaging.fcmpushclient import FcmPushClient, FcmPushClientRunState


async def _connected_pair():
    """Return (reader, writer, server) for a live loopback connection."""
    async def _accept(_r, _w):
        # Server never sends, so the client read blocks — exactly like a quiet
        # FCM push channel. The handler ends when the client disconnects, so
        # server.wait_closed() (which waits on handlers in py3.13+) can return.
        try:
            await _r.read()  # unblocks with EOF once the client closes its side
        finally:
            _w.close()

    server = await asyncio.start_server(_accept, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    return reader, writer, server


def _make_client(reader=None, writer=None, tasks=None, stopping_lock=True):
    """Build a bare client with only the attributes stop() touches."""
    c = object.__new__(FcmPushClient)
    c.stopping_lock = asyncio.Lock() if stopping_lock else None
    c.run_state = FcmPushClientRunState.STARTED
    c.do_listen = True
    c.tasks = tasks or []
    c.reader = reader
    c.writer = writer
    c.fcm_thread = None
    c.listen_event_loop = None
    return c


async def _case_stop_unblocks_and_awaits():
    reader, writer, server = await _connected_pair()
    # A task parked on the read, just like _listen().
    parked = asyncio.create_task(reader.readexactly(10))
    await asyncio.sleep(0.05)  # ensure it is actually blocked on the read
    assert not parked.done(), "precondition: task should be blocked on read"

    client = _make_client(reader=reader, writer=writer, tasks=[parked])

    start = time.monotonic()
    await asyncio.wait_for(client.stop(), timeout=3)  # must not hang
    elapsed = time.monotonic() - start

    assert parked.done(), "stop() must await the cancelled task to completion"
    assert client.writer is None, "stop() must close the socket"
    assert client.run_state is FcmPushClientRunState.STOPPED
    assert elapsed < 2, f"stop() took too long: {elapsed:.2f}s"
    server.close()
    await server.wait_closed()


async def _case_stop_before_start_no_crash():
    # stop() called on a client that never start()ed (stopping_lock is None).
    client = _make_client(stopping_lock=False)
    await asyncio.wait_for(client.stop(), timeout=2)
    assert client.run_state is FcmPushClientRunState.STOPPED


async def _case_stop_idempotent():
    reader, writer, server = await _connected_pair()
    parked = asyncio.create_task(reader.readexactly(10))
    await asyncio.sleep(0.05)
    client = _make_client(reader=reader, writer=writer, tasks=[parked])
    await asyncio.wait_for(client.stop(), timeout=3)
    # Second call is a no-op and must not raise.
    await asyncio.wait_for(client.stop(), timeout=2)
    server.close()
    await server.wait_closed()


CASES = [
    _case_stop_unblocks_and_awaits,
    _case_stop_before_start_no_crash,
    _case_stop_idempotent,
]


def main():
    failures = 0
    for case in CASES:
        name = case.__name__
        try:
            asyncio.run(case())
            print(f"PASS  {name}")
        except Exception as exc:  # noqa: BLE001 - test runner
            failures += 1
            print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{'OK' if not failures else 'FAILED'} — {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
