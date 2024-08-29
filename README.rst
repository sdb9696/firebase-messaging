==================
Firebase Messaging
==================

.. image:: https://badge.fury.io/py/firebase-messaging.svg
    :alt: PyPI Version
    :target: https://badge.fury.io/py/firebase-messaging

.. image:: https://github.com/sdb9696/firebase-messaging/actions/workflows/ci.yml/badge.svg?branch=main
    :alt: Build Status
    :target: https://github.com/sdb9696/firebase-messaging/actions/workflows/ci.yml?branch=main

.. image:: https://coveralls.io/repos/github/sdb9696/firebase-messaging/badge.svg?branch=main
    :alt: Coverage
    :target: https://coveralls.io/github/sdb9696/firebase-messaging?branch=main

.. image:: https://readthedocs.org/projects/firebase-messaging/badge/?version=latest
    :alt: Documentation Status
    :target: https://firebase-messaging.readthedocs.io/?badge=latest

.. image:: https://img.shields.io/pypi/pyversions/firebase-messaging.svg
    :alt: Py Versions
    :target: https://pypi.python.org/pypi/firebase-messaging#

A library to subscribe to GCM/FCM and receive notifications within a python application.

When should I use `firebase-messaging` ?
----------------------------------------

- I want to **receive** push notifications sent using Firebase Cloud Messaging in a python application.

When should I not use `firebase-messaging` ?
--------------------------------------------

- I want to **send** push notifications (use the firebase SDK instead)
- My application is running on a FCM supported platform (Android, iOS, Web).

Install
-------

PyPi::

    $ pip install firebase-messaging


Requirements
------------

- Firebase sender id to receive notification
- Firebase serverKey to send notification (optional)

Usage
-----

python::

    from firebase_messaging import FcmPushClient

    def on_notification(obj, notification, data_message):
        # Do something with the notification
        pass

    pc = FcmPushClient(None)
    fcm_token = pc.checkin(sender_id, app_id)

    # Notify the service you're connecting to of your FCM token

    pc.start(YOUR_NOTIFICATION_CALLBACK)


Attribution
-----------

Code originally based on typescript/node implementation by
`Matthieu Lemoine <https://github.com/MatthieuLemoine/push-receiver>`_.
See `this blog post <https://medium.com/@MatthieuLemoine/my-journey-to-bring-web-push-support-to-node-and-electron-ce70eea1c0b0>`_ for more details.

Converted to python by
`lolisamurai <https://github.com/Francesco149/push_receiver>`_

http decryption logic in decrypt.py by
`Martin Thomson <https://github.com/web-push-libs/encrypted-content-encoding>`_
