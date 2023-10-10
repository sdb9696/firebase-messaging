# push-receiver

A library to subscribe to GCM/FCM and receive notifications within a python application.

## When should I use `push-receiver` ?

- I want to **receive** push notifications sent using Firebase Cloud Messaging in a python application.

## When should I not use `push-receiver` ?

- I want to **send** push notifications (use the firebase SDK instead)
- My application is running on a FCM supported platform (Android, iOS, Web).

## Install

`
pip install pushreceiver
`

## Requirements

- Firebase sender id to receive notification
- Firebase serverKey to send notification (optional)

## Usage

```python
from push_receiver import PushReceiver

def on_notification(obj, notification, data_message):
    # Do something with the notification
    pass

pr = PushReceiver(None)
pr.connect(sender_id, app_id)
pr.start_listener(YOUR_NOTIFICATION_CALLBACK)

```

## Attribution

Code originally based on typescript/node implementation by
[Matthieu Lemoine](https://github.com/MatthieuLemoine/push-receiver). 
See [this blog post](https://medium.com/@MatthieuLemoine/my-journey-to-bring-web-push-support-to-node-and-electron-ce70eea1c0b0) for more details.

Converted to python by 
[lolisamurai](https://github.com/Francesco149/push_receiver)

http decryption logic in decrypt.py by 
[Martin Thomson](https://github.com/web-push-libs/encrypted-content-encoding)
