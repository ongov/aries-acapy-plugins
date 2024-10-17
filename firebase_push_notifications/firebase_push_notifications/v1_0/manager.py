"""This module contains the logic for sending push notifications to the user's device using the Firebase Cloud Messaging service."""  # noqa: E501

import json
import logging
import os
from datetime import timedelta

import google.auth.transport.requests
import requests
from acapy_agent.messaging.util import datetime_now, time_now
from acapy_agent.storage.base import StorageNotFoundError
from dateutil import parser
from google.oauth2 import service_account

from .constants import (
    BASE_URL,
    ENDPOINT_PREFIX,
    ENDPOINT_SUFFIX,
    MAX_SEND_RATE_MINUTES,
    SCOPES,
)
from .models import FirebaseConnectionRecord

PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "")
FCM_ENDPOINT = ENDPOINT_PREFIX + PROJECT_ID + ENDPOINT_SUFFIX
FCM_URL = BASE_URL + "/" + FCM_ENDPOINT

LOGGER = logging.getLogger(__name__)


def _get_access_token():
    """Gets an access token for sending firebase messages with the service account credentials."""  # noqa: E501
    credentials = service_account.Credentials.from_service_account_info(
        json.loads(os.environ.get("FIREBASE_SERVICE_ACCOUNT")), scopes=SCOPES
    )
    request = google.auth.transport.requests.Request()
    credentials.refresh(request)
    return credentials.token


async def send_message(profile, connection_id):
    """Attempt to send a push notification to the device associated with the connection id if passes the following checks."""  # noqa: E501
    headers = {
        "Authorization": "Bearer " + _get_access_token(),
        "Content-Type": "application/json; UTF-8",
    }

    async with profile.session() as session:
        record = None
        try:
            record = await FirebaseConnectionRecord.retrieve_by_connection_id(
                session, connection_id
            )
        except StorageNotFoundError:
            return

        """ Don't send token if it is blank. This is the same as being disabled """
        if not record or record.device_token == "":
            return

        """ 
            To avoid spamming the user with push notifications, 
            we will only send a push notification if the last one 
            was sent more than MAX_SEND_RATE_MINUTES minutes ago. 
        """
        if record.sent_time is not None and parser.parse(
            record.sent_time
        ) > datetime_now() - timedelta(minutes=MAX_SEND_RATE_MINUTES):
            LOGGER.debug(
                f"Connection {connection_id} was sent a push notification within the last {MAX_SEND_RATE_MINUTES} minutes. Skipping."  # noqa: E501
            )
            return

        LOGGER.debug(
            f"Sending push notification to firebase from connection: {connection_id}"
        )

        resp = requests.post(
            FCM_URL,
            data=json.dumps(
                {
                    "message": {
                        "token": record.device_token,
                        "notification": {
                            "title": os.environ.get("FIREBASE_NOTIFICATION_TITLE"),
                            "body": os.environ.get("FIREBASE_NOTIFICATION_BODY"),
                        },
                        "apns": {
                            "payload": {
                                "aps": {
                                    "alert": {
                                        "title": os.environ.get(
                                            "FIREBASE_NOTIFICATION_TITLE"
                                        ),
                                        "body": os.environ.get(
                                            "FIREBASE_NOTIFICATION_BODY"
                                        ),
                                    },
                                    "badge": 1,
                                }
                            }
                        },
                    }
                }
            ),
            headers=headers,
        )

        if resp.status_code == 200:
            LOGGER.debug(
                f"Successfully sent message to firebase for delivery. response: {resp.text}"  # noqa: E501
            )
            record.sent_time = time_now()
            await record.save(session, reason="Sent push notification")
        else:
            LOGGER.error(f"Unable to send message to Firebase. response: {resp.text}")


async def save_device_token(profile, token, connection_id):
    """Save or update the device token for the connection id."""
    conn_token_obj = {
        "connection_id": connection_id,
        "device_token": token,
    }

    LOGGER.info(f"Saving device token for connection: {connection_id}")

    conn_token_record: FirebaseConnectionRecord = FirebaseConnectionRecord.deserialize(
        conn_token_obj
    )

    try:
        async with profile.session() as session:
            records = await FirebaseConnectionRecord.query(
                session,
                {"connection_id": connection_id},
            )

            if len(records) == 0:
                await conn_token_record.save(session, reason="Saving device token")
            elif records[0].device_token != token:
                records[0].device_token = token
                await records[0].save(session, reason="Updating device token")
    except Exception as e:
        LOGGER.error(f"Error saving device token for connection: {connection_id}")
        LOGGER.error(e)
