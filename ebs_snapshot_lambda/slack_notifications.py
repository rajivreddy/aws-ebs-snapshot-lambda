#!/usr/bin/env python
import logging
import os

import requests

logging.basicConfig()
logger = logging.getLogger("slack_notification")
logger.setLevel("INFO")


class SlackNotificationSetup(object):
    def __init__(self):
        self.slack_url = "https://slack-notifications.tax.service.gov.uk/slack-notifications/notification"

    def send_notification(self, slack_url, slack_notifications_password, slack_channel):
        slack_client = SlackNotification()
        slack_client.create_ebs_snapshot_lambda_failure_notification(
            uri=slack_url,
            slack_notifications_password=slack_notifications_password,
            slack_channel=slack_channel,
        )


class SlackNotification(object):
    @staticmethod
    def post_request_to_slack(
        uri, payload, slack_notifications_password, slack_channel
    ):
        slack_notifications_username = "ebs-snapshot-lambda"
        slack_notifications_password = slack_notifications_password

        try:
            response = requests.post(
                url=uri,
                json=payload,
                headers={"Content-type": "application/json"},
                timeout=10,
                auth=requests.auth.HTTPBasicAuth(
                    slack_notifications_username, slack_notifications_password
                ),
            )
            response.raise_for_status()
            response_body = response.json()
            if response_body.get("errors") or response_body.get("exclusions"):
                logger.error("Slack error: {} {}").format(
                    response_body.get("errors"), response_body.get("exclusions")
                )
            if response.status_code == 200:
                logger.info(
                    "Slack notification successfully sent to {}".format(slack_channel)
                )
            else:
                logger.error(
                    "Error when attempting to send slack notification to {}: received {}".format(
                        slack_channel, response.status_code
                    )
                )
            return response
        except Exception as e:
            logger.error("Error: {}".format(e))

    def create_ebs_snapshot_lambda_failure_notification(
        self, uri, slack_notifications_password, slack_channel, color="#ff0000"
    ):
        environment = os.getenv("environment", "('environment' variable not set)")
        payload = {
            "channelLookup": {"by": "slack-channel", "slackChannels": [slack_channel]},
            "messageDetails": {
                "text": f"Encountered failure when running ebs-snapshot-lambda in {environment}",
                "username": "ebs-snapshot-lambda",
                "attachments": [
                    {
                        "fallback": f"Encountered failure when running ebs-snapshot-lambda in {environment}",
                        "color": color,
                        "title": f"Encountered failure when running ebs-snapshot-lambda in {environment}",
                        "fields": [
                            {
                                "title": "Message",
                                "value": f"Check cloudwatch logs for the ebs-snapshot-lambda in {environment} "
                                "to investigate cause of failure",
                                "short": False,
                            }
                        ],
                    }
                ],
            },
        }
        return self.post_request_to_slack(
            uri=uri,
            payload=payload,
            slack_notifications_password=slack_notifications_password,
            slack_channel=slack_channel,
        )
