import logging
import os
import sys
import time

import boto3
from aws_typings import LambdaContext
from aws_typings import LambdaDict
from slack_notifications import SlackNotificationSetup
from botocore.exceptions import ClientError

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


ec2_client = boto3.client("ec2", region_name="eu-west-2")
ec2_resource = boto3.resource("ec2", region_name="eu-west-2")
ssm_client = boto3.client("ssm", region_name="eu-west-2")


def get_all_ebs_volumes(ec2_resource, error_handler):
    try:
        list_of_volumes = ec2_resource.volumes.all()
        return list_of_volumes
    except ClientError as botocore_exception:
        LOGGER.error(f"Unable to retrieve list of volumes: {botocore_exception}")
        error_handler()


def get_ebs_volume_id(component, list_of_volumes, error_handler):
    for volume in list_of_volumes:
        if volume.tags is None:
            continue
        else:
            dict_of_tags = {x["Key"]: x["Value"] for x in volume.tags}
            try:
                if dict_of_tags["Component"] == component:
                    ebs_volume_id = volume.id
                    LOGGER.info(f"Retrieved EBS volume id of {ebs_volume_id}")
                    return ebs_volume_id
            except KeyError:
                continue

    LOGGER.error("No volume ID found for the orchestrator component")
    error_handler()


def create_snapshot_from_ebs_volume(
    component, ebs_volume_id, ec2_resource, ec2_client, error_handler
):
    try:
        snapshot_id = ec2_resource.create_snapshot(
            Description=f"Snapshot from {component} ebs volume {ebs_volume_id}",
            VolumeId=ebs_volume_id,
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [{"Key": "Name", "Value": component}],
                }
            ],
        )
    except ClientError as botocore_exception:
        LOGGER.error(f"Failed to create snapshot: {botocore_exception}")
        error_handler()

    LOGGER.info(f"Created new snapshot id of {snapshot_id.id}")

    try:
        wait_for_new_snapshot_to_become_available(
            component=component, ec2_client=ec2_client, snapshot_id=snapshot_id.id
        )
    except ClientError as botocore_exception:
        LOGGER.error(f"Failed to check snapshot status: {botocore_exception}")
        error_handler()


def wait_for_new_snapshot_to_become_available(
    component,
    ec2_client,
    error_handler,
    snapshot_id,
    desired_state="completed",
    max_retries=45,
    timeout=60,
):
    retry_count = 1

    while retry_count <= max_retries:
        snapshot_state = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])

        if snapshot_state["Snapshots"][0]["State"] == desired_state:
            LOGGER.info(f"{snapshot_id} is now available")
            return True
        else:
            LOGGER.info(
                f"State is not yet in the desired state of {desired_state}, retry_count={retry_count}"
            )
            LOGGER.info(f"Current state is: {snapshot_state['Snapshots'][0]['State']}")
            retry_count += 1
            time.sleep(timeout)

    LOGGER.error(
        f"Failed to create new {component} snapshot within timeout of {max_retries} minutes"
    )
    error_handler()


def identify_stale_snapshots(
    component, ec2_client, snapshot_retention_count, error_handler
):
    try:
        component_snapshots = ec2_client.describe_snapshots(
            Filters=[{"Name": "tag:Name", "Values": [component]}]
        )
    except ClientError as botocore_exception:
        LOGGER.error(f"Failed to obtain snapshots data: {botocore_exception}")
        error_handler()

    component_snapshots_data = component_snapshots["Snapshots"]

    sorted_component_snapshots = sorted(
        component_snapshots_data, key=lambda i: (i["StartTime"]), reverse=True
    )
    snapshots_to_remove = sorted_component_snapshots[snapshot_retention_count:]
    return snapshots_to_remove


def delete_stale_snapshots(ec2_client, snapshots_to_remove, error_handler):
    if len(snapshots_to_remove) == 0:
        LOGGER.info("No snapshots to delete")
    else:
        for snapshot in snapshots_to_remove:
            try:
                LOGGER.info(f"Attempting to delete snapshot {snapshot['SnapshotId']}")
                ec2_client.delete_snapshot(SnapshotId=snapshot["SnapshotId"])
                LOGGER.info(f"Successfully deleted snapshot {snapshot['SnapshotId']}")
            except ClientError as botocore_exception:
                LOGGER.error(f"Failed to remove snapshot: {botocore_exception}")
                error_handler()


def get_password_from_ssm(ssm_client, parameter_name, error_handler):
    try:
        ssm_response = ssm_client.get_parameter(
            Name=parameter_name, WithDecryption=True
        )
        password = ssm_response["Parameter"]["Value"]
    except ssm_client.exceptions.ParameterNotFound:
        LOGGER.warning("{} does not exist in ssm".format(parameter_name))
        error_handler()
    return password


def send_slack_notification_and_exit(slack_notification):
    slack_notifications_password = get_password_from_ssm(
        ssm_client=ssm_client,
        parameter_name="/ebs-snapshot-lambda/slack-notifications-password",
    )
    slack_notification.send_notification(
        slack_url="https://slack-notifications.tax.service.gov.uk/slack-notifications/notification",
        slack_notifications_password=slack_notifications_password,
        slack_channel="alerts-build-deploy",
    )
    sys.exit(1)


def lambda_handler(event: LambdaDict, context: LambdaContext):
    """
    Creates a snapshot for a given component, using the appropriate volume ID. Also checks for and removes
    any stale snapshots for the given component
    """
    component = os.getenv("component")
    snapshot_retention_count = int(os.getenv("snapshot_retention_count"))
    slack_notification = SlackNotificationSetup()
    error_handler = send_slack_notification_and_exit(slack_notification)
    list_of_volumes = get_all_ebs_volumes(
        ec2_resource=ec2_resource, error_handler=error_handler
    )
    ebs_volume_id = get_ebs_volume_id(
        component=component,
        list_of_volumes=list_of_volumes,
        error_handler=error_handler,
    )
    create_snapshot_from_ebs_volume(
        component=component,
        ebs_volume_id=ebs_volume_id,
        ec2_resource=ec2_resource,
        ec2_client=ec2_client,
        error_handler=error_handler,
    )
    snapshots_to_remove = identify_stale_snapshots(
        component=component,
        ec2_client=ec2_client,
        error_handler=error_handler,
        snapshot_retention_count=snapshot_retention_count,
    )
    delete_stale_snapshots(
        ec2_client=ec2_client,
        snapshots_to_remove=snapshots_to_remove,
        error_handler=error_handler,
    )
