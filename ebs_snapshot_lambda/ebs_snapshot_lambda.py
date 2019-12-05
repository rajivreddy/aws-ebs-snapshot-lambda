import argparse
import logging
import sys
import time

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)


def parse_arguments():
    description = "Arguments for creating a snapshot from an EBS volume"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--component",
        help="The name of the component you wish to create a snapshot from",
        dest="component",
        required=True,
    )
    parser.add_argument(
        "--snapshot_retention_count",
        help="The number of previous snapshots for the component to retain (defaults to zero)",
        dest="snapshot_retention_count",
        default=0,
        required=False,
    )
    return parser.parse_args()


def get_all_ebs_volumes(ec2_resource):
    try:
        list_of_volumes = ec2_resource.volumes.all()
        return list_of_volumes
    except ClientError as botocore_exception:
        logging.error(f"Unable to retrieve list of volumes: {botocore_exception}")
        sys.exit(1)


def get_ebs_volume_id(component, list_of_volumes):
    for volume in list_of_volumes:
        if volume.tags is None:
            continue
        else:
            dict_of_tags = {x["Key"]: x["Value"] for x in volume.tags}
            try:
                if dict_of_tags["Component"] == component:
                    ebs_volume_id = volume.id
                    logging.info(f"Retrieved EBS volume id of {ebs_volume_id}")
                    return ebs_volume_id
            except KeyError:
                continue

    logging.error("No volume ID found for the orchestrator component")
    sys.exit(1)


def create_snapshot_from_ebs_volume(component, ebs_volume_id, ec2_resource, ec2_client):
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
        logging.error(f"Failed to create snapshot: {botocore_exception}")
        sys.exit(1)

    logging.info(f"Created new snapshot id of {snapshot_id.id}")

    try:
        wait_for_new_snapshot_to_become_available(
            component=component, ec2_client=ec2_client, snapshot_id=snapshot_id.id
        )
    except ClientError as botocore_exception:
        logging.error(f"Failed to check snapshot status: {botocore_exception}")
        sys.exit(1)


def wait_for_new_snapshot_to_become_available(
    component,
    ec2_client,
    snapshot_id,
    desired_state="completed",
    max_retries=45,
    timeout=60,
):
    retry_count = 1

    while retry_count <= max_retries:
        snapshot_state = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])

        if snapshot_state["Snapshots"][0]["State"] == desired_state:
            logging.info(f"{snapshot_id} is now available")
            return True
        else:
            logging.info(
                f"State is not yet in the desired state of {desired_state}, retry_count={retry_count}"
            )
            logging.info(f"Current state is: {snapshot_state['Snapshots'][0]['State']}")
            retry_count += 1
            time.sleep(timeout)

    logging.error(
        f"Failed to create new {component} snapshot within timeout of {max_retries} minutes"
    )
    sys.exit(1)


def identify_stale_snapshots(component, ec2_client, snapshot_retention_count=0):
    try:
        component_snapshots = ec2_client.describe_snapshots(
            Filters=[{"Name": "tag:Name", "Values": [component]}]
        )
    except ClientError as botocore_exception:
        logging.error(f"Failed to obtain snapshots data: {botocore_exception}")
        sys.exit(1)

    component_snapshots_data = component_snapshots["Snapshots"]

    sorted_component_snapshots = sorted(
        component_snapshots_data, key=lambda i: (i["StartTime"]), reverse=True
    )
    snapshots_to_retain = snapshot_retention_count + 1
    snapshots_to_remove = sorted_component_snapshots[snapshots_to_retain:]
    return snapshots_to_remove


def delete_stale_snapshots(ec2_client, snapshots_to_remove):
    if len(snapshots_to_remove) == 0:
        logging.info("No snapshots to delete")
    else:
        for snapshot in snapshots_to_remove:
            try:
                logging.info(f"Attempting to delete snapshot {snapshot['SnapshotId']}")
                ec2_client.delete_snapshot(SnapshotId=snapshot["SnapshotId"])
                logging.info(f"Successfully deleted snapshot {snapshot['SnapshotId']}")
            except ClientError as botocore_exception:
                logging.error(f"Failed to remove snapshot: {botocore_exception}")
                sys.exit(1)


if __name__ == "__main__":
    args = parse_arguments()
    snapshot_retention_count = args.snapshot_retention_count
    component = args.component
    ec2_client = boto3.client("ec2")
    ec2_resource = boto3.resource("ec2")
    list_of_volumes = get_all_ebs_volumes(ec2_resource=ec2_resource)
    ebs_volume_id = get_ebs_volume_id(
        component=component, list_of_volumes=list_of_volumes
    )
    create_snapshot_from_ebs_volume(
        component=component,
        ebs_volume_id=ebs_volume_id,
        ec2_resource=ec2_resource,
        ec2_client=ec2_client,
    )
    snapshots_to_remove = identify_stale_snapshots(
        component=component,
        ec2_client=ec2_client,
        snapshot_retention_count=snapshot_retention_count,
    )
    delete_stale_snapshots(
        ec2_client=ec2_client, snapshots_to_remove=snapshots_to_remove
    )
