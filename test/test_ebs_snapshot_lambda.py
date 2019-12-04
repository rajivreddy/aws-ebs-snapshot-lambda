import logging
import re
from unittest import mock

import boto3
import botocore
import pytest
from botocore.exceptions import ClientError
from moto import mock_ec2
from testfixtures import LogCapture

from ebs_snapshot_lambda.ebs_snapshot_lambda import get_all_ebs_volumes
from ebs_snapshot_lambda.ebs_snapshot_lambda import get_ebs_volume_id

mock_ec2_client = boto3.client("ec2")
mock_ec2_resource = boto3.resource("ec2")


@mock_ec2
def test_get_all_ebs_volumes():
    client = boto3.client("ec2", region_name="eu-west-2")
    resource = boto3.resource("ec2", region_name="eu-west-2")
    client.create_volume(
        Size=10,
        AvailabilityZone="eu-west-2a",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Component", "Value": "orchestrator"}],
            }
        ],
    )
    get_all_ebs_volumes(resource)


@mock.patch("boto3.resource")
@mock.patch("ebs_snapshot_lambda.ebs_snapshot_lambda.get_all_ebs_volumes")
def test_get_all_ebs_volumes_raises_system_exit_on_client_error(_, mock_resource):
    def get_all_volumes_side_effect_client_error(**kwargs):
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "TestException", "Message": "Test Exception"}},
            {"Test Exception"},
        )

    mock_resource.return_value = mock_resource
    mock_resource().volumes.all.side_effect = get_all_volumes_side_effect_client_error
    with LogCapture() as log_capture:
        with pytest.raises(SystemExit):
            get_all_ebs_volumes(mock_resource)
    log_capture.check(
        (
            "root",
            "ERROR",
            "Unable to retrieve list of volumes: An error occurred (TestException) when "
            "calling the {'Test Exception'} operation: Test Exception",
        )
    )


@mock_ec2
def test_get_ebs_volume_id():
    # Given
    client = boto3.client("ec2", region_name="eu-west-2")
    resource = boto3.resource("ec2", region_name="eu-west-2")
    client.create_volume(
        Size=10,
        AvailabilityZone="eu-west-2a",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Component", "Value": "orchestrator"}],
            }
        ],
    )
    list_of_volumes = get_all_ebs_volumes(resource)
    get_ebs_volume_id(component="orchestrator", list_of_volumes=list_of_volumes)


def test_get_ebs_volume_id_raises_system_exit_on_unbound_local_error():
    with LogCapture() as log_capture:
        with pytest.raises(SystemExit):
            get_ebs_volume_id(component="orchestrator", list_of_volumes=[])
    log_capture.check(
        ("root", "ERROR", "No volume ID found for the orchestrator component")
    )


@mock_ec2
def test_get_ebs_volume_id_continues_on_key_error():
    # Given
    client = boto3.client("ec2", region_name="eu-west-2")
    resource = boto3.resource("ec2", region_name="eu-west-2")
    client.create_volume(
        Size=10,
        AvailabilityZone="eu-west-2a",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Foo", "Value": "bar"}]}
        ],
    )
    client.create_volume(
        Size=10,
        AvailabilityZone="eu-west-2a",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Component", "Value": "orchestrator"}],
            }
        ],
    )
    list_of_volumes = get_all_ebs_volumes(resource)
    get_ebs_volume_id(component="orchestrator", list_of_volumes=list_of_volumes)


"""
- test_create_snapshot_from_ebs_volume
- test_create_snapshot_from_ebs_volume_raises_client_error
- test_create_snapshot_from_ebs_volume_raises_param_validation_error
- test_wait_for_new_snapshot_to_become_available
- test_wait_for_new_snapshot_to_become_available_reaches_max_retries
- test_delete_stale_snapshots
- test_delete_stale_snapshots_no_snapshots
- test_delete_stale_snapshots_raises_client_error
"""
