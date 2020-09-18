import logging
from unittest import mock

import boto3
import botocore
import pytest
import sys
from botocore.exceptions import ClientError
from moto import mock_ec2
from testfixtures import LogCapture

from ebs_snapshot_lambda import create_snapshot_from_ebs_volume
from ebs_snapshot_lambda import delete_stale_snapshots
from ebs_snapshot_lambda import get_all_ebs_volumes
from ebs_snapshot_lambda import get_ebs_volume_id
from ebs_snapshot_lambda import identify_stale_snapshots
from ebs_snapshot_lambda import wait_for_new_snapshot_to_become_available


@mock_ec2
@mock.patch("ebs_snapshot_lambda.send_slack_notification_and_exit")
def test_get_all_ebs_volumes(mock_send_notification):
    client = boto3.client("ec2", region_name="eu-west-2")
    resource = boto3.resource("ec2", region_name="eu-west-2")
    single_volume = client.create_volume(
        Size=10,
        AvailabilityZone="eu-west-2a",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Component", "Value": "orchestrator"}],
            }
        ],
    )
    ebs_volumes = get_all_ebs_volumes(resource, mock_send_notification)
    volume_id = single_volume["VolumeId"]
    list_of_ebs_volumes = []

    for ebs_volume in ebs_volumes:
        list_of_ebs_volumes.append(ebs_volume.id)

    assert len(list_of_ebs_volumes) == 1
    assert volume_id == list_of_ebs_volumes[0]


@mock.patch("boto3.resource")
@mock.patch(
    "ebs_snapshot_lambda.send_slack_notification_and_exit", side_effect=SystemExit
)
@mock.patch("ebs_snapshot_lambda.get_all_ebs_volumes")
def test_get_all_ebs_volumes_raises_system_exit_on_client_error(
    _, mock_send_notification, mock_resource
):
    def get_all_volumes_side_effect_client_error(**kwargs):
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "TestException", "Message": "Test Exception"}},
            {"Test Exception"},
        )

    mock_resource.return_value = mock_resource
    mock_resource().volumes.all.side_effect = get_all_volumes_side_effect_client_error
    with LogCapture() as log_capture:
        with pytest.raises(SystemExit):
            get_all_ebs_volumes(mock_resource, mock_send_notification)
    log_capture.check(
        (
            "root",
            "ERROR",
            "Unable to retrieve list of volumes: An error occurred (TestException) when "
            "calling the {'Test Exception'} operation: Test Exception",
        )
    )


@mock_ec2
@mock.patch("slack_notifications.SlackNotificationSetup")
def test_get_ebs_volume_id(mock_slack_notification_setup):
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
    list_of_volumes = get_all_ebs_volumes(resource, "foo")
    get_ebs_volume_id(
        component="orchestrator",
        list_of_volumes=list_of_volumes,
        slack_notification_setup=mock_slack_notification_setup,
    )


@mock_ec2
@mock.patch("slack_notifications.SlackNotificationSetup")
def test_get_ebs_volume_id_from_multiple_volumes(mock_slack_notification_setup):
    client = boto3.client("ec2", region_name="eu-west-2")
    resource = boto3.resource("ec2", region_name="eu-west-2")
    orchestrator_volume = client.create_volume(
        Size=10,
        AvailabilityZone="eu-west-2a",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Component", "Value": "orchestrator"}],
            }
        ],
    )
    # Creating an additional volume
    client.create_volume(
        Size=10,
        AvailabilityZone="eu-west-2a",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Component", "Value": "app_server"}],
            }
        ],
    )
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    orchestrator_volume_id = orchestrator_volume["VolumeId"]
    with LogCapture(level=logging.INFO) as log_capture:
        ebs_volume_id = get_ebs_volume_id(
            component="orchestrator",
            list_of_volumes=list_of_volumes,
            slack_notification_setup=mock_slack_notification_setup,
        )
        assert ebs_volume_id == orchestrator_volume_id
    log_capture.check(
        ("root", "INFO", f"Retrieved EBS volume id of {orchestrator_volume_id}",)
    )


@mock_ec2
@mock.patch("slack_notifications.SlackNotificationSetup")
def test_get_ebs_volume_id_from_multiple_volumes_with_same_component_name(
    mock_slack_notification_setup,
):
    client = boto3.client("ec2", region_name="eu-west-2")
    resource = boto3.resource("ec2", region_name="eu-west-2")
    first_orchestrator_volume = client.create_volume(
        Size=10,
        AvailabilityZone="eu-west-2a",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Component", "Value": "orchestrator"}],
            }
        ],
    )
    # Creating an additional volume with the same component name
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
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    first_orchestrator_volume_id = first_orchestrator_volume["VolumeId"]
    with LogCapture(level=logging.INFO) as log_capture:
        ebs_volume_id = get_ebs_volume_id(
            component="orchestrator",
            list_of_volumes=list_of_volumes,
            slack_notification_setup=mock_slack_notification_setup,
        )
        assert ebs_volume_id == first_orchestrator_volume_id
    log_capture.check(
        ("root", "INFO", f"Retrieved EBS volume id of {first_orchestrator_volume_id}",)
    )


@mock.patch(
    "ebs_snapshot_lambda.send_slack_notification_and_exit", side_effect=SystemExit
)
@mock.patch("slack_notifications.SlackNotificationSetup")
def test_get_ebs_volume_id_raises_system_exit_on_unbound_local_error(
    _, mock_slack_notification_setup
):
    with LogCapture() as log_capture:
        with pytest.raises(SystemExit):
            get_ebs_volume_id(
                component="orchestrator",
                list_of_volumes=[],
                slack_notification_setup=mock_slack_notification_setup,
            )
    log_capture.check(
        ("root", "ERROR", "No volume ID found for the orchestrator component",)
    )


@mock_ec2
@mock.patch("slack_notifications.SlackNotificationSetup")
def test_get_ebs_volume_id_continues_on_key_error(mock_slack_notification_setup):
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
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    get_ebs_volume_id(
        component="orchestrator",
        list_of_volumes=list_of_volumes,
        slack_notification_setup=mock_slack_notification_setup,
    )


@mock_ec2
@mock.patch("slack_notifications.SlackNotificationSetup")
def test_create_snapshot_from_ebs_volume(mock_slack_notification_setup):
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
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    ebs_volume_id = get_ebs_volume_id(
        component="orchestrator",
        list_of_volumes=list_of_volumes,
        slack_notification_setup=mock_slack_notification_setup,
    )
    with LogCapture(level=logging.INFO) as log_capture:
        with mock.patch(
            "ebs_snapshot_lambda.wait_for_new_snapshot_to_become_available",
            return_value=True,
        ):
            create_snapshot_from_ebs_volume(
                "orchestrator",
                ebs_volume_id,
                resource,
                client,
                mock_slack_notification_setup,
            )


@mock.patch("slack_notifications.SlackNotificationSetup")
@mock.patch("ebs_snapshot_lambda.boto3.resource")
@mock.patch("ebs_snapshot_lambda.boto3.client")
def test_create_snapshot_from_ebs_volume_check_create_snapshot_calls_via_mock(
    mock_client, mock_resource, mock_slack_notification_setup
):
    with mock.patch(
        "ebs_snapshot_lambda.get_ebs_volume_id", return_value="vol-123"
    ) as mock_get_ebs_volume_id:
        with mock.patch(
            "ebs_snapshot_lambda.wait_for_new_snapshot_to_become_available",
            return_value=True,
        ):
            create_snapshot_from_ebs_volume(
                "orchestrator",
                mock_get_ebs_volume_id.return_value,
                mock_resource,
                mock_client,
                mock_slack_notification_setup,
            )
            assert mock_resource.create_snapshot.call_count is 1
            mock_resource.create_snapshot.assert_called_with(
                Description="Snapshot from orchestrator ebs volume vol-123",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [{"Key": "Name", "Value": "orchestrator"}],
                    }
                ],
                VolumeId="vol-123",
            )


@mock.patch("slack_notifications.SlackNotificationSetup")
@mock.patch("boto3.resource")
@mock.patch("ebs_snapshot_lambda.create_snapshot_from_ebs_volume")
@mock.patch(
    "ebs_snapshot_lambda.send_slack_notification_and_exit", side_effect=SystemExit
)
def test_create_snapshot_from_ebs_volume_raises_system_exit_on_client_error(
    _, __, mock_resource, mock_slack_notification_setup
):
    def create_snapshot_from_ebs_volume_side_effect_client_error(**kwargs):
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "TestException", "Message": "Test Exception"}},
            {"Test Exception"},
        )

    mock_resource.return_value = mock_resource
    mock_resource().create_snapshot.side_effect = (
        create_snapshot_from_ebs_volume_side_effect_client_error
    )
    client = boto3.client("ec2", region_name="eu-west-2")
    with LogCapture() as log_capture:
        with pytest.raises(SystemExit):
            create_snapshot_from_ebs_volume(
                component="orchestrator",
                ebs_volume_id="vol-123456",
                ec2_resource=mock_resource,
                ec2_client=client,
                slack_notification_setup=mock_slack_notification_setup,
            )
    log_capture.check(
        (
            "root",
            "ERROR",
            "Failed to create snapshot: An error occurred (TestException) when calling "
            "the {'Test Exception'} operation: Test Exception",
        )
    )


@mock_ec2
@mock.patch("slack_notifications.SlackNotificationSetup")
def test_wait_for_new_snapshot_to_become_available(mock_slack_notification_setup):
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
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    ebs_volume_id = get_ebs_volume_id(
        component="orchestrator",
        list_of_volumes=list_of_volumes,
        slack_notification_setup=mock_slack_notification_setup,
    )
    snapshot_id = resource.create_snapshot(VolumeId=ebs_volume_id)
    wait_for_new_snapshot_to_become_available(
        component="orchestrator",
        ec2_client=client,
        snapshot_id=snapshot_id.id,
        slack_notification_setup=mock_slack_notification_setup,
    )


@mock_ec2
@mock.patch("slack_notifications.SlackNotificationSetup")
@mock.patch(
    "ebs_snapshot_lambda.send_slack_notification_and_exit", side_effect=SystemExit
)
def test_wait_for_new_snapshot_to_become_available_reaches_max_retries(
    _, mock_slack_notification_setup
):
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
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    ebs_volume_id = get_ebs_volume_id(
        component="orchestrator",
        list_of_volumes=list_of_volumes,
        slack_notification_setup=mock_slack_notification_setup,
    )
    snapshot_id = resource.create_snapshot(VolumeId=ebs_volume_id)
    with LogCapture(level=logging.INFO) as log_capture:
        with pytest.raises(SystemExit):
            wait_for_new_snapshot_to_become_available(
                component="orchestrator",
                ec2_client=client,
                snapshot_id=snapshot_id.id,
                desired_state="invalid",
                max_retries=2,
                timeout=1,
                slack_notification_setup=mock_slack_notification_setup,
            )
    log_capture.check(
        (
            "root",
            "INFO",
            "State is not yet in the desired state of invalid, retry_count=1",
        ),
        ("root", "INFO", "Current state is: completed"),
        (
            "root",
            "INFO",
            "State is not yet in the desired state of invalid, retry_count=2",
        ),
        ("root", "INFO", "Current state is: completed"),
        (
            "root",
            "ERROR",
            "Failed to create new orchestrator snapshot within timeout of 2 minutes",
        ),
    )


@mock_ec2
@mock.patch("slack_notifications.SlackNotificationSetup")
def test_identify_stale_snapshots(mock_slack_notification_setup):
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
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    ebs_volume_id = get_ebs_volume_id(
        component="orchestrator",
        list_of_volumes=list_of_volumes,
        slack_notification_setup=mock_slack_notification_setup,
    )
    with mock.patch(
        "ebs_snapshot_lambda.wait_for_new_snapshot_to_become_available",
        return_value=True,
    ):
        create_snapshot_from_ebs_volume(
            component="orchestrator",
            ebs_volume_id=ebs_volume_id,
            ec2_resource=resource,
            ec2_client=client,
            slack_notification_setup=mock_slack_notification_setup,
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
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    ebs_volume_id = get_ebs_volume_id(
        component="orchestrator",
        list_of_volumes=list_of_volumes,
        slack_notification_setup=mock_slack_notification_setup,
    )
    with mock.patch(
        "ebs_snapshot_lambda.wait_for_new_snapshot_to_become_available",
        return_value=True,
    ):
        create_snapshot_from_ebs_volume(
            component="orchestrator",
            ebs_volume_id=ebs_volume_id,
            ec2_resource=resource,
            ec2_client=client,
            slack_notification_setup=mock_slack_notification_setup,
        )
    identify_stale_snapshots(
        component="orchestrator",
        ec2_client=client,
        snapshot_retention_count=1,
        slack_notification_setup=mock_slack_notification_setup,
    )


@mock.patch("slack_notifications.SlackNotificationSetup")
@mock.patch("boto3.client")
@mock.patch(
    "ebs_snapshot_lambda.send_slack_notification_and_exit", side_effect=SystemExit
)
@mock.patch("ebs_snapshot_lambda.identify_stale_snapshots")
def test_identify_stale_snapshots_raises_system_exit_on_client_error(
    _, __, mock_client, mock_slack_notification_setup
):
    def identify_stale_snapshots_side_effect_client_error(**kwargs):
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "TestException", "Message": "Test Exception"}},
            {"Test Exception"},
        )

    mock_client.return_value = mock_client
    mock_client().describe_snapshots.side_effect = (
        identify_stale_snapshots_side_effect_client_error
    )
    with LogCapture() as log_capture:
        with pytest.raises(SystemExit):
            identify_stale_snapshots(
                component="foo",
                ec2_client=mock_client,
                snapshot_retention_count=1,
                slack_notification_setup=mock_slack_notification_setup,
            )
    log_capture.check(
        (
            "root",
            "ERROR",
            "Failed to obtain snapshots data: An error occurred (TestException) when "
            "calling the {'Test Exception'} operation: Test Exception",
        )
    )


@mock_ec2
@mock.patch("slack_notifications.SlackNotificationSetup")
def test_delete_stale_snapshots(mock_slack_notification_setup):
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
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    ebs_volume_id = get_ebs_volume_id(
        component="orchestrator",
        list_of_volumes=list_of_volumes,
        slack_notification_setup=mock_slack_notification_setup,
    )
    with mock.patch(
        "ebs_snapshot_lambda.wait_for_new_snapshot_to_become_available",
        return_value=True,
    ):
        create_snapshot_from_ebs_volume(
            component="orchestrator",
            ebs_volume_id=ebs_volume_id,
            ec2_resource=resource,
            ec2_client=client,
            slack_notification_setup=mock_slack_notification_setup,
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
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    ebs_volume_id = get_ebs_volume_id(
        component="orchestrator",
        list_of_volumes=list_of_volumes,
        slack_notification_setup=mock_slack_notification_setup,
    )
    with mock.patch(
        "ebs_snapshot_lambda.wait_for_new_snapshot_to_become_available",
        return_value=True,
    ):
        create_snapshot_from_ebs_volume(
            component="orchestrator",
            ebs_volume_id=ebs_volume_id,
            ec2_resource=resource,
            ec2_client=client,
            slack_notification_setup=mock_slack_notification_setup,
        )
    snapshots_to_remove = identify_stale_snapshots(
        component="orchestrator",
        ec2_client=client,
        snapshot_retention_count=1,
        slack_notification_setup=mock_slack_notification_setup,
    )
    snapshot_ids = []

    for snapshot_id in snapshots_to_remove:
        snapshot_ids.append(snapshot_id["SnapshotId"])

    assert len(snapshot_ids) == 1

    with LogCapture(level=logging.INFO) as log_capture:
        delete_stale_snapshots(
            ec2_client=client,
            snapshots_to_remove=snapshots_to_remove,
            slack_notification_setup=mock_slack_notification_setup,
        )
    log_capture.check(
        ("root", "INFO", f"Attempting to delete snapshot {snapshot_ids[0]}",),
        ("root", "INFO", f"Successfully deleted snapshot {snapshot_ids[0]}",),
    )


@mock.patch("slack_notifications.SlackNotificationSetup")
@mock.patch("ebs_snapshot_lambda.boto3.client")
def test_delete_stale_snapshots_delete_snapshot_calls_via_mock(
    mock_client, mock_slack_notification_setup
):
    snapshots_to_remove = [{"SnapshotId": "snap-05fc368760b82218f"}]
    delete_stale_snapshots(
        ec2_client=mock_client,
        snapshots_to_remove=snapshots_to_remove,
        slack_notification_setup=mock_slack_notification_setup,
    )

    assert mock_client.delete_snapshot.call_count is 1
    mock_client.delete_snapshot.assert_called_with(SnapshotId="snap-05fc368760b82218f")


@mock.patch("slack_notifications.SlackNotificationSetup")
@mock.patch("boto3.client")
@mock.patch(
    "ebs_snapshot_lambda.send_slack_notification_and_exit", side_effect=SystemExit
)
@mock.patch("ebs_snapshot_lambda.delete_stale_snapshots")
def test_delete_stale_snapshots_raises_system_exit_on_client_error(
    _, __, mock_client, mock_slack_notification_setup
):
    def delete_stale_snapshots_side_effect_client_error(**kwargs):
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "TestException", "Message": "Test Exception"}},
            {"Test Exception"},
        )

    mock_client.return_value = mock_client
    mock_client().delete_snapshot.side_effect = (
        delete_stale_snapshots_side_effect_client_error
    )
    with LogCapture() as log_capture:
        with pytest.raises(SystemExit):
            delete_stale_snapshots(
                ec2_client=mock_client,
                snapshots_to_remove=[{"SnapshotId": "snap-f89214e2"}],
                slack_notification_setup=mock_slack_notification_setup,
            )
    log_capture.check(
        ("root", "INFO", "Attempting to delete snapshot snap-f89214e2"),
        (
            "root",
            "ERROR",
            "Failed to remove snapshot: An error occurred (TestException) when calling "
            "the {'Test Exception'} operation: Test Exception",
        ),
    )


@mock_ec2
@mock.patch("slack_notifications.SlackNotificationSetup")
def test_delete_stale_snapshots_no_snapshots_to_delete(mock_slack_notification_setup):
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
    list_of_volumes = get_all_ebs_volumes(resource, mock_slack_notification_setup)
    ebs_volume_id = get_ebs_volume_id(
        component="orchestrator",
        list_of_volumes=list_of_volumes,
        slack_notification_setup=mock_slack_notification_setup,
    )
    with mock.patch(
        "ebs_snapshot_lambda.wait_for_new_snapshot_to_become_available",
        return_value=True,
    ):
        create_snapshot_from_ebs_volume(
            component="orchestrator",
            ebs_volume_id=ebs_volume_id,
            ec2_resource=resource,
            ec2_client=client,
            slack_notification_setup=mock_slack_notification_setup,
        )
    snapshots_to_remove = identify_stale_snapshots(
        component="orchestrator",
        ec2_client=client,
        snapshot_retention_count=1,
        slack_notification_setup=mock_slack_notification_setup,
    )
    with LogCapture(level=logging.INFO) as log_capture:
        delete_stale_snapshots(
            ec2_client=client,
            snapshots_to_remove=snapshots_to_remove,
            slack_notification_setup=mock_slack_notification_setup,
        )
    log_capture.check(("root", "INFO", "No snapshots to delete"))
