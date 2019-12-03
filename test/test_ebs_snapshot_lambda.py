import logging

import pytest
from botocore.stub import Stubber
from test_data import test_list_of_volumes
from testfixtures import LogCapture

from ebs_snapshot_lambda.ebs_snapshot_lambda import ec2_client
from ebs_snapshot_lambda.ebs_snapshot_lambda import ec2_resource
from ebs_snapshot_lambda.ebs_snapshot_lambda import get_ebs_volume_id


@pytest.fixture(autouse=True)
def ec2_client_stubber():
    with Stubber(ec2_client) as ec2_client_stubber:
        yield ec2_client_stubber
        ec2_client_stubber.assert_no_pending_responses()


@pytest.fixture(autouse=True)
def ec2_resource_stubber():
    with Stubber(ec2_resource) as ec2_resource_stubber:
        yield ec2_resource_stubber
        ec2_resource_stubber.assert_no_pending_responses()


@pytest.mark.usefixtures()
def test_get_ebs_volume_id():
    ec2_resource_stubber.activate()
    ec2_resource_stubber.add_response("volumes.all", test_list_of_volumes)
    get_ebs_volume_id()


"""
- test_get_ebs_volume_id
- test_get_ebs_volume_id_continues_on_key_error
- test_get_ebs_volume_id_raises_unbound_local_error 
- test_create_snapshot_from_ebs_volume
- test_create_snapshot_from_ebs_volume_raises_client_error
- test_create_snapshot_from_ebs_volume_raises_param_validation_error
- test_wait_for_new_snapshot_to_become_available
- test_wait_for_new_snapshot_to_become_available_reaches_max_retries
- test_delete_stale_snapshots
- test_delete_stale_snapshots_no_snapshots
- test_delete_stale_snapshots_raises_client_error
"""
