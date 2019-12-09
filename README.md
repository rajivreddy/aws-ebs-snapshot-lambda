
# aws-ebs-snapshot-lambda

This repository contains a python script which can be used in order to create an ebs-snapshot from a given component, using the
appropriate volume ID.

The [ebs-snapshot-lambda](ebs_snapshot_lambda/ebs_snapshot_lambda.py) script does the above by retrieving the EBS Volume ID and using this to then 
create a snapshot for the appropriate component. It will also clean up any stale snapshots (snapshots that are not the most recent for a given component)

### Usage

_Steps on how to invoke the lambda and run the appropriate Jenkins job tbc_

