
# aws-ebs-snapshot-lambda

This repository contains a python script which can be used in order to create an ebs-snapshot from a given component, using the
appropriate volume ID.

The [ebs-snapshot-lambda](ebs_snapshot_lambda/ebs_snapshot_lambda.py) script does the above by retrieving the EBS Volume ID and using this to then 
create a snapshot for the appropriate component. It will also clean up any stale snapshots (snapshots that are not the most recent for a given component)

### Usage

_Steps on how to invoke the lambda and run the appropriate Jenkins job tbc_

#### Running the script manually

To manually run the script, you would need to first export your AWS_DEFAULT_PROFILE locally for the appropriate environment

```export AWS_DEFAULT_PROFILE="webops-integration```

You would also need to configure the virtual environment for this repository - you can do this by running ```make venv```

You can then run the script via the command line, passing an argument for the component you wish to create a snapshot for (for example, if you wanted to create
a snapshot for the Orchestrator component, you would run the following)

```python ebs-snapshot-lambda/ebs_snapshot_lambda.py --component orchestrator```
