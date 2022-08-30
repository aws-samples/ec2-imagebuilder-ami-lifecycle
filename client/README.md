# AMI Selection

The AMI Orchestrator maintains a DynamoDB *lookup* table that persists metadata related to an AMI.

The metadata can be used to select an appropriate AMI based on selection criteria.

| Metatdata         | Description | Example | 
|---------------    |-----------------|-----------------|
| ami_semver        | The semantic version associated with the AMI  | 1.0.0      |
| aws_region        | The aws region where the AMI is shared        | us-east-1     |
| lifecycle_event   | The latest completed lifecycle event        | MARK_FOR_PRODUCTION             |
| lifecycle_type    | The type of lifecycle         | ami-creation            |
| stack_tag         | The stack tag associated with the AMI        | main            |
| product_name      | An arbitrary identifier that can be used to associate a product name label with an AMI        | myProductLabel             |
| product_ver       | An arbitrary identifier that can be used to associate a product version label with an AMI        | 1.0.0             |
| commit_ref       | The SHA1 commit ref of the AMI branch        |   f43cc64fffe9be46563          |

## AMI Selection Preference

Depending on the specificity of the provided AMI selection criteria, it is possible that an AMI lookup query will return multiple matches.

When multiple matches are returned, the AMI with the *highest* semantic version will be preferred.

## Testing AMI Selection with a CLI

An AMI Selection CLI utility is provided that will allow you to:

* select the latest available AMI (default behavior)
* select an AMI via specific lookup parameters such as `ami_semver`, `product_name` etc.

## Getting started

In order to use the CLI utility, you need to fulfil the following prerequisites:

1. Ensure that your [AWS CLI environment variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html) have been configured correctly.
2. Setup a Python Virtual Environment

Sample code for creating Python virtual environment and installing dependencies:

```bash
# create Python virtual env
python3 -m venv .env

# activate the virtual env
source .env/bin/activate

# install the dependant libraries
pip install -r cli-requirements.txt
```

With the prerequisites installed, test the CLI by running the command below (which will display a *help* menu):

`python cli_ami_selection.py --help`

## Helper script

A helper bash script has been provided that can be used to run a simple AMI selection. This is useful for a quick sanity test to ensure that your AMI lifecycle generated AMIs are available for selection.

The helper script can be executed as shown below:

```
cd client
bash get_ami.sh
```

Helper script output example:

![Get AMI Shell Script Output](../docs/assets/screenshots/ami-client-selection.png)

## AMI selection examples

Below are a selection of examples demonstrating the use of the CLI.

Full usage options can be displayed at any time via:

`python cli_ami_selection.py --help`

### Get the latest available AMI Id

```bash
python cli_ami_selection.py \
    --stack_tag main \ 
    --region us-east-1
```

### Get the latest available AMI Id that has minimum qualifying event

```bash
python cli_ami_selection.py \
    --stack_tag main \
    --lifecycle_event "VULNERABILITY_SCANNED" \
    --region us-east-1
```

### Get an AMI Id with a specific AMI Semantic Version

```bash
python cli_ami_selection.py \
    --stack_tag main \
    --ami_semver 1.0.0 \
    --region us-east-1
```

### Get an AMI Id with a specific AMI Semantic Version and Product Name

```bash
python cli_ami_selection.py \
    --stack_tag main \
    --ami_semver 1.0.0 \
    --product_name "my product name" \
    --region us-east-1
```

### Complete lookup operation with all supported parameters (with default values)

```bash
python cli_ami_selection.py \
    --stack_tag main \
    --ami_semver "latest" \
    --product_ver "any" \
    --product_name "any" \
    --commit_ref"any" \
    --lifecycle_type "any" \
    --lifecycle_event "AMI_WITH_OS_HARDENING" \
    --region us-east-1
```