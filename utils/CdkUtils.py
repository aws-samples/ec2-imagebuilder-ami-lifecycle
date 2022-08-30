import os
import json
import re
from jsii.python import classproperty

_STACK_TAG = None

class CdkUtils():

    @classproperty
    def stack_prefix(self) -> str:
        return "ec2-imagebuilder-ami-lifecycle"

    @staticmethod
    def get_project_settings():
        filename = "cdk.json"
        with open(filename, 'r') as cdk_json:
            data = cdk_json.read()
        return json.loads(data).get("projectSettings")

    @classproperty
    def stack_tag(self) -> str:
        """The stack tag is an identifier that is used to differentiate between
        different instances of the same stack.  This is especially relevant in a
        feature-branch environment where developers will create their own
        version of the stack while making changes that are intended to be
        integrated into the "main" version of the stack.
        """

        # The stack tag only needs to be determined once.  From then on we use
        # the global variable _STACK_TAG to contain the value.
        global _STACK_TAG

        if _STACK_TAG is None:
            if "STACK_TAG" in os.environ:
                # An environment variable that can be used to define the stack suffix.
                _STACK_TAG = os.environ["STACK_TAG"]
            else:
                from git import Repo

                # If the stack tag is not provided in the OS environment, then it is
                # calculated from the Git branch that is currently checked out.
                repo = Repo(path=os.getcwd())
                branch_name = repo.active_branch.name

                # Create a "slug" from the branch name, by replacing all
                # non-alphanumeric characters in the branch name with a dash.
                _STACK_TAG = re.sub(
                    r"""[^a-zA-Z0-9-]""",
                    r"""-""",
                    branch_name
                ).lower()

        return _STACK_TAG