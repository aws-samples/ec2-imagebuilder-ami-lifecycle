import fnmatch
import json
import os

import pytest

cdk_out_dir = 'cdk.out'
suffix = 'template.json'


def find(pattern, path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result


def read(file_path):
    with open(file_path, 'r') as file:
        cfn_template = json.loads(file.read())
        file.close()

    return cfn_template


@pytest.fixture(scope="session")
def synth(request):
    os.system('rm -rf ./cdk.out/')
    os.system('cdk synth --json')
    pass
