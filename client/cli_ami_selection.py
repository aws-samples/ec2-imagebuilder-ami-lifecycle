#!/usr/bin/env python

"""
    cli_ami_selection.py: An AMI Selection CLI utility that allows for:
        * selection of the latest available AMI (default behaviour)
        * selection of an AMI via specific lookup parameters such as `ami_semver`, `product_name` etc.

    See the README.md for further information.
"""

import argparse
import logging
import traceback

from ami_selection import AmiSelection
from ami_selection_utils import AmiSelectionUtils

# set logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
    level=logging.INFO
)
logger = logging.getLogger()

ami_selection_utils = AmiSelectionUtils()


def main(args) -> None:

    try:
        
        ami_id = AmiSelection().get_ami_id(
            stack_tag=args.stack_tag,
            ami_semver=args.ami_semver,
            lifecycle_event=args.lifecycle_event,
            aws_region=args.region,
            product_ver=args.product_ver,
            product_name=args.product_name,
            commit_ref=args.commit_ref,
            lifecycle_type=args.lifecycle_type
        )

        print("")
        print("#############################################")
        print(f"Retrieved AMI ID == {ami_id}")
        print("#############################################")
        print("")
        
    except Exception as e:
        traceback.print_exception(type(e), value=e, tb=e.__traceback__)
        logger.error(f"ERROR attempting to get ami id: {str(e)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='python3 cli_ami_selection.py')

    parser.add_argument(
        '--stack_tag',  
        help='branch slug, e.g. feature-xxxx-cld-1234',
        type=str,
        default="main",
        required=False
    )

    parser.add_argument(
        '--region',  
        help='AWS Region',
        type=str,
        default="us-east-1",
        required=False
    )

    parser.add_argument(
        '--ami_semver',  
        help='latest or specific semver e.g. 1.2.3.',
        type=str,
        default="latest",
        required=False
    )

    parser.add_argument(
        '--product_ver',  
        help='any or specific product version e.g. 1.2.3.',
        type=str,
        default="any",
        required=False
    )

    parser.add_argument(
        '--product_name',  
        help='any or specific product name e.g. My Product Name',
        type=str,
        default="any", 
        required=False
    )

    parser.add_argument(
        '--commit_ref',  
        help='any or specific SHA1 commit ref e.g. f43cc64fffe9be46563feadc7be0e99622a69d14',
        type=str,
        default="any", 
        required=False
    )

    parser.add_argument(
        '--lifecycle_type',  
        help='the type of lifecycle',
        type=str,
        choices={'any', 'ami-creation', 'ami-patch'},
        default="any", 
        required=False
    )

    parser.add_argument(
        '--lifecycle_event',  
        help='minimum qualifying lifecycle event that the AMI must have completed',
        type=str,
        choices={
            'AMI_WITH_OS_HARDENING', 'SMOKE_TESTED', 'VULNERABILITY_SCANNED',
            'QA_CERTIFICATION_REQUESTED', 'QA_CERTIFIED', 'PRODUCTION_APPROVED'
        },
        default="AMI_WITH_OS_HARDENING", 
        required=False
    )

    args = parser.parse_args()

    main(args)
