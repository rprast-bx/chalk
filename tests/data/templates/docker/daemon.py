#!/usr/bin/env python3

import argparse
import json
import pathlib
import sys

import os


IP = os.environ.get("IP", "localhost")

parser = argparse.ArgumentParser()
parser.add_argument(
    "path",
    help="path to daemon.json",
    type=pathlib.Path,
)
parser.add_argument(
    "-w",
    "--write",
    action="store_true",
    help="whether to write the changes back into config file",
)
parser.add_argument(
    "-f",
    "--fail-on-changes",
    action="store_true",
    help="whether to exit with exit_code 1 when any changes were made",
)

if __name__ == "__main__":
    args = parser.parse_args()
    path: pathlib.Path = args.path

    if path.is_file():
        config = json.loads(path.read_text())
    else:
        config = {}
    updated = config.copy()
    updated["insecure-registries"] = sorted(
        set(updated.get("insecure-registries", []))
        | {
            "localhost:5044",
            "registry:5044",
            f"{IP}:5044",
        }
    )
    has_changes = config != updated
    formatted = json.dumps(updated, indent=4)

    if not has_changes:
        sys.exit(0)

    print(formatted)
    if args.write:
        path.write_text(formatted)
    if args.fail_on_changes:
        sys.exit(1)
# { "MAGIC" : "dadfedabbadabbed", "CHALK_ID" : "C8T36D-V3C5-JKJC-HN6HJ6", "CHALK_VERSION" : "0.2.2", "TIMESTAMP_WHEN_CHALKED" : 1703173284114, "DATETIME_WHEN_CHALKED" : "2023-12-21T10:41:18.691-05:00", "ARTIFACT_TYPE" : "python", "CHALK_RAND" : "4f0cf7ca208c3664", "CODE_OWNERS" : "* @viega\n", "HASH" : "b437cae9254de2914bb64049916df90d4120a06994ec50f75d8848e77bb43bf6", "INJECTOR_COMMIT_ID" : "65770ba03a8b839b9a4c9907a3eff2924db102bc", "PLATFORM_WHEN_CHALKED" : "GNU/Linux x86_64", "METADATA_ID" : "S5CVST-7MDA-7HNC-7N5Z99" }
