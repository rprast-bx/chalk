# Copyright (c) 2023, Crash Override, Inc.
#
# This file is part of Chalk
# (see https://crashoverride.com/docs/chalk)
import os
import re
import shutil
from pathlib import Path
from typing import IO
from unittest import mock

import pytest

from .chalk.runner import Chalk
from .chalk.validate import (
    ArtifactInfo,
    validate_chalk_report,
    validate_extracted_chalk,
    validate_virtual_chalk,
)
from .conf import CODEOWNERS, CONFIGS, LS_PATH
from .utils.git import init
from .utils.log import get_logger

logger = get_logger()


def test_codeowners(tmp_data_dir: Path, chalk: Chalk):
    folder = CODEOWNERS / "raw1"
    expected_owners = (folder / "CODEOWNERS").read_text()
    shutil.copytree(folder, tmp_data_dir, dirs_exist_ok=True)
    artifact_info = ArtifactInfo.all_shebangs()
    assert len(artifact_info) == 1
    artifact = Path(list(artifact_info.keys())[0])
    init(tmp_data_dir)

    # chalk reports generated by insertion, json array that has one element
    insert = chalk.insert(artifact=artifact, virtual=True)
    assert insert.mark["CODE_OWNERS"] == expected_owners
    # check chalk report
    validate_chalk_report(
        chalk_report=insert.report, artifact_map=artifact_info, virtual=True
    )

    # array of json chalk objects as output, of which we are only expecting one
    extract = chalk.extract(artifact=tmp_data_dir)
    validate_extracted_chalk(
        extracted_chalk=extract.report, artifact_map=artifact_info, virtual=True
    )
    validate_virtual_chalk(
        tmp_data_dir=tmp_data_dir, artifact_map=artifact_info, virtual=True
    )


# https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables
@mock.patch.dict(
    os.environ,
    {
        "CI": "true",
        "GITHUB_SHA": "ffac537e6cbbf934b08745a378932722df287a53",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "octocat/Hello-World",
        "GITHUB_RUN_ID": "1658821493",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_ACTOR": "octocat",
        # there are a bunch of variations of these
        # but for now at least we test basic flow
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF_TYPE": "tag",
    },
)
@pytest.mark.parametrize("copy_files", [[LS_PATH]], indirect=True)
def test_github(copy_files: list[Path], chalk: Chalk):
    bin_path = copy_files[0]
    artifact = ArtifactInfo.one_elf(
        bin_path,
        host_info={
            "BUILD_ID": "1658821493",
            "BUILD_TRIGGER": "tag",
            "BUILD_CONTACT": ["octocat"],
            "BUILD_URI": "https://github.com/octocat/Hello-World/actions/runs/1658821493",
            "BUILD_API_URI": "https://api.github.com",
        },
    )
    insert = chalk.insert(bin_path)

    validate_chalk_report(
        chalk_report=insert.report,
        artifact_map=artifact,
        virtual=False,
        chalk_action="insert",
    )


# https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
@mock.patch.dict(
    os.environ,
    {
        "CI": "true",
        "GITLAB_CI": "true",
        "CI_JOB_URL": "https://gitlab.com/gitlab-org/gitlab/-/jobs/4999820578",
        "CI_JOB_ID": "4999820578",
        "CI_API_V4_URL": "https://gitlab.com/api/v4",
        "GITLAB_USER_LOGIN": "user",
        "CI_PIPELINE_SOURCE": "push",
    },
)
@pytest.mark.parametrize("copy_files", [[LS_PATH]], indirect=True)
def test_gitlab(copy_files: list[Path], chalk: Chalk):
    bin_path = copy_files[0]
    artifact = ArtifactInfo.one_elf(
        bin_path,
        host_info={
            "BUILD_ID": "4999820578",
            "BUILD_TRIGGER": "push",
            "BUILD_CONTACT": ["user"],
            "BUILD_URI": "https://gitlab.com/gitlab-org/gitlab/-/jobs/4999820578",
            "BUILD_API_URI": "https://gitlab.com/api/v4",
        },
    )
    insert = chalk.insert(bin_path)
    validate_chalk_report(
        chalk_report=insert.report,
        artifact_map=artifact,
        virtual=False,
        chalk_action="insert",
    )


@pytest.mark.parametrize("copy_files", [[LS_PATH]], indirect=True)
@pytest.mark.parametrize("tmp_file", [{"path": "/tmp/vendor"}], indirect=True)
def test_imds(
    copy_files: list[Path],
    chalk: Chalk,
    tmp_file: IO,
    server_imds: str,
):
    # make imds plugin think we are running in EC2
    with tmp_file as fid:
        fid.write(b"Amazon")
    bin_path = copy_files[0]
    insert = chalk.insert(bin_path, config=CONFIGS / "imds.c4m")
    assert insert.report.contains(
        {
            "_OP_CLOUD_PROVIDER": "aws",
            "_OP_CLOUD_PROVIDER_SERVICE_TYPE": "aws_ec2",
            "_AWS_AMI_ID": "ami-0abcdef1234567890",
            "_AWS_AMI_LAUNCH_INDEX": "0",
            "_AWS_AMI_MANIFEST_PATH": "(unknown)",
            "_AWS_AZ": "us-east-1e",
            "_AWS_AZ_ID": "use1-az3",
            "_AWS_HOSTNAME": "ip-10-251-50-12.ec2.internal",
            "_AWS_IAM_INFO": {
                "Code": "Success",
                "LastUpdated": "2023-09-12T15:16:58Z",
                "InstanceProfileArn": "arn:aws:iam::123456789012:instance-profile/IMDSTestEc2Role",
                "InstanceProfileId": "AIPATILQWXT62BCWDUQCT",
            },
            "_AWS_INSTANCE_ID": "i-abc123xyz789",
            "_AWS_MAC": "00:25:96:FF:FE:12:34:56",
            "_AWS_VPC_ID": "vpc-1234567890",
            "_AWS_SUBNET_ID": "subnet-1234567890",
            "_AWS_INTERFACE_ID": "eni-1234567890",
            "_AWS_SECURITY_GROUPS": {"default", "test"},
            "_AWS_SECURITY_GROUP_IDS": {"sg-1234567890", "sg-098764321"},
            "_AWS_INSTANCE_IDENTITY_DOCUMENT": {
                "accountId": "123456789012",
                "architecture": "x86_64",
                "availabilityZone": "us-east-1e",
                "billingProducts": None,
                "devpayProductCodes": None,
                "marketplaceProductCodes": None,
                "imageId": "ami-0abcdef1234567890",
                "instanceId": "i-abc123xyz789",
                "instanceType": "t2.medium",
                "kernelId": None,
                "pendingTime": "2023-09-11T06:01:38Z",
                "privateIp": "10.251.50.12",
                "ramdiskId": None,
                "region": "us-east-1",
                "version": "2017-09-30",
            },
            "_AWS_INSTANCE_IDENTITY_PKCS7": re.compile(r"^.*=+$"),
            "_AWS_INSTANCE_IDENTITY_SIGNATURE": re.compile(r"^.*=+$"),
            "_AWS_INSTANCE_LIFE_CYCLE": "on-demand",
            "_AWS_INSTANCE_TYPE": "t2.medium",
            "_AWS_LOCAL_HOSTNAME": "ip-10-251-50-12.ec2.internal",
            "_AWS_LOCAL_IPV4_ADDR": "10.251.50.12",
            "_AWS_OPENSSH_PUBKEY": re.compile(r"^ssh-rsa .* test$"),
            "_AWS_PARTITION_NAME": "aws",
            "_AWS_PUBLIC_HOSTNAME": "ec2-203-0-113-25.compute-1.amazonaws.com",
            "_AWS_PUBLIC_IPV4_ADDR": "203.0.113.25",
            "_AWS_REGION": "us-east-1",
            "_AWS_RESOURCE_DOMAIN": "amazonaws.com",
            "_AWS_TAGS": {
                "Name": "foobar",
                "Environment": "staging",
            },
            "_AWS_IDENTITY_CREDENTIALS_EC2_INFO": {
                "Code": "Success",
                "LastUpdated": "2023-09-13T13:13:39Z",
                "AccountId": "123456789012",
            },
            "_AWS_IDENTITY_CREDENTIALS_EC2_SECURITY_CREDENTIALS_EC2_INSTANCE": {
                "Code": "Success",
                "LastUpdated": "2023-09-13T13:12:26Z",
                "Type": "AWS-HMAC",
                "AccessKeyId": "ASIATILQWXT67VGGR4O2",
                "SecretAccessKey": "<<redacted>>",
                "Token": "<<redacted>>",
                "Expiration": "2023-09-13T19:40:12Z",
            },
        }
    )


@pytest.mark.parametrize("copy_files", [[LS_PATH]], indirect=True)
@pytest.mark.parametrize("tmp_file", [{"path": "/tmp/vendor"}], indirect=True)
def test_imds_ecs(
    copy_files: list[Path],
    chalk: Chalk,
    tmp_file: IO,
    server_imds: str,
):
    # make imds plugin think we are running in EC2
    with tmp_file as fid:
        fid.write(b"Amazon")
    bin_path = copy_files[0]
    insert = chalk.insert(
        bin_path,
        config=CONFIGS / "imds.c4m",
        env={"ECS_CONTAINER_METADATA_URI": "foobar"},
    )
    assert insert.report.contains(
        {
            "_OP_CLOUD_PROVIDER": "aws",
            "_OP_CLOUD_PROVIDER_SERVICE_TYPE": "aws_ecs",
            "_OP_CLOUD_PROVIDER_ACCOUNT_INFO": "123456789012",
            "_OP_CLOUD_PROVIDER_IP": "203.0.113.25",
            "_OP_CLOUD_PROVIDER_REGION": "us-east-1",
            "_OP_CLOUD_PROVIDER_INSTANCE_TYPE": "t2.medium",
            "_OP_CLOUD_PROVIDER_TAGS": {
                "Name": "foobar",
                "Environment": "staging",
            },
        }
    )


@mock.patch.dict(
    os.environ,
    {
        "KUBERNETES_PORT": "tests",
    },
)
@pytest.mark.parametrize("copy_files", [[LS_PATH]], indirect=True)
@pytest.mark.parametrize("tmp_file", [{"path": "/tmp/vendor"}], indirect=True)
def test_imds_eks(
    copy_files: list[Path],
    chalk: Chalk,
    tmp_file: IO,
    server_imds: str,
):
    # make imds plugin think we are running in EC2
    with tmp_file as fid:
        fid.write(b"Amazon")
    bin_path = copy_files[0]
    insert = chalk.insert(bin_path, config=CONFIGS / "imds.c4m")
    assert insert.report.contains(
        {
            "_OP_CLOUD_PROVIDER": "aws",
            "_OP_CLOUD_PROVIDER_SERVICE_TYPE": "aws_eks",
        }
    )


@pytest.mark.parametrize("copy_files", [[LS_PATH]], indirect=True)
@pytest.mark.parametrize("tmp_file", [{"path": "/tmp/vendor"}], indirect=True)
def test_metadata_azure(
    copy_files: list[Path],
    chalk: Chalk,
    tmp_file: IO,
    server_imds: str,
):
    # make imds plugin think we are running in EC2
    with tmp_file as fid:
        fid.write(b"Microsoft Corporation")
    bin_path = copy_files[0]
    insert = chalk.insert(bin_path, config=CONFIGS / "imds.c4m")
    assert insert.report.contains(
        {
            "_OP_CLOUD_PROVIDER": "azure",
            "_OP_CLOUD_PROVIDER_ACCOUNT_INFO": "11111111-1111-1111-1111-111111111111",
            "_OP_CLOUD_PROVIDER_IP": "20.242.32.12",
            "_OP_CLOUD_PROVIDER_REGION": "westeurope",
            "_OP_CLOUD_PROVIDER_INSTANCE_TYPE": "Standard_B1ls",
            "_OP_CLOUD_PROVIDER_TAGS": [
                {"name": "testtag", "value": "testvalue"},
                {"name": "testtag2", "value": "testvalue2"},
            ],
            "_AZURE_INSTANCE_METADATA": {
                "compute": {
                    "azEnvironment": "AzurePublicCloud",
                    "customData": "",
                    "evictionPolicy": "",
                    "isHostCompatibilityLayerVm": "true",
                    "licenseType": "",
                    "location": "westeurope",
                    "name": "myVm",
                    "offer": "0001-com-ubuntu-server-focal",
                    "osProfile": {
                        "adminUsername": "testuser",
                        "computerName": "myVm",
                        "disablePasswordAuthentication": "true",
                    },
                    "osType": "Linux",
                    "placementGroupId": "",
                    "plan": {"name": "", "product": "", "publisher": ""},
                    "platformFaultDomain": "0",
                    "platformUpdateDomain": "0",
                    "priority": "",
                    "provider": "Microsoft.Compute",
                    "publicKeys": [
                        {
                            "keyData": "ssh-rsa AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJQPr4RsDbaJdKPHl2gfCwiWcTRVEu0XlQvsPgdvCH/Io8Im1VfBMamtRhTIEqlEoTaRD8h9ETDQAPg7GUVkg07P3ZgDfFf94KePpxADso7GoqaPsGuL4OQpURa4DQCmf1Jw+kDg0TI1ERYIQoNOGduiS5cuB74A5BxcgW2A52ocVoiINS1tPudZBIvnr8iQXa6BhB5EgUVP0w+pGaOgI4jHga8ThT9weGqzBrtBcyiZ44jfT2Tg/AjI4GuXq14HdFEN0096vk= generated-by-azure",
                            "path": "/home/testuser/.ssh/authorized_keys",
                        }
                    ],
                    "publisher": "canonical",
                    "resourceGroupName": "myVm_group",
                    "resourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myVm_group/providers/Microsoft.Compute/virtualMachines/myVm",
                    "securityProfile": {
                        "secureBootEnabled": "true",
                        "virtualTpmEnabled": "true",
                    },
                    "sku": "20_04-lts-gen2",
                    "storageProfile": {
                        "dataDisks": [],
                        "imageReference": {
                            "id": "",
                            "offer": "0001-com-ubuntu-server-focal",
                            "publisher": "canonical",
                            "sku": "20_04-lts-gen2",
                            "version": "latest",
                        },
                        "osDisk": {
                            "caching": "ReadWrite",
                            "createOption": "FromImage",
                            "diffDiskSettings": {"option": ""},
                            "diskSizeGB": "30",
                            "encryptionSettings": {"enabled": "false"},
                            "image": {"uri": ""},
                            "managedDisk": {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myVm_group/providers/Microsoft.Compute/disks/myVm_disk1_5e2103587ca646929255128ff64b5bdb",
                                "storageAccountType": "Premium_LRS",
                            },
                            "name": "myVm_disk1_5e2103587ca646929255128ff64b5bdb",
                            "osType": "Linux",
                            "vhd": {"uri": ""},
                            "writeAcceleratorEnabled": "false",
                        },
                        "resourceDisk": {"size": "34816"},
                    },
                    "subscriptionId": "11111111-1111-1111-1111-111111111111",
                    "tags": "testtag:testvalue;testtag2:testvalue2",
                    "tagsList": [
                        {"name": "testtag", "value": "testvalue"},
                        {"name": "testtag2", "value": "testvalue2"},
                    ],
                    "userData": "",
                    "version": "20.04.202308310",
                    "vmId": "e94f3f7f-6b23-4395-be46-ea363c549f71",
                    "vmScaleSetName": "",
                    "vmSize": "Standard_B1ls",
                    "zone": "2",
                },
                "network": {
                    "interface": [
                        {
                            "ipv4": {
                                "ipAddress": [
                                    {
                                        "privateIpAddress": "10.0.0.4",
                                        "publicIpAddress": "20.242.32.12",
                                    }
                                ],
                                "subnet": [{"address": "10.0.0.0", "prefix": "24"}],
                            },
                            "ipv6": {"ipAddress": []},
                            "macAddress": "AAAAAAAAAAAA",
                        }
                    ]
                },
            },
        }
    )


@pytest.mark.parametrize("copy_files", [[LS_PATH]], indirect=True)
@pytest.mark.parametrize("tmp_file", [{"path": "/tmp/vendor"}], indirect=True)
def test_metadata_gcp(
    copy_files: list[Path],
    chalk: Chalk,
    tmp_file: IO,
    server_imds: str,
):
    # make imds plugin think we are running in EC2
    with tmp_file as fid:
        fid.write(b"Google")
    bin_path = copy_files[0]
    insert = chalk.insert(bin_path, config=CONFIGS / "imds.c4m")
    assert insert.report.contains(
        {
            "_OP_CLOUD_PROVIDER": "gcp",
            "_OP_CLOUD_PROVIDER_ACCOUNT_INFO": {
                "11111111111-compute@developer.gserviceaccount.com": {
                    "aliases": ["default"],
                    "email": "11111111111-compute@developer.gserviceaccount.com",
                    "scopes": [
                        "https://www.googleapis.com/auth/devstorage.read_only",
                        "https://www.googleapis.com/auth/logging.write",
                        "https://www.googleapis.com/auth/monitoring.write",
                        "https://www.googleapis.com/auth/servicecontrol",
                        "https://www.googleapis.com/auth/service.management.readonly",
                        "https://www.googleapis.com/auth/trace.append",
                    ],
                },
                "default": {
                    "aliases": ["default"],
                    "email": "11111111111-compute@developer.gserviceaccount.com",
                    "scopes": [
                        "https://www.googleapis.com/auth/devstorage.read_only",
                        "https://www.googleapis.com/auth/logging.write",
                        "https://www.googleapis.com/auth/monitoring.write",
                        "https://www.googleapis.com/auth/servicecontrol",
                        "https://www.googleapis.com/auth/service.management.readonly",
                        "https://www.googleapis.com/auth/trace.append",
                    ],
                },
            },
            "_OP_CLOUD_PROVIDER_IP": "35.205.62.123",
            "_OP_CLOUD_PROVIDER_REGION": "europe-west1-b",
            "_OP_CLOUD_PROVIDER_INSTANCE_TYPE": "e2-micro",
            "_GCP_INSTANCE_METADATA": {
                "attributes": {
                    "ssh-keys": 'test:ecdsa-sha2-nistp256 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKgXTiO1+sSWCEsq/bWaLdY= google-ssh {"userName":"test@crashoverride.com","expireOn":"2023-10-14T15:11:57+0000"}\ntest:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvddnbJ/XWxMUPXOsDMNoRHJeaCgwqk6g7UYvrXqogwmJ1WpC1QPuG3mhDjmBOcjINi7TYsozDKZilL2BDu2i6CGC1s2Tokq41lsgnCePNdnYmPcA318PmuMmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeT7R92kx google-ssh {"userName":"test@crashoverride.com","expireOn":"2023-10-14T15:12:12+0000"}'
                },
                "cpuPlatform": "Intel Broadwell",
                "description": "",
                "disks": [
                    {
                        "deviceName": "instance-1",
                        "index": 0,
                        "interface": "SCSI",
                        "mode": "READ_WRITE",
                        "type": "PERSISTENT-BALANCED",
                    }
                ],
                "guestAttributes": {},
                "hostname": "instance-1.europe-west1-b.c.test-chalk-402014.internal",
                "id": 133380848178631130,
                "image": "projects/debian-cloud/global/images/debian-11-bullseye-v20231010",
                "licenses": [{"id": "4324324324234234234"}],
                "machineType": "projects/11111111111/machineTypes/e2-micro",
                "maintenanceEvent": "NONE",
                "name": "instance-1",
                "networkInterfaces": [
                    {
                        "accessConfigs": [
                            {"externalIp": "35.205.62.123", "type": "ONE_TO_ONE_NAT"}
                        ],
                        "dnsServers": ["169.254.169.254"],
                        "forwardedIps": [],
                        "gateway": "10.132.0.1",
                        "ip": "10.132.0.2",
                        "ipAliases": [],
                        "mac": "42:01:0a:84:00:02",
                        "mtu": 1460,
                        "network": "projects/11111111111/networks/default",
                        "subnetmask": "255.255.240.0",
                        "targetInstanceIps": [],
                    }
                ],
                "partnerAttributes": {},
                "preempted": "FALSE",
                "remainingCpuTime": -1,
                "scheduling": {
                    "automaticRestart": "TRUE",
                    "onHostMaintenance": "MIGRATE",
                    "preemptible": "FALSE",
                },
                "serviceAccounts": {
                    "11111111111-compute@developer.gserviceaccount.com": {
                        "aliases": ["default"],
                        "email": "11111111111-compute@developer.gserviceaccount.com",
                        "scopes": [
                            "https://www.googleapis.com/auth/devstorage.read_only",
                            "https://www.googleapis.com/auth/logging.write",
                            "https://www.googleapis.com/auth/monitoring.write",
                            "https://www.googleapis.com/auth/servicecontrol",
                            "https://www.googleapis.com/auth/service.management.readonly",
                            "https://www.googleapis.com/auth/trace.append",
                        ],
                    },
                    "default": {
                        "aliases": ["default"],
                        "email": "11111111111-compute@developer.gserviceaccount.com",
                        "scopes": [
                            "https://www.googleapis.com/auth/devstorage.read_only",
                            "https://www.googleapis.com/auth/logging.write",
                            "https://www.googleapis.com/auth/monitoring.write",
                            "https://www.googleapis.com/auth/servicecontrol",
                            "https://www.googleapis.com/auth/service.management.readonly",
                            "https://www.googleapis.com/auth/trace.append",
                        ],
                    },
                },
                "tags": [],
                "virtualClock": {"driftToken": "0"},
                "zone": "projects/11111111111/zones/europe-west1-b",
            },
        }
    )
