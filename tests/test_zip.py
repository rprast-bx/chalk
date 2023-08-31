import shutil
from pathlib import Path

import pytest

from .chalk.runner import Chalk
from .chalk.validate import (
    ArtifactInfo,
    validate_chalk_report,
    validate_extracted_chalk,
    validate_virtual_chalk,
)
from .conf import ZIPS
from .utils.log import get_logger


logger = get_logger()


@pytest.mark.slow()
@pytest.mark.parametrize(
    "test_file",
    [
        "nodejs",
        "python",
    ],
)
def test_virtual_valid_slow(tmp_data_dir: Path, chalk: Chalk, test_file: str):
    shutil.copytree(ZIPS / test_file, tmp_data_dir, dirs_exist_ok=True)
    artifact = next((ZIPS / test_file).iterdir())

    # we are only checking the ZIP chalk mark, not any of the subchalks
    # HASH is not the file hash -- chalk does something different internally
    # do not check hashes for zip files
    artifact_info = {
        str(tmp_data_dir / artifact.name): ArtifactInfo(type="ZIP", hash=""),
    }

    # chalk reports generated by insertion, json array that has one element
    insert = chalk.insert(artifact=tmp_data_dir, virtual=True)
    validate_chalk_report(
        chalk_report=insert.report, artifact_map=artifact_info, virtual=True
    )

    # array of json chalk objects as output, of which we are only expecting one
    extract = chalk.extract(artifact=tmp_data_dir)
    validate_extracted_chalk(
        extracted_chalk=extract.report, artifact_map=artifact_info, virtual=True
    )
    # FIXME: virtual chalks not currently validated as every subfile in zip gets chalked
    # generating too many chalks to check
    # validate_virtual_chalk(
    #     tmp_data_dir=tmp_data_dir, artifact_map=artifact_info, virtual=True
    # )


def test_virtual_empty(tmp_data_dir: Path, chalk: Chalk):
    # empty zip file does not get chalked, so no artifact info
    shutil.copytree(ZIPS / "empty", tmp_data_dir, dirs_exist_ok=True)

    # chalk reports generated by insertion, json array that has one element
    insert = chalk.insert(artifact=tmp_data_dir, virtual=True)

    # check chalk report -- operation is the only thing we can check since no _CHALK will be generated
    # on an unchalked empty zip
    assert insert.report["_OPERATION"] == "insert"
    assert not insert.report.get("_CHALK")

    # array of json chalk objects as output, of which we are only expecting one
    extract = chalk.extract(artifact=tmp_data_dir)

    # check chalk extract -- operation is the only thing we can check since no _CHALK will be generated
    # on an unchalked empty zip
    assert extract.report["_OPERATION"] == "extract"
    assert not insert.report.get("_CHALK")


@pytest.mark.parametrize(
    "test_file",
    [
        "misc",
        "golang",
    ],
)
def test_virtual_valid(tmp_data_dir: Path, chalk: Chalk, test_file: str):
    shutil.copytree(ZIPS / test_file, tmp_data_dir, dirs_exist_ok=True)
    artifact = next((ZIPS / test_file).iterdir())

    # we are only checking the ZIP chalk mark, not any of the subchalks
    # HASH is not the file hash -- chalk does something different internally
    # do not check hashes for zip files
    artifact_info = {
        str(tmp_data_dir / artifact.name): ArtifactInfo(type="ZIP", hash=""),
    }

    # chalk reports generated by insertion, json array that has one element
    insert = chalk.insert(artifact=tmp_data_dir, virtual=True)
    validate_chalk_report(
        chalk_report=insert.report, artifact_map=artifact_info, virtual=True
    )

    # array of json chalk objects as output, of which we are only expecting one
    extract = chalk.extract(artifact=tmp_data_dir)
    validate_extracted_chalk(
        extracted_chalk=extract.report, artifact_map=artifact_info, virtual=True
    )
    # FIXME: virtual chalks not currently validated as every subfile in zip gets chalked
    # generating too many chalks to check
    # validate_virtual_chalk(
    #     tmp_data_dir=tmp_data_dir, artifact_map=artifact_info, virtual=True
    # )


@pytest.mark.slow()
@pytest.mark.parametrize(
    "test_file",
    [
        "nodejs",
        "python",
    ],
)
def test_nonvirtual_valid_slow(tmp_data_dir: Path, chalk: Chalk, test_file: str):
    shutil.copytree(ZIPS / test_file, tmp_data_dir, dirs_exist_ok=True)
    artifact = next((ZIPS / test_file).iterdir())

    # we are only checking the ZIP chalk mark, not any of the subchalks
    # HASH is not the file hash -- chalk does something different internally
    # do not check hashes for zip files
    artifact_info = {
        str(tmp_data_dir / artifact.name): ArtifactInfo(type="ZIP", hash=""),
    }

    # chalk reports generated by insertion, json array that has one element
    insert = chalk.insert(artifact=tmp_data_dir, virtual=False)
    validate_chalk_report(
        chalk_report=insert.report, artifact_map=artifact_info, virtual=False
    )

    # array of json chalk objects as output, of which we are only expecting one
    extract = chalk.extract(artifact=tmp_data_dir)
    validate_extracted_chalk(
        extracted_chalk=extract.report, artifact_map=artifact_info, virtual=False
    )
    # validation here okay as we are just checking that virtual-chalk.json file doesn't exist
    validate_virtual_chalk(
        tmp_data_dir=tmp_data_dir, artifact_map=artifact_info, virtual=False
    )


@pytest.mark.parametrize(
    "test_file",
    [
        "misc",
        "golang",
    ],
)
def test_nonvirtual_valid(tmp_data_dir: Path, chalk: Chalk, test_file: str):
    shutil.copytree(ZIPS / test_file, tmp_data_dir, dirs_exist_ok=True)
    artifact = next((ZIPS / test_file).iterdir())

    # we are only checking the ZIP chalk mark, not any of the subchalks
    # HASH is not the file hash -- chalk does something different internally
    # do not check hashes for zip files
    artifact_info = {
        str(tmp_data_dir / artifact.name): ArtifactInfo(type="ZIP", hash=""),
    }

    # chalk reports generated by insertion, json array that has one element
    insert = chalk.insert(artifact=tmp_data_dir, virtual=False)
    validate_chalk_report(
        chalk_report=insert.report, artifact_map=artifact_info, virtual=False
    )

    extract = chalk.extract(artifact=tmp_data_dir)
    validate_extracted_chalk(
        extracted_chalk=extract.report, artifact_map=artifact_info, virtual=False
    )
    # validation here okay as we are just checking that virtual-chalk.json file doesn't exist
    validate_virtual_chalk(
        tmp_data_dir=tmp_data_dir, artifact_map=artifact_info, virtual=False
    )
