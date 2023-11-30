#!/usr/bin/env python3

import csv
import logging
import sys
from argparse import ArgumentParser
from datetime import datetime, timezone
from os import PathLike
from pathlib import Path
from typing import NamedTuple
from uuid import uuid4

from trestle.oscal.catalog import Catalog, Control
from trestle.oscal.common import Metadata


class CloudNativeControlCsvRow(NamedTuple):
    origin_doc: str
    section: str
    title: str
    implementation: str
    nist_sp80053_refs: str
    assurance_level: str
    risk_categories: str


def read_csv(file_path: PathLike, *args, **kwargs) -> list[list[str]]:
    try:
        with open(file_path, "r", newline="", encoding="UTF-8") as fd:
            csv_reader = csv.reader(fd, *args, **kwargs)
            return list(csv_reader)
    except Exception as err:
        raise err


def transform_csv(csv_rows: list[list[str]]) -> list[CloudNativeControlCsvRow]:
    try:
        controls = []
        header_cols = (
            True if csv_rows and len(csv_rows) > 0 and len(csv_rows[0]) > 0 else False
        )
        header_cols_count = len(csv_rows[0]) if header_cols else None

        for idx, r in enumerate(csv_rows):
            if header_cols and idx == 0:
                continue

            if not r or not len(r) == header_cols_count:
                logging.error(f"Row {idx} does not have correct column count")
                sys.exit(1)

            # Remove ID in column 0, we do not need it, keep the rest
            controls.append(CloudNativeControlCsvRow(*r[1:]))

        return controls

    except Exception as err:
        raise err


def create_catalog(controls: list[CloudNativeControlCsvRow]) -> Catalog:
    oscal_controls = []

    for idx, c in enumerate(controls):
        oscal_control = Control(id=f"control-{idx+1}", title=c.title)
        oscal_controls.append(oscal_control)

    timestamp = datetime.now()
    timestamp = timestamp.replace(tzinfo=timezone.utc)
    metadata = Metadata(
        title="Cloud Native Security Controls Catalog",
        last_modified=timestamp.isoformat(),
        version="0.0.1",
        oscal_version="1.0.4",
    )

    return Catalog(uuid=str(uuid4()), metadata=metadata, controls=oscal_controls)


def write_catalog(catalog: Catalog, output: PathLike) -> None:
    with open(output, "w") as fh:
        fh.write(catalog.json())


def get_args_config() -> dict:
    """Turn parse arguments into a config"""
    parser = ArgumentParser()

    parser.add_argument(
        "--input",
        type=Path,
        default=Path(__file__).absolute().parent / "controls/controls_catalog.csv",
        help="The input file",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).absolute().parent / "controls/controls_catalog.json",
        help="The output file",
    )

    return vars(parser.parse_args())


def run():
    try:
        args = get_args_config()

        input_file = args["input"]
        output_file = args["output"]

        csv_rows = read_csv(input_file)
        controls = transform_csv(csv_rows)
        catalog = create_catalog(controls)
        write_catalog(catalog, output_file)
    except Exception as err:
        raise err


if __name__ == "__main__":
    run()
