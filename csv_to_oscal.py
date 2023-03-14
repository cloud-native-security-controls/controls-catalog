#!/usr/bin/env python3

import csv
from datetime import datetime, timezone
from json import dumps
import logging
from os import PathLike
from trestle.oscal.common import Metadata
from trestle.oscal.catalog import Catalog, Control
from typing import List, NamedTuple
from uuid import uuid4

class CloudNativeControlCsvRow(NamedTuple):
    origin_doc: str
    section: str
    title: str
    implementation: str
    nist_sp80053_refs: str
    assurance_level: str
    risk_categories: str

def read_csv(file_path: PathLike, *args, **kwargs) -> List[List[str]]:
    try:
        with open(file_path, 'r', newline='') as fd:
            csv_reader = csv.reader(fd, *args, **kwargs)
            return list(csv_reader)

    except Exception as err:
        return None

def transform_csv(csv_rows: List[List[str]]) -> List[CloudNativeControlCsvRow]:
    try:
        controls = []
        header_cols = True if csv_rows and len(csv_rows) > 0 and len(csv_rows[0]) > 0 else False
        header_cols_count = len(csv_rows[0]) if header_cols else None

        for idx, r in enumerate(csv_rows):
            if header_cols and idx == 0: continue

            if not r or not len(r) == header_cols_count:
                logging.error(f"Row {idx} does not have correct column count")
                continue

            # Remove ID in column 0, we do not need it, keep the rest
            controls.append(CloudNativeControlCsvRow(*r[1:]))

        return controls

    except Exception as err:
        raise err

def create_catalog(controls: List[CloudNativeControlCsvRow]) -> Catalog:
    oscal_controls = []

    for idx, c in enumerate(controls):
        oc = Control(id=f"control-{idx+1}", title=c.title)
        oscal_controls.append(oc)

    timestamp = datetime.now()
    timestamp = timestamp.replace(tzinfo=timezone.utc)
    metadata = Metadata(
        title='Cloud Native Security Controls Catalog',
        last_modified=timestamp.isoformat(),
        version='0.0.1',
        oscal_version='1.0.2'
    )

    return Catalog(
        uuid=str(uuid4()),
        metadata=metadata,
        controls=oscal_controls
    )

def run():
    try:
        csv_rows = read_csv('controls/controls_catalog.csv')
        controls = transform_csv(csv_rows)
        catalog = create_catalog(controls)

        with open('controls/controls_catalog.json', 'w') as fh:
            fh.write(catalog.json())

    except Exception as err:
        raise err

if __name__ == '__main__':
    run()