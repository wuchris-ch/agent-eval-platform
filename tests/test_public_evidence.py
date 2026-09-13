import gzip
import hashlib
import json
import os
from pathlib import Path

import pytest

from agent_eval.candidates.bundles import verify_bundle


def load_catalog():
    docs = Path(__file__).resolve().parents[1] / "docs"
    catalog = json.loads((docs / "evidence/index.json").read_bytes())
    collections = {}
    for collection in catalog["collections"]:
        rows = []
        for filename in collection["rows_files"]:
            assert filename.startswith("evidence/") and ".." not in filename
            raw = (docs / filename).read_bytes()
            assert len(raw) <= 24002
            rows.extend(json.loads(raw))
        assert rows
        collections[collection["id"]] = rows
    manifest = json.loads((docs / "evidence/software-study-download.json").read_bytes())
    study = next(c for c in catalog["collections"] if c["id"] == "software-study")
    assert study["download"] == manifest["url"]
    return collections, manifest


def test_partitioned_catalog_retains_unique_study_records():
    collections, manifest = load_catalog()
    rows = collections["software-study"]
    assert len(rows) == manifest["records"] == 26
    assert len({row["execution_id"] for row in rows}) == len(rows)


def test_partitioned_catalog_preserves_every_portable_study_record():
    artifact = os.environ.get("AGENT_EVAL_SOFTWARE_BUNDLE")
    if not artifact:
        pytest.skip("Set AGENT_EVAL_SOFTWARE_BUNDLE to the downloaded release archive")
    collections, manifest = load_catalog()
    archived = Path(artifact).read_bytes()
    assert len(archived) == manifest["bytes"]
    assert hashlib.sha256(archived).hexdigest() == manifest["gzip_sha256"]
    assert archived[4:8] == b"\0" * 4  # Stable gzip timestamp.
    decoded = gzip.decompress(archived)
    assert hashlib.sha256(decoded).hexdigest() == manifest["json_sha256"]
    bundle = json.loads(decoded)
    assert bundle["bundle_sha256"] == manifest["bundle_sha256"]
    assert verify_bundle(bundle)["verified"]
    original = bundle["report"]["rows"]
    presented = collections["software-study"]
    assert len(presented) == len(original)
    for expected, actual in zip(original, presented, strict=True):
        assert {key: actual[key] for key in expected} == expected
