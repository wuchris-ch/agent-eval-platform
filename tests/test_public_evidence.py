import gzip
import json
from pathlib import Path

from agent_eval.candidates.bundles import verify_bundle


def test_partitioned_catalog_preserves_every_portable_study_record():
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
    archived = (docs / "evidence/software-study.json.gz").read_bytes()
    assert archived[4:8] == b"\0" * 4  # Stable gzip timestamp.
    bundle = json.loads(gzip.decompress(archived))
    assert verify_bundle(bundle)["verified"]
    original = bundle["report"]["rows"]
    presented = collections["software-study"]
    assert len(presented) == len(original)
    for expected, actual in zip(original, presented, strict=True):
        assert {key: actual[key] for key in expected} == expected
