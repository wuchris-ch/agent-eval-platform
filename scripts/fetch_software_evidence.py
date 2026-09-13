#!/usr/bin/env python3
"""Download the published study and verify its pinned compressed and JSON bytes."""

import argparse
import gzip
import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(
        (ROOT / "docs/evidence/software-study-download.json").read_bytes()
    )
    with urllib.request.urlopen(manifest["url"], timeout=30) as response:
        archived = response.read(manifest["bytes"] + 1)
    if (
        len(archived) != manifest["bytes"]
        or hashlib.sha256(archived).hexdigest() != manifest["gzip_sha256"]
    ):
        raise ValueError("Published archive differs from its pinned identity")
    decoded = gzip.decompress(archived)
    if hashlib.sha256(decoded).hexdigest() != manifest["json_sha256"]:
        raise ValueError("Published JSON differs from its pinned identity")
    args.output.write_bytes(archived)
    print(json.dumps({"verified_download": True, "bytes": len(archived)}))


if __name__ == "__main__":
    main()
