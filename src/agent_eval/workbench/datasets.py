"""Reviewed dataset revisions, quarantine and calibration without model calls."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, model_validator

from ..blackbox.models import StrictModel, Suite, digest
from ..experiments.models import Sha256


class Dataset(StrictModel):
    schema_version: Literal["agent-eval.dataset/v1"] = "agent-eval.dataset/v1"
    suite: Suite
    split: Literal["development", "regression", "capability", "held_out"]
    origin: str = Field(min_length=1, max_length=2000)
    license: str = Field(min_length=1, max_length=200)
    reviewed_by: str = Field(min_length=1, max_length=200)
    families: dict[str, str]
    exposure: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid_families(self):
        if set(self.families) != {c.id for c in self.suite.cases} or any(
            not v for v in self.families.values()
        ):
            raise ValueError("every case requires a task family")
        if self.split == "held_out" and self.exposure:
            raise ValueError("exposed cases cannot be held out")
        return self


def family_key(text):
    # Deliberately conservative normalization; human review handles semantic duplicates.
    return digest(re.sub(r"\W+", " ", text.casefold()).strip())


def register_dataset(store, project, dataset: Dataset, actor):
    families = set(dataset.families.values())
    # A single write transaction prevents concurrent registrations from placing
    # the same family in different splits.
    with store.db() as db:
        rows = db.execute(
            "SELECT id FROM records WHERE project=? AND kind='dataset'", (project,)
        ).fetchall()
        for row in rows:
            other = Dataset.model_validate(store.get(project, "dataset", row[0], db=db))
            if other.split != dataset.split and families & set(other.families.values()):
                raise ValueError("task family crosses dataset splits")
        return store.put(
            project, "dataset", dataset.model_dump(mode="json"), actor=actor, db=db
        )


def quarantine(store, project, public_input, expected, *, origin, actor):
    if not isinstance(public_input, str) or not isinstance(expected, str):
        raise ValueError("reviewable text cases required")

    # Minimize before persistence. Operators must still inspect contextual identifiers.
    def redact(value):
        value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[email]", value)
        value = re.sub(
            r"(?i)(bearer\s+|api[_-]?key[=: ]+)[\w.\-/+]{8,}", "[credential]", value
        )
        return value[:10000]

    clean = redact(public_input)
    value = {
        "input": clean,
        "expected": redact(expected),
        "family": family_key(clean),
        "origin": redact(origin),
        "status": "quarantined",
        "reviewed": False,
    }
    return store.put(project, "quarantine", value, actor=actor)


class CalibrationCase(StrictModel):
    id: str
    split: Literal["development", "validation"]
    category: str
    expected: Literal["pass", "fail", "abstain"]
    observed: Literal["pass", "fail", "abstain"]
    labelers: list[str] = Field(min_length=1)


def calibrate(cases: list[CalibrationCase], grader_sha256: Sha256):
    from pydantic import TypeAdapter

    TypeAdapter(Sha256).validate_python(grader_sha256)
    if not cases or len({c.id for c in cases}) != len(cases):
        raise ValueError("empty or duplicate calibration cases")
    validation = [c for c in cases if c.split == "validation"]
    if (
        not validation
        or not any(c.expected == "fail" for c in validation)
        or not any(c.expected == "pass" for c in validation)
    ):
        raise ValueError("validation requires positive and negative controls")
    matrix = {}
    for c in validation:
        key = f"{c.category}:{c.expected}:{c.observed}"
        matrix[key] = matrix.get(key, 0) + 1
    false_accepts = sum(
        c.expected != "pass" and c.observed == "pass" for c in validation
    )
    return {
        "grader_sha256": grader_sha256,
        "cases_sha256": digest([c.model_dump() for c in cases]),
        "validation_count": len(validation),
        "confusion": matrix,
        "false_accepts": false_accepts,
        "agreement": sum(c.expected == c.observed for c in validation)
        / len(validation),
        "admitted": false_accepts == 0
        and all(c.expected == c.observed for c in validation),
    }
