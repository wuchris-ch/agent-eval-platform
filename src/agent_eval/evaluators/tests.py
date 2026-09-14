"""Parse test artifacts (junit XML, pytest-cov JSON) produced in the eval pod."""

from __future__ import annotations

import errno
import json
import math
import os
import stat
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal

from pydantic import BaseModel, Field

MAX_JUNIT_BYTES = 16 * 1024 * 1024
MAX_COVERAGE_BYTES = 16 * 1024 * 1024
MAX_JUNIT_CASES = 100_000
MAX_JUNIT_FAILURES = 10_000
MAX_JUNIT_IDENTITY_CHARS = 1_024
MAX_JUNIT_XML_ELEMENTS = 250_000
MAX_JUNIT_XML_DEPTH = 128
MAX_JUNIT_SUITES = 10_000


class _ArtifactIntegrityError(ValueError):
    """An evaluator artifact violated a host-safety invariant."""


class _BoundedReader:
    """Prevent a file that grows after ``fstat`` from escaping its byte cap."""

    def __init__(self, raw: BinaryIO, maximum_bytes: int, label: str):
        self._raw = raw
        self._maximum_bytes = maximum_bytes
        self._label = label
        self._consumed = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self._maximum_bytes - self._consumed
        if size < 0 or size > remaining:
            size = remaining + 1
        data = self._raw.read(size)
        if len(data) > remaining:
            raise _ArtifactIntegrityError(
                f"{self._label} exceeds {self._maximum_bytes} bytes"
            )
        self._consumed += len(data)
        return data


@contextmanager
def _open_bounded_regular_file(
    path: Path, *, maximum_bytes: int, label: str
) -> Iterator[_BoundedReader]:
    """Open one regular artifact without following its final path component."""

    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode):
        raise _ArtifactIntegrityError(f"{label} must not be a symbolic link")
    if not stat.S_ISREG(before.st_mode):
        raise _ArtifactIntegrityError(f"{label} must be a regular file")

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise OSError(errno.ENOTSUP, "O_NOFOLLOW is unavailable")
    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    fd = -1
    try:
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP)}:
                raise _ArtifactIntegrityError(
                    f"{label} must not be a symbolic link"
                ) from exc
            raise
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise _ArtifactIntegrityError(f"{label} must be a regular file")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _ArtifactIntegrityError(f"{label} changed while it was opened")
        if opened.st_size > maximum_bytes:
            raise _ArtifactIntegrityError(f"{label} exceeds {maximum_bytes} bytes")

        raw = os.fdopen(fd, "rb")
        fd = -1
        try:
            yield _BoundedReader(raw, maximum_bytes, label)
        finally:
            raw.close()
    finally:
        if fd >= 0:
            os.close(fd)


class TestResults(BaseModel):
    evaluation_mode: Literal["cooperative", "isolated-black-box"] = "cooperative"
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    # Distinguish a successfully parsed all-zero JUnit result from the same
    # numeric defaults when evaluation never produced trustworthy count data.
    counts_observed: bool = False
    failures: list[str] = Field(default_factory=list)
    coverage_percent: float | None = None
    # The artifact alone is not sufficient evidence of success. The command
    # that produced it must also have completed successfully.
    command_exit_code: int | None = None
    # A hostile or structurally unsafe submission is a rejected result, not an
    # infrastructure outage.
    integrity_error: str | None = None
    runtime_image_digest: str | None = None
    submission_runtime_image_digest: str | None = None
    # eval infrastructure problems (missing junit etc.), distinct from test failures
    infra_error: str | None = None

    @property
    def resolved(self) -> bool:
        return (
            self.infra_error is None
            and self.integrity_error is None
            and self.command_exit_code == 0
            and self.total > 0
            and self.passed > 0
            and self.failed == 0
            and self.errors == 0
        )


def _local_name(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _junit_count(
    element: ET.Element,
    field: str,
    *,
    required: bool = False,
    maximum: int,
) -> int:
    raw = element.get(field)
    if raw is None:
        if required:
            raise ValueError(f"missing {field!r} count")
        return 0
    if not raw.isascii() or not raw.isdecimal():
        raise ValueError(f"{field!r} count must be a non-negative integer")
    if len(raw) > len(str(maximum)):
        raise _ArtifactIntegrityError(
            f"junit {field!r} count exceeds the limit of {maximum}"
        )
    value = int(raw)
    if value > maximum:
        raise _ArtifactIntegrityError(
            f"junit {field!r} count exceeds the limit of {maximum}"
        )
    return value


def _parse_junit_stream(
    stream: _BoundedReader, *, command_exit_code: int | None
) -> TestResults:
    results = TestResults(command_exit_code=command_exit_code)
    stack: list[str] = []
    root_name: str | None = None
    root_aggregate: dict[str, int] = {}
    suite_count = 0
    observed_cases = 0
    observed_failed = 0
    observed_errors = 0
    observed_skipped = 0
    element_count = 0

    for event, element in ET.iterparse(stream, events=("start", "end")):
        name = _local_name(element.tag)
        if event == "start":
            stack.append(name)
            element_count += 1
            if element_count > MAX_JUNIT_XML_ELEMENTS:
                raise _ArtifactIntegrityError(
                    f"junit xml contains more than {MAX_JUNIT_XML_ELEMENTS} elements"
                )
            if len(stack) > MAX_JUNIT_XML_DEPTH:
                raise _ArtifactIntegrityError(
                    f"junit xml nesting exceeds {MAX_JUNIT_XML_DEPTH} levels"
                )

            if len(stack) == 1:
                root_name = name
                if root_name not in {"testsuite", "testsuites"}:
                    raise ValueError("root must be <testsuite> or <testsuites>")
                if root_name == "testsuites":
                    maxima = {
                        "tests": MAX_JUNIT_CASES,
                        "failures": MAX_JUNIT_FAILURES,
                        "errors": MAX_JUNIT_FAILURES,
                        "skipped": MAX_JUNIT_CASES,
                    }
                    root_aggregate = {
                        field: _junit_count(element, field, maximum=maximum)
                        for field, maximum in maxima.items()
                        if element.get(field) is not None
                    }
                    if (
                        root_aggregate.get("failures", 0)
                        + root_aggregate.get("errors", 0)
                        > MAX_JUNIT_FAILURES
                    ):
                        raise _ArtifactIntegrityError(
                            "junit aggregate failures and errors exceed the "
                            f"limit of {MAX_JUNIT_FAILURES}"
                        )

            if name == "testsuite":
                valid_position = (len(stack) == 1 and root_name == "testsuite") or (
                    len(stack) == 2 and root_name == "testsuites"
                )
                if not valid_position:
                    raise ValueError("nested test suites are not supported")
                suite_count += 1
                if suite_count > MAX_JUNIT_SUITES:
                    raise _ArtifactIntegrityError(
                        f"junit xml contains more than {MAX_JUNIT_SUITES} suites"
                    )
                total = _junit_count(
                    element,
                    "tests",
                    required=True,
                    maximum=MAX_JUNIT_CASES,
                )
                failed_count = _junit_count(
                    element, "failures", maximum=MAX_JUNIT_FAILURES
                )
                error_count = _junit_count(
                    element, "errors", maximum=MAX_JUNIT_FAILURES
                )
                skipped_count = _junit_count(
                    element, "skipped", maximum=MAX_JUNIT_CASES
                )
                if failed_count + error_count + skipped_count > total:
                    raise ValueError(
                        "failures, errors, and skipped counts exceed tests count"
                    )
                if results.total + total > MAX_JUNIT_CASES:
                    raise _ArtifactIntegrityError(
                        f"junit test count exceeds the limit of {MAX_JUNIT_CASES}"
                    )
                if (
                    results.failed + results.errors + failed_count + error_count
                    > MAX_JUNIT_FAILURES
                ):
                    raise _ArtifactIntegrityError(
                        "junit failures and errors exceed the limit of "
                        f"{MAX_JUNIT_FAILURES}"
                    )
                results.total += total
                results.failed += failed_count
                results.errors += error_count
                results.skipped += skipped_count
            elif name == "testcase":
                if "testsuite" not in stack[:-1]:
                    raise ValueError("testcase must be inside a test suite")
                observed_cases += 1
                if observed_cases > MAX_JUNIT_CASES:
                    raise _ArtifactIntegrityError(
                        f"junit testcase elements exceed the limit of {MAX_JUNIT_CASES}"
                    )
                for field in ("classname", "name"):
                    if len(element.get(field, "")) > MAX_JUNIT_IDENTITY_CHARS:
                        raise _ArtifactIntegrityError(
                            f"junit testcase {field!r} exceeds "
                            f"{MAX_JUNIT_IDENTITY_CHARS} characters"
                        )
            continue

        if name == "testcase":
            child_names = {_local_name(child.tag) for child in element}
            if "failure" in child_names:
                observed_failed += 1
            if "error" in child_names:
                observed_errors += 1
            if "skipped" in child_names:
                observed_skipped += 1
            if "failure" in child_names or "error" in child_names:
                if observed_failed + observed_errors > MAX_JUNIT_FAILURES:
                    raise _ArtifactIntegrityError(
                        "junit failed testcase elements exceed the limit of "
                        f"{MAX_JUNIT_FAILURES}"
                    )
                results.failures.append(
                    f"{element.get('classname', '')}::{element.get('name', '')}"
                )
        elif len(stack) == 1 and root_name == "testsuites":
            if suite_count == 0:
                raise ValueError("<testsuites> contains no test suites")
            aggregate = {
                "tests": results.total,
                "failures": results.failed,
                "errors": results.errors,
                "skipped": results.skipped,
            }
            for field, actual in aggregate.items():
                if field in root_aggregate and root_aggregate[field] != actual:
                    raise ValueError(
                        f"aggregate {field!r} count does not match test suites"
                    )

        element.clear()
        stack.pop()

    observed = {
        "tests": observed_cases,
        "failures": observed_failed,
        "errors": observed_errors,
        "skipped": observed_skipped,
    }
    declared = {
        "tests": results.total,
        "failures": results.failed,
        "errors": results.errors,
        "skipped": results.skipped,
    }
    for field, actual in observed.items():
        if actual != declared[field]:
            raise _ArtifactIntegrityError(
                f"junit observed {field!r} count {actual} does not match "
                f"declared count {declared[field]}"
            )

    results.passed = results.total - results.failed - results.errors - results.skipped
    results.counts_observed = True
    return results


def parse_junit(
    junit_path: Path, *, command_exit_code: int | None = None
) -> TestResults:
    def failed(reason: str) -> TestResults:
        return TestResults(command_exit_code=command_exit_code, infra_error=reason)

    def rejected(reason: str) -> TestResults:
        return TestResults(
            command_exit_code=command_exit_code,
            integrity_error=reason,
            failures=[reason],
        )

    try:
        with _open_bounded_regular_file(
            junit_path,
            maximum_bytes=MAX_JUNIT_BYTES,
            label="junit.xml",
        ) as stream:
            return _parse_junit_stream(stream, command_exit_code=command_exit_code)
    except FileNotFoundError:
        return failed(f"junit xml not produced at {junit_path.name}")
    except _ArtifactIntegrityError as exc:
        return rejected(f"junit xml integrity violation: {exc}")
    except ET.ParseError as exc:
        return failed(f"junit xml unparseable: {exc}")
    except ValueError as exc:
        return failed(f"junit xml invalid: {exc}")
    except (LookupError, OSError, UnicodeError) as exc:
        return failed(f"junit xml unreadable: {type(exc).__name__}")


@dataclass(frozen=True)
class CoverageArtifactResult:
    percent: float | None = None
    integrity_error: str | None = None
    infra_error: str | None = None


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value!r}")


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def parse_coverage_artifact(coverage_json_path: Path) -> CoverageArtifactResult:
    """Parse optional coverage while retaining unsafe/unreadable evidence."""

    try:
        with _open_bounded_regular_file(
            coverage_json_path,
            maximum_bytes=MAX_COVERAGE_BYTES,
            label="coverage.json",
        ) as stream:
            raw = stream.read()
        data = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_strict_json_object,
        )
        if not isinstance(data, dict):
            raise ValueError("top-level value must be an object")
        totals = data.get("totals")
        if not isinstance(totals, dict):
            raise ValueError("'totals' must be an object")
        value = totals.get("percent_covered")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("'percent_covered' must be a number")
        percent = float(value)
        if not math.isfinite(percent) or not 0 <= percent <= 100:
            raise ValueError("'percent_covered' must be finite and between 0 and 100")
        return CoverageArtifactResult(percent=round(percent, 2))
    except FileNotFoundError:
        return CoverageArtifactResult()
    except _ArtifactIntegrityError as exc:
        return CoverageArtifactResult(
            integrity_error=f"coverage json integrity violation: {exc}"
        )
    except (LookupError, OSError, UnicodeError) as exc:
        return CoverageArtifactResult(
            infra_error=f"coverage json unreadable: {type(exc).__name__}"
        )
    except (json.JSONDecodeError, OverflowError, TypeError, ValueError) as exc:
        detail = str(exc).replace("\n", " ")[:200]
        return CoverageArtifactResult(
            integrity_error=(f"coverage json invalid: {type(exc).__name__}: {detail}")
        )


def parse_coverage(coverage_json_path: Path) -> float | None:
    """Compatibility wrapper returning only a validated coverage percentage."""

    return parse_coverage_artifact(coverage_json_path).percent
