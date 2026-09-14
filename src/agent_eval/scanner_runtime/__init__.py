"""Identity helpers for the bundled, hash-locked scanner environment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCANNER_RUNTIME_PROJECT = Path(__file__).with_name("pyproject.toml")
SCANNER_RUNTIME_LOCK = Path(__file__).with_name("uv.lock")
SCANNER_RUNTIME_RULESET = Path(__file__).with_name("semgrep.yml")
SCANNER_RUNTIME_GITLEAKS_CONFIG = Path(__file__).with_name("gitleaks.toml")
SCANNER_RUNTIME_EMPTY_IGNORE_POLICY = Path(__file__).with_name("ignore-empty.txt")
SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256 = (
    "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
)
SCANNER_RUNTIME_INVOCATION_POLICY = Path(__file__).with_name("invocation-policy.json")

_EXPECTED_INVOCATION_POLICY: dict[str, Any] = {
    "schema_version": "agent-eval.scanner-invocation-policy/v1",
    "ruff": {
        "version": "0.15.20",
        "arguments": [
            "--ignore-noqa",
            "--no-respect-gitignore",
            "--no-force-exclude",
        ],
    },
    "semgrep": {
        "version": "1.176.0",
        "arguments": [
            "--disable-nosem",
            "--no-git-ignore",
            "--x-ignore-semgrepignore-files",
            "--no-exclude-binary-files",
            "--max-target-bytes",
            "0",
            "--strict",
            "--scan-unknown-extensions",
        ],
        "reject_report_errors": True,
        "reject_skipped_rules": True,
        "reject_skipped_targets": True,
    },
    "gitleaks": {
        "version": "8.30.1",
        "arguments": [
            "--gitleaks-ignore-path",
            "{empty_ignore_policy}",
            "--ignore-gitleaks-allow",
            "--max-target-megabytes",
            "0",
        ],
        "empty_ignore_policy_sha256": (SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256),
    },
    "trivy": {
        "version": "0.72.0",
        "arguments": [
            "--config",
            "{empty_ignore_policy}",
            "--ignorefile",
            "{empty_ignore_policy}",
            "--skip-db-update",
            "--scanners",
            "vuln",
        ],
        "empty_ignore_policy_sha256": (SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256),
    },
}


def scanner_runtime_project_digest() -> str:
    """Return the SHA-256 digest of the scanner project definition."""

    return hashlib.sha256(SCANNER_RUNTIME_PROJECT.read_bytes()).hexdigest()


def scanner_runtime_lock_digest() -> str:
    """Return the SHA-256 digest of the exact bundled scanner lockfile."""

    return hashlib.sha256(SCANNER_RUNTIME_LOCK.read_bytes()).hexdigest()


def scanner_runtime_ruleset_digest() -> str:
    """Return the SHA-256 digest of the packaged Semgrep ruleset."""

    return hashlib.sha256(SCANNER_RUNTIME_RULESET.read_bytes()).hexdigest()


def scanner_runtime_gitleaks_config_digest() -> str:
    """Return the SHA-256 digest of the packaged Gitleaks configuration."""

    return hashlib.sha256(SCANNER_RUNTIME_GITLEAKS_CONFIG.read_bytes()).hexdigest()


def scanner_runtime_empty_ignore_policy_digest() -> str:
    """Return the SHA-256 digest of the evaluator-owned empty ignore policy."""

    return hashlib.sha256(SCANNER_RUNTIME_EMPTY_IGNORE_POLICY.read_bytes()).hexdigest()


def scanner_runtime_invocation_policy_digest() -> str:
    """Return the SHA-256 digest of the scanner invocation policy."""

    return hashlib.sha256(SCANNER_RUNTIME_INVOCATION_POLICY.read_bytes()).hexdigest()


def scanner_runtime_invocation_policy() -> dict[str, Any]:
    """Load the exact supported invocation policy and reject local drift."""

    try:
        policy = json.loads(
            SCANNER_RUNTIME_INVOCATION_POLICY.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("scanner invocation policy is unreadable") from exc
    if policy != _EXPECTED_INVOCATION_POLICY:
        raise RuntimeError("scanner invocation policy does not match this release")
    return policy


def _framed_digest(domain: bytes, paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    digest.update(domain + b"\0")
    for path in paths:
        content = path.read_bytes()
        name = path.name.encode("utf-8")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def scanner_runtime_environment_digest() -> str:
    """Return the project-and-lock identity used for private environments."""

    return _framed_digest(
        b"agent-eval-scanner-environment-v1",
        (SCANNER_RUNTIME_PROJECT, SCANNER_RUNTIME_LOCK),
    )


def scanner_runtime_digest() -> str:
    """Return the complete bundled scanner project, lock, and rules identity."""

    return _framed_digest(
        b"agent-eval-scanner-runtime-v1",
        (
            SCANNER_RUNTIME_PROJECT,
            SCANNER_RUNTIME_LOCK,
            SCANNER_RUNTIME_RULESET,
            SCANNER_RUNTIME_GITLEAKS_CONFIG,
            SCANNER_RUNTIME_EMPTY_IGNORE_POLICY,
            SCANNER_RUNTIME_INVOCATION_POLICY,
        ),
    )


__all__ = [
    "SCANNER_RUNTIME_EMPTY_IGNORE_POLICY",
    "SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256",
    "SCANNER_RUNTIME_GITLEAKS_CONFIG",
    "SCANNER_RUNTIME_INVOCATION_POLICY",
    "SCANNER_RUNTIME_LOCK",
    "SCANNER_RUNTIME_PROJECT",
    "SCANNER_RUNTIME_RULESET",
    "scanner_runtime_digest",
    "scanner_runtime_empty_ignore_policy_digest",
    "scanner_runtime_environment_digest",
    "scanner_runtime_gitleaks_config_digest",
    "scanner_runtime_invocation_policy",
    "scanner_runtime_invocation_policy_digest",
    "scanner_runtime_lock_digest",
    "scanner_runtime_project_digest",
    "scanner_runtime_ruleset_digest",
]
