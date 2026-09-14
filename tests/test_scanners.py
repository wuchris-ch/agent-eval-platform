import json
import os
import sys
import time
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_eval.evaluators import scanners
from agent_eval.metrics import ScanResults, TrivyDatabaseIdentity
from agent_eval.scanner_runtime import (
    SCANNER_RUNTIME_EMPTY_IGNORE_POLICY,
    SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256,
    SCANNER_RUNTIME_GITLEAKS_CONFIG,
    SCANNER_RUNTIME_INVOCATION_POLICY,
    SCANNER_RUNTIME_LOCK,
    SCANNER_RUNTIME_PROJECT,
    SCANNER_RUNTIME_RULESET,
    scanner_runtime_digest,
    scanner_runtime_empty_ignore_policy_digest,
    scanner_runtime_environment_digest,
    scanner_runtime_gitleaks_config_digest,
    scanner_runtime_invocation_policy,
    scanner_runtime_invocation_policy_digest,
    scanner_runtime_lock_digest,
    scanner_runtime_project_digest,
    scanner_runtime_ruleset_digest,
)


@pytest.fixture(autouse=True)
def _private_scanner_state(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(
        scanners,
        "_observed_runtime_version",
        lambda name: {"ruff": "0.15.20", "semgrep": "1.176.0"}[name],
    )
    installed_version = scanners._installed_version

    def exact_fake_external_version(command):
        executable = str(command[0]) if command else ""
        if executable == "/usr/bin/gitleaks":
            return "8.30.1"
        return installed_version(command)

    monkeypatch.setattr(scanners, "_installed_version", exact_fake_external_version)


def _semgrep_report(results=None, **updates):
    report = {
        "version": "1.176.0",
        "results": [] if results is None else results,
        "errors": [],
        "paths": {"scanned": []},
        "skipped_rules": [],
    }
    report.update(updates)
    return json.dumps(report)


def test_run_streams_and_caps_subprocess_output(monkeypatch, tmp_path):
    monkeypatch.setattr(scanners, "_MAX_STREAM_BYTES", 1_024)
    output = tmp_path / "scanner.log"

    proc, status = scanners._run(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"],
        output,
    )

    assert proc is not None
    assert status == "truncated"
    assert len(proc.stdout.encode()) == 1_024
    assert output.stat().st_size == 1_024


def test_run_terminates_continuous_output_on_capture_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(scanners, "_MAX_STREAM_BYTES", 1_024)
    monkeypatch.setattr(scanners, "SCAN_TIMEOUT", 5)
    monkeypatch.setattr(scanners, "_TERMINATION_GRACE_SECONDS", 0.1)
    started = time.monotonic()

    proc, status = scanners._run(
        [
            sys.executable,
            "-c",
            "import os\nwhile True: os.write(1, b'x' * 65536)",
        ],
        tmp_path / "continuous.log",
    )
    elapsed = time.monotonic() - started

    assert proc is not None
    assert status == "truncated"
    # Process startup and scheduling are slower under the Python 3.14 release
    # job on macOS. This remains well below the five-second scan deadline and
    # still proves that the output cap, not the deadline, ended the process.
    assert elapsed < 2.0
    assert len(proc.stdout.encode()) == 1_024


def test_run_timeout_terminates_the_entire_process_group(monkeypatch, tmp_path):
    sentinel = tmp_path / "escaped-child"
    child = (
        "import pathlib,sys,time; time.sleep(0.4); "
        "pathlib.Path(sys.argv[1]).write_text('escaped')"
    )
    parent = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}, sys.argv[1]]); "
        "time.sleep(5)"
    )
    monkeypatch.setattr(scanners, "SCAN_TIMEOUT", 0.05)
    monkeypatch.setattr(scanners, "_TERMINATION_GRACE_SECONDS", 0.1)
    monkeypatch.setattr(scanners, "_STREAM_JOIN_SECONDS", 0.1)

    proc, status = scanners._run(
        [sys.executable, "-c", parent, str(sentinel)],
        tmp_path / "timeout.log",
    )
    time.sleep(0.5)

    assert proc is None
    assert status == "timeout"
    assert not sentinel.exists()


def test_ruff_disables_workspace_suppression_with_pinned_package(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, out_file):
        captured["cmd"] = cmd
        captured["out_file"] = out_file
        return SimpleNamespace(returncode=0, stdout='[{"code": "F401"}]'), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "source.py"
    source.write_text("import os\n", encoding="utf-8")

    scanners._lint("python", workspace, tmp_path, results)

    assert captured["cmd"][:12] == [
        "/usr/bin/uv",
        "run",
        "--project",
        str(SCANNER_RUNTIME_PROJECT.parent),
        "--frozen",
        "--offline",
        "--no-sync",
        "--python",
        "3.12",
        "--no-dev",
        "--",
        "ruff",
    ]
    assert captured["out_file"] == tmp_path / "ruff.json"
    assert "--isolated" in captured["cmd"]
    assert "--ignore-noqa" in captured["cmd"]
    assert "--no-respect-gitignore" in captured["cmd"]
    assert "--no-force-exclude" in captured["cmd"]
    assert captured["cmd"][-1] == str(source.resolve())
    assert results.scanner_status["ruff"] == "ok"
    assert results.scanner_configs["ruff"] == (
        "packaged-runtime; isolated; "
        f"lock-sha256={scanner_runtime_lock_digest()}; "
        f"invocation-policy-sha256={scanner_runtime_invocation_policy_digest()}"
    )
    assert results.lint_errors == 1


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (1, "[]"),
        (2, "[]"),
        (0, "not-json"),
        (0, '{"findings": []}'),
    ],
)
def test_ruff_errors_leave_metric_unset(monkeypatch, tmp_path, returncode, stdout):
    def fake_run(cmd, out_file):
        del cmd, out_file
        return SimpleNamespace(returncode=returncode, stdout=stdout), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()

    scanners._lint("python", tmp_path / "workspace", tmp_path, results)

    assert results.scanner_status["ruff"] == "error"
    assert results.lint_errors is None


def test_semgrep_disables_workspace_suppression_and_binds_config(monkeypatch, tmp_path):
    captured = {}

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    results = ScanResults()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")

    def fake_run(cmd, out_file):
        captured["cmd"] = cmd
        captured["out_file"] = out_file
        return SimpleNamespace(
            returncode=0,
            stdout=_semgrep_report(paths={"scanned": [str(source.resolve())]}),
        ), "ok"

    monkeypatch.setattr(scanners, "_run", fake_run)
    scanners._semgrep(workspace, tmp_path, results)

    assert captured["cmd"][:12] == [
        "/usr/bin/uv",
        "run",
        "--project",
        str(SCANNER_RUNTIME_PROJECT.parent),
        "--frozen",
        "--offline",
        "--no-sync",
        "--python",
        "3.12",
        "--no-dev",
        "--",
        "semgrep",
    ]
    assert captured["cmd"][captured["cmd"].index("--config") + 1] == str(
        SCANNER_RUNTIME_RULESET
    )
    assert captured["cmd"][captured["cmd"].index("--metrics") + 1] == "off"
    assert "--no-rewrite-rule-ids" in captured["cmd"]
    assert "--disable-version-check" in captured["cmd"]
    assert "--disable-nosem" in captured["cmd"]
    assert "--no-git-ignore" in captured["cmd"]
    assert "--x-ignore-semgrepignore-files" in captured["cmd"]
    assert "--no-exclude-binary-files" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("--max-target-bytes") + 1] == "0"
    assert "--strict" in captured["cmd"]
    assert "--scan-unknown-extensions" in captured["cmd"]
    assert captured["cmd"][-1] == str(source.resolve())
    assert captured["out_file"] == tmp_path / "semgrep.json"
    assert results.scanner_status["semgrep"] == "ok"
    assert results.scanner_configs["semgrep"] == (
        "packaged:semgrep.yml; "
        f"sha256={scanner_runtime_ruleset_digest()}; "
        f"invocation-policy-sha256={scanner_runtime_invocation_policy_digest()}"
    )
    assert results.sec_findings_high == 0


def test_python_target_inventory_covers_excluded_and_unknown_sources(tmp_path):
    workspace = tmp_path / "workspace"
    excluded = workspace / ".venv" / "hidden.py"
    unknown = workspace / "service.txt"
    canary = workspace / "canary.txt"
    dependency = workspace / "node_modules" / "package-lock.json"
    excluded.parent.mkdir(parents=True)
    dependency.parent.mkdir(parents=True)
    excluded.write_text("import os\n", encoding="utf-8")
    unknown.write_text("eval('hidden')\n", encoding="utf-8")
    canary.write_text("AGENT_EVAL_NON_SECRET_CANARY\n", encoding="utf-8")
    dependency.write_text('{"lockfileVersion": 2}\n', encoding="utf-8")

    targets = scanners._python_scan_targets(workspace)

    assert set(targets) == {excluded.resolve(), unknown.resolve()}


def test_semgrep_rejects_a_clean_report_that_omits_an_explicit_target(
    monkeypatch, tmp_path
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first = workspace / "first.py"
    second = workspace / "second.txt"
    first.write_text("value = 1\n", encoding="utf-8")
    second.write_text("eval('hidden')\n", encoding="utf-8")

    def fake_run(cmd, out_file):
        del cmd, out_file
        return SimpleNamespace(
            returncode=0,
            stdout=_semgrep_report(paths={"scanned": [str(first.resolve())]}),
        ), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()

    scanners._semgrep(workspace, tmp_path, results)

    assert results.scanner_status["semgrep"] == "error"
    assert results.sec_findings_high is None


def test_scanner_runtime_has_exact_top_level_versions_and_stable_identity():
    project = tomllib.loads(SCANNER_RUNTIME_PROJECT.read_text(encoding="utf-8"))

    assert project["project"]["requires-python"] == ">=3.12,<3.13"
    assert project["project"]["dependencies"] == [
        "ruff==0.15.20",
        "semgrep==1.176.0",
    ]
    assert len(scanner_runtime_digest()) == 64
    assert len(scanner_runtime_environment_digest()) == 64
    assert len(scanner_runtime_project_digest()) == 64
    assert (
        scanner_runtime_lock_digest()
        == scanners.hashlib.sha256(SCANNER_RUNTIME_LOCK.read_bytes()).hexdigest()
    )
    assert (
        scanner_runtime_ruleset_digest()
        == scanners.hashlib.sha256(SCANNER_RUNTIME_RULESET.read_bytes()).hexdigest()
    )
    assert (
        scanner_runtime_gitleaks_config_digest()
        == scanners.hashlib.sha256(
            SCANNER_RUNTIME_GITLEAKS_CONFIG.read_bytes()
        ).hexdigest()
    )
    assert scanner_runtime_empty_ignore_policy_digest() == (
        SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256
    )
    assert SCANNER_RUNTIME_EMPTY_IGNORE_POLICY.read_bytes() == b"\n"
    assert (
        scanner_runtime_invocation_policy_digest()
        == scanners.hashlib.sha256(
            SCANNER_RUNTIME_INVOCATION_POLICY.read_bytes()
        ).hexdigest()
    )


def test_scanner_invocation_policy_is_exact_and_runtime_bound():
    policy = scanner_runtime_invocation_policy()

    assert policy["ruff"] == {
        "version": "0.15.20",
        "arguments": [
            "--ignore-noqa",
            "--no-respect-gitignore",
            "--no-force-exclude",
        ],
    }
    assert policy["semgrep"] == {
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
    }
    assert policy["gitleaks"] == {
        "version": "8.30.1",
        "arguments": [
            "--gitleaks-ignore-path",
            "{empty_ignore_policy}",
            "--ignore-gitleaks-allow",
            "--max-target-megabytes",
            "0",
        ],
        "empty_ignore_policy_sha256": (SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256),
    }
    assert policy["trivy"] == {
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
    }
    expected = scanners.hashlib.sha256()
    expected.update(b"agent-eval-scanner-runtime-v1\0")
    for path in (
        SCANNER_RUNTIME_PROJECT,
        SCANNER_RUNTIME_LOCK,
        SCANNER_RUNTIME_RULESET,
        SCANNER_RUNTIME_GITLEAKS_CONFIG,
        SCANNER_RUNTIME_EMPTY_IGNORE_POLICY,
        SCANNER_RUNTIME_INVOCATION_POLICY,
    ):
        content = path.read_bytes()
        name = path.name.encode("utf-8")
        expected.update(len(name).to_bytes(4, "big"))
        expected.update(name)
        expected.update(len(content).to_bytes(8, "big"))
        expected.update(content)
    assert scanner_runtime_digest() == expected.hexdigest()


def test_empty_ignore_policy_requires_exact_regular_file(monkeypatch, tmp_path):
    assert scanners._verified_empty_ignore_policy_sha256() == (
        SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256
    )

    target = tmp_path / "target"
    target.write_bytes(b"\n")
    linked_policy = tmp_path / "ignore-policy"
    linked_policy.symlink_to(target)
    monkeypatch.setattr(scanners, "SCANNER_RUNTIME_EMPTY_IGNORE_POLICY", linked_policy)

    assert scanners._verified_empty_ignore_policy_sha256() is None


@pytest.mark.parametrize("scanner_name", ["gitleaks", "trivy"])
def test_external_scanners_fail_closed_when_ignore_policy_is_tampered(
    monkeypatch, tmp_path, scanner_name
):
    tampered_policy = tmp_path / "ignore-policy"
    tampered_policy.write_text("CVE-2020-8203\n", encoding="utf-8")
    monkeypatch.setattr(
        scanners, "SCANNER_RUNTIME_EMPTY_IGNORE_POLICY", tampered_policy
    )
    monkeypatch.setattr(scanners, "_resolved_executable", lambda name: f"/tools/{name}")
    monkeypatch.setattr(
        scanners,
        "_run",
        lambda *args: pytest.fail("scanner ran with a tampered ignore policy"),
    )
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    results = ScanResults()

    getattr(scanners, f"_{scanner_name}")(workspace, scans_dir, results)

    assert results.scanner_status[scanner_name] == "error"


def test_scanner_subprocess_drops_host_credentials_and_uses_private_state(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("ALL_PROXY", "http://secret:token@proxy.invalid:8080")
    monkeypatch.setenv("SSL_CERT_FILE", "/private/cert.pem")
    output = tmp_path / "environment.json"

    proc, status = scanners._run(
        [
            sys.executable,
            "-c",
            "import json,os; print(json.dumps(dict(os.environ)))",
        ],
        output,
    )

    assert proc is not None
    assert status == "ok"
    environment = json.loads(proc.stdout)
    assert "ANTHROPIC_API_KEY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "AGENT_EVAL_STATE_DIR" not in environment
    assert environment["HTTPS_PROXY"] == "http://proxy.invalid:8080"
    assert "ALL_PROXY" not in environment
    assert environment["SSL_CERT_FILE"] == "/private/cert.pem"
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    identity_root = (
        tmp_path / "state-scanner-runtime" / scanner_runtime_environment_digest()
    )
    assert environment["HOME"] == str(identity_root / "home")
    assert environment["UV_CACHE_DIR"] == str(identity_root / "cache")
    assert environment["UV_PROJECT_ENVIRONMENT"] == str(identity_root / "environment")
    assert stat_mode(identity_root) == 0o700
    assert not (SCANNER_RUNTIME_PROJECT.parent / ".venv").exists()


def stat_mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode & 0o777


def test_run_scanners_records_runtime_lock_evidence(monkeypatch, tmp_path):
    for name in ("_lint", "_semgrep", "_gitleaks", "_trivy"):
        monkeypatch.setattr(scanners, name, lambda *args, **kwargs: None)

    results = scanners.run_scanners(tmp_path, tmp_path / "run")

    assert results.scanner_runtime_lock_sha256 == scanner_runtime_lock_digest()
    assert results.scanner_assurance is not None
    assert not results.scanner_assurance.promotion_ready


def test_scanner_assurance_identity_is_canonical_and_fail_closed():
    database = TrivyDatabaseIdentity(
        version=2,
        updated_at="2026-07-14T00:00:00Z",
        next_update="2026-07-15T00:00:00Z",
        downloaded_at="2026-07-14T01:00:00Z",
        content_sha256="c" * 64,
    )
    results = ScanResults(
        scanner_runtime_lock_sha256=scanner_runtime_lock_digest(),
        scanner_runtime_environment_sha256="2" * 64,
        scanner_status={
            "ruff": "ok",
            "semgrep": "ok",
            "gitleaks": "ok",
            "trivy": "ok",
        },
        scanner_versions={
            "ruff": "0.15.20",
            "semgrep": "1.176.0",
            "gitleaks": "8.30.1",
            "trivy": "0.72.0",
        },
        scanner_executable_sha256={
            "uv": "d" * 64,
            "python": "e" * 64,
            "ruff": "f" * 64,
            "semgrep": "1" * 64,
            "gitleaks": "a" * 64,
            "trivy": "b" * 64,
        },
        trivy_db=database,
    )

    first = scanners.scanner_assurance_identity(results)
    second = scanners.scanner_assurance_identity(results)

    assert first == second
    assert first.promotion_ready
    assert first.promotion_blockers == []
    assert first.runtime_lock_sha256 == scanner_runtime_lock_digest()
    assert first.semgrep_ruleset_sha256 == scanner_runtime_ruleset_digest()
    assert first.gitleaks_config_sha256 == scanner_runtime_gitleaks_config_digest()

    results.scanner_executable_sha256["trivy"] = None
    blocked = scanners.scanner_assurance_identity(results)
    assert not blocked.promotion_ready
    assert "scanner:trivy:executable-sha256-missing" in (blocked.promotion_blockers)
    assert blocked.identity_sha256 != first.identity_sha256

    tampered = first.model_copy(update={"runtime_environment_sha256": "9" * 64})
    with pytest.raises(ValueError, match="identity_sha256 does not match its material"):
        type(first).model_validate(tampered.model_dump(mode="python"))

    results.scanner_executable_sha256["trivy"] = "b" * 64
    results.trivy_db = database.model_copy(update={"content_sha256": None})
    blocked = scanners.scanner_assurance_identity(results)
    assert "scanner:trivy:database-content-sha256-missing" in (
        blocked.promotion_blockers
    )

    results.trivy_db = database
    results.scanner_versions["gitleaks"] = "8.29.0"
    blocked = scanners.scanner_assurance_identity(results)
    assert not blocked.promotion_ready
    assert "scanner:gitleaks:version-mismatch" in blocked.promotion_blockers


@pytest.mark.parametrize("scanner_name", ["ruff", "semgrep"])
def test_python_scanners_reject_wrong_observed_versions(
    monkeypatch, tmp_path, scanner_name
):
    workspace = tmp_path / "workspace"
    scans = tmp_path / "scans"
    workspace.mkdir()
    scans.mkdir()
    (workspace / "source.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        scanners,
        "_observed_runtime_version",
        lambda name: "0.0.0" if name == scanner_name else "1.176.0",
    )
    monkeypatch.setattr(
        scanners,
        "_run",
        lambda *args: pytest.fail("wrong-version scanner must not run"),
    )
    results = ScanResults()

    if scanner_name == "ruff":
        scanners._lint("python", workspace, scans, results)
    else:
        scanners._semgrep(workspace, scans, results)

    assert results.scanner_versions[scanner_name] == "0.0.0"
    assert results.scanner_status[scanner_name] == "error"


def test_scan_results_reject_assurance_that_contradicts_observed_material():
    results = ScanResults(
        scanner_runtime_lock_sha256=scanner_runtime_lock_digest(),
        scanner_runtime_environment_sha256="2" * 64,
        scanner_status={
            "ruff": "ok",
            "semgrep": "ok",
            "gitleaks": "ok",
            "trivy": "ok",
        },
        scanner_versions={
            "ruff": "0.15.20",
            "semgrep": "1.176.0",
            "gitleaks": "8.30.1",
            "trivy": "0.72.0",
        },
        scanner_executable_sha256={
            "uv": "1" * 64,
            "python": "2" * 64,
            "ruff": "3" * 64,
            "semgrep": "4" * 64,
            "gitleaks": "5" * 64,
            "trivy": "6" * 64,
        },
        trivy_db=TrivyDatabaseIdentity(
            version=2,
            updated_at="2026-07-14T00:00:00Z",
            next_update="2026-07-15T00:00:00Z",
            downloaded_at="2026-07-14T01:00:00Z",
            content_sha256="7" * 64,
        ),
    )
    results.scanner_assurance = scanners.scanner_assurance_identity(results)
    payload = results.model_dump(mode="python")
    payload["scanner_executable_sha256"]["semgrep"] = "8" * 64

    with pytest.raises(
        ValueError, match="executable evidence does not match scanner assurance"
    ):
        ScanResults.model_validate(payload)


def test_trivy_version_identity_normalizes_bounded_database_metadata(
    monkeypatch, tmp_path
):
    report = {
        "Version": "0.72.0",
        "VulnerabilityDB": {
            "Version": 2,
            "UpdatedAt": "2026-07-14T00:00:00Z",
            "NextUpdate": "2026-07-15T00:00:00Z",
            "DownloadedAt": "2026-07-14T01:00:00Z",
        },
    }

    def fake_execute(command, *, timeout):
        assert command == [
            "/usr/bin/trivy",
            "version",
            "--format",
            "json",
            "--cache-dir",
            str(tmp_path),
        ]
        assert timeout == scanners._VERSION_TIMEOUT
        proc = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(report),
            stderr="",
        )
        return proc, "ok", proc.stdout.encode()

    monkeypatch.setattr(scanners, "_execute_bounded", fake_execute)

    version, database = scanners._trivy_version_identity("/usr/bin/trivy", tmp_path)

    assert version == "0.72.0"
    assert database == TrivyDatabaseIdentity(
        version=2,
        updated_at="2026-07-14T00:00:00Z",
        next_update="2026-07-15T00:00:00Z",
        downloaded_at="2026-07-14T01:00:00Z",
    )


def test_trivy_database_content_digest_binds_names_and_bytes(tmp_path):
    database = tmp_path / "db"
    database.mkdir()
    (database / "metadata.json").write_text('{"Version": 2}\n')
    (database / "trivy.db").write_bytes(b"database-v1")

    first = scanners._trivy_database_content_digest(tmp_path)
    (database / "trivy.db").write_bytes(b"database-v2")
    second = scanners._trivy_database_content_digest(tmp_path)

    assert first is not None
    assert second is not None
    assert first != second


def test_scanner_environment_digest_binds_installed_package_tree(monkeypatch, tmp_path):
    environment = tmp_path / "environment"
    package = environment / "lib" / "python3.12" / "site-packages" / "semgrep"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VERSION = '1.176.0'\n", encoding="utf-8")
    bin_dir = environment / "bin"
    bin_dir.mkdir()
    (bin_dir / "semgrep").symlink_to("../lib/python3.12/site-packages/semgrep")
    monkeypatch.setattr(scanners, "_scanner_identity_root", lambda: tmp_path)

    first = scanners._scanner_environment_content_digest()
    (package / "__init__.py").write_text("VERSION = 'tampered'\n", encoding="utf-8")
    second = scanners._scanner_environment_content_digest()

    assert first is not None
    assert second is not None
    assert first != second


def test_scanner_preflight_binds_every_promoted_material(monkeypatch, tmp_path):
    database = TrivyDatabaseIdentity(
        version=2,
        updated_at="2026-07-14T00:00:00Z",
        next_update="2026-07-15T00:00:00Z",
        downloaded_at="2026-07-14T01:00:00Z",
    )
    executables = {
        "uv": "/tools/uv",
        "gitleaks": "/tools/gitleaks",
        "trivy": "/tools/trivy",
    }
    digests = {
        "/tools/uv": "a" * 64,
        "/tools/python": "b" * 64,
        "/tools/ruff": "f" * 64,
        "/tools/semgrep": "1" * 64,
        "/tools/gitleaks": "c" * 64,
        "/tools/trivy": "d" * 64,
    }
    monkeypatch.setattr(scanners, "_resolved_executable", executables.get)
    monkeypatch.setattr(
        scanners,
        "_scanner_environment_executable",
        lambda name: f"/tools/{name}",
    )
    monkeypatch.setattr(scanners, "_executable_sha256", digests.get)
    monkeypatch.setattr(
        scanners,
        "_installed_version",
        lambda command: "8.30.1" if "gitleaks" in command[0] else None,
    )
    monkeypatch.setattr(scanners, "_scanner_identity_root", lambda: tmp_path)
    monkeypatch.setattr(
        scanners, "_scanner_environment_content_digest", lambda: "2" * 64
    )
    monkeypatch.setattr(
        scanners,
        "_trivy_version_identity",
        lambda executable, cache_dir: ("0.72.0", database),
    )
    monkeypatch.setattr(
        scanners, "_trivy_database_content_digest", lambda cache_dir: "e" * 64
    )

    identity = scanners.scanner_preflight_assurance_identity()

    assert identity.promotion_ready
    assert identity.promotion_blockers == []
    assert identity.scanner_executable_sha256 == {
        "uv": "a" * 64,
        "python": "b" * 64,
        "ruff": "f" * 64,
        "semgrep": "1" * 64,
        "gitleaks": "c" * 64,
        "trivy": "d" * 64,
    }
    assert identity.trivy_db is not None
    assert identity.trivy_db.content_sha256 == "e" * 64


def test_prepare_scanner_runtime_hydrates_then_returns_exact_identity(
    monkeypatch, tmp_path
):
    executables = {"uv": "/tools/uv", "trivy": "/tools/trivy"}
    calls = []
    expected_identity = object()

    monkeypatch.setattr(scanners, "_resolved_executable", executables.get)
    monkeypatch.setattr(
        scanners,
        "_executable_sha256",
        {
            "/tools/uv": "a" * 64,
            "/tools/trivy": "b" * 64,
        }.get,
    )
    monkeypatch.setattr(scanners, "_scanner_identity_root", lambda: tmp_path)

    def fake_execute(command, *, timeout):
        calls.append((command, timeout))
        return SimpleNamespace(returncode=0, stdout="", stderr=""), "ok", b""

    monkeypatch.setattr(scanners, "_execute_bounded", fake_execute)
    monkeypatch.setattr(
        scanners,
        "scanner_preflight_assurance_identity",
        lambda: expected_identity,
    )

    actual = scanners.prepare_scanner_runtime()

    assert actual is expected_identity
    assert calls == [
        (
            [
                "/tools/uv",
                "sync",
                "--project",
                str(SCANNER_RUNTIME_PROJECT.parent),
                "--frozen",
                "--python",
                "3.12",
                "--no-dev",
                "--no-install-project",
            ],
            scanners._PREPARE_TIMEOUT,
        ),
        (
            [
                "/tools/trivy",
                "image",
                "--cache-dir",
                str(tmp_path / "trivy-cache"),
                "--download-db-only",
                "--no-progress",
            ],
            scanners._PREPARE_TIMEOUT,
        ),
    ]


@pytest.mark.parametrize(
    "stdout",
    [
        "not-json",
        "[]",
        '{"results": {}}',
        '{"results": ["bad"]}',
        '{"results": [{"extra": {"severity": []}}]}',
        '{"results": [{"start": "bad"}]}',
    ],
)
def test_semgrep_malformed_report_leaves_metrics_unset(monkeypatch, tmp_path, stdout):
    def fake_run(cmd, out_file):
        del cmd, out_file
        return SimpleNamespace(returncode=0, stdout=stdout), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()

    scanners._semgrep(tmp_path / "workspace", tmp_path, results)

    assert results.scanner_status["semgrep"] == "error"
    assert results.sec_findings_high is None
    assert results.sec_findings_medium is None
    assert results.sec_findings_low is None


@pytest.mark.parametrize(
    "report_update",
    [
        {"version": "1.168.0"},
        {"errors": [{"type": "ParseError"}]},
        {"skipped_rules": [{"rule_id": "unavailable"}]},
        {
            "paths": {
                "scanned": ["safe.py"],
                "skipped": [{"path": "hidden.py", "reason": "ignored"}],
            }
        },
    ],
)
def test_semgrep_rejects_incomplete_target_or_rule_evidence(
    monkeypatch, tmp_path, report_update
):
    def fake_run(cmd, out_file):
        del cmd, out_file
        return SimpleNamespace(
            returncode=0,
            stdout=_semgrep_report(**report_update),
        ), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()

    scanners._semgrep(tmp_path / "workspace", tmp_path, results)

    assert results.scanner_status["semgrep"] == "error"
    assert results.sec_findings_high is None


def test_semgrep_caps_retained_findings_but_preserves_total_counts(
    monkeypatch, tmp_path
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "missing.py"
    source.write_text("danger()\n", encoding="utf-8")
    severities = ["ERROR", "ERROR", "ERROR", "WARNING", "INFO"]
    report = [
        {
            "check_id": f"rule-{index}",
            "extra": {"severity": severity},
            "path": "missing.py",
            "start": {"line": 1},
        }
        for index, severity in enumerate(severities)
    ]

    def fake_run(cmd, out_file):
        del cmd, out_file
        return SimpleNamespace(
            returncode=0,
            stdout=_semgrep_report(report, paths={"scanned": [str(source.resolve())]}),
        ), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    monkeypatch.setattr(scanners, "_MAX_RETAINED_FINDINGS", 2)
    results = ScanResults()

    scanners._semgrep(workspace, tmp_path, results)

    assert results.scanner_status["semgrep"] == "truncated"
    assert results.sec_findings_high == 3
    assert results.sec_findings_medium == 1
    assert results.sec_findings_low == 1
    assert len(results.findings) == 2


def test_semgrep_bounds_fields_and_caches_source_reads(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "source.py").write_text("danger()\ndanger()\n", encoding="utf-8")
    report = [
        {
            "check_id": "r" * 1_000,
            "extra": {"severity": "ERROR"},
            "path": "source.py",
            "start": {"line": line},
        }
        for line in (1, 2)
    ]
    reads = 0
    read_source = scanners._read_source_lines_bounded

    def counted_read(path):
        nonlocal reads
        reads += 1
        return read_source(path)

    def fake_run(cmd, out_file):
        del cmd, out_file
        return SimpleNamespace(
            returncode=0,
            stdout=_semgrep_report(
                report, paths={"scanned": [str((workspace / "source.py").resolve())]}
            ),
        ), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    monkeypatch.setattr(scanners, "_read_source_lines_bounded", counted_read)
    results = ScanResults()

    scanners._semgrep(workspace, tmp_path, results)

    assert reads == 1
    assert results.scanner_status["semgrep"] == "truncated"
    assert len(results.findings) == 2
    assert all(
        len(finding["rule"]) <= scanners._MAX_RULE_CHARS for finding in results.findings
    )
    assert all("primary_location_line_hash" in finding for finding in results.findings)


def test_semgrep_marks_oversize_source_identity_input_truncated(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "source.py").write_text("oversize source\n", encoding="utf-8")
    report = [
        {
            "check_id": "rule",
            "extra": {"severity": "ERROR"},
            "path": "source.py",
            "start": {"line": 1},
        }
    ]

    def fake_run(cmd, out_file):
        del cmd, out_file
        return SimpleNamespace(
            returncode=0,
            stdout=_semgrep_report(
                report, paths={"scanned": [str((workspace / "source.py").resolve())]}
            ),
        ), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    monkeypatch.setattr(scanners, "_MAX_SOURCE_FILE_BYTES", 4)
    results = ScanResults()

    scanners._semgrep(workspace, tmp_path, results)

    assert results.scanner_status["semgrep"] == "truncated"
    assert len(results.findings) == 1
    assert "primary_location_line_hash" not in results.findings[0]


@pytest.mark.parametrize(
    ("returncode", "report_contents"),
    [
        (2, "[]"),
        (0, ""),
        (0, "not-json"),
        (0, b"\xff"),
        (1, '{"findings": []}'),
    ],
)
def test_gitleaks_errors_leave_metric_unset(
    monkeypatch, tmp_path, returncode, report_contents
):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()

    def fake_run(cmd, out_file):
        del out_file
        assert cmd[cmd.index("--report-path") + 1] == "-"
        return SimpleNamespace(returncode=returncode, stdout=report_contents), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    assert results.scanner_status["gitleaks"] == "error"
    assert results.secrets_found is None
    assert results.findings == []


@pytest.mark.parametrize("returncode", [0, 1])
def test_gitleaks_accepts_valid_empty_list_for_documented_exits(
    monkeypatch, tmp_path, returncode
):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()

    def fake_run(cmd, out_file):
        assert out_file == Path(os.devnull)
        assert cmd[cmd.index("--report-path") + 1] == "-"
        assert cmd[cmd.index("--config") + 1] == str(SCANNER_RUNTIME_GITLEAKS_CONFIG)
        assert cmd[cmd.index("--gitleaks-ignore-path") + 1] == str(
            SCANNER_RUNTIME_EMPTY_IGNORE_POLICY
        )
        assert "--ignore-gitleaks-allow" in cmd
        assert cmd[cmd.index("--max-target-megabytes") + 1] == "0"
        return SimpleNamespace(returncode=returncode, stdout=json.dumps([])), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    assert results.scanner_status["gitleaks"] == "ok"
    assert results.secrets_found == 0
    assert json.loads((scans_dir / "gitleaks.json").read_text()) == []
    assert results.scanner_configs["gitleaks"] == (
        "packaged-default; "
        f"config-sha256={scanner_runtime_gitleaks_config_digest()}; "
        "empty-ignore-policy-sha256="
        f"{SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256}; "
        "target-suppressions=disabled; "
        f"invocation-policy-sha256={scanner_runtime_invocation_policy_digest()}"
    )


def test_gitleaks_rejects_a_wrong_observed_version(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_installed_version", lambda command: "8.29.0")
    monkeypatch.setattr(
        scanners,
        "_run",
        lambda cmd, out_file: (
            SimpleNamespace(returncode=0, stdout="[]"),
            "ok",
        ),
    )
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    assert results.scanner_versions["gitleaks"] == "8.29.0"
    assert results.scanner_status["gitleaks"] == "error"
    assert results.secrets_found is None


def test_gitleaks_rejects_ignore_policy_changed_during_scan(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    ignore_policy = tmp_path / "ignore-policy"
    workspace.mkdir()
    scans_dir.mkdir()
    ignore_policy.write_bytes(b"\n")
    monkeypatch.setattr(scanners, "SCANNER_RUNTIME_EMPTY_IGNORE_POLICY", ignore_policy)

    def fake_run(cmd, out_file):
        del cmd, out_file
        ignore_policy.write_text("secret.txt:rule:1\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="[]"), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    assert results.scanner_status["gitleaks"] == "error"
    assert results.secrets_found is None


def test_gitleaks_uses_private_bounded_stage_and_maps_target_ignore_as_data(
    monkeypatch, tmp_path
):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    secret = "".join(("AKIA", "ZXYWVUTSRQPONMLK"))
    git_secret = "".join(("AKIA", "LMNPQRSTVWXZBCDF"))
    target_ignore = workspace / ".gitleaksignore"
    target_ignore.write_text(f'aws_access_key_id = "{secret}"\n', encoding="utf-8")
    git_directory = workspace / ".git"
    git_directory.mkdir()
    (git_directory / "secret.txt").write_text(
        f'aws_access_key_id = "{git_secret}"\n', encoding="utf-8"
    )
    captured = {}

    def fake_run(cmd, out_file):
        del out_file
        staged_workspace = Path(cmd[2])
        staged_ignore = staged_workspace / scanners._GITLEAKS_STAGED_IGNORE_NAME
        staged_git_secret = (
            staged_workspace / scanners._GITLEAKS_STAGED_GIT_NAME / "secret.txt"
        )
        captured["workspace"] = staged_workspace
        assert staged_workspace != workspace
        assert not (staged_workspace / ".gitleaksignore").exists()
        assert not (staged_workspace / ".git").exists()
        assert staged_ignore.read_bytes() == target_ignore.read_bytes()
        assert (
            staged_git_secret.read_bytes()
            == (git_directory / "secret.txt").read_bytes()
        )
        assert stat_mode(staged_workspace) == 0o700
        assert stat_mode(staged_ignore) == 0o600
        return SimpleNamespace(
            returncode=1,
            stdout=json.dumps(
                [
                    {
                        "RuleID": "aws-access-token",
                        "File": str(staged_ignore),
                        "StartLine": 1,
                        "Secret": secret,
                    },
                    {
                        "RuleID": "aws-access-token",
                        "File": str(staged_git_secret),
                        "StartLine": 1,
                        "Secret": git_secret,
                    },
                ]
            ),
        ), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    assert not captured["workspace"].exists()
    assert results.scanner_status["gitleaks"] == "ok"
    assert results.secrets_found == 2
    assert [finding["path"] for finding in results.findings] == [
        ".gitleaksignore",
        ".git/secret.txt",
    ]
    assert secret not in (scans_dir / "gitleaks.json").read_text(encoding="utf-8")
    assert git_secret not in (scans_dir / "gitleaks.json").read_text(encoding="utf-8")


def test_external_stage_neutralizes_nested_scanner_skip_directories(tmp_path):
    workspace = tmp_path / "workspace"
    destination = tmp_path / "staged"
    nested_git = workspace / "nested" / ".git" / "secret.txt"
    node_manifest = workspace / "node_modules" / "package-lock.json"
    nested_git.parent.mkdir(parents=True)
    node_manifest.parent.mkdir(parents=True)
    nested_git.write_text("secret\n", encoding="utf-8")
    node_manifest.write_text("{}\n", encoding="utf-8")

    renamed = scanners._stage_gitleaks_workspace(workspace, destination)

    staged_git = (
        destination / "nested" / scanners._GITLEAKS_STAGED_GIT_NAME / "secret.txt"
    )
    staged_manifest = (
        destination / scanners._STAGED_NODE_MODULES_NAME / "package-lock.json"
    )
    assert staged_git.read_bytes() == nested_git.read_bytes()
    assert staged_manifest.read_bytes() == node_manifest.read_bytes()
    findings = [
        {"File": str(staged_git)},
        {"File": str(staged_manifest)},
    ]
    assert scanners._normalize_staged_gitleaks_findings(
        findings, destination, renamed_controls=renamed
    )
    assert [finding["File"] for finding in findings] == [
        "nested/.git/secret.txt",
        "node_modules/package-lock.json",
    ]


@pytest.mark.parametrize("unsafe_kind", ["symlink", "oversize"])
def test_gitleaks_staging_fails_closed_on_unsafe_or_unbounded_input(
    monkeypatch, tmp_path, unsafe_kind
):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    source = workspace / "source.txt"
    if unsafe_kind == "symlink":
        target = tmp_path / "outside.txt"
        target.write_text("outside\n", encoding="utf-8")
        source.symlink_to(target)
    else:
        source.write_bytes(b"too large")
        monkeypatch.setattr(scanners, "_MAX_GITLEAKS_STAGE_BYTES", 1)
    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(
        scanners,
        "_run",
        lambda *args: pytest.fail("Gitleaks ran with unsafe staged input"),
    )
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    assert results.scanner_status["gitleaks"] == "error"
    assert results.secrets_found is None


def test_gitleaks_8301_target_suppressions_and_size_skip_cannot_hide_secret(
    monkeypatch, tmp_path
):
    executable = scanners._resolved_executable("gitleaks")
    if (
        executable is None
        or scanners._installed_version([executable, "version"]) != "8.30.1"
    ):
        pytest.skip("exact Gitleaks 8.30.1 executable is unavailable")

    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    secret = "".join(("AKIA", "ZXYWVUTSRQPONMLK"))
    source = workspace / "large.txt"
    source.write_bytes(
        b'padding = "safe"\n' * 65_000
        + f'aws_access_key_id = "{secret}" # gitleaks:allow\n'.encode()
    )
    assert source.stat().st_size > 1_000_000
    (workspace / ".gitleaksignore").write_text(
        f"{source}:aws-access-token:65001\n", encoding="utf-8"
    )
    monkeypatch.chdir(workspace)
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    assert results.scanner_status["gitleaks"] == "ok"
    assert results.secrets_found == 1
    assert results.findings[0]["rule"] == "aws-access-token"


def test_gitleaks_8301_default_git_skip_cannot_hide_secret(monkeypatch, tmp_path):
    executable = scanners._resolved_executable("gitleaks")
    if (
        executable is None
        or scanners._installed_version([executable, "version"]) != "8.30.1"
    ):
        pytest.skip("exact Gitleaks 8.30.1 executable is unavailable")

    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    git_directory = workspace / "nested" / ".git"
    git_directory.mkdir(parents=True)
    scans_dir.mkdir()
    secret = "".join(("AKIA", "LMNPQRSTVWXZBCDF"))
    (git_directory / "secret.txt").write_text(
        f'aws_access_key_id = "{secret}" # gitleaks:allow\n',
        encoding="utf-8",
    )
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    assert results.scanner_status["gitleaks"] == "ok"
    assert results.secrets_found == 1
    assert results.findings[0]["path"] == "nested/.git/secret.txt"


def test_gitleaks_rejects_bounded_stdout_truncation(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()

    def fake_run(cmd, out_file):
        del out_file
        assert cmd[cmd.index("--report-path") + 1] == "-"
        return SimpleNamespace(returncode=0, stdout="[]"), "truncated"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    assert results.scanner_status["gitleaks"] == "truncated"
    assert results.secrets_found is None
    assert results.findings == []


def test_gitleaks_caps_findings_and_fields_but_preserves_total_count(
    monkeypatch, tmp_path
):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    raw_findings = [
        {
            "RuleID": "r" * 1_000,
            "File": "missing.txt",
            "StartLine": index + 1,
        }
        for index in range(5)
    ]

    def fake_run(cmd, out_file):
        del out_file
        assert cmd[cmd.index("--report-path") + 1] == "-"
        return SimpleNamespace(returncode=1, stdout=json.dumps(raw_findings)), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    monkeypatch.setattr(scanners, "_MAX_RETAINED_FINDINGS", 2)
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    retained = json.loads((scans_dir / "gitleaks.json").read_text())
    assert results.scanner_status["gitleaks"] == "truncated"
    assert results.secrets_found == 5
    assert len(results.findings) == 2
    assert len(retained) == 2
    assert all(
        len(finding["rule"]) <= scanners._MAX_RULE_CHARS for finding in results.findings
    )


@pytest.mark.parametrize(
    ("constant", "limit", "expected_reads"),
    [
        ("_MAX_SOURCE_CACHE_FILES", 1, 1),
        ("_MAX_SOURCE_CACHE_BYTES", len("secret-one\n"), 2),
        ("_MAX_SOURCE_CACHE_LINES", 1, 2),
    ],
)
def test_gitleaks_enforces_global_source_cache_budgets_across_files(
    monkeypatch, tmp_path, constant, limit, expected_reads
):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    (workspace / "one.txt").write_text("secret-one\n", encoding="utf-8")
    (workspace / "two.txt").write_text("secret-two\n", encoding="utf-8")
    raw_findings = [
        {
            "RuleID": "secret",
            "File": "one.txt",
            "StartLine": 1,
            "Secret": "secret-one",
        },
        {
            "RuleID": "secret",
            "File": "two.txt",
            "StartLine": 1,
            "Secret": "secret-two",
        },
    ]
    reads = 0
    read_source = scanners._read_source_lines_bounded

    def counted_read(path):
        nonlocal reads
        reads += 1
        return read_source(path)

    def fake_run(cmd, out_file):
        del out_file
        assert cmd[cmd.index("--report-path") + 1] == "-"
        return SimpleNamespace(returncode=1, stdout=json.dumps(raw_findings)), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    monkeypatch.setattr(scanners, constant, limit)
    monkeypatch.setattr(scanners, "_read_source_lines_bounded", counted_read)
    results = ScanResults()

    scanners._gitleaks(workspace, scans_dir, results)

    assert reads == expected_reads
    assert results.scanner_status["gitleaks"] == "truncated"
    assert results.secrets_found == 2
    assert len(results.findings) == 2
    assert "primary_location_line_hash" in results.findings[0]
    assert "primary_location_line_hash" not in results.findings[1]


def test_trivy_uses_evaluator_owned_ignore_policy(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    captured = {}
    database = TrivyDatabaseIdentity(
        version=2,
        updated_at="2026-07-14T00:00:00Z",
        next_update="2026-07-15T00:00:00Z",
        downloaded_at="2026-07-14T01:00:00Z",
    )

    def fake_run(cmd, out_file):
        captured["cmd"] = cmd
        captured["out_file"] = out_file
        return SimpleNamespace(returncode=0, stdout=json.dumps({"Results": []})), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    monkeypatch.setattr(
        scanners,
        "_trivy_version_identity",
        lambda executable, cache_dir: ("0.72.0", database),
    )
    monkeypatch.setattr(
        scanners, "_trivy_database_content_digest", lambda cache_dir: "d" * 64
    )
    results = ScanResults()

    scanners._trivy(workspace, scans_dir, results)

    command = captured["cmd"]
    assert command[command.index("--config") + 1] == str(
        SCANNER_RUNTIME_EMPTY_IGNORE_POLICY
    )
    assert command[command.index("--ignorefile") + 1] == str(
        SCANNER_RUNTIME_EMPTY_IGNORE_POLICY
    )
    assert "--skip-db-update" in command
    assert command[command.index("--scanners") + 1] == "vuln"
    assert command[-1] != str(workspace)
    assert not Path(command[-1]).exists()
    assert captured["out_file"] == Path(os.devnull)
    assert results.scanner_status["trivy"] == "ok"
    assert results.vulns == 0
    assert results.scanner_configs["trivy"] == (
        "filesystem-vulnerability-db; "
        "empty-ignore-policy-sha256="
        f"{SCANNER_RUNTIME_EMPTY_IGNORE_POLICY_SHA256}; "
        "target-suppressions=disabled; "
        f"invocation-policy-sha256={scanner_runtime_invocation_policy_digest()}"
    )


def test_trivy_rejects_a_wrong_observed_version(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(
        scanners,
        "_trivy_version_identity",
        lambda executable, cache_dir: ("0.71.0", None),
    )
    monkeypatch.setattr(
        scanners,
        "_run",
        lambda *args: pytest.fail("wrong-version Trivy must not run"),
    )
    results = ScanResults()

    scanners._trivy(workspace, scans_dir, results)

    assert results.scanner_versions["trivy"] == "0.71.0"
    assert results.scanner_status["trivy"] == "error"
    assert results.vulns is None


def test_trivy_rejects_ignore_policy_changed_during_scan(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    ignore_policy = tmp_path / "ignore-policy"
    workspace.mkdir()
    scans_dir.mkdir()
    ignore_policy.write_bytes(b"\n")
    database = TrivyDatabaseIdentity(
        version=2,
        updated_at="2026-07-14T00:00:00Z",
        next_update="2026-07-15T00:00:00Z",
        downloaded_at="2026-07-14T01:00:00Z",
    )
    monkeypatch.setattr(scanners, "SCANNER_RUNTIME_EMPTY_IGNORE_POLICY", ignore_policy)

    def fake_run(cmd, out_file):
        del cmd, out_file
        ignore_policy.write_text("CVE-2020-8203\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout=json.dumps({"Results": []})), "ok"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    monkeypatch.setattr(
        scanners,
        "_trivy_version_identity",
        lambda executable, cache_dir: ("0.72.0", database),
    )
    monkeypatch.setattr(
        scanners, "_trivy_database_content_digest", lambda cache_dir: "d" * 64
    )
    results = ScanResults()

    scanners._trivy(workspace, scans_dir, results)

    assert results.scanner_status["trivy"] == "error"
    assert results.vulns is None


def test_trivy_rejects_database_content_changed_during_scan(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    database = TrivyDatabaseIdentity(
        version=2,
        updated_at="2026-07-14T00:00:00Z",
        next_update="2026-07-15T00:00:00Z",
        downloaded_at="2026-07-14T01:00:00Z",
    )
    digests = iter(("d" * 64, "e" * 64))
    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(
        scanners,
        "_trivy_version_identity",
        lambda executable, cache_dir: ("0.72.0", database),
    )
    monkeypatch.setattr(
        scanners, "_trivy_database_content_digest", lambda cache_dir: next(digests)
    )
    monkeypatch.setattr(
        scanners,
        "_run",
        lambda cmd, out_file: (
            SimpleNamespace(returncode=0, stdout=json.dumps({"Results": []})),
            "ok",
        ),
    )
    results = ScanResults()

    scanners._trivy(workspace, scans_dir, results)

    assert results.scanner_status["trivy"] == "error"
    assert results.vulns is None


def test_trivy_0720_caller_ignore_file_cannot_hide_vulnerability(monkeypatch, tmp_path):
    executable = scanners._resolved_executable("trivy")
    cache_dir_value = os.environ.get("AGENT_EVAL_TEST_TRIVY_CACHE")
    if executable is None or cache_dir_value is None:
        pytest.skip("exact Trivy executable and prepared test DB are unavailable")
    cache_dir = Path(cache_dir_value)
    version, database = scanners._trivy_version_identity(executable, cache_dir)
    if version != "0.72.0" or database is None:
        pytest.skip("exact Trivy 0.72.0 executable and test DB are unavailable")

    workspace = tmp_path / "workspace"
    scans_dir = tmp_path / "scans"
    workspace.mkdir()
    scans_dir.mkdir()
    manifest = workspace / "node_modules" / "package-lock.json"
    manifest.parent.mkdir()
    manifest.write_text(
        json.dumps(
            {
                "name": "fixture",
                "version": "1.0.0",
                "lockfileVersion": 2,
                "requires": True,
                "packages": {
                    "": {"name": "fixture", "version": "1.0.0"},
                    "node_modules/lodash": {"version": "4.17.15"},
                },
                "dependencies": {"lodash": {"version": "4.17.15"}},
            }
        ),
        encoding="utf-8",
    )
    (workspace / ".trivyignore").write_text("CVE-2020-8203\n", encoding="utf-8")
    (workspace / "trivy.yaml").write_text(
        "ignorefile: .trivyignore\n", encoding="utf-8"
    )
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(scanners, "_scanner_identity_root", lambda: cache_dir.parent)
    results = ScanResults()

    scanners._trivy(workspace, scans_dir, results)

    assert results.scanner_status["trivy"] == "ok"
    report = json.loads((scans_dir / "trivy.json").read_text(encoding="utf-8"))
    assert {item["Target"] for item in report["Results"]} == {
        "node_modules/package-lock.json"
    }
    vulnerability_ids = {
        vulnerability["VulnerabilityID"]
        for item in report["Results"]
        for vulnerability in item.get("Vulnerabilities") or []
    }
    assert "CVE-2020-8203" in vulnerability_ids
    assert results.vulns == len(vulnerability_ids)


def test_truncated_process_output_remains_explicitly_non_ok(monkeypatch, tmp_path):
    def fake_run(cmd, out_file):
        del cmd, out_file
        return SimpleNamespace(returncode=0, stdout="[]"), "truncated"

    monkeypatch.setattr(scanners.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(scanners, "_run", fake_run)
    results = ScanResults()
    source = tmp_path / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")

    scanners._lint("python", tmp_path, tmp_path, results)

    assert results.scanner_status["ruff"] == "truncated"
    assert results.lint_errors is None


def _phase_payload(workspace, run_dir):
    return json.dumps(
        scanners.run_scanners(workspace, run_dir).model_dump(mode="json"),
        sort_keys=False,
    )


def test_concurrent_scan_phase_matches_serial_execution(monkeypatch, tmp_path):
    """Concurrency must not change the recorded evidence.

    The scan phase runs registered scanners in parallel. Findings order and
    scanner_* key order both reach the persisted record and the attestation, so
    the parallel phase has to produce exactly what the serial phase produced.
    """

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        "import os\n\n\ndef handler(path):\n    return os.popen(path).read()\n",
        encoding="utf-8",
    )
    (workspace / "config.env").write_text(
        'token = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
    )

    # The first phase in a fresh state directory materialises the scanner
    # runtime, so its before/after environment digests disagree and are
    # recorded as null. Warm that up so the comparison isolates concurrency.
    monkeypatch.setenv("AGENT_EVAL_SCANNER_WORKERS", "1")
    _phase_payload(workspace, tmp_path / "warmup")

    serial = _phase_payload(workspace, tmp_path / "serial")

    monkeypatch.setenv(
        "AGENT_EVAL_SCANNER_WORKERS", str(len(scanners._SCANNER_REGISTRY))
    )
    parallel = _phase_payload(workspace, tmp_path / "parallel")

    assert parallel == serial
    assert json.loads(serial)["scanner_runtime_environment_sha256"] is not None


def test_scan_phase_surfaces_the_first_registered_scanner_failure(monkeypatch):
    """A scanner crash must not be masked or reordered by the thread pool."""

    calls = []

    def failing(name):
        def run(context, results):
            del context, results
            calls.append(name)
            raise RuntimeError(f"{name} exploded")

        return run

    def succeeding(name):
        def run(context, results):
            del context
            calls.append(name)
            results.scanner_status[name] = "ok"

        return run

    monkeypatch.setattr(
        scanners,
        "_SCANNER_REGISTRY",
        (
            scanners._RegisteredScanner("first", failing("first")),
            scanners._RegisteredScanner("second", succeeding("second")),
        ),
    )
    context = scanners.ScannerContext(
        workspace=Path("/nonexistent"),
        scans_dir=Path("/nonexistent"),
        language="python",
        python_targets=None,
    )

    with pytest.raises(RuntimeError, match="first exploded"):
        scanners._execute_scanners(context)

    assert "first" in calls


def test_scanner_worker_count_is_bounded_and_fails_soft(monkeypatch):
    registered = len(scanners._SCANNER_REGISTRY)

    monkeypatch.delenv("AGENT_EVAL_SCANNER_WORKERS", raising=False)
    assert scanners._scanner_worker_count() == registered

    for value, expected in (
        ("1", 1),
        ("0", 1),
        ("-4", 1),
        (str(registered + 99), registered),
        ("not-a-number", registered),
        ("  2  ", min(2, registered)),
        ("", registered),
    ):
        monkeypatch.setenv("AGENT_EVAL_SCANNER_WORKERS", value)
        assert scanners._scanner_worker_count() == expected, value
