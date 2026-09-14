from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

import agent_eval.attestation as attestation_module
from agent_eval.attestation import (
    CLEAN_WORKTREE_SHA256,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    TREE_ALGORITHM,
    AttestationError,
    build_statement,
    canonical_statement_bytes,
    capture_git_state,
    create_attestation,
    hash_tree,
    read_regular_file,
    verify_attestation,
    write_attestation,
)

GIT_SHA = "a" * 40
IMAGE_DIGEST = f"sha256:{'b' * 64}"


def _task(root: Path) -> Path:
    task = root / "task"
    (task / "environment" / "workspace").mkdir(parents=True)
    (task / "task.yaml").write_text(
        "schema_version: agent-eval.task/v1\n"
        "version: 1.0.0\n"
        "id: demo\nprompt: test\ntest_command: pytest\n",
        encoding="utf-8",
    )
    (task / "environment" / "Dockerfile").write_text(
        "FROM python:3.12\n",
        encoding="utf-8",
    )
    (task / "environment" / "workspace" / "app.py").write_text(
        "answer = 42\n",
        encoding="utf-8",
    )
    return task


def _artifacts(root: Path) -> Path:
    artifacts = root / "run"
    (artifacts / "results").mkdir(parents=True)
    (artifacts / "results.json").write_text(
        '{"resolved":true}\n',
        encoding="utf-8",
    )
    (artifacts / "results" / "junit.xml").write_text(
        '<testsuite tests="1" failures="0"/>\n',
        encoding="utf-8",
    )
    return artifacts


def _build(root: Path, *, reverse: bool = False) -> dict:
    artifacts = _artifacts(root)
    task = _task(root)
    paths = ["results.json", "results/junit.xml"]
    if reverse:
        paths.reverse()
    tools = {"python": "3.12.10", "ruff": "0.15.20"}
    models = {"judge": "codex/default", "agent": "gpt-5.4"}
    if reverse:
        tools = dict(reversed(list(tools.items())))
        models = dict(reversed(list(models.items())))
    return build_statement(
        artifact_root=artifacts,
        artifacts=paths,
        task_root=task,
        task_id="demo",
        image_tag="agent-eval/demo:latest",
        image_digest=IMAGE_DIGEST,
        harness_git_sha=GIT_SHA,
        harness_git_dirty=False,
        models=models,
        tool_versions=tools,
        outcome={
            "correctness": {"passed": 1, "total": 1},
            "resolved": True,
        },
    )


def _bundle(root: Path, **overrides):
    artifacts = _artifacts(root)
    task = _task(root)
    arguments = {
        "statement_path": artifacts / "attestation.json",
        "artifact_root": artifacts,
        "task_root": task,
        "task_id": "demo",
        "image_tag": "agent-eval/demo:latest",
        "image_digest": IMAGE_DIGEST,
        "harness_git_sha": GIT_SHA,
        "harness_git_dirty": False,
        "models": {"agent": "gpt-5.4", "judge": "codex/default"},
        "tool_versions": {"agent-eval": "0.1.0", "python": "3.12.10"},
        "outcome": {"resolved": True, "tests": {"passed": 1, "total": 1}},
    }
    arguments.update(overrides)
    bundle = create_attestation(**arguments)
    return artifacts, task, bundle


def _codes(result) -> set[str]:
    return {failure.code for failure in result.failures}


def _rewrite_statement(path: Path, statement: dict) -> None:
    data = canonical_statement_bytes(statement)
    path.write_bytes(data)
    sidecar = path.with_name(f"{path.name}.sha256")
    sidecar.write_text(f"{hashlib.sha256(data).hexdigest()}\n", encoding="ascii")


def test_statement_is_deterministic_and_binds_required_evidence(tmp_path):
    first = _build(tmp_path / "first")
    second = _build(tmp_path / "second", reverse=True)

    assert canonical_statement_bytes(first) == canonical_statement_bytes(second)
    assert first["_type"] == STATEMENT_TYPE
    assert first["predicateType"] == PREDICATE_TYPE
    assert [subject["name"] for subject in first["subject"]] == [
        "results.json",
        "results/junit.xml",
    ]

    predicate = first["predicate"]
    assert predicate["integrity"] == {
        "mode": "unsigned-local",
        "authenticityClaimed": False,
    }
    assert predicate["harness"]["git"] == {
        "sha": GIT_SHA,
        "dirty": False,
        "worktree_sha256": CLEAN_WORKTREE_SHA256,
    }
    assert predicate["task"]["id"] == "demo"
    assert predicate["task"]["manifest"]["path"] == "task.yaml"
    assert len(predicate["task"]["manifest"]["digest"]["sha256"]) == 64
    assert predicate["task"]["tree"]["algorithm"] == TREE_ALGORITHM
    assert len(predicate["task"]["tree"]["digest"]["sha256"]) == 64
    assert predicate["image"] == {
        "tag": "agent-eval/demo:latest",
        "digest": {"sha256": "b" * 64},
    }
    assert list(predicate["models"]) == ["agent", "judge"]
    assert list(predicate["tools"]) == ["python", "ruff"]
    assert predicate["outcome"]["resolved"] is True


def test_statement_binds_governance_evidence_deterministically(tmp_path):
    artifacts = _artifacts(tmp_path)
    task = _task(tmp_path)
    common = {
        "artifact_root": artifacts,
        "artifacts": ["results/junit.xml", "results.json"],
        "task_root": task,
        "task_id": "demo",
        "image_tag": "agent-eval/demo:latest",
        "image_digest": IMAGE_DIGEST,
        "harness_git_sha": GIT_SHA,
        "harness_git_dirty": False,
    }

    first = build_statement(
        **common,
        governance={
            "policy_revision": "2026-07-14",
            "request_digest": "a" * 64,
            "decision": {"allowed": True, "reason_codes": []},
        },
    )
    second = build_statement(
        **common,
        governance={
            "decision": {"reason_codes": [], "allowed": True},
            "request_digest": "a" * 64,
            "policy_revision": "2026-07-14",
        },
    )

    assert canonical_statement_bytes(first) == canonical_statement_bytes(second)
    assert first["predicate"]["governance"]["decision"]["allowed"] is True


def test_statement_rejects_invalid_governance_evidence(tmp_path):
    artifacts = _artifacts(tmp_path)
    task = _task(tmp_path)
    common = {
        "artifact_root": artifacts,
        "artifacts": ["results.json"],
        "task_root": task,
        "image_tag": "agent-eval/demo:latest",
        "image_digest": IMAGE_DIGEST,
        "harness_git_sha": GIT_SHA,
        "harness_git_dirty": False,
    }

    with pytest.raises(AttestationError, match="non-finite"):
        build_statement(**common, governance={"budget": float("nan")})
    with pytest.raises(AttestationError, match="JSON object"):
        build_statement(**common, governance=["not", "an", "object"])


def test_create_writes_canonical_statement_and_exact_byte_sidecar(tmp_path):
    artifacts, task, bundle = _bundle(tmp_path)

    statement_bytes = bundle.statement_path.read_bytes()
    statement = json.loads(statement_bytes)
    assert statement_bytes == canonical_statement_bytes(statement)
    assert bundle.statement_sha256 == hashlib.sha256(statement_bytes).hexdigest()
    assert bundle.sidecar_path.read_text().strip() == bundle.statement_sha256
    assert bundle.subject_count == 2
    assert {subject["name"] for subject in statement["subject"]} == {
        "results.json",
        "results/junit.xml",
    }

    result = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )
    assert result.ok
    assert result.failures == []
    assert result.sidecar_verified
    assert result.subjects_declared == 2
    assert result.subjects_checked == 2
    assert result.subject_digests == {
        subject["name"]: subject["digest"]["sha256"] for subject in statement["subject"]
    }
    assert result.task_checked
    assert not result.harness_checked


def test_artifact_tamper_is_reported_with_expected_and_actual_digests(tmp_path):
    artifacts, task, bundle = _bundle(tmp_path)
    (artifacts / "results.json").write_text('{"resolved":false}\n')

    result = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )

    assert not result.ok
    failure = next(
        failure
        for failure in result.failures
        if failure.code == "artifact_digest_mismatch"
    )
    assert failure.path == "results.json"
    assert len(failure.expected or "") == 64
    assert len(failure.actual or "") == 64
    assert failure.expected != failure.actual
    assert result.sidecar_verified


@pytest.mark.parametrize(
    ("file_name", "failure_code"),
    [
        ("attestation.json", "statement_unsafe"),
        ("attestation.json.sha256", "sidecar_unsafe"),
    ],
)
def test_verifier_rejects_symlinked_attestation_files(
    tmp_path, file_name, failure_code
):
    artifacts, task, bundle = _bundle(tmp_path)
    linked = artifacts / file_name
    external = tmp_path / f"external-{file_name}"
    external.write_bytes(linked.read_bytes())
    linked.unlink()
    linked.symlink_to(external)

    result = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )

    assert not result.ok
    assert failure_code in _codes(result)


@pytest.mark.parametrize(
    "unsafe_name",
    ["../outside.txt", "/tmp/outside.txt", "a/../../outside", "a\\outside"],
)
def test_verifier_rejects_traversal_and_ambiguous_subject_paths(tmp_path, unsafe_name):
    artifacts, task, bundle = _bundle(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("private\n")
    statement = json.loads(bundle.statement_path.read_bytes())
    statement["subject"][0]["name"] = unsafe_name
    statement["subject"][0]["digest"]["sha256"] = hashlib.sha256(
        outside.read_bytes()
    ).hexdigest()
    _rewrite_statement(bundle.statement_path, statement)

    result = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )

    assert not result.ok
    assert "unsafe_subject_path" in _codes(result)
    assert result.sidecar_verified


def test_verifier_does_not_follow_subject_symlinks(tmp_path):
    artifacts, task, bundle = _bundle(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n")
    os.symlink(outside, artifacts / "escape")
    statement = json.loads(bundle.statement_path.read_bytes())
    statement["subject"][0] = {
        "name": "escape",
        "digest": {"sha256": hashlib.sha256(outside.read_bytes()).hexdigest()},
    }
    _rewrite_statement(bundle.statement_path, statement)

    result = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )

    assert not result.ok
    assert "unsafe_artifact_path" in _codes(result)
    assert "unsafe_artifact_tree" in _codes(result)


def test_task_manifest_and_tree_tamper_are_both_reported(tmp_path):
    artifacts, task, bundle = _bundle(tmp_path)
    (task / "task.yaml").write_text(
        "id: other\nprompt: changed\ntest_command: pytest\n"
    )

    result = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )

    codes = _codes(result)
    assert "task_manifest_digest_mismatch" in codes
    assert "task_id_mismatch" in codes
    assert "task_tree_digest_mismatch" in codes


def test_task_tree_hash_binds_modes_empty_directories_and_symlink_targets(tmp_path):
    task = _task(tmp_path)
    empty = task / "empty"
    empty.mkdir()
    executable = task / "tool.sh"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    os.symlink("tool.sh", task / "tool-link")
    original = hash_tree(task)

    executable.chmod(0o644)
    assert hash_tree(task) != original
    executable.chmod(0o755)
    assert hash_tree(task) == original

    (task / "tool-link").unlink()
    os.symlink("task.yaml", task / "tool-link")
    assert hash_tree(task) != original


def test_extra_artifacts_fail_complete_set_verification_but_can_be_allowed(tmp_path):
    artifacts, task, bundle = _bundle(tmp_path)
    (artifacts / "late.log").write_text("created after attestation\n")

    strict = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )
    partial = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
        require_complete_artifact_set=False,
    )

    assert not strict.ok
    assert any(
        failure.code == "unattested_artifact" and failure.path == "late.log"
        for failure in strict.failures
    )
    assert partial.ok


def test_sidecar_tamper_is_a_structured_failure(tmp_path):
    artifacts, task, bundle = _bundle(tmp_path)
    bundle.sidecar_path.write_text(f"{'0' * 64}\n")

    result = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )

    assert not result.ok
    assert not result.sidecar_verified
    assert "sidecar_digest_mismatch" in _codes(result)


def test_regular_file_snapshot_enforces_a_byte_limit(tmp_path):
    path = tmp_path / "bounded.json"
    path.write_bytes(b"12345")

    with pytest.raises(AttestationError, match="exceeds 4 bytes"):
        read_regular_file(path, max_bytes=4)


def test_task_tree_hash_enforces_entry_and_depth_limits(monkeypatch, tmp_path):
    task = _task(tmp_path)
    monkeypatch.setattr(attestation_module, "MAX_ARTIFACT_FILES", 1)

    with pytest.raises(AttestationError, match="task tree exceeds 1 entries"):
        hash_tree(task)

    monkeypatch.setattr(attestation_module, "MAX_ARTIFACT_FILES", 50_000)
    monkeypatch.setattr(attestation_module, "MAX_JSON_DEPTH", 1)

    with pytest.raises(AttestationError, match="maximum depth"):
        hash_tree(task)


def test_verifier_rejects_excessive_subject_count(monkeypatch, tmp_path):
    artifacts, task, bundle = _bundle(tmp_path)
    statement = json.loads(bundle.statement_path.read_bytes())
    monkeypatch.setattr(attestation_module, "MAX_ATTESTATION_SUBJECTS", 1)
    _rewrite_statement(bundle.statement_path, statement)

    result = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )

    assert not result.ok
    assert "subjects_too_many" in _codes(result)


def test_noncanonical_statement_fails_even_with_updated_sidecar(tmp_path):
    artifacts, task, bundle = _bundle(tmp_path)
    statement = json.loads(bundle.statement_path.read_bytes())
    pretty = (json.dumps(statement, indent=2) + "\n").encode()
    bundle.statement_path.write_bytes(pretty)
    bundle.sidecar_path.write_text(f"{hashlib.sha256(pretty).hexdigest()}\n")

    result = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )

    assert not result.ok
    assert result.sidecar_verified
    assert "statement_not_canonical" in _codes(result)


def test_harness_git_state_can_be_captured_and_rechecked(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    tracked = repo / "tracked.txt"
    tracked.write_text("one\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True)
    captured = capture_git_state(repo)
    assert not captured.dirty
    assert captured.worktree_sha256 == CLEAN_WORKTREE_SHA256

    artifacts, task, bundle = _bundle(
        tmp_path / "evidence",
        harness_repo=repo,
        harness_git_sha=None,
        harness_git_dirty=None,
    )
    matching = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
        harness_repo=repo,
    )
    assert matching.ok
    assert matching.harness_checked

    tracked.write_text("two\n")
    changed = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
        harness_repo=repo,
    )
    assert not changed.ok
    assert changed.harness_checked
    assert "harness_git_dirty_mismatch" in _codes(changed)


def test_different_dirty_worktrees_at_same_head_do_not_verify_as_equivalent(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    tracked = repo / "tracked.txt"
    tracked.write_text("base\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True)

    tracked.write_text("dirty one\n")
    first = capture_git_state(repo)
    artifacts, task, bundle = _bundle(
        tmp_path / "evidence",
        harness_repo=repo,
        harness_git_sha=None,
        harness_git_dirty=None,
    )

    tracked.write_text("dirty two\n")
    second = capture_git_state(repo)
    assert first.sha == second.sha
    assert first.dirty and second.dirty
    assert first.worktree_sha256 != second.worktree_sha256

    changed = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
        harness_repo=repo,
    )
    assert not changed.ok
    assert "harness_git_worktree_sha256_mismatch" in _codes(changed)


def test_worktree_digest_covers_staged_unstaged_and_untracked_evidence(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    tracked = repo / "tracked.txt"
    tracked.write_text("base\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True)

    tracked.write_text("staged\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    staged = capture_git_state(repo)
    tracked.write_text("unstaged\n")
    unstaged = capture_git_state(repo)
    untracked = repo / "new.txt"
    untracked.write_text("one\n")
    untracked_one = capture_git_state(repo)
    untracked.write_text("two\n")
    untracked_two = capture_git_state(repo)

    assert (
        len(
            {
                staged.worktree_sha256,
                unstaged.worktree_sha256,
                untracked_one.worktree_sha256,
                untracked_two.worktree_sha256,
            }
        )
        == 4
    )


def test_untracked_symlink_hashes_target_text_without_following_target(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    tracked = repo / "tracked.txt"
    tracked.write_text("base\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True)

    outside = tmp_path / "outside.txt"
    outside.write_text("first\n")
    link = repo / "untracked-link"
    os.symlink(outside, link)
    before = capture_git_state(repo)
    outside.write_text("second\n")
    after_target_content_change = capture_git_state(repo)
    assert after_target_content_change.worktree_sha256 == before.worktree_sha256

    link.unlink()
    os.symlink(tmp_path / "other-target.txt", link)
    after_link_target_change = capture_git_state(repo)
    assert after_link_target_change.worktree_sha256 != before.worktree_sha256


def test_dirty_explicit_git_state_requires_worktree_digest(tmp_path):
    artifacts = _artifacts(tmp_path)
    task = _task(tmp_path)

    with pytest.raises(AttestationError, match="requires"):
        build_statement(
            artifact_root=artifacts,
            artifacts=["results.json"],
            task_root=task,
            image_tag="agent-eval/demo:latest",
            image_digest=IMAGE_DIGEST,
            harness_git_sha=GIT_SHA,
            harness_git_dirty=True,
        )

    with pytest.raises(AttestationError, match="cannot use"):
        build_statement(
            artifact_root=artifacts,
            artifacts=["results.json"],
            task_root=task,
            image_tag="agent-eval/demo:latest",
            image_digest=IMAGE_DIGEST,
            harness_git_sha=GIT_SHA,
            harness_git_dirty=True,
            harness_git_worktree_sha256=CLEAN_WORKTREE_SHA256,
        )


def test_verifier_aggregates_independent_failures(tmp_path):
    artifacts, task, bundle = _bundle(tmp_path)
    (artifacts / "results.json").write_text("changed\n")
    (task / "environment" / "Dockerfile").write_text("FROM scratch\n")
    bundle.sidecar_path.write_text("not-a-digest\n")

    result = verify_attestation(
        bundle.statement_path,
        artifact_root=artifacts,
        task_root=task,
    )

    codes = _codes(result)
    assert {
        "sidecar_invalid",
        "artifact_digest_mismatch",
        "task_tree_digest_mismatch",
    } <= codes


def test_invalid_digest_and_non_json_outcome_are_rejected_at_creation(tmp_path):
    artifacts = _artifacts(tmp_path)
    task = _task(tmp_path)
    common = {
        "artifact_root": artifacts,
        "artifacts": ["results.json"],
        "task_root": task,
        "image_tag": "agent-eval/demo:latest",
        "harness_git_sha": GIT_SHA,
        "harness_git_dirty": False,
    }

    with pytest.raises(AttestationError, match="image digest"):
        build_statement(**common, image_digest="latest")
    with pytest.raises(AttestationError, match="non-finite"):
        build_statement(
            **common,
            image_digest=IMAGE_DIGEST,
            outcome={"score": float("nan")},
        )


def test_write_rejects_statement_sidecar_path_collision(tmp_path):
    statement = _build(tmp_path / "evidence")
    output = tmp_path / "same"
    with pytest.raises(AttestationError, match="must differ"):
        write_attestation(statement, output, sidecar_path=output)
