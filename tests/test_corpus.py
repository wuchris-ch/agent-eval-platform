import os
import shutil
import sys
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

import agent_eval.corpus as corpus_module
from agent_eval.cli import app
from agent_eval.corpus import load_corpus, validate_corpus

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "benchmarks" / "reviewer-corpus" / "v1" / "corpus.yaml"


def test_checked_in_corpus_hashes_labels_and_reproducers_are_valid():
    result = validate_corpus(CORPUS, execute=True)

    assert result.valid, result.errors
    assert result.version == "1.1.0"
    assert {item.case_id for item in result.reproducers} == {
        "auth-bypass",
        "clean-comprehension",
        "clean-constant",
        "clean-dict-get",
        "clean-enumerate",
        "clean-fstring",
        "clean-guard-clause",
        "clean-refactor",
        "pagination-last-page",
        "path-traversal",
        "retry-extra-attempt",
        "secret-exposure",
        "shell-injection",
        "signature-timing-compare",
        "sql-injection",
        "swallowed-error",
        "tenant-cache-collision",
        "tls-verification-disabled",
        "transfer-balance-loss",
        "validation-boundary",
    }
    assert all(item.passed for item in result.reproducers)


def test_corpus_validation_is_static_by_default():
    result = validate_corpus(CORPUS)

    assert result.valid, result.errors
    assert result.reproducers == []


def test_corpus_rejects_duplicate_yaml_keys(tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    manifest = copied / "corpus.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            'version: "1.1.0"', 'version: "1.1.0"\nversion: "2.0.0"'
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate YAML key 'version'"):
        load_corpus(manifest)


def test_cli_requires_explicit_local_execution_opt_in():
    runner = CliRunner()

    static = runner.invoke(app, ["corpus", "validate", str(CORPUS)])
    explicitly_static = runner.invoke(
        app, ["corpus", "validate", str(CORPUS), "--no-execute"]
    )
    executed = runner.invoke(
        app,
        ["corpus", "validate", str(CORPUS), "--allow-local-execution"],
    )

    assert static.exit_code == 0, static.output
    assert "0 reproducer(s) checked" in static.output
    assert explicitly_static.exit_code == 0, explicitly_static.output
    assert "0 reproducer(s) checked" in explicitly_static.output
    assert executed.exit_code == 0, executed.output
    assert "20 reproducer(s) checked" in executed.output


def test_reproducer_environment_does_not_forward_host_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_EVAL_TEST_SECRET", "must-not-leak")
    command = [
        sys.executable,
        "-c",
        (
            "import os, sys; "
            "sys.exit(1 if 'AGENT_EVAL_TEST_SECRET' in os.environ else 0)"
        ),
    ]

    returncode, output, error = corpus_module._run_reproducer_command(command, tmp_path)

    assert returncode == 0, (output, error)
    assert error is None


@pytest.mark.parametrize(
    ("stream", "program"),
    [
        ("stdout", "print('x' * 10_000)"),
        ("stderr", "import sys; sys.stderr.write('x' * 10_000)"),
    ],
)
def test_reproducer_output_is_bounded(monkeypatch, tmp_path, stream, program):
    monkeypatch.setattr(corpus_module, "REPRODUCER_OUTPUT_LIMIT_BYTES", 128)
    command = [sys.executable, "-c", program]

    returncode, output, error = corpus_module._run_reproducer_command(command, tmp_path)

    assert returncode is None
    assert len(output.encode("utf-8")) <= corpus_module.REPRODUCER_DETAIL_LIMIT_BYTES
    assert error == f"{stream} exceeded the 128-byte limit"


def test_reproducer_timeout_is_enforced(monkeypatch, tmp_path):
    monkeypatch.setattr(corpus_module, "REPRODUCER_TIMEOUT_SECONDS", 0.05)
    command = [sys.executable, "-c", "import time; time.sleep(5)"]

    returncode, output, error = corpus_module._run_reproducer_command(command, tmp_path)

    assert returncode is None
    assert output == ""
    assert error == "timed out after 0.05 second(s)"


def test_reproducer_failure_terminates_process_group_once(monkeypatch, tmp_path):
    monkeypatch.setattr(corpus_module, "REPRODUCER_OUTPUT_LIMIT_BYTES", 128)
    terminate = corpus_module._terminate_reproducer
    calls = 0

    def counted_terminate(process):
        nonlocal calls
        calls += 1
        terminate(process)

    monkeypatch.setattr(corpus_module, "_terminate_reproducer", counted_terminate)

    _, _, error = corpus_module._run_reproducer_command(
        [sys.executable, "-c", "print('x' * 10_000)"], tmp_path
    )

    assert error == "stdout exceeded the 128-byte limit"
    assert calls == 1


def test_reproducer_timeout_kills_descendants_after_leader_exits(monkeypatch, tmp_path):
    monkeypatch.setattr(corpus_module, "REPRODUCER_TIMEOUT_SECONDS", 1)
    pid_file = tmp_path / "child.pid"
    child_program = "import time; time.sleep(30)"
    parent_program = (
        "import pathlib, subprocess, sys; "
        f"child=subprocess.Popen([sys.executable, '-c', {child_program!r}]); "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))"
    )

    returncode, _, error = corpus_module._run_reproducer_command(
        [sys.executable, "-c", parent_program], tmp_path
    )

    assert returncode is None
    assert error == "timed out after 1 second(s)"
    child_pid = int(pid_file.read_text())
    for _ in range(25):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"reproducer descendant {child_pid} survived group termination")


def test_successful_reproducer_cannot_leave_redirected_descendants(tmp_path):
    pid_file = tmp_path / "redirected-child.pid"
    child_program = "import time; time.sleep(30)"
    parent_program = (
        "import pathlib, subprocess, sys; "
        "sink=open('/dev/null', 'wb'); "
        f"child=subprocess.Popen([sys.executable, '-c', {child_program!r}], "
        "stdout=sink, stderr=sink); "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))"
    )

    returncode, _, error = corpus_module._run_reproducer_command(
        [sys.executable, "-c", parent_program], tmp_path
    )

    assert returncode == 0
    assert error is None
    child_pid = int(pid_file.read_text())
    for _ in range(25):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"reproducer descendant {child_pid} survived successful command")


def test_corpus_detects_artifact_tampering(tmp_path):
    root = CORPUS.parent
    copied = tmp_path / "corpus"

    shutil.copytree(root, copied)
    target = copied / "cases" / "auth-bypass" / "head" / "auth.py"
    target.write_text(target.read_text() + "# modified\n")

    result = validate_corpus(copied / "corpus.yaml", execute=False)

    assert not result.valid
    assert any("artifact hash mismatch" in error for error in result.errors)


def test_corpus_detects_referenced_diff_tampering(tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    diff = copied / "cases" / "auth-bypass" / "change.diff"
    diff.write_text(
        diff.read_text(encoding="utf-8") + "\n# unbound mutation\n",
        encoding="utf-8",
    )

    result = validate_corpus(copied / "corpus.yaml", execute=False)

    assert not result.valid
    assert any(
        "artifact hash mismatch: cases/auth-bypass/change.diff" in error
        for error in result.errors
    )


def test_corpus_rejects_rehashed_diff_that_does_not_match_base_and_head(tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    diff = copied / "cases" / "auth-bypass" / "change.diff"
    old_digest = corpus_module._sha256(diff)
    diff.write_text(
        diff.read_text(encoding="utf-8").replace(
            "+    return True", "+    return False"
        ),
        encoding="utf-8",
    )
    manifest = copied / "corpus.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            old_digest,
            corpus_module._sha256(diff),
            1,
        ),
        encoding="utf-8",
    )

    result = validate_corpus(manifest, execute=True)

    assert not result.valid
    assert result.reproducers == []
    assert any("diff artifact does not match" in error for error in result.errors)


def test_corpus_derives_changed_line_denominator_from_verified_diff(tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    benchmark = copied / "benchmark.yaml"
    old_digest = corpus_module._sha256(benchmark)
    benchmark.write_text(
        benchmark.read_text(encoding="utf-8").replace(
            "changed_lines: 1",
            "changed_lines: 1000000",
            1,
        ),
        encoding="utf-8",
    )
    manifest = copied / "corpus.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            old_digest,
            corpus_module._sha256(benchmark),
            1,
        ),
        encoding="utf-8",
    )

    result = validate_corpus(manifest, execute=False)

    assert not result.valid
    assert any("changed_lines does not match" in error for error in result.errors)


def test_corpus_checks_huge_finding_ranges_against_finite_added_lines(tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    benchmark = copied / "benchmark.yaml"
    old_digest = corpus_module._sha256(benchmark)
    benchmark.write_text(
        benchmark.read_text(encoding="utf-8")
        .replace("file: auth.py", "file: missing.py", 1)
        .replace("line_end: 2", "line_end: 999999999999999999", 1),
        encoding="utf-8",
    )
    manifest = copied / "corpus.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            old_digest,
            corpus_module._sha256(benchmark),
            1,
        ),
        encoding="utf-8",
    )

    started = time.monotonic()
    result = validate_corpus(manifest, execute=False)

    assert time.monotonic() - started < 1
    assert not result.valid
    assert any("is not on an added diff line" in error for error in result.errors)


def test_diff_parser_treats_triple_plus_source_as_added_content():
    diff = (
        "diff --git a/a.cpp b/a.cpp\n"
        "--- a/a.cpp\n"
        "+++ b/a.cpp\n"
        "@@ -1 +1,2 @@\n"
        " int i = 0;\n"
        "+++i;\n"
    )

    assert corpus_module._added_lines(diff) == {("a.cpp", 2)}
    assert corpus_module._changed_nonblank_lines(diff) == 1
    assert corpus_module._normalize_git_tree_diff(diff.encode()) == diff.encode()


def test_diff_parser_treats_triple_plus_space_as_added_content():
    diff = (
        "diff --git a/a.cpp b/a.cpp\n"
        "--- a/a.cpp\n"
        "+++ b/a.cpp\n"
        "@@ -1 +1,2 @@\n"
        " int i = 0;\n"
        "+++ i;\n"
    )

    assert corpus_module._added_lines(diff) == {("a.cpp", 2)}
    assert corpus_module._changed_nonblank_lines(diff) == 1


@pytest.mark.parametrize("field", ["base_cwd", "head_cwd"])
def test_corpus_rejects_reproducer_cwd_outside_case_subtree(tmp_path, field):
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(
        CORPUS.read_text(encoding="utf-8").replace(
            f"{field}: cases/auth-bypass/",
            f"{field}: shared/auth-bypass/",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must stay beneath"):
        load_corpus(manifest)


def test_corpus_rejects_swapped_base_and_head_reproducer_labels(tmp_path):
    text = CORPUS.read_text(encoding="utf-8")
    text = text.replace(
        "base_cwd: cases/auth-bypass/base",
        "base_cwd: cases/auth-bypass/head",
        1,
    ).replace(
        "head_cwd: cases/auth-bypass/head",
        "head_cwd: cases/auth-bypass/base",
        1,
    )
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="base_cwd must stay beneath"):
        load_corpus(manifest)


def test_corpus_requires_matching_base_and_head_cwd_suffixes(tmp_path):
    text = CORPUS.read_text(encoding="utf-8").replace(
        "base_cwd: cases/auth-bypass/base",
        "base_cwd: cases/auth-bypass/base/nested",
        1,
    )
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="same relative suffix"):
        load_corpus(manifest)


def test_corpus_rejects_diff_outside_case_subtree_even_after_mutation(tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    unbound = copied / "auth-bypass-unbound.diff"
    shutil.copy2(copied / "cases/auth-bypass/change.diff", unbound)
    unbound.write_text(
        unbound.read_text(encoding="utf-8") + "\n# unbound mutation\n",
        encoding="utf-8",
    )
    manifest = copied / "corpus.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "diff: cases/auth-bypass/change.diff",
            "diff: auth-bypass-unbound.diff",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must stay beneath the case subtree"):
        validate_corpus(manifest, execute=False)


def test_corpus_does_not_execute_when_static_validation_fails(monkeypatch, tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    target = copied / "cases" / "auth-bypass" / "head" / "auth.py"
    target.write_text(target.read_text() + "# modified\n")

    def unexpected_execution(*_args, **_kwargs):
        pytest.fail("reproducer executed before static validation passed")

    monkeypatch.setattr(corpus_module, "_run_reproducer", unexpected_execution)

    result = validate_corpus(copied / "corpus.yaml", execute=True)

    assert not result.valid
    assert result.reproducers == []
    assert any("artifact hash mismatch" in error for error in result.errors)


def test_corpus_detects_benchmark_gold_tampering(tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    benchmark = copied / "benchmark.yaml"
    benchmark.write_text(
        benchmark.read_text(encoding="utf-8").replace(
            "severity: blocker", "severity: major"
        ),
        encoding="utf-8",
    )

    result = validate_corpus(copied / "corpus.yaml", execute=False)

    assert not result.valid
    assert "benchmark manifest hash mismatch" in result.errors


def test_corpus_rejects_unlisted_case_files(tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    helper = copied / "cases" / "auth-bypass" / "head" / "helper.py"
    helper.write_text("UNDECLARED = True\n", encoding="utf-8")

    result = validate_corpus(copied / "corpus.yaml", execute=False)

    assert not result.valid
    assert any(
        "unlisted artifact" in error and "helper.py" in error for error in result.errors
    )


def test_corpus_rejects_symlinks_in_case_subtree(tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    link = copied / "cases" / "auth-bypass" / "head" / "auth-link.py"
    link.symlink_to("auth.py")

    result = validate_corpus(copied / "corpus.yaml", execute=False)

    assert not result.valid
    assert any("symlink is not allowed" in error for error in result.errors)


def test_corpus_rejects_symlinked_cases_ancestor(tmp_path):
    copied = tmp_path / "corpus"
    relocated = copied / "relocated-cases"
    shutil.copytree(CORPUS.parent, copied)
    (copied / "cases").rename(relocated)
    (copied / "cases").symlink_to(relocated, target_is_directory=True)

    result = validate_corpus(copied / "corpus.yaml", execute=False)

    assert not result.valid
    assert any("symlink is not allowed: cases" in error for error in result.errors)


def test_faulty_case_requires_nonzero_head_exit(tmp_path):
    text = CORPUS.read_text(encoding="utf-8").replace(
        "expected_head_exit: 1", "expected_head_exit: 0", 1
    )
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="expected_head_exit must be nonzero"):
        load_corpus(manifest)


def test_all_cases_require_zero_base_exit(tmp_path):
    text = CORPUS.read_text(encoding="utf-8").replace(
        "expected_base_exit: 0", "expected_base_exit: 1", 1
    )
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="expected_base_exit must be zero"):
        load_corpus(manifest)


def test_clean_case_requires_zero_head_exit(tmp_path):
    text = CORPUS.read_text(encoding="utf-8").replace(
        "expected_head_exit: 0", "expected_head_exit: 1", 1
    )
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="clean case expected_head_exit must be zero"):
        load_corpus(manifest)


def test_reproducer_cannot_mutate_head_before_it_runs(monkeypatch, tmp_path):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    calls: list[str] = []

    def mutating_reproducer(_command, cwd):
        calls.append(cwd.name)
        target = cwd.parent / "head" / "auth.py"
        target.write_text("MUTATED = True\n", encoding="utf-8")
        return 0, "", None

    monkeypatch.setattr(
        corpus_module,
        "_run_reproducer_command",
        mutating_reproducer,
    )

    result = validate_corpus(copied / "corpus.yaml", execute=True)

    assert not result.valid
    assert calls == ["base"]
    assert result.reproducers[0].head_exit is None
    assert "mutated the corpus snapshot" in result.reproducers[0].detail


def test_snapshot_detects_same_size_source_mutation_with_restored_mtime(
    monkeypatch, tmp_path
):
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS.parent, copied)
    target = copied / "cases" / "auth-bypass" / "head" / "auth.py"
    original_reader = corpus_module._read_corpus_file_stable
    mutated = False

    def mutating_reader(path, expected):
        nonlocal mutated
        data = original_reader(path, expected)
        if not mutated:
            mutated = True
            metadata = target.stat()
            original = target.read_bytes()
            replacement = bytes([original[0] ^ 1]) + original[1:]
            target.write_bytes(replacement)
            os.utime(
                target,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
            )
        return data

    monkeypatch.setattr(
        corpus_module,
        "_read_corpus_file_stable",
        mutating_reader,
    )

    result = validate_corpus(copied / "corpus.yaml", execute=False)

    assert not result.valid
    assert "changed while its snapshot was created" in result.errors[0]


def test_corpus_paths_cannot_escape_root(tmp_path):
    text = CORPUS.read_text().replace(
        "benchmark_manifest: benchmark.yaml",
        "benchmark_manifest: ../benchmark.yaml",
    )
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(text)

    with pytest.raises(ValueError, match="safe relative path"):
        load_corpus(manifest)
