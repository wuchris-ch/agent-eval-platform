import importlib.util
import json
from pathlib import Path

import pytest

from agent_eval.blackbox.models import digest
from agent_eval.workbench.store import Store

ROOT = Path(__file__).resolve().parents[1]


def load_driver():
    spec = importlib.util.spec_from_file_location(
        "software_study_driver", ROOT / "scripts/software_study.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("broken_runtime", [False, True])
def test_actual_wrapper_preflight_precedes_trial_admission(
    tmp_path, monkeypatch, broken_runtime
):
    driver = load_driver()
    root = tmp_path / "study"
    monkeypatch.setenv("AGENT_EVAL_STATE_DIR", str(root / "evaluator-state"))
    image = "sha256:" + "a" * 64
    calls = []

    def phase(_root, _config, name, path, **_kwargs):
        request = json.loads(path.read_bytes())
        task = path.stem.rsplit("-", 1)[0]
        calls.append((name, task))
        assert name in {"preflight", "recipe"}, "Preparation must not invoke models"
        if task == "payment-form":
            assert request["recipe"]["image"] == image
        if name == "preflight":
            if broken_runtime and task == "payment-form":
                raise RuntimeError("SandboxError")
            return {"passed": True, "model_calls": 0}
        assert ("preflight", task) in calls
        return {
            "schema_version": "agent-eval.recipe/v2",
            "name": request["policy"]["name"],
            "producer_sha256": digest(request["policy"]),
            "capability_sha256": digest(request["allowed_paths"]),
            "model_configuration_sha256": "b" * 64,
            "budget": {
                "max_model_requests": 20,
                "max_total_tokens": 200000,
                "max_elapsed_seconds": 600,
                "max_repairs": 0,
            },
        }

    monkeypatch.setattr(driver, "phase", phase)
    config = {
        "producer_source": str(ROOT),
        "producer_python": "python",
        "gateway_profile": str(tmp_path / "private-profile.json"),
        "image": image,
    }
    if broken_runtime:
        with pytest.raises(RuntimeError, match="SandboxError"):
            driver.prepare(root, config)
        assert not (root / "prepared.json").exists()
        assert not (root / "executions").exists()
        assert Store().list("software-study-v1", "trial-ticket-v2")["items"] == []
    else:
        driver.prepare(root, config)
        prepared = json.loads((root / "prepared.json").read_bytes())
        assert len(set(prepared["schedule"])) == 24
        assert len(list((root / "preflights").glob("*.json"))) == 4
        assert [name for name, _task in calls].count("preflight") == 4
