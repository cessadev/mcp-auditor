import importlib.util
from pathlib import Path

RUNNER = Path(__file__).parent.parent / "evals" / "run_eval.py"
KNOWN_MISSES = {"bad-poison-paraphrase"}


def _load_runner():
    spec = importlib.util.spec_from_file_location("run_eval", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rule_quality_does_not_regress():
    runner = _load_runner()
    result = runner.evaluate()
    summary = runner.summarize(result)
    assert summary["precision"] >= 0.95
    assert summary["recall"] >= 0.95
    unexpected = [m for m in result["mismatches"] if m[0] not in KNOWN_MISSES]
    assert unexpected == []