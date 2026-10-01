"""Measures rule quality on the labeled corpus: precision and recall per rule."""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from corpus import CASES  # noqa: E402

from mcp_toolcheck.engine import audit_tools  # noqa: E402
from mcp_toolcheck.rules import ALL_RULES  # noqa: E402


def evaluate() -> dict:
    """Returns per-rule counts plus a list of mismatching cases."""
    counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    mismatches = []
    for item in CASES:
        found = {f.rule_id for f in audit_tools([item["tool"]], ALL_RULES)}
        expected = item["expected"]
        for rule in found & expected:
            counts[rule]["tp"] += 1
        for rule in found - expected:
            counts[rule]["fp"] += 1
        for rule in expected - found:
            counts[rule]["fn"] += 1
        if found != expected:
            mismatches.append((item["id"], sorted(expected), sorted(found)))
    return {"counts": dict(counts), "mismatches": mismatches, "cases": len(CASES)}


def _ratio(num: int, den: int) -> float:
    return num / den if den else 1.0


def summarize(result: dict) -> dict:
    total = {"tp": 0, "fp": 0, "fn": 0}
    for c in result["counts"].values():
        for key in total:
            total[key] += c[key]
    return {
        "precision": _ratio(total["tp"], total["tp"] + total["fp"]),
        "recall": _ratio(total["tp"], total["tp"] + total["fn"]),
    }


def main() -> None:
    result = evaluate()
    print(f"{'rule':8} {'TP':>3} {'FP':>3} {'FN':>3} {'precision':>10} {'recall':>8}")
    for rule in sorted(result["counts"]):
        c = result["counts"][rule]
        print(f"{rule:8} {c['tp']:>3} {c['fp']:>3} {c['fn']:>3} "
              f"{_ratio(c['tp'], c['tp'] + c['fp']):>10.2f} {_ratio(c['tp'], c['tp'] + c['fn']):>8.2f}")
    total = summarize(result)
    print(f"\nOverall ({result['cases']} cases): precision {total['precision']:.2f}, recall {total['recall']:.2f}")
    if result["mismatches"]:
        print("\nMismatches (case: expected -> found):")
        for case_id, expected, found in result["mismatches"]:
            print(f"  {case_id}: {expected} -> {found}")


if __name__ == "__main__":
    main()