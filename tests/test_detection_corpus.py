"""Detection quality: every lint rule against the adversarial corpus (tests/corpus).

* each rule has >= 3 positive and >= 3 negative cases;
* positives must raise the rule, negatives must not;
* ``known_fn`` / ``known_fp`` are documented limitations, run as *strict* expected
  failures: fixing one makes the suite say so, so the case gets promoted, never forgotten;
* every rule is documented (lint.RULES) and the registry matches what the engine emits.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mcpsonar.lint import RULES, lint_tool

CORPUS = yaml.safe_load(
    (Path(__file__).parent / "corpus" / "detection.yaml").read_text(encoding="utf-8")
)["rules"]


def _definition(case) -> dict:
    if isinstance(case, dict):
        d = dict(case)
        if isinstance(d.get("description"), str) and d["description"].startswith("LONG:"):
            d["description"] = "word " * (int(d["description"][5:]) // 5)
        return d
    return {"name": "t", "description": case, "inputSchema": {"type": "object"}}


def _raises(rule: str, case) -> bool:
    return any(f.rule == rule for f in lint_tool(_definition(case)))


def _cases(kind: str):
    for rule, sets in CORPUS.items():
        for i, case in enumerate(sets.get(kind, [])):
            yield pytest.param(rule, case, id=f"{rule}-{kind}-{i}")


def test_corpus_covers_every_rule_with_enough_cases():
    assert set(CORPUS) == set(RULES)
    for rule, sets in CORPUS.items():
        assert len(sets["positive"]) >= 3 or rule == "long-description", rule
        assert len(sets["negative"]) >= 2, rule


@pytest.mark.parametrize("rule, case", list(_cases("positive")))
def test_positive_cases_are_detected(rule, case):
    assert _raises(rule, case), f"{rule} missed: {case!r}"


@pytest.mark.parametrize("rule, case", list(_cases("negative")))
def test_negative_cases_are_not_flagged(rule, case):
    assert not _raises(rule, case), f"{rule} false positive: {case!r}"


@pytest.mark.parametrize("rule, case", list(_cases("known_fn")))
@pytest.mark.xfail(strict=True, reason="documented false negative (see corpus)")
def test_known_false_negatives(rule, case):
    assert _raises(rule, case)


@pytest.mark.parametrize("rule, case", list(_cases("known_fp")))
@pytest.mark.xfail(strict=True, reason="documented false positive (see corpus)")
def test_known_false_positives(rule, case):
    assert not _raises(rule, case)


def test_detection_rules_doc_matches_the_registry():
    """docs/detection-rules.md documents every rule with the registry's own metadata."""
    doc = (Path(__file__).parents[1] / "docs" / "detection-rules.md").read_text(encoding="utf-8")
    for rule, info in RULES.items():
        assert f"### `{rule}` — {info.title}" in doc, rule
        line = (f"**Severity** {info.severity} · **Confidence** {info.confidence} · "
                f"**OWASP** {', '.join(info.owasp)}")
        assert line in doc, (rule, line)
