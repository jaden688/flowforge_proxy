"""
Tier 2 Boundary & Corner Case Tests: Rule Engine ReDoS Safety, Invalid YAML/JSON Syntax,
Missing Targets, Shannon Entropy Edge Cases, and Combinators (Features F11–F14).
"""

from __future__ import annotations

import re
import time
import pytest

from flowforge.heuristics.rule_engine import (
    ConditionEvaluator,
    FlowInspectionContext,
    RuleEngine,
    calculate_shannon_entropy,
)
from flowforge.models.rules import (
    MatchRule,
    RuleCondition,
    RuleOperator,
    RuleSeverity,
)


def test_t2_rules_redos_and_regex_safety_bound():
    """Verify regex evaluation enforces bounded input length to prevent catastrophic backtracking."""
    evaluator = ConditionEvaluator(max_regex_length=5000)

    # Evil regex vulnerable to ReDoS: (a+)+$
    evil_pattern = r"^(a+)+$"
    # Input with non-matching suffix
    evil_input = "a" * 100_000 + "X"

    ctx = FlowInspectionContext(response_body=evil_input)
    cond = RuleCondition(field="body", operator=RuleOperator.REGEX, value=evil_pattern)

    start = time.perf_counter()
    matched, details = evaluator.evaluate(cond, ctx)
    duration = time.perf_counter() - start

    # Must finish rapidly (< 0.5s) due to bounded length truncation
    assert duration < 0.5
    assert matched is False


def test_t2_rules_invalid_regex_syntax_safe_fallback():
    """Verify invalid/uncompilable regular expressions do not crash and return matched=False."""
    evaluator = ConditionEvaluator()
    ctx = FlowInspectionContext(response_body="Sample Body Content")

    # Invalid regex syntax (unclosed parenthesis)
    cond = RuleCondition(field="body", operator=RuleOperator.REGEX, value="([unclosed_regex")

    matched, details = evaluator.evaluate(cond, ctx)
    assert matched is False
    assert details["matched"] is False

    # NOT_REGEX with invalid pattern should return True (safe fallback)
    cond_not = RuleCondition(field="body", operator=RuleOperator.NOT_REGEX, value="([unclosed_regex")
    matched_not, _ = evaluator.evaluate(cond_not, ctx)
    assert matched_not is True


def test_t2_rules_invalid_yaml_and_json_parsing_resilience():
    """Verify RuleEngine raises ValueError on malformed YAML or non-dictionary syntax."""
    # 1. Broken YAML syntax
    broken_yaml = "id: rule-test\nname: [unclosed list\n  - invalid"
    with pytest.raises(Exception):
        RuleEngine.parse_rule_from_yaml(broken_yaml)

    # 2. YAML is a list instead of dict
    list_yaml = "- item1\n- item2\n- item3"
    with pytest.raises(ValueError):
        RuleEngine.parse_rule_from_yaml(list_yaml)

    # 3. Broken JSON syntax
    broken_json = '{"id": "rule-test", "name": '
    with pytest.raises(Exception):
        RuleEngine.parse_rules_from_json(broken_json)


def test_t2_rules_missing_targets_and_none_values():
    """Verify condition evaluator handles missing headers, cookies, and query params cleanly."""
    evaluator = ConditionEvaluator()
    ctx = FlowInspectionContext(
        request_headers={},
        response_headers={},
        query_params={},
        request_cookies={},
        response_body="",
    )

    # 1. Missing header equals value
    cond1 = RuleCondition(field="header", target="x-nonexistent", operator=RuleOperator.EQUALS, value="admin")
    assert evaluator.evaluate(cond1, ctx)[0] is False

    # 2. Missing header exists -> False
    cond2 = RuleCondition(field="header", target="x-nonexistent", operator=RuleOperator.EXISTS)
    assert evaluator.evaluate(cond2, ctx)[0] is False

    # 3. Missing header not_exists -> True
    cond3 = RuleCondition(field="header", target="x-nonexistent", operator=RuleOperator.NOT_EXISTS)
    assert evaluator.evaluate(cond3, ctx)[0] is True

    # 4. Invert flag on missing target
    cond4 = RuleCondition(field="header", target="x-nonexistent", operator=RuleOperator.EQUALS, value="admin", invert=True)
    assert evaluator.evaluate(cond4, ctx)[0] is True


def test_t2_rules_non_numeric_comparisons_safety():
    """Verify numeric operators (gt, lt, gte, lte) handle non-numeric values without raising exceptions."""
    evaluator = ConditionEvaluator()
    ctx = FlowInspectionContext(response_body="non_numeric_body_string")

    cond_gt = RuleCondition(field="body", operator=RuleOperator.GT, value=100)
    assert evaluator.evaluate(cond_gt, ctx)[0] is False

    cond_lt = RuleCondition(field="status", operator=RuleOperator.LT, value=400)
    # When status_code is None, must return False
    assert evaluator.evaluate(cond_lt, ctx)[0] is False


def test_t2_rules_entropy_boundary_and_null_inputs():
    """Verify Shannon entropy handles None, bytes, zero-length, single-byte, and maximum entropy."""
    assert calculate_shannon_entropy(None) == 0.0
    assert calculate_shannon_entropy(b"") == 0.0
    assert calculate_shannon_entropy(b"\x00") == 0.0
    assert calculate_shannon_entropy(b"\x00\x00\x00") == 0.0

    # 256 distinct bytes in 256 byte payload = exact max theoretical entropy 8.0
    all_bytes = bytes(range(256))
    max_ent = calculate_shannon_entropy(all_bytes)
    assert round(max_ent, 2) == 8.0


def test_t2_rules_combinator_all_any_not_edge_cases():
    """Verify rule evaluation with empty condition lists and all/any/not combinator logic."""
    engine = RuleEngine(load_defaults=False)
    ctx_obj = {"method": "GET", "url": "http://test.com", "response_status": 200}

    # 1. Rule with empty conditions
    empty_rule = MatchRule(id="rule-empty", name="Empty Rule", conditions=[])
    res_empty = engine.evaluate_rule(empty_rule, ctx_obj)
    assert res_empty.matched is True

    # 2. Rule with combinator "not" (NOR)
    nor_rule = MatchRule(
        id="rule-nor",
        name="NOR Rule",
        condition_combinator="not",
        conditions=[
            RuleCondition(field="status", operator=RuleOperator.EQUALS, value=500),
            RuleCondition(field="method", operator=RuleOperator.EQUALS, value="DELETE"),
        ],
    )
    res_nor = engine.evaluate_rule(nor_rule, ctx_obj)
    # Neither 500 nor DELETE matched -> NOR passes
    assert res_nor.matched is True
