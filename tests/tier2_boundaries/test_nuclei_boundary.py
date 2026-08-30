"""
Tier 2 Boundary & Corner Case Tests: Nuclei Template Parsing, Matcher Engine,
Malformed YAML Files, ReDoS Bounds, Extreme Payload Sizes, Non-UTF8 Bytes, and AST Safety.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
import pytest

from flowforge.heuristics.nuclei_loader import (
    NucleiTemplateLoader,
    get_nuclei_loader,
    reset_nuclei_loader,
)
from flowforge.heuristics.nuclei_matcher import (
    NucleiMatcherEngine,
    SafeDSLEvaluator,
    get_nuclei_matcher,
    reset_nuclei_matcher,
)
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.nuclei import (
    NucleiHttpBlock,
    NucleiMatcher,
    NucleiMatcherType,
    NucleiMatchResult,
    NucleiSeverity,
    NucleiTemplate,
)


# ===========================================================================
# 1. Malformed YAML and Corrupt File Boundary Tests
# ===========================================================================

def test_t2_nuclei_boundary_malformed_yaml_structures():
    """Verify loader safely ignores malformed YAML syntax, broken lists, and unexpected roots."""
    with tempfile.TemporaryDirectory(prefix="ff_nuclei_bnd_") as temp_dir:
        root = Path(temp_dir)
        (root / "templates").mkdir(parents=True, exist_ok=True)

        # 1. Broken YAML indentation and unclosed braces
        (root / "templates" / "broken_indent.yaml").write_text(
            "id: broken-indent\ninfo:\n  name: Test\n http:\n- method: [unclosed\n",
            encoding="utf-8",
        )

        # 2. Scalar string root
        (root / "templates" / "scalar_root.yaml").write_text(
            "This is just a raw string, not a dictionary.\n",
            encoding="utf-8",
        )

        # 3. List root
        (root / "templates" / "list_root.yaml").write_text(
            "- item 1\n- item 2\n- item 3\n",
            encoding="utf-8",
        )

        # 4. Null / empty file
        (root / "templates" / "empty_file.yaml").write_text(
            "   \n\t\n",
            encoding="utf-8",
        )

        # 5. Missing ID field
        (root / "templates" / "missing_id.yaml").write_text(
            "info:\n  name: Missing ID\n  severity: high\nhttp:\n  - method: GET\n",
            encoding="utf-8",
        )

        # 6. Null ID field
        (root / "templates" / "null_id.yaml").write_text(
            "id: null\ninfo:\n  name: Null ID\n",
            encoding="utf-8",
        )

        # 7. Valid template alongside broken ones
        (root / "templates" / "valid_template.yaml").write_text(
            "id: valid-template-01\ninfo:\n  name: Valid Template\n  severity: critical\nhttp:\n  - method: GET\n    matchers:\n      - type: status\n        status:\n          - 200\n",
            encoding="utf-8",
        )

        loader = NucleiTemplateLoader(roots=[root], auto_load=True)
        assert loader.total_count == 1
        valid_tmpl = loader.get_template("valid-template-01")
        assert valid_tmpl is not None
        assert valid_tmpl.severity == NucleiSeverity.CRITICAL


def test_t2_nuclei_boundary_non_utf8_and_corrupt_binary_yaml():
    """Verify loader handles binary garbage and invalid UTF-8 bytes gracefully without crashing."""
    with tempfile.TemporaryDirectory(prefix="ff_nuclei_bin_") as temp_dir:
        root = Path(temp_dir)
        (root / "templates").mkdir(parents=True, exist_ok=True)

        # Write binary garbage with invalid UTF-8 sequences
        bin_file = root / "templates" / "corrupted_binary.yaml"
        with open(bin_file, "wb") as fh:
            fh.write(b"\xff\xfe\x00\x00id: \x80\x81\x82\xffinvalid_utf8\ninfo:\n  name: \xf0\x28\x8c\xbc\n")

        # Write valid template
        (root / "templates" / "good.yaml").write_text(
            "id: good-template\ninfo:\n  name: Good\n  severity: low\n",
            encoding="utf-8",
        )

        loader = NucleiTemplateLoader(roots=[root], auto_load=True)
        assert loader.total_count >= 1
        assert loader.get_template("good-template") is not None


def test_t2_nuclei_boundary_invalid_template_ids_and_lookups():
    """Verify get_template gracefully handles empty, none, whitespace, and special characters."""
    loader = NucleiTemplateLoader(roots=[], auto_load=False)
    assert loader.get_template("") is None
    assert loader.get_template("   ") is None
    assert loader.get_template(None) is None  # type: ignore
    assert loader.get_template("../../etc/passwd") is None
    assert loader.get_template("\x00nullbyte") is None
    assert loader.get_template("🎉🚀🔥") is None


# ===========================================================================
# 2. Matcher Engine Boundary & Edge Case Tests
# ===========================================================================

def test_t2_nuclei_boundary_empty_and_null_matcher_fields():
    """Verify matchers with empty words, regexes, status lists, or invalid types fail safely."""
    matcher_engine = NucleiMatcherEngine()

    # 1. Word matcher with empty words list -> returns False
    m_empty_words = NucleiMatcher(type=NucleiMatcherType.WORD, words=[])
    tmpl_empty = NucleiTemplate(
        id="empty-words-tmpl",
        name="Empty Words",
        http_blocks=[NucleiHttpBlock(matchers=[m_empty_words])],
    )
    res = matcher_engine.evaluate_response(tmpl_empty, status_code=200, headers={}, body="Some body text")
    assert res.matched is False

    # 2. Status matcher with empty status list -> returns False
    m_empty_status = NucleiMatcher(type=NucleiMatcherType.STATUS, status=[])
    tmpl_status = NucleiTemplate(
        id="empty-status-tmpl",
        name="Empty Status",
        http_blocks=[NucleiHttpBlock(matchers=[m_empty_status])],
    )
    res_status = matcher_engine.evaluate_response(tmpl_status, status_code=200, headers={}, body="")
    assert res_status.matched is False

    # 3. Regex matcher with invalid syntax regex (e.g. unclosed paren)
    m_bad_regex = NucleiMatcher(type=NucleiMatcherType.REGEX, regex=["[unclosed-bracket(", "(?P<invalid)"])
    tmpl_bad_regex = NucleiTemplate(
        id="bad-regex-tmpl",
        name="Bad Regex",
        http_blocks=[NucleiHttpBlock(matchers=[m_bad_regex])],
    )
    res_bad_re = matcher_engine.evaluate_response(tmpl_bad_regex, status_code=200, headers={}, body="test body")
    assert res_bad_re.matched is False


def test_t2_nuclei_boundary_extreme_payload_sizes_and_subsecond_execution():
    """Verify matching against 10MB+ payloads is bounded and executes without memory exhaustion."""
    matcher_engine = NucleiMatcherEngine()

    template = NucleiTemplate(
        id="cve-large-payload-test",
        name="Large Payload Detection",
        severity=NucleiSeverity.HIGH,
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.REGEX,
                        part="body",
                        regex=[r"AWS_SECRET_ACCESS_KEY=[A-Za-z0-9/+=]{40}"],
                    )
                ],
            )
        ],
    )

    # 10 MB payload consisting of filler + target pattern at the beginning
    prefix = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    ten_mb_body = prefix + ("X" * 10_000_000)

    start = time.perf_counter()
    res = matcher_engine.evaluate_response(template, status_code=200, headers={}, body=ten_mb_body)
    duration = time.perf_counter() - start

    assert res.matched is True
    assert duration < 1.0  # Must evaluate in sub-second time due to bounded regex scan limit


def test_t2_nuclei_boundary_redos_regex_protection():
    """Verify catastrophic backtracking (ReDoS) patterns are safely handled and don't freeze engine."""
    matcher_engine = NucleiMatcherEngine()

    # Potentially catastrophic polynomial / exponential regex pattern
    evil_pattern = r"^(a+)+$"
    template = NucleiTemplate(
        id="redos-test-template",
        name="ReDoS Boundary Test",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.REGEX,
                        part="body",
                        regex=[evil_pattern],
                    )
                ],
            )
        ],
    )

    # Non-matching backtracking string
    backtrack_input = "a" * 22 + "!"

    start = time.perf_counter()
    res = matcher_engine.evaluate_response(template, status_code=200, headers={}, body=backtrack_input)
    duration = time.perf_counter() - start

    assert res.matched is False
    assert duration < 2.0


def test_t2_nuclei_boundary_dsl_ast_safety_and_dunder_denial():
    """Verify SafeDSLEvaluator disallows private dunder attribute access, imports, and arbitrary execution."""
    # 1. Dunder / __class__ exploration attempt
    assert SafeDSLEvaluator.evaluate("body.__class__.__mro__[1].__subclasses__()", {"body": "test"}) is False

    # 2. Builtin execution attempt
    assert SafeDSLEvaluator.evaluate("__import__('os').system('id')", {}) is False

    # 3. Unbalanced or malformed syntax in DSL expression
    assert SafeDSLEvaluator.evaluate("contains((((", {}) is False
    assert SafeDSLEvaluator.evaluate("status_code == = 200", {"status_code": 200}) is False
    assert SafeDSLEvaluator.evaluate("unknown_function(body)", {"body": "test"}) is False

    # 4. Safe expressions with missing variables resolve False rather than throwing
    assert SafeDSLEvaluator.evaluate("non_existent_var > 10", {}) is False


def test_t2_nuclei_boundary_binary_hex_malformed_inputs():
    """Verify binary matcher handles malformed hex patterns without exceptions."""
    matcher_engine = NucleiMatcherEngine()

    template = NucleiTemplate(
        id="malformed-binary-test",
        name="Malformed Binary Pattern",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.BINARY,
                        words=["0xNOTHEX", "GGHHII", "123"],  # Odd digits and non-hex
                    )
                ],
            )
        ],
    )

    res = matcher_engine.evaluate_response(template, status_code=200, headers={}, body=b"\x01\x02\x03")
    assert res.matched is False
