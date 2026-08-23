"""
Tier 2 Boundary Tests: Complex Parameter Syntax, Conflicting Keys, and Empty Values.
"""

from __future__ import annotations

import pytest

from flowforge.heuristics.parameters import ParameterExtractor


def test_repeated_and_bracket_array_query_parameters():
    """Verify handling of repeated query parameters and mixed bracket notation."""
    extractor = ParameterExtractor()

    # Repeated identical keys
    qs1 = "role=admin&role=auditor&role=operator"
    params1 = extractor.extract_query_params(qs1)
    assert len(params1) == 1
    assert params1[0].name == "role"
    assert params1[0].is_array is True
    assert params1[0].value == ["admin", "auditor", "operator"]

    # Explicit bracket arrays
    qs2 = "filters[]=active&filters[]=pending&category[]=finance"
    params2 = extractor.extract_query_params(qs2)
    p_map = {p.name: p for p in params2}
    assert "filters" in p_map
    assert p_map["filters"].is_array is True
    assert p_map["filters"].value == ["active", "pending"]


def test_empty_string_and_null_value_parameters():
    """Verify handling of empty string values, valueless keys, and null representations."""
    extractor = ParameterExtractor()

    qs = "search=&debug&filter=null&mode=none&page=0"
    params = extractor.extract_query_params(qs)
    p_map = {p.name: p for p in params}

    assert "search" in p_map and p_map["search"].value == ""
    assert "debug" in p_map and p_map["debug"].value == ""
    assert "filter" in p_map and p_map["filter"].inferred_type == "null"
    assert "mode" in p_map and p_map["mode"].inferred_type == "null"
    assert "page" in p_map and p_map["page"].inferred_type == "integer"


def test_unicode_and_special_character_keys():
    """Verify parameter names and values with unicode characters, spaces, and punctuation."""
    extractor = ParameterExtractor()

    qs = "user%20name=%E6%9D%8E%E9%9B%B7&email=user%2Btag%40test.com&weird%5Bkey%21%5D=value%24100"
    params = extractor.extract_query_params(qs)
    p_map = {p.name: p for p in params}

    assert "user name" in p_map
    assert p_map["user name"].value == "李雷"
    assert "email" in p_map
    assert p_map["email"].value == "user+tag@test.com"
    assert p_map["email"].inferred_type == "string"


def test_large_parameter_collection():
    """Verify extraction performance over a query string with 150 unique parameters."""
    extractor = ParameterExtractor()

    qs = "&".join(f"param_{i}=val_{i * 2}" for i in range(150))
    params = extractor.extract_query_params(qs)

    assert len(params) == 150
    assert params[0].name == "param_0"
    assert params[-1].name == "param_149"
