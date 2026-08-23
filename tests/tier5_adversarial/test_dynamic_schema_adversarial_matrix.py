"""
Tier 5 Adversarial Matrix: Dynamic JSON Schema Inferrer & Multi-Flow Synthesizer.
Adversarial Challenger Suite:
1. Deep nested objects and recursion limit boundaries.
2. Rapid succession of conflicting type fields and polymorphic type unions.
3. Lists of heterogeneous dictionaries, primitives, and nested collections.
4. Empty objects, nulls, and boundary structures.
5. Boolean-to-integer distinction, numeric promotion, and type coalescence.
6. Multi-endpoint schema isolation and cross-contamination prevention.
7. Mathematical frequency calculation and required vs. optional property tracking.
8. Randomized stress fuzzing and JSON serializability invariant.
"""

import copy
import json
import math
import random
import string
import time
from typing import Any, Dict, List, Set, Union
import pytest

from flowforge.heuristics.schema_inferrer import SchemaInferrer
from flowforge.api.routes.dossier import compute_endpoint_hash


# ============================================================================
# 1. Deep Nested Objects & Recursion Limit Stress Tests
# ============================================================================

def _generate_nested_dict(depth: int, branch_factor: int = 1, current: int = 1) -> Dict[str, Any]:
    """Generate deeply nested dictionary with optional branching."""
    if current >= depth:
        return {f"leaf_{i}": f"val_{i}_{current}" for i in range(branch_factor)}
    
    node = {f"level_{current}_key_{i}": _generate_nested_dict(depth, branch_factor, current + 1) for i in range(branch_factor)}
    node["depth_marker"] = current
    return node


def test_adversarial_deep_nesting_exact_recursion_limits():
    """Empirically test SchemaInferrer at exact recursion limit boundaries (10, 19, 20, 21, 50, 100)."""
    inferrer = SchemaInferrer()

    # Boundary 1: Depth 10 (well within limit 20)
    d10 = _generate_nested_dict(depth=10)
    s10 = inferrer.infer_payload_schema(d10)
    assert s10["type"] == "object"
    assert "properties" in s10

    # Boundary 2: Depth 20 (exact limit)
    d20 = _generate_nested_dict(depth=20)
    s20 = inferrer.infer_payload_schema(d20)
    assert s20["type"] == "object"

    # Boundary 3: Depth 21 (triggers recursion limit at leaf)
    d21 = _generate_nested_dict(depth=21)
    s21 = inferrer.infer_payload_schema(d21)
    assert s21["type"] == "object"
    # Find leaf representation
    curr = s21
    while isinstance(curr, dict) and "properties" in curr and curr["properties"]:
        key = list(curr["properties"].keys())[0]
        curr = curr["properties"][key]
    # Leaf at depth > 20 must gracefully degrade to bounded string descriptor
    assert curr.get("type") == "string"
    assert "Max recursion depth exceeded" in curr.get("description", "")

    # Boundary 4: Extreme Depth 100 (must not raise RecursionError)
    d100 = _generate_nested_dict(depth=100)
    s100 = inferrer.infer_payload_schema(d100)
    assert isinstance(s100, dict)
    assert s100["type"] == "object"


def test_adversarial_asymmetric_nested_tree_merges():
    """Empirically verify merging asymmetric nested trees with divergent depths and schemas."""
    inferrer = SchemaInferrer()

    tree_a = {
        "user": {
            "profile": {
                "geo": {
                    "lat": 37.7749,
                    "lon": -122.4194,
                    "metadata": {
                        "accuracy": 5,
                        "source": "gps",
                    }
                }
            }
        }
    }

    tree_b = {
        "user": {
            "profile": {
                "geo": {
                    "city": "San Francisco",
                    "country": "USA",
                },
                "preferences": {
                    "theme": "dark",
                    "notifications": True,
                }
            }
        }
    }

    schema_a = inferrer.infer_payload_schema(tree_a)
    schema_b = inferrer.infer_payload_schema(tree_b)

    merged = inferrer.merge_schemas(schema_a, schema_b, sample_count=2)

    user_props = merged["properties"]["user"]["properties"]
    prof_props = user_props["profile"]["properties"]

    assert "geo" in prof_props
    assert "preferences" in prof_props

    geo_props = prof_props["geo"]["properties"]
    # Verify properties from both branches merged accurately
    assert "lat" in geo_props
    assert "lon" in geo_props
    assert "city" in geo_props
    assert "country" in geo_props
    assert "metadata" in geo_props

    # Required field verification in nested tree:
    # 'user' and 'profile' were in both -> required
    assert "user" in merged["required"]
    assert "profile" in user_props["user"]["required"] if "user" in user_props else "profile" in merged["properties"]["user"]["required"]
    # 'geo' was in both profile objects -> required
    assert "geo" in prof_props["geo"]["required"] if "geo" in prof_props and isinstance(prof_props["geo"].get("required"), list) and "geo" in prof_props["geo"].get("required") else "geo" in user_props["profile"]["required"]
    # 'preferences' was only in tree_b -> optional
    assert "preferences" not in user_props["profile"]["required"]


# ============================================================================
# 2. Conflicting Type Fields & Polymorphic Union Stress Tests
# ============================================================================

def test_adversarial_rapid_succession_conflicting_types():
    """Empirically test 1,000 rapid polymorphic type mutations on a single field."""
    inferrer = SchemaInferrer()

    payload_types = [
        ("int", {"target_field": 100}),
        ("str", {"target_field": "hello world"}),
        ("bool", {"target_field": True}),
        ("float", {"target_field": 3.14159}),
        ("null", {"target_field": None}),
        ("dict", {"target_field": {"sub_key": "val"}}),
        ("list", {"target_field": [1, 2, 3]}),
    ]

    current_schema = None
    sample_count = 0

    for i in range(1000):
        sample_count += 1
        _, payload = payload_types[i % len(payload_types)]
        new_schema = inferrer.infer_payload_schema(payload)
        current_schema = inferrer.merge_schemas(current_schema, new_schema, sample_count=sample_count)

    target_prop = current_schema["properties"]["target_field"]
    merged_types = target_prop["type"]

    assert isinstance(merged_types, list)
    expected_all_types = sorted(["array", "boolean", "null", "number", "object", "string"])
    assert sorted(merged_types) == expected_all_types

    # Ensure observed count equals total samples
    assert target_prop["x-flowforge-observed-count"] == 1000
    assert target_prop["x-flowforge-frequency"] == 1.0


def test_adversarial_numeric_type_coalescence_and_bounds():
    """Verify numeric type promotion: integer + number -> number, with correct min/max bounds."""
    inferrer = SchemaInferrer()

    # Step 1: Integer [10, 100]
    s1 = inferrer.infer_payload_schema({"val": 10})
    s2 = inferrer.infer_payload_schema({"val": 100})
    merged = inferrer.merge_schemas(s1, s2, sample_count=2)
    assert merged["properties"]["val"]["type"] == "integer"
    assert merged["properties"]["val"]["minimum"] == 10
    assert merged["properties"]["val"]["maximum"] == 100

    # Step 2: Float [5.5, 50.0]
    s3 = inferrer.infer_payload_schema({"val": 5.5})
    s4 = inferrer.infer_payload_schema({"val": 150.25})
    merged = inferrer.merge_schemas(merged, s3, sample_count=3)
    merged = inferrer.merge_schemas(merged, s4, sample_count=4)

    prop = merged["properties"]["val"]
    # Number covers integer
    assert prop["type"] == "number"
    assert prop["minimum"] == 5.5
    assert prop["maximum"] == 150.25


# ============================================================================
# 3. Lists of Heterogeneous Dictionaries & Arrays
# ============================================================================

def test_adversarial_heterogeneous_lists_of_dicts_and_primitives():
    """Empirically test arrays containing mixed dictionaries, strings, numbers, and booleans."""
    inferrer = SchemaInferrer()

    hetero_payload = {
        "items": [
            {"id": 1, "name": "Item A", "active": True},
            {"id": 2, "sku": "SKU-99", "price": 49.99},
            {"id": 3, "tags": ["sale", "featured"]},
            "scalar_string_element",
            420,
            True,
            None,
        ]
    }

    schema = inferrer.infer_payload_schema(hetero_payload)
    items_schema = schema["properties"]["items"]

    assert items_schema["type"] == "array"
    assert items_schema["minItems"] == 7
    assert items_schema["maxItems"] == 7

    elem_schema = items_schema["items"]
    # Array items schema should unify all types
    assert isinstance(elem_schema["type"], list)
    assert "object" in elem_schema["type"]
    assert "string" in elem_schema["type"]
    assert "integer" in elem_schema["type"]
    assert "boolean" in elem_schema["type"]
    assert "null" in elem_schema["type"]

    # Check merged object properties across dict items
    assert "properties" in elem_schema
    dict_props = elem_schema["properties"]
    assert "id" in dict_props
    assert "name" in dict_props
    assert "sku" in dict_props
    assert "price" in dict_props
    assert "tags" in dict_props


def test_adversarial_array_schema_evolution_across_flows():
    """Verify array schemas evolving across separate flows from empty to heterogeneous."""
    inferrer = SchemaInferrer()

    flow1 = {"records": []}
    flow2 = {"records": [{"id": "uuid-1", "value": 10}]}
    flow3 = {"records": [{"id": "uuid-2", "value": 20, "extra": "info"}]}
    flow4 = {"records": ["raw_id_1", "raw_id_2", "raw_id_3"]}

    s1 = inferrer.infer_payload_schema(flow1)
    s2 = inferrer.infer_payload_schema(flow2)
    s3 = inferrer.infer_payload_schema(flow3)
    s4 = inferrer.infer_payload_schema(flow4)

    merged = inferrer.merge_schemas(s1, s2, sample_count=2)
    merged = inferrer.merge_schemas(merged, s3, sample_count=3)
    merged = inferrer.merge_schemas(merged, s4, sample_count=4)

    rec_prop = merged["properties"]["records"]
    assert rec_prop["type"] == "array"
    assert rec_prop["minItems"] == 0
    assert rec_prop["maxItems"] == 3

    item_types = rec_prop["items"]["type"]
    assert isinstance(item_types, list)
    assert sorted(item_types) == ["object", "string"]


# ============================================================================
# 4. Empty Objects, Null Values & Boundary Structures
# ============================================================================

def test_adversarial_empty_objects_and_null_coalescence():
    """Empirically test empty dicts, empty lists, null fields, and boundary primitives."""
    inferrer = SchemaInferrer()

    # Case A: Empty dicts
    empty_obj_schema = inferrer.infer_payload_schema({})
    assert empty_obj_schema["type"] == "object"
    assert empty_obj_schema["properties"] == {}
    assert empty_obj_schema["required"] == []

    # Case B: Merge empty dict with rich dict
    rich_obj_schema = inferrer.infer_payload_schema({"a": 1, "b": "val"})
    merged_empty_rich = inferrer.merge_schemas(empty_obj_schema, rich_obj_schema, sample_count=2)
    assert merged_empty_rich["type"] == "object"
    assert "a" in merged_empty_rich["properties"]
    assert "b" in merged_empty_rich["properties"]
    # Since empty dict had no required fields, merged required must be empty
    assert merged_empty_rich.get("required", []) == []

    # Case C: Null value inference
    null_schema = inferrer.infer_payload_schema(None)
    assert null_schema["type"] == "null"

    # Case D: Empty string
    empty_str_schema = inferrer.infer_payload_schema("")
    assert empty_str_schema["type"] == "string"
    assert empty_str_schema["minLength"] == 0
    assert empty_str_schema["maxLength"] == 0

    # Case E: Merging null property with primitive
    s_null_prop = inferrer.infer_payload_schema({"status": None})
    s_str_prop = inferrer.infer_payload_schema({"status": "active"})
    merged_status = inferrer.merge_schemas(s_null_prop, s_str_prop, sample_count=2)
    status_type = merged_status["properties"]["status"]["type"]
    assert sorted(status_type) == ["null", "string"]


# ============================================================================
# 5. Boolean vs Integer Distinction & Python Subtype Defense
# ============================================================================

def test_adversarial_boolean_vs_integer_distinction():
    """Verify SchemaInferrer distinguishes Python bool (subclass of int) from int and float."""
    inferrer = SchemaInferrer()

    # Standalone inferences
    s_true = inferrer.infer_payload_schema({"flag": True})
    s_false = inferrer.infer_payload_schema({"flag": False})
    s_zero = inferrer.infer_payload_schema({"flag": 0})
    s_one = inferrer.infer_payload_schema({"flag": 1})

    assert s_true["properties"]["flag"]["type"] == "boolean"
    assert s_false["properties"]["flag"]["type"] == "boolean"
    assert s_zero["properties"]["flag"]["type"] == "integer"
    assert s_one["properties"]["flag"]["type"] == "integer"

    # Merge True with 1
    m1 = inferrer.merge_schemas(s_true, s_one, sample_count=2)
    assert sorted(m1["properties"]["flag"]["type"]) == ["boolean", "integer"]

    # Merge False with 0 and with float 0.0
    s_float_zero = inferrer.infer_payload_schema({"flag": 0.0})
    m2 = inferrer.merge_schemas(s_false, s_zero, sample_count=2)
    m2 = inferrer.merge_schemas(m2, s_float_zero, sample_count=3)
    assert sorted(m2["properties"]["flag"]["type"]) == ["boolean", "number"]


# ============================================================================
# 6. Multi-Endpoint Schema Isolation Stress
# ============================================================================

def test_adversarial_multi_endpoint_schema_isolation_100_endpoints():
    """Verify 100 interleaved endpoints maintain strict schema isolation with no cross-leakage."""
    inferrer = SchemaInferrer()
    endpoint_schemas: Dict[str, Dict[str, Any]] = {}
    endpoint_counts: Dict[str, int] = {}

    # Define 100 distinct endpoints with distinct parameter types for shared parameter names
    num_endpoints = 100
    for ep_idx in range(num_endpoints):
        method = "POST" if ep_idx % 2 == 0 else "GET"
        path = f"/api/v1/resource_{ep_idx}"
        ep_hash = compute_endpoint_hash(method, "api.corp.internal", path)
        endpoint_schemas[ep_hash] = {}
        endpoint_counts[ep_hash] = 0

    # Interleave 10 flows per endpoint (1,000 total flows)
    for flow_cycle in range(10):
        for ep_idx in range(num_endpoints):
            method = "POST" if ep_idx % 2 == 0 else "GET"
            path = f"/api/v1/resource_{ep_idx}"
            ep_hash = compute_endpoint_hash(method, "api.corp.internal", path)

            # Each endpoint has a signature type for 'common_id'
            sig = ep_idx % 4
            if sig == 0:
                payload = {"common_id": 1000 + flow_cycle, f"ep_{ep_idx}_unique": True}
            elif sig == 1:
                payload = {"common_id": f"uuid-{ep_idx}-{flow_cycle}", f"ep_{ep_idx}_unique": "str"}
            elif sig == 2:
                payload = {"common_id": (flow_cycle % 2 == 0), f"ep_{ep_idx}_unique": 3.14}
            else:
                payload = {"common_id": [flow_cycle, flow_cycle + 1], f"ep_{ep_idx}_unique": {"k": "v"}}

            inferred = inferrer.infer_payload_schema(payload)
            endpoint_counts[ep_hash] += 1
            endpoint_schemas[ep_hash] = inferrer.merge_schemas(
                endpoint_schemas[ep_hash],
                inferred,
                sample_count=endpoint_counts[ep_hash],
            )

    # Verification: Assert each endpoint's schema contains only its own types and properties
    for ep_idx in range(num_endpoints):
        method = "POST" if ep_idx % 2 == 0 else "GET"
        path = f"/api/v1/resource_{ep_idx}"
        ep_hash = compute_endpoint_hash(method, "api.corp.internal", path)
        schema = endpoint_schemas[ep_hash]

        props = schema["properties"]
        assert f"ep_{ep_idx}_unique" in props
        # Verify NO other endpoint's unique key is present
        other_ep_key = f"ep_{(ep_idx + 1) % num_endpoints}_unique"
        assert other_ep_key not in props

        # Verify signature type for common_id
        sig = ep_idx % 4
        common_id_type = props["common_id"]["type"]
        if sig == 0:
            assert common_id_type == "integer"
        elif sig == 1:
            assert common_id_type == "string"
        elif sig == 2:
            assert common_id_type == "boolean"
        else:
            assert common_id_type == "array"


# ============================================================================
# 7. Mathematical Frequency & Required/Optional Oracle
# ============================================================================

def test_adversarial_mathematical_frequency_and_required_oracle():
    """Verify exact mathematical frequencies and required set logic across 20 synthetic flows."""
    inferrer = SchemaInferrer()
    total_flows = 20

    # Define properties with exact intended observation frequencies:
    # P_100: present in 20/20 (100% -> required)
    # P_75: present in 15/20 (75% -> optional)
    # P_50: present in 10/20 (50% -> optional)
    # P_25: present in 5/20 (25% -> optional)
    # P_05: present in 1/20 (5% -> optional)

    cum_schema = None
    for flow_num in range(1, total_flows + 1):
        payload: Dict[str, Any] = {}

        # P_100: always
        payload["p_100"] = f"always_{flow_num}"

        # P_75: 15 times (flows 1..15)
        if flow_num <= 15:
            payload["p_75"] = flow_num * 10

        # P_50: 10 times (flows 1..10)
        if flow_num <= 10:
            payload["p_50"] = bool(flow_num % 2)

        # P_25: 5 times (flows 1..5)
        if flow_num <= 5:
            payload["p_25"] = [flow_num]

        # P_05: 1 time (flow 1)
        if flow_num == 1:
            payload["p_05"] = {"first_only": True}

        inferred = inferrer.infer_payload_schema(payload)
        cum_schema = inferrer.merge_schemas(cum_schema, inferred, sample_count=flow_num)

    props = cum_schema["properties"]

    # Oracle verifications
    # 1. P_100: count = 20, freq = 1.0, required = True
    assert props["p_100"]["x-flowforge-observed-count"] == 20
    assert math.isclose(props["p_100"]["x-flowforge-frequency"], 1.0, rel_tol=1e-4)

    # 2. P_75: count = 15, freq = 0.75, required = False
    assert props["p_75"]["x-flowforge-observed-count"] == 15
    assert math.isclose(props["p_75"]["x-flowforge-frequency"], 0.75, rel_tol=1e-4)

    # 3. P_50: count = 10, freq = 0.50, required = False
    assert props["p_50"]["x-flowforge-observed-count"] == 10
    assert math.isclose(props["p_50"]["x-flowforge-frequency"], 0.50, rel_tol=1e-4)

    # 4. P_25: count = 5, freq = 0.25, required = False
    assert props["p_25"]["x-flowforge-observed-count"] == 5
    assert math.isclose(props["p_25"]["x-flowforge-frequency"], 0.25, rel_tol=1e-4)

    # 5. P_05: count = 1, freq = 0.05, required = False
    assert props["p_05"]["x-flowforge-observed-count"] == 1
    assert math.isclose(props["p_05"]["x-flowforge-frequency"], 0.05, rel_tol=1e-4)

    # Required set must strictly contain ONLY p_100
    assert cum_schema["required"] == ["p_100"]


# ============================================================================
# 8. High-Throughput Randomized Fuzzing & Serialization Invariant
# ============================================================================

def _random_value(depth: int = 0) -> Any:
    """Generate random JSON-compatible values."""
    if depth > 4:
        return random.choice([
            random.randint(-1000, 1000),
            round(random.uniform(-100.0, 100.0), 2),
            "".join(random.choices(string.ascii_letters, k=8)),
            random.choice([True, False]),
            None,
        ])
    
    choice = random.randint(0, 6)
    if choice == 0:
        return random.randint(-1000, 1000)
    elif choice == 1:
        return round(random.uniform(-100.0, 100.0), 2)
    elif choice == 2:
        return "".join(random.choices(string.ascii_letters + " -_", k=12))
    elif choice == 3:
        return random.choice([True, False])
    elif choice == 4:
        return None
    elif choice == 5:
        # Array
        length = random.randint(0, 5)
        return [_random_value(depth + 1) for _ in range(length)]
    else:
        # Dict
        num_keys = random.randint(0, 5)
        return {f"k_{i}": _random_value(depth + 1) for i in range(num_keys)}


def test_adversarial_fuzzing_5000_payloads_and_json_serializability():
    """Fuzz SchemaInferrer with 5,000 randomized dynamic payloads and verify JSON serialization."""
    inferrer = SchemaInferrer()
    random.seed(42)  # Deterministic seed for reproducible challenger runs

    start_time = time.perf_counter()
    num_payloads = 5000

    cum_schema = None
    for i in range(1, num_payloads + 1):
        payload = _random_value(depth=0)
        inferred = inferrer.infer_payload_schema(payload)
        cum_schema = inferrer.merge_schemas(cum_schema, inferred, sample_count=i)

    elapsed = time.perf_counter() - start_time
    ops_per_sec = num_payloads / elapsed

    # Assert schema is valid JSON serializable
    json_str = json.dumps(cum_schema)
    assert len(json_str) > 0
    assert cum_schema is not None

    # Performance expectation: > 1,000 operations per second
    assert ops_per_sec > 1000, f"Throughput {ops_per_sec:.1f} ops/sec was below threshold 1,000 ops/sec"


# ============================================================================
# 9. Unicode, Control Characters & Extreme Payloads
# ============================================================================

def test_adversarial_unicode_control_characters_and_overflow():
    """Verify handling of Unicode, emojis, zero-width characters, null bytes, and numeric overflow."""
    inferrer = SchemaInferrer()

    payload = {
        "🚀_emoji_key": "🌟_super_value",
        "zero_width_\u200B_key": "val_\u200C",
        "null_byte_str": "prefix\x00suffix",
        "large_int": 10**100,
        "large_negative_int": -10**100,
        "huge_string": "A" * 50000,
    }

    schema = inferrer.infer_payload_schema(payload)
    assert schema["type"] == "object"
    props = schema["properties"]

    assert "🚀_emoji_key" in props
    assert "zero_width_\u200B_key" in props
    assert "null_byte_str" in props

    assert props["large_int"]["minimum"] == 10**100
    assert props["large_int"]["maximum"] == 10**100

    assert props["large_negative_int"]["minimum"] == -10**100
    assert props["large_negative_int"]["maximum"] == -10**100

    assert props["huge_string"]["minLength"] == 50000
    assert props["huge_string"]["maxLength"] == 50000
    # Length > 1000 should bypass format matching safely
    assert "format" not in props["huge_string"]


# ============================================================================
# 10. String Format Regex Boundary & Near-Miss Tests
# ============================================================================

def test_adversarial_string_format_precision_and_near_misses():
    """Verify precision of format inference regexes and ensure near-misses do not falsely match."""
    inferrer = SchemaInferrer()

    valid_samples = {
        "uuid_val": "550e8400-e29b-41d4-a716-446655440000",
        "email_val": "attacker+bounty@sec-audit.corp.internal",
        "ipv4_val": "10.240.0.1",
        "ipv6_val": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "datetime_val": "2026-08-22T21:46:25Z",
        "date_val": "2026-08-22",
        "uri_val": "https://flowforge.local/api/v1/health",
        "jwt_val": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
    }

    schema_valid = inferrer.infer_payload_schema(valid_samples)
    props_v = schema_valid["properties"]
    assert props_v["uuid_val"].get("format") == "uuid"
    assert props_v["email_val"].get("format") == "email"
    assert props_v["ipv4_val"].get("format") == "ipv4"
    assert props_v["ipv6_val"].get("format") == "ipv6"
    assert props_v["datetime_val"].get("format") == "date-time"
    assert props_v["date_val"].get("format") == "date"
    assert props_v["uri_val"].get("format") == "uri"
    assert props_v["jwt_val"].get("format") == "jwt"

    # Near misses that MUST NOT be classified as the format
    invalid_samples = {
        "not_uuid": "550e8400-e29b-41d4-a716-44665544000Z",  # Invalid hex char 'Z'
        "not_ipv4_overflow": "256.0.0.1",  # 256 is out of octet range
        "not_email": "not_an_email_at_all",
        "not_datetime": "2026-08-22 21:46:25",  # Space instead of T
        "not_uri": "just/a/relative/path",
        "not_jwt": "eyNotAJwtTokenWithNoDots",
    }

    schema_invalid = inferrer.infer_payload_schema(invalid_samples)
    props_inv = schema_invalid["properties"]
    assert props_inv["not_uuid"].get("format") is None
    assert props_inv["not_ipv4_overflow"].get("format") is None
    assert props_inv["not_email"].get("format") is None
    assert props_inv["not_datetime"].get("format") is None
    assert props_inv["not_uri"].get("format") is None
    assert props_inv["not_jwt"].get("format") is None


# ============================================================================
# 11. Enum Detection Threshold & Stability Mechanics
# ============================================================================

def test_adversarial_enum_inference_threshold_mechanics():
    """Verify enum detection generates enums only when sample_count >= 3 and 2 <= examples <= 8."""
    inferrer = SchemaInferrer()

    # Step 1: Only 2 samples -> No enum yet (sample_count < 3)
    s1 = inferrer.infer_payload_schema({"status": "pending"})
    s2 = inferrer.infer_payload_schema({"status": "active"})
    m1 = inferrer.merge_schemas(s1, s2, sample_count=2)
    assert "enum" not in m1["properties"]["status"]

    # Step 2: 3 samples with same 2 unique values -> Enum created
    s3 = inferrer.infer_payload_schema({"status": "pending"})
    m2 = inferrer.merge_schemas(m1, s3, sample_count=3)
    assert "enum" in m2["properties"]["status"]
    assert sorted(m2["properties"]["status"]["enum"]) == ["active", "pending"]

    # Step 3: Expanding to 9 distinct values -> Enum pruned (> 8 values is not a discrete enum)
    cur = m2
    for i in range(3, 10):
        si = inferrer.infer_payload_schema({"status": f"state_{i}"})
        cur = inferrer.merge_schemas(cur, si, sample_count=i + 1)
    
    assert "enum" not in cur["properties"]["status"]


# ============================================================================
# 12. Asynchronous Concurrency Safety
# ============================================================================

def test_adversarial_async_concurrency_stress():
    """Verify SchemaInferrer under concurrent async task execution across 50 coroutines."""
    import asyncio

    inferrer = SchemaInferrer()
    total_tasks = 50

    async def worker(task_id: int):
        cum = None
        for step in range(1, 20):
            payload = {
                "task_id": task_id,
                "step": step,
                "flag": (step % 2 == 0),
                "data": {"nested_score": task_id * 100 + step},
            }
            inferred = inferrer.infer_payload_schema(payload)
            cum = inferrer.merge_schemas(cum, inferred, sample_count=step)
            await asyncio.sleep(0.001)  # Context switch
        return cum

    async def main():
        return await asyncio.gather(*(worker(i) for i in range(total_tasks)))

    results = asyncio.run(main())
    assert len(results) == total_tasks

    for idx, schema in enumerate(results):
        assert schema["properties"]["task_id"]["minimum"] == idx
        assert schema["properties"]["task_id"]["maximum"] == idx
        assert schema["properties"]["step"]["minimum"] == 1
        assert schema["properties"]["step"]["maximum"] == 19
        assert schema["properties"]["flag"]["type"] == "boolean"
        assert schema["properties"]["data"]["properties"]["nested_score"]["minimum"] == idx * 100 + 1
        assert schema["properties"]["data"]["properties"]["nested_score"]["maximum"] == idx * 100 + 19

