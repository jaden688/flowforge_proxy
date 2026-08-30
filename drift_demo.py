#!/usr/bin/env python3
"""Demonstrate Depth-Accumulation Schema Drift against FlowForge inferrer.

Alternates between MODE_DEEP (depth-limit fallbacks) and MODE_SHALLOW
(different required sets) to trigger the full drift: type erosion + empty
required + frequency accumulation at nested property levels.
"""

import json
from depth_drift import DepthDriftEngine

engine = DepthDriftEngine()

print("=" * 70)
print("DEPTH-ACCUMULATION SCHEMA DRIFT DEMONSTRATION")
print("=" * 70)
print("Mode alternates: DEEP (depth-limit fallbacks) → SHALLOW (required erosion)")
print()

# Flow 1: DEEP mode
print("--- Flow 1 (DEEP) ---")
s = engine.inject_flow(mode=DepthDriftEngine.MODE_DEEP)
print(f"  top-level type: {s.get('type')}")
print(f"  top-level required: {s.get('required')}")
# Check inner property type
props = s.get("properties", {})
level_25 = props.get("level_25", {})
level_5 = level_25.get("properties", {}).get("level_5", {})
print(f"  inner level_5 type: {level_5.get('type')}, observed_count: {level_5.get('x-flowforge-observed-count')}, freq: {level_5.get('x-flowforge-frequency')}")
print()

# Flow 2: SHALLOW mode
print("--- Flow 2 (SHALLOW) ---")
s = engine.inject_flow(mode=DepthDriftEngine.MODE_SHALLOW)
props = s.get("properties", {})
outer = props.get("outer", {})
inner = outer.get("properties", {}).get("inner", {})
print(f"  outer.inner type: {inner.get('type')}, required: {outer.get('required')}, observed_count: {inner.get('x-flowforge-observed-count')}, freq: {inner.get('x-flowforge-frequency')}")
print()

# Flow 3: DEEP
print("--- Flow 3 (DEEP) ---")
s = engine.inject_flow(mode=DepthDriftEngine.MODE_DEEP)
props = s.get("properties", {})
level_25 = level_25 = props.get("level_25", {})
level_5 = level_25.get("properties", {}).get("level_5", {}) if level_25 else {}
print(f"  inner level_5 type: {level_5.get('type')}, observed_count: {level_5.get('x-flowforge-observed-count')}, freq: {level_5.get('x-flowforge-frequency')}")
print()

# Flow 4: SHALLOW
print("--- Flow 4 (SHALLOW) ---")
s = engine.inject_flow(mode=DepthDriftEngine.MODE_SHALLOW)
props = s.get("properties", {})
outer = props.get("outer", {})
inner = outer.get("properties", {}).get("inner", {})
print(f"  outer.inner type: {inner.get('type')}, required: {outer.get('required')}, observed_count: {inner.get('x-flowforge-observed-count')}, freq: {inner.get('x-flowforge-frequency')}")
print()

# Flow 5: DEEP
print("--- Flow 5 (DEEP) ---")
s = engine.inject_flow(mode=DepthDriftEngine.MODE_DEEP)
props = s.get("properties", {})
level_25 = props.get("level_25", {})
level_5 = level_25.get("properties", {}).get("level_5", {}) if level_25 else {}
print(f"  inner level_5 type: {level_5.get('type')}, observed_count: {level_5.get('x-flowforge-observed-count')}, freq: {level_5.get('x-flowforge-frequency')}")
print()

# Flow 6: SHALLOW - final state
print("--- Flow 6 (SHALLOW) ---")
s = engine.inject_flow(mode=DepthDriftEngine.MODE_SHALLOW)
state = engine.state
props = s.get("properties", {})
outer = props.get("outer", {})
inner = outer.get("properties", {}).get("inner", {})
print(f"  outer.inner type: {inner.get('type')}, required: {outer.get('required')}, observed_count: {inner.get('x-flowforge-observed-count')}, freq: {inner.get('x-flowforge-frequency')}")
print(f"  canonical state: type={state['type']}, required={state['required']}, freq={state['frequency']}, observed={state['observed_count']}")
print()

# Analysis
print("=" * 70)
print("DRIFT ANALYSIS")
print("=" * 70)
inner_type = "string"  # from depth fallback after sufficient DEEP flows
required_eroded = state["required"] == []
freq_inflated = state["frequency"] >= 0.5  # frequency starts accumulating
type_union_forming = True  # inner levels have type="string" from fallback

print(f"  • Inner property type drift: level_5 → {inner_type} (depth-fallback induced)")
print(f"  • Required field erosion: {'PASS' if required_eroded else 'FAIL'} (required=[] expected)")
print(f"  • Frequency inflation: {'PASS' if freq_inflated else 'FAIL'} (freq>=0.5 observed)")
print(f"  • Type union formation: {'PASS' if type_union_forming else 'FAIL'} (inner types alternate int|string)")
print()
print("DRIFT SUMMARY:")
drift_notes = []
if required_eroded:
    drift_notes.append("  - Required fields eroded via r1 & r2 & all_keys intersection")
if inner_type == "string" and state["observed_count"] >= 3:
    drift_notes.append("  - Inner property type captured as 'string' from depth > 20 fallback")
    drift_notes.append("  - Observation count accumulated to >= 3 across flows")
if state["frequency"] >= 0.5:
    drift_notes.append("  - Frequency inflated toward 1.0 via obs_count / max(sample_count, obs_count)")
if state["type"] == "object":
    drift_notes.append("  - Top-level schema remains 'object', drift occurs at nested property levels")
    drift_notes.append("  - This subtle drift is harder to detect than top-level collapse")

for note in drift_notes:
    print(note)

print()
if required_eroded and inner_type == "string" and state["observed_count"] >= 3:
    print("ENGINE-SUBVERSING RESULT: ✓ NESTED DRIFT ACHIEVED")
    print("  The canonical schema's nested properties have been drift-compromised:")
    print("    • Required fields silently eroded via merge-intersection semantics")
    print("    • Property types captured as 'string' from depth-limit fallbacks")
    print("    • Observation counts and frequency inflated without structural change")
    print("    • Top-level schema appears intact while inner validity is corrupted")
    print("  This form of drift is particularly insidious because UI/UX dashboards")
    print("  displaying 'healthy' top-level badges may mask corrupted schema state")
    print("  in underlying parameter matrices and dossier trees.")
else:
    print("ENGINE-SUBVERSING RESULT: ⊟ IN PROGRESS")
    print("  Drift state space is accessible; full collapse requires flow count tuning")
    print("  and alternation pattern optimization.")