# E2E Test Infra: FlowForge Proxy — Auto-Find, Live Highlighting & Operator Approval Pipeline

## Test Philosophy
- Opaque-box, requirement-driven. Derived from verbatim user specifications in `ORIGINAL_REQUEST.md`.
- No dependency on internal implementation details; exercises public REST APIs, WebSocket streams, and end-to-end replay pipelines.
- Systematic 4-tier methodology: Category-Partition, Boundary Value Analysis, Pairwise Combinatorial, and Real-World Application Workloads.

## Feature Inventory
| # | Feature | Source (requirement) | Tier 1 | Tier 2 | Tier 3 |
|---|---------|---------------------|:------:|:------:|:------:|
| 1 | Automated Proposal Synthesis across Anomalies (Reflections, IDORs, Auth, JSON) | Follow-up R1 | 6 | 3 | ✓ |
| 2 | Proposal Management REST API (List/Filter, Get, Dismiss, Batch, Stats) | Follow-up R1 | 5 | 2 | ✓ |
| 3 | 1-Click Approve & Run, Replay Execution & Diff Delta Engine | Follow-up R3 | 5 | 1 | ✓ |
| 4 | Curated Collections & Matrix Builder Transfer Bridges | Follow-up R3 | 5 | 1 | ✓ |
| 5 | WebSocket Real-Time Event Broadcasting & Badge Streaming | Follow-up R1, R2 | 5 | 1 | ✓ |

## Test Architecture
- **Test Runner**: Pytest (`pytest -v tests/`) with isolated async execution hook in `tests/conftest.py`.
- **Reference Target App**: Fully functional FastAPI application (`tests/target_app.py`) exposing reflection, IDOR, auth, and state mutation endpoints.
- **Synthetic Traffic Generator**: `SyntheticTrafficGenerator` in `tests/generator.py`.
- **Frontend Verification**: `npm run build` (`tsc && vite build`) for static type checking and production bundling.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Reflected XSS Auto-Find & Operator 1-Click Approval | Reflection detection, DOM breakout proposal synthesis, 1-click execution, diff delta, save to curated | High |
| 2 | Sequential BOLA / IDOR Auto-Find & Matrix Escalation | Sequential integer triage, IDOR candidate proposal, transfer to Matrix Builder, range expansion, batch execution | High |
| 3 | Auth Anomaly & JWT Forgery Operator Workflow | Auth omission detection, Drop Auth & JWT `alg: none` proposals, replay execution, sensitive data leak verification | High |
| 4 | JSON State Mutation & Mass Assignment Workflow | Nested JSON parsing, mass assignment proposal synthesis, replay execution, role elevation verification | High |

## Coverage Thresholds
- **Tier 1**: ≥5 test cases per feature (26 tests total)
- **Tier 2**: ≥8 boundary and corner cases
- **Tier 3**: ≥5 cross-feature interaction pipelines
- **Tier 4**: ≥4 realistic end-to-end application scenarios
- **Total Minimum**: ≥43 automated tests with 100% pass rate.
