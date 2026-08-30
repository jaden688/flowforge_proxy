# E2E Test Infra: FlowForge Proxy - Nuclei Engine & Real Data Decoder Verification

## Test Philosophy
- Opaque-box, requirement-driven testing against real SQLite persistence, live HTTP proxies, authentic cryptography, and real HTTP replay targets.
- Zero mocks, zero stubs, zero fake sample data.
- 4-Tier Test Architecture: Category-Partition (Tier 1), Boundary Value Analysis (Tier 2), Cross-Module Interactions (Tier 3), Real-World Pen-Test Workflows (Tier 4), Adversarial Coverage (Tier 5).

## Feature Inventory
| # | Feature | Source | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|---|---------|--------|:------:|:------:|:------:|:------:|
| 1 | Nuclei Template Models & Schemas | ORIGINAL_REQUEST §R1 | 5 | 3 | ✓ | ✓ |
| 2 | Multi-Root Discovery (`flowforge/` & `data/wordlists/`) | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ | ✓ |
| 3 | Template ID Deduplication & Overrides | ORIGINAL_REQUEST §R1 | 5 | 4 | ✓ | ✓ |
| 4 | Passive Flow Matcher (Status/Words/Regex/Headers) | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ | ✓ |
| 5 | Triage Summary & Threat HUD Stats | ORIGINAL_REQUEST §R1 | 5 | 3 | ✓ | ✓ |
| 6 | Staged Test Proposal Synthesis (`[Nuclei] {name}`) | ORIGINAL_REQUEST §R1 | 5 | 4 | ✓ | ✓ |
| 7 | Nuclei REST API Endpoints (`/api/v1/nuclei/*`) | ORIGINAL_REQUEST §R1 | 5 | 3 | ✓ | ✓ |
| 8 | Authentic Decoder Live Flow Processing | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ | ✓ |
| 9 | Zero Fake Data / Mock Compliance Audit | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ | ✓ |
| 10 | Real-World CVE Auto-Find & Operator Approval E2E | ORIGINAL_REQUEST §R1, §R2 | - | - | - | 5 |

## Test Architecture
- Backend Test Runner: `pytest -v tests/`
- Frontend Test Runner: `npm run build` & `npx tsx frontend/tests/run_all_frontend_adversarial_suite.ts`
- In-process target app: `tests/target_app.py`
- Synthetic traffic generator: `tests/generator.py`

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Intercept Exposed Swagger/OpenAPI -> Passive Nuclei Match -> Threat HUD & Dossier Annotation | F1, F2, F4, F5 | Medium |
| 2 | Intercept Debug Error Trace -> Passive Airflow/Django Match -> Proposal Staging | F3, F4, F6 | Medium |
| 3 | Operator Approves Nuclei Active Probe -> Replay Execution -> Confirmed CVE Diff | F6, F7, F10 | High |
| 4 | Intercept Live Flow with JWT -> Decode Header/Claims -> Mutate Claims -> Replay | F8, F9, F10 | High |
| 5 | Custom Arsenal Template Overrides Builtin -> Deduplication & Custom Match Execution | F2, F3, F4, F6, F10 | High |
