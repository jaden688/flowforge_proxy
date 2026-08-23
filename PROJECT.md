# Project: FlowForge Proxy — Dynamic JSON Schema Evolution & Bug Bounty Vulnerability Triage

## Architecture
FlowForge Proxy is an asynchronous, high-throughput HTTP/1.1, HTTP/2, and WebSocket intercepting proxy and security testing workbench.
This feature milestone introduces dynamic JSON schema evolution (cumulative payload merging across flows for endpoint templates), comprehensive multi-category bug bounty vulnerability triage and automated proposal synthesis (IDOR/BOLA boundary sweeps, Reflected XSS breakouts with static noise filtering, Broken Auth token stripping, Secrets/JWT `alg:none`, and Custom Rules), real-time WebSocket event broadcasting, and seamless synchronization with the Target Dossier, Threat HUD, and Operator Approval Drawer.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 Frontend Cockpit UI                                    │
│  - Live Traffic Stream (glowing [⚡ N Tests Staged] pulse badges, 1-click filter)       │
│  - Threat HUD (Reflections, Predictable IDs / IDOR, Auth Deviations, Secrets, Rules)   │
│  - Target Dossier View (Dynamic Schema Tree, Parameter Type Matrix, Sample Values)     │
│  - Operator Approval Drawer (1-Click Replay Execution, Diff Modal, Matrix Bridge)      │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ REST API & WebSocket Events (/api/v1/*)
┌───────────────────────────────────────────▼────────────────────────────────────────────┐
│                              FastAPI Application Layer                                 │
│  - /api/v1/dossiers (and /api/v1/dossier) (list, get by endpoint_hash, OpenAPI export) │
│  - /api/v1/proposals (list, stats, get, approve, execute, dismiss, batch, generate)    │
│  - /api/v1/ws/traffic (schema_updated, proposal_created, proposal_executed, etc.)      │
└─────────────────────┬────────────────────────────────────────────┬─────────────────────┘
                      │                                            │
┌─────────────────────▼────────────────────┐   ┌───────────────────▼─────────────────────┐
│          Proxy Interception Core         │   │    Passive Vulnerability Pipeline       │
│  - Mitmproxy DumpMaster engine           │   │  - Reflection Detector (DOM Contexts +  │
│  - FlowForgeInterceptorAddon hooks       │   │    Static Asset Noise Filter)           │
│  - EventBroadcaster Pub/Sub Hub          │   │  - Identifier Classifier (IDOR / BOLA)  │
│  - Endpoint & Parameter Triage Ingestion │   │  - Auth Tracker & JWT Scanner           │
└─────────────────────┬────────────────────┘   │  - Dynamic Schema Inferrer & Merger     │
                      │                        │  - Custom YAML/JSON Rule Matcher        │
                      │                        └───────────────────┬─────────────────────┘
                      │                                            │
                      │                        ┌───────────────────▼─────────────────────┐
                      │                        │       Proposal Synthesizer Engine       │
                      │                        │  - Synthesizes XSS context breakouts    │
                      │                        │  - Synthesizes IDOR boundary sweeps     │
                      │                        │  - Synthesizes Auth drop/swap probes    │
                      │                        │  - Synthesizes JWT alg:none probes      │
                      │                        │  - Synthesizes Mass Assignment probes   │
                      │                        └───────────────────┬─────────────────────┘
                      │                                            │
┌─────────────────────▼────────────────────────────────────────────▼─────────────────────┐
│                     Storage & Persistence Layer (SQLite + WAL)                         │
│  - AsyncDBWriter (single-writer queue for atomic batch upsert)                         │
│  - Tables: flows, endpoints, parameters, proposals, curated_payloads                   │
│  - Repository: FlowRepository (cumulative schema merge, queries, stats, replay diffs)  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Dynamic JSON Schema Evolution & Field Merging | Evolving cumulative JSON schema across multiple flows for endpoint templates, tracking field types, type unions, optional/required frequency, nested hierarchies, array element schemas | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Endpoint & Parameter Triage Persistence | Ingest endpoint templates, discovered parameters, and cumulative schemas into SQLite `endpoints` and `parameters` tables in real time via `AsyncDBWriter` | M1 | ORIGINAL_REQUEST §R1 |
| 3 | Dossier REST API & WebSocket Streaming | Expose `/api/v1/dossiers` and `/api/v1/dossiers/{endpoint_hash}` with `schema_updated` and `endpoint_updated` WebSocket events | M1 | ORIGINAL_REQUEST §R1 |
| 4 | Context-Aware Reflection Detection & Noise Filter | Context-aware reflection detection across HTML body, attribute, JS string, script context; filter static asset tokens (.js, .css, images, fonts) to eliminate false positives | M2 | ORIGINAL_REQUEST §R2 |
| 5 | IDOR / BOLA Predictable Identifier Triage | Detect sequential integers, UUID patterns, numeric params and auto-generate 5-point boundary sweep test proposals (`+1`, `-1`, `0`, `MAX_INT`) | M2 | ORIGINAL_REQUEST §R2 |
| 6 | Broken Auth & Session Deviation Triage | Flag unauthenticated sensitive routes, role discrepancies, missing auth headers, and synthesize `DROP`, `USER_B`, and `ALG_NONE` test proposals | M2 | ORIGINAL_REQUEST §R2 |
| 7 | High-Entropy Tokens & Secret Leakage | Dissect JWTs, API keys, bearer tokens with expiration checks and signature forgery probes (`alg: none`) | M2 | ORIGINAL_REQUEST §R2 |
| 8 | Custom Rule Engine & Mass Assignment Triage | Evaluate dynamic user-defined YAML/JSON rules across all intercepted traffic and emit matching tags and high-priority proposals; detect privilege escalation attributes | M2 | ORIGINAL_REQUEST §R2 |
| 9 | Target Dossier Dynamic Schema UI | Dynamically update JSON Schema tree, parameter type matrix, and observed value samples in real time as new flows arrive over WebSocket | M3 | ORIGINAL_REQUEST §R3 |
| 10 | Threat HUD & Live Stream Badges UI | Accurately count and display all anomaly/vulnerability categories with 1-click filter tabs, glowing `[⚡ N Tests Staged]` badges, and slide-out approval drawer | M3 | ORIGINAL_REQUEST §R3 |
| 11 | Multi-layer Decoders & Quick Triggers UI | Seamless multi-pass decoding (JWT, Base64, URL, Hex, HTML) and quick-action triggers across headers, query parameters, and schema fields | M3 | ORIGINAL_REQUEST §R3 |
| 12 | 4-Tier Automated Verification & Test Suite | Comprehensive pytest suite covering dynamic schema merging, IDOR boundary sweep generation, static reflection filtering, auth bypass probes, dossier API/WS streaming, and replay diff execution | M4 | ORIGINAL_REQUEST §R4 |
| 13 | Final Verification & Forensic Audit | Assert 100% pytest pass rate, 0-error `npm run build`, and Forensic Auditor integrity verification | M4 | ORIGINAL_REQUEST §R4 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Dynamic JSON Schema Evolution & Dossier Persistence (Backend) | SchemaInferrer cumulative merging, type unions, optional/required frequencies, Addon triage ingestion into SQLite endpoints/parameters, FlowRepository query methods, Dossier REST/WS routes | None | PLANNED |
| M2 | Multi-Category Vulnerability Triage & Bounty Synthesizer (Backend) | Static asset reflection noise filtering, IDOR boundary sweep proposals, Auth drop/swap proposals, JWT alg:none proposals, Custom rules & Mass assignment triage | M1 | PLANNED |
| M3 | Dynamic Schema & Vulnerability Synchronization in UI (Frontend) | Target Dossier real-time schema tree & parameter matrix, Threat HUD 1-click filter tabs, glowing staged badges, decoders & triggers | M1, M2 | PLANNED |
| M4 | Comprehensive E2E Verification & Forensic Victory Audit | 4-Tier automated test suite (pytest), clean TypeScript build (`npm run build`), and Forensic Integrity Audit | M1, M2, M3 | PLANNED |

## Interface Contracts

### Backend ↔ Frontend REST API
- `GET /api/v1/dossiers` (alias `/api/v1/dossier`) $\to$ `{ endpoints: EndpointDossier[], total: int }`
- `GET /api/v1/dossiers/{endpoint_hash}` $\to$ `EndpointDossier` (with cumulative JSON schema, parameter catalog, observed values)
- `GET /api/v1/proposals?flow_id={id}&state={state}&anomaly_type={type}&severity={sev}&search={q}&page={p}&page_size={s}` $\to$ `{ items: TestProposal[], total: int, page: int, page_size: int, total_pages: int }`
- `GET /api/v1/proposals/stats` $\to$ `{ total: int, pending: int, approved: int, executing: int, completed: int, dismissed: int, by_category: Record<string, int> }`
- `POST /api/v1/proposals/{id}/execute` $\to$ `{ proposal: TestProposal, executed_flow: FlowRecord, diff: FlowComparisonResult }`

### WebSocket Events (`/api/v1/ws/traffic`)
- `schema_updated`: `{ event: "schema_updated", endpoint_hash: string, data: { host: string, method: string, path_template: string, request_schema: dict, response_schema: dict, parameter_count: int } }`
- `proposal_created`: `{ event: "proposal_created", flow_id: string, data: { flow_id: string, proposal_count: int, top_severity: string, proposals: TestProposal[] } }`
- `proposal_executed`: `{ event: "proposal_executed", flow_id: string, data: { proposal_id: string, state: "COMPLETED", verdict_level: string, verdict_description: string, length_delta_bytes: int, status_delta: string, latency_ms: float } }`

## Code Layout
```
flowforge_proxy/
├── flowforge/
│   ├── api/
│   │   ├── app.py                     # Route registration (dossiers, proposals, flows, etc.)
│   │   └── routes/
│   │       ├── dossier.py             # Dossier REST endpoints (list, get, OpenAPI)
│   │       └── proposals.py           # Proposal REST endpoints
│   ├── core/
│   │   ├── addon.py                   # Mitmproxy addon: triage, endpoint persistence, proposal synthesis
│   │   └── broadcaster.py             # WebSocket Pub/Sub event broadcaster
│   ├── db/
│   │   ├── schema.py                  # SQLite tables: endpoints, parameters, proposals, flows
│   │   ├── writer.py                  # Async single-writer queue
│   │   └── repository.py              # FlowRepository (list_endpoints, get_endpoint_by_hash, merge_schema)
│   ├── heuristics/
│   │   ├── schema_inferrer.py         # Dynamic JSON schema inference & cumulative merging engine
│   │   ├── reflection_detector.py     # Reflection detection with static asset noise filter
│   │   ├── identifier_classifier.py   # IDOR/BOLA classification & boundary generator
│   │   ├── auth_tracker.py            # Auth deviation tracker & bypass probe generator
│   │   ├── token_scanner.py           # JWT & secret scanner with alg:none check
│   │   ├── custom_rules.py            # Dynamic YAML/JSON rule evaluation engine
│   │   └── proposal_synthesizer.py    # Automated test proposal synthesizer engine
│   └── models/
│       ├── dossier.py                 # Endpoint, Parameter, Dossier models
│       ├── proposal.py                # TestProposal, ProposalState, AnomalyType models
│       └── events.py                  # EventType enum
├── frontend/
│   └── src/
│       ├── types/index.ts             # TypeScript definitions
│       ├── store/flowStore.ts         # Zustand store (flows, proposals, dossiers, HUD)
│       ├── services/                  # REST & WS client services
│       └── components/
│           ├── dossier/               # TargetDossier, SchemaTree, ParameterGrid
│           ├── stream/                # TrafficTable with glowing badges & HUD
│           ├── cockpit/               # Threat HUD intelligence cards
│           └── proposals/             # Slide-out Approval Drawer, Diff Modal
└── tests/
    ├── tier1_features/                # Unit & feature tests
    ├── tier2_boundaries/              # Boundary value & edge case tests
    ├── tier3_interactions/            # Cross-module interaction tests
    ├── tier4_application/             # Real-world E2E workflow tests
    └── tier5_adversarial/             # Adversarial stress & security tests
```
