# Project: FlowForge Proxy Zero-Mock & Dynamic Target Replay Hardening

## Architecture
FlowForge Proxy is an intelligent, high-performance security intercepting proxy and automated test workbench built with a Python (FastAPI / mitmproxy / aiosqlite / httpx) backend and a React (TypeScript / Vite / TailwindCSS / Lucide) frontend.
The system intercepts live HTTP/HTTPS traffic, analyzes flows with passive heuristic triage rules (IDOR, reflection, auth-bypass, mass assignment), synthesizes actionable test proposals, generates ranked mutation matrices, and provides an Operator Cockpit with autonomous Auto-Pilot and human-in-the-loop approval workflows.

### Core Data Flow
1. **Interception**: Mitmproxy core intercepts external traffic -> writes raw flow telemetry to SQLite FTS5 database -> broadcasts events over WebSocket `/ws/traffic`.
2. **Analysis & Synthesis**: Passive triage engine analyzes flows -> generates ranked test proposals (`TestProposal`) and mutation matrices (`MatrixJob`).
3. **Execution & Replay**:
   - Proposal Replay (`POST /api/v1/proposals/{id}/execute`): Reconstructs original request method, scheme, host, port, path, headers, and params -> executes against the live target -> computes semantic and byte deltas.
   - Single Flow Replay (`POST /api/v1/flows/{id}/replay`): Reconstructs absolute target URL -> replays flow -> updates live telemetry.
   - Matrix Runner (`POST /api/v1/matrix/execute`): Dynamically resolves baseline flows per test case -> constructs authentic target URLs -> executes concurrent mutation matrix -> persists executed flow records.
4. **Autonomous Operator Control**: Operator Cockpit Auto-Pilot executes verified proposals sequentially with human-observable pacing, configurable rate limits, live HUD telemetry logging, and safety brakes.

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Dynamic Target Replay in Flow Replay | Construct dynamic absolute URLs from `flow.request.url` or `scheme://server_host:server_port/path` for relative captured paths without loopback. | M1 | R1 / Survey |
| 2 | Dynamic Matrix Per-Case Baseline Resolution | Cache and resolve baseline flows individually for each matrix test case rather than using only the first case or defaulting to localhost. | M1 | R1 / Survey |
| 3 | Matrix Target URL Construction | Build target URLs dynamically per case from baseline flow scheme/host/port and endpoint path, eliminating hardcoded `127.0.0.1:8000` fallback. | M1 | R1 / Survey |
| 4 | Matrix Executed Flow Persistence | Construct and persist `FlowRecord` for matrix executions into `db_writer` so matrix runs appear in Live Traffic Stream and Diff Viewer. | M1 | R1 / Survey |
| 5 | Query Parameter Deduplication | Strip query string from base URL when passing `params=query_params` to `httpx.request()` in `proposals.py` and `matrix.py` to prevent duplicate query params. | M1 | R1 / Survey |
| 6 | Hop-by-Hop Header Stripping | Strip `Host` and `Content-Length` headers before dispatching mutated requests in `proposals.py` and `matrix.py` to avoid routing/length mismatch errors. | M1 | R1 / Survey |
| 7 | Intruder Bridge Dynamic Target Resolution | Dynamically extract target scheme, host, and port from proposal/flow in `bridge.py` instead of hardcoded `http://127.0.0.1:8000`. | M1 | R1 / Survey |
| 8 | Frontend API Replay Route Alignment | Route `api.replayRequest` and `api.replayFlow` to backend `POST /api/v1/flows/{id}/replay` and add 1-Click Replay action in `SplitInspector.tsx`. | M1 | R1 / Survey |
| 9 | Auto-Pilot Pacing Control Loop | Replace unconfigurable 2500ms `setInterval` with safe recursive `setTimeout` + execution lock; add configurable pacing delay selector (500ms/1000ms/2000ms/5000ms/slider). | M2 | R2 / Survey |
| 10 | Auto-Pilot Safety Brakes & Filters | Add "Stop on Anomaly" safety brake, configurable minimum confidence threshold slider (0-100%), and category filters (ALL, IDOR, REFLECTION, AUTH, MASS_ASSIGNMENT). | M2 | R2 / Survey |
| 11 | Human-Observable Batch Approvals | Paced sequential execution in `handleRunAllPending` and `ProposalApprovalDrawer` with inter-step delay, progress counter, and cancellation. | M2 | R2 / Survey |
| 12 | Live HUD Telemetry Event Log | Connect Cockpit HUD `autoLog` to WebSocket `proposal_executed` stream and format entries with HTTP status, latency delta (ms), size delta (bytes), and verdict tags. | M2 | R2 / Survey |
| 13 | UI Telemetry & Status Fallback Polish | Replace `|| 45` latency and `|| 200` response status fallbacks with authentic `??` expressions in `SplitInspector.tsx` and `DiffViewer.tsx`. | M3 | R3 / Survey |
| 14 | Error Handling Cleanliness in Custom Send | Return proper error status codes and detail instead of dummy `status_code: 200` on connection failures in `flows.py:send_custom_request`. | M3 | R3 / Survey |
| 15 | Full Regression & Zero-Mock Verification | Run `pytest -v tests/` (383/383 passing), `npm run build` (0 errors), adversarial verification, and forensic audit. | M4 | R3 / Acceptance |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Dynamic Target Replay & Matrix Routing | Backend `matrix.py`, `proposals.py`, `flows.py`, `bridge.py`, `proxy.py`, frontend `api.ts`, `SplitInspector.tsx` | none | DONE |
| M2 | Human-Observable Auto-Pilot & Operator Control | Frontend `OperatorCockpit.tsx`, `ProposalApprovalDrawer.tsx`, `flowStore.ts` | M1 | DONE |
| M3 | Zero-Mock Pipeline Polish & Fallback Cleanup | Frontend `SplitInspector.tsx`, `DiffViewer.tsx`, backend `flows.py` | M1, M2 | DONE |
| M4 | Comprehensive Verification & Forensic Audit | Pytest 401 tests, npm run build, Challenger verification, Forensic Auditor verification | M1, M2, M3 | DONE |

---

## Interface Contracts

### Backend Matrix Execution Request Contract (`POST /api/v1/matrix/execute`)
- Input:
  ```json
  {
    "job_id": "string",
    "case_ids": ["string"],
    "target_url": "optional string",
    "concurrency": 5
  }
  ```
- Target Resolution:
  1. If `target_url` provided: `target_url.rstrip("/") + case.endpoint_path`
  2. Else if `case.baseline_flow_id` present: Resolve baseline flow from repository -> construct `scheme://server_host:server_port/case.endpoint_path` -> strip query from URL base when passing `params=query_params`.
  3. Else: mark case `status="FAILED"`, `anomaly_flag="MISSING_TARGET_URL"`.

### Proposal Execution Request Contract (`POST /api/v1/proposals/{id}/execute`)
- Target Resolution:
  - Extract baseline flow -> construct fully qualified URL `scheme://server_host:server_port/endpoint_path` -> clean URL query before passing `params=query_params` -> strip `Host` and `Content-Length` headers -> execute via `httpx.AsyncClient`.

### Auto-Pilot Pacing Contract (Frontend Cockpit)
- State Variables:
  - `pacingDelayMs: number` (Default: `2000`, selectable: `500`, `1000`, `2000`, `5000` or custom slider)
  - `minConfidence: number` (Default: `60`, range: `0` to `100`)
  - `stopOnAnomaly: boolean` (Default: `true`)
  - `autoPilotCategory: string` (Default: `'ALL'`)
- Loop Behavior:
  - Recursive `setTimeout` with `isExecutingRef` lock.
  - Pauses execution and logs alert if `stopOnAnomaly` is true and an anomaly verdict (`CRITICAL_IDOR`, `HIGH_REFLECTION`, etc.) is returned.

---

## Code Layout
- Backend Source: `flowforge/`
  - Routes: `flowforge/api/routes/` (`flows.py`, `proposals.py`, `matrix.py`, `tools.py`, `proxy.py`, `streaming.py`, `diff.py`, `intruder.py`, `findings.py`, `curation.py`)
  - Core: `flowforge/core/` (`bridge.py`, `intruder.py`, `storage.py`, `models.py`)
- Frontend Source: `frontend/src/`
  - Components: `frontend/src/components/` (`cockpit/`, `stream/`, `diff/`, `matrix/`, `intruder/`, `decoder/`, `findings/`)
  - Store & Services: `frontend/src/store/` (`flowStore.ts`), `frontend/src/services/` (`api.ts`, `websocket.ts`)
- Tests (Read-only / Untouched fixtures): `tests/`
  - `tests/tier1_features/`, `tests/tier2_boundaries/`, `tests/tier3_interactions/`, `tests/tier4_application/`, `tests/tier5_adversarial/`
- Metadata: `.agents/`
