# Dead Ends Log

| Iteration | Approach Tried | Why It Failed | Files Touched |
|-----------|---------------|---------------|---------------|
| 1 | High-level sub-orchestration relying on message handoffs without ensuring subagents physically wrote all source code, frontend, and tests to disk | Audit failure: filesystem was empty (`flowforge/`, `frontend/`, `tests/` missing on disk; tests were not physically executed) | None on disk |
