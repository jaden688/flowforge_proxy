"""Repository for persisting custom heuristic rules to SQLite."""

from __future__ import annotations

import json
import logging
import time
from typing import Dict, List, Optional

from flowforge.db.connection import get_connection
from flowforge.models.rules import MatchRule, RuleCondition, RuleSeverity

logger = logging.getLogger("flowforge.db.rules_repository")


class RulesRepository:
    """CRUD operations for the custom_rules table."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def list_rules(
        self,
        enabled_only: bool = False,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[MatchRule]:
        """List all rules with optional filtering."""
        clauses: List[str] = []
        params: List = []
        if enabled_only:
            clauses.append("enabled = 1")
        if category:
            clauses.append("category = ?")
            params.append(category)
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if search:
            clauses.append("(name LIKE ? OR description LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT * FROM custom_rules{where} ORDER BY created_at DESC;"

        rules: List[MatchRule] = []
        async with get_connection(self.db_path) as conn:
            async with conn.execute(query, params) as cursor:
                async for row in cursor:
                    rules.append(self._row_to_rule(row))
        return rules

    async def get_rule(self, rule_id: str) -> Optional[MatchRule]:
        """Get a single rule by ID."""
        async with get_connection(self.db_path) as conn:
            async with conn.execute(
                "SELECT * FROM custom_rules WHERE rule_id = ?;", (rule_id,)
            ) as cursor:
                row = await cursor.fetchone()
                return self._row_to_rule(row) if row else None

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def upsert_rule(self, rule: MatchRule) -> MatchRule:
        """Insert or update a rule."""
        now = time.time()
        rule.updated_at = now
        async with get_connection(self.db_path) as conn:
            await conn.execute(
                """INSERT INTO custom_rules
                   (rule_id, name, description, severity, category, tags,
                    enabled, condition_combinator, conditions, raw_yaml,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(rule_id) DO UPDATE SET
                       name=excluded.name, description=excluded.description,
                       severity=excluded.severity, category=excluded.category,
                       tags=excluded.tags, enabled=excluded.enabled,
                       condition_combinator=excluded.condition_combinator,
                       conditions=excluded.conditions,
                       raw_yaml=excluded.raw_yaml, updated_at=excluded.updated_at;""",
                (
                    rule.id,
                    rule.name,
                    rule.description,
                    rule.severity.value if hasattr(rule.severity, "value") else str(rule.severity),
                    rule.category,
                    json.dumps(rule.tags),
                    1 if rule.enabled else 0,
                    rule.condition_combinator,
                    json.dumps([c.model_dump() for c in rule.conditions]),
                    rule.raw_yaml,
                    rule.created_at,
                    rule.updated_at,
                ),
            )
            await conn.commit()
        return rule

    async def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule by ID. Returns True if deleted."""
        async with get_connection(self.db_path) as conn:
            cursor = await conn.execute(
                "DELETE FROM custom_rules WHERE rule_id = ?;", (rule_id,)
            )
            await conn.commit()
            return cursor.rowcount > 0

    async def toggle_rule(self, rule_id: str, enabled: Optional[bool] = None) -> Optional[MatchRule]:
        """Toggle or explicitly set the enabled state. Returns updated rule."""
        rule = await self.get_rule(rule_id)
        if rule is None:
            return None
        rule.enabled = not rule.enabled if enabled is None else enabled
        rule.updated_at = time.time()
        async with get_connection(self.db_path) as conn:
            await conn.execute(
                "UPDATE custom_rules SET enabled = ?, updated_at = ? WHERE rule_id = ?;",
                (1 if rule.enabled else 0, rule.updated_at, rule_id),
            )
            await conn.commit()
        return rule

    async def clear_all(self) -> int:
        """Delete all rules. Returns count deleted."""
        async with get_connection(self.db_path) as conn:
            cursor = await conn.execute("DELETE FROM custom_rules;")
            await conn.commit()
            return cursor.rowcount or 0

    async def count_rules(self) -> int:
        """Return total rule count."""
        async with get_connection(self.db_path) as conn:
            async with conn.execute("SELECT COUNT(*) AS cnt FROM custom_rules;") as c:
                return (await c.fetchone())["cnt"]

    # ------------------------------------------------------------------
    # Bulk load into RuleEngine
    # ------------------------------------------------------------------

    async def load_all_into_engine(self, engine) -> int:
        """Load all DB rules into a RuleEngine instance. Returns count loaded."""
        rules = await self.list_rules()
        count = 0
        for rule in rules:
            engine.register_rule(rule)
            count += 1
        return count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_rule(row) -> MatchRule:
        """Convert a SQLite row to a MatchRule model."""
        tags = json.loads(row["tags"]) if row["tags"] else []
        conditions_raw = json.loads(row["conditions"]) if row["conditions"] else []
        conditions = []
        for c in conditions_raw:
            conditions.append(RuleCondition(
                field=c.get("field", ""),
                operator=c.get("operator", "equals"),
                value=c.get("value"),
                target=c.get("target"),
                case_sensitive=c.get("case_sensitive", False),
                invert=c.get("invert", False),
            ))

        return MatchRule(
            id=row["rule_id"],
            name=row["name"],
            description=row["description"] or "",
            severity=RuleSeverity(row["severity"]),
            category=row["category"] or "CUSTOM",
            tags=tags,
            enabled=bool(row["enabled"]),
            condition_combinator=row["condition_combinator"] or "all",
            conditions=conditions,
            raw_yaml=row["raw_yaml"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
