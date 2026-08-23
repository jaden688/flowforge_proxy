"""Wordlist loader that indexes local security wordlist collections and streams entries safely.

Discovers collections such as SecLists, dirb/dirbuster, wfuzz, PayloadsAllTheThings,
and custom operator directories, categorizes each file into arsenal categories, and
provides lazy, memory-bounded entry access (including gzip-transparent reading).
"""

from __future__ import annotations

import gzip
import hashlib
import logging
import os
from enum import Enum
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("flowforge.wordlists.loader")

_INDEXED_EXTENSIONS = {".txt", ".lst", ".dic", ".dict", ".csv", ".json", ".log", ".cfg"}
_COUNT_READ_CHUNK = 8 * 1024 * 1024


class WordlistCategory(str, Enum):
    """Functional category of an indexed wordlist."""

    DISCOVERY = "discovery"
    PARAMETERS = "parameters"
    ATTACK_PAYLOADS = "attack_payloads"
    FUZZ = "fuzz"
    AUTH_PASSWORDS = "auth_passwords"
    EXPLOITS = "exploits"
    MISC = "misc"


class WordlistEntry(BaseModel):
    """Metadata record describing one indexed wordlist file."""

    id: str
    name: str
    filename: str
    category: WordlistCategory
    collection: str
    path: str
    size_bytes: int
    line_count: Optional[int] = None
    tags: List[str] = Field(default_factory=list)


_CATEGORY_HINTS: List[tuple] = [
    (
        WordlistCategory.PARAMETERS,
        ["parameter", "parameters", "params", "burp-parameter", "query-param", "fields"],
    ),
    (
        WordlistCategory.ATTACK_PAYLOADS,
        [
            "xss", "sqli", "sql-injection", "sqlinjection", "injection", "traversal",
            "lfi", "rfi", "rce", "command-injection", "cmd", "ssrf", "xxe", "ssti",
            "upload", "ldap", "nosql", "xpath", "crlf", "open-redirect", "redirect",
            "csrf", "deserialization", "template-injection", "payloadsallthethings",
            "fuzzing", "webshell", "reverse-shell", "http-protocol",
        ],
    ),
    (
        WordlistCategory.EXPLOITS,
        ["exploit", "exploits", "exploitdb", "cve", "metasploit", "msf", "nmap"],
    ),
    (
        WordlistCategory.FUZZ,
        ["fuzz", "wfuzz", "fuzzdb", "attack", "intruder", "intruders", "stress", "malformed"],
    ),
    (
        WordlistCategory.AUTH_PASSWORDS,
        [
            "password", "passwords", "username", "usernames", "users", "credentials",
            "creds", "brute", "rockyou", "fasttrack", "wifite", "john", "wifi",
            "auth", "common-credentials", "default-creds", "jwt", "secrets",
            "token", "tokens", "api-keys",
        ],
    ),
    (
        WordlistCategory.DISCOVERY,
        [
            "discovery", "dirb", "dirbuster", "directories", "directory", "vhosts",
            "vhost", "dns", "subdomains", "subdomain", "content_discovery",
            "content-discovery", "webservices", "api-endpoints", "endpoints",
            "raft", "common.txt", "big.txt", "small.txt", "mutations",
        ],
    ),
]

_DEFAULT_SCAN_ROOTS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/usr/share/payloadsallthethings",
    "/usr/share/dirb/wordlists",
    "/usr/share/wfuzz/wordlist",
    "~/PayloadsAllTheThings-master",
    "~/.flowforge/wordlists",
]


class WordlistLoader:
    """Indexes wordlist files under configured scan roots and streams their entries."""

    def __init__(self, roots: Optional[List[str]] = None) -> None:
        self._roots: List[Path] = []
        for raw in roots if roots is not None else _DEFAULT_SCAN_ROOTS:
            expanded = Path(os.path.expanduser(str(raw))).resolve()
            if expanded.is_dir() and expanded not in self._roots:
                self._roots.append(expanded)
        self._index: Dict[str, WordlistEntry] = {}
        self._line_count_cache: Dict[str, int] = {}

    @property
    def roots(self) -> List[str]:
        return [str(r) for r in self._roots]

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def refresh(self) -> int:
        """Rescan all roots and rebuild the index. Returns number of indexed lists."""
        self._index.clear()
        self._line_count_cache.clear()
        for root in self._roots:
            try:
                self._scan_root(root)
            except Exception as exc:
                logger.warning("Failed scanning wordlist root %s: %s", root, exc)
        logger.info("Wordlist Arsenal indexed %d lists across %d roots", len(self._index), len(self._roots))
        return len(self._index)

    def _scan_root(self, root: Path) -> None:
        collection = root.name.lower()
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                suffix = fpath.suffix.lower()
                is_gz = suffix == ".gz"
                base_suffix = Path(fname).stem.rsplit(".", 1)[-1].lower() if is_gz else suffix
                if not is_gz and suffix not in _INDEXED_EXTENSIONS:
                    continue
                if is_gz and f".{base_suffix}" not in _INDEXED_EXTENSIONS:
                    continue
                try:
                    rel = fpath.relative_to(root)
                except ValueError:
                    continue
                entry = WordlistEntry(
                    id=self._make_id(fpath),
                    name=str(rel),
                    filename=fname,
                    category=self.categorize(rel),
                    collection=collection,
                    path=str(fpath),
                    size_bytes=fpath.stat().st_size,
                    tags=self._derive_tags(rel),
                )
                self._index[entry.id] = entry

    @staticmethod
    def _make_id(path: Path) -> str:
        return hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _derive_tags(rel_path: Path) -> List[str]:
        parts = [p.lower() for p in rel_path.parts[:-1]]
        tags: List[str] = []
        known_markers = {
            "xss": "xss", "sql": "sqli", "traversal": "path-traversal",
            "lfi": "lfi", "rfi": "rfi", "ssrf": "ssrf", "xxe": "xxe",
            "ssti": "ssti", "rce": "rce", "ldap": "ldap", "nosql": "nosql",
            "upload": "file-upload", "password": "passwords", "username": "usernames",
            "dns": "dns", "vhost": "vhosts", "api": "api", "graphql": "graphql",
            "websocket": "websocket", "jwt": "jwt",
        }
        for part in parts:
            for marker, tag in known_markers.items():
                if marker in part and tag not in tags:
                    tags.append(tag)
        return tags[:6]

    @staticmethod
    def categorize(path: Path) -> WordlistCategory:
        """Classify a wordlist file by its relative path/name heuristics.

        Expects a path relative to the collection root so that collection
        directory names (e.g. 'seclists') do not skew classification.
        """
        haystack = " ".join(p.lower() for p in path.parts)
        fname = path.name.lower()
        for category, hints in _CATEGORY_HINTS:
            for hint in hints:
                if hint in fname or hint in haystack:
                    return category
        return WordlistCategory.MISC

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def list_wordlists(
        self,
        category: Optional[str] = None,
        search: Optional[str] = None,
        offset: int = 0,
        limit: int = 200,
        include_counts: bool = False,
    ) -> List[WordlistEntry]:
        items = list(self._ensure_index().values())
        if category:
            cat_lower = category.lower()
            items = [
                e for e in items
                if e.category.value == cat_lower
                or any(t == cat_lower for t in e.tags)
            ]
        if search:
            needle = search.lower()
            items = [e for e in items if needle in e.name.lower() or needle in e.collection.lower()]
        items.sort(key=lambda e: (e.category.value, e.collection, e.name))
        window = items[offset : offset + limit]
        if include_counts:
            for e in window:
                e.line_count = self.count_lines(e.id)
        return window

    def count_total(self, category: Optional[str] = None, search: Optional[str] = None) -> int:
        items = list(self._ensure_index().values())
        if category:
            cat_lower = category.lower()
            items = [
                e for e in items
                if e.category.value == cat_lower
                or any(t == cat_lower for t in e.tags)
            ]
        if search:
            needle = search.lower()
            items = [e for e in items if needle in e.name.lower() or needle in e.collection.lower()]
        return len(items)

    def category_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self._ensure_index().values():
            counts[e.category.value] = counts.get(e.category.value, 0) + 1
        return dict(sorted(counts.items()))

    def get(self, list_id: str) -> Optional[WordlistEntry]:
        return self._ensure_index().get(list_id)

    def resolve_ids(self, list_ids: List[str]) -> List[WordlistEntry]:
        resolved: List[WordlistEntry] = []
        for lid in list_ids:
            entry = self.get(lid)
            if entry:
                resolved.append(entry)
        return resolved

    # ------------------------------------------------------------------
    # Entry streaming
    # ------------------------------------------------------------------

    def iter_entries(self, list_id: str) -> Iterator[str]:
        entry = self.get(list_id)
        if not entry:
            return
        path = Path(entry.path)
        opener = gzip.open if path.suffix.lower() == ".gz" else open
        try:
            with opener(path, "rb") as fh:  # type: ignore[operator]
                for raw_line in fh:
                    try:
                        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                    except Exception:
                        continue
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    yield stripped
        except FileNotFoundError:
            logger.warning("Wordlist disappeared since indexing: %s", path)
        except Exception as exc:
            logger.warning("Failed reading wordlist %s: %s", path, exc)

    def read_entries(self, list_id: str, offset: int = 0, limit: int = 100) -> Dict[str, object]:
        """Return a page of non-comment entries plus pagination metadata."""
        entries: List[str] = []
        skipped = 0
        total_matched = 0
        hard_cap = max(offset + limit + 1_000_000, 0)
        for idx, value in enumerate(self.iter_entries(list_id)):
            total_matched += 1
            if idx >= hard_cap:
                break
            if skipped < offset:
                skipped += 1
                continue
            if len(entries) < limit:
                entries.append(value)
            else:
                break
        return {
            "entries": entries,
            "offset": offset,
            "limit": limit,
            "returned": len(entries),
        }

    def sample_entries(self, list_id: str, n: int, scan_cap: int = 20000) -> List[str]:
        """Evenly sample up to n entries from the first scan_cap lines of a list."""
        if n <= 0:
            return []
        collected: List[str] = []
        seen = 0
        for value in self.iter_entries(list_id):
            if seen >= scan_cap:
                break
            collected.append(value)
            seen += 1
        if len(collected) <= n:
            return collected
        step = len(collected) / float(n)
        return [collected[int(i * step)] for i in range(n)]

    def count_lines(self, list_id: str) -> Optional[int]:
        """Count usable entries (non-blank, non-comment) using memory-bounded chunked reads."""
        cached = self._line_count_cache.get(list_id)
        if cached is not None:
            return cached
        entry = self.get(list_id)
        if not entry:
            return None
        count = 0
        path = Path(entry.path)
        opener = gzip.open if path.suffix.lower() == ".gz" else open

        def _usable(raw_line: bytes) -> bool:
            stripped = raw_line.strip()
            return bool(stripped) and not stripped.startswith(b"#")

        try:
            with opener(path, "rb") as fh:  # type: ignore[operator]
                tail = b""
                while True:
                    chunk = fh.read(_COUNT_READ_CHUNK)  # type: ignore[attr-defined]
                    if not chunk:
                        break
                    lines = (tail + chunk).split(b"\n")
                    tail = lines.pop()
                    count += sum(1 for ln in lines if _usable(ln))
                if _usable(tail):
                    count += 1
        except FileNotFoundError:
            return None
        except Exception as exc:
            logger.warning("Failed counting lines of %s: %s", path, exc)
            return None
        self._line_count_cache[list_id] = count
        return count

    def preview(self, list_id: str, n: int = 25) -> List[str]:
        return self.sample_entries(list_id, n, scan_cap=n * 2)

    def _ensure_index(self) -> Dict[str, WordlistEntry]:
        if not self._index:
            self.refresh()
        return self._index


_loader_instance: Optional[WordlistLoader] = None


def get_wordlist_loader() -> WordlistLoader:
    """Return the process-wide WordlistLoader built from current settings."""
    global _loader_instance
    if _loader_instance is None:
        roots: Optional[List[str]] = None
        try:
            from flowforge.config import get_settings
            cfg_dirs = get_settings().wordlist_dirs
            if cfg_dirs:
                roots = list(cfg_dirs)
        except Exception:
            roots = None
        _loader_instance = WordlistLoader(roots=roots)
    return _loader_instance


def reset_wordlist_loader() -> None:
    """Drop the singleton so the next access re-reads settings (used by tests)."""
    global _loader_instance
    _loader_instance = None
