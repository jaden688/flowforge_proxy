"""
Multi-root Nuclei template loader, scanner, deduplicator, and indexer.

Scans templates across multiple filesystem roots:
- flowforge/nuclei-templates (built-in)
- data/wordlists/flowforge-arsenal/nuclei-templates (arsenal)
- ~/.flowforge/nuclei-templates (user custom)
- Any custom roots specified by caller

Deduplicates templates by normalized template ID (`template.id.lower()`),
guaranteeing that Arsenal and custom paths cleanly override built-in templates.
Provides thread-safe access, robust malformed YAML handling, and fast querying.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

try:
    from yaml import CSafeLoader as FastYamlLoader
except ImportError:
    from yaml import SafeLoader as FastYamlLoader  # type: ignore

from flowforge.models.nuclei import (
    NucleiHttpBlock,
    NucleiMatcher,
    NucleiMatcherType,
    NucleiSeverity,
    NucleiTemplate,
)

logger = logging.getLogger("flowforge.heuristics.nuclei_loader")

# Base project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Default scan roots in precedence order (later roots override earlier roots)
DEFAULT_NUCLEI_ROOTS = [
    PROJECT_ROOT / "flowforge" / "nuclei-templates",
    PROJECT_ROOT / "data" / "wordlists" / "flowforge-arsenal" / "nuclei-templates",
    Path.home() / ".flowforge" / "nuclei-templates",
]

_YAML_EXTENSIONS = {".yaml", ".yml"}


class NucleiTemplateLoader:
    """
    Thread-safe loader and indexer for Nuclei vulnerability and exposure templates
    across multiple filesystem roots.
    """

    def __init__(
        self,
        roots: Optional[List[Union[str, Path]]] = None,
        auto_load: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._roots: List[Path] = []

        raw_roots = roots if roots is not None else DEFAULT_NUCLEI_ROOTS
        for raw in raw_roots:
            p = Path(os.path.expanduser(str(raw))).resolve()
            if p not in self._roots:
                self._roots.append(p)

        self._templates: Dict[str, NucleiTemplate] = {}
        self._template_sources: Dict[str, List[str]] = {}
        self._overridden_count: int = 0
        self._last_refresh_time: float = 0.0

        if auto_load:
            self.refresh()

    @property
    def roots(self) -> List[str]:
        """List of configured template scan root paths as strings."""
        with self._lock:
            return [str(r) for r in self._roots]

    @property
    def total_count(self) -> int:
        """Count of currently indexed deduplicated templates."""
        with self._lock:
            return len(self._templates)

    def refresh(self) -> int:
        """
        Rescans all filesystem roots, parses YAML templates, applies override precedence,
        and rebuilds the in-memory index.

        Returns:
            Total count of deduplicated templates indexed.
        """
        start_time = time.time()
        new_templates: Dict[str, NucleiTemplate] = {}
        new_sources: Dict[str, List[str]] = {}
        overridden = 0

        with self._lock:
            for root in self._roots:
                if not root.exists() or not root.is_dir():
                    continue

                for dirpath, dirnames, filenames in os.walk(root):
                    # Skip hidden directories
                    dirnames[:] = [d for d in dirnames if not d.startswith(".")]

                    for fname in filenames:
                        if fname.startswith("."):
                            continue
                        fpath = Path(dirpath) / fname
                        if fpath.suffix.lower() not in _YAML_EXTENSIONS:
                            continue

                        parsed = self._load_template_file(fpath, root)
                        if parsed is None:
                            continue

                        norm_id = parsed.id.strip().lower()
                        if norm_id in new_templates:
                            overridden += 1
                            new_sources[norm_id].append(str(fpath))
                        else:
                            new_sources[norm_id] = [str(fpath)]

                        # Latest root or file takes precedence (overrides earlier)
                        new_templates[norm_id] = parsed

            self._templates = new_templates
            self._template_sources = new_sources
            self._overridden_count = overridden
            self._last_refresh_time = time.time()

            elapsed = self._last_refresh_time - start_time
            logger.info(
                "NucleiTemplateLoader loaded %d templates across %d roots in %.2fs (overridden: %d)",
                len(self._templates),
                len(self._roots),
                elapsed,
                self._overridden_count,
            )
            return len(self._templates)

    def _load_template_file(self, fpath: Path, root: Path) -> Optional[NucleiTemplate]:
        """
        Safely reads and parses a single YAML template file.
        Handles malformed/corrupted files gracefully without raising exceptions.
        """
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                raw_text = fh.read()

            if not raw_text.strip():
                return None

            data = yaml.load(raw_text, Loader=FastYamlLoader)
            if not isinstance(data, dict):
                return None

            return self._build_template_model(data, raw_text, str(fpath), root)

        except Exception as exc:
            logger.warning("Failed parsing Nuclei template at %s: %s", fpath, exc)
            return None

    def _build_template_model(
        self,
        data: Dict[str, Any],
        raw_yaml: str,
        fpath_str: str,
        root: Path,
    ) -> Optional[NucleiTemplate]:
        """Constructs a NucleiTemplate instance from parsed dictionary data."""
        raw_id = data.get("id")
        if not raw_id:
            return None
        template_id = str(raw_id).strip()

        info = data.get("info") if isinstance(data.get("info"), dict) else {}

        name = str(info.get("name") or template_id)
        author = info.get("author", "flowforge")
        severity_val = info.get("severity", "info")
        description = str(info.get("description") or "")
        reference = info.get("reference", [])
        tags = info.get("tags", [])
        metadata = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}

        # Parse HTTP blocks from 'http' or 'requests'
        http_data = data.get("http") or data.get("requests") or []
        http_blocks: List[NucleiHttpBlock] = []

        if isinstance(http_data, list):
            for blk in http_data:
                if not isinstance(blk, dict):
                    continue

                # Parse matchers
                matchers_list: List[NucleiMatcher] = []
                for m in blk.get("matchers") or []:
                    if not isinstance(m, dict):
                        continue
                    m_type_raw = m.get("type", "word")
                    matcher = NucleiMatcher(
                        type=NucleiMatcherType.from_str(m_type_raw),
                        part=str(m.get("part", "body")),
                        words=m.get("words", []),
                        regex=m.get("regex", []),
                        status=m.get("status", []),
                        condition=str(m.get("condition", "or")),
                        case_insensitive=bool(m.get("case-insensitive", m.get("case_insensitive", False))),
                        negative=bool(m.get("negative", False)),
                        dsl=m.get("dsl", []),
                        name=m.get("name"),
                        internal=bool(m.get("internal", False)),
                        encoding=m.get("encoding"),
                    )
                    matchers_list.append(matcher)

                http_block = NucleiHttpBlock(
                    method=str(blk.get("method", "GET")),
                    path=blk.get("path", []),
                    raw=blk.get("raw", []),
                    headers=blk.get("headers") if isinstance(blk.get("headers"), dict) else {},
                    body=str(blk.get("body")) if blk.get("body") is not None else None,
                    matchers_condition=str(blk.get("matchers-condition") or blk.get("matchers_condition") or "or"),
                    matchers=matchers_list,
                    extractors=blk.get("extractors", []) if isinstance(blk.get("extractors"), list) else [],
                    stop_at_first_match=bool(blk.get("stop-at-first-match", blk.get("stop_at_first_match", False))),
                    payloads=blk.get("payloads") if isinstance(blk.get("payloads"), dict) else {},
                    cookie_reuse=bool(blk.get("cookie-reuse", blk.get("cookie_reuse", False))),
                    redirects=bool(blk.get("redirects", False)),
                    max_redirects=int(blk.get("max-redirects", blk.get("max_redirects", 10))),
                )
                http_blocks.append(http_block)

        # Infer category
        category = self._infer_category(template_id, tags, fpath_str)

        # Infer passive vs active
        is_passive, is_active = self._infer_execution_mode(tags, metadata, http_blocks, category)

        return NucleiTemplate(
            id=template_id,
            name=name,
            author=author,
            severity=NucleiSeverity.from_str(severity_val),
            description=description,
            reference=reference,
            tags=tags,
            category=category,
            source_path=fpath_str,
            http_blocks=http_blocks,
            raw_yaml=raw_yaml,
            is_passive=is_passive,
            is_active=is_active,
            metadata=metadata,
            variables=data.get("variables") if isinstance(data.get("variables"), dict) else {},
        )

    def _infer_category(self, template_id: str, tags: Any, fpath_str: str) -> str:
        """Categorizes a template based on path structure, ID naming, and tags."""
        p_lower = fpath_str.lower()
        id_lower = template_id.lower()
        tag_list = [str(t).lower() for t in (tags if isinstance(tags, list) else str(tags).split(","))]

        if any(k in id_lower for k in ("cve-", "cnvd-")) or any(k in p_lower for k in ("/cves/", "/cnvd/")) or "cve" in tag_list:
            return "CVE"
        if "/exposures/" in p_lower or "/exposed-panels/" in p_lower or "exposure" in tag_list or "exposed" in tag_list:
            return "EXPOSURE"
        if "/misconfiguration/" in p_lower or "/misconfigurations/" in p_lower or "misconfig" in tag_list or "misconfiguration" in tag_list:
            return "MISCONFIG"
        if "/vulnerabilities/" in p_lower or "vuln" in tag_list or "vulnerability" in tag_list:
            return "VULNERABILITY"
        if "/technologies/" in p_lower or "tech" in tag_list or "technology" in tag_list:
            return "TECH"
        if "/default-logins/" in p_lower or "default-login" in tag_list or "login" in tag_list:
            return "LOGIN"
        if "/token-spray/" in p_lower or "token" in tag_list or "secret" in tag_list or "keys" in tag_list:
            return "TOKEN"
        if "/fuzzing/" in p_lower or "fuzz" in tag_list:
            return "FUZZING"
        if "/dast/" in p_lower or "dast" in tag_list:
            return "DAST"
        if "/cloud/" in p_lower or "cloud" in tag_list or "gcp" in tag_list or "aws" in tag_list:
            return "CLOUD"
        if any(k in p_lower for k in ("/network/", "/dns/", "/ssl/")) or any(k in tag_list for k in ("network", "dns", "ssl")):
            return "NETWORK"
        if "/flowforge-arsenal/" in p_lower or "/custom/" in p_lower:
            return "CUSTOM"

        return "MISC"

    def _infer_execution_mode(
        self,
        tags: Any,
        metadata: Dict[str, Any],
        http_blocks: List[NucleiHttpBlock],
        category: str,
    ) -> Tuple[bool, bool]:
        """
        Determines whether a template can be passively evaluated on intercepted traffic,
        actively executed with outbound requests, or both.
        """
        tag_list = [str(t).lower() for t in (tags if isinstance(tags, list) else str(tags).split(","))]
        cat_upper = category.upper()

        # Explicit passive markers (following official Nuclei passive scanning specification)
        is_passive = (
            "passive" in tag_list
            or bool(metadata.get("passive", False))
            or cat_upper == "PASSIVE"
        )

        # Active is true if it contains HTTP blocks or active probes
        is_active = len(http_blocks) > 0

        # If no HTTP blocks, check if passive
        if not http_blocks:
            is_passive = True
            is_active = False

        return is_passive, is_active

    def get_template(self, template_id: str) -> Optional[NucleiTemplate]:
        """Retrieves an indexed template by its case-insensitive template ID."""
        if not template_id:
            return None
        norm_id = str(template_id).strip().lower()
        with self._lock:
            return self._templates.get(norm_id)

    def register_template(self, template: NucleiTemplate) -> None:
        """
        Directly registers or overrides a template in memory.
        Useful for dynamic user-defined templates or test cases.
        """
        norm_id = template.id.strip().lower()
        with self._lock:
            if norm_id in self._templates:
                self._overridden_count += 1
            self._templates[norm_id] = template

    def list_templates(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        tag: Optional[str] = None,
        query: Optional[str] = None,
        is_passive: Optional[bool] = None,
        is_active: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[NucleiTemplate], int]:
        """
        Filters and paginates indexed templates matching search criteria.

        Returns:
            Tuple of (matching_templates_page, total_matching_count).
        """
        with self._lock:
            cat_filter = category.strip().lower() if category else None
            sev_filter = severity.strip().lower() if severity else None
            tag_filter = tag.strip().lower() if tag else None
            q_filter = query.strip().lower() if query else None

            matched: List[NucleiTemplate] = []
            for tmpl in self._templates.values():
                if cat_filter and tmpl.category.lower() != cat_filter:
                    continue

                if sev_filter:
                    tmpl_sev = tmpl.severity.value if isinstance(tmpl.severity, NucleiSeverity) else str(tmpl.severity).lower()
                    if tmpl_sev != sev_filter:
                        continue

                if tag_filter and not any(tag_filter in t.lower() for t in tmpl.tags):
                    continue

                if is_passive is not None and tmpl.is_passive != is_passive:
                    continue

                if is_active is not None and tmpl.is_active != is_active:
                    continue

                if q_filter:
                    corpus = f"{tmpl.id} {tmpl.name} {tmpl.description} {' '.join(tmpl.tags)}".lower()
                    if q_filter not in corpus:
                        continue

                matched.append(tmpl)

            total_count = len(matched)
            if limit > 0:
                paginated = matched[offset : offset + limit]
            else:
                paginated = matched[offset:]

            return paginated, total_count

    def get_passive_templates(self) -> List[NucleiTemplate]:
        """Returns all templates capable of passive response matching."""
        with self._lock:
            return [t for t in self._templates.values() if t.is_passive]

    def get_active_templates(self) -> List[NucleiTemplate]:
        """Returns all templates configured for active HTTP scanning/probing."""
        with self._lock:
            return [t for t in self._templates.values() if t.is_active]

    def get_stats(self) -> Dict[str, Any]:
        """Computes summary statistics of indexed templates."""
        with self._lock:
            by_sev: Dict[str, int] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }
            by_cat: Dict[str, int] = {}
            passive_count = 0
            active_count = 0

            for tmpl in self._templates.values():
                sev_str = tmpl.severity.value if isinstance(tmpl.severity, NucleiSeverity) else str(tmpl.severity).lower()
                by_sev[sev_str] = by_sev.get(sev_str, 0) + 1

                by_cat[tmpl.category] = by_cat.get(tmpl.category, 0) + 1

                if tmpl.is_passive:
                    passive_count += 1
                if tmpl.is_active:
                    active_count += 1

            return {
                "total_templates": len(self._templates),
                "by_severity": by_sev,
                "by_category": by_cat,
                "passive_count": passive_count,
                "active_count": active_count,
                "roots_scanned": [str(r) for r in self._roots if r.exists()],
                "overridden_count": self._overridden_count,
                "last_refresh_timestamp": self._last_refresh_time,
            }


# ----------------------------------------------------------------------
# Singleton Access
# ----------------------------------------------------------------------

_GLOBAL_LOADER: Optional[NucleiTemplateLoader] = None
_GLOBAL_LOADER_LOCK = threading.Lock()


def get_nuclei_loader(
    roots: Optional[List[Union[str, Path]]] = None,
    auto_refresh: bool = True,
) -> NucleiTemplateLoader:
    """Returns the process-wide singleton NucleiTemplateLoader instance."""
    global _GLOBAL_LOADER
    with _GLOBAL_LOADER_LOCK:
        if _GLOBAL_LOADER is None:
            _GLOBAL_LOADER = NucleiTemplateLoader(roots=roots, auto_load=auto_refresh)
        return _GLOBAL_LOADER


def reset_nuclei_loader() -> None:
    """Resets the singleton loader instance (primarily for test isolation)."""
    global _GLOBAL_LOADER
    with _GLOBAL_LOADER_LOCK:
        _GLOBAL_LOADER = None
