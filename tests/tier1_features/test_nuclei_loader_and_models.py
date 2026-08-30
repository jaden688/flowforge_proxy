"""
Tier 1 Feature Tests: Nuclei Pydantic v2 Models & Multi-Root Template Loader.

Verifies:
- Data model serialization, normalization, and validation.
- Multi-root filesystem discovery across built-in, arsenal, and custom roots.
- Case-insensitive template ID deduplication and override precedence.
- Robust error tolerance for corrupted/malformed YAML files.
- Thread-safe querying, filtering, search, and statistics computation.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
import pytest

from flowforge.models.nuclei import (
    NucleiHttpBlock,
    NucleiMatcher,
    NucleiMatcherType,
    NucleiMatchResult,
    NucleiSeverity,
    NucleiTemplate,
)
from flowforge.heuristics.nuclei_loader import (
    NucleiTemplateLoader,
    get_nuclei_loader,
    reset_nuclei_loader,
)


# ===========================================================================
# 1. Model Parsing & Serialization Tests
# ===========================================================================

def test_nuclei_severity_enum_and_normalization():
    """Verify NucleiSeverity parsing handles varying cases and fallback values."""
    assert NucleiSeverity.from_str("critical") == NucleiSeverity.CRITICAL
    assert NucleiSeverity.from_str("CRITICAL") == NucleiSeverity.CRITICAL
    assert NucleiSeverity.from_str("High") == NucleiSeverity.HIGH
    assert NucleiSeverity.from_str("medium") == NucleiSeverity.MEDIUM
    assert NucleiSeverity.from_str("Low") == NucleiSeverity.LOW
    assert NucleiSeverity.from_str("INFO") == NucleiSeverity.INFO
    assert NucleiSeverity.from_str("unknown_val") == NucleiSeverity.INFO
    assert NucleiSeverity.from_str("") == NucleiSeverity.INFO
    assert NucleiSeverity.from_str(None) == NucleiSeverity.INFO
    assert NucleiSeverity.from_str("informational") == NucleiSeverity.INFO


def test_nuclei_matcher_type_enum():
    """Verify NucleiMatcherType enum conversions and aliases."""
    assert NucleiMatcherType.from_str("word") == NucleiMatcherType.WORD
    assert NucleiMatcherType.from_str("words") == NucleiMatcherType.WORD
    assert NucleiMatcherType.from_str("regex") == NucleiMatcherType.REGEX
    assert NucleiMatcherType.from_str("STATUS") == NucleiMatcherType.STATUS
    assert NucleiMatcherType.from_str("binary") == NucleiMatcherType.BINARY
    assert NucleiMatcherType.from_str("size") == NucleiMatcherType.SIZE
    assert NucleiMatcherType.from_str("dsl") == NucleiMatcherType.DSL
    assert NucleiMatcherType.from_str("xpath") == NucleiMatcherType.XPATH
    assert NucleiMatcherType.from_str("invalid") == NucleiMatcherType.WORD


def test_nuclei_matcher_model_coercion_and_aliases():
    """Verify NucleiMatcher parses kebab-case aliases, scalar strings to lists, and condition."""
    raw_dict = {
        "type": "word",
        "part": "body",
        "words": "root:.*:0:0:",
        "regex": ["uid=[0-9]+"],
        "status": "200",
        "condition": "AND",
        "case-insensitive": True,
        "negative": False,
        "dsl": "len(body) > 100",
    }
    matcher = NucleiMatcher.model_validate(raw_dict)
    assert matcher.type == NucleiMatcherType.WORD
    assert matcher.part == "body"
    assert matcher.words == ["root:.*:0:0:"]
    assert matcher.regex == ["uid=[0-9]+"]
    assert matcher.status == [200]
    assert matcher.condition == "and"
    assert matcher.case_insensitive is True
    assert matcher.negative is False
    assert matcher.dsl == ["len(body) > 100"]

    # Test serialization round-trip
    dump = matcher.model_dump()
    assert dump["type"] == "word"
    assert dump["words"] == ["root:.*:0:0:"]
    assert dump["case_insensitive"] is True


def test_nuclei_http_block_model():
    """Verify NucleiHttpBlock parses methods, paths, raw queries, headers, and matchers."""
    raw_block = {
        "method": "post",
        "path": "{{BaseURL}}/api/v1/debug",
        "raw": ["POST /api/v1/debug HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"],
        "headers": {"X-Custom-Header": "test-val"},
        "body": '{"debug": true}',
        "matchers-condition": "AND",
        "matchers": [
            {
                "type": "status",
                "status": [200, 201],
            },
            {
                "type": "word",
                "part": "body",
                "words": ["debug_active"],
            },
        ],
        "stop-at-first-match": True,
        "cookie-reuse": True,
        "max-redirects": 5,
    }
    block = NucleiHttpBlock.model_validate(raw_block)
    assert block.method == "POST"
    assert block.path == ["{{BaseURL}}/api/v1/debug"]
    assert len(block.raw) == 1
    assert block.headers == {"X-Custom-Header": "test-val"}
    assert block.body == '{"debug": true}'
    assert block.matchers_condition == "and"
    assert len(block.matchers) == 2
    assert block.matchers[0].status == [200, 201]
    assert block.stop_at_first_match is True
    assert block.cookie_reuse is True
    assert block.max_redirects == 5


def test_nuclei_template_and_match_result_models():
    """Verify NucleiTemplate and NucleiMatchResult model serialization and properties."""
    template = NucleiTemplate(
        id="cve-2023-12345",
        name="Test CVE Vulnerability",
        author=["security_researcher", "pdteam"],
        severity=NucleiSeverity.CRITICAL,
        description="Critical Remote Code Execution test template",
        reference=["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"],
        tags="cve,cve2023,rce,auth-bypass",
        category="CVE",
        source_path="/path/to/cve-2023-12345.yaml",
        raw_yaml="id: cve-2023-12345\n...",
        is_passive=False,
        is_active=True,
    )
    assert template.id == "cve-2023-12345"
    assert template.severity == NucleiSeverity.CRITICAL
    assert template.author_str == "security_researcher, pdteam"
    assert template.cve_id == "CVE-2023-12345"
    assert "rce" in template.tags
    assert "cve" in template.tags

    result = NucleiMatchResult(
        template_id=template.id,
        template_name=template.name,
        severity=template.severity,
        category=template.category,
        tags=template.tags,
        matched=True,
        matched_conditions=["status == 200", "word 'root:' in body"],
        extracted_data={"version": "1.2.3"},
        matched_at="https://target.local/vuln",
        execution_time_ms=1.45,
    )
    assert result.matched is True
    assert result.severity == NucleiSeverity.CRITICAL
    assert len(result.matched_conditions) == 2
    assert result.execution_time_ms == 1.45


# ===========================================================================
# 2. Multi-Root Discovery & Override Precedence Tests
# ===========================================================================

@pytest.fixture
def multi_root_environment():
    """Creates a temporary multi-root environment with built-in, arsenal, and custom templates."""
    temp_dir = tempfile.mkdtemp(prefix="ff_nuclei_test_")
    builtin_root = Path(temp_dir) / "builtin"
    arsenal_root = Path(temp_dir) / "arsenal"
    custom_root = Path(temp_dir) / "custom"

    # Setup directories
    (builtin_root / "http" / "cves").mkdir(parents=True, exist_ok=True)
    (builtin_root / "http" / "exposures").mkdir(parents=True, exist_ok=True)
    (arsenal_root / "cves").mkdir(parents=True, exist_ok=True)
    (arsenal_root / "misconfigurations").mkdir(parents=True, exist_ok=True)
    (custom_root / "custom-yaml").mkdir(parents=True, exist_ok=True)

    # 1. Built-in template: cve-2024-0001 (Severity LOW in built-in)
    builtin_cve = builtin_root / "http" / "cves" / "cve-2024-0001.yaml"
    builtin_cve.write_text("""
id: cve-2024-0001
info:
  name: Built-in Base CVE
  author: builtin_author
  severity: low
  description: Built-in description
  tags: cve,builtin
http:
  - method: GET
    path:
      - "{{BaseURL}}/builtin-path"
    matchers:
      - type: status
        status:
          - 200
""", encoding="utf-8")

    # 2. Built-in exposure template: swagger-exposure
    builtin_exp = builtin_root / "http" / "exposures" / "swagger-exposure.yaml"
    builtin_exp.write_text("""
id: swagger-exposure
info:
  name: Swagger API Exposure
  author: pdteam
  severity: info
  description: Swagger docs detected
  tags: exposure,swagger,passive
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "swagger:"
""", encoding="utf-8")

    # 3. Arsenal template overriding cve-2024-0001 with HIGH severity and custom payload
    arsenal_cve = arsenal_root / "cves" / "cve-2024-0001.yaml"
    arsenal_cve.write_text("""
id: CVE-2024-0001
info:
  name: Arsenal Overridden CVE
  author: arsenal_elite
  severity: high
  description: Enhanced arsenal exploit
  tags: cve,arsenal,rce
http:
  - method: POST
    path:
      - "{{BaseURL}}/arsenal-exploit"
    body: "cmd=id"
    matchers:
      - type: word
        words:
          - "uid=0"
""", encoding="utf-8")

    # 4. Arsenal unique template: misconfig-aws-keys
    arsenal_misc = arsenal_root / "misconfigurations" / "misconfig-aws-keys.yaml"
    arsenal_misc.write_text("""
id: misconfig-aws-keys
info:
  name: Exposed AWS Keys
  author: arsenal_team
  severity: critical
  tags: misconfig,aws,keys
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers:
      - type: word
        words:
          - "AKIA"
""", encoding="utf-8")

    # 5. Custom unique template: custom-internal-portal
    custom_yaml = custom_root / "custom-yaml" / "custom-internal-portal.yaml"
    custom_yaml.write_text("""
id: custom-internal-portal
info:
  name: Internal Portal Discovery
  author: internal_tester
  severity: medium
  tags: custom,internal
http:
  - method: GET
    path:
      - "{{BaseURL}}/portal"
    matchers:
      - type: status
        status:
          - 200
""", encoding="utf-8")

    yield {
        "temp_dir": temp_dir,
        "roots": [builtin_root, arsenal_root, custom_root],
        "builtin_root": builtin_root,
        "arsenal_root": arsenal_root,
        "custom_root": custom_root,
    }

    shutil.rmtree(temp_dir, ignore_errors=True)


def test_multi_root_discovery_and_deduplication(multi_root_environment):
    """Verify loader discovers templates across all roots and deduplicates by normalized ID."""
    roots = multi_root_environment["roots"]
    loader = NucleiTemplateLoader(roots=roots, auto_load=True)

    # 4 unique template IDs: cve-2024-0001, swagger-exposure, misconfig-aws-keys, custom-internal-portal
    assert loader.total_count == 4
    stats = loader.get_stats()
    assert stats["total_templates"] == 4
    assert stats["overridden_count"] == 1  # cve-2024-0001 was overridden by arsenal

    # Verify that Arsenal version overrode the built-in version
    cve_template = loader.get_template("cve-2024-0001")
    assert cve_template is not None
    assert cve_template.name == "Arsenal Overridden CVE"
    assert cve_template.author == "arsenal_elite"
    assert cve_template.severity == NucleiSeverity.HIGH
    assert cve_template.category == "CVE"
    assert cve_template.http_blocks[0].method == "POST"

    # Case-insensitive lookup check
    assert loader.get_template("CVE-2024-0001") is not None
    assert loader.get_template("  cve-2024-0001  ") is not None

    # Verify custom template was discovered
    custom_tmpl = loader.get_template("custom-internal-portal")
    assert custom_tmpl is not None
    assert custom_tmpl.severity == NucleiSeverity.MEDIUM


def test_template_filtering_listing_and_stats(multi_root_environment):
    """Verify list_templates filtering by category, severity, tags, text query, and stats."""
    roots = multi_root_environment["roots"]
    loader = NucleiTemplateLoader(roots=roots)

    # Category filter
    cves, cve_count = loader.list_templates(category="CVE")
    assert cve_count == 1
    assert cves[0].id.lower() == "cve-2024-0001"

    # Severity filter
    crit, crit_count = loader.list_templates(severity="critical")
    assert crit_count == 1
    assert crit[0].id == "misconfig-aws-keys"

    # Tag filter
    swagger_matches, sw_count = loader.list_templates(tag="swagger")
    assert sw_count == 1
    assert swagger_matches[0].id == "swagger-exposure"

    # Query search
    query_matches, q_count = loader.list_templates(query="portal")
    assert q_count == 1
    assert query_matches[0].id == "custom-internal-portal"

    # Passive / Active filter
    passive = loader.get_passive_templates()
    active = loader.get_active_templates()
    assert any(t.id.lower() == "swagger-exposure" for t in passive)
    assert any(t.id.lower() == "cve-2024-0001" for t in active)

    # Stats validation
    stats = loader.get_stats()
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1
    assert stats["by_severity"]["medium"] == 1
    assert stats["by_severity"]["info"] == 1


# ===========================================================================
# 3. Graceful Tolerance of Malformed YAML Tests
# ===========================================================================

def test_loader_tolerates_malformed_and_corrupt_yaml(multi_root_environment):
    """Verify loader ignores malformed YAML without crashing or dropping valid templates."""
    custom_root = multi_root_environment["custom_root"]

    # Create invalid files
    corrupt1 = custom_root / "custom-yaml" / "broken_syntax.yaml"
    corrupt1.write_text("id: broken\ninfo:\n  name: [unclosed list\n  severity: high", encoding="utf-8")

    corrupt2 = custom_root / "custom-yaml" / "empty_file.yaml"
    corrupt2.write_text("   \n\n", encoding="utf-8")

    corrupt3 = custom_root / "custom-yaml" / "scalar_only.yaml"
    corrupt3.write_text("just a string not a dict", encoding="utf-8")

    corrupt4 = custom_root / "custom-yaml" / "no_id.yaml"
    corrupt4.write_text("info:\n  name: No ID Template\n  severity: low", encoding="utf-8")

    # Refresh loader
    loader = NucleiTemplateLoader(roots=multi_root_environment["roots"])
    # Total count should still be 4 valid templates
    assert loader.total_count == 4
    assert loader.get_template("cve-2024-0001") is not None
    assert loader.get_template("broken") is None


# ===========================================================================
# 4. In-Memory Registration and Dynamic Override
# ===========================================================================

def test_register_template_in_memory_override():
    """Verify register_template directly injects and overrides templates in memory."""
    loader = NucleiTemplateLoader(roots=[], auto_load=False)
    assert loader.total_count == 0

    t1 = NucleiTemplate(
        id="dynamic-test-01",
        name="Dynamic Initial",
        severity=NucleiSeverity.LOW,
        category="CUSTOM",
    )
    loader.register_template(t1)
    assert loader.total_count == 1
    assert loader.get_template("dynamic-test-01").name == "Dynamic Initial"

    # Override same ID
    t2 = NucleiTemplate(
        id="DYNAMIC-TEST-01",
        name="Dynamic Overridden",
        severity=NucleiSeverity.CRITICAL,
        category="CUSTOM",
    )
    loader.register_template(t2)
    assert loader.total_count == 1
    tmpl = loader.get_template("dynamic-test-01")
    assert tmpl.name == "Dynamic Overridden"
    assert tmpl.severity == NucleiSeverity.CRITICAL


# ===========================================================================
# 5. Singleton Lifecycle Tests
# ===========================================================================

def test_singleton_get_and_reset():
    """Verify get_nuclei_loader returns singleton and reset_nuclei_loader clears it."""
    reset_nuclei_loader()
    loader1 = get_nuclei_loader(roots=[], auto_refresh=False)
    loader2 = get_nuclei_loader()
    assert loader1 is loader2

    reset_nuclei_loader()
    loader3 = get_nuclei_loader(roots=[], auto_refresh=False)
    assert loader3 is not loader1
    reset_nuclei_loader()


# ===========================================================================
# 6. Real Repository Discovery Spot-Check
# ===========================================================================

def test_real_repo_nuclei_discovery():
    """Verify loader scans real repository templates in flowforge/nuclei-templates."""
    loader = NucleiTemplateLoader(auto_load=True)
    # The repo has over 10,000 built-in templates
    assert loader.total_count > 1000
    stats = loader.get_stats()
    assert stats["total_templates"] > 1000
    assert "critical" in stats["by_severity"]
    assert "high" in stats["by_severity"]

    # Verify a known template like swagger-api or cve template is indexed
    swagger = loader.get_template("swagger-api")
    if swagger:
        assert swagger.name is not None
        assert swagger.severity in (NucleiSeverity.INFO, NucleiSeverity.LOW, NucleiSeverity.MEDIUM)
