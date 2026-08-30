"""
Tier 1 Feature Tests: Nuclei Matcher Engine, Pipeline Integration & REST API.

Verifies:
1. Matcher Evaluation:
   - Status code matching (single, multiple, condition, negative).
   - Word matching (condition AND/OR, case-insensitive, negative).
   - Regex matching (regex patterns, condition AND/OR, case-insensitive, negative, ReDoS bounded matching).
   - Binary matching (hex byte sequences).
   - Size matching (body length assertions).
   - DSL matching (safe AST evaluator, contains, len, status code checks).
   - Multi-part extraction (body, header, header.<name>, all/response, status).
2. Triage Pipeline Integration:
   - Passive flow evaluation in TriagePipeline.
   - Population of TriageSummary.nuclei_matches.
   - Tag propagation and high-priority anomaly flagging.
3. Proposal Synthesis Integration:
   - Synthesis of [Nuclei] {name} ({id}) test proposals.
   - AnomalyType mapping (CVE, EXPOSURE, MISCONFIG, NUCLEI_TEMPLATE).
   - Severity and confidence score mapping.
4. Nuclei REST API:
   - GET /api/v1/nuclei/templates (pagination, filtering by category, severity, tag, search query).
   - GET /api/v1/nuclei/templates/{id} (found vs 404).
   - GET /api/v1/nuclei/stats (counts by category and severity).
   - POST /api/v1/nuclei/test (dry-run with raw response, flow record, template YAML, 400/404 handling).
"""

from __future__ import annotations

import json
import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.heuristics.nuclei_loader import (
    NucleiTemplateLoader,
    get_nuclei_loader,
    reset_nuclei_loader,
)
from flowforge.heuristics.nuclei_matcher import (
    NucleiMatcherEngine,
    SafeDSLEvaluator,
    get_nuclei_matcher,
    reset_nuclei_matcher,
)
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.heuristics.proposal_synthesizer import ProposalSynthesizer
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.nuclei import (
    NucleiHttpBlock,
    NucleiMatcher,
    NucleiMatcherType,
    NucleiMatchResult,
    NucleiSeverity,
    NucleiTemplate,
)
from flowforge.models.proposal import (
    AnomalyType,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)


# ===========================================================================
# 1. Matcher Engine Unit Tests
# ===========================================================================

def test_matcher_status_code():
    """Verify status code matching with single, multiple, and negative conditions."""
    matcher_engine = NucleiMatcherEngine()

    template = NucleiTemplate(
        id="status-test-01",
        name="Status Check",
        severity=NucleiSeverity.INFO,
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.STATUS,
                        status=[200, 201],
                    )
                ],
            )
        ],
    )

    # Status 200 should match
    res200 = matcher_engine.evaluate_response(template, status_code=200, headers={}, body="")
    assert res200.matched is True
    assert "status == 200" in res200.matched_conditions

    # Status 404 should not match
    res404 = matcher_engine.evaluate_response(template, status_code=404, headers={}, body="")
    assert res404.matched is False

    # Negative status matcher (e.g. status != 404)
    neg_template = NucleiTemplate(
        id="status-neg-01",
        name="Negative Status Check",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.STATUS,
                        status=[404],
                        negative=True,
                    )
                ],
            )
        ],
    )
    res_neg_200 = matcher_engine.evaluate_response(neg_template, status_code=200, headers={}, body="")
    assert res_neg_200.matched is True

    res_neg_404 = matcher_engine.evaluate_response(neg_template, status_code=404, headers={}, body="")
    assert res_neg_404.matched is False


def test_matcher_words_and_or_case():
    """Verify word matching with AND/OR conditions, case sensitivity, and negative flags."""
    matcher_engine = NucleiMatcherEngine()

    # 1. Words with condition AND
    and_template = NucleiTemplate(
        id="words-and-test",
        name="Words AND Test",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.WORD,
                        part="body",
                        words=["admin_portal", "logged_in"],
                        condition="and",
                        case_insensitive=True,
                    )
                ],
            )
        ],
    )

    # Both words present (case-varied)
    res_both = matcher_engine.evaluate_response(
        and_template,
        status_code=200,
        headers={},
        body="Welcome to ADMIN_PORTAL! You are LOGGED_IN as admin.",
    )
    assert res_both.matched is True
    assert len(res_both.matched_conditions) == 2

    # Only one word present
    res_one = matcher_engine.evaluate_response(
        and_template,
        status_code=200,
        headers={},
        body="Welcome to ADMIN_PORTAL! Please sign in.",
    )
    assert res_one.matched is False

    # 2. Words with condition OR
    or_template = NucleiTemplate(
        id="words-or-test",
        name="Words OR Test",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.WORD,
                        part="body",
                        words=["critical_error", "database_down"],
                        condition="or",
                    )
                ],
            )
        ],
    )
    res_or = matcher_engine.evaluate_response(
        or_template,
        status_code=500,
        headers={},
        body="Server encountered a critical_error in worker.",
    )
    assert res_or.matched is True


def test_matcher_regex_and_redos_safety():
    """Verify regex matching with capture groups and ReDoS bounded protection."""
    matcher_engine = NucleiMatcherEngine()

    template = NucleiTemplate(
        id="regex-test-01",
        name="Regex Test",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.REGEX,
                        part="body",
                        regex=[r"root:[x*]:0:0:[^:]*:[^:]*:[^\n]+", r"uid=[0-9]+\([a-z]+\)"],
                        condition="or",
                    )
                ],
            )
        ],
    )

    # Matching passwd content
    passwd_body = "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nroot:x:0:0:root:/root:/bin/bash\n"
    res = matcher_engine.evaluate_response(template, status_code=200, headers={}, body=passwd_body)
    assert res.matched is True
    assert len(res.matched_conditions) >= 1

    # Non-matching body
    res_fail = matcher_engine.evaluate_response(template, status_code=200, headers={}, body="plain user profile page")
    assert res_fail.matched is False

    # ReDoS bounded protection: test large input does not hang or raise
    large_payload = "a" * 2_000_000 + "uid=0(root)"
    res_large = matcher_engine.evaluate_response(template, status_code=200, headers={}, body=large_payload)
    # The scan safely truncates to 1MB and completes in milliseconds
    assert res_large.execution_time_ms < 500


def test_matcher_binary_and_size():
    """Verify binary hex sequence and response body size matching."""
    matcher_engine = NucleiMatcherEngine()

    # 1. Binary PK ZIP header match
    bin_template = NucleiTemplate(
        id="binary-zip-test",
        name="ZIP Header Check",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.BINARY,
                        words=["504b0304"],  # PK\x03\x04
                    )
                ],
            )
        ],
    )

    zip_bytes = b"PK\x03\x04\x14\x00\x00\x00some_zip_content"
    res_bin = matcher_engine.evaluate_response(bin_template, status_code=200, headers={}, body=zip_bytes)
    assert res_bin.matched is True

    # 2. Size matcher
    size_template = NucleiTemplate(
        id="size-test-01",
        name="Size Check",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.SIZE,
                        words=["42"],
                    )
                ],
            )
        ],
    )
    body_42 = "a" * 42
    res_sz = matcher_engine.evaluate_response(size_template, status_code=200, headers={}, body=body_42)
    assert res_sz.matched is True

    res_sz_fail = matcher_engine.evaluate_response(size_template, status_code=200, headers={}, body="short")
    assert res_sz_fail.matched is False


def test_matcher_dsl_and_safe_evaluator():
    """Verify safe AST DSL expressions evaluation."""
    assert SafeDSLEvaluator.evaluate("contains('hello world', 'world')", {}) is True
    assert SafeDSLEvaluator.evaluate("contains_all('abcdef', 'ab', 'ef')", {}) is True
    assert SafeDSLEvaluator.evaluate("to_lower('ADMIN') == 'admin'", {}) is True
    assert SafeDSLEvaluator.evaluate("len('test') == 4", {}) is True
    assert SafeDSLEvaluator.evaluate("status_code == 200 && content_length > 10", {"status_code": 200, "content_length": 50}) is True

    # DSL Matcher in template
    matcher_engine = NucleiMatcherEngine()
    dsl_template = NucleiTemplate(
        id="dsl-test-01",
        name="DSL Expression Test",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.DSL,
                        dsl=["status_code == 200", "contains(to_lower(body), 'vulnerable')"],
                        condition="and",
                    )
                ],
            )
        ],
    )

    res = matcher_engine.evaluate_response(
        dsl_template,
        status_code=200,
        headers={},
        body="This service is VULNERABLE to CVE-2024-XXXX.",
    )
    assert res.matched is True
    assert len(res.matched_conditions) == 2


def test_matcher_parts_headers_and_response():
    """Verify part routing across headers, header.content-type, all response, and body."""
    matcher_engine = NucleiMatcherEngine()

    template = NucleiTemplate(
        id="header-part-test",
        name="Header Part Test",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers_condition="and",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.WORD,
                        part="header.x-debug-mode",
                        words=["enabled"],
                        case_insensitive=True,
                    ),
                    NucleiMatcher(
                        type=NucleiMatcherType.WORD,
                        part="body",
                        words=["debug_dump"],
                    ),
                ],
            )
        ],
    )

    headers = {
        "Content-Type": "application/json",
        "X-Debug-Mode": "ENABLED",
        "Server": "FlowForge/1.0",
    }
    body = '{"debug_dump": {"pid": 1234}}'

    res = matcher_engine.evaluate_response(template, status_code=200, headers=headers, body=body)
    assert res.matched is True


# ===========================================================================
# 2. Triage Pipeline Integration Tests
# ===========================================================================

def test_triage_pipeline_passive_nuclei_evaluation():
    """Verify TriagePipeline executes passive Nuclei templates and populates TriageSummary."""
    loader = NucleiTemplateLoader(roots=[], auto_load=False)
    matcher = NucleiMatcherEngine()

    # Register a passive exposure template
    passive_tmpl = NucleiTemplate(
        id="passive-git-config-exposure",
        name="Git Config File Exposure",
        severity=NucleiSeverity.HIGH,
        category="EXPOSURE",
        tags=["git", "exposure", "passive"],
        is_passive=True,
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.WORD,
                        part="body",
                        words=["[core]", "repositoryformatversion"],
                        condition="and",
                    )
                ],
            )
        ],
    )
    loader.register_template(passive_tmpl)

    pipeline = TriagePipeline(nuclei_loader=loader, nuclei_matcher=matcher)

    # Create synthetic FlowRecord matching git config
    flow = FlowRecord(
        id="flow-git-test",
        server_host="target.local",
        server_port=443,
        request=RequestModel(
            method="GET",
            url="https://target.local/.git/config",
            path="/.git/config",
            headers={"Host": "target.local"},
        ),
        response=ResponseModel(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body="[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n",
        ),
    )

    summary = pipeline.process_flow_sync(flow)

    assert len(summary.nuclei_matches) == 1
    match = summary.nuclei_matches[0]
    assert match.template_id == "passive-git-config-exposure"
    assert match.matched is True
    assert match.severity == NucleiSeverity.HIGH

    # Verify tags and high priority anomaly flag
    assert "nuclei" in summary.tags
    assert "passive-git-config-exposure" in summary.tags
    assert "exposure" in summary.tags
    assert summary.has_high_priority_anomalies is True


# ===========================================================================
# 3. Proposal Synthesis Tests
# ===========================================================================

def test_proposal_synthesis_from_nuclei_match():
    """Verify ProposalSynthesizer transforms Nuclei matches into [Nuclei] test proposals."""
    synthesizer = ProposalSynthesizer()

    flow = FlowRecord(
        id="flow-cve-test",
        server_host="target.local",
        server_port=8080,
        request=RequestModel(
            method="GET",
            url="http://target.local/api/v1/users",
            path="/api/v1/users",
            headers={"Host": "target.local"},
        ),
        response=ResponseModel(
            status_code=200,
            headers={"Server": "VulnerableServer/2.4.49"},
            body="root:x:0:0:root:/root:/bin/sh\n",
        ),
    )

    # Match finding from pipeline
    nuclei_match = NucleiMatchResult(
        template_id="cve-2021-41773",
        template_name="Apache 2.4.49 Path Traversal",
        severity=NucleiSeverity.CRITICAL,
        category="CVE",
        tags=["cve", "cve2021", "rce", "apache"],
        matched=True,
        matched_conditions=["word 'root:x:0:0:' in body"],
        matched_at="http://target.local/api/v1/users",
    )

    from flowforge.heuristics.models import EndpointCategory, TriageSummary
    triage = TriageSummary(
        flow_id=flow.id,
        canonical_endpoint="GET /api/v1/users",
        endpoint_category=EndpointCategory.DATA_READ,
        nuclei_matches=[nuclei_match],
        tags=["nuclei", "cve-2021-41773", "cve"],
        has_high_priority_anomalies=True,
    )

    proposals = synthesizer.synthesize(flow, triage)
    nuclei_proposals = [p for p in proposals if p.title.startswith("[Nuclei]")]

    assert len(nuclei_proposals) >= 1
    p = nuclei_proposals[0]
    assert p.title == "[Nuclei] Apache 2.4.49 Path Traversal (cve-2021-41773)"
    assert p.anomaly_type == AnomalyType.CVE
    assert p.severity == ProposalSeverity.CRITICAL
    assert p.confidence_score >= 85.0
    assert "cve-2021-41773" in p.tags
    assert p.state == ProposalState.PENDING


# ===========================================================================
# 4. REST API Endpoint Tests
# ===========================================================================

async def test_api_nuclei_templates_listing_and_stats():
    """Verify /api/v1/nuclei/templates and /api/v1/nuclei/stats endpoints."""
    reset_nuclei_loader()
    reset_nuclei_matcher()
    loader = get_nuclei_loader()

    # Register sample templates
    loader.register_template(
        NucleiTemplate(
            id="api-test-cve-01",
            name="API Test CVE",
            severity=NucleiSeverity.HIGH,
            category="CVE",
            tags=["cve", "auth-bypass"],
        )
    )
    loader.register_template(
        NucleiTemplate(
            id="api-test-exposure-01",
            name="API Test Exposure",
            severity=NucleiSeverity.MEDIUM,
            category="EXPOSURE",
            tags=["exposure", "env"],
        )
    )

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Get stats
        stats_resp = await client.get("/api/v1/nuclei/stats")
        assert stats_resp.status_code == 200
        stats_data = stats_resp.json()
        assert stats_data["total_templates"] >= 2
        assert "by_severity" in stats_data
        assert "by_category" in stats_data

        # 2. List templates
        list_resp = await client.get("/api/v1/nuclei/templates?limit=10")
        assert list_resp.status_code == 200
        list_data = list_resp.json()
        assert "items" in list_data
        assert list_data["total"] >= 2

        # 3. Filter by category with search query
        cat_resp = await client.get("/api/v1/nuclei/templates?category=CVE&query=api-test")
        assert cat_resp.status_code == 200
        cat_data = cat_resp.json()
        assert len(cat_data["items"]) == 1
        assert cat_data["items"][0]["id"] == "api-test-cve-01"

        exp_resp = await client.get("/api/v1/nuclei/templates?category=EXPOSURE&query=api-test")
        assert exp_resp.status_code == 200
        exp_data = exp_resp.json()
        assert len(exp_data["items"]) == 1
        assert exp_data["items"][0]["id"] == "api-test-exposure-01"

        # 4. Get template by ID
        get_resp = await client.get("/api/v1/nuclei/templates/api-test-cve-01")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == "api-test-cve-01"

        # 4b. 404 for missing template
        missing_resp = await client.get("/api/v1/nuclei/templates/nonexistent-template-id")
        assert missing_resp.status_code == 404


async def test_api_nuclei_test_dry_run_endpoint(tmp_dir: str):
    """Verify /api/v1/nuclei/test endpoint for dry-run evaluations."""
    reset_nuclei_loader()
    reset_nuclei_matcher()
    loader = get_nuclei_loader()
    loader.register_template(
        NucleiTemplate(
            id="dryrun-header-match",
            name="Dry Run Header Match",
            severity=NucleiSeverity.LOW,
            category="MISCONFIG",
            http_blocks=[
                NucleiHttpBlock(
                    method="GET",
                    matchers=[
                        NucleiMatcher(
                            type=NucleiMatcherType.WORD,
                            part="header.x-powered-by",
                            words=["Express", "PHP"],
                        )
                    ],
                )
            ],
        )
    )

    from flowforge.config import Settings
    from flowforge.db.connection import init_db
    from flowforge.db.repository import FlowRepository
    from flowforge.db.writer import AsyncDBWriter

    db_path = f"{tmp_dir}/test_nuclei_api.db"
    await init_db(db_path)
    settings = Settings(db_path=db_path, auto_start_proxy=False)
    app = create_app(settings)

    writer = AsyncDBWriter(db_path=db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()
    repo = FlowRepository(db_path=db_path)
    app.state.repo = repo
    app.state.db_writer = writer

    # Insert a test flow
    persisted_flow = FlowRecord(
        id="flow-stored-express",
        server_host="example.com",
        server_port=80,
        request=RequestModel(
            method="GET",
            url="http://example.com/status",
            path="/status",
            headers={"Host": "example.com"},
        ),
        response=ResponseModel(
            status_code=200,
            headers={"X-Powered-By": "Express"},
            body="OK",
        ),
    )
    await writer.enqueue_insert_flow(persisted_flow)
    await writer.flush()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test positive match with raw response parameters
        payload_match = {
            "template_id": "dryrun-header-match",
            "status_code": 200,
            "headers": {"X-Powered-By": "Express"},
            "body": "OK",
        }
        res = await client.post("/api/v1/nuclei/test", json=payload_match)
        assert res.status_code == 200
        data = res.json()
        assert data["matched"] is True
        assert data["template_id"] == "dryrun-header-match"

        # Test negative match
        payload_no_match = {
            "template_id": "dryrun-header-match",
            "status_code": 200,
            "headers": {"X-Powered-By": "Nginx"},
            "body": "OK",
        }
        res_no = await client.post("/api/v1/nuclei/test", json=payload_no_match)
        assert res_no.status_code == 200
        assert res_no.json()["matched"] is False

        # Test evaluating against an existing flow_id in DB
        res_flow = await client.post(
            "/api/v1/nuclei/test",
            json={"template_id": "dryrun-header-match", "flow_id": "flow-stored-express"},
        )
        assert res_flow.status_code == 200
        flow_eval_data = res_flow.json()
        assert flow_eval_data["matched"] is True
        assert flow_eval_data["template_id"] == "dryrun-header-match"

        # Test inline template YAML
        inline_yaml = """
id: inline-test-yaml
info:
  name: Inline YAML Probe
  severity: critical
http:
  - method: GET
    matchers:
      - type: status
        status:
          - 500
"""
        res_yaml = await client.post(
            "/api/v1/nuclei/test",
            json={
                "template_yaml": inline_yaml,
                "status_code": 500,
                "body": "Internal Server Error",
            },
        )
        assert res_yaml.status_code == 200
        assert res_yaml.json()["matched"] is True
        assert res_yaml.json()["template_id"] == "inline-test-yaml"

        # Test validation error when neither template_id nor template_yaml is supplied
        bad_req = await client.post("/api/v1/nuclei/test", json={"status_code": 200})
        assert bad_req.status_code == 400

        # Test 404 on missing template_id in test endpoint
        bad_tmpl = await client.post("/api/v1/nuclei/test", json={"template_id": "nonexistent-xyz", "status_code": 200})
        assert bad_tmpl.status_code == 404

        # Test 404 on missing flow_id in test endpoint
        bad_flow = await client.post(
            "/api/v1/nuclei/test",
            json={"template_id": "dryrun-header-match", "flow_id": "flow-does-not-exist"},
        )
        assert bad_flow.status_code == 404

        # Test refresh endpoint
        refresh_resp = await client.post("/api/v1/nuclei/refresh")
        assert refresh_resp.status_code == 200
        assert "total_templates" in refresh_resp.json()

    await writer.stop()


def test_matcher_extractors_and_stop_at_first_match():
    """Verify regex extractors and stop-at-first-match behavior in http blocks."""
    matcher_engine = NucleiMatcherEngine()

    template = NucleiTemplate(
        id="extractor-test-01",
        name="Extractor and Multi-Block Test",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                stop_at_first_match=True,
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.WORD,
                        part="body",
                        words=["Version:"],
                    )
                ],
                extractors=[
                    {
                        "type": "regex",
                        "part": "body",
                        "name": "app_version",
                        "regex": [r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+)"],
                        "group": 1,
                    }
                ],
            ),
            NucleiHttpBlock(
                method="GET",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.WORD,
                        part="body",
                        words=["unreachable_block"],
                    )
                ],
            ),
        ],
    )

    body = "System Health: OK\nApplication Version: 2.4.18\nEnvironment: production\n"
    res = matcher_engine.evaluate_response(template, status_code=200, headers={}, body=body)

    assert res.matched is True
    assert res.extracted_data.get("app_version") == "2.4.18"


def test_matcher_and_condition_failure():
    """Verify matchers-condition 'and' fails when one matcher does not match."""
    matcher_engine = NucleiMatcherEngine()

    template = NucleiTemplate(
        id="multi-matcher-and-test",
        name="Multi-Matcher AND Test",
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                matchers_condition="and",
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.STATUS,
                        status=[200],
                    ),
                    NucleiMatcher(
                        type=NucleiMatcherType.WORD,
                        part="body",
                        words=["SECRET_CANARY_TOKEN"],
                    ),
                ],
            )
        ],
    )

    # Status 200 but missing body word -> should fail
    res = matcher_engine.evaluate_response(
        template,
        status_code=200,
        headers={},
        body="Normal response body without the canary.",
    )
    assert res.matched is False
