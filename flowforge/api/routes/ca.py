"""
TLS Certificate Authority export and download endpoints.
"""

from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter, Response
from fastapi.responses import HTMLResponse

from flowforge.core.ca import CertificateManager

router = APIRouter(tags=["Certificate Authority"])


def get_cert_manager() -> CertificateManager:
    """Dependency provider for CertificateManager."""
    return CertificateManager()


@router.get("/api/v1/ca/cert.pem")
async def download_ca_pem() -> Response:
    """Download FlowForge Root CA Certificate in PEM format."""
    mgr = get_cert_manager()
    pem_str = mgr.get_ca_cert_pem()
    return Response(
        content=pem_str,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="flowforge-ca-cert.pem"'},
    )


@router.get("/api/v1/ca/cert.crt")
@router.get("/api/v1/ca/cert.cer")
async def download_ca_crt() -> Response:
    """Download FlowForge Root CA Certificate in DER / CRT binary format."""
    mgr = get_cert_manager()
    crt_bytes = mgr.get_ca_cert_bytes()
    return Response(
        content=crt_bytes,
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": 'attachment; filename="flowforge-ca-cert.crt"'},
    )


@router.get("/api/v1/ca/info")
async def get_ca_info() -> Dict[str, Any]:
    """Retrieve metadata and SHA256 fingerprint of the active Root CA."""
    mgr = get_cert_manager()
    return mgr.get_ca_info()


@router.get("/cert", response_class=HTMLResponse)
@router.get("/ca", response_class=HTMLResponse)
async def ca_landing_page() -> HTMLResponse:
    """Interception landing page for downloading the Root CA certificate in browsers."""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FlowForge CA Certificate Installation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2.5rem; max-width: 540px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }
        h1 { font-size: 1.5rem; font-weight: 700; color: #38bdf8; margin-top: 0; }
        p { color: #94a3b8; line-height: 1.6; font-size: 0.95rem; }
        .btn-group { display: flex; gap: 1rem; margin-top: 1.5rem; }
        .btn { display: inline-flex; align-items: center; justify-content: center; padding: 0.75rem 1.25rem; border-radius: 8px; font-weight: 600; text-decoration: none; transition: background 0.15s; font-size: 0.9rem; }
        .btn-primary { background: #0284c7; color: white; }
        .btn-primary:hover { background: #0369a1; }
        .btn-secondary { background: #334155; color: #e2e8f0; }
        .btn-secondary:hover { background: #475569; }
        .badge { background: #0369a1; color: #bae6fd; font-size: 0.75rem; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600; text-transform: uppercase; }
    </style>
</head>
<body>
    <div class="card">
        <span class="badge">Security Testing CA</span>
        <h1>FlowForge Intercepting CA</h1>
        <p>To enable HTTPS decryption and dynamic inspection in your browser or operating system, install and trust the FlowForge Root Certificate Authority.</p>
        <div class="btn-group">
            <a href="/api/v1/ca/cert.pem" class="btn btn-primary">Download PEM Certificate</a>
            <a href="/api/v1/ca/cert.crt" class="btn btn-secondary">Download CRT / DER Certificate</a>
        </div>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html_content)
