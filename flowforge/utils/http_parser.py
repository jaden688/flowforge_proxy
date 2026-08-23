"""
HTTP parsing helpers for headers, cookies, MIME types, and wire decoding.
"""

from __future__ import annotations

import base64
import urllib.parse
from typing import Any, Dict, Optional, Tuple


def split_content_type(content_type: Optional[str]) -> Tuple[str, str]:
    """Split 'application/json; charset=utf-8' into ('application/json', 'utf-8')."""
    if not content_type:
        return ("", "utf-8")
    parts = [p.strip() for p in content_type.split(";")]
    mime = parts[0].lower()
    charset = "utf-8"
    for part in parts[1:]:
        if part.lower().startswith("charset="):
            charset = part.split("=", 1)[1].strip().strip('"').strip("'")
            break
    return (mime, charset)


def is_binary_content(data: bytes, content_type: Optional[str] = None) -> bool:
    """Determine whether a payload is binary or text."""
    if not data:
        return False
    if content_type:
        mime, _ = split_content_type(content_type)
        text_prefixes = (
            "text/",
            "application/json",
            "application/xml",
            "application/javascript",
            "application/x-javascript",
            "application/x-www-form-urlencoded",
            "application/graphql",
            "application/xhtml+xml",
            "application/ld+json",
        )
        if any(mime.startswith(prefix) for prefix in text_prefixes):
            return False
        binary_prefixes = (
            "image/",
            "video/",
            "audio/",
            "application/octet-stream",
            "application/pdf",
            "application/zip",
            "application/gzip",
        )
        if any(mime.startswith(prefix) for prefix in binary_prefixes):
            return True

    # Inspect bytes: check for null bytes or excessive non-printable characters
    sample = data[:1024]
    if b"\x00" in sample:
        return True
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
    non_text = sum(1 for byte in sample if byte not in text_chars)
    return (non_text / len(sample)) > 0.30


def decode_body(
    body_bytes: Optional[bytes],
    content_type: Optional[str] = None,
    max_size: int = 5 * 1024 * 1024,
) -> Tuple[Optional[str], bool]:
    """
    Safely decode request/response body bytes.
    Returns: (content_string, is_binary)
    """
    if body_bytes is None:
        return (None, False)
    if len(body_bytes) == 0:
        return ("", False)

    # Truncate if exceeds max size
    data = body_bytes[:max_size]
    _, charset = split_content_type(content_type)
    if is_binary_content(data, content_type):
        return (base64.b64encode(data).decode("ascii"), True)

    try:
        return (data.decode(charset, errors="replace"), False)
    except Exception:
        try:
            return (data.decode("utf-8", errors="replace"), False)
        except Exception:
            return (base64.b64encode(data).decode("ascii"), True)


def parse_cookies(cookie_header: Optional[str]) -> Dict[str, str]:
    """Parse HTTP Cookie header string into key-value dictionary."""
    if not cookie_header:
        return {}
    cookies: Dict[str, str] = {}
    for item in cookie_header.split(";"):
        item = item.strip()
        if "=" in item:
            name, val = item.split("=", 1)
            cookies[name.strip()] = urllib.parse.unquote(val.strip())
    return cookies


def parse_query_params(url_or_query: str) -> Dict[str, Any]:
    """Parse query string or full URL into query params dictionary."""
    if "?" in url_or_query:
        query_str = url_or_query.split("?", 1)[1]
    else:
        query_str = url_or_query

    parsed = urllib.parse.parse_qs(query_str, keep_blank_values=True)
    result: Dict[str, Any] = {}
    for k, v in parsed.items():
        if len(v) == 1:
            result[k] = v[0]
        else:
            result[k] = v
    return result


def format_raw_request(
    method: str,
    path: str,
    http_version: str,
    headers: Dict[str, str],
    body: Optional[str],
    body_is_binary: bool = False,
) -> str:
    """Format an HTTP request into standard raw wire representation."""
    lines = [f"{method} {path} {http_version}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        if body_is_binary:
            lines.append(f"[Binary Body: {len(body)} Base64 chars]")
        else:
            lines.append(body)
    return "\r\n".join(lines)


def format_raw_response(
    http_version: str,
    status_code: Optional[int],
    reason: Optional[str],
    headers: Dict[str, str],
    body: Optional[str],
    body_is_binary: bool = False,
) -> str:
    """Format an HTTP response into standard raw wire representation."""
    status = status_code or 200
    reason_str = reason or "OK"
    lines = [f"{http_version} {status} {reason_str}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        if body_is_binary:
            lines.append(f"[Binary Body: {len(body)} Base64 chars]")
        else:
            lines.append(body)
    return "\r\n".join(lines)
