"""
Multi-layer and multi-format decoders, encoders, hex dumper, deep JWT inspector,
and recursive auto-decoding pipeline (Requirement R1).
"""

from __future__ import annotations

import base64
import datetime
import html
import json
import re
import time
import urllib.parse
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field


class DecoderType(str, Enum):
    AUTO = "auto"
    BASE64 = "base64"
    BASE64_URL = "base64_url"
    URL = "url"
    HEX = "hex"
    HTML = "html"
    JWT = "jwt"


class EncoderType(str, Enum):
    BASE64 = "base64"
    BASE64_URL = "base64_url"
    URL = "url"
    HEX = "hex"
    HTML = "html"


class DecodeLayer(BaseModel):
    """Represents a single layer step in a multi-layer decoding chain."""
    layer: int
    type: str
    result: str


class JWTInspectionResult(BaseModel):
    """Detailed structural, claims, expiration, and security warning analysis of a JWT."""
    valid: bool
    header: Dict[str, Any] = Field(default_factory=dict)
    payload: Dict[str, Any] = Field(default_factory=dict)
    signature: Optional[str] = None
    algorithm: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    audience: Optional[Any] = None
    expiration: Optional[Union[int, float]] = None
    issued_at: Optional[Union[int, float]] = None
    not_before: Optional[Union[int, float]] = None
    jwt_id: Optional[str] = None
    is_expired: bool = False
    expires_in_seconds: Optional[float] = None
    expired_ago_seconds: Optional[float] = None
    expires_at_iso: Optional[str] = None
    issued_at_iso: Optional[str] = None
    not_before_iso: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    custom_claims: Dict[str, Any] = Field(default_factory=dict)
    security_flags: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class AutoDecodeResult(BaseModel):
    """Result of recursive multi-layer auto-decoding."""
    status: str = "success"
    detected_type: str
    result: str
    is_binary: bool = False
    layers: List[DecodeLayer] = Field(default_factory=list)
    jwt_claims: Optional[JWTInspectionResult] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Base64 Decoders & Encoders
# ---------------------------------------------------------------------------

def decode_base64(data: str, url_safe: bool = False) -> Tuple[str, bool, bytes]:
    """
    Decode standard RFC 4648 or URL-safe Base64 with padding auto-repair.
    Returns (decoded_string, is_binary, raw_bytes).
    """
    cleaned = data.strip()
    if not cleaned:
        return "", False, b""

    # Repair padding
    rem = len(cleaned) % 4
    if rem > 0:
        cleaned += "=" * (4 - rem)

    raw_bytes: bytes
    try:
        if url_safe or "-" in cleaned or "_" in cleaned:
            raw_bytes = base64.urlsafe_b64decode(cleaned.encode("ascii"))
        else:
            raw_bytes = base64.b64decode(cleaned.encode("ascii"))
    except Exception as exc:
        raise ValueError(f"Invalid Base64 payload: {exc}") from exc

    # Check UTF-8 validity
    try:
        decoded_text = raw_bytes.decode("utf-8")
        # Check for non-printable binary control characters (except common whitespace)
        is_binary = any(ord(c) < 32 and c not in "\r\n\t" for c in decoded_text)
        return decoded_text, is_binary, raw_bytes
    except UnicodeDecodeError:
        return raw_bytes.decode("latin-1", errors="replace"), True, raw_bytes


def encode_base64(data: Union[str, bytes], url_safe: bool = False) -> str:
    """Encode string or bytes to standard or URL-safe Base64."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if url_safe:
        return base64.urlsafe_b64encode(data).decode("ascii")
    return base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------
# URL Percent Decoders & Encoders
# ---------------------------------------------------------------------------

def decode_url(data: str, multi_pass: bool = False, max_passes: int = 5) -> Tuple[str, int]:
    """
    Percent-decode URL strings. If multi_pass is True, recursively decodes until
    the string no longer changes or max_passes is reached (e.g. %252F -> %2F -> /).
    Returns (decoded_string, passes_performed).
    """
    if not data:
        return "", 0

    if not multi_pass:
        decoded = urllib.parse.unquote(data)
        return decoded, 1

    current = data
    passes = 0
    while passes < max_passes:
        next_val = urllib.parse.unquote(current)
        if next_val == current:
            break
        current = next_val
        passes += 1

    return current, max(1, passes)


def encode_url(data: str, safe: str = "") -> str:
    """Percent-encode URL string."""
    return urllib.parse.quote(data, safe=safe)


# ---------------------------------------------------------------------------
# Hex Decoders, Encoders & 16-byte Offset Dumper
# ---------------------------------------------------------------------------

_HEX_CLEAN_REGEX = re.compile(r"(?:0x|\\x|[\s,;:])+")


def decode_hex(data: str) -> Tuple[str, bool, bytes]:
    """
    Decode hex string in various formats ('414243', '41 42 43', '\\x41\\x42', '0x41:0x42').
    Returns (decoded_string, is_binary, raw_bytes).
    """
    cleaned = _HEX_CLEAN_REGEX.sub("", data.strip())
    if not cleaned:
        return "", False, b""

    # If odd number of digits, prefix with '0'
    if len(cleaned) % 2 != 0:
        cleaned = "0" + cleaned

    try:
        raw_bytes = bytes.fromhex(cleaned)
    except Exception as exc:
        raise ValueError(f"Invalid Hex string: {exc}") from exc

    try:
        decoded_text = raw_bytes.decode("utf-8")
        is_binary = any(ord(c) < 32 and c not in "\r\n\t" for c in decoded_text)
        return decoded_text, is_binary, raw_bytes
    except UnicodeDecodeError:
        return raw_bytes.decode("latin-1", errors="replace"), True, raw_bytes


def encode_hex(data: Union[str, bytes], separator: str = "") -> str:
    """Encode string or bytes to hexadecimal with optional separator (e.g. ' ', ':')."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    hex_str = data.hex()
    if not separator:
        return hex_str
    # Insert separator every 2 characters
    return separator.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))


def hex_dump(data: Union[str, bytes], bytes_per_line: int = 16) -> str:
    """
    Format data as standard 16-byte offset hex dump with ASCII column.
    Example:
    00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21 00 01 02 03  |Hello World!....|
    """
    if isinstance(data, str):
        raw_bytes = data.encode("utf-8", errors="replace")
    else:
        raw_bytes = data

    if not raw_bytes:
        return "00000000                                                   ||"

    lines: List[str] = []
    total = len(raw_bytes)

    for offset in range(0, total, bytes_per_line):
        chunk = raw_bytes[offset:offset + bytes_per_line]
        hex_parts = [f"{b:02x}" for b in chunk]

        # Format hex column with split at 8 bytes
        if len(hex_parts) > 8:
            first_half = " ".join(hex_parts[:8])
            second_half = " ".join(hex_parts[8:])
            hex_col = f"{first_half}  {second_half}"
        else:
            hex_col = " ".join(hex_parts)

        # Pad hex column to constant width (3 * bytes_per_line + 1 for split)
        # 16 bytes = 8 * 3 - 1 + 2 + 8 * 3 - 1 = 23 + 2 + 23 = 48 chars
        pad_len = 48 if bytes_per_line == 16 else (bytes_per_line * 3)
        hex_col_padded = hex_col.ljust(pad_len)

        # Format ASCII column
        ascii_chars = [chr(b) if 32 <= b <= 126 else "." for b in chunk]
        ascii_col = "".join(ascii_chars)

        line = f"{offset:08x}  {hex_col_padded}  |{ascii_col}|"
        lines.append(line)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML Entity Decoders & Encoders
# ---------------------------------------------------------------------------

def decode_html_entities(data: str) -> str:
    """Decode named, decimal, and hex HTML entities (&quot;, &#34;, &#x22;)."""
    if not data:
        return ""
    return html.unescape(data)


def encode_html_entities(data: str) -> str:
    """Escape string to HTML entities (&, <, >, \", ')."""
    if not data:
        return ""
    return html.escape(data, quote=True)


# ---------------------------------------------------------------------------
# Deep JWT Inspector
# ---------------------------------------------------------------------------

_JWT_REGEX = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


def inspect_jwt(jwt_str: str) -> JWTInspectionResult:
    """
    Parse and deeply inspect 3-segment JWT tokens.
    Extracts header, payload, signature, claims, expiration status, and security warning flags.
    """
    token = jwt_str.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")
    if len(parts) != 3:
        return JWTInspectionResult(
            valid=False,
            error=f"Invalid JWT structure: expected 3 dot-separated segments, got {len(parts)}",
        )

    header_b64, payload_b64, signature_b64 = parts
    security_flags: List[str] = []

    # 1. Decode Header
    header: Dict[str, Any] = {}
    try:
        h_pad = header_b64 + "=" * (-len(header_b64) % 4)
        h_bytes = base64.urlsafe_b64decode(h_pad.encode("ascii"))
        header = json.loads(h_bytes.decode("utf-8"))
        if not isinstance(header, dict):
            return JWTInspectionResult(valid=False, error="JWT header is not a JSON object")
    except Exception as exc:
        return JWTInspectionResult(valid=False, error=f"Failed to decode JWT header: {exc}")

    # 2. Decode Payload
    payload: Dict[str, Any] = {}
    try:
        p_pad = payload_b64 + "=" * (-len(payload_b64) % 4)
        p_bytes = base64.urlsafe_b64decode(p_pad.encode("ascii"))
        payload = json.loads(p_bytes.decode("utf-8"))
        if not isinstance(payload, dict):
            return JWTInspectionResult(valid=False, error="JWT payload is not a JSON object")
    except Exception as exc:
        return JWTInspectionResult(valid=False, error=f"Failed to decode JWT payload: {exc}")

    # 3. Security Warning Checks
    alg = str(header.get("alg", "")).strip()
    alg_lower = alg.lower()

    if alg_lower in ("none", "null", "") or not signature_b64:
        security_flags.append("ALG_NONE_UNSECURED")

    if alg_lower in ("hs256", "hs384", "hs512"):
        security_flags.append("SYMMETRIC_HMAC_ALGORITHM")

    if "jku" in header:
        security_flags.append("JKU_EXTERNAL_HEADER")

    if "x5u" in header:
        security_flags.append("X5U_EXTERNAL_HEADER")

    kid = str(header.get("kid", ""))
    if kid:
        if "../" in kid or "..\\" in kid or "/" in kid or "\\" in kid:
            security_flags.append("KID_DIR_TRAVERSAL")
        if any(c in kid for c in ("'", '"', ";", "--", "/*")):
            security_flags.append("KID_SQL_INJECTION")

    # 4. Standard Claims Extraction & Expiration Analysis
    now = time.time()
    sub = payload.get("sub")
    iss = payload.get("iss")
    aud = payload.get("aud")
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")
    jti = payload.get("jti")

    is_expired = False
    expires_in_sec: Optional[float] = None
    expired_ago_sec: Optional[float] = None
    exp_iso: Optional[str] = None
    iat_iso: Optional[str] = None
    nbf_iso: Optional[str] = None

    if exp is not None and isinstance(exp, (int, float)):
        try:
            exp_iso = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc).isoformat()
            if now >= exp:
                is_expired = True
                expired_ago_sec = round(now - exp, 2)
                security_flags.append("TOKEN_EXPIRED")
            else:
                expires_in_sec = round(exp - now, 2)
        except Exception:
            pass
    else:
        security_flags.append("MISSING_EXPIRATION")

    if iat is not None and isinstance(iat, (int, float)):
        try:
            iat_iso = datetime.datetime.fromtimestamp(iat, tz=datetime.timezone.utc).isoformat()
        except Exception:
            pass

    if nbf is not None and isinstance(nbf, (int, float)):
        try:
            nbf_iso = datetime.datetime.fromtimestamp(nbf, tz=datetime.timezone.utc).isoformat()
            if now < nbf:
                security_flags.append("TOKEN_NOT_YET_VALID")
        except Exception:
            pass

    # 5. Extract Roles and Permissions
    roles: List[str] = []
    for rk in ("role", "roles", "groups", "scope", "scopes", "permissions", "authorities", "isAdmin", "is_admin", "admin"):
        if rk in payload:
            val = payload[rk]
            if isinstance(val, list):
                for v in val:
                    roles.append(f"{rk}:{v}")
            else:
                roles.append(f"{rk}:{val}")

    # 6. Extract Custom Claims (excluding standard reserved claims)
    standard_keys = {"sub", "iss", "aud", "exp", "iat", "nbf", "jti"}
    custom_claims = {k: v for k, v in payload.items() if k not in standard_keys}

    return JWTInspectionResult(
        valid=True,
        header=header,
        payload=payload,
        signature=signature_b64,
        algorithm=alg or None,
        subject=str(sub) if sub is not None else None,
        issuer=str(iss) if iss is not None else None,
        audience=aud,
        expiration=exp if isinstance(exp, (int, float)) else None,
        issued_at=iat if isinstance(iat, (int, float)) else None,
        not_before=nbf if isinstance(nbf, (int, float)) else None,
        jwt_id=str(jti) if jti is not None else None,
        is_expired=is_expired,
        expires_in_seconds=expires_in_sec,
        expired_ago_seconds=expired_ago_sec,
        expires_at_iso=exp_iso,
        issued_at_iso=iat_iso,
        not_before_iso=nbf_iso,
        roles=roles,
        custom_claims=custom_claims,
        security_flags=security_flags,
    )


# ---------------------------------------------------------------------------
# Multi-Layer Recursive Auto-Decoder Pipeline
# ---------------------------------------------------------------------------

_HTML_ENTITY_CHECK = re.compile(r"&(?:[a-zA-Z]+|#\d+|#x[0-9a-fA-F]+);")
_URL_PERCENT_CHECK = re.compile(r"%[0-9a-fA-F]{2}")
_HEX_FORMAT_CHECK = re.compile(r"^(?:(?:0x|\\x)[0-9a-fA-F]{2})+|(?:[0-9a-fA-F]{2}[\s,;:]){2,}[0-9a-fA-F]{2}$")


def _is_probable_jwt(s: str) -> bool:
    """Check if string is a structural 3-segment JWT with valid JSON header."""
    s = s.strip()
    if s.lower().startswith("bearer "):
        s = s[7:].strip()
    if not (s.startswith("ey") and s.count(".") == 2):
        return False
    parts = s.split(".")
    try:
        h_pad = parts[0] + "=" * (-len(parts[0]) % 4)
        h_bytes = base64.urlsafe_b64decode(h_pad.encode("ascii"))
        hdr = json.loads(h_bytes.decode("utf-8"))
        return isinstance(hdr, dict) and ("alg" in hdr or "typ" in hdr)
    except Exception:
        return False


def _is_probable_hex(s: str) -> bool:
    """Check if string is an explicit hex representation."""
    cleaned = s.strip()
    if _HEX_FORMAT_CHECK.match(cleaned):
        return True
    # Pure continuous hex of length >= 6 and even
    if len(cleaned) >= 6 and len(cleaned) % 2 == 0 and re.match(r"^[0-9a-fA-F]+$", cleaned):
        # Don't treat normal English words or numbers as hex unless they decode to printable text
        try:
            b = bytes.fromhex(cleaned)
            decoded = b.decode("utf-8")
            return all(32 <= ord(c) <= 126 or c in "\r\n\t" for c in decoded)
        except Exception:
            return False
    return False


def _is_probable_base64(s: str) -> bool:
    """Check if string is valid Base64 decoding into printable UTF-8."""
    cleaned = s.strip()
    if len(cleaned) < 4:
        return False
    # Must only contain base64 charset
    if not re.match(r"^[A-Za-z0-9+/=_-]+$", cleaned):
        return False
    try:
        rem = len(cleaned) % 4
        if rem > 0:
            cleaned_pad = cleaned + "=" * (4 - rem)
        else:
            cleaned_pad = cleaned

        if "-" in cleaned or "_" in cleaned:
            raw = base64.urlsafe_b64decode(cleaned_pad.encode("ascii"))
        else:
            raw = base64.b64decode(cleaned_pad.encode("ascii"))

        if not raw:
            return False

        decoded = raw.decode("utf-8")
        # Must decode to printable string and not be identical to input
        is_printable = all(32 <= ord(c) <= 126 or c in "\r\n\t" for c in decoded)
        return is_printable and decoded != s
    except Exception:
        return False


def multi_layer_decode(content: str, max_depth: int = 5) -> AutoDecodeResult:
    """
    Recursively detect and decode multi-layered encodings (e.g. Base64 -> URL -> HTML -> JSON).
    Returns complete transformation layer trace, final result, and JWT inspection if applicable.
    """
    if not content:
        return AutoDecodeResult(
            detected_type="plain_text",
            result="",
            layers=[],
        )

    current = content.strip()
    layers: List[DecodeLayer] = []
    initial_detected_type: Optional[str] = None
    jwt_claims: Optional[JWTInspectionResult] = None
    is_binary = False

    for depth in range(1, max_depth + 1):
        # 1. JWT Detection
        if _is_probable_jwt(current):
            jwt_res = inspect_jwt(current)
            if jwt_res.valid:
                if not initial_detected_type:
                    initial_detected_type = "jwt"
                jwt_claims = jwt_res
                pretty_payload = json.dumps(jwt_res.payload, indent=2)
                layers.append(DecodeLayer(layer=depth, type="JWT_PAYLOAD", result=pretty_payload))
                current = pretty_payload
                continue

        # 2. Hex Detection
        if _is_probable_hex(current):
            try:
                dec_str, bin_flag, _ = decode_hex(current)
                if dec_str and dec_str != current:
                    if not initial_detected_type:
                        initial_detected_type = "hex"
                    layers.append(DecodeLayer(layer=depth, type="HEX", result=dec_str))
                    current = dec_str
                    is_binary = is_binary or bin_flag
                    continue
            except Exception:
                pass

        # 3. URL Percent Encoding Detection
        if _URL_PERCENT_CHECK.search(current):
            unquoted = urllib.parse.unquote(current)
            if unquoted != current:
                if not initial_detected_type:
                    initial_detected_type = "url"
                layers.append(DecodeLayer(layer=depth, type="URL", result=unquoted))
                current = unquoted
                continue

        # 4. HTML Entities Detection
        if _HTML_ENTITY_CHECK.search(current):
            unescaped = html.unescape(current)
            if unescaped != current:
                if not initial_detected_type:
                    initial_detected_type = "html"
                layers.append(DecodeLayer(layer=depth, type="HTML", result=unescaped))
                current = unescaped
                continue

        # 5. Base64 / Base64URL Detection
        if _is_probable_base64(current):
            try:
                url_safe = "-" in current or "_" in current
                dec_str, bin_flag, _ = decode_base64(current, url_safe=url_safe)
                if dec_str and dec_str != current:
                    b64_type = "BASE64_URL" if url_safe else "BASE64"
                    if not initial_detected_type:
                        initial_detected_type = b64_type.lower()
                    layers.append(DecodeLayer(layer=depth, type=b64_type, result=dec_str))
                    current = dec_str
                    is_binary = is_binary or bin_flag
                    continue
            except Exception:
                pass

        # No further encoding detected
        break

    if not initial_detected_type:
        initial_detected_type = "plain_text"

    return AutoDecodeResult(
        status="success",
        detected_type=initial_detected_type,
        result=current,
        is_binary=is_binary,
        layers=layers,
        jwt_claims=jwt_claims,
    )


# ---------------------------------------------------------------------------
# General Dispatchers
# ---------------------------------------------------------------------------

def decode_content(
    content: str,
    decoder_type: Union[DecoderType, str] = DecoderType.AUTO,
    multi_pass: bool = False,
    max_depth: int = 5,
) -> AutoDecodeResult:
    """Dispatch decoding request based on explicit decoder type or auto-detection."""
    d_type = str(decoder_type).lower()

    if d_type in ("auto", "all"):
        return multi_layer_decode(content, max_depth=max_depth)

    if d_type in ("base64", "b64"):
        try:
            res, is_bin, _ = decode_base64(content, url_safe=False)
            return AutoDecodeResult(
                detected_type="base64",
                result=res,
                is_binary=is_bin,
                layers=[DecodeLayer(layer=1, type="BASE64", result=res)],
            )
        except Exception as exc:
            return AutoDecodeResult(
                status="error",
                detected_type="base64",
                result=content,
                error=str(exc),
            )

    if d_type in ("base64_url", "b64url", "base64url"):
        try:
            res, is_bin, _ = decode_base64(content, url_safe=True)
            return AutoDecodeResult(
                detected_type="base64_url",
                result=res,
                is_binary=is_bin,
                layers=[DecodeLayer(layer=1, type="BASE64_URL", result=res)],
            )
        except Exception as exc:
            return AutoDecodeResult(
                status="error",
                detected_type="base64_url",
                result=content,
                error=str(exc),
            )

    if d_type in ("url", "percent", "uri"):
        res, passes = decode_url(content, multi_pass=multi_pass, max_passes=max_depth)
        layers = [DecodeLayer(layer=1, type="URL", result=res)] if passes > 0 else []
        return AutoDecodeResult(
            detected_type="url",
            result=res,
            layers=layers,
        )

    if d_type in ("hex", "hexadecimal"):
        try:
            res, is_bin, _ = decode_hex(content)
            return AutoDecodeResult(
                detected_type="hex",
                result=res,
                is_binary=is_bin,
                layers=[DecodeLayer(layer=1, type="HEX", result=res)],
            )
        except Exception as exc:
            return AutoDecodeResult(
                status="error",
                detected_type="hex",
                result=content,
                error=str(exc),
            )

    if d_type in ("html", "html_entities", "entities"):
        res = decode_html_entities(content)
        return AutoDecodeResult(
            detected_type="html",
            result=res,
            layers=[DecodeLayer(layer=1, type="HTML", result=res)],
        )

    if d_type in ("jwt", "jwt_token"):
        jwt_res = inspect_jwt(content)
        if jwt_res.valid:
            pretty_payload = json.dumps(jwt_res.payload, indent=2)
            return AutoDecodeResult(
                detected_type="jwt",
                result=pretty_payload,
                layers=[DecodeLayer(layer=1, type="JWT_PAYLOAD", result=pretty_payload)],
                jwt_claims=jwt_res,
            )
        return AutoDecodeResult(
            status="error",
            detected_type="jwt",
            result=content,
            error=jwt_res.error or "Invalid JWT structure",
        )

    # Fallback to auto
    return multi_layer_decode(content, max_depth=max_depth)


def encode_content(
    content: str,
    encoder_type: Union[EncoderType, str] = EncoderType.BASE64,
    hex_separator: str = "",
) -> str:
    """Dispatch encoding request for given encoder type."""
    e_type = str(encoder_type).lower()

    if e_type in ("base64", "b64"):
        return encode_base64(content, url_safe=False)

    if e_type in ("base64_url", "b64url", "base64url"):
        return encode_base64(content, url_safe=True)

    if e_type in ("url", "uri", "percent"):
        return encode_url(content)

    if e_type in ("hex", "hexadecimal"):
        return encode_hex(content, separator=hex_separator)

    if e_type in ("html", "html_entities", "entities"):
        return encode_html_entities(content)

    raise ValueError(f"Unsupported encoder type: {encoder_type}")
