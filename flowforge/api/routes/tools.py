"""
REST API endpoints for data decoding, encoding, hex dumping, and deep JWT analysis (Requirement R1).
"""

from __future__ import annotations

import logging
from typing import Optional, Union
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from flowforge.utils.decoders import (
    AutoDecodeResult,
    DecodeLayer,
    DecoderType,
    EncoderType,
    JWTInspectionResult,
    decode_content,
    encode_content,
    hex_dump,
    inspect_jwt,
    multi_layer_decode,
)

logger = logging.getLogger("flowforge.api.routes.tools")

router = APIRouter(prefix="/api/v1/tools", tags=["Tools & Decoders"])


class DecodeRequest(BaseModel):
    content: str = ""
    decoder_type: Union[DecoderType, str] = DecoderType.AUTO
    multi_pass: bool = False
    max_depth: int = Field(default=5, ge=1, le=20)


class EncodeRequest(BaseModel):
    content: str = ""
    encoder_type: Union[EncoderType, str] = EncoderType.BASE64
    hex_separator: str = ""


class EncodeResponse(BaseModel):
    status: str = "success"
    result: str


class HexdumpRequest(BaseModel):
    content: str = ""
    bytes_per_line: int = Field(default=16, ge=4, le=64)


class HexdumpResponse(BaseModel):
    status: str = "success"
    dump: str
    hex_dump: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.hex_dump:
            self.hex_dump = self.dump


class JWTInspectRequest(BaseModel):
    token: str = ""


@router.post("/decode", response_model=AutoDecodeResult)
async def decode_data(req: DecodeRequest) -> AutoDecodeResult:
    """
    Decode input data using specified decoder (auto, base64, url, hex, html, jwt)
    or recursively through the multi-layer pipeline.
    """
    try:
        return decode_content(
            content=req.content,
            decoder_type=req.decoder_type,
            multi_pass=req.multi_pass,
            max_depth=req.max_depth,
        )
    except Exception as exc:
        logger.error("Decode failed: %s", exc)
        return AutoDecodeResult(
            status="error",
            detected_type=str(req.decoder_type),
            result=req.content,
            error=str(exc),
        )


@router.post("/encode", response_model=EncodeResponse)
async def encode_data(req: EncodeRequest) -> EncodeResponse:
    """
    Encode input text to specified format (base64, base64_url, url, hex, html).
    """
    try:
        res = encode_content(
            content=req.content,
            encoder_type=req.encoder_type,
            hex_separator=req.hex_separator,
        )
        return EncodeResponse(status="success", result=res)
    except ValueError as exc:
        logger.warning("Unsupported encoder type or payload error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error("Encode failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encoding failed: {exc}",
        ) from exc


@router.post("/hexdump", response_model=HexdumpResponse)
async def generate_hexdump(req: HexdumpRequest) -> HexdumpResponse:
    """
    Generate standard 16-byte offset hex dump with formatted hex and ASCII columns.
    """
    try:
        dump_str = hex_dump(data=req.content, bytes_per_line=req.bytes_per_line)
        return HexdumpResponse(status="success", dump=dump_str, hex_dump=dump_str)
    except Exception as exc:
        logger.error("Hexdump generation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Hexdump generation failed: {exc}",
        ) from exc


@router.post("/jwt", response_model=JWTInspectionResult)
@router.post("/jwt/inspect", response_model=JWTInspectionResult)
async def inspect_jwt_token(req: JWTInspectRequest) -> JWTInspectionResult:
    """
    Deeply parse and inspect a 3-segment JWT token, returning header, payload,
    signature, claims, expiration status, and security anomaly flags.
    """
    return inspect_jwt(jwt_str=req.token)
