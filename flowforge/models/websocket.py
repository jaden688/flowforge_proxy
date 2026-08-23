"""
Pydantic data models for WebSocket frame interception and history.
"""

from __future__ import annotations

import time
from typing import Optional
from pydantic import BaseModel, Field


class WebSocketMessageModel(BaseModel):
    """Represents a single intercepted WebSocket message/frame."""
    id: Optional[int] = None
    flow_id: str
    timestamp: float = Field(default_factory=time.time)
    from_client: bool  # True: client -> server, False: server -> client
    opcode: int = 1    # 1=Text, 2=Binary, 8=Close, 9=Ping, 10=Pong
    content_length: int = 0
    content: str       # UTF-8 text or Base64 encoded binary
    is_binary: bool = False

    @property
    def direction_label(self) -> str:
        return "client->server" if self.from_client else "server->client"

    @property
    def opcode_name(self) -> str:
        opcodes = {
            1: "TEXT",
            2: "BINARY",
            8: "CLOSE",
            9: "PING",
            10: "PONG",
        }
        return opcodes.get(self.opcode, f"OPCODE_{self.opcode}")
