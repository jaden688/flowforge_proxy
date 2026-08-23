"""
FlowForge API route definitions package.
"""

from flowforge.api.routes.flows import router as flows_router
from flowforge.api.routes.streaming import router as streaming_router
from flowforge.api.routes.ca import router as ca_router
from flowforge.api.routes.proxy import router as proxy_router

__all__ = [
    "flows_router",
    "streaming_router",
    "ca_router",
    "proxy_router",
]
