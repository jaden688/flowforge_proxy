"""
Synthetic Traffic Generator for FlowForge Automated Verification (Requirement R4).
Replays deterministic security scenarios (reflections, auth anomalies, IDOR patterns,
state mutations, and boundary cases) through the proxy or directly against the reference target.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
import httpx


class SyntheticTrafficGenerator:
    """Replays controlled traffic scenarios through proxy or direct target."""

    def __init__(
        self,
        target_url: str = "http://127.0.0.1:8081",
        proxy_url: Optional[str] = None,
        timeout: float = 10.0
    ):
        self.target_url = target_url.rstrip("/")
        self.proxy_url = proxy_url
        self.timeout = timeout
        
        # Configure httpx client with proxy if supplied
        client_kwargs: Dict[str, Any] = {
            "timeout": self.timeout,
            "verify": False,  # Allow proxy self-signed root CA
            "follow_redirects": False
        }
        if self.proxy_url:
            client_kwargs["proxy"] = self.proxy_url

        self.client = httpx.AsyncClient(**client_kwargs)

    async def scenario_reflection_traffic(self) -> Dict[str, Any]:
        """Sends requests with reflected query parameters, JSON fields, and headers."""
        res_html = await self.client.get(
            f"{self.target_url}/reflect/html",
            params={"q": "ReflectMeXSS_Value", "attr": "QuotedAttrValue_123", "script": "ScriptInjectionPayload"}
        )
        res_json = await self.client.post(
            f"{self.target_url}/reflect/json",
            json={"user": "AliceSecurity", "bio": "Senior Pentester", "notes": "JSONReflectedToken"}
        )
        res_header = await self.client.get(
            f"{self.target_url}/reflect/header",
            headers={"X-Custom-Tracking": "TRACKING_TOKEN_ABC123"}
        )
        return {
            "html_status": res_html.status_code,
            "html_body": res_html.text,
            "json_status": res_json.status_code,
            "json_body": res_json.json(),
            "header_status": res_header.status_code,
            "header_echo": res_header.headers.get("X-Echoed-Tracking"),
        }

    async def scenario_auth_and_entropy_traffic(self) -> Dict[str, Any]:
        """Sends authentication requests returning high-entropy tokens and secrets."""
        res_login = await self.client.post(
            f"{self.target_url}/auth/login",
            json={"username": "admin", "password": "SuperSecretPassword123!"}
        )
        login_data = res_login.json()
        token = login_data.get("token")
        
        # Call protected endpoint WITH token
        res_auth = await self.client.get(
            f"{self.target_url}/auth/protected",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Call protected endpoint WITHOUT token (unauthenticated sensitive access anomaly)
        res_unauth = await self.client.get(
            f"{self.target_url}/auth/protected"
        )
        
        return {
            "token": token,
            "api_key": login_data.get("api_key"),
            "aws_key": login_data.get("aws_key_id"),
            "auth_status": res_auth.status_code,
            "auth_data": res_auth.json(),
            "unauth_status": res_unauth.status_code,
            "unauth_data": res_unauth.json(),
        }

    async def scenario_idor_and_clustering_traffic(self) -> Dict[str, Any]:
        """Sends sequential IDs, UUIDs, mutation requests, and admin calls."""
        orders_results = []
        for order_id in [1001, 1002, 1003]:
            r = await self.client.get(f"{self.target_url}/orders/{order_id}")
            orders_results.append({"order_id": order_id, "status": r.status_code, "data": r.json()})

        res_uuid = await self.client.get(
            f"{self.target_url}/users/550e8400-e29b-41d4-a716-446655440000"
        )
        res_mutation = await self.client.post(
            f"{self.target_url}/orders/checkout",
            json={"items": [{"id": 1, "qty": 2}], "coupon": "DISCOUNT50"}
        )
        res_admin = await self.client.get(
            f"{self.target_url}/admin/users"
        )

        return {
            "orders": orders_results,
            "uuid_status": res_uuid.status_code,
            "uuid_data": res_uuid.json(),
            "mutation_status": res_mutation.status_code,
            "mutation_data": res_mutation.json(),
            "admin_status": res_admin.status_code,
            "admin_data": res_admin.json(),
        }

    async def scenario_boundary_traffic(self) -> Dict[str, Any]:
        """Sends boundary values: empty payloads, deep JSON nesting, special characters."""
        res_empty = await self.client.post(
            f"{self.target_url}/reflect/json",
            content=b"",
            headers={"Content-Type": "application/json"}
        )
        
        # Deeply nested JSON payload
        nested = {"level1": {"level2": {"level3": {"level4": {"level5": {"value": "deep_leaf"}}}}}}
        res_nested = await self.client.post(
            f"{self.target_url}/reflect/json",
            json=nested
        )

        # Special characters / quotes / null bytes
        res_special = await self.client.get(
            f"{self.target_url}/reflect/html",
            params={"q": "<script>alert(1)</script>", "attr": "value\" onfocus=\"alert(1)"}
        )

        return {
            "empty_status": res_empty.status_code,
            "nested_status": res_nested.status_code,
            "special_status": res_special.status_code,
        }

    async def scenario_burst_traffic(self, count: int = 50, concurrency: int = 10) -> List[int]:
        """Sends a burst of concurrent requests to test async ingestion throughput."""
        semaphore = asyncio.Semaphore(concurrency)

        async def send_single(i: int) -> int:
            async with semaphore:
                try:
                    r = await self.client.get(f"{self.target_url}/health", params={"seq": i})
                    return r.status_code
                except Exception:
                    return -1

        tasks = [send_single(i) for i in range(count)]
        return await asyncio.gather(*tasks)

    async def close(self):
        """Closes the underlying httpx client session."""
        await self.client.aclose()

    async def __aenter__(self) -> "SyntheticTrafficGenerator":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
