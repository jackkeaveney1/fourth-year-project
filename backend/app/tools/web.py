"""HTTP tools for interacting with web services inside the target range."""

from __future__ import annotations

from typing import Any

import requests

from app.guardrails.policy import GuardrailViolation, NetworkAllowlist
from app.models.schemas import ToolResult
from app.tools.base import Tool, ToolSpec

MAX_RESPONSE_CHARS = 4000


class HttpRequestTool(Tool):
    """Issue an HTTP request, confined to the range's network allowlist."""

    def __init__(self, network: NetworkAllowlist, timeout_s: float = 5.0) -> None:
        self.network = network
        self.timeout_s = timeout_s
        self.spec = ToolSpec(
            name="http_request",
            description="Send an HTTP request to a service inside the target range.",
            parameters={
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "url": {"type": "string", "description": "URL of an in-range service"},
                    "headers": {"type": "object"},
                    "data": {"type": "object", "description": "Form fields or JSON body"},
                },
                "required": ["method", "url"],
            },
        )

    def run(self, **kwargs: Any) -> ToolResult:
        method: str = kwargs["method"].upper()
        url: str = kwargs["url"]
        headers: dict[str, str] | None = kwargs.get("headers")
        data: dict[str, Any] | None = kwargs.get("data")

        try:
            self.network.check_url(url)
        except GuardrailViolation as exc:
            return ToolResult(ok=False, output="", error=str(exc))

        try:
            response = requests.request(
                method, url, headers=headers, data=data, timeout=self.timeout_s
            )
        except requests.RequestException as exc:
            return ToolResult(ok=False, output="", error=f"Request failed: {exc}")

        body = response.text[:MAX_RESPONSE_CHARS]
        summary = f"HTTP {response.status_code}\n{body}"
        return ToolResult(ok=response.ok, output=summary)
