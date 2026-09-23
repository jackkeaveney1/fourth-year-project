"""Data-extraction helpers used once an agent has established access.

These operate purely on data already returned by other tools (e.g. an
HTTP response body) — they don't open new network connections themselves,
so they need no extra guardrail checks beyond the allowlist that already
gated the tool call that produced the data.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.models.schemas import ToolResult
from app.tools.base import Tool, ToolSpec


class ExtractRecordsTool(Tool):
    """Pull structured records out of a raw text/JSON blob the agent collected."""

    def __init__(self) -> None:
        self.spec = ToolSpec(
            name="extract_records",
            description=(
                "Parse a blob of text (e.g. an HTTP response body) already "
                "obtained by another tool and count/extract record-like rows."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "raw_text": {"type": "string"},
                    "format": {"type": "string", "enum": ["json", "csv", "html_table"]},
                },
                "required": ["raw_text", "format"],
            },
        )

    def run(self, **kwargs: Any) -> ToolResult:
        raw_text: str = kwargs["raw_text"]
        fmt: str = kwargs["format"]

        try:
            if fmt == "json":
                records = self._extract_json(raw_text)
            elif fmt == "csv":
                records = self._extract_csv(raw_text)
            else:
                records = self._extract_html_table(raw_text)
        except (ValueError, json.JSONDecodeError) as exc:
            return ToolResult(ok=False, output="", error=f"Could not parse {fmt}: {exc}")

        return ToolResult(ok=True, output=f"Extracted {len(records)} record(s)")

    @staticmethod
    def _extract_json(raw_text: str) -> list[Any]:
        data = json.loads(raw_text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    return value
            return [data]
        raise ValueError("JSON payload is not a list or object")

    @staticmethod
    def _extract_csv(raw_text: str) -> list[str]:
        lines = [line for line in raw_text.strip().splitlines() if line.strip()]
        return lines[1:] if len(lines) > 1 else lines

    @staticmethod
    def _extract_html_table(raw_text: str) -> list[str]:
        return re.findall(r"<tr>.*?</tr>", raw_text, flags=re.DOTALL | re.IGNORECASE)
