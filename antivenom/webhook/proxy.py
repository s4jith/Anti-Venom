"""Webhook proxy: intercepts embedding API calls and scans chunks before forwarding.

Usage:
    antivenom serve --upstream https://api.openai.com/v1/embeddings --port 8765

Then point your embedding URL at http://localhost:8765 — no other code changes needed.
"""
from __future__ import annotations
import json
from typing import Any

try:
    from fastapi import FastAPI, Request, Response  # type: ignore[import]
    import httpx  # type: ignore[import]
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
    FastAPI = Any  # type: ignore[assignment,misc]

from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.scanner import AntiVenomScanner


def create_proxy_app(
    upstream_url: str,
    config: ScannerConfig | None = None,
    auth_header: str | None = None,
) -> Any:
    """Create a FastAPI ASGI app that proxies requests through Anti-Venom."""
    if not _FASTAPI_AVAILABLE:
        raise ImportError(
            "fastapi and httpx are required for webhook proxy mode. "
            "Install with: pip install antivenom[serve]"
        )

    app = FastAPI(title="Anti-Venom Proxy", version="0.2.0")
    scanner = AntiVenomScanner(config=config)

    @app.post("/{path:path}")
    async def proxy(path: str, request: Request) -> Response:
        body_bytes = await request.body()
        try:
            body = json.loads(body_bytes)
        except json.JSONDecodeError:
            body = {}

        # Extract text inputs from common embedding API formats
        inputs: list[str] = []
        if "input" in body:
            raw = body["input"]
            if isinstance(raw, str):
                inputs = [raw]
            elif isinstance(raw, list):
                inputs = [str(x) for x in raw]
        elif "texts" in body:
            inputs = body["texts"] if isinstance(body["texts"], list) else [body["texts"]]

        # Scan all inputs
        if inputs:
            chunks = [Chunk(text=t, source_id=f"proxy/{path}") for t in inputs]
            results = await scanner.ascan_batch(chunks)
            poisoned = [(i, r) for i, r in enumerate(results) if r.is_poisoned]
            if poisoned:
                details = [
                    {
                        "index": i,
                        "confidence": r.confidence,
                        "severity": r.severity.value,
                        "evidence": [e for lr in r.layer_results for e in lr.evidence][:5],
                    }
                    for i, r in poisoned
                ]
                return Response(
                    content=json.dumps({
                        "error": "antivenom_blocked",
                        "message": f"{len(poisoned)} chunk(s) blocked due to detected prompt injection",
                        "details": details,
                    }),
                    status_code=422,
                    media_type="application/json",
                )

        # Forward clean request to upstream
        headers = dict(request.headers)
        headers.pop("host", None)
        if auth_header:
            headers["Authorization"] = auth_header

        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream_resp = await client.post(
                f"{upstream_url.rstrip('/')}/{path}",
                content=body_bytes,
                headers=headers,
            )

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=dict(upstream_resp.headers),
            media_type=upstream_resp.headers.get("content-type", "application/json"),
        )

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": "0.2.0", "upstream": upstream_url}

    return app
