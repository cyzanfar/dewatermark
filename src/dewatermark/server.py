"""Small, dependency-free local HTTP/OpenAPI server."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import analyze, capabilities, remove, sanitize

MAX_BODY_BYTES = 2_000_000


def process_request(path: str, payload: dict[str, Any]) -> object:
    """Process an API operation without transport concerns (also useful to embedders)."""
    text = payload["text"]
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    if path == "/analyze":
        return analyze(text)
    if path == "/sanitize":
        cleaned = sanitize(text, profile=payload.get("profile", "safe"))
        return {"cleaned_text": cleaned, "changed": cleaned != text}
    if path == "/remove":
        return remove(text, mode=payload.get("mode", "auto")).to_dict()
    raise KeyError(path)


def openapi_schema() -> dict[str, Any]:
    operations = {}
    for route, summary in (
        ("/analyze", "Inspect text"),
        ("/sanitize", "Remove Unicode artifacts"),
        ("/remove", "Run removal pipeline"),
    ):
        operations[route] = {
            "post": {
                "summary": summary,
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["text"],
                                "properties": {"text": {"type": "string"}},
                            }
                        }
                    },
                },
                "responses": {"200": {"description": "Success"}},
            }
        }
    return {
        "openapi": "3.1.0",
        "info": {"title": "dewatermark API", "version": "1.0"},
        "paths": {
            "/health": {"get": {"responses": {"200": {"description": "Healthy"}}}},
            "/capabilities": {"get": {"responses": {"200": {"description": "Capabilities"}}}},
            **operations,
        },
    }


class DewatermarkHandler(BaseHTTPRequestHandler):
    api_key: str | None = None

    def log_message(self, format: str, *args: object) -> None:
        # Deliberately omit request paths and bodies: source text can be sensitive.
        return

    def _send(self, status: int, value: object) -> None:
        body = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return not self.api_key or self.headers.get("Authorization") == f"Bearer {self.api_key}"

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        routes = {
            "/health": {"status": "ok"},
            "/capabilities": capabilities(),
            "/openapi.json": openapi_schema(),
        }
        self._send(200, routes[self.path]) if self.path in routes else self._send(
            404, {"error": "not found"}
        )

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY_BYTES:
                raise ValueError("request body is empty or too large")
            payload = json.loads(self.rfile.read(length))
            if self.path not in {"/analyze", "/sanitize", "/remove"}:
                self._send(404, {"error": "not found"})
                return
            result = process_request(self.path, payload)
            self._send(200, result)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": type(exc).__name__})


def serve(
    host: str = "127.0.0.1", port: int = 8765, api_key_env: str = "DEWATERMARK_SERVER_API_KEY"
) -> None:
    """Serve forever. Non-loopback binds require a configured API key."""
    api_key = os.environ.get(api_key_env)
    if host not in {"127.0.0.1", "localhost", "::1"} and not api_key:
        raise ValueError(f"non-loopback server requires {api_key_env}")
    handler = type("ConfiguredHandler", (DewatermarkHandler,), {"api_key": api_key})
    ThreadingHTTPServer((host, port), handler).serve_forever()
