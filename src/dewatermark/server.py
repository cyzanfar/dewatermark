"""Small, dependency-free local HTTP/OpenAPI server."""

from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterable, cast
from urllib.parse import urlparse

from . import analyze, capabilities, remove, sanitize
from .assurance_api import (
    ConsentRequiredError,
    PlanMismatchError,
    apply_plan,
    create_plan,
    inspect_text,
    local_only_config,
    verify_text,
)
from .models import RemovalMode, SanitizeProfile

MAX_BODY_BYTES = 2_000_000
_POST_ROUTES = {"/analyze", "/inspect", "/sanitize", "/remove", "/plan", "/apply", "/verify"}
_MODES = {"auto", "sanitize", "paraphrase", "full", "sira", "bias_inversion", "adversarial"}
_REQUEST_FIELDS = {
    "/analyze": frozenset({"text"}),
    "/inspect": frozenset({"text", "detector"}),
    "/sanitize": frozenset({"text", "profile"}),
    "/remove": frozenset({"text", "mode"}),
    "/plan": frozenset(
        {
            "text",
            "mode",
            "detector",
            "options",
            "allow_network",
            "allow_model_download",
            "require_verified",
        }
    ),
    "/apply": frozenset(
        {
            "text",
            "plan_digest",
            "mode",
            "detector",
            "options",
            "require_verified",
            "consent",
        }
    ),
    "/verify": frozenset({"source_text", "candidate_text", "detector"}),
}


def _is_json_content_type(value: str) -> bool:
    return value.split(";", 1)[0].strip().lower() == "application/json"


def _bool(payload: dict[str, Any], name: str, default: bool = False) -> bool:
    value = payload.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _closed_object(payload: dict[str, Any], allowed: Iterable[str]) -> None:
    allowed_fields = allowed if isinstance(allowed, (set, frozenset)) else frozenset(allowed)
    for key in payload:
        if type(key) is not str or key not in allowed_fields:
            raise ValueError("request contains unsupported fields")


def _mapping(
    payload: dict[str, Any], name: str, *, allowed: Iterable[str] | None = None
) -> dict[str, Any]:
    value = payload.get(name, {})
    if type(value) is not dict:
        raise ValueError(f"{name} must be an object")
    if allowed is not None:
        _closed_object(value, allowed)
    return value


def _mode(payload: dict[str, Any], default: str = "auto") -> RemovalMode:
    value = payload.get("mode", default)
    if not isinstance(value, str) or value not in _MODES:
        raise ValueError("mode is not supported")
    return cast(RemovalMode, value)


def _profile(payload: dict[str, Any]) -> SanitizeProfile:
    value = payload.get("profile", "safe")
    if not isinstance(value, str) or value not in {"safe", "aggressive"}:
        raise ValueError("profile is not supported")
    return cast(SanitizeProfile, value)


def _text(payload: dict[str, Any], name: str = "text", *, nonempty: bool = False) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if nonempty and not value:
        raise ValueError(f"{name} must not be empty")
    return value


def process_request(path: str, payload: dict[str, Any]) -> object:
    """Process an API operation without transport concerns (also useful to embedders)."""
    if type(payload) is not dict:
        raise ValueError("request body must be a JSON object")
    allowed = _REQUEST_FIELDS.get(path)
    if allowed is None:
        raise KeyError(path)
    _closed_object(payload, allowed)
    if path == "/analyze":  # legacy alias with its original response shape
        return analyze(_text(payload))
    if path == "/inspect":
        detector = payload.get("detector", "unicode")
        if not isinstance(detector, str):
            raise ValueError("detector must be a string")
        return inspect_text(_text(payload), detector)
    if path == "/sanitize":
        text = _text(payload)
        cleaned = sanitize(text, profile=_profile(payload))
        return {"cleaned_text": cleaned, "changed": cleaned != text}
    if path == "/remove":  # compatibility endpoint; use /plan + /apply for agents
        return remove(_text(payload), mode=_mode(payload), config=local_only_config()).to_dict()
    if path == "/plan":
        return create_plan(
            _text(payload, nonempty=True),
            mode=_mode(payload),
            detector=payload.get("detector", "unicode"),
            allow_network=_bool(payload, "allow_network"),
            allow_model_download=_bool(payload, "allow_model_download"),
            require_verified=_bool(payload, "require_verified"),
            options=_mapping(payload, "options"),
        )
    if path == "/apply":
        consent = _mapping(
            payload,
            "consent",
            allowed=("transformation", "network", "model_download"),
        )
        return apply_plan(
            _text(payload, nonempty=True),
            _text(payload, "plan_digest", nonempty=True),
            mode=_mode(payload),
            detector=payload.get("detector", "unicode"),
            consent=_bool(consent, "transformation"),
            allow_network=_bool(consent, "network"),
            allow_model_download=_bool(consent, "model_download"),
            require_verified=_bool(payload, "require_verified"),
            options=_mapping(payload, "options"),
        )
    if path == "/verify":
        detector = payload.get("detector", "unicode-artifacts-v1")
        if not isinstance(detector, str):
            raise ValueError("detector must be a string")
        return verify_text(
            _text(payload, "source_text"),
            _text(payload, "candidate_text"),
            detector=detector,
        )
    raise KeyError(path)


def _request_schema(*, required: Iterable[str], properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "required": list(required),
        "properties": properties,
        "additionalProperties": False,
    }


def _operation(summary: str, schema: dict[str, Any], operation_id: str) -> dict[str, Any]:
    response_name = {
        "inspectText": "InspectResponse",
        "analyzeText": "AnalysisResponse",
        "sanitizeText": "SanitizeResponse",
        "planTransformation": "PlanResponse",
        "applyTransformation": "ApplyResponse",
        "verifyTransformation": "VerifyResponse",
        "removeWatermarkLegacy": "RemovalResponse",
    }[operation_id]
    return {
        "post": {
            "summary": summary,
            "operationId": operation_id,
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": schema}},
            },
            "responses": {
                "200": {
                    "description": "Success",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": f"#/components/schemas/{response_name}"}
                        }
                    },
                },
                "400": {"$ref": "#/components/responses/BadRequest"},
                "401": {"$ref": "#/components/responses/Unauthorized"},
                "403": {"$ref": "#/components/responses/Forbidden"},
                "415": {"$ref": "#/components/responses/UnsupportedMediaType"},
            },
        }
    }


def openapi_schema() -> dict[str, Any]:
    """Complete OpenAPI document for humans, generators, and AI agents."""
    text = {"text": {"type": "string"}}
    permissions = {
        "allow_network": {"type": "boolean", "default": False},
        "allow_model_download": {"type": "boolean", "default": False},
    }
    verification_policy = {"require_verified": {"type": "boolean", "default": False}}
    detector = {"type": "string", "default": "unicode"}
    options = {
        "type": "object",
        "properties": {
            "passes": {"type": "integer", "minimum": 1, "maximum": 5},
            "epsilon": {"type": "number", "minimum": 0.05, "maximum": 0.9},
            "beta": {"type": "number", "minimum": 0, "maximum": 20},
            "best_of": {"type": "integer", "minimum": 1, "maximum": 6},
        },
        "additionalProperties": False,
    }
    mode = {
        "type": "string",
        "enum": ["auto", "sanitize", "paraphrase", "full", "sira", "bias_inversion", "adversarial"],
        "default": "auto",
    }
    paths = {
        "/health": {
            "get": {"operationId": "health", "responses": {"200": {"description": "Healthy"}}}
        },
        "/capabilities": {
            "get": {
                "operationId": "capabilities",
                "responses": {"200": {"description": "Side-effect-free capabilities"}},
            }
        },
        "/inspect": _operation(
            "Inspect text without changing it",
            _request_schema(required=("text",), properties={**text, "detector": detector}),
            "inspectText",
        ),
        "/analyze": _operation(
            "Legacy alias for text inspection",
            _request_schema(required=("text",), properties=text),
            "analyzeText",
        ),
        "/sanitize": _operation(
            "Sanitize Unicode artifacts",
            _request_schema(
                required=("text",),
                properties={
                    **text,
                    "profile": {
                        "type": "string",
                        "enum": ["safe", "aggressive"],
                        "default": "safe",
                    },
                },
            ),
            "sanitizeText",
        ),
        "/plan": _operation(
            "Create a content-bound, side-effect-free execution plan",
            _request_schema(
                required=("text",),
                properties={
                    **text,
                    "mode": mode,
                    "detector": detector,
                    "options": options,
                    **permissions,
                    **verification_policy,
                },
            ),
            "planTransformation",
        ),
        "/apply": _operation(
            "Apply the exact reviewed plan with explicit consent",
            _request_schema(
                required=("text", "plan_digest", "consent"),
                properties={
                    **text,
                    "plan_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "mode": mode,
                    "detector": detector,
                    "options": options,
                    **verification_policy,
                    "consent": {
                        "type": "object",
                        "required": ["transformation"],
                        "properties": {
                            "transformation": {"type": "boolean"},
                            "network": {"type": "boolean", "default": False},
                            "model_download": {"type": "boolean", "default": False},
                        },
                        "additionalProperties": False,
                    },
                },
            ),
            "applyTransformation",
        ),
        "/verify": _operation(
            "Verify with a named detector or explicitly abstain",
            _request_schema(
                required=("source_text", "candidate_text"),
                properties={
                    "source_text": {"type": "string"},
                    "candidate_text": {"type": "string"},
                    "detector": {"type": "string", "default": "unicode-artifacts-v1"},
                },
            ),
            "verifyTransformation",
        ),
        "/remove": _operation(
            "Legacy one-step transformation; agents should use plan/apply",
            _request_schema(required=("text",), properties={**text, "mode": mode}),
            "removeWatermarkLegacy",
        ),
    }
    error_schema = {
        "type": "object",
        "required": ["error"],
        "properties": {"error": {"type": "string"}},
        "additionalProperties": False,
    }
    object_schema = {"type": "object", "additionalProperties": True}
    response_schemas = {
        "AnalysisResponse": object_schema,
        "RemovalResponse": object_schema,
        "InspectResponse": {
            "type": "object",
            "required": [
                "schema_version",
                "input_sha256",
                "detector_evidence",
                "unicode",
                "stats",
            ],
            "properties": {
                "schema_version": {"const": "1.0"},
                "input_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "detector_evidence": {"type": "object"},
                "unicode": {"type": "object"},
                "stats": {"type": "object"},
            },
            "additionalProperties": False,
        },
        "SanitizeResponse": {
            "type": "object",
            "required": ["cleaned_text", "changed"],
            "properties": {
                "cleaned_text": {"type": "string"},
                "changed": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        "PlanResponse": {
            "type": "object",
            "required": [
                "schema_version",
                "input_sha256",
                "mode",
                "detector",
                "options",
                "permissions",
                "policy",
                "execution",
                "plan_digest",
                "consent_required",
            ],
            "properties": {
                "schema_version": {"const": "1.0"},
                "input_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "mode": mode,
                "detector": {"type": "string"},
                "options": options,
                "permissions": {"type": "object"},
                "policy": {"type": "object"},
                "execution": {"type": "object"},
                "plan_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "digest_algorithm": {"const": "sha256"},
                "consent_required": {"const": True},
                "digest_is_authentication": {"const": False},
            },
            "additionalProperties": False,
        },
        "ApplyResponse": {
            "type": "object",
            "required": [
                "schema_version",
                "operation",
                "plan_digest",
                "input_sha256",
                "output_sha256",
                "consent",
                "policy",
                "result",
            ],
            "properties": {
                "schema_version": {"const": "1.0"},
                "operation": {"const": "apply"},
                "plan_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "input_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "output_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "consent": {"type": "object"},
                "policy": {"type": "object"},
                "result": {"type": "object"},
            },
            "additionalProperties": False,
        },
        "VerifyResponse": {
            "type": "object",
            "required": [
                "schema_version",
                "detector",
                "source_sha256",
                "candidate_sha256",
                "detection_status",
                "verification_status",
                "claim_scope",
            ],
            "properties": {
                "schema_version": {"const": "1.0"},
                "detector": {"type": "string"},
                "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "candidate_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "detection_status": {
                    "enum": [
                        "detected",
                        "not_detected",
                        "insufficient_evidence",
                        "unsupported",
                        "configuration_mismatch",
                        "detector_error",
                    ]
                },
                "verification_status": {
                    "enum": ["verified_cleared", "residual", "not_verifiable", "failed"]
                },
                "before": {"type": "object"},
                "after": {"type": "object"},
                "reason": {"type": ["string", "null"]},
                "claim_scope": {"type": "string"},
            },
            "additionalProperties": False,
        },
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "dewatermark assurance API",
            "version": "1.1",
            "description": (
                "Local-first text inspection and consent-bound transformation. A changed "
                "string is not represented as independently verified watermark removal."
            ),
        },
        # Authentication is optional on loopback and mandatory when the server
        # is deliberately bound externally. Referencing the scheme here makes
        # generated clients expose bearer-token configuration without claiming
        # that every local deployment requires a token.
        "security": [{"bearerAuth": []}, {}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "opaque"}
            },
            "schemas": {"Error": error_schema, **response_schemas},
            "responses": {
                name: {
                    "description": description,
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Error"}}
                    },
                }
                for name, description in (
                    ("BadRequest", "Invalid request"),
                    ("Unauthorized", "Authentication required"),
                    ("Forbidden", "Origin or consent denied"),
                    ("UnsupportedMediaType", "Content-Type must be application/json"),
                )
            },
        },
    }


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("request contains a duplicate JSON key")
        result[key] = value
    return result


class DewatermarkHandler(BaseHTTPRequestHandler):
    api_key: str | None = None
    allowed_origins: frozenset[str] = frozenset()
    bound_port: int = 8765

    def log_message(self, format: str, *args: object) -> None:
        # Deliberately omit request paths and bodies: source text can be sensitive.
        return

    def _send(self, status: int, value: object) -> None:
        body = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        origin = self.headers.get("Origin")
        if origin and origin in self.allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if not self.api_key:
            return True
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {self.api_key}"
        try:
            return hmac.compare_digest(supplied, expected)
        except (TypeError, ValueError):
            return False

    def _origin_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        if origin in self.allowed_origins:
            return True
        # Same-origin browser use remains possible without a CORS allowlist.
        host = self.headers.get("Host", "")
        try:
            parsed = urlparse(origin)
        except ValueError:
            return False
        return parsed.scheme in {"http", "https"} and parsed.netloc == host

    def _host_allowed(self) -> bool:
        """Block DNS rebinding against an unauthenticated loopback server."""
        if self.api_key:
            return True
        raw = self.headers.get("Host", "")
        try:
            parsed = urlparse(f"//{raw}")
            port = parsed.port
        except ValueError:
            return False
        if parsed.username or parsed.password:
            return False
        hostname = (parsed.hostname or "").lower()
        return hostname in {"localhost", "127.0.0.1", "::1"} and port == self.bound_port

    def _guard(self) -> bool:
        if not self._host_allowed():
            self._send(403, {"error": "host not allowed"})
            return False
        if not self._origin_allowed():
            self._send(403, {"error": "origin not allowed"})
            return False
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return False
        return True

    def do_GET(self) -> None:
        if not self._guard():
            return
        try:
            api_capabilities = capabilities()
        except Exception:
            self._send(500, {"error": "capability discovery failed; details redacted"})
            return
        api_capabilities["agent_operations"] = ["inspect", "plan", "apply", "verify"]
        routes = {
            "/health": {"status": "ok"},
            "/capabilities": api_capabilities,
            "/openapi.json": openapi_schema(),
        }
        self._send(200, routes[self.path]) if self.path in routes else self._send(
            404, {"error": "not found"}
        )

    def do_OPTIONS(self) -> None:
        if not self._origin_allowed():
            self._send(403, {"error": "origin not allowed"})
            return
        origin = self.headers.get("Origin")
        self.send_response(204)
        if origin and origin in self.allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def do_POST(self) -> None:
        if not self._guard():
            return
        if self.path not in _POST_ROUTES:
            self._send(404, {"error": "not found"})
            return
        if not _is_json_content_type(self.headers.get("Content-Type", "")):
            self._send(415, {"error": "Content-Type must be application/json"})
            return
        try:
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("transfer-encoded request bodies are not supported")
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY_BYTES:
                raise ValueError("request body is empty or too large")
            payload = json.loads(self.rfile.read(length), object_pairs_hook=_no_duplicate_keys)
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            result = process_request(self.path, payload)
            self._send(200, result)
        except ConsentRequiredError:
            self._send(403, {"error": "transformation consent is required"})
        except PlanMismatchError:
            self._send(400, {"error": "plan digest does not match the reviewed request"})
        except PermissionError:
            self._send(403, {"error": "operation is not permitted"})
        except json.JSONDecodeError:
            self._send(400, {"error": "request body is not valid JSON"})
        except (KeyError, TypeError, ValueError):
            self._send(400, {"error": "invalid request"})
        except Exception:
            # Never echo provider responses, text, or credential-bearing errors.
            self._send(500, {"error": "processing failed; details redacted"})


def _validate_origins(values: Iterable[str], label: str) -> tuple[str, ...]:
    normalized = tuple(value.strip().rstrip("/") for value in values if value.strip())
    for value in normalized:
        parsed = urlparse(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.params
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError(f"{label} must contain HTTP(S) origins without paths or credentials")
    return normalized


def _origins_from_env(name: str) -> tuple[str, ...]:
    values = tuple(value.strip() for value in os.environ.get(name, "").split(",") if value.strip())
    return _validate_origins(values, name)


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    api_key_env: str = "DEWATERMARK_SERVER_API_KEY",
    allowed_origins: Iterable[str] | None = None,
) -> None:
    """Serve forever. Non-loopback binds require a configured API key."""
    api_key = os.environ.get(api_key_env)
    if host not in {"127.0.0.1", "localhost", "::1"} and not api_key:
        raise ValueError(f"non-loopback server requires {api_key_env}")
    origins = (
        _validate_origins(allowed_origins, "allowed_origins")
        if allowed_origins is not None
        else _origins_from_env("DEWATERMARK_SERVER_ALLOWED_ORIGINS")
    )
    handler = type(
        "ConfiguredHandler",
        (DewatermarkHandler,),
        {
            "api_key": api_key,
            "allowed_origins": frozenset(value.rstrip("/") for value in origins),
            "bound_port": port,
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    configured_handler: Any = handler
    configured_handler.bound_port = int(server.server_address[1])
    server.serve_forever()
