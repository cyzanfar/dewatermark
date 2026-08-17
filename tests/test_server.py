import pytest

from dewatermark.server import openapi_schema, process_request, serve


def test_openapi_has_routes():
    assert "/sanitize" in openapi_schema()["paths"]


def test_process_sanitize_without_network():
    result = process_request("/sanitize", {"text": "he\u200bllo"})
    assert result == {"cleaned_text": "hello", "changed": True}


def test_external_bind_requires_key(monkeypatch):
    monkeypatch.delenv("DEWATERMARK_SERVER_API_KEY", raising=False)
    with pytest.raises(ValueError, match="requires"):
        serve("0.0.0.0", 8765)
