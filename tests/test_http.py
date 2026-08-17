from dewatermark import http
from dewatermark.config import DewatermarkConfig


class _Response:
    def __init__(self, status_code):
        self.status_code = status_code


def test_post_json_retries_transient_status(monkeypatch):
    statuses = iter([429, 503, 200])
    calls = []

    def fake_post(*args, **kwargs):
        calls.append((args, kwargs))
        return _Response(next(statuses))

    monkeypatch.setattr(http.requests, "post", fake_post)
    monkeypatch.setattr(http.time, "sleep", lambda _seconds: None)
    events = []
    response = http.post_json(
        "http://127.0.0.1/x",
        headers={},
        body={},
        timeout=1,
        retries=2,
        config=DewatermarkConfig(event_handler=events.append),
        backend="fixture",
    )
    assert response.status_code == 200
    assert len(calls) == 3
    assert sum(event["event"] == "http.request.retry" for event in events) == 2
    assert all("body" not in event and "headers" not in event for event in events)
