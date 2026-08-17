from dewatermark.mcp_server import analyze_text, get_capabilities, plan_removal, sanitize_text


def test_pure_mcp_tools():
    assert sanitize_text("he\u200bllo")["cleaned_text"] == "hello"
    assert analyze_text("plain")["unicode"]["total_flags"] == 0
    assert plan_removal("sanitize")["available"] is True
    assert "modes" in get_capabilities()
