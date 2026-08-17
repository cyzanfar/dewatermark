from hypothesis import given, settings
from hypothesis import strategies as st

from dewatermark.unicode import sanitize


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=500))
@settings(max_examples=200, deadline=None)
def test_safe_sanitize_is_idempotent_for_arbitrary_unicode(text):
    once, _ = sanitize(text, profile="safe")
    twice, _ = sanitize(once, profile="safe")
    assert twice == once


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=300))
@settings(max_examples=100, deadline=None)
def test_analyze_and_sanitize_never_raise_for_unicode(text):
    cleaned, counts = sanitize(text, profile="safe")
    assert isinstance(cleaned, str)
    assert all(value >= 0 for value in counts.values())
