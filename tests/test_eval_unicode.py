import run_eval


def test_unicode_evaluation_uses_explicit_aggressive_profile():
    rows = run_eval.run_unicode_suite()
    assert rows
    assert all(row["rate"] == 1.0 for row in rows)
