from argparse import Namespace

from run_eval import write_results


def test_unicode_only_report_does_not_imply_statistical_samples_ran(tmp_path):
    output = tmp_path / "results.md"
    args = Namespace(
        date="2026-08-17",
        local_lm="fixture/model",
        samples=100,
        null_samples=1000,
        lengths=None,
        length=220,
        seed=13,
    )
    write_results(
        [{"family": "fixture", "removed": 1, "total": 1, "rate": 1.0}],
        None,
        args,
        output,
    )
    rendered = output.read_text(encoding="utf-8")
    assert "Statistical suite: not run" in rendered
    assert "100 positives" not in rendered
