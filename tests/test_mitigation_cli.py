import hashlib
import json

from dewatermark.cli import EXIT_OK, EXIT_PROCESSING, EXIT_USAGE, main
from dewatermark.models import CapabilityManifest
from dewatermark.providers import (
    register_detector,
    register_provider,
    unregister_detector,
    unregister_provider,
)

SOURCE = "alpha blue beta blue gamma blue delta epsilon zeta eta theta"


def _capability(identifier):
    return CapabilityManifest(
        identifier=identifier,
        kind="detector",
        schemes=("cli-search-fixture",),
        calibrated=True,
        independent=True,
        metadata={
            "configuration_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
            "resource_accounting": "none",
            "score_direction": "higher",
            "threshold": 2.0,
            "threshold_operator": ">=",
            "watermark_target_sha256": "c" * 64,
        },
    )


class PrimaryDetector:
    capability = _capability("cli-search-primary")

    def __init__(self, _config=None):
        pass

    def available(self):
        return True

    def detect(self, text):
        score = float(text.count("blue"))
        start = text.find("blue")
        return {
            "scheme": "cli-search-fixture",
            "status": "detected" if score >= 2 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
            "p_value": 0.001 if score >= 2 else 0.8,
            "localization": ([{"start": start, "end": start + 4}] if start >= 0 else []),
        }


class VerifierDetector(PrimaryDetector):
    capability = _capability("cli-search-verifier")

    def detect(self, text):
        # Deliberately use an independently implemented token counter so this
        # fixture models a distinct held-out detector, not a cosmetic subclass.
        score = float(sum(token == "blue" for token in text.split()))
        start = text.find("blue")
        return {
            "scheme": "cli-search-fixture",
            "status": "detected" if score >= 2 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
            "p_value": 0.001 if score >= 2 else 0.8,
            "localization": ([{"start": start, "end": start + 4}] if start >= 0 else []),
        }


class RewriteProvider:
    capability = CapabilityManifest(
        identifier="cli-search-strategy",
        kind="transformer",
        metadata={"resource_accounting": "none"},
    )
    constructed = 0

    def __init__(self, _config):
        type(self).constructed += 1

    def available(self):
        return True

    def rewrite(self, text, **_options):
        return text.replace("blue", "teal", 2), {"status": "candidate"}


def _register():
    register_detector("cli-search-primary", PrimaryDetector)
    register_detector("cli-search-verifier", VerifierDetector)
    register_provider("cli-search-strategy", RewriteProvider)


def _unregister():
    unregister_detector("cli-search-primary")
    unregister_detector("cli-search-verifier")
    unregister_provider("cli-search-strategy")


def test_cli_localize_returns_content_free_native_spans(capsys):
    _register()
    try:
        assert (
            main(
                [
                    "localize",
                    SOURCE,
                    "--detector",
                    "cli-search-primary",
                ]
            )
            == EXIT_OK
        )
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "localized_exploratory"
        assert payload["method"] == "detector_attribution"
        assert payload["spans"] == [{"start": 6, "end": 10, "contributing_windows": 1}]
        assert SOURCE not in json.dumps(payload)
    finally:
        _unregister()


def test_cli_mitigate_requires_consent_then_returns_verified_minimal_candidate(capsys):
    RewriteProvider.constructed = 0
    _register()
    arguments = [
        "mitigate",
        SOURCE,
        "--detector",
        "cli-search-primary",
        "--verifier",
        "cli-search-verifier",
        "--strategy",
        "cli-search-strategy",
    ]
    try:
        assert main(arguments) == EXIT_USAGE
        assert RewriteProvider.constructed == 0
        denied = json.loads(capsys.readouterr().err)
        assert denied["error"] == "mitigate requires explicit consent=true"

        assert main([*arguments, "--consent"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "verified"
        assert payload["changed"] is True
        assert payload["cleaned_text"] == SOURCE.replace("blue", "teal", 2)
        assert payload["receipt"]["verification"]["status"] == "verified"
        assert SOURCE not in json.dumps(payload["receipt"])
    finally:
        _unregister()


def test_cli_validates_and_reads_input_before_loading_strategy_plugins(
    monkeypatch, capsys, tmp_path
):
    loaded = False

    def load_strategy(_name, _config):
        nonlocal loaded
        loaded = True
        raise AssertionError("strategy should not load for invalid input")

    monkeypatch.setattr("dewatermark.cli.registered_strategy", load_strategy)
    status = main(
        [
            "mitigate",
            "--input",
            str(tmp_path / "missing.txt"),
            "--detector",
            "unused-primary",
            "--verifier",
            "unused-verifier",
            "--strategy",
            "unused-strategy",
            "--consent",
        ]
    )

    assert status == EXIT_USAGE
    assert loaded is False
    assert json.loads(capsys.readouterr().err)["error"] == "input must be a regular file"


def test_cli_mitigate_rolls_back_and_returns_processing_exit_when_verifier_is_repeated(capsys):
    _register()
    try:
        status = main(
            [
                "mitigate",
                SOURCE,
                "--detector",
                "cli-search-primary",
                "--verifier",
                "cli-search-primary",
                "--strategy",
                "cli-search-strategy",
                "--consent",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert status == EXIT_PROCESSING
        assert payload["status"] == "rolled_back"
        assert payload["cleaned_text"] == SOURCE
        assert payload["changed"] is False
    finally:
        _unregister()
