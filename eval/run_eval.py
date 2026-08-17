"""Efficacy harness for dewatermark.

UNICODE suite: 5 covert families x 10 covers -> deterministic strip, expects 100%.

STATISTICAL suite: for each watermark scheme and removal mode, generate
watermarked positives and matched unwatermarked controls, pass both populations
through the same transformation, and report estimable fixed-FPR metrics plus a
multi-metric quality battery.
This directly A/Bs the self-information modes (sira, bias_inversion) against the
legacy paraphrase (full).

Results -> eval/RESULTS.md. Heavy deps (torch/transformers/sentence-transformers)
are needed only for the statistical suite; --skip-statistical runs unicode only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from pathlib import Path

import dewatermark

try:
    from . import metrics, schemes, stego
    from .adapters import CommandScheme
    from .calibration import select_strength
    from .manifest import content_addressed_score_table
except ImportError:  # direct ``python eval/run_eval.py`` compatibility
    import metrics  # type: ignore
    import schemes  # type: ignore
    import stego  # type: ignore
    from adapters import CommandScheme  # type: ignore
    from calibration import select_strength  # type: ignore
    from manifest import content_addressed_score_table  # type: ignore

RESULTS_PATH = Path.cwd() / "dewatermark-results.md"

COVER_TEXTS = [
    "The committee published its annual report on Tuesday, outlining a plan to modernize the city's water infrastructure over the next decade.",
    "Machine learning models have transformed natural language processing, enabling applications from translation to summarization at scale.",
    "Researchers at the marine institute documented a steady recovery of coral reefs along the northern coast after five years of protection.",
    "The novel opens in a small railway town where the arrival of a stranger unsettles the quiet routines of its inhabitants.",
    "Regular exercise, adequate sleep, and a balanced diet remain the most reliable foundations of long-term cardiovascular health.",
    "The quarterly earnings call revealed stronger than expected growth in the cloud division, though hardware sales continued to decline.",
    "Photosynthesis converts sunlight, water, and carbon dioxide into glucose and oxygen, sustaining nearly all life on Earth.",
    "The recipe calls for slow-roasting the tomatoes with garlic and olive oil until they collapse into a rich, sweet sauce.",
    "Voters in the region turned out in record numbers, driven by debates over housing costs, transit funding, and school budgets.",
    "The symphony's final movement builds from a solitary cello line into a sweeping theme that resolves in a quiet brass chorale.",
]

PROMPTS = [
    "Write an essay about the economic effects of remote work on mid-sized cities.",
    "Explain how transformer neural networks process sequences of text.",
    "Discuss the causes and consequences of the fall of the Roman Republic.",
    "Describe the process of photosynthesis and its role in the carbon cycle.",
    "Argue for or against universal basic income as a response to automation.",
    "Summarize the history and cultural impact of the printing press.",
    "Explain the science behind mRNA vaccines and how they were developed.",
    "Write about the challenges of detecting and mitigating climate tipping points.",
]

# per-mode default params for dewatermark.remove()
MODE_PARAMS = {
    "full": {"passes": 2},
    "sira": {"epsilon": 0.35},
    "bias_inversion": {"beta": 6.0},
    "adversarial": {"best_of": 3, "epsilon": 0.3},
}
FPRS = [0.01, 0.001, 1e-5]


def _evaluation_config_manifest(config) -> dict:
    """Public, content-addressable config without credentials or endpoint URLs."""
    value = config.to_dict(redact_secrets=True)
    value["fireworks_api_key_configured"] = bool(config.fireworks_api_key)
    value["llm_api_key_configured"] = bool(config.llm_api_key)
    value.pop("fireworks_api_key", None)
    value.pop("llm_api_key", None)
    for key in ("fireworks_base_url", "llm_base_url"):
        endpoint = str(value.pop(key, ""))
        value[f"{key}_sha256"] = hashlib.sha256(endpoint.encode()).hexdigest()
    return value


def remove_text(text: str, mode: str) -> str:
    params = MODE_PARAMS.get(mode, {})
    return dewatermark.remove(text, mode=mode, **params).cleaned_text


def _remove_with_outcome(text: str, mode: str):
    params = MODE_PARAMS.get(mode, {})
    result = dewatermark.remove(text, mode=mode, **params)
    transformation = result.report.transformation_status
    if transformation == "failed":
        state = "failed"
    elif transformation in {"unsupported_scheme", "rejected_quality"}:
        state = "abstained"
    else:
        state = "accepted"
    return result.cleaned_text, {
        "state": state,
        "transformation_status": transformation,
        "changed": result.cleaned_text != text,
    }


def analyze_flags(text: str) -> int:
    return dewatermark.analyze(text)["unicode"]["total_flags"]


# ---------------------------------------------------------------- unicode suite
def run_unicode_suite() -> list[dict]:
    rows = []
    for family in stego.FAMILIES:
        embed = stego.EMBEDDERS[family]
        removed = 0
        for i, cover in enumerate(COVER_TEXTS):
            payload = f"zd-{family}-{i}".encode()
            watermarked = embed(cover, payload)
            # The efficacy suite embeds known covert payloads, so it intentionally
            # uses the lossy forensic profile. The package default remains safe.
            cleaned = dewatermark.sanitize(watermarked, profile="aggressive")
            expected = dewatermark.sanitize(cover, profile="aggressive")
            removed += cleaned == expected
        rate = removed / len(COVER_TEXTS)
        rows.append({"family": family, "removed": removed, "total": len(COVER_TEXTS), "rate": rate})
        print(f"[unicode] {family:20s} {removed}/{len(COVER_TEXTS)} ({rate:.0%})")
    return rows


# ------------------------------------------------------------ statistical suite
def _mode_metrics(
    before,
    after,
    plain_before,
    plain_after,
    calibration_plain_before,
    calibration_plain_after,
    sims,
    berts,
    quality_passes,
    mauve_score,
    ppl_b,
    ppl_a,
    *,
    seed=0,
    positive_cluster_ids=None,
    null_cluster_ids=None,
):
    source_calibration = metrics.calibration_report(calibration_plain_before, 0.01)
    candidate_calibration = metrics.calibration_report(calibration_plain_after, 0.01)
    source_threshold = source_calibration.get("threshold")
    candidate_threshold = candidate_calibration.get("threshold")
    flagged = (
        sum(1 for value in after if value > candidate_threshold)
        if candidate_threshold is not None
        else None
    )
    before_auc = metrics.auroc(before, plain_before)
    after_auc = metrics.auroc(after, plain_after)
    row = {
        "auroc_before": before_auc,
        "auroc_before_ci95": metrics.bootstrap_auroc_interval(before, plain_before, seed=seed),
        "auroc_after": after_auc,
        "auroc_after_ci95": metrics.bootstrap_auroc_interval(after, plain_after, seed=seed + 1),
        "mean_before": sum(before) / len(before),
        "mean_after": sum(after) / len(after),
        "flagged_after": flagged,
        "n": len(after),
        "sim_mean": sum(sims) / len(sims) if sims else float("nan"),
        "bertscore_mean": sum(berts) / len(berts) if berts else float("nan"),
        "quality_gate_rate": sum(quality_passes) / len(quality_passes)
        if quality_passes
        else float("nan"),
        "mauve": mauve_score,
        "ppl_before": sum(ppl_b) / len(ppl_b) if ppl_b else float("nan"),
        "ppl_after": sum(ppl_a) / len(ppl_a) if ppl_a else float("nan"),
        "calibration@0.01": candidate_calibration,
        "calibration_before@0.01": source_calibration,
        "calibration_after@0.01": candidate_calibration,
        "paired_outcomes@0.01": metrics.paired_detection_outcomes(
            before,
            after,
            plain_before,
            plain_after,
            source_threshold=float("nan") if source_threshold is None else source_threshold,
            candidate_threshold=float("nan")
            if candidate_threshold is None
            else candidate_threshold,
            bootstrap_seed=seed,
            positive_cluster_ids=positive_cluster_ids,
            null_cluster_ids=null_cluster_ids,
        ),
    }
    for fpr in FPRS:
        before_cal = metrics.calibration_report(calibration_plain_before, fpr)
        after_cal = metrics.calibration_report(calibration_plain_after, fpr)
        before_threshold = before_cal.get("threshold")
        after_threshold = after_cal.get("threshold")
        row[f"calibration_before@{fpr}"] = before_cal
        row[f"calibration_after@{fpr}"] = after_cal
        row[f"tpr_before@{fpr}"] = (
            sum(value > before_threshold for value in before) / len(before)
            if before_threshold is not None and before
            else float("nan")
        )
        row[f"tpr_after@{fpr}"] = (
            sum(value > after_threshold for value in after) / len(after)
            if after_threshold is not None and after
            else float("nan")
        )
        row[f"tpr_before_ci95@{fpr}"] = (
            metrics.wilson_interval(sum(value > before_threshold for value in before), len(before))
            if before_threshold is not None and before
            else (float("nan"), float("nan"))
        )
        row[f"tpr_after_ci95@{fpr}"] = (
            metrics.wilson_interval(sum(value > after_threshold for value in after), len(after))
            if after_threshold is not None and after
            else (float("nan"), float("nan"))
        )
        row[f"test_fpr_before@{fpr}"] = (
            sum(value > before_threshold for value in plain_before) / len(plain_before)
            if before_threshold is not None and plain_before
            else float("nan")
        )
        row[f"test_fpr_after@{fpr}"] = (
            sum(value > after_threshold for value in plain_after) / len(plain_after)
            if after_threshold is not None and plain_after
            else float("nan")
        )
        row[f"test_fpr_after_ci95@{fpr}"] = (
            metrics.wilson_interval(
                sum(value > after_threshold for value in plain_after), len(plain_after)
            )
            if after_threshold is not None and plain_after
            else (float("nan"), float("nan"))
        )
    if flagged is not None:
        row["tpr_after_ci95"] = metrics.wilson_interval(flagged, len(after))
    return row


def _metadata(callback) -> dict:
    if not callable(callback):
        return {}
    value = callback()
    return dict(value) if isinstance(value, dict) else {}


def _generate_population(sc, tok, model, *, scheme_name, cohort, count, length, seed, marked):
    texts, metadata_rows, sample_seeds = [], [], []
    for index in range(count):
        sample_seed = schemes.sample_seed(seed, scheme_name, cohort, length, index)
        text = sc["generate"](
            PROMPTS[index % len(PROMPTS)], tok, model, length, sample_seed, marked
        )
        texts.append(text)
        sample_seeds.append(sample_seed)
        metadata_rows.append(_metadata(sc.get("generation_metadata")))
    return texts, metadata_rows, sample_seeds


def _detect_population(detector, texts, tok):
    scores, metadata_rows = [], []
    for text in texts:
        scores.append(detector["detect"](text, tok))
        metadata_rows.append(_metadata(detector.get("detection_metadata")))
    return scores, metadata_rows


def _transform_population(texts, mode, *, label, failure_policy):
    candidates, outcomes = [], []
    for index, text in enumerate(texts):
        try:
            candidate, outcome = _remove_with_outcome(text, mode)
        except Exception as exc:
            error_name = type(exc).__name__
            print(f"  ! {label}/{mode} sample {index} failed: {error_name}", file=sys.stderr)
            if failure_policy == "strict":
                raise RuntimeError(f"{label}/{mode} sample {index} failed") from None
            candidate = text
            outcome = {
                "state": "failed",
                "transformation_status": "failed",
                "changed": False,
                "error": error_name,
            }
        candidates.append(candidate)
        outcomes.append(outcome)
    return candidates, outcomes


def _is_flagged(score, threshold):
    return score > threshold if threshold is not None and math.isfinite(threshold) else None


def _outcome_label(cohort, source_flag, candidate_flag):
    if source_flag is None or candidate_flag is None:
        return "not_estimable"
    if cohort == "positive":
        if source_flag and not candidate_flag:
            return "cleared"
        if source_flag and candidate_flag:
            return "residual"
        if not source_flag and candidate_flag:
            return "newly_flagged"
        return "not_initially_detected"
    if not source_flag and candidate_flag:
        return "false_inserted"
    if source_flag and not candidate_flag:
        return "flag_cleared"
    if source_flag and candidate_flag:
        return "flag_persisted"
    return "stable_unflagged"


def _score_table(
    *,
    detector_name,
    cohort,
    source_scores,
    candidate_scores,
    source_threshold,
    candidate_threshold,
    transformation_outcomes,
    generation_metadata,
    source_detection_metadata,
    candidate_detection_metadata,
    sample_seeds,
    requested_tokens,
):
    rows = []
    for index, (source_score, candidate_score) in enumerate(zip(source_scores, candidate_scores)):
        source_flag = _is_flagged(source_score, source_threshold)
        candidate_flag = _is_flagged(candidate_score, candidate_threshold)
        generation = generation_metadata[index] if index < len(generation_metadata) else {}
        source_meta = (
            source_detection_metadata[index] if index < len(source_detection_metadata) else {}
        )
        candidate_meta = (
            candidate_detection_metadata[index] if index < len(candidate_detection_metadata) else {}
        )
        transformation = (
            transformation_outcomes[index]
            if index < len(transformation_outcomes)
            else {"state": "not_applicable", "changed": False}
        )
        rows.append(
            {
                "sample": index,
                "sample_seed": sample_seeds[index] if index < len(sample_seeds) else None,
                "prompt_cluster": index % len(PROMPTS),
                "cohort": cohort,
                "detector": detector_name,
                "requested_tokens": generation.get("requested_tokens", requested_tokens),
                "generation_effective_tokens": generation.get("effective_tokens"),
                "source_detector_effective_tokens": source_meta.get("effective_tokens"),
                "candidate_detector_effective_tokens": candidate_meta.get("effective_tokens"),
                "source_score": source_score,
                "candidate_score": candidate_score,
                "source_flagged": source_flag,
                "candidate_flagged": candidate_flag,
                "outcome": _outcome_label(cohort, source_flag, candidate_flag),
                "transformation_state": transformation.get("state"),
                "transformation_status": transformation.get("transformation_status"),
                "changed": bool(transformation.get("changed", False)),
                "error": transformation.get("error"),
            }
        )
    return content_addressed_score_table(rows)


def _transformation_summary(outcomes):
    attempted = len(outcomes)
    accepted = sum(value.get("state") == "accepted" for value in outcomes)
    failed = sum(value.get("state") == "failed" for value in outcomes)
    abstained = sum(value.get("state") == "abstained" for value in outcomes)
    return {
        "attempted": attempted,
        "accepted": accepted,
        "failed": failed,
        "abstained": abstained,
        "changed": sum(bool(value.get("changed")) for value in outcomes),
        "rate_denominator": "all attempted transformations",
        "accepted_rate": accepted / attempted if attempted else float("nan"),
        "failure_rate": failed / attempted if attempted else float("nan"),
        "abstention_rate": abstained / attempted if attempted else float("nan"),
    }


def _detector_confusion(primary, secondary):
    pairs = [
        (left, right)
        for left, right in zip(primary, secondary)
        if left is not None and right is not None
    ]
    return {
        "samples": len(pairs),
        "both_flagged": sum(left and right for left, right in pairs),
        "primary_only": sum(left and not right for left, right in pairs),
        "secondary_only": sum(not left and right for left, right in pairs),
        "neither_flagged": sum(not left and not right for left, right in pairs),
    }


def _composite_success(source_scores, candidate_scores, outcomes, quality_passes, metrics_row):
    paired = metrics_row.get("paired_outcomes@0.01", {})
    source_threshold = paired.get("source_threshold")
    candidate_threshold = paired.get("candidate_threshold")
    source_flags = [_is_flagged(value, source_threshold) for value in source_scores]
    candidate_flags = [_is_flagged(value, candidate_threshold) for value in candidate_scores]
    eligible = sum(value is True for value in source_flags)
    successes = sum(
        source is True and candidate is False and outcome.get("state") == "accepted" and quality
        for source, candidate, outcome, quality in zip(
            source_flags, candidate_flags, outcomes, quality_passes
        )
    )
    return {
        "definition": "source flagged, candidate cleared, transform accepted, quality gate passed",
        "attempted": len(source_scores),
        "initially_detected_denominator": eligible,
        "successes": successes,
        "rate_over_initially_detected": successes / eligible if eligible else float("nan"),
        "rate_over_attempted": successes / len(source_scores) if source_scores else float("nan"),
        "ci95_over_initially_detected": metrics.wilson_interval(successes, eligible),
    }


def run_statistical_suite(
    scheme_names,
    modes,
    samples,
    null_samples,
    length,
    seed,
    calibration_target=None,
    strength_grid=None,
    calibration_samples=100,
    failure_policy="strict",
    model_name="Qwen/Qwen2.5-0.5B-Instruct",
    model_revision=None,
    allow_model_download=False,
    artifact_sink=None,
    include_text_artifacts=False,
    allow_network=False,
    cross_detectors=None,
):
    print("[statistical] loading generator ...")
    schemes.reset_strengths()
    tok, model = schemes.load_model(
        model_name, revision=model_revision, allow_download=allow_model_download
    )
    schemes.seed_everything(seed)
    sem = metrics.SemanticScorer(
        allow_network=allow_network, allow_model_download=allow_model_download
    )
    bert = metrics.BERTScoreScorer(
        allow_network=allow_network, allow_model_download=allow_model_download
    )
    results = {}
    for scheme_name in scheme_names:
        sc = schemes.SCHEMES[scheme_name]
        print(f"[statistical] === {scheme_name} ({sc['family']}) ===")
        plain_texts, plain_generation_meta, plain_seeds = _generate_population(
            sc,
            tok,
            model,
            scheme_name=scheme_name,
            cohort="test-null",
            count=null_samples,
            length=length,
            seed=seed,
            marked=False,
        )
        calibration_plain_texts, calibration_generation_meta, calibration_seeds = (
            _generate_population(
                sc,
                tok,
                model,
                scheme_name=scheme_name,
                cohort="threshold-null",
                count=null_samples,
                length=length,
                seed=seed,
                marked=False,
            )
        )
        plain, plain_detection_meta = _detect_population(sc, plain_texts, tok)
        calibration_plain, calibration_detection_meta = _detect_population(
            sc, calibration_plain_texts, tok
        )
        calibration = None
        if calibration_target is not None and sc.get("set_strength"):
            scores_by_strength = {}
            for strength in strength_grid:
                sc["set_strength"](strength)
                scores_by_strength[strength] = [
                    sc["detect"](
                        sc["generate"](
                            PROMPTS[i % len(PROMPTS)],
                            tok,
                            model,
                            length,
                            schemes.sample_seed(
                                seed, scheme_name, "strength-calibration", strength, length, i
                            ),
                            True,
                        ),
                        tok,
                    )
                    for i in range(calibration_samples)
                ]
            calibration = select_strength(
                scores_by_strength, calibration_plain, target_tpr=calibration_target
            )
            if calibration["chosen"] is None:
                raise RuntimeError(
                    f"{scheme_name} did not reach calibration target; expand --strength-grid"
                )
            sc["set_strength"](calibration["chosen"])
        wm_texts, positive_generation_meta, sample_seeds = _generate_population(
            sc,
            tok,
            model,
            scheme_name=scheme_name,
            cohort="positive-test",
            count=samples,
            length=length,
            seed=seed,
            marked=True,
        )
        before, positive_detection_meta = _detect_population(sc, wm_texts, tok)
        print(
            f"[statistical] {scheme_name}: mean score watermarked={sum(before) / len(before):.2f} "
            f"plain={sum(plain) / len(plain):.2f}"
        )

        scheme_res = {
            "family": sc["family"],
            "source": sc.get("source"),
            "independent": sc.get("independent", False),
            "manifest": sc.get("manifest", {}),
            "calibration": calibration,
            "plain": plain,
            "calibration_plain": calibration_plain,
            "before": before,
            "modes": {},
        }
        for mode in modes:
            cleaned_texts, positive_outcomes = _transform_population(
                wm_texts,
                mode,
                label=f"{scheme_name}/positive",
                failure_policy=failure_policy,
            )
            transformed_nulls, null_outcomes = _transform_population(
                plain_texts,
                mode,
                label=f"{scheme_name}/test-null",
                failure_policy=failure_policy,
            )
            transformed_calibration_nulls, calibration_outcomes = _transform_population(
                calibration_plain_texts,
                mode,
                label=f"{scheme_name}/threshold-null",
                failure_policy=failure_policy,
            )
            after, candidate_detection_meta = _detect_population(sc, cleaned_texts, tok)
            plain_after, plain_after_detection_meta = _detect_population(sc, transformed_nulls, tok)
            calibration_plain_after, calibration_after_detection_meta = _detect_population(
                sc, transformed_calibration_nulls, tok
            )
            sims = [
                sem.similarity(source, candidate)
                for source, candidate in zip(wm_texts, cleaned_texts)
            ]
            berts = [
                bert.similarity(source, candidate)
                for source, candidate in zip(wm_texts, cleaned_texts)
            ]
            quality_passes = [
                outcome.get("state") == "accepted"
                and metrics.deterministic_quality_pass(source, candidate)
                for source, candidate, outcome in zip(wm_texts, cleaned_texts, positive_outcomes)
            ]
            ppl_b = [metrics.perplexity(value, tok, model) for value in wm_texts]
            ppl_a = [metrics.perplexity(value, tok, model) for value in cleaned_texts]
            for j, (wt, cleaned, zb, za) in enumerate(zip(wm_texts, cleaned_texts, before, after)):
                if artifact_sink:
                    artifact = {
                        "event": "sample.completed",
                        "scheme": scheme_name,
                        "mode": mode,
                        "length": length,
                        "sample": j,
                        "sample_seed": sample_seeds[j],
                        "score_before": zb,
                        "score_after": za,
                        "semantic_similarity": sims[j],
                        "bertscore": berts[j],
                        "quality_passed": quality_passes[j],
                        "source_sha256": hashlib.sha256(wt.encode("utf-8")).hexdigest(),
                        "candidate_sha256": hashlib.sha256(cleaned.encode("utf-8")).hexdigest(),
                        "error": positive_outcomes[j].get("error"),
                    }
                    if include_text_artifacts:
                        artifact.update(source_text=wt, candidate_text=cleaned)
                    artifact_sink(artifact)
                print(
                    f"  [{scheme_name}/{mode}] {j + 1}/{samples} score {zb:6.2f} -> {za:6.2f} "
                    f"sim {sims[j]:.2f}"
                )
            mauve_score = metrics.corpus_mauve(
                wm_texts,
                cleaned_texts,
                allow_network=allow_network,
                allow_model_download=allow_model_download,
            )
            mode_result = _mode_metrics(
                before,
                after,
                plain,
                plain_after,
                calibration_plain,
                calibration_plain_after,
                sims,
                berts,
                quality_passes,
                mauve_score,
                ppl_b,
                ppl_a,
                seed=schemes.sample_seed(seed, scheme_name, mode, "bootstrap"),
                positive_cluster_ids=[index % len(PROMPTS) for index in range(samples)],
                null_cluster_ids=[index % len(PROMPTS) for index in range(null_samples)],
            )
            paired = mode_result["paired_outcomes@0.01"]
            source_threshold = paired.get("source_threshold")
            candidate_threshold = paired.get("candidate_threshold")
            primary_tables = {
                "positive": _score_table(
                    detector_name=scheme_name,
                    cohort="positive",
                    source_scores=before,
                    candidate_scores=after,
                    source_threshold=source_threshold,
                    candidate_threshold=candidate_threshold,
                    transformation_outcomes=positive_outcomes,
                    generation_metadata=positive_generation_meta,
                    source_detection_metadata=positive_detection_meta,
                    candidate_detection_metadata=candidate_detection_meta,
                    sample_seeds=sample_seeds,
                    requested_tokens=length,
                ),
                "test_null": _score_table(
                    detector_name=scheme_name,
                    cohort="test_null",
                    source_scores=plain,
                    candidate_scores=plain_after,
                    source_threshold=source_threshold,
                    candidate_threshold=candidate_threshold,
                    transformation_outcomes=null_outcomes,
                    generation_metadata=plain_generation_meta,
                    source_detection_metadata=plain_detection_meta,
                    candidate_detection_metadata=plain_after_detection_meta,
                    sample_seeds=plain_seeds,
                    requested_tokens=length,
                ),
                "calibration_null": _score_table(
                    detector_name=scheme_name,
                    cohort="calibration_null",
                    source_scores=calibration_plain,
                    candidate_scores=calibration_plain_after,
                    source_threshold=source_threshold,
                    candidate_threshold=candidate_threshold,
                    transformation_outcomes=calibration_outcomes,
                    generation_metadata=calibration_generation_meta,
                    source_detection_metadata=calibration_detection_meta,
                    candidate_detection_metadata=calibration_after_detection_meta,
                    sample_seeds=calibration_seeds,
                    requested_tokens=length,
                ),
            }
            mode_result["score_tables"] = primary_tables
            if artifact_sink:
                for cohort, table in primary_tables.items():
                    artifact_sink(
                        {
                            "event": "score_table.completed",
                            "scheme": scheme_name,
                            "detector": scheme_name,
                            "mode": mode,
                            "length": length,
                            "cohort": cohort,
                            "table": table,
                        }
                    )
            mode_result["quality_metric_backends"] = {
                "semantic": sem.backend,
                "bertscore": bert.backend,
                "mauve": (
                    "mauve:default"
                    if math.isfinite(mauve_score)
                    else (
                        "unavailable-without-network-and-download-consent"
                        if not (allow_network and allow_model_download)
                        else "unavailable-runtime"
                    )
                ),
                "perplexity": f"generator:{model_name}@{model_revision or 'unresolved'}",
            }
            mode_result["transformation_denominators"] = {
                "positive": _transformation_summary(positive_outcomes),
                "test_null": _transformation_summary(null_outcomes),
                "calibration_null": _transformation_summary(calibration_outcomes),
            }
            mode_result["failures"] = [
                {"sample": index, "error": value.get("error")}
                for index, value in enumerate(positive_outcomes)
                if value.get("state") == "failed"
            ]
            mode_result["composite_success"] = _composite_success(
                before, after, positive_outcomes, quality_passes, mode_result
            )

            # Optional named detectors measure transfer without being mistaken
            # for the scheme's own detector. Each receives exactly the same
            # paired populations and has an independently reported manifest.
            cross_results = {}
            for detector_name, detector in (cross_detectors or {}).items():
                d_before, d_before_meta = _detect_population(detector, wm_texts, tok)
                d_after, d_after_meta = _detect_population(detector, cleaned_texts, tok)
                d_plain, d_plain_meta = _detect_population(detector, plain_texts, tok)
                d_plain_after, d_plain_after_meta = _detect_population(
                    detector, transformed_nulls, tok
                )
                d_calibration, d_calibration_meta = _detect_population(
                    detector, calibration_plain_texts, tok
                )
                d_calibration_after, d_calibration_after_meta = _detect_population(
                    detector, transformed_calibration_nulls, tok
                )
                cross_metrics = _mode_metrics(
                    d_before,
                    d_after,
                    d_plain,
                    d_plain_after,
                    d_calibration,
                    d_calibration_after,
                    [],
                    [],
                    [],
                    float("nan"),
                    [],
                    [],
                    seed=schemes.sample_seed(seed, scheme_name, mode, detector_name, "bootstrap"),
                    positive_cluster_ids=[index % len(PROMPTS) for index in range(samples)],
                    null_cluster_ids=[index % len(PROMPTS) for index in range(null_samples)],
                )
                d_paired = cross_metrics["paired_outcomes@0.01"]
                cross_tables = {
                    "positive": _score_table(
                        detector_name=detector_name,
                        cohort="positive",
                        source_scores=d_before,
                        candidate_scores=d_after,
                        source_threshold=d_paired.get("source_threshold"),
                        candidate_threshold=d_paired.get("candidate_threshold"),
                        transformation_outcomes=positive_outcomes,
                        generation_metadata=positive_generation_meta,
                        source_detection_metadata=d_before_meta,
                        candidate_detection_metadata=d_after_meta,
                        sample_seeds=sample_seeds,
                        requested_tokens=length,
                    ),
                    "test_null": _score_table(
                        detector_name=detector_name,
                        cohort="test_null",
                        source_scores=d_plain,
                        candidate_scores=d_plain_after,
                        source_threshold=d_paired.get("source_threshold"),
                        candidate_threshold=d_paired.get("candidate_threshold"),
                        transformation_outcomes=null_outcomes,
                        generation_metadata=plain_generation_meta,
                        source_detection_metadata=d_plain_meta,
                        candidate_detection_metadata=d_plain_after_meta,
                        sample_seeds=plain_seeds,
                        requested_tokens=length,
                    ),
                    "calibration_null": _score_table(
                        detector_name=detector_name,
                        cohort="calibration_null",
                        source_scores=d_calibration,
                        candidate_scores=d_calibration_after,
                        source_threshold=d_paired.get("source_threshold"),
                        candidate_threshold=d_paired.get("candidate_threshold"),
                        transformation_outcomes=calibration_outcomes,
                        generation_metadata=calibration_generation_meta,
                        source_detection_metadata=d_calibration_meta,
                        candidate_detection_metadata=d_calibration_after_meta,
                        sample_seeds=calibration_seeds,
                        requested_tokens=length,
                    ),
                }
                primary_source_flags = [_is_flagged(value, source_threshold) for value in before]
                primary_candidate_flags = [
                    _is_flagged(value, candidate_threshold) for value in after
                ]
                cross_source_flags = [
                    _is_flagged(value, d_paired.get("source_threshold")) for value in d_before
                ]
                cross_candidate_flags = [
                    _is_flagged(value, d_paired.get("candidate_threshold")) for value in d_after
                ]
                both_source_flagged = sum(
                    primary is True and cross is True
                    for primary, cross in zip(primary_source_flags, cross_source_flags)
                )
                both_cleared = sum(
                    primary_source is True
                    and cross_source is True
                    and primary_candidate is False
                    and cross_candidate is False
                    and outcome.get("state") == "accepted"
                    and quality
                    for primary_source, cross_source, primary_candidate, cross_candidate, outcome, quality in zip(
                        primary_source_flags,
                        cross_source_flags,
                        primary_candidate_flags,
                        cross_candidate_flags,
                        positive_outcomes,
                        quality_passes,
                    )
                )
                cross_results[detector_name] = {
                    "manifest": detector.get("manifest", {}),
                    "metrics": cross_metrics,
                    "score_tables": cross_tables,
                    "confusion": {
                        "source": _detector_confusion(primary_source_flags, cross_source_flags),
                        "candidate": _detector_confusion(
                            primary_candidate_flags, cross_candidate_flags
                        ),
                    },
                    "composite_success": {
                        "definition": "both named detectors flag source and clear candidate; transform accepted; quality passed",
                        "both_source_flagged_denominator": both_source_flagged,
                        "successes": both_cleared,
                        "rate": both_cleared / both_source_flagged
                        if both_source_flagged
                        else float("nan"),
                        "ci95": metrics.wilson_interval(both_cleared, both_source_flagged),
                    },
                }
                if artifact_sink:
                    for cohort, table in cross_tables.items():
                        artifact_sink(
                            {
                                "event": "score_table.completed",
                                "scheme": scheme_name,
                                "detector": detector_name,
                                "mode": mode,
                                "length": length,
                                "cohort": cohort,
                                "table": table,
                            }
                        )
            mode_result["cross_detectors"] = cross_results
            scheme_res["modes"][mode] = mode_result
        results[scheme_name] = scheme_res
    return results


# ------------------------------------------------------------------- reporting
def _fmt(x, nd=2):
    if x is None or (isinstance(x, float) and x != x):
        return "-"
    return f"{x:.{nd}f}"


def write_results(unicode_rows, stat_results, args, output_path=RESULTS_PATH):
    cfg = dewatermark.get_config()
    lines = [
        "# Evaluation Results — dewatermark",
        "",
        f"- Date: {args.date}",
        f"- dewatermark {dewatermark.__version__}  |  lm_backend: `{cfg.resolved_lm_backend}`"
        f"  |  local rewriter: `{args.local_lm}`",
        (
            f"- Statistical: {args.samples} positives + {args.null_samples} matched "
            f"nulls/scheme at lengths {args.lengths or args.length} tokens, seed {args.seed}"
            if stat_results is not None
            else "- Statistical suite: not run (`--skip-statistical`)"
        ),
        "",
    ]

    if unicode_rows is not None:
        total_r = sum(r["removed"] for r in unicode_rows)
        total_n = sum(r["total"] for r in unicode_rows)
        lines += [
            "## UNICODE suite (explicit aggressive profile: steganography + NFKC + UTS#39)",
            "",
            "| Family | Removed | Rate |",
            "| --- | --- | --- |",
            *[
                f"| {r['family']} | {r['removed']}/{r['total']} | {r['rate']:.0%} |"
                for r in unicode_rows
            ],
            f"| **overall** | **{total_r}/{total_n}** | **{total_r / total_n:.0%}** |",
            "",
        ]

    if stat_results is not None:
        lines += [
            "## STATISTICAL suite (multi-scheme, calibrated detection)",
            "",
            "Detection scored as AUROC and TPR@fixed-FPR calibrated on un-watermarked "
            "samples from a dedicated threshold split, then measured on disjoint matched "
            "controls. `flagged@1%FPR` is residual detector positives—not proof of origin. "
            "False insertion is an initially unflagged matched null crossing that same "
            "named detector threshold. Quality metric backends are recorded in JSON.",
            "",
        ]
        for scheme_name, res in stat_results.items():
            auroc_wm = metrics.auroc(res["before"], res["plain"])
            lines += [
                f"### {scheme_name} — {res['family']}",
                "",
                f"Watermarked-vs-unwatermarked AUROC (before removal): **{_fmt(auroc_wm)}**  "
                f"(mean score {_fmt(sum(res['before']) / len(res['before']))} vs "
                f"plain {_fmt(sum(res['plain']) / len(res['plain']))}).",
                "",
                "| Mode | AUROC after | TPR@1%FPR | TPR@0.1%FPR | TPR@1e-5 | flagged@1%FPR | false insertion | semantic | gate pass | accepted/attempted | failed | abstained | composite/eligible |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
            cross_notes = []
            for mode, m in res["modes"].items():
                insertion = m["paired_outcomes@0.01"].get("false_insertion_rate")
                denominator = m.get("transformation_denominators", {}).get("positive", {})
                composite = m.get("composite_success", {})
                lines.append(
                    f"| {mode} | {_fmt(m['auroc_after'])} | {_fmt(m['tpr_after@0.01'])} | "
                    f"{_fmt(m['tpr_after@0.001'])} | {_fmt(m['tpr_after@1e-05'])} | "
                    f"{m['flagged_after'] if m['flagged_after'] is not None else 'not estimable'}/{m['n']} | "
                    f"{_fmt(insertion)} | {_fmt(m['sim_mean'])} | {_fmt(m['quality_gate_rate'])} | "
                    f"{denominator.get('accepted', 0)}/{denominator.get('attempted', 0)} | "
                    f"{denominator.get('failed', 0)}/{denominator.get('attempted', 0)} | "
                    f"{denominator.get('abstained', 0)}/{denominator.get('attempted', 0)} | "
                    f"{composite.get('successes', 0)}/{composite.get('initially_detected_denominator', 0)} |"
                )
                for detector_name, detector_result in m.get("cross_detectors", {}).items():
                    cross_composite = detector_result.get("composite_success", {})
                    source_confusion = detector_result.get("confusion", {}).get("source", {})
                    candidate_confusion = detector_result.get("confusion", {}).get("candidate", {})
                    cross_notes.append(
                        f"  - Cross-detector `{detector_name}`: composite "
                        f"{cross_composite.get('successes', 0)}/"
                        f"{cross_composite.get('both_source_flagged_denominator', 0)}; "
                        f"source agreement {source_confusion.get('both_flagged', 0)} both flagged, "
                        f"candidate agreement {candidate_confusion.get('neither_flagged', 0)} "
                        "both unflagged."
                    )
            lines.append("")
            lines.extend(cross_notes)
            if cross_notes:
                lines.append("")
            first_mode = next(iter(res["modes"].values()), {})
            lines.append(
                f"_Baseline (no removal) TPR@1%FPR on the held-out threshold: "
                f"{_fmt(first_mode.get('tpr_before@0.01'))}._"
            )
            lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Results written to {output_path}")


def main() -> None:
    p = argparse.ArgumentParser(description="Efficacy harness for dewatermark")
    p.add_argument("--schemes", default="KGW,Unigram,EXP")
    p.add_argument(
        "--modes",
        default="bias_inversion",
        help="comma-separated transforms; remote rewrite modes require --allow-network",
    )
    p.add_argument("--samples", type=int, default=100)
    p.add_argument(
        "--null-samples",
        type=int,
        default=1000,
        help="matched nulls; >=100 for 1%% FPR and >=1000 for 0.1%% FPR",
    )
    p.add_argument("--length", type=int, default=220)
    p.add_argument(
        "--lengths", default="", help="comma-separated length sweep, e.g. 100,250,500,1000,2000"
    )
    p.add_argument("--seed", type=int, default=13)
    p.add_argument("--local-lm", default="Qwen/Qwen2.5-0.5B-Instruct")
    p.add_argument(
        "--model-revision",
        default=None,
        help="immutable model revision/commit for reproducible runs",
    )
    p.add_argument("--allow-model-download", action="store_true")
    p.add_argument(
        "--allow-network",
        action="store_true",
        help="allow evaluation components to access the network; disabled by default",
    )
    p.add_argument("--skip-unicode", action="store_true")
    p.add_argument("--skip-statistical", action="store_true")
    p.add_argument("--date", default="")
    p.add_argument(
        "--adapter",
        action="append",
        default=[],
        help=(
            "adapter: NAME|FAMILY|SOURCE|SIDECAR|COMMAND (preferred) or legacy "
            "NAME|FAMILY|SOURCE|COMMAND"
        ),
    )
    p.add_argument(
        "--cross-detector",
        action="append",
        default=[],
        help="named detector: NAME|FAMILY|SOURCE|SIDECAR|COMMAND (static sidecar required for independence)",
    )
    p.add_argument(
        "--calibrate-target",
        type=float,
        default=None,
        help="equalize initial TPR at 1%% FPR (e.g. 0.95)",
    )
    p.add_argument("--strength-grid", default="0.5,1,2,4,8")
    p.add_argument("--calibration-samples", type=int, default=100)
    p.add_argument("--output", type=Path, default=RESULTS_PATH)
    p.add_argument("--json-output", type=Path, default=None)
    p.add_argument("--checkpoint", type=Path, default=Path("dewatermark-eval.jsonl"))
    p.add_argument("--resume", action="store_true")
    p.add_argument("--failure-policy", choices=("strict", "continue"), default="strict")
    p.add_argument(
        "--include-text-artifacts",
        action="store_true",
        help="include generated text in checkpoints; hashes are the privacy-safe default",
    )
    args = p.parse_args()
    if args.samples < 1 or args.null_samples < 1 or args.calibration_samples < 1:
        p.error("--samples, --null-samples, and --calibration-samples must be positive")
    if args.length < 1:
        p.error("--length must be positive")
    if args.seed < 0:
        p.error("--seed must be non-negative")
    if args.calibrate_target is not None and not 0 < args.calibrate_target <= 1:
        p.error("--calibrate-target must be in (0, 1]")
    try:
        sweep_lengths = (
            [int(value.strip()) for value in args.lengths.split(",") if value.strip()]
            if args.lengths
            else [args.length]
        )
        strength_grid = [
            float(value.strip()) for value in args.strength_grid.split(",") if value.strip()
        ]
    except ValueError:
        p.error("--lengths and --strength-grid must contain numbers")
    if not sweep_lengths or any(value < 1 for value in sweep_lengths):
        p.error("all requested lengths must be positive")
    if not strength_grid or any(not math.isfinite(value) or value <= 0 for value in strength_grid):
        p.error("all strengths must be positive")
    if args.allow_model_download and not args.allow_network:
        p.error("--allow-model-download requires --allow-network")
    selected_schemes = [value.strip() for value in args.schemes.split(",") if value.strip()]
    selected_modes = [value.strip() for value in args.modes.split(",") if value.strip()]
    if not selected_schemes or not selected_modes:
        p.error("--schemes and --modes cannot be empty")
    valid_modes = {
        "auto",
        "sanitize",
        "paraphrase",
        "full",
        "sira",
        "bias_inversion",
        "adversarial",
    }
    unknown_modes = sorted(set(selected_modes) - valid_modes)
    if unknown_modes:
        p.error(f"unknown removal modes: {', '.join(unknown_modes)}")
    args.schemes = ",".join(selected_schemes)
    args.modes = ",".join(selected_modes)
    if not args.date:
        args.date = time.strftime("%Y-%m-%d %H:%M %Z")
    cross_detectors = {}
    try:
        for spec in args.adapter:
            adapter = CommandScheme.from_spec(spec)
            adapter.allow_network = args.allow_network
            adapter.allow_model_download = args.allow_model_download
            schemes.SCHEMES[adapter.name] = adapter.as_scheme()
        for spec in args.cross_detector:
            detector = CommandScheme.from_spec(spec)
            detector.allow_network = args.allow_network
            detector.allow_model_download = args.allow_model_download
            cross_detectors[detector.name] = {
                "detect": detector.detect,
                "detection_metadata": detector.detection_metadata,
                "manifest": detector.manifest(),
            }
    except (RuntimeError, ValueError) as exc:
        p.error(str(exc))
    unknown_schemes = sorted(set(selected_schemes) - set(schemes.SCHEMES))
    if unknown_schemes:
        p.error(f"unknown schemes: {', '.join(unknown_schemes)}")
    for scheme_name in selected_schemes:
        scheme_manifest = schemes.SCHEMES[scheme_name].get("manifest", {})
        minimum = int(
            scheme_manifest.get(
                "minimum_effective_tokens", scheme_manifest.get("minimum_tokens", 0)
            )
        )
        if scheme_manifest.get("independent") and any(value < minimum for value in sweep_lengths):
            p.error(
                f"{scheme_name} requires at least {minimum} effective tokens; "
                "increase --length/--lengths"
            )
    base_config = dewatermark.get_config()
    dewatermark.configure(
        lm_backend=base_config.lm_backend if args.allow_network else "local",
        local_lm=args.local_lm,
        allow_model_download=args.allow_model_download,
        allow_remote_processing=args.allow_network,
        fireworks_api_key=base_config.fireworks_api_key if args.allow_network else None,
        llm_api_key=base_config.llm_api_key if args.allow_network else None,
        scorer_provider=None,
        detector_provider=None,
        rewriter_provider=None,
        random_seed=args.seed,
        require_verified=False,
    )

    try:
        from .manifest import (
            IncompatibleResumeError,
            append_checkpoint,
            completed_lengths,
            ensure_resume_compatible,
            environment_manifest,
            finalize_manifest,
            json_safe,
        )
    except ImportError:
        from manifest import (  # type: ignore
            IncompatibleResumeError,
            append_checkpoint,
            completed_lengths,
            ensure_resume_compatible,
            environment_manifest,
            finalize_manifest,
            json_safe,
        )
    manifest = environment_manifest(args)
    manifest["prompt_sha256"] = hashlib.sha256(
        json.dumps(PROMPTS, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    manifest["scheme_manifests"] = schemes.scheme_manifests(selected_schemes)
    manifest["detector_manifests"] = {
        name: value["manifest"] for name, value in sorted(cross_detectors.items())
    }
    manifest["dewatermark_config"] = _evaluation_config_manifest(dewatermark.get_config())
    manifest["runtime_backends"] = {
        "generator": {"model": args.local_lm, "revision": args.model_revision},
        "remover": {
            "backend": dewatermark.get_config().resolved_lm_backend,
            "network_allowed": args.allow_network,
            "model_download_allowed": args.allow_model_download,
        },
    }
    manifest["reproducibility_warnings"] = [
        message
        for condition, message in (
            (
                args.model_revision is None and not args.skip_statistical,
                "generator model revision is not pinned to an immutable commit",
            ),
            (
                args.allow_network,
                "remote adapters or rewrite services may be nondeterministic",
            ),
        )
        if condition
    ]
    manifest = finalize_manifest(manifest)
    run_id = manifest["run_id"]
    if args.resume:
        try:
            ensure_resume_compatible(args.checkpoint, manifest)
        except IncompatibleResumeError as exc:
            p.error(str(exc))
    elif args.checkpoint.exists() and args.checkpoint.stat().st_size:
        p.error(
            f"checkpoint already exists: {args.checkpoint}; use --resume only for the "
            "same run or choose a new --checkpoint"
        )
    else:
        append_checkpoint(
            args.checkpoint, {"event": "run.started", "run_id": run_id, "manifest": manifest}
        )
    unicode_rows = None if args.skip_unicode else run_unicode_suite()
    stat_results = None
    if not args.skip_statistical:
        stat_results = {}
        resumed = completed_lengths(args.checkpoint, run_id=run_id) if args.resume else {}
        for length in sweep_lengths:
            if length in resumed:
                stat_results.update(resumed[length])
                continue
            one = run_statistical_suite(
                selected_schemes,
                selected_modes,
                args.samples,
                args.null_samples,
                length,
                args.seed,
                args.calibrate_target,
                strength_grid,
                args.calibration_samples,
                args.failure_policy,
                args.local_lm,
                args.model_revision,
                args.allow_model_download,
                lambda item: append_checkpoint(args.checkpoint, {"run_id": run_id, **item}),
                args.include_text_artifacts,
                args.allow_network,
                cross_detectors,
            )
            for name, result in one.items():
                stat_results[f"{name}@{length}"] = result
            append_checkpoint(
                args.checkpoint,
                {
                    "event": "length.completed",
                    "run_id": run_id,
                    "length": length,
                    "results": {f"{name}@{length}": result for name, result in one.items()},
                },
            )
    write_results(unicode_rows, stat_results, args, args.output)
    payload = {
        "schema_version": "1.0",
        "manifest": manifest,
        "unicode": unicode_rows,
        "statistical": stat_results,
    }
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(json_safe(payload), indent=2, allow_nan=False), encoding="utf-8"
        )
    append_checkpoint(args.checkpoint, {"event": "run.completed", "run_id": run_id})
    print(
        json.dumps(
            {
                "unicode": unicode_rows is not None,
                "statistical": stat_results is not None,
                "output": str(args.output),
                "json_output": str(args.json_output) if args.json_output else None,
                "run_id": run_id,
            }
        )
    )


if __name__ == "__main__":
    main()
