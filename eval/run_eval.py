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
import sys
import time
from pathlib import Path

import dewatermark

try:
    from . import metrics, schemes, stego
    from .adapters import CommandScheme
    from .calibration import select_strength
except ImportError:  # direct ``python eval/run_eval.py`` compatibility
    import metrics  # type: ignore
    import schemes  # type: ignore
    import stego  # type: ignore
    from adapters import CommandScheme  # type: ignore
    from calibration import select_strength  # type: ignore

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


def remove_text(text: str, mode: str) -> str:
    params = MODE_PARAMS.get(mode, {})
    return dewatermark.remove(text, mode=mode, **params).cleaned_text


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
    before, after, plain_before, plain_after, sims, berts, quality_passes, mauve_score, ppl_b, ppl_a
):
    thr = metrics.threshold_at_fpr(plain_after, 0.01)
    flagged = sum(1 for a in after if a > thr) if thr == thr else None
    row = {
        "auroc_before": metrics.auroc(before, plain_before),
        "auroc_after": metrics.auroc(after, plain_after),
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
    }
    for fpr in FPRS:
        row[f"tpr_before@{fpr}"] = metrics.tpr_at_fpr(before, plain_before, fpr)
        row[f"tpr_after@{fpr}"] = metrics.tpr_at_fpr(after, plain_after, fpr)
    if flagged is not None:
        row["tpr_after_ci95"] = metrics.wilson_interval(flagged, len(after))
    return row


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
):
    print("[statistical] loading generator ...")
    tok, model = schemes.load_model(
        model_name, revision=model_revision, allow_download=allow_model_download
    )
    sem = metrics.SemanticScorer()
    bert = metrics.BERTScoreScorer()
    results = {}
    internal_plain_texts = [
        schemes.generate_plain(PROMPTS[i % len(PROMPTS)], tok, model, length, seed * 100 + i)
        for i in range(null_samples)
    ]
    internal_transformed_nulls = {
        mode: [remove_text(item, mode) for item in internal_plain_texts] for mode in modes
    }

    for scheme_name in scheme_names:
        sc = schemes.SCHEMES[scheme_name]
        print(f"[statistical] === {scheme_name} ({sc['family']}) ===")
        if sc.get("independent"):
            plain_texts = [
                sc["generate"](PROMPTS[i % len(PROMPTS)], tok, model, length, seed * 100 + i, False)
                for i in range(null_samples)
            ]
            transformed_nulls = {
                mode: [remove_text(item, mode) for item in plain_texts] for mode in modes
            }
        else:
            plain_texts = internal_plain_texts
            transformed_nulls = internal_transformed_nulls
        plain = [sc["detect"](item, tok) for item in plain_texts]
        calibration = None
        if calibration_target is not None and sc.get("set_strength"):
            scores_by_strength = {}
            for strength in strength_grid:
                sc["set_strength"](strength)
                scores_by_strength[strength] = [
                    sc["detect"](
                        sc["generate"](
                            PROMPTS[i % len(PROMPTS)], tok, model, length, seed * 10000 + i, True
                        ),
                        tok,
                    )
                    for i in range(calibration_samples)
                ]
            calibration = select_strength(scores_by_strength, plain, target_tpr=calibration_target)
            if calibration["chosen"] is None:
                raise RuntimeError(
                    f"{scheme_name} did not reach calibration target; expand --strength-grid"
                )
            sc["set_strength"](calibration["chosen"])
        wm_texts, before = [], []
        for i in range(samples):
            wt = sc["generate"](
                PROMPTS[i % len(PROMPTS)], tok, model, length, seed * 1000 + i, True
            )
            wm_texts.append(wt)
            before.append(sc["detect"](wt, tok))
        print(
            f"[statistical] {scheme_name}: mean score watermarked={sum(before) / len(before):.2f} "
            f"plain={sum(plain) / len(plain):.2f}"
        )

        scheme_res = {
            "family": sc["family"],
            "source": sc.get("source"),
            "independent": sc.get("independent", False),
            "calibration": calibration,
            "plain": plain,
            "before": before,
            "modes": {},
        }
        for mode in modes:
            after, sims, berts, quality_passes, cleaned_texts, ppl_b, ppl_a = (
                [],
                [],
                [],
                [],
                [],
                [],
                [],
            )
            failures = []
            for j, (wt, zb) in enumerate(zip(wm_texts, before)):
                failure = None
                try:
                    cleaned = remove_text(wt, mode)
                except Exception as exc:
                    print(f"  ! {scheme_name}/{mode} sample {j} failed: {exc}", file=sys.stderr)
                    failures.append({"sample": j, "error": str(exc)})
                    failure = str(exc)
                    if failure_policy == "strict":
                        raise RuntimeError(f"{scheme_name}/{mode} sample {j} failed") from exc
                    cleaned = wt
                za = sc["detect"](cleaned, tok)
                after.append(za)
                cleaned_texts.append(cleaned)
                sims.append(sem.similarity(wt, cleaned))
                berts.append(bert.similarity(wt, cleaned))
                quality_passes.append(metrics.deterministic_quality_pass(wt, cleaned))
                ppl_b.append(metrics.perplexity(wt, tok, model))
                ppl_a.append(metrics.perplexity(cleaned, tok, model))
                if artifact_sink:
                    artifact = {
                        "event": "sample.completed",
                        "scheme": scheme_name,
                        "mode": mode,
                        "length": length,
                        "sample": j,
                        "score_before": zb,
                        "score_after": za,
                        "semantic_similarity": sims[-1],
                        "bertscore": berts[-1],
                        "quality_passed": quality_passes[-1],
                        "source_sha256": hashlib.sha256(wt.encode("utf-8")).hexdigest(),
                        "candidate_sha256": hashlib.sha256(cleaned.encode("utf-8")).hexdigest(),
                        "error": failure,
                    }
                    if include_text_artifacts:
                        artifact.update(source_text=wt, candidate_text=cleaned)
                    artifact_sink(artifact)
                print(
                    f"  [{scheme_name}/{mode}] {j + 1}/{samples} score {zb:6.2f} -> {za:6.2f} "
                    f"sim {sims[-1]:.2f}"
                )
            # Calibrate against matched controls after the same transformation;
            # otherwise the rewrite model's distribution is a confounder.
            plain_after = [sc["detect"](item, tok) for item in transformed_nulls[mode]]
            scheme_res["modes"][mode] = _mode_metrics(
                before,
                after,
                plain,
                plain_after,
                sims,
                berts,
                quality_passes,
                metrics.corpus_mauve(wm_texts, cleaned_texts),
                ppl_b,
                ppl_a,
            )
            scheme_res["modes"][mode]["failures"] = failures
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
        "# Efficacy Results — dewatermark",
        "",
        f"- Date: {args.date}",
        f"- dewatermark {dewatermark.__version__}  |  lm_backend: `{cfg.resolved_lm_backend}`"
        f"  |  local rewriter: `{args.local_lm}`",
        f"- Statistical: {args.samples} positives + {args.null_samples} matched nulls/scheme "
        f"at lengths {args.lengths or args.length} tokens, seed {args.seed}",
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
            "samples of the same length (not a raw-threshold count). `flagged@1%FPR` is "
            "the residual detections at a 1% false-positive threshold. Quality: `sim` = "
            "MiniLM cosine, BERTScore, MAUVE, deterministic preservation gates, and `PPL`.",
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
                "| Mode | AUROC after | TPR@1%FPR | TPR@0.1%FPR | TPR@1e-5 | flagged@1%FPR | MiniLM | BERTScore | MAUVE | gate pass | ΔPPL |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
            for mode, m in res["modes"].items():
                dppl = m["ppl_after"] - m["ppl_before"]
                lines.append(
                    f"| {mode} | {_fmt(m['auroc_after'])} | {_fmt(m['tpr_after@0.01'])} | "
                    f"{_fmt(m['tpr_after@0.001'])} | {_fmt(m['tpr_after@1e-05'])} | "
                    f"{m['flagged_after'] if m['flagged_after'] is not None else 'not estimable'}/{m['n']} | "
                    f"{_fmt(m['sim_mean'])} | {_fmt(m['bertscore_mean'])} | "
                    f"{_fmt(m['mauve'])} | {_fmt(m['quality_gate_rate'])} | {_fmt(dppl, 1)} |"
                )
            lines.append("")
            lines.append(
                f"_Baseline (no removal) TPR@1%FPR: "
                f"{_fmt(metrics.tpr_at_fpr(res['before'], res['plain'], 0.01))}._"
            )
            lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Results written to {output_path}")


def main() -> None:
    p = argparse.ArgumentParser(description="Efficacy harness for dewatermark")
    p.add_argument("--schemes", default="KGW,Unigram,EXP")
    p.add_argument("--modes", default="full,bias_inversion,sira")
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
    p.add_argument("--skip-unicode", action="store_true")
    p.add_argument("--skip-statistical", action="store_true")
    p.add_argument("--date", default="")
    p.add_argument(
        "--adapter",
        action="append",
        default=[],
        help="independent detector: NAME|FAMILY|SOURCE|COMMAND (repeatable)",
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
    if not args.date:
        args.date = time.strftime("%Y-%m-%d %H:%M %Z")
    for spec in args.adapter:
        adapter = CommandScheme.from_spec(spec)
        schemes.SCHEMES[adapter.name] = adapter.as_scheme()
    dewatermark.configure(
        local_lm=args.local_lm,
        allow_model_download=args.allow_model_download,
    )

    try:
        from .manifest import append_checkpoint, completed_lengths, environment_manifest
    except ImportError:
        from manifest import (  # type: ignore
            append_checkpoint,
            completed_lengths,
            environment_manifest,
        )
    manifest = environment_manifest(args)
    manifest["prompt_sha256"] = hashlib.sha256(
        json.dumps(PROMPTS, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    append_checkpoint(args.checkpoint, {"event": "run.started", "manifest": manifest})
    unicode_rows = None if args.skip_unicode else run_unicode_suite()
    stat_results = None
    if not args.skip_statistical:
        lengths = [int(v) for v in args.lengths.split(",") if v] if args.lengths else [args.length]
        stat_results = {}
        resumed = completed_lengths(args.checkpoint) if args.resume else {}
        for length in lengths:
            if length in resumed:
                stat_results.update(resumed[length])
                continue
            one = run_statistical_suite(
                args.schemes.split(","),
                args.modes.split(","),
                args.samples,
                args.null_samples,
                length,
                args.seed,
                args.calibrate_target,
                [float(v) for v in args.strength_grid.split(",")],
                args.calibration_samples,
                args.failure_policy,
                args.local_lm,
                args.model_revision,
                args.allow_model_download,
                lambda item: append_checkpoint(args.checkpoint, item),
                args.include_text_artifacts,
            )
            for name, result in one.items():
                stat_results[f"{name}@{length}"] = result
            append_checkpoint(
                args.checkpoint,
                {
                    "event": "length.completed",
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
        args.json_output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    append_checkpoint(args.checkpoint, {"event": "run.completed"})
    print(
        json.dumps(
            {
                "unicode": unicode_rows is not None,
                "statistical": stat_results is not None,
                "output": str(args.output),
                "json_output": str(args.json_output) if args.json_output else None,
            }
        )
    )


if __name__ == "__main__":
    main()
