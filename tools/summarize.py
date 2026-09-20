#!/usr/bin/env python3
"""Summarize JEV_EVAL logs without treating Ollama predictions as ground truth."""

import argparse
import csv
import json
import math
import sys
from collections import Counter

MARKER = "JEV_EVAL "
LABELS = {"ham", "spam", "phishing"}
DECISIONS = LABELS | {"uncertain"}
SPAM_ACTIONS = {"reject", "add header", "rewrite subject", "quarantine", "discard"}


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def read_records(stream):
    for line_number, line in enumerate(stream, 1):
        if MARKER in line:
            line = line.split(MARKER, 1)[1]
        elif not line.lstrip().startswith("{"):
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict) or record.get("schema_version") != 1:
                raise ValueError("unsupported record schema")
            digest = record.get("message_digest")
            if not isinstance(digest, str) or len(digest) != 32 or any(
                    char not in "0123456789abcdef" for char in digest):
                raise ValueError("invalid message_digest")
            if record.get("mode") not in {"live", "mock"}:
                raise ValueError("invalid mode")
            if record.get("status") not in {"ok", "error", "skipped"}:
                raise ValueError("invalid status")
            if not number(record.get("timestamp")):
                raise ValueError("invalid timestamp")
            baseline = record.get("baseline")
            if not isinstance(baseline, dict) or baseline.get("verdict") not in {
                "ham", "spam", "uncertain", "not_observed", "conflict"
            }:
                raise ValueError("invalid baseline")
            if record["status"] == "ok":
                result = record.get("jev")
                if not isinstance(result, dict) or result.get("decision") not in DECISIONS:
                    raise ValueError("invalid Jev decision")
                if result.get("choice") not in LABELS:
                    raise ValueError("invalid Jev choice")
                if not number(result.get("confidence")) or not 0 <= result["confidence"] <= 1:
                    raise ValueError("invalid confidence")
                probabilities = result.get("probabilities")
                if not isinstance(probabilities, dict) or set(probabilities) != LABELS:
                    raise ValueError("invalid probabilities")
                if any(not number(p) or not 0 <= p <= 1 for p in probabilities.values()):
                    raise ValueError("invalid probabilities")
                if abs(sum(probabilities.values()) - 1) > 0.01:
                    raise ValueError("probabilities do not sum to one")
                if not number(result.get("input_tokens")) or result["input_tokens"] < 0:
                    raise ValueError("invalid input_tokens")
                if not number(record.get("latency_ms")) or record["latency_ms"] < 0:
                    raise ValueError("invalid latency_ms")
            yield record
        except (ValueError, TypeError) as exc:
            raise ValueError(f"line {line_number}: {exc}") from exc


def read_labels(stream):
    reader = csv.DictReader(stream)
    if reader.fieldnames != ["message_digest", "label"]:
        raise ValueError("labels CSV header must be message_digest,label")
    labels = {}
    for row in reader:
        digest, label = row["message_digest"], row["label"]
        if label not in LABELS or digest in labels:
            raise ValueError("invalid or duplicate label")
        labels[digest] = label
    return labels


def quantile(values, percentile):
    if not values:
        return None
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * percentile) - 1)]


def binary(label):
    if label in {"spam", "phishing"}:
        return "spam"
    return label


def pipeline_decision(record):
    action = record.get("rspamd_action")
    if action == "no action":
        return "ham"
    if action in SPAM_ACTIONS:
        return "spam"
    return "uncertain"


def metrics(pairs):
    counts = Counter((binary(actual), binary(predicted)) for actual, predicted in pairs)
    tp, fp = counts["spam", "spam"], counts["ham", "spam"]
    tn, fn = counts["ham", "ham"], counts["spam", "ham"]
    return {
        "n": len(pairs),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "ham_false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "spam_recall": tp / (tp + fn) if tp + fn else None,
        "precision": tp / (tp + fp) if tp + fp else None,
    }


def summarize(records, mode="live", labels=None, price_per_million=0.042):
    labels = labels or {}
    selected = [record for record in records if record["mode"] == mode]
    configs = {
        json.dumps({
            key: record.get(key) for key in (
                "model", "prompt_version", "sample_rate", "probability_threshold", "confidence_threshold"
            )
        } | {"baseline": {key: record["baseline"].get(key) for key in ("provider", "configured_model")}},
                   sort_keys=True)
        for record in selected
    }
    if len(configs) > 1:
        raise ValueError("mixed model/prompt/threshold/sampling/baseline settings; split the input logs")
    statuses = Counter(record["status"] for record in selected)
    reasons = Counter(record.get("reason", "unspecified") for record in selected if record["status"] != "ok")
    successes = [record for record in selected if record["status"] == "ok"]
    latest = {}
    for record in successes:
        digest = record["message_digest"]
        if digest not in latest or record["timestamp"] >= latest[digest]["timestamp"]:
            latest[digest] = record
    unique = list(latest.values())
    comparable = [record for record in unique
                  if record["baseline"]["verdict"] in {"ham", "spam"}
                  and record["jev"]["decision"] != "uncertain"]
    matrix = Counter((record["baseline"]["verdict"], binary(record["jev"]["decision"])) for record in comparable)
    input_tokens = sum(record["jev"]["input_tokens"] for record in successes)
    attempted_latencies = [record["latency_ms"] for record in selected
                           if record.get("requested") and number(record.get("latency_ms"))]
    paired_labeled = [record for record in comparable if record["message_digest"] in labels]
    jev_pairs = [(labels[record["message_digest"]], record["jev"]["decision"]) for record in paired_labeled]
    baseline_pairs = [(labels[record["message_digest"]], record["baseline"]["verdict"]) for record in paired_labeled]
    labeled_unique = [record for record in unique if record["message_digest"] in labels]
    pipeline_paired = [record for record in labeled_unique
                       if record["jev"]["decision"] != "uncertain"
                       and pipeline_decision(record) != "uncertain"]
    return {
        "mode": mode,
        "warning": "Mock results are synthetic, not model quality." if mode == "mock"
                   else "Agreement is not accuracy. Labels must be independent human ground truth.",
        "config": json.loads(next(iter(configs))) if configs else None,
        "scans": len(selected),
        "excluded_other_mode_scans": len(records) - len(selected),
        "statuses": dict(statuses),
        "skip_error_reasons": dict(reasons),
        "successful_unique_messages": len(unique),
        "repeated_successful_scans": len(successes) - len(unique),
        "jev_decisions": dict(Counter(record["jev"]["decision"] for record in unique)),
        "baseline_verdicts": dict(Counter(record["baseline"]["verdict"] for record in unique)),
        "comparable_unique_messages": len(comparable),
        "agreement": sum(record["baseline"]["verdict"] == binary(record["jev"]["decision"])
                         for record in comparable) / len(comparable) if comparable else None,
        "baseline_vs_jev": {f"{a}->{b}": matrix[a, b] for a in ("ham", "spam") for b in ("ham", "spam")},
        "http_latency_ms": {
            "n": len(attempted_latencies),
            "p50": quantile(attempted_latencies, 0.5),
            "p95": quantile(attempted_latencies, 0.95),
            "p99": quantile(attempted_latencies, 0.99),
        },
        "successful_input_tokens": input_tokens,
        "estimated_success_cost_usd": input_tokens / 1_000_000 * price_per_million if mode == "live" else 0,
        "labeled_unique_messages": len(labeled_unique),
        "paired_labeled_coverage": len(paired_labeled) / len(labeled_unique) if labeled_unique else None,
        "paired_labeled_jev": metrics(jev_pairs),
        "paired_labeled_baseline": metrics(baseline_pairs),
        "current_pipeline_actions": dict(Counter(record.get("rspamd_action", "unknown") for record in unique)),
        "pipeline_paired_labeled_coverage": len(pipeline_paired) / len(labeled_unique) if labeled_unique else None,
        "pipeline_paired_labeled_jev": metrics([
            (labels[record["message_digest"]], record["jev"]["decision"]) for record in pipeline_paired
        ]),
        "pipeline_paired_labeled_rspamd_ollama": metrics([
            (labels[record["message_digest"]], pipeline_decision(record)) for record in pipeline_paired
        ]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", help="Rspamd text log or JSONL; '-' for stdin")
    parser.add_argument("--mode", choices=("live", "mock"), default="live")
    parser.add_argument("--labels", help="CSV: message_digest,label (ham/spam/phishing)")
    parser.add_argument("--price-per-million", type=float, default=0.042)
    args = parser.parse_args()
    if not number(args.price_per_million) or args.price_per_million < 0:
        parser.error("price must be a finite nonnegative number")
    try:
        if args.log == "-":
            records = list(read_records(sys.stdin))
        else:
            with open(args.log, encoding="utf-8") as stream:
                records = list(read_records(stream))
        labels = {}
        if args.labels:
            with open(args.labels, encoding="utf-8", newline="") as stream:
                labels = read_labels(stream)
        report = summarize(records, args.mode, labels, args.price_per_million)
        print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
