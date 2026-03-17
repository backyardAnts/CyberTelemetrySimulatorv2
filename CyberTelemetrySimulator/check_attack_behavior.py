#!/usr/bin/env python3
"""Analyze JSONL telemetry data and validate attack behavior."""

import argparse
import json
from collections import defaultdict
from typing import Dict, Iterable, Tuple


IMPORTANT_METRICS = [
    "TotalFailedLogins",
    "FailedToSuccessRatio",
    "UniquePortsAccessed",
    "AveragePacketRate",
    "TrafficVolumeBytes",
    "ConnectionAttemptsPerSecond",
    "OutgoingBytes",
    "OutgoingIncomingRatio",
]

EXPECTED_HIGHER = {
    "BruteForce": ["TotalFailedLogins", "FailedToSuccessRatio"],
    "PortScan": ["UniquePortsAccessed"],
    "DDoS": [
        "AveragePacketRate",
        "TrafficVolumeBytes",
        "ConnectionAttemptsPerSecond",
    ],
    "Exfiltration": ["OutgoingBytes", "OutgoingIncomingRatio"],
}


def load_jsonl(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                yield json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}") from exc


def compute_means(
    rows: Iterable[dict], metrics: Iterable[str]
) -> Tuple[Dict[str, int], Dict[str, Dict[str, float]]]:
    counts = defaultdict(int)
    sums = defaultdict(lambda: defaultdict(float))
    metric_counts = defaultdict(lambda: defaultdict(int))

    for row in rows:
        label = row.get("Label", "Unknown")
        counts[label] += 1
        metric_values = row.get("Metrics", {})
        for metric in metrics:
            if metric not in metric_values:
                continue
            value = metric_values[metric]
            try:
                numeric_value = float(value)
            except (TypeError, ValueError):
                continue
            sums[label][metric] += numeric_value
            metric_counts[label][metric] += 1

    means: Dict[str, Dict[str, float]] = defaultdict(dict)
    for label, metric_map in sums.items():
        for metric, total in metric_map.items():
            count = metric_counts[label][metric]
            if count:
                means[label][metric] = total / count
    return counts, means


def format_metric(value: float) -> str:
    return f"{value:.4f}" if isinstance(value, float) else "N/A"


def compare_metrics(
    means: Dict[str, Dict[str, float]],
    normal_label: str,
    factor: float,
) -> None:
    normal_means = means.get(normal_label, {})
    if not normal_means:
        print("Warning: Normal label not found; comparisons skipped.")
        return

    print("\nAttack behavior checks:")
    for attack_label, metrics in EXPECTED_HIGHER.items():
        attack_means = means.get(attack_label, {})
        if not attack_means:
            print(f"- {attack_label}: label missing; cannot compare.")
            continue
        all_passed = True
        for metric in metrics:
            normal_value = normal_means.get(metric)
            attack_value = attack_means.get(metric)
            if normal_value is None or attack_value is None:
                print(
                    f"  Warning: {attack_label} missing metric {metric} for comparison."
                )
                all_passed = False
                continue
            required = normal_value * factor
            if attack_value <= required:
                print(
                    f"  Warning: {attack_label} {metric} {attack_value:.4f} "
                    f"not >= {factor:.2f}x Normal ({normal_value:.4f})."
                )
                all_passed = False
        if all_passed:
            print(f"- {attack_label}: expected metrics higher than Normal.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check attack behavior in a telemetry JSONL dataset."
    )
    parser.add_argument("path", help="Path to JSONL telemetry data")
    parser.add_argument(
        "--normal-label",
        default="Normal",
        help="Label name to use as the baseline (default: Normal)",
    )
    parser.add_argument(
        "--significance-factor",
        type=float,
        default=1.2,
        help="Multiplier over Normal required to be significant (default: 1.2)",
    )
    args = parser.parse_args()

    counts, means = compute_means(load_jsonl(args.path), IMPORTANT_METRICS)

    print("Label counts:")
    for label, count in sorted(counts.items()):
        print(f"- {label}: {count}")

    print("\nMean metrics by label:")
    for label in sorted(counts.keys()):
        metrics = means.get(label, {})
        print(label)
        for metric in IMPORTANT_METRICS:
            value = metrics.get(metric)
            if value is None:
                continue
            print(f"  {metric}: {format_metric(value)}")

    compare_metrics(means, args.normal_label, args.significance_factor)


if __name__ == "__main__":
    main()
