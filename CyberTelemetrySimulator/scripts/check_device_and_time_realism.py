#!/usr/bin/env python3
"""Analyze JSONL telemetry data for device/time realism checks."""

import argparse
import json
from collections import defaultdict
from typing import Dict, Iterable, Tuple


KEY_METRICS = [
    "AveragePacketRate",
    "TrafficVolumeBytes",
    "ConnectionAttemptsPerSecond",
    "TotalFailedLogins",
    "OutgoingBytes",
    "IncomingBytes",
]


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
    rows: Iterable[dict], metrics: Iterable[str], group_key: str
) -> Tuple[Dict[str, int], Dict[str, Dict[str, float]]]:
    counts = defaultdict(int)
    sums = defaultdict(lambda: defaultdict(float))
    metric_counts = defaultdict(lambda: defaultdict(int))

    for row in rows:
        group_value = row.get(group_key, "Unknown")
        counts[group_value] += 1
        metric_values = row.get("Metrics", {})
        for metric in metrics:
            if metric not in metric_values:
                continue
            value = metric_values[metric]
            try:
                numeric_value = float(value)
            except (TypeError, ValueError):
                continue
            sums[group_value][metric] += numeric_value
            metric_counts[group_value][metric] += 1

    means: Dict[str, Dict[str, float]] = defaultdict(dict)
    for group_value, metric_map in sums.items():
        for metric, total in metric_map.items():
            count = metric_counts[group_value][metric]
            if count:
                means[group_value][metric] = total / count
    return counts, means


def format_value(value: float) -> str:
    return f"{value:.4f}" if isinstance(value, float) else "N/A"


def summarize_device_types(
    rows: Iterable[dict], metrics: Iterable[str], normal_label: str
) -> None:
    normal_rows = (row for row in rows if row.get("Label") == normal_label)
    counts, means = compute_means(normal_rows, metrics, "DeviceType")

    print("Normal traffic by device type:")
    if not counts:
        print("  Warning: no Normal rows found.")
        return

    for device_type in sorted(counts.keys()):
        print(f"- {device_type} ({counts[device_type]} rows)")
        device_metrics = means.get(device_type, {})
        for metric in metrics:
            value = device_metrics.get(metric)
            if value is None:
                continue
            print(f"  {metric}: {format_value(value)}")


def summarize_time_of_day(rows: Iterable[dict], metrics: Iterable[str]) -> None:
    counts = {"Day": 0, "Night": 0}
    sums = {"Day": defaultdict(float), "Night": defaultdict(float)}
    metric_counts = {"Day": defaultdict(int), "Night": defaultdict(int)}

    for row in rows:
        metric_values = row.get("Metrics", {})
        time_of_day = metric_values.get("TimeOfDay")
        if time_of_day is None:
            continue
        bucket = "Day" if str(time_of_day).lower().startswith("day") else "Night"
        counts[bucket] += 1
        for metric in metrics:
            if metric not in metric_values:
                continue
            value = metric_values[metric]
            try:
                numeric_value = float(value)
            except (TypeError, ValueError):
                continue
            sums[bucket][metric] += numeric_value
            metric_counts[bucket][metric] += 1

    print("\nDay vs night traffic:")
    for bucket in ("Day", "Night"):
        if not counts[bucket]:
            print(f"- {bucket}: no rows found")
            continue
        print(f"- {bucket} ({counts[bucket]} rows)")
        for metric in metrics:
            count = metric_counts[bucket].get(metric, 0)
            if not count:
                continue
            mean = sums[bucket][metric] / count
            print(f"  {metric}: {format_value(mean)}")

    if counts["Day"] and counts["Night"]:
        day_volume = sums["Day"].get("TrafficVolumeBytes")
        night_volume = sums["Night"].get("TrafficVolumeBytes")
        if day_volume is not None and night_volume is not None:
            if day_volume <= night_volume:
                print("  Warning: daytime traffic volume is not higher than nighttime.")
            else:
                print("  Daytime traffic volume is higher than nighttime.")


def summarize_attack_distribution(rows: Iterable[dict], normal_label: str) -> None:
    attack_device_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    attack_totals = defaultdict(int)

    for row in rows:
        label = row.get("Label")
        if label == normal_label:
            continue
        device_type = row.get("DeviceType", "Unknown")
        attack_device_counts[label][device_type] += 1
        attack_totals[label] += 1

    print("\nAttack distribution by device type:")
    if not attack_totals:
        print("  Warning: no attack rows found.")
        return

    for label in sorted(attack_totals.keys()):
        device_counts = attack_device_counts[label]
        print(f"- {label} ({attack_totals[label]} rows)")
        for device_type, count in sorted(device_counts.items()):
            percent = (count / attack_totals[label]) * 100
            print(f"  {device_type}: {count} ({percent:.1f}%)")
        if len(device_counts) < 2:
            print("  Warning: attacks concentrated in a single device type.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check device/time realism in telemetry JSONL data."
    )
    parser.add_argument("path", help="Path to JSONL telemetry data")
    parser.add_argument(
        "--normal-label",
        default="Normal",
        help="Label name to use as the baseline (default: Normal)",
    )
    args = parser.parse_args()

    rows = list(load_jsonl(args.path))
    summarize_device_types(rows, KEY_METRICS, args.normal_label)
    summarize_time_of_day(rows, KEY_METRICS)
    summarize_attack_distribution(rows, args.normal_label)


if __name__ == "__main__":
    main()
