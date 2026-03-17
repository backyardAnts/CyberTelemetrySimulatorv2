#!/usr/bin/env python3
"""Analyze JSONL telemetry data for ML leakage risks."""

import argparse
import json
import math
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Tuple


METRICS_FOR_VARIANCE = [
    "AveragePacketRate",
    "TotalFailedLogins",
    "FailedToSuccessRatio",
    "UniquePortsAccessed",
    "ConnectionAttemptsPerSecond",
    "TrafficVolumeBytes",
    "OutgoingBytes",
    "IncomingBytes",
    "OutgoingIncomingRatio",
    "AverageCpuUsage",
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


def print_header() -> None:
    print("=" * 24)
    print("ML DATASET LEAKAGE CHECK")
    print("=" * 24)


def summarize_device_type_label(rows: List[dict], warnings: List[str]) -> None:
    device_type_counts = defaultdict(Counter)
    for row in rows:
        device_type = row.get("DeviceType", "Unknown")
        label = row.get("Label", "Unknown")
        device_type_counts[device_type][label] += 1

    print("\nDeviceType-label correlation:")
    for device_type in sorted(device_type_counts.keys()):
        total = sum(device_type_counts[device_type].values())
        print(f"{device_type}:")
        for label, count in device_type_counts[device_type].most_common():
            percent = (count / total) * 100 if total else 0
            print(f"  {label}: {percent:.1f}%")
            if percent > 90:
                warnings.append(
                    f"DeviceType {device_type} is {percent:.1f}% {label}."
                )


def summarize_attack_id(rows: List[dict], warnings: List[str]) -> None:
    attack_id_labels = defaultdict(set)
    for row in rows:
        attack_id = row.get("AttackId")
        label = row.get("Label", "Unknown")
        if attack_id is None:
            continue
        attack_id_labels[attack_id].add(label)

    print("\nAttackId leakage:")
    if not attack_id_labels:
        print("No AttackId values found.")
        return

    unique_mapping = all(len(labels) == 1 for labels in attack_id_labels.values())
    for attack_id in sorted(attack_id_labels.keys()):
        labels = sorted(attack_id_labels[attack_id])
        label_text = ", ".join(labels)
        print(f"{attack_id}: {label_text}")

    if unique_mapping:
        warnings.append("AttackId perfectly predicts label.")


def parse_time_of_day(value) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        hour = int(value)
    else:
        try:
            hour = int(str(value).strip())
        except ValueError:
            return None
    if 0 <= hour <= 23:
        return hour
    return None


def summarize_time_of_day(rows: List[dict], warnings: List[str]) -> None:
    time_by_label = defaultdict(list)
    for row in rows:
        metrics = row.get("Metrics", {})
        hour = parse_time_of_day(metrics.get("TimeOfDay"))
        if hour is None:
            continue
        label = row.get("Label", "Unknown")
        time_by_label[label].append(hour)

    print("\nTimeOfDay distribution:")
    for label in sorted(time_by_label.keys()):
        hours = time_by_label[label]
        if not hours:
            continue
        avg_hour = sum(hours) / len(hours)
        min_hour = min(hours)
        max_hour = max(hours)
        print(f"{label}: avg={avg_hour:.2f}, range={min_hour}-{max_hour}")
        if max_hour - min_hour <= 2:
            warnings.append(
                f"{label} traffic occurs in a narrow hour range ({min_hour}-{max_hour})."
            )


def count_duplicates(rows: List[dict]) -> int:
    seen = set()
    duplicates = 0
    for row in rows:
        metrics = row.get("Metrics", {})
        metrics_key = json.dumps(metrics, sort_keys=True, separators=(",", ":"))
        key = (
            row.get("DeviceId"),
            row.get("Timestamp"),
            metrics_key,
            row.get("Label"),
        )
        if key in seen:
            duplicates += 1
        else:
            seen.add(key)
    return duplicates


def compute_variances(rows: List[dict]) -> Dict[str, float]:
    sums = defaultdict(float)
    sums_sq = defaultdict(float)
    counts = defaultdict(int)

    for row in rows:
        metrics = row.get("Metrics", {})
        for metric in METRICS_FOR_VARIANCE:
            if metric not in metrics:
                continue
            value = metrics[metric]
            try:
                numeric_value = float(value)
            except (TypeError, ValueError):
                continue
            sums[metric] += numeric_value
            sums_sq[metric] += numeric_value**2
            counts[metric] += 1

    variances = {}
    for metric, total in sums.items():
        count = counts[metric]
        if count < 2:
            continue
        mean = total / count
        variance = (sums_sq[metric] / count) - mean**2
        variances[metric] = max(variance, 0.0)
    return variances


def summarize_variances(rows: List[dict], warnings: List[str]) -> None:
    variances = compute_variances(rows)
    print("\nLow variance features:")
    if not variances:
        print("No metric variance data available.")
        return
    for metric in sorted(variances.keys()):
        variance = variances[metric]
        print(f"{metric} variance: {variance:.6f}")
        if math.isclose(variance, 0.0, abs_tol=1e-6):
            warnings.append(f"{metric} variance is near zero.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect ML leakage risks in telemetry JSONL datasets."
    )
    parser.add_argument("path", help="Path to JSONL telemetry data")
    args = parser.parse_args()

    rows = list(load_jsonl(args.path))
    print_header()
    print(f"Rows analyzed: {len(rows)}")

    warnings: List[str] = []
    summarize_device_type_label(rows, warnings)
    summarize_attack_id(rows, warnings)
    summarize_time_of_day(rows, warnings)

    duplicates = count_duplicates(rows)
    print("\nDuplicate rows:")
    print(f"{duplicates}")

    summarize_variances(rows, warnings)

    print("\nWarnings:")
    if warnings:
        for warning in warnings:
            print(f"- {warning}")
    else:
        print("- None")


if __name__ == "__main__":
    main()
